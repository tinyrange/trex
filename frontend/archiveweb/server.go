package archiveweb

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	cabarchive "github.com/tinyrange/trex/archive/cab"
	"github.com/tinyrange/trex/archive/wim"
	ziparchive "github.com/tinyrange/trex/archive/zip"
	filesystemapi "github.com/tinyrange/trex/filesystem"
	filesystemfat "github.com/tinyrange/trex/filesystem/fat"
	filesystemiso9660 "github.com/tinyrange/trex/filesystem/iso9660"
	filesystemudf "github.com/tinyrange/trex/filesystem/udf"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	windowsapi "github.com/tinyrange/trex/windows"
	"go.starlark.net/starlark"
)

const (
	webPreviewLimit = 64 * 1024
	webMountLimit   = 64
	webNodeLimit    = 250000
)

type File = starfile.File

type webServer struct {
	rootName  string
	rootFS    *os.Root
	remote    bool
	csrfToken string
	mu        sync.RWMutex
	nextID    int64
	root      *webNode
	nodes     map[string]*webNode
	mounts    map[string]*webNode
}

type ServeOptions struct {
	// AllowRemote permits binding the token-authenticated inspection UI to a
	// non-loopback address. Callers must opt in explicitly; TLS is external.
	AllowRemote bool
}

type webNode struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Path         string     `json:"path"`
	Kind         string     `json:"kind"`
	Size         int64      `json:"size,omitempty"`
	MountedAs    string     `json:"mountedAs,omitempty"`
	Lazy         bool       `json:"lazy,omitempty"`
	Children     []*webNode `json:"children,omitempty"`
	file         File
	loadChildren func() ([]webArchiveEntry, error)
	loaded       bool
	mountErrors  []string
}

type webTreeNode struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Path        string        `json:"path"`
	Kind        string        `json:"kind"`
	Size        int64         `json:"size,omitempty"`
	MountedAs   string        `json:"mountedAs,omitempty"`
	Lazy        bool          `json:"lazy,omitempty"`
	MountErrors []string      `json:"mountErrors,omitempty"`
	Children    []webTreeNode `json:"children,omitempty"`
}

type webArchiveEntry struct {
	Name         string
	Dir          bool
	Size         int64
	File         File
	Lazy         bool
	loadChildren func() ([]webArchiveEntry, error)
}

func Serve(addr, root string) error {
	return ServeWithOptions(addr, root, ServeOptions{})
}

func ServeWithOptions(addr, root string, options ServeOptions) error {
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", abs)
	}
	listenAddr, err := webListenAddress(addr, options.AllowRemote)
	if err != nil {
		return err
	}
	rootFS, err := os.OpenRoot(abs)
	if err != nil {
		return err
	}
	defer rootFS.Close()
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("generate request token: %w", err)
	}
	server := &webServer{
		rootName:  filepath.Base(abs),
		rootFS:    rootFS,
		remote:    webAddressIsRemote(listenAddr),
		csrfToken: hex.EncodeToString(tokenBytes),
		nodes:     make(map[string]*webNode),
		mounts:    make(map[string]*webNode),
	}
	server.root = server.addNode(&webNode{Name: "Mountpoints", Path: "/", Kind: "dir"})
	hostName := server.rootName
	if hostName == "." || hostName == string(filepath.Separator) {
		hostName = "local"
	}
	server.rootName = hostName
	host := server.scanHostDir(".", hostName, path.Join("/", hostName))
	host.MountedAs = "directory"
	server.root.Children = append(server.root.Children, host)

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleIndex)
	mux.HandleFunc("/api/tree", server.handleTree)
	mux.HandleFunc("/api/children", server.handleChildren)
	mux.HandleFunc("/api/preview", server.handlePreview)
	mux.HandleFunc("/api/mount", server.handleMount)

	displayURL := webDisplayURL(listenAddr)
	if server.remote {
		displayURL += "?token=" + server.csrfToken
	}
	fmt.Fprintf(os.Stderr, "Serving %s at %s\n", abs, displayURL)
	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           webSecurityHeaders(server.authenticate(mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	return httpServer.ListenAndServe()
}

func webAddressIsRemote(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return host == ""
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

func (s *webServer) authenticate(next http.Handler) http.Handler {
	if !s.remote {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := r.URL.Query().Get("token")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(s.csrfToken)) == 1 {
			http.SetCookie(w, &http.Cookie{
				Name:     "trex_archive_access",
				Value:    s.csrfToken,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
			cleaned := *r.URL
			query := cleaned.Query()
			query.Del("token")
			cleaned.RawQuery = query.Encode()
			http.Redirect(w, r, cleaned.String(), http.StatusSeeOther)
			return
		}
		cookie, err := r.Cookie("trex_archive_access")
		if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(s.csrfToken)) != 1 {
			http.Error(w, "archive browser access token required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func webSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func webListenAddress(addr string, allowRemote bool) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid web address %q: %w", addr, err)
	}
	if host == "" && !allowRemote {
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	if allowRemote || strings.EqualFold(host, "localhost") {
		return addr, nil
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return addr, nil
	}
	return "", fmt.Errorf("refusing non-loopback web address %q without explicit remote access", addr)
}

func webDisplayURL(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "http://localhost" + addr + "/"
	}
	return "http://" + addr + "/"
}

func (s *webServer) nextNodeID() string {
	s.nextID++
	return strconv.FormatInt(s.nextID, 10)
}

func (s *webServer) addNode(node *webNode) *webNode {
	node.ID = s.nextNodeID()
	s.nodes[node.ID] = node
	return node
}

func (s *webServer) scanHostDir(dir, name, displayPath string) *webNode {
	node := s.addNode(&webNode{Name: name, Path: displayPath, Kind: "dir"})
	directory, err := s.rootFS.Open(dir)
	if err != nil {
		node.mountErrors = append(node.mountErrors, err.Error())
		return node
	}
	entries, err := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err != nil {
		node.mountErrors = append(node.mountErrors, err.Error())
		return node
	}
	if closeErr != nil {
		node.mountErrors = append(node.mountErrors, closeErr.Error())
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return strings.ToLower(entries[i].Name()) < strings.ToLower(entries[j].Name())
	})
	for _, entry := range entries {
		if len(s.nodes) >= webNodeLimit {
			node.mountErrors = append(node.mountErrors, fmt.Sprintf("node limit of %d reached", webNodeLimit))
			break
		}
		full := filepath.Join(dir, entry.Name())
		childPath := path.Join(displayPath, entry.Name())
		info, err := s.rootFS.Lstat(full)
		if err != nil {
			node.mountErrors = append(node.mountErrors, fmt.Sprintf("%s: %v", entry.Name(), err))
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			node.mountErrors = append(node.mountErrors, fmt.Sprintf("%s: symbolic link omitted", entry.Name()))
			continue
		}
		if info.IsDir() {
			node.Children = append(node.Children, s.scanHostDir(full, entry.Name(), childPath))
			continue
		}
		if !info.Mode().IsRegular() {
			node.mountErrors = append(node.mountErrors, fmt.Sprintf("%s: non-regular file omitted", entry.Name()))
			continue
		}
		node.Children = append(node.Children, s.addNode(&webNode{
			Name: entry.Name(),
			Path: childPath,
			Kind: "file",
			Size: info.Size(),
			file: &localReadFile{root: s.rootFS, name: full, size: info.Size()},
		}))
	}
	return node
}

func (s *webServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = webIndexTemplate.Execute(w, map[string]string{"Root": s.rootName, "Token": s.csrfToken})
}

func (s *webServer) handleTree(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	tree := cloneWebTree(s.root)
	s.mu.RUnlock()
	writeJSON(w, tree)
}

func (s *webServer) handleChildren(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	node := s.nodes[id]
	if node == nil || node.Kind != "dir" {
		http.Error(w, "directory not found", http.StatusNotFound)
		return
	}
	if err := s.loadWebNodeChildren(node); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, cloneWebTree(node))
}

func (s *webServer) handlePreview(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "hex"
	}
	s.mu.RLock()
	node := s.nodes[id]
	s.mu.RUnlock()
	if node == nil || node.file == nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	switch mode {
	case "hex":
		data, truncated, err := readPreviewBytes(node.file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"name":      node.Name,
			"path":      node.Path,
			"size":      node.file.Size(),
			"truncated": truncated,
			"content":   hex.Dump(data),
		})
	case "text":
		data, truncated, err := readPreviewBytes(node.file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"name":      node.Name,
			"path":      node.Path,
			"size":      node.file.Size(),
			"truncated": truncated,
			"content":   string(bytes.ToValidUTF8(data, []byte("\ufffd"))),
		})
	case "utf16":
		data, truncated, err := readPreviewBytes(node.file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(data)%2 != 0 {
			data = data[:len(data)-1]
		}
		writeJSON(w, map[string]any{
			"name":      node.Name,
			"path":      node.Path,
			"size":      node.file.Size(),
			"truncated": truncated,
			"content":   strings.TrimRight(windowsapi.DecodeUTF16LE(data), "\x00"),
		})
	case "inf":
		inf, err := infView(node.file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"name": node.Name, "path": node.Path, "content": inf})
	case "hive":
		view, err := hiveView(node.file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"name": node.Name, "path": node.Path, "content": view})
	default:
		http.Error(w, "unknown preview mode", http.StatusBadRequest)
	}
}

func (s *webServer) handleMount(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	format := r.URL.Query().Get("format")
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Trex-CSRF")), []byte(s.csrfToken)) != 1 {
		http.Error(w, "invalid request token", http.StatusForbidden)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	node := s.nodes[id]
	if node == nil || node.file == nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	mountKey := id + "\x00" + format
	if mount := s.mounts[mountKey]; mount != nil {
		writeJSON(w, cloneWebTree(mount))
		return
	}
	if len(s.mounts) >= webMountLimit {
		http.Error(w, fmt.Sprintf("mount limit of %d reached", webMountLimit), http.StatusTooManyRequests)
		return
	}
	if format == "wim" {
		archive, err := wim.Open(node.file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mount := s.addMountPoint(node, format)
		if err := s.addWIMMountEntries(mount, archive); err != nil {
			s.removeMountPoint(mount)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		node.MountedAs = format
		node.mountErrors = nil
		s.mounts[mountKey] = mount
		writeJSON(w, cloneWebTree(mount))
		return
	}
	entries, err := mountWebArchive(format, node.file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.ensureNodeCapacity(1 + webArchiveEntryNodeCount(entries)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	node.MountedAs = format
	node.mountErrors = nil
	mount := s.addMountPoint(node, format)
	s.addArchiveEntries(mount, entries)
	s.mounts[mountKey] = mount
	writeJSON(w, cloneWebTree(mount))
}

func (s *webServer) addMountPoint(source *webNode, format string) *webNode {
	baseName := fmt.Sprintf("%s (%s)", source.Name, format)
	name := s.uniqueMountPointName(baseName)
	mount := s.addNode(&webNode{
		Name:      name,
		Path:      path.Join("/", name),
		Kind:      "dir",
		MountedAs: format,
	})
	s.root.Children = append(s.root.Children, mount)
	return mount
}

func (s *webServer) removeMountPoint(mount *webNode) {
	delete(s.nodes, mount.ID)
	for index, child := range s.root.Children {
		if child == mount {
			s.root.Children = append(s.root.Children[:index], s.root.Children[index+1:]...)
			break
		}
	}
}

func (s *webServer) ensureNodeCapacity(additional int) error {
	if additional < 0 || len(s.nodes) > webNodeLimit-additional {
		return fmt.Errorf("node limit of %d would be exceeded", webNodeLimit)
	}
	return nil
}

func webArchiveEntryNodeCount(entries []webArchiveEntry) int {
	directories := map[string]struct{}{"/": {}}
	files := 0
	for _, entry := range entries {
		cleaned := storage.CleanPath(entry.Name)
		if cleaned == "/" {
			continue
		}
		directory := cleaned
		if !entry.Dir {
			files++
			directory = path.Dir(cleaned)
		}
		for directory != "/" {
			directories[directory] = struct{}{}
			directory = path.Dir(directory)
		}
	}
	return len(directories) - 1 + files
}

func (s *webServer) uniqueMountPointName(baseName string) string {
	existing := make(map[string]struct{}, len(s.root.Children))
	for _, child := range s.root.Children {
		existing[child.Name] = struct{}{}
	}
	if _, ok := existing[baseName]; !ok {
		return baseName
	}
	for i := 2; ; i++ {
		name := fmt.Sprintf("%s %d", baseName, i)
		if _, ok := existing[name]; !ok {
			return name
		}
	}
}

func (s *webServer) addArchiveEntries(parent *webNode, entries []webArchiveEntry) {
	byPath := map[string]*webNode{"/": parent}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Dir != entries[j].Dir {
			return entries[i].Dir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	for _, entry := range entries {
		cleaned := storage.CleanPath(entry.Name)
		if cleaned == "/" {
			continue
		}
		if entry.Dir {
			dir := ensureWebDir(s, byPath, parent, cleaned)
			if entry.Lazy {
				dir.Lazy = true
				dir.loaded = false
				dir.loadChildren = entry.loadChildren
			}
			continue
		}
		dir := ensureWebDir(s, byPath, parent, path.Dir(cleaned))
		dir.Children = append(dir.Children, s.addNode(&webNode{
			Name: path.Base(cleaned),
			Path: path.Join(parent.Path, cleaned),
			Kind: "file",
			Size: entry.Size,
			file: entry.File,
		}))
	}
	sortWebChildren(parent)
}

func (s *webServer) loadWebNodeChildren(node *webNode) error {
	if node.loaded || node.loadChildren == nil {
		return nil
	}
	entries, err := node.loadChildren()
	if err != nil {
		node.mountErrors = []string{err.Error()}
		node.loaded = true
		return err
	}
	if err := s.ensureNodeCapacity(webArchiveEntryNodeCount(entries)); err != nil {
		node.mountErrors = []string{err.Error()}
		return err
	}
	node.Children = nil
	s.addArchiveEntries(node, entries)
	node.loaded = true
	node.Lazy = false
	return nil
}

func ensureWebDir(s *webServer, byPath map[string]*webNode, root *webNode, name string) *webNode {
	name = storage.CleanPath(name)
	if node := byPath[name]; node != nil {
		return node
	}
	parent := ensureWebDir(s, byPath, root, path.Dir(name))
	node := s.addNode(&webNode{
		Name: path.Base(name),
		Path: path.Join(root.Path, name),
		Kind: "dir",
	})
	parent.Children = append(parent.Children, node)
	byPath[name] = node
	return node
}

func sortWebChildren(node *webNode) {
	sort.Slice(node.Children, func(i, j int) bool {
		a, b := node.Children[i], node.Children[j]
		if (a.Kind == "dir") != (b.Kind == "dir") {
			return a.Kind == "dir"
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	for _, child := range node.Children {
		sortWebChildren(child)
	}
}

func mountWebArchive(format string, file File) ([]webArchiveEntry, error) {
	switch format {
	case "zip":
		reader, err := zip.NewReader(file, file.Size())
		if err != nil {
			return nil, err
		}
		entries := make([]webArchiveEntry, 0, len(reader.File))
		for _, entry := range reader.File {
			if entry.FileInfo().IsDir() {
				entries = append(entries, webArchiveEntry{Name: entry.Name, Dir: true})
				continue
			}
			entries = append(entries, webArchiveEntry{
				Name: entry.Name,
				Size: int64(entry.UncompressedSize64),
				File: ziparchive.NewEntry(entry),
			})
		}
		return entries, nil
	case "cab":
		cab, err := cabarchive.Open(file, true)
		if err != nil {
			return nil, err
		}
		files := cab.Files()
		entries := make([]webArchiveEntry, 0, len(files))
		for _, entry := range files {
			file, err := cab.Lookup(entry.Name)
			if err != nil {
				return nil, err
			}
			entries = append(entries, webArchiveEntry{
				Name: entry.Name,
				Size: entry.Size,
				File: file,
			})
		}
		return entries, nil
	case "iso9660":
		entries, err := filesystemiso9660.Entries(file)
		return webFilesystemEntries(entries), err
	case "hive":
		entries, err := windowsapi.HiveEntries(file)
		if err != nil {
			return nil, err
		}
		result := make([]webArchiveEntry, len(entries))
		for index, entry := range entries {
			result[index] = webArchiveEntry{Name: entry.Name, Dir: entry.Directory, File: entry.File}
			if entry.File != nil {
				result[index].Size = entry.File.Size()
			}
		}
		return result, nil
	case "fat":
		entries, err := filesystemfat.Entries(file)
		return webFilesystemEntries(entries), err
	case "udf":
		entries, err := filesystemudf.Entries(file)
		return webFilesystemEntries(entries), err
	default:
		return nil, fmt.Errorf("unknown archive format %q", format)
	}
}

func webFilesystemEntries(entries []filesystemapi.ArchiveEntry) []webArchiveEntry {
	result := make([]webArchiveEntry, len(entries))
	for index, entry := range entries {
		result[index] = webArchiveEntry{Name: entry.Name, Size: entry.Size, Dir: entry.Directory, File: entry.File}
	}
	return result
}

func (s *webServer) addWIMMountEntries(parent *webNode, archive *wim.Archive) error {
	resources := archive.MetadataFiles()
	roots, err := archive.List("/")
	if err != nil {
		return err
	}
	if err := s.ensureNodeCapacity(1 + len(resources) + len(roots)); err != nil {
		return err
	}
	metadata := s.addNode(&webNode{Name: "$metadata", Path: path.Join(parent.Path, "$metadata"), Kind: "dir"})
	parent.Children = append(parent.Children, metadata)
	for _, resource := range resources {
		metadata.Children = append(metadata.Children, s.addNode(&webNode{
			Name: path.Base(resource.Name),
			Path: path.Join(parent.Path, strings.TrimPrefix(resource.Name, "/")),
			Kind: "file",
			Size: resource.File.Size(),
			file: resource.File,
		}))
	}
	for _, root := range roots {
		parent.Children = append(parent.Children, s.addWIMDirNode(parent, archive, root))
	}
	sortWebChildren(parent)
	return nil
}

func (s *webServer) addWIMDirNode(parent *webNode, archive *wim.Archive, entry wim.EntryInfo) *webNode {
	node := s.addNode(&webNode{
		Name: entry.Name,
		Path: path.Join(parent.Path, strings.TrimPrefix(entry.Path, "/")),
		Kind: "dir",
		Lazy: true,
	})
	node.loadChildren = func() ([]webArchiveEntry, error) {
		return webWIMDirEntries(archive, entry.Path)
	}
	return node
}

func webWIMDirEntries(archive *wim.Archive, directory string) ([]webArchiveEntry, error) {
	children, err := archive.List(directory)
	if err != nil {
		return nil, err
	}
	entries := make([]webArchiveEntry, 0, len(children))
	for _, child := range children {
		if child.Directory {
			child := child
			entries = append(entries, webArchiveEntry{
				Name: "/" + child.Name,
				Dir:  true,
				Lazy: true,
				loadChildren: func() ([]webArchiveEntry, error) {
					return webWIMDirEntries(archive, child.Path)
				},
			})
			continue
		}
		file, err := archive.OpenFile(child.Path)
		if err != nil {
			return nil, err
		}
		entries = append(entries, webArchiveEntry{
			Name: "/" + child.Name,
			Size: child.Size,
			File: file,
		})
	}
	return entries, nil
}

func readPreviewBytes(file File) ([]byte, bool, error) {
	size := file.Size()
	if size < 0 {
		return nil, false, fmt.Errorf("negative file size")
	}
	limit := size
	truncated := false
	if limit > webPreviewLimit {
		limit = webPreviewLimit
		truncated = true
	}
	data := make([]byte, limit)
	if _, err := file.ReadAt(data, 0); err != nil && err != io.EOF {
		return nil, false, err
	}
	return data, truncated, nil
}

func infView(file File) (string, error) {
	return windowsapi.INFJSON(file)
}

func hiveView(file File) (string, error) {
	return windowsapi.HiveJSON(file, 3)
}

func cloneWebTree(node *webNode) webTreeNode {
	out := webTreeNode{
		ID:          node.ID,
		Name:        node.Name,
		Path:        node.Path,
		Kind:        node.Kind,
		Size:        node.Size,
		MountedAs:   node.MountedAs,
		Lazy:        node.Lazy,
		MountErrors: append([]string(nil), node.mountErrors...),
	}
	if len(node.Children) > 0 {
		out.Children = make([]webTreeNode, len(node.Children))
		for i, child := range node.Children {
			out.Children[i] = cloneWebTree(child)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

type localReadFile struct {
	root *os.Root
	name string
	size int64
}

func (f *localReadFile) ReadAt(p []byte, off int64) (int, error) {
	file, err := f.root.Open(f.name)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	return file.ReadAt(p, off)
}
func (f *localReadFile) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("%s is read-only", f.name)
}
func (f *localReadFile) Size() int64          { return f.size }
func (f *localReadFile) String() string       { return fmt.Sprintf("<file %q>", f.name) }
func (f *localReadFile) Type() string         { return "file" }
func (f *localReadFile) Freeze()              {}
func (f *localReadFile) Truth() starlark.Bool { return starlark.True }
func (f *localReadFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *localReadFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *localReadFile) AttrNames() []string { return starfile.AttrNames() }

type memoryReadFile struct {
	name string
	data []byte
}

func (f *memoryReadFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (f *memoryReadFile) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("%s is read-only", f.name)
}
func (f *memoryReadFile) Size() int64          { return int64(len(f.data)) }
func (f *memoryReadFile) String() string       { return fmt.Sprintf("<file %q>", f.name) }
func (f *memoryReadFile) Type() string         { return "file" }
func (f *memoryReadFile) Freeze()              {}
func (f *memoryReadFile) Truth() starlark.Bool { return starlark.True }
func (f *memoryReadFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *memoryReadFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *memoryReadFile) AttrNames() []string { return starfile.AttrNames() }

var webIndexTemplate = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="trex-csrf-token" content="{{.Token}}">
  <title>trex archive browser</title>
  <style>
    :root { color-scheme: light; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    html, body { height: 100%; overflow: hidden; }
    body { margin: 0; background: #f6f7f9; color: #20242c; }
    header { height: 48px; display: flex; align-items: center; gap: 16px; padding: 0 18px; border-bottom: 1px solid #d9dde5; background: #ffffff; }
    header strong { font-size: 15px; }
    header span { color: #5d6676; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    main { display: grid; grid-template-columns: minmax(280px, 34vw) minmax(0, 1fr); height: calc(100vh - 49px); min-height: 0; overflow: hidden; }
    aside { min-height: 0; overflow: auto; border-right: 1px solid #d9dde5; background: #ffffff; padding: 10px; overscroll-behavior: contain; }
    section { min-width: 0; min-height: 0; display: grid; grid-template-rows: auto minmax(0, 1fr); overflow: hidden; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 8px; padding: 10px; border-bottom: 1px solid #d9dde5; background: #ffffff; }
    button { border: 1px solid #b9c0cb; background: #ffffff; color: #20242c; border-radius: 6px; padding: 6px 10px; font-size: 13px; cursor: pointer; }
    button:hover { background: #edf1f7; }
    button:disabled { opacity: .45; cursor: default; }
    pre { min-height: 0; margin: 0; padding: 14px; overflow: auto; font: 12px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; white-space: pre-wrap; overscroll-behavior: contain; }
    .tree ul { list-style: none; padding-left: 17px; margin: 0; }
    .tree ul.collapsed { display: none; }
    .tree li { margin: 1px 0; }
    .node { width: 100%; display: grid; grid-template-columns: 18px 1fr auto; gap: 4px; align-items: center; border: 0; background: transparent; padding: 3px 4px; text-align: left; }
    .node:hover, .node.selected { background: #e8edf5; }
    .twisty { color: #6d7582; font-size: 11px; text-align: center; }
    .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .meta { color: #6d7582; font-size: 11px; }
    .dir .name { font-weight: 600; }
    .error { color: #9b1c1c; padding: 12px; }
    @media (max-width: 760px) {
      main { grid-template-columns: 1fr; grid-template-rows: minmax(160px, 42vh) minmax(0, 1fr); }
      aside { border-right: 0; border-bottom: 1px solid #d9dde5; }
    }
  </style>
</head>
<body>
  <header><strong>trex</strong><span>{{.Root}}</span></header>
  <main>
    <aside><div id="tree" class="tree"></div></aside>
    <section>
      <div class="toolbar">
        <button id="hex" disabled>Hexdump</button>
        <button id="text" disabled>Text</button>
        <button id="utf16" disabled>UTF-16</button>
        <button id="inf" disabled>INF JSON</button>
        <button id="hive" disabled>Hive JSON</button>
        <button id="zip" disabled>Mount ZIP</button>
        <button id="cab" disabled>Mount CAB</button>
        <button id="wim" disabled>Mount WIM</button>
        <button id="iso9660" disabled>Mount ISO9660</button>
        <button id="fat" disabled>Mount FAT</button>
        <button id="udf" disabled>Mount UDF</button>
        <button id="mountHive" disabled>Mount Hive</button>
      </div>
      <pre id="preview">Select a file to preview or mount it.</pre>
    </section>
  </main>
<script>
let selected = null;
let selectedButton = null;
let rootChildList = null;
const treeEl = document.getElementById('tree');
const previewEl = document.getElementById('preview');
const csrfToken = document.querySelector('meta[name="trex-csrf-token"]').content;
const actions = ['hex', 'text', 'utf16', 'inf', 'hive', 'zip', 'cab', 'wim', 'iso9660', 'fat', 'udf', 'mountHive'];

async function loadTree() {
  const res = await fetch('/api/tree');
  renderTree(await res.json());
}

function renderTree(root) {
  treeEl.innerHTML = '';
  const ul = document.createElement('ul');
  ul.appendChild(renderNode(root));
  treeEl.appendChild(ul);
}

function renderNode(node) {
  const li = document.createElement('li');
  const button = document.createElement('button');
  button.className = 'node ' + node.kind;
  button.dataset.id = node.id;
  const twisty = document.createElement('span');
  twisty.className = 'twisty';
  const hasChildren = node.lazy || (node.children && node.children.length);
  twisty.textContent = hasChildren ? 'v' : '';
  const name = document.createElement('span');
  name.className = 'name';
  name.textContent = node.name || '/';
  const meta = document.createElement('span');
  meta.className = 'meta';
  meta.textContent = node.kind === 'file' ? formatSize(node.size || 0) : (node.mountedAs ? node.mountedAs : '');
  button.append(twisty, name, meta);
  button.onclick = () => selectNode(node, button, childList, twisty);
  li.appendChild(button);
  if (node.mountErrors) {
    for (const err of node.mountErrors) {
      const div = document.createElement('div');
      div.className = 'error';
      div.textContent = err;
      li.appendChild(div);
    }
  }
  let childList = null;
  if (hasChildren) {
    childList = document.createElement('ul');
    if (node.path === '/') rootChildList = childList;
    if (node.path !== '/') {
      childList.classList.add('collapsed');
      twisty.textContent = '>';
    }
    if (node.children) {
      for (const child of node.children) childList.appendChild(renderNode(child));
    }
    li.appendChild(childList);
  }
  return li;
}

async function selectNode(node, button, childList, twisty) {
  selected = node;
  if (selectedButton) selectedButton.classList.remove('selected');
  selectedButton = button;
  selectedButton.classList.add('selected');
  for (const id of actions) document.getElementById(id).disabled = node.kind !== 'file';
  if (childList) {
    if (node.lazy && !node.childrenLoaded) {
      twisty.textContent = '...';
      try {
        const loaded = await loadChildren(node.id);
        node.children = loaded.children || [];
        node.lazy = loaded.lazy;
        node.childrenLoaded = true;
        childList.innerHTML = '';
        for (const child of node.children) childList.appendChild(renderNode(child));
      } catch (err) {
        previewEl.textContent = String(err);
      }
    }
    const collapsed = childList.classList.toggle('collapsed');
    twisty.textContent = collapsed ? '>' : 'v';
  }
  if (node.kind === 'file') preview('hex');
}

async function loadChildren(id) {
  const res = await fetch('/api/children?id=' + encodeURIComponent(id));
  const body = await res.text();
  if (!res.ok) throw new Error(body);
  return JSON.parse(body);
}

async function preview(mode) {
  if (!selected) return;
  previewEl.textContent = 'Loading...';
  const res = await fetch('/api/preview?id=' + encodeURIComponent(selected.id) + '&mode=' + encodeURIComponent(mode));
  const body = await res.text();
  if (!res.ok) {
    previewEl.textContent = body;
    return;
  }
  const data = JSON.parse(body);
  previewEl.textContent = (data.truncated ? '[preview truncated]\n\n' : '') + data.content;
}

async function mount(format) {
  if (!selected) return;
  previewEl.textContent = 'Mounting ' + format + '...';
  const res = await fetch('/api/mount?id=' + encodeURIComponent(selected.id) + '&format=' + encodeURIComponent(format), {
    method: 'POST',
    headers: {'X-Trex-CSRF': csrfToken},
  });
  if (!res.ok) {
    previewEl.textContent = await res.text();
    return;
  }
  const mountPoint = await res.json();
  appendMountPoint(mountPoint);
  previewEl.textContent = 'Mounted as ' + format + '.';
}

function appendMountPoint(mountPoint) {
  const target = rootChildList || treeEl.querySelector('ul ul');
  if (!target) {
    loadTree().catch(err => previewEl.textContent = err);
    return;
  }
  target.appendChild(renderNode(mountPoint));
}

function formatSize(size) {
  if (size < 1024) return size + ' B';
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = size / 1024;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) { value /= 1024; idx++; }
  return value.toFixed(value >= 10 ? 1 : 2) + ' ' + units[idx];
}

document.getElementById('hex').onclick = () => preview('hex');
document.getElementById('text').onclick = () => preview('text');
document.getElementById('utf16').onclick = () => preview('utf16');
document.getElementById('inf').onclick = () => preview('inf');
document.getElementById('hive').onclick = () => preview('hive');
document.getElementById('zip').onclick = () => mount('zip');
document.getElementById('cab').onclick = () => mount('cab');
document.getElementById('wim').onclick = () => mount('wim');
document.getElementById('iso9660').onclick = () => mount('iso9660');
document.getElementById('fat').onclick = () => mount('fat');
document.getElementById('udf').onclick = () => mount('udf');
document.getElementById('mountHive').onclick = () => mount('hive');
loadTree().catch(err => previewEl.textContent = err);
</script>
</body>
</html>`))

var _ File = (*localReadFile)(nil)
var _ File = (*memoryReadFile)(nil)
