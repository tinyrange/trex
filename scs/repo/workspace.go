package repo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

var (
	ErrReadOnly = errors.New("workspace is read-only")
	ErrConflict = errors.New("workspace root changed; reopen before publishing")
)

// Times stores nanoseconds since the Unix epoch. Absent metadata reads as epoch.
type Times struct {
	A int64 `json:"a"`
	M int64 `json:"m"`
	C int64 `json:"c"`
}

type Entry struct {
	Times  Times  `json:"times,omitzero"`
	Body   ID     `json:"body,omitempty"`
	GitOID string `json:"git_oid,omitempty"`
	Kind   string `json:"kind"` // file, dir, symlink, gitlink
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size,omitempty"`
	Blocks []ID   `json:"blocks,omitempty"`
}
type child struct {
	parent ID
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode"`
	ID     ID     `json:"id"`
}
type tree struct {
	Times Times `json:"times,omitzero"`
	Index ID    `json:"index"`
}
type snapshot struct {
	Tree         ID     `json:"tree"`
	SourceCommit string `json:"source_commit,omitempty"`
}
type state struct {
	loadErr  error
	mu       sync.Mutex
	root     *node
	snapshot ID // nonempty only after this exact state is durable
	source   string
	name     string
	base     ID
}

// Workspace is a capability over live tree state. Readonly shares that live state;
// Fork creates independent state. File block slices are immutable once installed.
type Workspace struct {
	r        *Repository
	s        *state
	readonly bool
}

func validName(n string) bool {
	if n == "" || len(n) > 255 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return n != "." && n != ".."
}
func clean(p string) (string, error) {
	if !utf8.ValidString(p) || strings.ContainsAny(p, "\x00\\") || strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("invalid workspace-relative path %q", p)
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return "", errors.New("parent traversal is not allowed")
		}
	}
	p = path.Clean(p)
	if len(p) > 4096 || strings.Count(p, "/") > 255 {
		return "", errors.New("path exceeds MVP depth/length limit")
	}
	return p, nil
}
func (r *Repository) Empty() *Workspace {
	return &Workspace{r: r, s: &state{root: &node{entry: Entry{Kind: "dir", Mode: 0755}}}}
}
func (r *Repository) Checkout(name string) (*Workspace, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return nil, err
	}
	id, ok := r.refs[name]
	if !ok {
		return nil, fmt.Errorf("unknown workspace %q", name)
	}
	w, err := r.load(id)
	if err != nil {
		return nil, err
	}
	w.s.name = name
	w.s.base = id
	return w, nil
}
func (r *Repository) Fork(id ID) (*Workspace, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.load(id)
}
func (r *Repository) load(id ID) (*Workspace, error) {
	var sn snapshot
	if err := r.getJSON(id, snapshotKind, &sn); err != nil {
		return nil, err
	}
	if !r.earlier(sn.Tree, id) {
		return nil, errors.New("snapshot tree must precede snapshot")
	}
	if r.fast != nil {
		return &Workspace{r: r, s: &state{root: &node{entry: Entry{Kind: "dir", Mode: 0755}, id: sn.Tree, lazy: true}, source: sn.SourceCommit}}, nil
	}
	var visit func(ID, string, uint32, int) (*node, error)
	visit = func(id ID, p string, mode uint32, depth int) (*node, error) {
		if depth > 256 {
			return nil, errors.New("tree depth limit exceeded")
		}
		var t tree
		if err := r.getJSON(id, treeKind, &t); err != nil {
			return nil, err
		}
		n := &node{entry: Entry{Kind: "dir", Mode: mode, Times: t.Times}, id: id}
		if t.Index == "" {
			return n, nil
		}
		if !r.earlier(t.Index, id) {
			return nil, errors.New("directory index must precede tree")
		}
		index, err := r.loadIndex(t.Index, 0, [32]byte{}, func(c child) (*node, error) {
			if c.Name == "" || strings.Contains(c.Name, "/") || c.Name == "." || c.Name == ".." || c.Mode > 0777 {
				return nil, errors.New("invalid tree entry")
			}
			q := path.Join(p, c.Name)
			if _, err := clean(q); err != nil {
				return nil, err
			}
			if c.Kind == "dir" {
				return visit(c.ID, q, c.Mode, depth+1)
			}
			var e Entry
			if err := r.getJSON(c.ID, fileKind, &e); err != nil {
				return nil, err
			}
			if e.Kind != c.Kind || e.Mode != c.Mode || e.Size < 0 || e.Body == "" && int64(len(e.Blocks)) != e.Size/BlockSize+boolInt(e.Size%BlockSize != 0) {
				return nil, errors.New("invalid file descriptor")
			}
			if e.Body != "" {
				loc, ok := r.lookupObject(key(e.Body))
				if !ok || loc.kind != bodyKind || int64(loc.size) != e.Size || len(e.Blocks) != 0 || !r.earlier(e.Body, c.ID) || e.Kind == "gitlink" {
					return nil, errors.New("invalid file body")
				}
			}
			if e.Kind == "gitlink" {
				if _, err := ParseGitOID(e.GitOID); err != nil || e.Size != 0 || len(e.Blocks) != 0 || e.Mode != 0 {
					return nil, errors.New("invalid gitlink")
				}
			} else if e.GitOID != "" {
				return nil, errors.New("unexpected gitlink ID")
			}
			for i, b := range e.Blocks {
				loc, ok := r.lookupObject(key(b))
				expected := BlockSize
				if i == len(e.Blocks)-1 && e.Size%BlockSize != 0 {
					expected = int(e.Size % BlockSize)
				}
				if !ok || loc.kind != blockKind || loc.size != expected || !r.earlier(b, c.ID) {
					return nil, errors.New("missing or invalid file block")
				}
			}
			return &node{entry: e, id: c.ID}, nil
		})
		if err != nil {
			return nil, err
		}
		n.children = index
		return n, nil
	}
	root, err := visit(sn.Tree, ".", 0755, 0)
	if err != nil {
		return nil, err
	}
	// Loaded records might have survived a failed sync in another process. Sync
	// on the first Snapshot rather than assuming that reading implies durability.
	return &Workspace{r: r, s: &state{root: root, source: sn.SourceCommit}}, nil
}
func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
func (w *Workspace) Readonly() *Workspace { return &Workspace{r: w.r, s: w.s, readonly: true} }
func (w *Workspace) IsReadOnly() bool     { return w.readonly }
func (w *Workspace) parent(p string) error {
	e, ok := w.s.get(path.Dir(p))
	if !ok || e.Kind != "dir" {
		return fmt.Errorf("parent is not a directory: %s", path.Dir(p))
	}
	return nil
}
func (w *Workspace) Stat(p string) (Entry, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	p, err := clean(p)
	if err != nil {
		return Entry{}, err
	}
	if err := w.prepare(p, false); err != nil {
		return Entry{}, err
	}
	e, ok := w.s.get(p)
	if !ok {
		return Entry{}, fmt.Errorf("%w: %s", fs.ErrNotExist, p)
	}
	e.Blocks = append([]ID(nil), e.Blocks...)
	return e, nil
}
func (w *Workspace) ListDir(p string) ([]string, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	p, err := clean(p)
	if err != nil {
		return nil, err
	}
	if err := w.prepare(p, false); err != nil {
		return nil, err
	}
	e, ok := w.s.get(p)
	if !ok || e.Kind != "dir" {
		return nil, fmt.Errorf("not a directory: %s", p)
	}
	out := make([]string, 0, count(findNode(w.s.root, p).children))
	eachChild(findNode(w.s.root, p).children, func(name string, _ *node) error {
		out = append(out, name)
		return nil
	})
	return out, nil
}

// Paths returns all non-root paths in sorted order, including directories.
// Paths is the compatibility wrapper; use PathsWithError to report deferred
// metadata corruption. It never returns a partially enumerated tree.
func (w *Workspace) Paths() []string { paths, _ := w.PathsWithError(); return paths }
func (w *Workspace) PathsWithError() ([]string, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if err := w.prepare(".", true); err != nil {
		return nil, err
	}
	out := []string{}
	walkNodes(w.s.root, ".", func(p string, _ *node) error {
		out = append(out, p)
		return nil
	})
	sort.Strings(out)
	return out, nil
}
func (w *Workspace) read(p, kind string) ([]byte, error) {
	p, err := clean(p)
	if err != nil {
		return nil, err
	}
	if err := w.prepare(p, false); err != nil {
		return nil, err
	}
	e, ok := w.s.get(p)
	if !ok || e.Kind != kind {
		return nil, fmt.Errorf("not a %s: %s (symlinks are not followed)", kind, p)
	}
	var b bytes.Buffer
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if e.Body != "" {
		return w.r.get(e.Body, bodyKind)
	}
	for _, id := range e.Blocks {
		data, err := w.r.get(id, blockKind)
		if err != nil {
			return nil, err
		}
		b.Write(data)
	}
	if int64(b.Len()) != e.Size {
		return nil, errors.New("file size mismatch")
	}
	return b.Bytes(), nil
}
func (w *Workspace) ReadFile(p string) ([]byte, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return w.read(p, "file")
}
func (w *Workspace) Readlink(p string) (string, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	b, e := w.read(p, "symlink")
	return string(b), e
}
func (w *Workspace) write(p string, input io.Reader, kind string, mode uint32) error {
	if w.readonly {
		return ErrReadOnly
	}
	p, err := clean(p)
	if err != nil {
		return err
	}
	if err := w.prepare(p, false); err != nil {
		return err
	}
	if p == "." {
		return errors.New("cannot replace root")
	}
	if err = w.parent(p); err != nil {
		return err
	}
	if old, ok := w.s.get(p); ok {
		if old.Kind != kind {
			return fmt.Errorf("cannot overwrite %s with %s", old.Kind, kind)
		}
		mode = old.Mode
	}
	e := Entry{Kind: kind, Mode: mode}
	if old, ok := w.s.get(p); ok {
		e.Times = old.Times
	}
	w.r.mu.Lock()
	if err := w.r.ready(); err != nil {
		w.r.mu.Unlock()
		return err
	}
	optimized := w.r.optimized
	w.r.mu.Unlock()

	// Source readers can themselves borrow this repository (slices/composites).
	// Never call arbitrary input.Read while holding Repository.mu. The workspace
	// lock still keeps the old entry visible until the complete new entry exists.
	if optimized {
		data, err := io.ReadAll(io.LimitReader(input, (16<<20)+1))
		if err != nil {
			return err
		}
		if len(data) <= 16<<20 {
			w.r.mu.Lock()
			defer w.r.mu.Unlock()
			if err := w.r.ready(); err != nil {
				return err
			}
			var base ID
			var extents []Extent
			if old, ok := w.s.get(p); ok && old.Body != "" {
				base = old.Body
				b, err := w.r.borrowBody(base)
				if err != nil {
					return err
				}
				extents = editExtents(b, data)
			}
			id, err := w.r.putBody(data, base, extents)
			if err != nil {
				return err
			}
			e.Body = id
			e.Size = int64(len(data))
			w.s.set(p, &node{entry: e})
			return nil
		}
		input = io.MultiReader(bytes.NewReader(data), input)
	}
	buf := make([]byte, BlockSize)
	for {
		n, err := io.ReadFull(input, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		if n > 0 {
			w.r.mu.Lock()
			writeErr := w.r.ready()
			var id ID
			if writeErr == nil {
				id, writeErr = w.r.append(blockKind, buf[:n])
			}
			w.r.mu.Unlock()
			if writeErr != nil {
				return writeErr
			}
			e.Blocks = append(e.Blocks, id)
			e.Size += int64(n)
		}
		if err != nil {
			break
		}
	}
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if err := w.r.ready(); err != nil {
		return err
	}
	w.s.set(p, &node{entry: e})
	return nil
}
func (w *Workspace) WriteFile(p string, data []byte) error {
	return w.WriteFrom(p, bytes.NewReader(data))
}

// WriteFrom ingests a stream without materializing the whole file. Visibility is
// atomic at method completion; failed ingestion leaves the old entry unchanged.
func (w *Workspace) WriteFrom(p string, input io.Reader) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return w.write(p, input, "file", 0644)
}
func (w *Workspace) Symlink(p, target string) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return w.write(p, strings.NewReader(target), "symlink", 0777)
}
func (w *Workspace) Replace(p, old, new string) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return ErrReadOnly
	}
	if old == "" {
		return errors.New("replacement target must not be empty")
	}
	b, err := w.read(p, "file")
	if err != nil {
		return err
	}
	if !bytes.Contains(b, []byte(old)) {
		return errors.New("replacement target not found")
	}
	return w.write(p, bytes.NewReader(bytes.ReplaceAll(b, []byte(old), []byte(new))), "file", 0644)
}
func (w *Workspace) Mkdir(p string) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return ErrReadOnly
	}
	p, err := clean(p)
	if err != nil {
		return err
	}
	if err := w.prepare(p, false); err != nil {
		return err
	}
	if _, ok := w.s.get(p); ok {
		return errors.New("path already exists")
	}
	if err = w.parent(p); err != nil {
		return err
	}
	w.s.set(p, &node{entry: Entry{Kind: "dir", Mode: 0755}})
	return nil
}
func (w *Workspace) Delete(p string) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return ErrReadOnly
	}
	p, err := clean(p)
	if err != nil {
		return err
	}
	if err := w.prepare(p, false); err != nil {
		return err
	}
	if p == "." {
		return errors.New("cannot delete root")
	}
	if _, ok := w.s.get(p); !ok {
		return errors.New("path not found")
	}
	if findNode(w.s.root, p).children != nil {
		return errors.New("directory is not empty")
	}
	w.s.set(p, nil)
	return nil
}

// Rename never replaces an existing destination, and moves directories atomically.
func (w *Workspace) Rename(old, new string) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return ErrReadOnly
	}
	old, err := clean(old)
	if err != nil {
		return err
	}
	new, err = clean(new)
	if err != nil {
		return err
	}
	if err := w.prepare(old, true); err != nil {
		return err
	}
	if err := w.prepare(new, false); err != nil {
		return err
	}
	if old == "." || new == "." {
		return errors.New("cannot rename root")
	}
	if _, ok := w.s.get(old); !ok {
		return errors.New("source not found")
	}
	if old == new {
		return nil
	}
	if _, ok := w.s.get(new); ok {
		return errors.New("destination exists")
	}
	if strings.HasPrefix(new, old+"/") {
		return errors.New("cannot move directory into itself")
	}
	if err = w.parent(new); err != nil {
		return err
	}
	moved := findNode(w.s.root, old)
	// Validate every destination before changing either path. The subtree itself
	// is reused; no descendant metadata needs to be rewritten.
	if err := walkNodes(moved, new, func(p string, _ *node) error {
		_, err := clean(p)
		return err
	}); err != nil {
		return err
	}
	w.s.set(old, nil)
	w.s.set(new, moved)
	return nil
}
func (w *Workspace) Chmod(p string, mode uint32) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return ErrReadOnly
	}
	if mode > 0777 {
		return errors.New("mode must be in 0000..0777")
	}
	p, err := clean(p)
	if err != nil {
		return err
	}
	if err := w.prepare(p, false); err != nil {
		return err
	}
	if p == "." {
		return errors.New("root mode is fixed")
	}
	e, ok := w.s.get(p)
	if !ok {
		return errors.New("path not found")
	}
	if e.Kind == "symlink" || e.Kind == "gitlink" {
		return errors.New("symlink/gitlink chmod denied")
	}
	if e.Mode == mode {
		return nil
	}
	n := findNode(w.s.root, p)
	e.Mode = mode
	changed := &node{entry: e, children: n.children}
	// A directory's own encoding excludes its mode. Its parent's ID is dirtied.
	if e.Kind == "dir" {
		w.r.mu.Lock()
		changed.id = n.id
		w.r.mu.Unlock()
	}
	w.s.set(p, changed)
	return nil
}
func (w *Workspace) save() (ID, error) {
	if w.s.loadErr != nil {
		return "", w.s.loadErr
	}
	if w.s.snapshot != "" {
		return w.s.snapshot, nil
	}
	root, err := w.r.saveNode(w.s.root)
	if err != nil {
		return "", err
	}
	return w.r.putJSON(snapshotKind, snapshot{root, w.s.source})
}

// snapshotLocked requires both the workspace and repository locks. Memoization
// is installed only after successful fsync, never just after serialization.
func (w *Workspace) snapshotLocked() (ID, error) {
	if err := w.r.ready(); err != nil {
		return "", err
	}
	if w.s.snapshot != "" {
		return w.s.snapshot, nil
	}
	id, err := w.save()
	if err != nil {
		return "", err
	}
	if err := w.r.sync(); err != nil {
		return "", err
	}
	w.s.snapshot = id
	return id, nil
}

// Snapshot durably stores an immutable tree without changing any named root.
func (w *Workspace) Snapshot() (ID, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return "", ErrReadOnly
	}
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	return w.snapshotLocked()
}

// Publish atomically updates a name after syncing its reachable objects. A
// checkout may update its own name with compare-and-swap; other names must be new.
func (w *Workspace) Publish(name string) (ID, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return "", ErrReadOnly
	}
	if !validName(name) {
		return "", errors.New("invalid workspace name")
	}
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if err := w.r.ready(); err != nil {
		return "", err
	}
	current := w.r.refs[name]
	if name == w.s.name {
		if current != w.s.base {
			return "", ErrConflict
		}
	} else if current != "" {
		return "", ErrConflict
	}
	id, err := w.snapshotLocked()
	if err != nil {
		return "", err
	}
	refs := map[string]ID{}
	for n, id := range w.r.refs {
		refs[n] = id
	}
	refs[name] = id
	if _, err = w.r.putJSON(refsKind, catalog{refs}); err != nil {
		return "", err
	}
	if err = w.r.sync(); err != nil {
		return "", err
	}
	w.r.refs = refs
	w.s.name = name
	w.s.base = id
	return id, nil
}
