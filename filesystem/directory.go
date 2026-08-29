package filesystem

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	tararchive "github.com/tinyrange/trex/archive/tar"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func DirectoryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("directory", args, kwargs); err != nil {
		return nil, err
	}
	return New(), nil
}

type Directory struct {
	dirs           map[string]struct{}
	files          map[string]FileRecord
	attributes     map[string]Attributes
	metadata       map[string]Metadata
	nextWriteOrder uint64
	revision       uint64
	fatShortIndex  map[string]string
	fatShortErr    error
	fatShortRev    uint64
	fatShortValid  bool
}

// Attributes contains portable DOS-style file attributes.
type Attributes struct {
	ReadOnly bool
	Hidden   bool
	System   bool
	Archive  bool
}

// Metadata contains optional Windows filesystem metadata used by image
// builders that can represent it.
type Metadata struct {
	FileAttributes     uint32
	HasFileAttributes  bool
	SecurityDescriptor []byte
	CreationTime       uint64
	LastAccessTime     uint64
	LastWriteTime      uint64
	HardLink           uint64
	ShortName          string
}

// FileRecord is a file stored in a Directory. File takes precedence over Data
// when both are present; Size records the logical length of Data-backed files.
type FileRecord struct {
	File       starfile.File
	Data       []byte
	Size       int64
	WriteOrder uint64
}

// Snapshot is an immutable view of a directory used by filesystem builders.
// Maps and byte slices are copied so callers cannot mutate Directory state.
type Snapshot struct {
	Directories []string
	Files       map[string]FileRecord
	Attributes  map[string]Attributes
	Metadata    map[string]Metadata
}

// New creates an empty portable in-memory directory tree.
func New() *Directory {
	return &Directory{
		dirs:       map[string]struct{}{"/": {}},
		files:      make(map[string]FileRecord),
		attributes: make(map[string]Attributes),
		metadata:   make(map[string]Metadata),
	}
}

// Snapshot returns the complete portable input needed by an on-disk
// filesystem builder.
func (d *Directory) Snapshot() Snapshot {
	directories := make([]string, 0, len(d.dirs))
	for name := range d.dirs {
		directories = append(directories, name)
	}
	files := make(map[string]FileRecord, len(d.files))
	for name, file := range d.files {
		file.Data = append([]byte(nil), file.Data...)
		files[name] = file
	}
	attributes := make(map[string]Attributes, len(d.attributes))
	for name, value := range d.attributes {
		attributes[name] = value
	}
	metadata := make(map[string]Metadata, len(d.metadata))
	for name, value := range d.metadata {
		value.SecurityDescriptor = append([]byte(nil), value.SecurityDescriptor...)
		metadata[name] = value
	}
	sort.Strings(directories)
	return Snapshot{Directories: directories, Files: files, Attributes: attributes, Metadata: metadata}
}

func (d *Directory) String() string       { return fmt.Sprintf("<directory files=%d>", len(d.files)) }
func (d *Directory) Type() string         { return "directory" }
func (d *Directory) Freeze()              {}
func (d *Directory) Truth() starlark.Bool { return starlark.True }
func (d *Directory) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", d.Type())
}
func (d *Directory) Attr(name string) (starlark.Value, error) {
	switch name {
	case "mkdir":
		return starlark.NewBuiltin("mkdir", d.mkdirBuiltin), nil
	case "write":
		return starlark.NewBuiltin("write", d.writeBuiltin), nil
	case "find":
		return starlark.NewBuiltin("find", d.findBuiltin), nil
	case "remove":
		return starlark.NewBuiltin("remove", d.removeBuiltin), nil
	case "set_attributes":
		return starlark.NewBuiltin("set_attributes", d.setAttributesBuiltin), nil
	case "files":
		return d.fileList(), nil
	case "fat_short_path":
		return starlark.NewBuiltin("fat_short_path", d.fatShortPathBuiltin), nil
	}
	return nil, nil
}
func (d *Directory) AttrNames() []string {
	return []string{"fat_short_path", "files", "find", "mkdir", "remove", "set_attributes", "write"}
}

func (d *Directory) findBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
		return nil, err
	}
	file, ok := d.files[storage.CleanPath(name)]
	if !ok {
		return starlark.None, nil
	}
	if file.File != nil {
		return file.File, nil
	}
	return &starfile.Bytes{Name: storage.CleanPath(name), Data: file.Data}, nil
}

func (d *Directory) removeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("remove", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	cleaned := storage.CleanPath(name)
	if _, exists := d.files[cleaned]; !exists {
		return nil, fmt.Errorf("remove: file %q does not exist", cleaned)
	}
	delete(d.files, cleaned)
	delete(d.metadata, cleaned)
	d.revision++
	d.fatShortValid = false
	return starlark.None, nil
}

func (d *Directory) fatShortPathBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("fat_short_path", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	short, err := d.fatShortPath(name)
	if err != nil {
		return nil, err
	}
	return starlark.String(short), nil
}

func (d *Directory) fatShortPath(name string) (string, error) {
	drive := ""
	if len(name) >= 3 && name[1] == ':' && (name[2] == '\\' || name[2] == '/') {
		drive = name[:2]
		name = name[2:]
	}
	cleaned := storage.CleanPath(name)
	index, err := d.currentFATShortIndex()
	if err != nil {
		return "", err
	}

	longParts := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
	parts := make([]string, 0, len(longParts))
	parent := "/"
	found := true
	for _, part := range longParts {
		parent = storage.CleanPath(path.Join(parent, part))
		short, ok := index[strings.ToLower(parent)]
		if !found || !ok {
			parts = append(parts, defaultFATShortName(part))
			found = false
			continue
		}
		parts = append(parts, short)
	}
	separator := "/"
	prefix := "/"
	if drive != "" {
		separator = `\`
		prefix = drive + `\`
	}
	return prefix + strings.Join(parts, separator), nil
}

func (d *Directory) currentFATShortIndex() (map[string]string, error) {
	if d.fatShortValid && d.fatShortRev == d.revision {
		return d.fatShortIndex, d.fatShortErr
	}
	children := make(map[string][]string)
	for name := range d.dirs {
		if name != "/" {
			children[path.Dir(name)] = append(children[path.Dir(name)], name)
		}
	}
	for name := range d.files {
		children[path.Dir(name)] = append(children[path.Dir(name)], name)
	}
	index := make(map[string]string, len(d.dirs)+len(d.files))
	for _, names := range children {
		sort.Slice(names, func(i, j int) bool {
			return strings.ToLower(path.Base(names[i])) < strings.ToLower(path.Base(names[j]))
		})
		assigned := assignShortNames(names)
		for i, name := range names {
			index[strings.ToLower(name)] = assigned[i]
		}
	}
	var err error
	d.fatShortIndex = index
	d.fatShortErr = err
	d.fatShortRev = d.revision
	d.fatShortValid = true
	return index, err
}

func assignShortNames(paths []string) []string {
	result := make([]string, len(paths))
	used := make(map[string]bool)
	nextSuffix := make(map[string]int)
	for i, fullPath := range paths {
		name := path.Base(fullPath)
		base, ext := shortParts(name)
		candidate := shortName(base, ext)
		if simple83(name, base, ext) && !used[candidate] {
			result[i], used[candidate] = candidate, true
			continue
		}
		key := base + "\x00" + ext
		n := nextSuffix[key]
		if n == 0 {
			n = 1
		}
		for ; ; n++ {
			suffix := fmt.Sprintf("~%d", n)
			limit := max(1, 8-len(suffix))
			prefix := base
			if len(prefix) > limit {
				prefix = prefix[:limit]
			}
			candidate = shortName(prefix+suffix, ext)
			if used[candidate] {
				continue
			}
			result[i], used[candidate], nextSuffix[key] = candidate, true, n+1
			break
		}
	}
	return result
}

func defaultFATShortName(name string) string { return assignShortNames([]string{name})[0] }

// DefaultFATShortName derives an 8.3 alias for an isolated path component.
func DefaultFATShortName(name string) string { return defaultFATShortName(name) }

func shortParts(name string) (string, string) {
	base, ext := name, ""
	if index := strings.LastIndex(name, "."); index > 0 {
		base, ext = name[:index], name[index+1:]
	}
	base, ext = shortClean(base), shortClean(ext)
	if base == "" {
		base = "FILE"
	}
	if len(base) > 8 {
		base = base[:8]
	}
	if len(ext) > 3 {
		ext = ext[:3]
	}
	return base, ext
}

func shortClean(value string) string {
	var out strings.Builder
	for _, rune := range strings.ToUpper(value) {
		if rune >= 'A' && rune <= 'Z' || rune >= '0' && rune <= '9' || strings.ContainsRune("_$~", rune) {
			out.WriteRune(rune)
		}
	}
	return out.String()
}

func simple83(name, base, ext string) bool {
	want := strings.TrimRight(base, " ")
	if ext != "" {
		want += "." + strings.TrimRight(ext, " ")
	}
	return strings.EqualFold(name, want) && len(base) <= 8 && len(ext) <= 3
}

func shortName(base, ext string) string {
	if ext != "" {
		return base + "." + ext
	}
	return base
}

func (d *Directory) mkdirBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("mkdir", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	d.Mkdir(name)
	return starlark.None, nil
}

func (d *Directory) writeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var value starlark.Value
	if err := starlark.UnpackArgs("write", args, kwargs, "name", &name, "value", &value); err != nil {
		return nil, err
	}
	file, err := virtualFileForValue(value)
	if err != nil {
		return nil, err
	}
	d.PutFile(name, file)
	return starlark.None, nil
}

// PutFile adds or replaces a file and creates its parent directories.
func (d *Directory) PutFile(name string, file FileRecord) {
	cleaned := storage.CleanPath(name)
	d.Mkdir(path.Dir(cleaned))
	d.nextWriteOrder++
	file.WriteOrder = d.nextWriteOrder
	d.files[cleaned] = file
	d.revision++
}

// SetMetadata associates filesystem metadata with a path.
func (d *Directory) SetMetadata(name string, metadata Metadata) {
	if d.metadata == nil {
		d.metadata = make(map[string]Metadata)
	}
	d.metadata[storage.CleanPath(name)] = metadata
}

func (d *Directory) setAttributesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var attributes Attributes
	if err := starlark.UnpackArgs(
		"set_attributes", args, kwargs,
		"name", &name,
		"readonly?", &attributes.ReadOnly,
		"hidden?", &attributes.Hidden,
		"system?", &attributes.System,
		"archive?", &attributes.Archive,
	); err != nil {
		return nil, err
	}
	if err := d.SetAttributes(name, attributes); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

// SetAttributes applies portable DOS/Windows attributes to an existing path.
func (d *Directory) SetAttributes(name string, attributes Attributes) error {
	cleaned := storage.CleanPath(name)
	if _, isDir := d.dirs[cleaned]; !isDir {
		if _, isFile := d.files[cleaned]; !isFile {
			return fmt.Errorf("set_attributes: path %q does not exist", name)
		}
	}
	d.attributes[cleaned] = attributes
	return nil
}

// Mkdir creates a directory and any missing parents.
func (d *Directory) Mkdir(name string) {
	cleaned := storage.CleanPath(name)
	changed := false
	for {
		if _, ok := d.dirs[cleaned]; !ok {
			d.dirs[cleaned] = struct{}{}
			changed = true
		}
		if cleaned == "/" {
			if changed {
				d.revision++
			}
			return
		}
		cleaned = path.Dir(cleaned)
	}
}

func (d *Directory) fileList() *starlark.List {
	names := make([]string, 0, len(d.files))
	for name := range d.files {
		names = append(names, name)
	}
	sort.Strings(names)
	values := make([]starlark.Value, len(names))
	for i, name := range names {
		values[i] = starlark.String(name)
	}
	return starlark.NewList(values)
}

func PathFromWindowsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("from_windows", args, kwargs, "path", &name); err != nil {
		return nil, err
	}
	return starlark.String(storage.CleanPath(name)), nil
}

func PathBaseBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("base", args, kwargs, "path", &name); err != nil {
		return nil, err
	}
	return starlark.String(path.Base(storage.CleanPath(name))), nil
}

func PathDirBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("dir", args, kwargs, "path", &name); err != nil {
		return nil, err
	}
	return starlark.String(path.Dir(storage.CleanPath(name))), nil
}

func PathExtBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("ext", args, kwargs, "path", &name); err != nil {
		return nil, err
	}
	return starlark.String(path.Ext(storage.CleanPath(name))), nil
}

func PathCleanBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("clean", args, kwargs, "path", &name); err != nil {
		return nil, err
	}
	return starlark.String(storage.CleanPath(name)), nil
}

func PathJoinBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	parts := make([]string, len(args))
	for i, arg := range args {
		part, ok := starlark.AsString(arg)
		if !ok {
			return nil, fmt.Errorf("join: got %s, want string", arg.Type())
		}
		parts[i] = part
	}
	if len(kwargs) > 0 {
		return nil, fmt.Errorf("join: got unexpected keyword arguments")
	}
	return starlark.String(storage.CleanPath(path.Join(parts...))), nil
}

func TarBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	compress := ""
	maximumEntries := 1_000_000
	if err := starlark.UnpackArgs("tar", args, kwargs, "directory", &value, "compress?", &compress, "maximum_entries?", &maximumEntries); err != nil {
		return nil, err
	}
	if dir, ok := value.(*Directory); ok {
		data, err := dir.tar(compress)
		if err != nil {
			return nil, err
		}
		return starlark.Bytes(data), nil
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("tar: got %s, want directory or file", value.Type())
	}
	if compress != "" {
		return nil, fmt.Errorf("tar: compress is only valid when building from a directory")
	}
	return tararchive.Open(file, maximumEntries)
}

func (d *Directory) tar(compress string) ([]byte, error) {
	var buf bytes.Buffer
	var out = anyWriter(&buf)
	var gz *gzip.Writer
	if compress != "" {
		if compress != "gz" {
			return nil, fmt.Errorf("tar: unsupported compression %q", compress)
		}
		var err error
		gz, err = gzip.NewWriterLevel(&buf, gzip.BestSpeed)
		if err != nil {
			return nil, err
		}
		out = gz
	}
	tw := tar.NewWriter(out)

	dirs := make([]string, 0, len(d.dirs))
	for name := range d.dirs {
		if name != "/" {
			dirs = append(dirs, name)
		}
	}
	sort.Strings(dirs)
	for _, name := range dirs {
		if err := tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/") + "/", Mode: 0755, Typeflag: tar.TypeDir}); err != nil {
			return nil, err
		}
	}

	files := make([]string, 0, len(d.files))
	for name := range d.files {
		files = append(files, name)
	}
	sort.Strings(files)
	for _, name := range files {
		file := d.files[name]
		if err := tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Mode: 0644, Size: file.Size, Typeflag: tar.TypeReg}); err != nil {
			return nil, err
		}
		if file.File != nil {
			if err := writeFileTo(tw, file.File); err != nil {
				return nil, err
			}
		} else {
			if _, err := tw.Write(file.Data); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if gz != nil {
		if err := gz.Close(); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

type anyWriter interface {
	Write([]byte) (int, error)
}

func virtualFileForValue(value starlark.Value) (FileRecord, error) {
	switch value := value.(type) {
	case starfile.File:
		return FileRecord{File: value, Size: value.Size()}, nil
	case starlark.String:
		data := []byte(string(value))
		return FileRecord{Data: data, Size: int64(len(data))}, nil
	case starlark.Bytes:
		data := []byte(value)
		return FileRecord{Data: data, Size: int64(len(data))}, nil
	default:
		return FileRecord{}, fmt.Errorf("write: got %s, want file, string, or bytes", value.Type())
	}
}

func writeFileTo(writer io.Writer, file starfile.File) error {
	_, err := io.CopyN(writer, io.NewSectionReader(file, 0, file.Size()), file.Size())
	return err
}
