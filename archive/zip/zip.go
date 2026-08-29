package ziparchive

import (
	"archive/zip"
	"fmt"
	"io"
	"sync"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starlark.Value
	if err := starlark.UnpackArgs("zip", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	hostFile, ok := file.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("zip: got %s, want file", file.Type())
	}
	reader, err := zip.NewReader(hostFile, hostFile.Size())
	if err != nil {
		return nil, err
	}
	files := make([]starlark.Value, len(reader.File))
	for i, entry := range reader.File {
		files[i] = &Entry{entry: entry}
	}
	return &Archive{files: starlark.NewList(files)}, nil
}

type Archive struct {
	files *starlark.List
}

func (z *Archive) String() string       { return "<zip>" }
func (z *Archive) Type() string         { return "zip" }
func (z *Archive) Freeze()              { z.files.Freeze() }
func (z *Archive) Truth() starlark.Bool { return starlark.True }
func (z *Archive) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", z.Type())
}
func (z *Archive) Attr(name string) (starlark.Value, error) {
	if name == "files" {
		return z.files, nil
	}
	return nil, nil
}
func (z *Archive) AttrNames() []string {
	return []string{"files"}
}

type Entry struct {
	entry  *zip.File
	mu     sync.Mutex
	reader io.ReadCloser
	data   []byte
	err    error
}

func NewEntry(entry *zip.File) *Entry { return &Entry{entry: entry} }

func (f *Entry) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if off >= f.Size() {
		return 0, io.EOF
	}
	end := off + int64(len(p))
	if end > f.Size() {
		end = f.Size()
	}
	if err := f.cacheUntil(end); err != nil && err != io.EOF {
		return 0, err
	}

	n := copy(p, f.data[off:end])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (f *Entry) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("zip entry %q is read-only", f.entry.Name)
}
func (f *Entry) Size() int64          { return int64(f.entry.UncompressedSize64) }
func (f *Entry) String() string       { return fmt.Sprintf("<zip.file %q>", f.entry.Name) }
func (f *Entry) Type() string         { return "file" }
func (f *Entry) Freeze()              {}
func (f *Entry) Truth() starlark.Bool { return starlark.True }
func (f *Entry) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *Entry) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *Entry) AttrNames() []string {
	return starfile.AttrNames()
}

func (f *Entry) cacheUntil(end int64) error {
	if int64(len(f.data)) >= end || f.err == io.EOF {
		return f.err
	}
	if f.err != nil {
		return f.err
	}
	if f.reader == nil {
		reader, err := f.entry.Open()
		if err != nil {
			f.err = err
			return err
		}
		f.reader = reader
	}

	buf := make([]byte, min(int64(128*1024), end-int64(len(f.data))))
	for int64(len(f.data)) < end {
		need := int(end - int64(len(f.data)))
		if need > len(buf) {
			need = len(buf)
		}
		n, err := f.reader.Read(buf[:need])
		if n > 0 {
			f.data = append(f.data, buf[:n]...)
		}
		if err != nil {
			_ = f.reader.Close()
			f.reader = nil
			f.err = err
			return err
		}
	}
	return nil
}
