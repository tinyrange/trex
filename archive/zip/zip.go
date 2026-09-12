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
	if name == "files" || name == "entries" {
		return z.files, nil
	}
	return nil, nil
}
func (z *Archive) AttrNames() []string {
	return []string{"entries", "files"}
}

type Entry struct {
	entry    *zip.File
	mu       sync.Mutex
	reader   io.ReadCloser
	data     []byte
	err      error
	verified bool
}

func NewEntry(entry *zip.File) *Entry { return &Entry{entry: entry} }

func (f *Entry) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.Size() {
		return 0, io.EOF
	}
	end := off + min(int64(len(p)), f.Size()-off)
	if err := f.cacheUntil(end); err != nil && err != io.EOF {
		return 0, err
	}
	if int64(len(f.data)) < end {
		return 0, io.ErrUnexpectedEOF
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
	if name == "name" || name == "path" {
		return starlark.String(f.entry.Name), nil
	}
	if name == "entry_type" {
		if f.entry.FileInfo().IsDir() {
			return starlark.String("directory"), nil
		}
		return starlark.String("file"), nil
	}
	if name == "verify" {
		return starlark.NewBuiltin("verify", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("verify", args, kwargs); err != nil {
				return nil, err
			}
			return starlark.None, f.Verify()
		}), nil
	}
	return starfile.Attr(f, name), nil
}
func (f *Entry) AttrNames() []string {
	return append(starfile.AttrNames(), "name", "path", "entry_type", "verify")
}

// Verify reads the complete payload and checks its ZIP checksum, including for
// empty entries where a generic zero-length file read need not touch the source.
func (f *Entry) Verify() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Size() < 0 {
		return fmt.Errorf("zip: decoded size exceeds file addressing range")
	}
	err := f.cacheUntil(f.Size())
	if err == io.EOF && f.verified {
		return nil
	}
	return err
}

func (f *Entry) cacheUntil(end int64) error {
	if f.err != nil {
		return f.err
	}
	if int64(len(f.data)) >= end && (end < f.Size() || f.verified) {
		return nil
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
			if err == io.EOF {
				if int64(len(f.data)) != f.Size() {
					err = io.ErrUnexpectedEOF
				} else {
					f.verified = true
				}
			}
			f.err = err
			return err
		}
	}
	if end == f.Size() && !f.verified {
		// Stored ZIP readers can return the final requested bytes with nil
		// error; their CRC check runs only on the next EOF read. Do not let
		// an exact-sized ReadAt bypass it.
		var extra [1]byte
		n, err := f.reader.Read(extra[:])
		_ = f.reader.Close()
		f.reader = nil
		if n != 0 {
			err = fmt.Errorf("zip: payload exceeds declared size")
		} else if err == io.EOF {
			f.verified = true
		} else if err == nil {
			err = io.ErrNoProgress
		}
		f.err = err
		return err
	}
	return nil
}
