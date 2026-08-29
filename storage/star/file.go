// Package star adapts portable storage values to Starlark. Format packages can
// keep their parsers independent of Starlark and use this package only in
// their optional scripting adapters.
package star

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

type File interface {
	storage.File
	starlark.Value
}

func AttrNames() []string { return []string{"binary", "bytes", "hex", "read", "size", "slice"} }

func Attr(file File, name string) starlark.Value {
	switch name {
	case "read":
		return starlark.NewBuiltin("read", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("read", args, kwargs); err != nil {
				return nil, err
			}
			data, err := ReadAll(file)
			return starlark.String(data), err
		})
	case "bytes", "hex", "binary":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			off, size, err := rangeArgs(name, args, kwargs, file.Size())
			if err != nil {
				return nil, err
			}
			data := make([]byte, size)
			if _, err := ReadFullAt(file, data, off); err != nil {
				return nil, err
			}
			if name == "hex" {
				return starlark.String(hex.Dump(data)), nil
			}
			if name == "binary" {
				return starlark.String(binaryString(data)), nil
			}
			return starlark.Bytes(data), nil
		})
	case "slice":
		return starlark.NewBuiltin("slice", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			off, size, err := rangeArgs("slice", args, kwargs, file.Size())
			if err != nil {
				return nil, err
			}
			return &Slice{Name: file.String(), Base: file, Offset: off, Length: size}, nil
		})
	case "size":
		return starlark.MakeInt64(file.Size())
	}
	return nil
}

func binaryString(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	out := make([]byte, 0, len(data)*9-1)
	for i, value := range data {
		if i != 0 {
			out = append(out, ' ')
		}
		for bit := 7; bit >= 0; bit-- {
			if value&(1<<uint(bit)) != 0 {
				out = append(out, '1')
			} else {
				out = append(out, '0')
			}
		}
	}
	return string(out)
}

type Slice struct {
	Name           string
	Base           File
	Offset, Length int64
}

func (f *Slice) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= f.Length {
		return 0, io.EOF
	}
	requested := len(p)
	if int64(len(p)) > f.Length-off {
		p = p[:f.Length-off]
	}
	n, err := f.Base.ReadAt(p, f.Offset+off)
	if err == nil && n < requested {
		err = io.EOF
	}
	return n, err
}
func (*Slice) WriteAt([]byte, int64) (int, error) { return 0, fmt.Errorf("slice is read-only") }
func (f *Slice) Size() int64                      { return f.Length }
func (f *Slice) String() string {
	return fmt.Sprintf("<file %s[%d:%d]>", f.Name, f.Offset, f.Offset+f.Length)
}
func (*Slice) Type() string                               { return "file" }
func (*Slice) Freeze()                                    {}
func (*Slice) Truth() starlark.Bool                       { return starlark.True }
func (*Slice) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (f *Slice) Attr(name string) (starlark.Value, error) { return Attr(f, name), nil }
func (*Slice) AttrNames() []string                        { return AttrNames() }

type Bytes struct {
	Name string
	Data []byte
}

func (f *Bytes) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(f.Data)) {
		return 0, io.EOF
	}
	n := copy(p, f.Data[off:])
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (*Bytes) WriteAt([]byte, int64) (int, error)         { return 0, fmt.Errorf("file is read-only") }
func (f *Bytes) Size() int64                              { return int64(len(f.Data)) }
func (f *Bytes) String() string                           { return fmt.Sprintf("<file %s size=%d>", f.Name, len(f.Data)) }
func (*Bytes) Type() string                               { return "file" }
func (*Bytes) Freeze()                                    {}
func (*Bytes) Truth() starlark.Bool                       { return starlark.True }
func (*Bytes) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (f *Bytes) Attr(name string) (starlark.Value, error) { return Attr(f, name), nil }
func (*Bytes) AttrNames() []string                        { return AttrNames() }

func ReadAll(file storage.Reader) ([]byte, error) {
	if file.Size() < 0 || file.Size() > int64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("invalid file size %d", file.Size())
	}
	data := make([]byte, int(file.Size()))
	_, err := ReadFullAt(file, data, 0)
	return data, err
}

// BytesForValue converts a bounded Starlark binary value without involving
// host paths or intermediate files. Any Starlark value implementing the
// portable storage.Reader contract is accepted.
func BytesForValue(value starlark.Value, maximum int64) ([]byte, error) {
	if maximum < 0 {
		return nil, fmt.Errorf("negative binary size limit")
	}
	switch value := value.(type) {
	case storage.Reader:
		if value.Size() < 0 || value.Size() > maximum {
			return nil, fmt.Errorf("input size %d exceeds limit %d", value.Size(), maximum)
		}
		return ReadAll(value)
	case starlark.String:
		if int64(len(value)) > maximum {
			return nil, fmt.Errorf("input size %d exceeds limit %d", len(value), maximum)
		}
		return []byte(value), nil
	case starlark.Bytes:
		if int64(len(value)) > maximum {
			return nil, fmt.Errorf("input size %d exceeds limit %d", len(value), maximum)
		}
		return []byte(value), nil
	default:
		return nil, fmt.Errorf("got %s, want file, string, or bytes", value.Type())
	}
}

func ReadFullAt(reader io.ReaderAt, p []byte, off int64) (int, error) {
	done := 0
	for done < len(p) {
		n, err := reader.ReadAt(p[done:], off+int64(done))
		done += n
		if err != nil {
			if err == io.EOF && done == len(p) {
				return done, nil
			}
			return done, err
		}
		if n == 0 {
			return done, io.ErrUnexpectedEOF
		}
	}
	return done, nil
}

// ReadSubfileAt reads from a bounded range of another random-access source.
func ReadSubfileAt(base storage.Reader, baseOffset, size int64, p []byte, off int64) (int, error) {
	if off < 0 || off >= size {
		return 0, io.EOF
	}
	requested := len(p)
	if remaining := size - off; int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := base.ReadAt(p, baseOffset+off)
	if err != nil && err != io.EOF {
		return n, err
	}
	if n < requested {
		return n, io.EOF
	}
	return n, nil
}

func rangeArgs(name string, args starlark.Tuple, kwargs []starlark.Tuple, total int64) (int64, int64, error) {
	off := int64(0)
	size := total
	if err := starlark.UnpackArgs(name, args, kwargs, "off?", &off, "size?", &size); err != nil {
		return 0, 0, err
	}
	if off < 0 || size < 0 || off > total || size > total-off {
		return 0, 0, fmt.Errorf("%s: range outside file", name)
	}
	return off, size, nil
}
