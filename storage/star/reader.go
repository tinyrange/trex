package star

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
	"io"
)

// ReaderValue wraps a portable immutable reader without copying its payload.
// The owning execution/repository supplies its lifetime; this value borrows it.
type ReaderValue struct {
	name   string
	reader storage.Reader
}

func NewReader(name string, reader storage.Reader) *ReaderValue {
	return &ReaderValue{name: name, reader: reader}
}
func (v *ReaderValue) StorageReader() storage.Reader           { return v.reader }
func (v *ReaderValue) ReadAt(p []byte, off int64) (int, error) { return v.reader.ReadAt(p, off) }
func (*ReaderValue) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("file version is immutable")
}
func (v *ReaderValue) Size() int64                              { return v.reader.Size() }
func (v *ReaderValue) String() string                           { return fmt.Sprintf("<file %q>", v.name) }
func (*ReaderValue) Type() string                               { return "file" }
func (*ReaderValue) Freeze()                                    {}
func (*ReaderValue) Truth() starlark.Bool                       { return starlark.True }
func (*ReaderValue) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (v *ReaderValue) AttrNames() []string                      { return AttrNames() }
func (v *ReaderValue) Attr(name string) (starlark.Value, error) { return Attr(v, name), nil }
func (v *ReaderValue) WriteTo(w io.Writer) (int64, error) {
	if fast, ok := v.reader.(io.WriterTo); ok {
		return fast.WriteTo(w)
	}
	return io.Copy(w, io.NewSectionReader(v.reader, 0, v.reader.Size()))
}
func (v *ReaderValue) WriteRangeTo(w io.Writer, off, size int64) (int64, error) {
	if off < 0 || size < 0 || off > v.Size() || size > v.Size()-off {
		return 0, fmt.Errorf("invalid file range")
	}
	if fast, ok := v.reader.(storage.RangeWriterTo); ok {
		return fast.WriteRangeTo(w, off, size)
	}
	return io.Copy(w, io.NewSectionReader(v.reader, off, size))
}
