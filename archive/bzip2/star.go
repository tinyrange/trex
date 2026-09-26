package bzip2

import (
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source, maximum starlark.Value
	if err := starlark.UnpackArgs("bzip2", args, kwargs, "file", &source, "maximum_bytes?", &maximum); err != nil {
		return nil, err
	}
	reader, ok := source.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("bzip2: expected file, got %s", source.Type())
	}
	limit := int64(0)
	if maximum != nil {
		if err := starlark.AsInt(maximum, &limit); err != nil {
			return nil, err
		}
		if limit <= 0 {
			return nil, fmt.Errorf("bzip2: maximum_bytes must be positive")
		}
	}
	decoded := NewReader(reader, limit)
	var first [1]byte
	if _, err := decoded.ReadAt(first[:], 0); err != nil && err != io.EOF {
		return nil, err
	}
	return decoded, nil
}

func (*Reader) WriteAt([]byte, int64) (int, error) { return 0, fmt.Errorf("bzip2 file is read-only") }
func (r *Reader) String() string {
	size, known := r.KnownSize()
	return fmt.Sprintf("<bzip2.file size=%d known=%v>", size, known)
}
func (*Reader) Type() string                               { return "file" }
func (*Reader) Freeze()                                    {}
func (*Reader) Truth() starlark.Bool                       { return starlark.True }
func (*Reader) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (r *Reader) Attr(name string) (starlark.Value, error) { return starfile.Attr(r, name), nil }
func (*Reader) AttrNames() []string                        { return starfile.AttrNames() }
