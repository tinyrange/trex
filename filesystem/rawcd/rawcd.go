// Package rawcd exposes the 2048-byte data sectors of a raw Mode 1 or Mode 2
// Form 1 CD image. Sector framing/subchannels remain in the original reader.
package rawcd

import (
	"bytes"
	"fmt"
	"io"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/filesystem/iso9660"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

var syncBytes = []byte{0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0}

type File struct {
	source               storage.Reader
	stride, mode, offset int64
}

// Open recognizes a single-track raw data CD using its sector framing and
// ISO volume descriptor. Both 2352-byte sectors and 2448-byte sectors with
// subchannel bytes are accepted. Mixed-mode tracks require an explicit map.
func Open(source storage.Reader) (*File, error) {
	var h [24]byte
	if _, e := source.ReadAt(h[:], 0); e != nil {
		return nil, e
	}
	if !bytes.Equal(h[:12], syncBytes) || (h[15] != 1 && h[15] != 2) {
		return nil, fmt.Errorf("raw CD: invalid data-sector framing")
	}
	offset := int64(16)
	if h[15] == 2 {
		offset = 24
	}
	for _, stride := range []int64{2352, 2448} {
		if source.Size()%stride != 0 || source.Size() < 17*stride {
			continue
		}
		var descriptor [7]byte
		if _, e := source.ReadAt(descriptor[:], 16*stride+offset); e == nil && string(descriptor[1:6]) == "CD001" && descriptor[6] == 1 {
			return &File{source: source, stride: stride, mode: int64(h[15]), offset: offset}, nil
		}
	}
	return nil, fmt.Errorf("raw CD: no ISO9660 descriptor in a supported sector layout")
}
func (f *File) Size() int64 { return f.source.Size() / f.stride * 2048 }
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("raw CD: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.Size() {
		return 0, io.EOF
	}
	want := len(p)
	p = p[:min(int64(len(p)), f.Size()-off)]
	n := 0
	for len(p) > 0 {
		sector := off / 2048
		within := off % 2048
		var h [24]byte
		if _, e := f.source.ReadAt(h[:], sector*f.stride); e != nil {
			return n, e
		}
		if !bytes.Equal(h[:12], syncBytes) || int64(h[15]) != f.mode {
			return n, fmt.Errorf("raw CD: invalid sector %d", sector)
		}
		if f.mode == 2 && (!bytes.Equal(h[16:20], h[20:24]) || h[18]&0x20 != 0) {
			return n, fmt.Errorf("raw CD: sector %d is not Mode 2 Form 1", sector)
		}
		count := min(len(p), int(2048-within))
		got, e := f.source.ReadAt(p[:count], sector*f.stride+f.offset+within)
		n += got
		off += int64(got)
		p = p[got:]
		if e != nil {
			return n, e
		}
		if got != count {
			return n, io.ErrUnexpectedEOF
		}
	}
	if n < want {
		return n, io.EOF
	}
	return n, nil
}
func (f *File) WriteAt([]byte, int64) (int, error)    { return 0, fmt.Errorf("raw CD: read-only") }
func (f *File) String() string                        { return "<rawcd>" }
func (f *File) Type() string                          { return "file" }
func (f *File) Freeze()                               {}
func (f *File) Truth() starlark.Bool                  { return true }
func (f *File) Hash() (uint32, error)                 { return 0, fmt.Errorf("unhashable raw CD") }
func (f *File) Attr(n string) (starlark.Value, error) { return starfile.Attr(f, n), nil }
func (f *File) AttrNames() []string                   { return starfile.AttrNames() }
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if e := starlark.UnpackArgs("raw_cd", args, kwargs, "file", &value); e != nil {
		return nil, e
	}
	r, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("raw_cd: want file")
	}
	return Open(r)
}
func init() {
	auto.Register("rawcd", 45, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 16 || !bytes.Equal(p[:12], syncBytes) || (p[15] != 1 && p[15] != 2) {
			return nil, auto.ErrNoMatch
		}
		f, e := Open(r)
		if e != nil {
			return nil, e
		}
		v, e := adapter.Parse(iso9660.ISO9660Builtin, f, o)
		if e != nil {
			return nil, e
		}
		return &auto.DescribedView{View: v, Format: "rawcd", Attributes: map[string]any{"sector_size": f.stride, "mode": f.mode, "logical_sector_size": 2048}}, nil
	})
}
