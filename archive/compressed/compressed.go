// Package compressed decodes gzip, bzip2, UNIX compress and UNIX pack streams
// into bounded, in-memory random-access files. It validates complete streams
// and their available size/checksum fields before publishing a file.
package compressed

import (
	"compress/gzip"
	"fmt"
	"io"

	"github.com/tinyrange/trex/archive/internal/bzip2"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const chunkSize = 1 << 20

// File holds decoded bytes in fixed-size chunks, avoiding whole-image copies
// during growth. It is immutable and supports independent concurrent readers.
type File struct {
	chunks [][]byte
	size   int64
	format string
}

// Open validates and decodes the selected format (including concatenated gzip
// and bzip2 streams). maximum bounds decoded bytes, not compressed input bytes.
// UNIX compress has no checksum or size field; callers should check enclosing
// metadata. No temporary files are used.
func Open(source storage.Reader, format string, maximum int64) (*File, error) {
	return open(source, format, maximum, false)
}

// OpenPaddedUnix reads a UNIX compress stream in a zero-padded media record.
// It does not strip decoded zeroes or verify package contents; callers must
// check the decoded container and its external inventory or checksums.
func OpenPaddedUnix(source storage.Reader, maximum int64) (*File, error) {
	return open(source, "compress", maximum, true)
}

func open(source storage.Reader, format string, maximum int64, zeroPadding bool) (*File, error) {
	if maximum <= 0 || source.Size() < 0 {
		return nil, fmt.Errorf("%s: invalid size limit or input size", format)
	}
	var r io.Reader = io.NewSectionReader(source, 0, source.Size())
	switch format {
	case "gzip":
		g, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer g.Close()
		r = g
	case "bzip2":
		r = bzip2.NewReader(r)
	case "compress":
		var err error
		r, err = newUnixReader(source)
		if err != nil {
			return nil, err
		}
		r.(*unixReader).zeroPadding = zeroPadding
	case "pack":
		var err error
		r, err = newPackReader(source)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported compression %q", format)
	}
	f := &File{format: format}
	for {
		// One extra byte distinguishes an exact-limit file from a larger stream.
		length := int64(chunkSize)
		if remaining := maximum - f.size; remaining < length {
			length = remaining + 1
		}
		buf := make([]byte, int(length))
		n := 0
		var err error
		for n < len(buf) {
			count, readErr := r.Read(buf[n:])
			n += count
			if readErr != nil {
				err = readErr
				break
			}
			if count == 0 {
				return nil, fmt.Errorf("%s: decoder made no progress", format)
			}
		}
		if int64(n) > maximum-f.size {
			return nil, fmt.Errorf("%s: decoded data exceeds maximum_bytes %d", format, maximum)
		}
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("%s: decode: %w", format, err)
		}
		if n != 0 {
			f.chunks = append(f.chunks, buf[:n])
			f.size += int64(n)
		}
		if err != nil {
			return f, nil
		}
	}
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	n := 0
	for len(p) > 0 && off < f.size {
		chunk := f.chunks[off/chunkSize]
		count := copy(p, chunk[off%chunkSize:])
		n += count
		off += int64(count)
		p = p[count:]
	}
	if len(p) > 0 {
		return n, io.EOF
	}
	return n, nil
}
func (*File) WriteAt([]byte, int64) (int, error)         { return 0, fmt.Errorf("decoded file is read-only") }
func (f *File) Size() int64                              { return f.size }
func (f *File) String() string                           { return fmt.Sprintf("<%s decoded size=%d>", f.format, f.size) }
func (*File) Type() string                               { return "file" }
func (*File) Freeze()                                    {}
func (*File) Truth() starlark.Bool                       { return true }
func (*File) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (f *File) Attr(name string) (starlark.Value, error) { return starfile.Attr(f, name), nil }
func (*File) AttrNames() []string                        { return starfile.AttrNames() }

func Builtin(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	maximum := int64(2 << 30)
	zeroPadding := false
	parameters := []any{"file", &source, "maximum_bytes?", &maximum}
	if b.Name() == "compress" {
		parameters = append(parameters, "zero_padding?", &zeroPadding)
	}
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, parameters...); err != nil {
		return nil, err
	}
	f, ok := source.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("%s: expected file, got %s", b.Name(), source.Type())
	}
	return open(f, b.Name(), maximum, zeroPadding)
}
