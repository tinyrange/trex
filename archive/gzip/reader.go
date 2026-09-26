// Package gzip provides bounded-memory random access to gzip streams. Forward
// reads reuse the decoder; backward reads outside the cache replay the stream.
package gzip

import (
	stdgzip "compress/gzip"
	"fmt"
	"io"
	"math"
	"sync"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const cacheBytes = 1 << 20

// File retains a one-MiB decoded window and the decoder's bounded state. Size
// scans the stream when necessary; KnownSize never scans. gzip ISIZE describes
// only one member modulo 2^32 and is deliberately not used as the file length.
// Concatenated members and their checksums are checked as they are consumed.
type File struct {
	source      storage.Reader
	maximum     int64
	mu          sync.Mutex
	decoder     *stdgzip.Reader
	offset      int64
	cache       []byte
	cacheOffset int64
	size        int64
	known       bool
	err         error
}

// Open validates the first header without expanding the stream. A zero maximum
// permits any decoded length; a positive maximum bounds the complete output.
// Integrity validation is lazy; Validate checks every member and returns the
// exact size without retaining the expanded data.
func Open(source storage.Reader, maximum int64) (*File, error) {
	if source == nil || maximum < 0 {
		return nil, fmt.Errorf("gzip: invalid source or maximum_bytes")
	}
	f := &File{source: source, maximum: maximum}
	if err := f.reset(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *File) reset() error {
	size := int64(math.MaxInt64)
	if stream, ok := f.source.(interface{ KnownSize() (int64, bool) }); ok {
		if n, known := stream.KnownSize(); known {
			size = n
		}
	} else {
		size = f.source.Size()
	}
	if size < 0 {
		return fmt.Errorf("gzip: invalid compressed size")
	}
	r := io.NewSectionReader(f.source, 0, size)
	if f.decoder == nil {
		decoder, err := stdgzip.NewReader(r)
		if err != nil {
			return fmt.Errorf("gzip: initialize decoder: %w", err)
		}
		f.decoder = decoder
	} else if err := f.decoder.Reset(r); err != nil {
		return fmt.Errorf("gzip: reset decoder: %w", err)
	}
	f.offset = 0
	f.cache = f.cache[:0]
	return nil
}

// read advances the decoder, preserving checksum failures and the exact EOF.
func (f *File) read(p []byte) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	if f.known && f.offset == f.size {
		return 0, io.EOF
	}
	if f.maximum > 0 {
		remaining := f.maximum - f.offset
		if remaining < int64(len(p)) {
			// The extra byte distinguishes a complete exact-limit stream from
			// overflow, including empty concatenated members and their trailers.
			p = p[:remaining+1]
		}
	}
	n, err := f.decoder.Read(p)
	if int64(n) > math.MaxInt64-f.offset || (f.maximum > 0 && int64(n) > f.maximum-f.offset) {
		maximum := f.maximum
		if maximum == 0 {
			maximum = math.MaxInt64
		}
		f.err = fmt.Errorf("gzip: decoded data exceeds maximum_bytes %d: %w", maximum, auto.ErrLimit)
		return 0, f.err
	}
	f.offset += int64(n)
	if err == io.EOF {
		f.size, f.known = f.offset, true
	} else if err != nil {
		f.err = fmt.Errorf("gzip: decode at offset %d: %w", f.offset, err)
		err = f.err
	} else if n == 0 {
		f.err = io.ErrNoProgress
		err = f.err
	}
	return n, err
}

func (f *File) fill() error {
	if cap(f.cache) == 0 {
		f.cache = make([]byte, 0, cacheBytes)
	}
	f.cacheOffset = f.offset
	f.cache = f.cache[:0]
	for len(f.cache) < cap(f.cache) {
		buf := f.cache[:cap(f.cache)]
		n, err := f.read(buf[len(f.cache):])
		f.cache = buf[:len(f.cache)+n]
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > math.MaxInt64-int64(len(p)) {
		return 0, fmt.Errorf("gzip: invalid offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	n := 0
	for n < len(p) {
		if off >= f.cacheOffset && off < f.cacheOffset+int64(len(f.cache)) {
			count := copy(p[n:], f.cache[off-f.cacheOffset:])
			n += count
			off += int64(count)
			continue
		}
		if f.known && off >= f.size {
			return n, io.EOF
		}
		if off < f.offset {
			if err := f.reset(); err != nil {
				f.err = err
				return n, err
			}
		}
		// Skip using the same fixed buffer that will hold the next window.
		if cap(f.cache) == 0 {
			f.cache = make([]byte, 0, cacheBytes)
		}
		for f.offset < off {
			f.cache = f.cache[:0]
			buf := f.cache[:min(int64(cap(f.cache)), off-f.offset)]
			_, err := f.read(buf)
			if err != nil {
				return n, err
			}
		}
		if err := f.fill(); err != nil && err != io.EOF {
			return n, err
		}
	}
	return n, nil
}

func (f *File) KnownSize() (int64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.size, f.known && f.err == nil
}

func (f *File) Validate() (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	if f.known {
		return f.size, nil
	}
	var buf [32 << 10]byte
	for {
		_, err := f.read(buf[:])
		if err == io.EOF {
			return f.size, nil
		}
		if err != nil {
			return 0, err
		}
	}
}

func (f *File) Size() int64 {
	size, err := f.Validate()
	if err != nil {
		return -1
	}
	return size
}

func (*File) WriteAt([]byte, int64) (int, error) { return 0, fmt.Errorf("gzip file is read-only") }
func (f *File) String() string {
	size, known := f.KnownSize()
	return fmt.Sprintf("<gzip.file size=%d known=%v>", size, known)
}
func (*File) Type() string                               { return "file" }
func (*File) Freeze()                                    {}
func (*File) Truth() starlark.Bool                       { return starlark.True }
func (*File) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (f *File) Attr(name string) (starlark.Value, error) { return starfile.Attr(f, name), nil }
func (*File) AttrNames() []string                        { return starfile.AttrNames() }

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source, maximum starlark.Value
	if err := starlark.UnpackArgs("gzip", args, kwargs, "file", &source, "maximum_bytes?", &maximum); err != nil {
		return nil, err
	}
	reader, ok := source.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("gzip: expected file, got %s", source.Type())
	}
	limit := int64(0)
	if maximum != nil {
		if err := starlark.AsInt(maximum, &limit); err != nil {
			return nil, err
		}
		if limit <= 0 {
			return nil, fmt.Errorf("gzip: maximum_bytes must be positive")
		}
	}
	return Open(reader, limit)
}
