// Package zstd exposes bounded-memory Zstandard streams as portable files.
package zstd

import (
	"encoding/binary"
	"fmt"
	codec "github.com/klauspost/compress/zstd"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"io"
	"math"
	"sync"
)

const defaultWindow = 64 << 20

func decoder(r storage.Reader, window uint32) (*codec.Decoder, error) {
	return codec.NewReader(io.NewSectionReader(r, 0, r.Size()), codec.WithDecoderConcurrency(1), codec.WithDecoderLowmem(true), codec.WithDecoderMaxWindow(uint64(window)), codec.WithDecoderMaxMemory(uint64(window)))
}
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var v starlark.Value
	if err := starlark.UnpackArgs("zstd", args, kwargs, "file", &v); err != nil {
		return nil, err
	}
	f, ok := v.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("zstd: expected file")
	}
	return Open(f, 0)
}
func init() {
	auto.Register("zstd", 10, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 4 {
			return nil, auto.ErrNoMatch
		}
		m := binary.LittleEndian.Uint32(p)
		if m != 0xfd2fb528 && m&0xfffffff0 != 0x184d2a50 {
			return nil, auto.ErrNoMatch
		}
		f, e := Open(r, 0)
		if e != nil {
			return nil, e
		}
		return &auto.DecodedView{Reader: f}, nil
	})
}

type File struct {
	base       storage.Reader
	size       int64
	dictionary uint32

	mu      sync.Mutex
	reader  *codec.Decoder
	offset  int64
	readErr error
}

func Open(file storage.Reader, dictionary uint32) (*File, error) {
	if dictionary == 0 {
		dictionary = defaultWindow
	}
	size, err := decodedSize(file, dictionary)
	if err != nil {
		return nil, err
	}
	return &File{base: file, size: size, dictionary: dictionary, offset: -1}, nil
}
func (f *File) reset() error {
	if f.reader != nil {
		f.reader.Close()
	}
	reader, err := decoder(f.base, f.dictionary)
	if err != nil {
		return fmt.Errorf("zstd: initialize decoder: %w", err)
	}
	f.reader = reader
	f.offset = 0
	f.readErr = nil
	return nil
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if len(p) == 0 {
		if off > f.size {
			return 0, io.EOF
		}
		return 0, nil
	}
	if off >= f.size {
		return 0, io.EOF
	}

	requested := len(p)
	if remaining := f.size - off; int64(len(p)) > remaining {
		p = p[:remaining]
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reader == nil || off < f.offset {
		if err := f.reset(); err != nil {
			return 0, err
		}
	}
	if f.readErr != nil {
		return 0, f.readErr
	}
	if off > f.offset {
		n, err := io.CopyN(io.Discard, f.reader, off-f.offset)
		f.offset += n
		if err != nil {
			f.readErr = fmt.Errorf("zstd: seek to uncompressed offset %d: %w", off, err)
			return 0, f.readErr
		}
	}

	n, err := io.ReadFull(f.reader, p)
	f.offset += int64(n)
	if err != nil {
		f.readErr = fmt.Errorf("zstd: decompress at offset %d: %w", off, err)
		return n, f.readErr
	}
	if f.offset == f.size {
		if err := verifyZstdEnd(f.reader); err != nil {
			f.readErr = err
			return n, err
		}
	}
	if n < requested {
		return n, io.EOF
	}
	return n, nil
}

func verifyZstdEnd(reader io.Reader) error {
	n, err := io.CopyN(io.Discard, reader, 1)
	if n != 0 {
		return fmt.Errorf("zstd: decoded data exceeds size declared by stream indexes")
	}
	if err != io.EOF {
		if err == nil {
			return fmt.Errorf("zstd: decoder did not terminate at indexed size")
		}
		return fmt.Errorf("zstd: verify stream footer: %w", err)
	}
	return nil
}

func (f *File) WriteTo(w io.Writer) (int64, error) {
	reader, err := decoder(f.base, f.dictionary)
	if err != nil {
		return 0, fmt.Errorf("zstd: initialize decoder: %w", err)
	}
	defer reader.Close()
	n, err := io.CopyN(w, reader, f.size)
	if err != nil {
		return n, fmt.Errorf("zstd: decompress: %w", err)
	}
	if err := verifyZstdEnd(reader); err != nil {
		return n, err
	}
	return n, nil
}

func (f *File) WriteAt([]byte, int64) (int, error) { return 0, fmt.Errorf("zstd file is read-only") }
func (f *File) Size() int64                        { return f.size }
func (f *File) String() string {
	return fmt.Sprintf("<zstd.file compressed=%d size=%d>", f.base.Size(), f.size)
}
func (f *File) Type() string          { return "file" }
func (f *File) Freeze()               {}
func (f *File) Truth() starlark.Bool  { return starlark.True }
func (f *File) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", f.Type()) }
func (f *File) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *File) AttrNames() []string { return starfile.AttrNames() }

// Frame sizes are obtained without materializing the decoded stream. Streaming
// encoders may omit content sizes; only those streams require a counting pass.
func decodedSize(r storage.Reader, window uint32) (int64, error) {
	if r.Size() == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	var total uint64
	unknown := false
	off := int64(0)
	for off < r.Size() {
		var prefix [18]byte
		n, e := r.ReadAt(prefix[:min(int64(len(prefix)), r.Size()-off)], off)
		if e != nil {
			return 0, e
		}
		var h codec.Header
		if e = h.Decode(prefix[:n]); e != nil {
			return 0, fmt.Errorf("zstd header: %w", e)
		}
		off += int64(h.HeaderSize)
		if h.Skippable {
			off += int64(h.SkippableSize)
			if off > r.Size() {
				return 0, io.ErrUnexpectedEOF
			}
			continue
		}
		if h.DictionaryID != 0 {
			return 0, fmt.Errorf("zstd: external dictionary %d required", h.DictionaryID)
		}
		if !h.SingleSegment && h.WindowSize > uint64(window) {
			return 0, fmt.Errorf("zstd: window exceeds limit")
		}
		if h.HasFCS {
			if h.FrameContentSize > math.MaxInt64-total {
				return 0, fmt.Errorf("zstd: size overflow")
			}
			total += h.FrameContentSize
		} else {
			unknown = true
		}
		for {
			var b [3]byte
			if _, e = r.ReadAt(b[:], off); e != nil {
				return 0, e
			}
			off += 3
			v := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
			size := int64(v >> 3)
			typ := (v >> 1) & 3
			if size > 128<<10 || typ == 3 {
				return 0, fmt.Errorf("zstd: invalid block")
			}
			if typ == 1 {
				size = 1
			}
			off += size
			if v&1 != 0 {
				break
			}
			if off >= r.Size() {
				return 0, io.ErrUnexpectedEOF
			}
		}
		if h.HasCheckSum {
			off += 4
		}
		if off > r.Size() {
			return 0, io.ErrUnexpectedEOF
		}
	}
	if unknown {
		d, e := decoder(r, window)
		if e != nil {
			return 0, e
		}
		defer d.Close()
		return io.Copy(io.Discard, d)
	}
	return int64(total), nil
}
