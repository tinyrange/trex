package rar

import (
	"fmt"
	"github.com/tinyrange/trex/archive/internal/rarcodec"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	"hash"
	"hash/crc32"
	"io"
	"sync"
)

const pageSize = 64 << 10

// Archive indexes headers only. Payload pages are decoded on demand with a
// bounded cache; backwards seeks replay from the nearest independent member.
type Archive struct {
	source   storage.Reader
	Files    []*File
	cache    *bytecache.Cache
	mu       sync.Mutex
	decoder  rarcodec.Reader
	current  int
	offset   int64
	stream   io.Reader
	crc      hash.Hash32
	terminal error
	verified bool
}
type File struct {
	Header
	archive      *Archive
	index        int
	storedCRC    hash.Hash32
	storedOffset int64
}

func Open(source storage.Reader, maximumEntries int) (*Archive, error) {
	headers, e := Headers(source, maximumEntries)
	if e != nil {
		return nil, e
	}
	a := &Archive{source: source, cache: bytecache.New(2 << 20), current: -1}
	for i, h := range headers {
		a.Files = append(a.Files, &File{Header: h, archive: a, index: i})
	}
	return a, nil
}
func (a *Archive) start(i int) error {
	f := a.Files[i]
	a.stream = nil
	if f.Encrypted {
		return fmt.Errorf("rar: member %q requires a password", f.Name)
	}
	src := io.NewSectionReader(a.source, f.Offset, f.PackedSize)
	a.current = i
	a.offset = 0
	a.terminal = nil
	a.verified = false
	a.crc = crc32.NewIEEE()
	if f.Method == 0 {
		if f.Size() != f.PackedSize {
			return fmt.Errorf("rar: stored size mismatch")
		}
		a.stream = src
	} else {
		if f.Method < 1 || f.Method > 5 {
			return fmt.Errorf("rar: unknown compression method %d", f.Method)
		}
		if e := a.decoder.Reset(src, f.Version, f.Dictionary, f.Size(), f.Solid); e != nil {
			return e
		}
		a.stream = &a.decoder
	}
	return nil
}
func (a *Archive) read(p []byte) (int, error) {
	if a.terminal != nil {
		return 0, a.terminal
	}
	f := a.Files[a.current]
	if int64(len(p)) > f.Size()-a.offset {
		p = p[:f.Size()-a.offset]
	}
	n, e := io.ReadFull(a.stream, p)
	a.offset += int64(n)
	a.crc.Write(p[:n])
	if e != nil {
		a.terminal = fmt.Errorf("rar: %s at %d: %w", f.Name, a.offset, e)
		return n, a.terminal
	}
	if a.offset == f.Size() && !a.verified {
		// Consume the actual stream terminator, even when the caller requested
		// exactly the declared length. This also finishes the solid model state.
		var extra [1]byte
		nn, ee := a.stream.Read(extra[:])
		if nn != 0 || ee != io.EOF {
			if ee == nil {
				ee = fmt.Errorf("decoded data exceeds member length")
			}
			a.terminal = fmt.Errorf("rar: %s terminator: %w", f.Name, ee)
			return n, a.terminal
		}
		if f.HasCRC && a.crc.Sum32() != f.CRC {
			a.terminal = fmt.Errorf("rar: %s data CRC mismatch", f.Name)
			return n, a.terminal
		}
		a.verified = true
	}
	return n, nil
}
func (a *Archive) skip(n int64) error {
	var buf [pageSize]byte
	for n > 0 {
		k := min(n, int64(len(buf)))
		nn, e := a.read(buf[:k])
		if e != nil {
			return e
		}
		if nn == 0 {
			return io.ErrNoProgress
		}
		n -= int64(nn)
	}
	if a.offset == a.Files[a.current].Size() && !a.verified {
		_, e := a.read(nil)
		return e
	}
	return nil
}
func (a *Archive) seek(i int, off int64) error {
	if a.current == i && a.stream != nil && off >= a.offset {
		return a.skip(off - a.offset)
	}
	// Continue a solid chain in order when possible. Otherwise restart at its
	// first non-solid member; unrelated members need no decompression.
	start := i
	if a.Files[i].Solid {
		for start > 0 && a.Files[start].Solid {
			start--
		}
	}
	if a.current >= start && a.current < i && a.stream != nil {
		if e := a.skip(a.Files[a.current].Size() - a.offset); e != nil {
			return e
		}
		start = a.current + 1
	} else {
		a.decoder = rarcodec.Reader{}
		a.stream = nil
	}
	for j := start; j <= i; j++ {
		if e := a.start(j); e != nil {
			return e
		}
		if j < i {
			if e := a.skip(a.Files[j].Size()); e != nil {
				return e
			}
		}
	}
	return a.skip(off)
}
func (f *File) Size() int64 { return f.Header.Size }
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("rar: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.Size() {
		return 0, io.EOF
	}
	if f.Method == 0 {
		return f.readStoredAt(p, off)
	}
	total := 0
	for len(p) > 0 && off < f.Size() {
		page := off / pageSize * pageSize
		data, e := f.archive.cache.Get(bytecache.Key{Index: f.index, Offset: page}, func() ([]byte, error) {
			a := f.archive
			a.mu.Lock()
			defer a.mu.Unlock()
			if e := a.seek(f.index, page); e != nil {
				return nil, e
			}
			b := make([]byte, min(int64(pageSize), f.Size()-page))
			_, e := a.read(b)
			return b, e
		})
		if e != nil {
			return total, e
		}
		n := copy(p, data[off-page:])
		p = p[n:]
		off += int64(n)
		total += n
	}
	if len(p) > 0 {
		return total, io.EOF
	}
	return total, nil
}

// Stored members are already random-access bytes. Do not replay a multi-GB
// prefix to satisfy a small read near the end. Consecutive reads from offset
// zero verify the CRC; Verify remains available for arbitrary access patterns.
func (f *File) readStoredAt(p []byte, off int64) (int, error) {
	f.archive.mu.Lock()
	defer f.archive.mu.Unlock()
	if f.Encrypted || f.Size() != f.PackedSize {
		return 0, fmt.Errorf("rar: invalid or encrypted stored member %q", f.Name)
	}
	requested := len(p)
	p = p[:min(int64(len(p)), f.Size()-off)]
	n, err := f.archive.source.ReadAt(p, f.Offset+off)
	if off == 0 {
		f.storedCRC = crc32.NewIEEE()
		f.storedOffset = 0
	}
	if f.storedCRC != nil && off == f.storedOffset {
		f.storedCRC.Write(p[:n])
		f.storedOffset += int64(n)
		if f.storedOffset == f.Size() && f.HasCRC && f.storedCRC.Sum32() != f.CRC {
			return n, fmt.Errorf("rar: %s data CRC mismatch", f.Name)
		}
	} else {
		f.storedCRC = nil
	}
	if err == nil && n < requested {
		err = io.EOF
	}
	return n, err
}

// Verify reads the entire member and verifies its terminator and checksum.
func (f *File) Verify() error { _, e := f.WriteTo(io.Discard); return e }
func (f *File) WriteTo(w io.Writer) (int64, error) {
	a := f.archive
	a.mu.Lock()
	defer a.mu.Unlock()
	if e := a.seek(f.index, 0); e != nil {
		return 0, e
	}
	var buf [pageSize]byte
	var total int64
	for total < f.Size() {
		n, e := a.read(buf[:min(int64(len(buf)), f.Size()-total)])
		if e != nil {
			return total, e
		}
		nn, e := w.Write(buf[:n])
		total += int64(nn)
		if e != nil {
			return total, e
		}
		if nn != n {
			return total, io.ErrShortWrite
		}
	}
	if !a.verified {
		_, e := a.read(nil)
		return total, e
	}
	return total, nil
}
func (a *Archive) View(options auto.Options) (auto.View, error) {
	entries := make([]auto.Entry, 0, len(a.Files))
	for _, f := range a.Files {
		e := auto.Entry{Name: f.Name, Kind: "file", Reader: f, Attributes: map[string]any{"size": f.Size(), "packed_size": f.PackedSize, "solid": f.Solid, "compression_version": f.Version, "method": f.Method}}
		if f.Directory {
			e.Kind = "directory"
			e.Reader = nil
		}
		entries = append(entries, e)
	}
	return auto.Tree(entries, options)
}
func init() {
	auto.Register("rar", 10, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 7 || string(p[:6]) != "Rar!\x1a\x07" {
			return nil, auto.ErrNoMatch
		}
		a, e := Open(r, o.MaxEntries)
		if e != nil {
			return nil, e
		}
		return a.View(o)
	})
}
