// Package inno reads the ANSI Inno Setup Extensions 3.0.6.1 generation.
// It presents declared destination paths and portable lazy file readers, not
// an installation plan: conditions and setup code are never executed.
package inno

import (
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/tinyrange/trex/auto"
	binaryapi "github.com/tinyrange/trex/binary"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
)

var le = binary.LittleEndian

const version3061 = "My Inno Setup Extensions Setup Data (3.0.6.1)"

func init() { auto.Register("inno", 18, Open) }
func read(source storage.Reader, off, n int64) ([]byte, error) {
	if off < 0 || n < 0 || off > source.Size() || n > source.Size()-off || n > 512<<20 {
		return nil, fmt.Errorf("inno: extent outside source or limit")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(io.NewSectionReader(source, off, n), b)
	return b, err
}

// headerBlock checks both the header CRC and each framed 4 KiB chunk CRC.
func headerBlock(source storage.Reader, off, maximum int64) ([]byte, int64, error) {
	h, err := read(source, off, 12)
	if err != nil {
		return nil, off, err
	}
	if crc32.ChecksumIEEE(h[4:]) != le.Uint32(h) {
		return nil, off, fmt.Errorf("inno: header CRC mismatch")
	}
	packed, raw := int64(le.Uint32(h[4:])), int64(le.Uint32(h[8:]))
	stored := packed == 0xffffffff
	if stored {
		packed = raw
	}
	if packed > maximum || raw > maximum {
		return nil, off, auto.ErrLimit
	}
	off += 12
	compressed := make([]byte, 0, packed)
	for remaining := packed; remaining > 0; {
		n := min(remaining, int64(4096))
		b, e := read(source, off, n+4)
		if e != nil {
			return nil, off, e
		}
		if crc32.ChecksumIEEE(b[4:]) != le.Uint32(b) {
			return nil, off, fmt.Errorf("inno: header chunk CRC mismatch")
		}
		compressed = append(compressed, b[4:]...)
		off += n + 4
		remaining -= n
	}
	if stored {
		return compressed, off, nil
	}
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, off, err
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, raw+1))
	if err != nil {
		return nil, off, err
	}
	if int64(len(out)) != raw {
		return nil, off, fmt.Errorf("inno: header length mismatch")
	}
	return out, off, nil
}

type cursor struct {
	b   []byte
	at  int
	err error
}

func (c *cursor) take(n int) []byte {
	if c.err != nil {
		return make([]byte, max(0, min(n, 64)))
	}
	if n < 0 || n > len(c.b)-c.at {
		c.err = fmt.Errorf("inno: truncated record at %d", c.at)
		return make([]byte, max(0, min(n, 64)))
	}
	b := c.b[c.at : c.at+n]
	c.at += n
	return b
}
func (c *cursor) u32() uint32 { return le.Uint32(c.take(4)) }
func (c *cursor) blob() []byte {
	n := c.u32()
	if uint64(n) > uint64(len(c.b)) {
		c.err = fmt.Errorf("inno: oversized string")
		return nil
	}
	return c.take(int(n))
}
func (c *cursor) text() string {
	b := c.blob()
	s, err := binaryapi.DecodeText(b, "windows1252", false)
	if err != nil && c.err == nil {
		c.err = err
	}
	return s
}
func (c *cursor) strings(n int) {
	for i := 0; i < n; i++ {
		c.blob()
	}
}

type location struct {
	first, last, offset, size, packed, checksum uint32
	bzip                                        bool
}
type archive struct {
	source     storage.Reader
	dataOffset int64
	options    auto.Options
	cache      *bytecache.Cache
}
type file struct {
	archive  *archive
	location location
	index    int
}

func Open(prefix []byte, source storage.Reader, o auto.Options) (auto.View, error) {
	if len(prefix) < 60 || string(prefix[:2]) != "MZ" || string(prefix[48:52]) != "Inno" {
		return nil, auto.ErrNoMatch
	}
	tableOffset := le.Uint32(prefix[52:])
	if tableOffset != ^le.Uint32(prefix[56:]) {
		return nil, auto.ErrNoMatch
	}
	table, err := read(source, int64(tableOffset), 44)
	if err != nil {
		return nil, err
	}
	if string(table[:12]) != "rDlPtS02\x87eVx" {
		return nil, fmt.Errorf("inno: unsupported loader generation")
	}
	headerOffset, dataOffset := int64(le.Uint32(table[36:])), int64(le.Uint32(table[40:]))
	signature, err := read(source, headerOffset, 64)
	if err != nil {
		return nil, err
	}
	version := strings.TrimRight(string(signature), "\x00")
	if version != version3061 {
		return nil, fmt.Errorf("inno: unsupported setup data version %q", version)
	}
	maximum := o.MaxExpandedBytes
	if maximum <= 0 {
		maximum = 512 << 20
	}
	limit := o.MaxEntries
	if limit <= 0 {
		limit = 100000
	}
	primary, next, err := headerBlock(source, headerOffset+64, min(maximum, 64<<20))
	if err != nil {
		return nil, err
	}
	secondary, _, err := headerBlock(source, next, min(maximum, 64<<20))
	if err != nil {
		return nil, err
	}
	c := &cursor{b: primary}
	c.strings(23)
	c.take(32) // ANSI lead-byte set
	counts := make([]uint32, 13)
	for i := range counts {
		counts[i] = c.u32()
		if uint64(counts[i]) > uint64(limit) {
			return nil, auto.ErrLimit
		}
	}
	c.take(20 + 16 + 4 + 4 + 5) // Windows version range, colors, password CRC, space and enums
	flags := c.take(5)
	usesBzip := flags[4]&1 != 0
	c.strings(5)
	c.take(24) // single language and font metrics
	c.blob()
	c.blob() // large and small wizard images
	if usesBzip {
		c.blob()
	} // embedded decompressor DLL
	// These are declarative selection records, not executable setup effects.
	for i := uint32(0); i < counts[0]; i++ {
		c.strings(3)
		c.take(25)
	}
	for i := uint32(0); i < counts[1]; i++ {
		c.strings(4)
		c.take(34)
	}
	for i := uint32(0); i < counts[2]; i++ {
		c.strings(5)
		c.take(26)
	}
	for i := uint32(0); i < counts[3]; i++ {
		c.strings(4)
		c.take(25)
	}
	if c.err != nil {
		return nil, c.err
	}
	if uint64(counts[5])*41 != uint64(len(secondary)) {
		return nil, fmt.Errorf("inno: data record size mismatch: %d records, %d bytes", counts[5], len(secondary))
	}
	locations := make([]location, int(counts[5]))
	for i := range locations {
		b := secondary[i*41:]
		l := location{first: le.Uint32(b), last: le.Uint32(b[4:]), offset: le.Uint32(b[8:]), size: le.Uint32(b[12:]), packed: le.Uint32(b[16:]), checksum: le.Uint32(b[20:]), bzip: b[40]&4 != 0}
		if l.first == 0 || l.last < l.first || l.last-l.first > 1024 || int64(l.size) > maximum {
			return nil, fmt.Errorf("inno: invalid file location or expanded limit")
		}
		locations[i] = l
	}
	a := &archive{source: source, dataOffset: dataOffset, options: o, cache: bytecache.New(maximum)}
	var entries []auto.Entry
	seen := map[string]bool{}
	for i := uint32(0); i < counts[4]; i++ {
		sourceName, destination := c.text(), c.text()
		c.text() // font name
		components, tasks, check := c.text(), c.text(), c.text()
		c.take(20)
		index, attributes, externalSize := c.u32(), c.u32(), c.u32()
		fileFlags := c.u32()
		kind := c.take(1)[0]
		if c.err != nil {
			return nil, c.err
		}
		name := strings.ReplaceAll(destination, string([]byte{92}), "/")
		for _, component := range strings.Split(name, "/") {
			if component == ".." || strings.ContainsRune(component, 0) {
				return nil, fmt.Errorf("inno: unsafe destination")
			}
		}
		if fileFlags&(1<<12) == 0 && sourceName != "" {
			name = path.Join(name, path.Base(strings.ReplaceAll(sourceName, string([]byte{92}), "/")))
		}
		if name == "" {
			name = fmt.Sprintf("$installer/file-%d", i)
		}
		if strings.HasPrefix(name, "/") {
			return nil, fmt.Errorf("inno: absolute destination")
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." || strings.ContainsRune(part, 0) {
				return nil, fmt.Errorf("inno: unsafe destination")
			}
		}
		name = path.Clean(name)
		if seen[name] {
			return nil, fmt.Errorf("inno: duplicate destination %q", name)
		}
		seen[name] = true
		e := auto.Entry{Name: name, Kind: "file", Attributes: map[string]any{"source": sourceName, "destination": destination, "components": components, "tasks": tasks, "check": check, "file_flags": fileFlags, "attributes": attributes, "file_type": kind}}
		if index == 0xffffffff {
			e.Attributes["missing_contents"] = true
			e.Attributes["size"] = externalSize
			if relative := strings.ReplaceAll(sourceName, string([]byte{92}), "/"); strings.HasPrefix(relative, "{src}/") && o.Source != nil {
				part := strings.TrimPrefix(relative, "{src}/")
				for _, component := range strings.Split(part, "/") {
					if component == ".." || component == "." || component == "" || strings.ContainsAny(component, ":\x00") {
						return nil, fmt.Errorf("inno: unsafe external source")
					}
				}
				if strings.ContainsAny(part, "*?") {
					matches, lookupErr := a.expand(path.Join(path.Dir(o.Source.Path), part))
					if lookupErr != nil && !errors.Is(lookupErr, fs.ErrNotExist) {
						return nil, lookupErr
					}
					if len(matches) == 0 {
						// Preserve the declared missing source rather than silently
						// dropping an external wildcard from the inventory.
						entries = append(entries, e)
						continue
					}
					if fileFlags&(1<<12) != 0 {
						return nil, fmt.Errorf("inno: wildcard source with custom destination")
					}
					for _, match := range matches {
						expanded := e
						expanded.Name = path.Join(path.Dir(name), match.Name)
						if seen[expanded.Name] {
							return nil, fmt.Errorf("inno: duplicate expanded destination")
						}
						seen[expanded.Name] = true
						expanded.Reader = match.Reader
						expanded.Attributes = map[string]any{}
						for key, value := range e.Attributes {
							expanded.Attributes[key] = value
						}
						expanded.Attributes["missing_contents"] = false
						expanded.Attributes["size"] = match.Reader.Size()
						entries = append(entries, expanded)
						if len(entries) > limit {
							return nil, auto.ErrLimit
						}
					}
					continue
				}
				reader, lookupErr := a.companion(path.Join(path.Dir(o.Source.Path), part))
				if lookupErr == nil {
					e.Reader = reader
					e.Attributes["missing_contents"] = false
					e.Attributes["size"] = reader.Size()
				} else if !errors.Is(lookupErr, fs.ErrNotExist) {
					return nil, lookupErr
				}
			}
		} else {
			if uint64(index) >= uint64(len(locations)) {
				return nil, fmt.Errorf("inno: invalid file location index")
			}
			e.Reader = &file{archive: a, location: locations[index], index: int(index)}
		}
		entries = append(entries, e)
	}
	// Remaining primary bytes describe shortcuts, registry/setup actions and
	// compiled policy. Parsing the file inventory does not execute those actions.
	return auto.Tree(entries, o)
}
func (f *file) Size() int64 { return int64(f.location.size) }
func (f *file) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("inno: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.Size() {
		return 0, io.EOF
	}
	b, err := f.archive.cache.Get(bytecache.Key{Kind: 1, Index: f.index}, func() ([]byte, error) { return f.decode() })
	if err != nil {
		return 0, err
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (a *archive) slice(number uint32) (storage.Reader, int64, error) {
	if a.dataOffset != 0 {
		if number != 1 {
			return nil, 0, fmt.Errorf("inno: invalid embedded slice")
		}
		return a.source, a.source.Size(), nil
	}
	ctx := a.options.Source
	if ctx == nil {
		return nil, 0, fmt.Errorf("inno: external slices require a companion source tree")
	}
	base := strings.TrimSuffix(path.Base(ctx.Path), path.Ext(ctx.Path))
	name := path.Join(path.Dir(ctx.Path), fmt.Sprintf("%s-%d.bin", base, number))
	source, err := a.companion(name)
	if err != nil {
		return nil, 0, fmt.Errorf("inno: companion %q: %w", name, err)
	}
	h, err := read(source, 0, 12)
	if err != nil {
		return nil, 0, err
	}
	if string(h[:8]) != "idska32\x1a" && string(h[:8]) != "idska16\x1a" {
		return nil, 0, fmt.Errorf("inno: invalid slice signature")
	}
	size := int64(le.Uint32(h[8:]))
	if size < 12 || size > source.Size() {
		return nil, 0, fmt.Errorf("inno: invalid slice size")
	}
	return source, size, nil
}
func (f *file) decode() ([]byte, error) {
	l, a := f.location, f.archive
	remaining := int64(l.packed) + 4
	var readers []io.Reader
	for part := uint32(0); part <= l.last-l.first; part++ {
		number := l.first + part
		source, size, err := a.slice(number)
		if err != nil {
			return nil, err
		}
		offset := int64(12)
		if number == l.first {
			offset = int64(l.offset) + a.dataOffset
		}
		if offset < 0 || offset > size {
			return nil, fmt.Errorf("inno: chunk offset outside slice")
		}
		n := min(remaining, size-offset)
		readers = append(readers, io.NewSectionReader(source, offset, n))
		remaining -= n
		if remaining == 0 {
			if number != l.last {
				return nil, fmt.Errorf("inno: inconsistent last slice")
			}
			break
		}
	}
	if remaining != 0 {
		return nil, fmt.Errorf("inno: truncated chunk")
	}
	packed := io.MultiReader(readers...)
	var magic [4]byte
	if _, err := io.ReadFull(packed, magic[:]); err != nil || string(magic[:]) != "zlb\x1a" {
		return nil, fmt.Errorf("inno: invalid chunk signature")
	}
	var r io.Reader
	if l.bzip {
		r = bzip2.NewReader(packed)
	} else {
		z, err := zlib.NewReader(packed)
		if err != nil {
			return nil, err
		}
		defer z.Close()
		r = z
	}
	data, err := io.ReadAll(io.LimitReader(r, int64(l.size)+1))
	if err != nil {
		return nil, err
	}
	if len(data) != int(l.size) || adler32.Checksum(data) != l.checksum {
		return nil, fmt.Errorf("inno: file size or Adler32 mismatch")
	}
	return data, nil
}
