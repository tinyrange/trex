// Package rpm reads RPM package metadata without executing scriptlets or
// decompressing payloads. It reads lead versions 3/4 and v1 headers, including
// legacy IBM RPMs with a version-4 lead. Metadata is not authenticated.
// Format references: rpm-software-management/rpm docs/manual/format_lead.md,
// format_header.md, format_v4.md, and include/rpm/rpmtag.h.
// The implementation and fixtures are original.
package rpm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

// Limits bound both on-disk metadata and decoded values (including aliases).
type Limits struct{ MaximumEntries, MaximumBytes int }

func DefaultLimits() Limits { return Limits{65536, 16 << 20} }

// Entry retains unknown tags and their declared type. Integer types 1..5 use
// Numbers, STRING uses Text[0], string arrays use Text, and BIN uses Bytes.
type Entry struct {
	Tag, Type, Count uint32
	Numbers          []uint64
	Text             []string
	Bytes            []byte
}
type Header struct{ Entries []Entry }
type Package struct {
	Source            bool
	Signature, Header Header
	PayloadOffset     int64
	Payload           storage.Reader
}

type budget struct{ entries, bytes, decoded int64 }

func read(r storage.Reader, off, n int64) ([]byte, error) {
	if off < 0 || n < 0 || off > r.Size() || n > r.Size()-off {
		return nil, fmt.Errorf("rpm: metadata outside source")
	}
	b := make([]byte, int(n))
	_, err := io.ReadFull(io.NewSectionReader(r, off, n), b)
	return b, err
}

// Open borrows source only for Payload; all header values are retained in memory.
// Only metadata is read. The payload may be empty; no digest or signature is
// authenticated, and no claim is made that the payload matches its header.
func Open(source storage.Reader, limits Limits) (*Package, error) {
	if source == nil || limits.MaximumEntries < 1 || limits.MaximumEntries > 1<<20 || limits.MaximumBytes < 16 || limits.MaximumBytes > 256<<20 {
		return nil, fmt.Errorf("rpm: invalid source or limits")
	}
	lead, err := read(source, 0, 96)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(lead[:4], []byte{0xed, 0xab, 0xee, 0xdb}) || (lead[4] != 3 && lead[4] != 4) || lead[5] != 0 {
		return nil, fmt.Errorf("rpm: expected version 3/4 RPM lead")
	}
	kind := binary.BigEndian.Uint16(lead[6:8])
	if kind > 1 || binary.BigEndian.Uint16(lead[78:80]) != 5 {
		return nil, fmt.Errorf("rpm: unsupported package or signature type")
	}
	b := budget{int64(limits.MaximumEntries), int64(limits.MaximumBytes), int64(limits.MaximumBytes)}
	sig, end, err := readHeader(source, 96, &b)
	if err != nil {
		return nil, fmt.Errorf("rpm signature: %w", err)
	}
	// Only the signature header is padded to an eight-byte boundary.
	start := (end + 7) &^ 7
	padding, err := read(source, end, start-end)
	if err != nil {
		return nil, err
	}
	for _, v := range padding {
		if v != 0 {
			return nil, fmt.Errorf("rpm: nonzero signature padding")
		}
	}
	hdr, end, err := readHeader(source, start, &b)
	if err != nil {
		return nil, fmt.Errorf("rpm header: %w", err)
	}
	return &Package{Source: kind == 1, Signature: sig, Header: hdr, PayloadOffset: end, Payload: io.NewSectionReader(source, end, source.Size()-end)}, nil
}

func readHeader(source storage.Reader, off int64, budget *budget) (Header, int64, error) {
	h, err := read(source, off, 16)
	if err != nil {
		return Header{}, 0, err
	}
	if !bytes.Equal(h[:8], []byte{0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0}) {
		return Header{}, 0, fmt.Errorf("invalid header magic/version/reserved bytes")
	}
	n := int64(binary.BigEndian.Uint32(h[8:12]))
	size := int64(binary.BigEndian.Uint32(h[12:16]))
	total := 16 + n*16 + size
	if n > budget.entries || total > budget.bytes {
		return Header{}, 0, fmt.Errorf("metadata limit exceeded")
	}
	budget.entries -= n
	budget.bytes -= total
	raw, err := read(source, off+16, total-16)
	if err != nil {
		return Header{}, 0, err
	}
	data := raw[n*16:]
	result := Header{Entries: make([]Entry, 0, int(n))}
	seen := make(map[uint32]bool)
	for j := int64(0); j < n; j++ {
		idx := raw[j*16 : j*16+16]
		e := Entry{Tag: binary.BigEndian.Uint32(idx), Type: binary.BigEndian.Uint32(idx[4:]), Count: binary.BigEndian.Uint32(idx[12:])}
		pos := int64(binary.BigEndian.Uint32(idx[8:]))
		count := int64(e.Count)
		if seen[e.Tag] {
			return Header{}, 0, fmt.Errorf("duplicate tag %d", e.Tag)
		}
		seen[e.Tag] = true
		if pos > size {
			return Header{}, 0, fmt.Errorf("tag %d offset exceeds store", e.Tag)
		}
		switch e.Type {
		case 0:
			if count != 0 {
				return Header{}, 0, fmt.Errorf("nonempty NULL tag")
			}
		case 1, 2, 3, 4, 5:
			width := int64(1)
			if e.Type >= 3 {
				width = 1 << (e.Type - 2)
			}
			if pos%width != 0 || count > (size-pos)/width || count > budget.decoded/8 {
				return Header{}, 0, fmt.Errorf("tag %d invalid numeric bounds/alignment", e.Tag)
			}
			e.Numbers = make([]uint64, int(count))
			for k := range e.Numbers {
				v := uint64(0)
				for _, x := range data[pos : pos+width] {
					v = v<<8 | uint64(x)
				}
				e.Numbers[k] = v
				pos += width
			}
			budget.decoded -= count * 8
		case 6, 8, 9:
			if e.Type == 6 && count != 1 {
				return Header{}, 0, fmt.Errorf("STRING tag must have count one")
			}
			if count > size-pos || count > budget.decoded/16 {
				return Header{}, 0, fmt.Errorf("string count exceeds bounds")
			}
			// Charge both string descriptors and their copied contents.
			budget.decoded -= count * 16
			e.Text = make([]string, 0, int(count))
			for k := int64(0); k < count; k++ {
				remaining := size - pos
				if remaining > budget.decoded {
					remaining = budget.decoded
				}
				end := bytes.IndexByte(data[pos:pos+remaining], 0)
				if end < 0 {
					return Header{}, 0, fmt.Errorf("unterminated string or decoded metadata limit")
				}
				e.Text = append(e.Text, string(data[pos:pos+int64(end)]))
				pos += int64(end) + 1
				budget.decoded -= int64(end) + 1
			}
		case 7:
			if count > size-pos || count > budget.decoded {
				return Header{}, 0, fmt.Errorf("binary value exceeds bounds")
			}
			e.Bytes = data[pos : pos+count]
			pos += count
			budget.decoded -= count
		default:
			return Header{}, 0, fmt.Errorf("unsupported RPM type %d", e.Type)
		}
		result.Entries = append(result.Entries, e)
	}
	return result, off + total, nil
}
