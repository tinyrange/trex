package appledouble

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
	"unicode/utf8"
)

// Metadata keeps decoded FinderInfo, resource forks and named attributes as
// borrowed views. Unknown AppleDouble IDs are retained separately.
type Metadata struct {
	FinderInfo, Resource storage.Reader
	Attributes           map[string]storage.Reader
	Other                []Entry
}

// OpenMetadata decodes the macOS ATTR extension inside entry 9. Its offsets
// are absolute file offsets, not relative to FinderInfo. Layout provenance:
// apple-oss-distributions/xnu, xnu-2050.48.11, bsd/vfs/vfs_xattr.c.
// Only the bounded 64 KiB attribute header/table is read; data stays borrowed.
func OpenMetadata(r storage.Reader) (*Metadata, error) {
	entries, err := Open(r)
	if err != nil {
		return nil, err
	}
	m := &Metadata{Attributes: map[string]storage.Reader{}}
	for _, entry := range entries {
		switch entry.ID {
		case 2:
			m.Resource = entry.Data
		case 9:
			p := entry.Data.(part)
			if p.size < 32 {
				return nil, fmt.Errorf("appledouble: truncated FinderInfo")
			}
			m.FinderInfo = part{r, p.off, 32}
			if p.size == 32 {
				continue
			}
			start := p.off + 34 // FinderInfo followed by two alignment bytes
			if p.size < 70 {
				return nil, fmt.Errorf("appledouble: truncated ATTR header")
			}
			var h [36]byte
			if _, err := io.ReadFull(io.NewSectionReader(r, start, 36), h[:]); err != nil {
				return nil, err
			}
			be := binary.BigEndian
			total, dataStart, dataLength := int64(be.Uint32(h[8:])), int64(be.Uint32(h[12:])), int64(be.Uint32(h[16:]))
			count := int(be.Uint16(h[34:]))
			if be.Uint32(h[:]) != 0x41545452 || total > p.off+p.size || total < start+36 || dataStart < start+36 || dataStart > total || dataStart > 65536 || dataLength > total-dataStart {
				return nil, fmt.Errorf("appledouble: invalid ATTR bounds")
			}
			table := make([]byte, dataStart-start-36)
			if _, err := io.ReadFull(io.NewSectionReader(r, start+36, int64(len(table))), table); err != nil {
				return nil, err
			}
			var spans [][2]int64
			pos := 0
			for i := 0; i < count; i++ {
				if len(table)-pos < 11 {
					return nil, fmt.Errorf("appledouble: truncated ATTR entry")
				}
				e := table[pos:]
				off, length := int64(be.Uint32(e)), int64(be.Uint32(e[4:]))
				nameLength := int(e[10])
				width := (11 + nameLength + 3) &^ 3
				if nameLength < 2 || nameLength > 128 || width > len(e) {
					return nil, fmt.Errorf("appledouble: invalid ATTR name length")
				}
				name := e[11 : 11+nameLength]
				if name[nameLength-1] != 0 || bytes.IndexByte(name[:nameLength-1], 0) >= 0 || !utf8.Valid(name[:nameLength-1]) {
					return nil, fmt.Errorf("appledouble: invalid ATTR name")
				}
				key := string(name[:nameLength-1])
				if _, exists := m.Attributes[key]; exists {
					return nil, fmt.Errorf("appledouble: duplicate ATTR name")
				}
				if off < dataStart || off > dataStart+dataLength || length > dataStart+dataLength-off {
					return nil, fmt.Errorf("appledouble: invalid ATTR data extent")
				}
				for _, s := range spans {
					if length > 0 && off < s[1] && s[0] < off+length {
						return nil, fmt.Errorf("appledouble: overlapping ATTR data")
					}
				}
				spans = append(spans, [2]int64{off, off + length})
				m.Attributes[key] = part{r, off, length}
				pos += width
			}
		default:
			m.Other = append(m.Other, entry)
		}
	}
	return m, nil
}
