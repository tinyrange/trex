// Package os2pack reads IBM OS/2 PACK2 archives with FT19 compression.
package os2pack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"strings"
)

func init() {
	auto.Register("os2pack2", 10, func(prefix []byte, source storage.Reader, o auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte{0xa5, 0x96, 0xfd, 0xff}) {
			return nil, auto.ErrNoMatch
		}
		return Read(source, o)
	})
}

// Read validates absolute member/EA offsets and expands within the caller's
// aggregate limit. Extended attributes are retained as their native FEA bytes.
func Read(source storage.Reader, o auto.Options) (auto.View, error) {
	o = o.WithExpandedMaximum(o.MaxExpandedBytes)
	if source.Size() < 41 || source.Size() > 256<<20 {
		return nil, fmt.Errorf("PACK2 input size out of bounds")
	}
	data := make([]byte, int(source.Size()))
	if n, e := source.ReadAt(data, 0); n != len(data) {
		return nil, io.ErrUnexpectedEOF
	} else if e != nil && e != io.EOF {
		return nil, e
	}
	var entries []auto.Entry
	var expanded int64
	for pos := 0; ; {
		if len(entries) >= o.MaxEntries {
			return nil, auto.ErrLimit
		}
		if pos < 0 || pos > len(data)-41 {
			return nil, io.ErrUnexpectedEOF
		}
		h := data[pos:]
		if !bytes.HasPrefix(h, []byte{0xa5, 0x96, 0xfd, 0xff}) || string(h[24:31]) != "FTCOMP\x00" {
			return nil, fmt.Errorf("PACK2 invalid member at %d", pos)
		}
		ea := int(binary.LittleEndian.Uint32(h[12:]))
		size := int64(binary.LittleEndian.Uint32(h[16:]))
		next := int(binary.LittleEndian.Uint32(h[20:]))
		easize := int64(binary.LittleEndian.Uint32(h[35:]))
		namesize := int(binary.LittleEndian.Uint16(h[39:]))
		start := pos + 41 + namesize
		end := next
		if end == 0 {
			end = len(data)
		}
		if namesize < 1 || namesize > 512 || start > end || end > len(data) || end <= pos {
			return nil, fmt.Errorf("PACK2 invalid member bounds at %d", pos)
		}
		name := strings.TrimRight(string(data[pos+41:start]), "\x00")
		name = strings.TrimLeft(strings.ReplaceAll(name, "\\", "/"), "/")
		if strings.ContainsRune(name, 0) || name == "" {
			return nil, fmt.Errorf("PACK2 invalid name")
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return nil, fmt.Errorf("PACK2 parent traversal")
			}
		}
		if size > o.MaxExpandedBytes-expanded || easize > o.MaxExpandedBytes-expanded-size {
			return nil, auto.ErrLimit
		}
		expanded += size + easize
		payloadEnd := end
		if ea != 0 {
			if ea < start || ea > end {
				return nil, fmt.Errorf("PACK2 invalid EA offset")
			}
			payloadEnd = ea
		} else if easize != 0 && easize != 4 {
			return nil, fmt.Errorf("PACK2 missing EAs")
		}
		body, e := DecodeFT19(data[start:payloadEnd], size)
		if e != nil {
			return nil, fmt.Errorf("PACK2 %s: %w", name, e)
		}
		attrs := map[string]any{"dos_attributes": h[8], "dos_datetime": binary.LittleEndian.Uint32(h[4:]), "compression": "FT19"}
		if ea != 0 {
			attrs["extended_attributes"], e = DecodeFT19(data[ea:end], easize)
			if e != nil {
				return nil, fmt.Errorf("PACK2 %s EAs: %w", name, e)
			}
		}
		entries = append(entries, auto.Entry{Name: name, Kind: "file", Reader: &starfile.Bytes{Data: body}, Attributes: attrs})
		if next == 0 {
			break
		}
		pos = next
	}
	return auto.Tree(entries, o)
}
