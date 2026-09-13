package ibmisave

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"golang.org/x/text/encoding/charmap"
)

// sourceRecords recognizes the inspected, uncompressed type-3 data-space
// generation with 93-byte source rows. It does not classify arbitrary database
// data as source merely because some bytes happen to be printable.
func sourceRecords(s Section, number int) (map[string]any, *auto.Entry, error) {
	if s.Data.Size() < 32 {
		return nil, nil, nil
	}
	var header [32]byte
	if _, err := starfile.ReadFullAt(s.Data, header[:], 0); err != nil {
		return nil, nil, err
	}
	be := binary.BigEndian
	if be.Uint16(header[:]) != 3 || be.Uint32(header[24:]) != 93 {
		return nil, nil, nil
	}
	meta := map[string]any{"section": number, "record_size": 93, "record_offset": 32, "sequence_digits": 6, "sequence_decimal_places": 2, "date_digits": 6, "text_bytes": 80, "stored_size": s.Data.Size(), "logical_size": s.LogicalSize, "saved_ccsid": "unknown"}
	if s.Data.Size() > 1<<20 {
		meta["decoded"] = false
		meta["reason"] = "source record inspection exceeds 1 MiB bound"
		return meta, nil, nil
	}
	raw, err := starfile.ReadAll(s.Data)
	if err != nil {
		return nil, nil, err
	}
	var text strings.Builder
	var rows []map[string]any
	for off := 32; off < len(raw); {
		if raw[off] == 0 {
			if !bytes.Equal(raw[off:], make([]byte, len(raw)-off)) {
				meta["decoded"] = false
				meta["reason"] = "nonzero data after source row terminator"
				return meta, nil, nil
			}
			break
		}
		if len(raw)-off < 93 || raw[off] != 0x80 {
			meta["decoded"] = false
			meta["reason"] = "unsupported source row framing"
			return meta, nil, nil
		}
		row := raw[off : off+93]
		for _, c := range row[1:13] {
			if c < 0xf0 || c > 0xf9 {
				meta["decoded"] = false
				meta["reason"] = "source sequence/date is not unsigned zoned decimal"
				return meta, nil, nil
			}
		}
		line, err := charmap.CodePage037.NewDecoder().Bytes(row[13:])
		if err != nil {
			return nil, nil, err
		}
		text.Write(bytes.TrimRight(line, " "))
		text.WriteByte('\n')
		rows = append(rows, map[string]any{"sequence": textIdentifier(row[1:7]), "date_digits": textIdentifier(row[7:13]), "offset": off})
		off += 93
	}
	if len(rows) == 0 {
		return nil, nil, nil
	}
	meta["decoded"] = true
	meta["record_count"] = len(rows)
	meta["records"] = rows
	meta["rendering"] = "Explicit IBM037 rendering; saved CCSID has not been identified"
	file := &auto.Entry{Name: fmt.Sprintf("source-section%d.cp037.txt", number), Kind: "file", Reader: &starfile.Bytes{Data: []byte(text.String())}, Attributes: map[string]any{"content_view": "text", "encoding": "utf-8", "source_encoding": "IBM037 (explicit rendering, not detected CCSID)", "record_count": len(rows)}}
	return meta, file, nil
}
