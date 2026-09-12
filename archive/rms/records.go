// Package rms decodes OpenVMS record framing without translating record data
// or applying terminal/printer carriage-control semantics.
package rms

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

type Record struct {
	Offset  int64
	Control storage.Reader
	Data    storage.Reader
}

// VariableRecords reads sequential VAR or VFC records using the 32-byte RMS
// attributes found in ODS-2 headers and BACKUP file attributes. Returned data
// and fixed control areas are borrowed views; length words, alignment bytes
// and end-of-block padding are not part of either view. Unknown organizations,
// record formats and extended record attributes are rejected, not guessed.
func VariableRecords(source storage.Reader, attributes []byte, maximumRecords int) ([]Record, error) {
	if len(attributes) != 32 || maximumRecords < 1 || source.Size() < 0 {
		return nil, fmt.Errorf("rms: invalid attributes, record limit or source size")
	}
	format, flags := attributes[0], attributes[1]
	if format != 2 && format != 3 {
		return nil, fmt.Errorf("rms: expected sequential VAR or VFC format, got %02x", format)
	}
	if flags&0xf0 != 0 {
		return nil, fmt.Errorf("rms: unsupported record attributes %02x", flags)
	}
	maximum := int64(binary.LittleEndian.Uint16(attributes[2:]))
	control := int64(0)
	if format == 3 {
		control = int64(attributes[15])
	}
	records := []Record{}
	for offset := int64(0); offset < source.Size(); {
		var header [2]byte
		if source.Size()-offset < 2 {
			return nil, fmt.Errorf("rms: truncated length at %d", offset)
		}
		if err := readExact(source, header[:], offset); err != nil {
			return nil, err
		}
		length := int64(binary.LittleEndian.Uint16(header[:]))
		if length == 0xffff {
			skip := 512 - offset%512
			if skip > source.Size()-offset {
				return nil, fmt.Errorf("rms: truncated block padding at %d", offset)
			}
			offset += skip
			continue
		}
		if len(records) >= maximumRecords {
			return nil, fmt.Errorf("rms: record limit")
		}
		if length < control || maximum != 0 && length-control > maximum {
			return nil, fmt.Errorf("rms: invalid record length %d at %d", length, offset)
		}
		stored := 2 + length + length%2
		if stored > source.Size()-offset {
			return nil, fmt.Errorf("rms: truncated record at %d", offset)
		}
		if flags&8 != 0 && stored > 512-offset%512 {
			return nil, fmt.Errorf("rms: forbidden block span at %d", offset)
		}
		records = append(records, Record{
			Offset:  offset,
			Control: io.NewSectionReader(source, offset+2, control),
			Data:    io.NewSectionReader(source, offset+2+control, length-control),
		})
		offset += stored
	}
	return records, nil
}

func readExact(source storage.Reader, p []byte, offset int64) error {
	n, err := source.ReadAt(p, offset)
	if n == len(p) && (err == nil || err == io.EOF) {
		return nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("rms: read at %d: %w", offset, err)
}
