// Package nls decodes Windows National Language Support data without relying
// on the host operating system's locale implementation.
package nls

import (
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"

	"github.com/tinyrange/trex/storage"
)

const (
	sortHeaderSize = 16
	sortGUIDSize   = 40
	baseKeyCount   = 1 << 16

	normIgnoreCase     = 0x00000001
	normIgnoreNonspace = 0x00000002
	normIgnoreSymbols  = 0x00000004
	normIgnoreKanaType = 0x00010000
	normIgnoreWidth    = 0x00020000

	scriptUnsortable  = 0
	scriptNonspace    = 1
	scriptExpansion   = 2
	scriptEastAsia    = 3
	scriptJamo        = 4
	scriptExtensionA  = 5
	scriptPunctuation = 6
	scriptSymbolLast  = 12
	scriptArabic      = 41
	scriptHebrew      = 40

	caseFullWidth = 0x01
	caseFullSize  = 0x02
	caseSubscript = 0x08
	caseUpper     = 0x10
	caseKatakana  = 0x20
	caseCompress  = 0xc0
)

// SortTable is the decoded, immutable part of SortDefault.nls needed to
// produce Windows sort keys. It owns its input bytes and is safe to reuse.
type SortTable struct {
	data       []byte
	keysOffset uint32
	guids      []sortGUID
}

type sortGUID struct {
	id            [16]byte
	flags         uint32
	compression   uint32
	exception     uint32
	lingException uint32
	caseMap       uint32
}

// OpenSortDefault reads and validates a Windows SortDefault.nls file through
// TinyRange's portable storage abstraction.
func OpenSortDefault(source storage.Reader) (*SortTable, error) {
	if source == nil {
		return nil, fmt.Errorf("nls: nil SortDefault source")
	}
	if source.Size() < sortHeaderSize || source.Size() > int64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("nls: invalid SortDefault size %d", source.Size())
	}
	data := make([]byte, int(source.Size()))
	if _, err := readFullAt(source, data, 0); err != nil {
		return nil, fmt.Errorf("nls: read SortDefault: %w", err)
	}
	return parseSortDefault(data)
}

func parseSortDefault(data []byte) (*SortTable, error) {
	if len(data) < sortHeaderSize {
		return nil, fmt.Errorf("nls: short SortDefault header")
	}
	keys := binary.LittleEndian.Uint32(data[0:4])
	caseMaps := binary.LittleEndian.Uint32(data[4:8])
	ctypes := binary.LittleEndian.Uint32(data[8:12])
	sortIDs := binary.LittleEndian.Uint32(data[12:16])
	if keys < sortHeaderSize || keys > caseMaps || caseMaps > ctypes || ctypes > sortIDs || uint64(sortIDs)+8 > uint64(len(data)) {
		return nil, fmt.Errorf("nls: invalid SortDefault section offsets %#x/%#x/%#x/%#x", keys, caseMaps, ctypes, sortIDs)
	}
	if uint64(keys)+baseKeyCount*4 > uint64(caseMaps) {
		return nil, fmt.Errorf("nls: SortDefault key section is too small")
	}
	count := binary.LittleEndian.Uint32(data[sortIDs+4 : sortIDs+8])
	guidsEnd := uint64(sortIDs) + 8 + uint64(count)*sortGUIDSize
	if guidsEnd > uint64(len(data)) {
		return nil, fmt.Errorf("nls: %d sort GUIDs exceed the file", count)
	}
	guids := make([]sortGUID, count)
	for index := range guids {
		offset := int(sortIDs) + 8 + index*sortGUIDSize
		copy(guids[index].id[:], data[offset:offset+16])
		guids[index].flags = binary.LittleEndian.Uint32(data[offset+16 : offset+20])
		guids[index].compression = binary.LittleEndian.Uint32(data[offset+20 : offset+24])
		guids[index].exception = binary.LittleEndian.Uint32(data[offset+24 : offset+28])
		guids[index].lingException = binary.LittleEndian.Uint32(data[offset+28 : offset+32])
		guids[index].caseMap = binary.LittleEndian.Uint32(data[offset+32 : offset+36])
	}
	return &SortTable{data: append([]byte(nil), data...), keysOffset: keys, guids: guids}, nil
}

// SortKey applies the requested persisted LCMap flags using one sort GUID.
// The returned bytes have the same level separators and terminator as
// LCMapStringEx(..., LCMAP_SORTKEY, ...). The current implementation covers
// ordinary BMP weights, symbols, and punctuation; it rejects expansion,
// compression, East Asian, and Hangul records instead of silently emitting a
// key with different ordering semantics.
func (table *SortTable) SortKey(text string, flags uint32, sortID []byte) ([]byte, error) {
	if table == nil {
		return nil, fmt.Errorf("nls: nil sort table")
	}
	if len(sortID) != 16 {
		return nil, fmt.Errorf("nls: sort ID is %d bytes, want 16", len(sortID))
	}
	guid, present := table.findGUID(sortID)
	if !present {
		return nil, fmt.Errorf("nls: sort ID %x is not present", sortID)
	}
	caseMask := byte(0x3f)
	if flags&normIgnoreCase != 0 {
		caseMask &^= caseUpper | caseSubscript
	}
	if flags&normIgnoreWidth != 0 {
		caseMask &^= caseFullWidth
	}
	if flags&normIgnoreKanaType != 0 {
		caseMask &^= caseKatakana
	}

	var primary, diacritic, casing, special []byte
	for position, character := range utf16.Encode([]rune(text)) {
		weight, err := table.characterWeight(character, guid.exception)
		if err != nil {
			return nil, fmt.Errorf("nls: character U+%04X at %d: %w", character, position, err)
		}
		primaryWeight := byte(weight)
		script := byte(weight >> 8)
		diacriticWeight := byte(weight >> 16)
		caseWeight := byte(weight>>24) & caseMask
		if byte(weight>>24)&caseCompress != 0 {
			return nil, fmt.Errorf("nls: compressed character weights are not implemented")
		}
		switch script {
		case scriptUnsortable:
			continue
		case scriptNonspace:
			if flags&normIgnoreNonspace == 0 {
				if len(diacritic) == 0 {
					diacritic = append(diacritic, diacriticWeight)
				} else {
					diacritic[len(diacritic)-1] += diacriticWeight
				}
			}
			continue
		case scriptExpansion, scriptEastAsia, scriptJamo, scriptExtensionA:
			return nil, fmt.Errorf("nls: sort script %d is not implemented", script)
		case scriptPunctuation:
			if flags&normIgnoreSymbols != 0 {
				continue
			}
			// Punctuation is ordered after ordinary levels. The signed position
			// is measured in two-byte primary weights, matching Windows NLS.
			location := int16(-(len(primary)/2 + 1))
			special = append(special, byte(location>>8), byte(location), primaryWeight, caseWeight|(diacriticWeight<<3))
			continue
		default:
			if script <= scriptSymbolLast && flags&normIgnoreSymbols != 0 {
				continue
			}
			primary = append(primary, script, primaryWeight)
			if flags&normIgnoreNonspace == 0 {
				diacritic = append(diacritic, diacriticWeight)
			}
			casing = append(casing, caseWeight)
		}
	}
	diacritic = trimDefaultWeights(diacritic)
	casing = trimDefaultWeights(casing)
	result := make([]byte, 0, len(primary)+len(diacritic)+len(casing)+len(special)+5)
	result = append(result, primary...)
	result = append(result, 0x01)
	result = append(result, diacritic...)
	result = append(result, 0x01)
	result = append(result, casing...)
	result = append(result, 0x01, 0x01)
	result = append(result, special...)
	result = append(result, 0x00)
	return result, nil
}

func (table *SortTable) findGUID(identifier []byte) (sortGUID, bool) {
	for _, guid := range table.guids {
		if string(guid.id[:]) == string(identifier) {
			return guid, true
		}
	}
	return sortGUID{}, false
}

func (table *SortTable) characterWeight(character uint16, exception uint32) (uint32, error) {
	index := uint32(character)
	if exception != 0 {
		pageIndex, err := table.keyAt(exception + uint32(character>>8))
		if err != nil {
			return 0, err
		}
		index = pageIndex + uint32(character&0xff)
	}
	return table.keyAt(index)
}

func (table *SortTable) keyAt(index uint32) (uint32, error) {
	offset := uint64(table.keysOffset) + uint64(index)*4
	if offset+4 > uint64(len(table.data)) {
		return 0, fmt.Errorf("sort-key index %#x exceeds the key section", index)
	}
	return binary.LittleEndian.Uint32(table.data[offset : offset+4]), nil
}

func trimDefaultWeights(values []byte) []byte {
	for len(values) > 0 && values[len(values)-1] <= 2 {
		values = values[:len(values)-1]
	}
	return values
}

func readFullAt(reader io.ReaderAt, data []byte, offset int64) (int, error) {
	total := 0
	for total < len(data) {
		count, err := reader.ReadAt(data[total:], offset+int64(total))
		total += count
		if err != nil {
			if err == io.EOF && total == len(data) {
				return total, nil
			}
			return total, err
		}
		if count == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}
