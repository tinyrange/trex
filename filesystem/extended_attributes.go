package filesystem

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ValidateExtendedAttributes checks the bounded NTFS EA representation. Values
// are opaque: neither a catalog hint nor any other EA establishes file trust.
func ValidateExtendedAttributes(eas []ExtendedAttribute) error {
	packed, unpacked := 0, 0
	seen := map[string]bool{}
	for _, ea := range eas {
		key := strings.ToUpper(ea.Name)
		if len(ea.Name) == 0 || len(ea.Name) > 255 || strings.ContainsRune(ea.Name, 0) || len(ea.Value) > 65535 || ea.Flags&^byte(0x80) != 0 || seen[key] {
			return fmt.Errorf("invalid or duplicate extended attribute %q", ea.Name)
		}
		seen[key] = true
		packed += 5 + len(ea.Name) + len(ea.Value)
		unpacked += (8 + len(ea.Name) + 1 + len(ea.Value) + 3) &^ 3
		if packed > 65535 || unpacked > 65536 {
			return fmt.Errorf("extended attributes exceed 64 KiB")
		}
	}
	return nil
}

// DecodeFileFullEAInformation decodes a bounded native EA chain (not WIM's
// tightly packed EA format). All offsets are validated before slicing; returned
// names and values own their storage. A final record may omit alignment padding.
func DecodeFileFullEAInformation(data []byte) ([]ExtendedAttribute, error) {
	if len(data) < 9 || len(data) > 65536 {
		return nil, fmt.Errorf("invalid EA buffer length %d", len(data))
	}
	var result []ExtendedAttribute
	for offset := 0; ; {
		if len(data)-offset < 9 {
			return nil, fmt.Errorf("truncated EA header at %d", offset)
		}
		p := data[offset:]
		next := uint64(binary.LittleEndian.Uint32(p))
		n := int(p[5])
		size := 9 + n + int(binary.LittleEndian.Uint16(p[6:]))
		if n == 0 || size > len(p) || p[8+n] != 0 {
			return nil, fmt.Errorf("invalid EA record at %d", offset)
		}
		result = append(result, ExtendedAttribute{Name: string(p[8 : 8+n]), Flags: p[4], Value: append([]byte(nil), p[9+n:size]...)})
		if next == 0 {
			if len(p)-size > 3 {
				return nil, fmt.Errorf("trailing EA data at %d", offset+size)
			}
			break
		}
		if next&3 != 0 || next < uint64(size) || next > uint64(len(p)-9) {
			return nil, fmt.Errorf("invalid next EA offset at %d", offset)
		}
		offset += int(next)
	}
	if err := ValidateExtendedAttributes(result); err != nil {
		return nil, err
	}
	return result, nil
}
