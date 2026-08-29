package acpi

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const acpiHeaderSize = 36

// Table constructs an ACPI system-description table and computes its checksum.
func Table(signature string, body []byte, revision int, oemID, oemTableID string, oemRevision uint64, creatorID string, creatorRevision uint64) ([]byte, error) {
	if err := acpiFixedName("signature", signature, 4); err != nil {
		return nil, err
	}
	if err := acpiFixedName("OEM ID", oemID, 6); err != nil {
		return nil, err
	}
	if err := acpiFixedName("OEM table ID", oemTableID, 8); err != nil {
		return nil, err
	}
	if err := acpiFixedName("creator ID", creatorID, 4); err != nil {
		return nil, err
	}
	if revision < 0 || revision > 0xff || oemRevision > uint64(^uint32(0)) || creatorRevision > uint64(^uint32(0)) {
		return nil, fmt.Errorf("revision is out of range")
	}
	if len(body) > int(^uint32(0))-acpiHeaderSize {
		return nil, fmt.Errorf("table body is too large")
	}
	table := make([]byte, acpiHeaderSize, acpiHeaderSize+len(body))
	copy(table[0:4], signature)
	binary.LittleEndian.PutUint32(table[4:8], uint32(acpiHeaderSize+len(body)))
	table[8] = byte(revision)
	copy(table[10:16], oemID)
	copy(table[16:24], oemTableID)
	binary.LittleEndian.PutUint32(table[24:28], uint32(oemRevision))
	copy(table[28:32], creatorID)
	binary.LittleEndian.PutUint32(table[32:36], uint32(creatorRevision))
	table = append(table, body...)
	var checksum byte
	for _, value := range table {
		checksum += value
	}
	table[9] = -checksum
	return table, nil
}

// CompatibleIDAML constructs AML declaring a _CID value under device.
func CompatibleIDAML(device, compatibleID string) ([]byte, error) {
	name, err := acpiAbsoluteName(device)
	if err != nil {
		return nil, err
	}
	if err := acpiNameString("compatible ID", compatibleID, 1, 8); err != nil {
		return nil, err
	}
	body := append([]byte(nil), name...)
	body = append(body, 0x08, '_', 'C', 'I', 'D') // NameOp, _CID
	if eisaID, ok := acpiEISAID(compatibleID); ok {
		body = append(body, 0x0c) // DWordPrefix
		body = binary.LittleEndian.AppendUint32(body, eisaID)
	} else {
		body = append(body, 0x0d) // StringPrefix
		body = append(body, compatibleID...)
		body = append(body, 0)
	}
	aml := []byte{0x10} // ScopeOp
	aml = append(aml, acpiPackageLength(len(body))...)
	return append(aml, body...), nil
}

func acpiEISAID(value string) (uint32, bool) {
	if len(value) != 7 {
		return 0, false
	}
	var vendor uint16
	for _, char := range []byte(value[:3]) {
		if char < 'A' || char > 'Z' {
			return 0, false
		}
		vendor = vendor<<5 | uint16(char-'A'+1)
	}
	var product uint16
	for _, char := range []byte(value[3:]) {
		product <<= 4
		switch {
		case char >= '0' && char <= '9':
			product |= uint16(char - '0')
		case char >= 'A' && char <= 'F':
			product |= uint16(char-'A') + 10
		default:
			return 0, false
		}
	}
	vendor = vendor<<8 | vendor>>8
	return uint32(product)<<16 | uint32(vendor), true
}

func acpiAbsoluteName(name string) ([]byte, error) {
	if !strings.HasPrefix(name, `\`) {
		return nil, fmt.Errorf("ACPI device path %q is not absolute", name)
	}
	parts := strings.Split(strings.TrimPrefix(name, `\`), ".")
	if len(parts) == 0 || len(parts) > 255 {
		return nil, fmt.Errorf("ACPI device path %q has invalid depth", name)
	}
	out := []byte{'\\'}
	if len(parts) == 2 {
		out = append(out, 0x2e)
	} else if len(parts) > 2 {
		out = append(out, 0x2f, byte(len(parts)))
	}
	for _, part := range parts {
		if err := acpiNameString("device path segment", part, 1, 4); err != nil {
			return nil, err
		}
		out = append(out, part...)
		out = append(out, strings.Repeat("_", 4-len(part))...)
	}
	return out, nil
}

func acpiFixedName(kind, value string, length int) error {
	if len(value) != length {
		return fmt.Errorf("ACPI %s %q must be exactly %d characters", kind, value, length)
	}
	for _, char := range []byte(value) {
		if char < 0x20 || char > 0x7e {
			return fmt.Errorf("ACPI %s %q contains a non-printable character", kind, value)
		}
	}
	return nil
}

func acpiNameString(kind, value string, minimum, maximum int) error {
	if len(value) < minimum || len(value) > maximum {
		return fmt.Errorf("ACPI %s %q must be %d..%d characters", kind, value, minimum, maximum)
	}
	for index, char := range []byte(value) {
		if !((char >= 'A' && char <= 'Z') || char == '_' || (index > 0 && char >= '0' && char <= '9')) {
			return fmt.Errorf("ACPI %s %q contains an invalid character", kind, value)
		}
	}
	return nil
}

func acpiPackageLength(bodyLength int) []byte {
	for width := 1; width <= 4; width++ {
		length := bodyLength + width
		if width == 1 && length <= 0x3f {
			return []byte{byte(length)}
		}
		if width > 1 && length < 1<<(4+8*(width-1)) {
			out := make([]byte, width)
			out[0] = byte((width-1)<<6) | byte(length&0x0f)
			length >>= 4
			for index := 1; index < width; index++ {
				out[index] = byte(length)
				length >>= 8
			}
			return out
		}
	}
	panic("ACPI package is too large")
}
