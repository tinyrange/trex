package wim

import (
	"bytes"
	"encoding/binary"
	"fmt"

	virtualfs "github.com/tinyrange/trex/filesystem"
)

// WIMGAPI (Windows 10 1607+) tag 2 stores tightly packed EAs. Its
// value-length/name-length/flags header differs from NTFS FILE_FULL_EA_INFORMATION.
func parseWIMEAs(data []byte) ([]virtualfs.ExtendedAttribute, error) {
	var result []virtualfs.ExtendedAttribute
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, fmt.Errorf("wim: truncated EA header")
		}
		valueLen := int(binary.LittleEndian.Uint16(data))
		nameLen := int(data[2])
		end := 4 + nameLen + 1 + valueLen
		if nameLen == 0 || end > len(data) || data[4+nameLen] != 0 || bytes.IndexByte(data[4:4+nameLen], 0) >= 0 || data[3]&^byte(0x80) != 0 {
			return nil, fmt.Errorf("wim: invalid EA name, flags or length")
		}
		result = append(result, virtualfs.ExtendedAttribute{Name: string(data[4 : 4+nameLen]), Flags: data[3], Value: data[5+nameLen : end]})
		data = data[end:]
	}
	return result, nil
}
