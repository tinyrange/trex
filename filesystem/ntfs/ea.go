package ntfs

import (
	"encoding/binary"
	"fmt"
	"strings"

	filesystemapi "github.com/tinyrange/trex/filesystem"
)

const (
	ntfsAttrEAInformation uint32 = 0xd0
	ntfsAttrEA            uint32 = 0xe0
)

// Encode FILE_FULL_EA_INFORMATION, including four-byte record alignment, and
// the packed length/NEED_EA count/unpacked length in $EA_INFORMATION.
func ntfsEncodeEAs(eas []filesystemapi.ExtendedAttribute) (info, data []byte, err error) {
	if len(eas) == 0 {
		return nil, nil, nil
	}
	packed, need := 0, 0
	seen := map[string]bool{}
	for i, ea := range eas {
		key := strings.ToUpper(ea.Name)
		if len(ea.Name) == 0 || len(ea.Name) > 255 || strings.ContainsRune(ea.Name, 0) || len(ea.Value) > 65535 || ea.Flags&^byte(0x80) != 0 || seen[key] {
			return nil, nil, fmt.Errorf("ntfs: invalid or duplicate extended attribute %q", ea.Name)
		}
		seen[key] = true
		packed += 5 + len(ea.Name) + len(ea.Value)
		size := (8 + len(ea.Name) + 1 + len(ea.Value) + 3) &^ 3
		if packed > 65535 || len(data)+size > 65536 {
			return nil, nil, fmt.Errorf("ntfs: extended attributes exceed 64 KiB")
		}
		record := make([]byte, size)
		if i+1 < len(eas) {
			binary.LittleEndian.PutUint32(record, uint32(size))
		}
		record[4] = ea.Flags
		record[5] = byte(len(ea.Name))
		binary.LittleEndian.PutUint16(record[6:], uint16(len(ea.Value)))
		copy(record[8:], ea.Name)
		copy(record[9+len(ea.Name):], ea.Value)
		data = append(data, record...)
		if ea.Flags&0x80 != 0 {
			need++
		}
	}
	info = make([]byte, 8)
	binary.LittleEndian.PutUint16(info, uint16(packed))
	binary.LittleEndian.PutUint16(info[2:], uint16(need))
	binary.LittleEndian.PutUint32(info[4:], uint32(len(data)))
	return info, data, nil
}

// Small catalog hints remain resident. Larger values use an allocated extent
// rather than overflowing the fixed MFT record.
func ntfsEAAttrs(node *ntfsNode, lcn int64) [][]byte {
	if len(node.eaData) == 0 {
		return nil
	}
	ea := ntfsResidentAttr(ntfsAttrEA, "", node.eaData)
	if len(node.eaData) > 192 {
		ea = ntfsNonResidentAttr(ntfsAttrEA, "", lcn, int64(len(node.eaData)))
	}
	return [][]byte{ntfsResidentAttr(ntfsAttrEAInformation, "", node.eaInfo), ea}
}

func ntfsEARecordSize(node *ntfsNode) int {
	size := 0
	for _, attr := range ntfsEAAttrs(node, 1<<56) {
		size += len(attr)
	}
	return size
}

func ntfsAppendEAList(node *ntfsNode, id uint16) {
	if len(node.eaData) == 0 {
		return
	}
	node.attributeList = append(node.attributeList, ntfsAttributeListEntry(ntfsAttrEAInformation, id, node.id)...)
	node.attributeList = append(node.attributeList, ntfsAttributeListEntry(ntfsAttrEA, id+1, node.id)...)
}
