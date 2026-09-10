package ntfs

import (
	"encoding/binary"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
)

type ntfsReadAttributeListEntry struct {
	typ      uint32
	name     string
	firstVCN int64
	record   uint64
	sequence uint16
	instance uint16
}

// Attribute lists name the current owner of each attribute, including its
// record sequence. Backlinks on unlisted extension records are not sufficient.
func parseNTFSReadAttributeList(data []byte) ([]ntfsReadAttributeListEntry, error) {
	var entries []ntfsReadAttributeListEntry
	for offset := 0; offset < len(data); {
		if len(data)-offset < 26 {
			return nil, fmt.Errorf("truncated entry at %#x", offset)
		}
		raw := data[offset:]
		length := int(binary.LittleEndian.Uint16(raw[4:6]))
		if length < 26 || length&7 != 0 || length > len(raw) {
			return nil, fmt.Errorf("invalid entry length at %#x: type=%#x length=%d remaining=%d header=%x", offset, binary.LittleEndian.Uint32(raw[:4]), length, len(raw), raw[:26])
		}
		raw = raw[:length]
		units, nameOffset := int(raw[6]), int(raw[7])
		if units != 0 && nameOffset < 26 {
			return nil, fmt.Errorf("invalid entry name offset at %#x", offset)
		}
		name, err := decodeNTFSReadName(raw, nameOffset, units)
		if err != nil {
			return nil, err
		}
		vcn := binary.LittleEndian.Uint64(raw[8:16])
		if vcn > 1<<63-1 {
			return nil, fmt.Errorf("invalid entry VCN at %#x", offset)
		}
		reference := binary.LittleEndian.Uint64(raw[16:24])
		entries = append(entries, ntfsReadAttributeListEntry{
			typ: binary.LittleEndian.Uint32(raw[:4]), name: name, firstVCN: int64(vcn),
			record: reference & 0x0000ffffffffffff, sequence: uint16(reference >> 48),
			instance: binary.LittleEndian.Uint16(raw[24:26]),
		})
		offset += length
	}
	return entries, nil
}

func ntfsReadAttributeListed(entries []ntfsReadAttributeListEntry, node *ntfsReadNode, attribute ntfsReadAttribute) bool {
	for _, entry := range entries {
		if entry.record == node.id && entry.sequence == node.sequence && entry.typ == attribute.typ && entry.name == attribute.name && entry.firstVCN == attribute.firstVCN {
			// Continuation extents are identified by their lowest VCN; the
			// instance field identifies the initial/resident attribute.
			if entry.firstVCN != 0 || entry.instance == attribute.instance {
				return true
			}
		}
	}
	return false
}

func (v *ntfsVolume) readAttributeList(attributes []ntfsReadAttribute) ([]ntfsReadAttributeListEntry, bool, error) {
	var file *ntfsReadFile
	for _, attribute := range attributes {
		if attribute.typ != ntfsAttrAttributeList {
			continue
		}
		part := &ntfsReadFile{volume: v.file, clusterSize: v.clusterSize, size: attribute.size, firstVCN: attribute.firstVCN, resident: attribute.value, runs: attribute.runs}
		var err error
		file, err = mergeNTFSReadFileExtents(file, part)
		if err != nil {
			return nil, true, err
		}
	}
	if file == nil {
		return nil, false, nil
	}
	if file.firstVCN != 0 || file.size < 0 || file.size > 64<<20 {
		return nil, true, fmt.Errorf("invalid attribute-list extent or size")
	}
	data := make([]byte, file.size)
	if _, err := starfile.ReadFullAt(file, data, 0); err != nil {
		return nil, true, err
	}
	entries, err := parseNTFSReadAttributeList(data)
	return entries, true, err
}
