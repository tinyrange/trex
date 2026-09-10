// Package dmr implements Dependency Mini Repository binary structures without
// host filesystem or process dependencies.
package dmr

import (
	"encoding/binary"
	"fmt"
)

const (
	maxSize       = 1 << 30
	maxSections   = 8192
	headerSize    = 16
	tocHeaderSize = 12
)

var le = binary.LittleEndian

// Section contains an ARI8 table-of-contents tag and its serialized payload.
// Tags may repeat (for example, per-package resource sections). Payloads include
// their own format headers and must already be padded to four-byte boundaries.
// Container encoding does not validate section-specific semantics.
type Section struct {
	Tag  uint32
	Data []byte
}

// EncodeContainer serializes an ordered collection of sections using the
// Windows 11 ARI8 envelope. It does not invent required sections or package data.
func EncodeContainer(sections []Section) ([]byte, error) {
	if len(sections) == 0 || len(sections) > maxSections {
		return nil, fmt.Errorf("dmr: section count must be 1..%d", maxSections)
	}
	tocSize := tocHeaderSize + 8*len(sections)
	size := headerSize + tocSize
	for _, section := range sections {
		if len(section.Data) == 0 || len(section.Data)%4 != 0 {
			return nil, fmt.Errorf("dmr: section %#x must be nonempty and four-byte aligned", section.Tag)
		}
		if len(section.Data) > maxSize-size {
			return nil, fmt.Errorf("dmr: container exceeds %d bytes", maxSize)
		}
		size += len(section.Data)
	}
	out := make([]byte, size)
	copy(out, "ARI8")
	le.PutUint32(out[8:], uint32(size))
	copy(out[16:], "TOC8")
	le.PutUint32(out[20:], uint32(tocSize))
	le.PutUint32(out[24:], uint32(len(sections)))
	offset := headerSize + tocSize
	for i, section := range sections {
		entry := out[28+i*8:]
		le.PutUint32(entry, section.Tag)
		le.PutUint32(entry[4:], uint32(offset))
		copy(out[offset:], section.Data)
		offset += len(section.Data)
	}
	return out, nil
}

// ParseContainer validates an ARI8 envelope and returns ordered section views
// into data. The caller must keep data immutable while using these views. The
// reserved header words are required to match the Windows 11 writer's zeros;
// unsupported envelope variants fail closed. Section-specific validation is
// separate, so unknown section tags can be inspected without interpreting them.
func ParseContainer(data []byte) ([]Section, error) {
	if len(data) < 36 || len(data) > maxSize {
		return nil, fmt.Errorf("dmr: invalid container length")
	}
	if string(data[:4]) != "ARI8" || le.Uint32(data[4:]) != 0 ||
		le.Uint32(data[12:]) != 0 || uint64(le.Uint32(data[8:])) != uint64(len(data)) {
		return nil, fmt.Errorf("dmr: invalid or unsupported ARI8 header")
	}
	if string(data[16:20]) != "TOC8" {
		return nil, fmt.Errorf("dmr: invalid TOC8 signature")
	}
	count := uint64(le.Uint32(data[24:]))
	tocSize := uint64(le.Uint32(data[20:]))
	if count == 0 || count > maxSections || tocSize != tocHeaderSize+8*count ||
		headerSize+tocSize > uint64(len(data)) {
		return nil, fmt.Errorf("dmr: invalid table of contents")
	}
	sections := make([]Section, int(count))
	minimum := uint64(headerSize) + tocSize
	for i := range sections {
		entry := data[28+i*8:]
		start := uint64(le.Uint32(entry[4:]))
		end := uint64(len(data))
		if i+1 < len(sections) {
			end = uint64(le.Uint32(entry[12:]))
		}
		if start < minimum || start%4 != 0 || end%4 != 0 || end <= start || end > uint64(len(data)) {
			return nil, fmt.Errorf("dmr: invalid section %d extent", i)
		}
		sections[i] = Section{Tag: le.Uint32(entry), Data: data[int(start):int(end):int(end)]}
		minimum = end
	}
	return sections, nil
}
