// Package pri reads Windows package resource indexes without host tools.
package pri

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

var le = binary.LittleEndian

// Section retains its complete native section bytes, including its own header
// and trailer. Type and Metadata come from the file's table of contents.
// Data aliases the input with capped capacity; callers must keep it immutable.
type Section struct {
	Type     [16]byte
	Metadata [8]byte
	Data     []byte
}

// Container is the mrm_pri2 envelope. Section formats and resource lookup are
// separate from envelope validation; an accepted container is not yet a valid
// resource map. Header fields without established semantics remain raw.
type Container struct {
	Header8  uint32
	Header26 uint16
	Header28 uint32
	Sections []Section
}

// ParseContainer checks the PRI2 file envelope and section extents. It does not
// allocate copies of section payloads. Unlike the native shallow validator it
// rejects negative section counts and requires an exact input extent.
func ParseContainer(data []byte) (Container, error) {
	var out Container
	if len(data) < 48 || !bytes.Equal(data[:8], []byte("mrm_pri2")) {
		return out, fmt.Errorf("pri: unsupported or truncated header")
	}
	size := uint64(le.Uint32(data[12:]))
	aligned := (size + 7) &^ uint64(7)
	if size < 48 || aligned != uint64(len(data)) {
		return out, fmt.Errorf("pri: invalid file extent")
	}
	footer := data[len(data)-16:]
	if le.Uint32(footer) != 0xdefffade || le.Uint32(footer[4:]) != uint32(size) || !bytes.Equal(footer[8:], data[:8]) {
		return out, fmt.Errorf("pri: invalid file trailer")
	}
	toc := uint64(le.Uint32(data[16:]))
	base := uint64(le.Uint32(data[20:]))
	count := int(le.Uint16(data[24:]))
	end := toc + uint64(count)*32
	if count > 32767 || toc < 32 || toc%8 != 0 || end+16 > size ||
		base < end || base%8 != 0 || base >= size-16 {
		return out, fmt.Errorf("pri: invalid table extent")
	}
	out.Header8 = le.Uint32(data[8:])
	out.Header26 = le.Uint16(data[26:])
	out.Header28 = le.Uint32(data[28:])
	out.Sections = make([]Section, 0, count)
	available := aligned - 16 - base
	for i := 0; i < count; i++ {
		entry := data[toc+uint64(i)*32:][:32]
		offset := uint64(le.Uint32(entry[24:]))
		length := uint64(le.Uint32(entry[28:]))
		var section Section
		copy(section.Type[:], entry[:16])
		copy(section.Metadata[:], entry[16:24])
		// The native validator explicitly permits a zero/zero absent entry.
		if offset != 0 || length != 0 {
			if length < 40 || offset > available || length > available-offset {
				return Container{}, fmt.Errorf("pri: invalid section %d extent", i)
			}
			start, stop := base+offset, base+offset+length
			section.Data = data[start:stop:stop]
		}
		out.Sections = append(out.Sections, section)
	}
	return out, nil
}
