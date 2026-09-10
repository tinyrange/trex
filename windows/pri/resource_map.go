package pri

import "fmt"

const ResourceMap2Type = "[mrm_res_map2_]\x00"

type mapPair struct{ first, second uint32 }

// ResourceInfo identifies a resource's decision and its first value locator.
// Candidate counts come from decision information, not adjacent value offsets.
type ResourceInfo struct {
	Decision   uint16
	FirstValue uint32
}

// ResourceMap retains validated standard and large map directories. Value
// locators remain opaque here; this reader does not resolve candidate strings.
type ResourceMap struct {
	SchemaSection, DecisionSection uint16
	ValueCount                     uint32
	directory, ranges              []mapPair
	items                          []ResourceInfo
}

// ParseResourceMap parses the environment-free Windows 8.1+ map2 layout.
// It supports mixed standard/large items and both value-locator widths.
func ParseResourceMap(section Section) (*ResourceMap, error) {
	if string(section.Type[:]) != ResourceMap2Type {
		return nil, fmt.Errorf("pri: expected resource map2")
	}
	b, err := section.Payload()
	if err != nil {
		return nil, err
	}
	if len(b) < 32 || le.Uint16(b) != 0 || le.Uint16(b[2:]) != 0 || le.Uint16(b[18:]) & ^uint16(1) != 0 {
		return nil, fmt.Errorf("pri: invalid map2 header")
	}
	m := &ResourceMap{SchemaSection: le.Uint16(b[4:]), DecisionSection: le.Uint16(b[8:]), ValueCount: le.Uint32(b[20:])}
	off := uint64(32) + uint64(le.Uint16(b[6:])) + 8*uint64(le.Uint16(b[10:]))
	take := func(count, width uint64) ([]byte, error) {
		if off > uint64(len(b)) || count > (uint64(len(b))-off)/width {
			return nil, fmt.Errorf("pri: truncated resource map array")
		}
		end := off + count*width
		data := b[off:end:end]
		off = end
		return data, nil
	}
	readPairs := func(count uint64, large bool) ([]mapPair, error) {
		width := uint64(4)
		if large {
			width = 8
		}
		data, e := take(count, width)
		if e != nil {
			return nil, e
		}
		out := make([]mapPair, int(count))
		for i := range out {
			p := data[uint64(i)*width:]
			if large {
				out[i] = mapPair{le.Uint32(p), le.Uint32(p[4:])}
			} else {
				out[i] = mapPair{uint32(le.Uint16(p)), uint32(le.Uint16(p[2:]))}
			}
		}
		return out, nil
	}
	readItems := func(count uint64, large bool) ([]ResourceInfo, error) {
		width := uint64(4)
		if large {
			width = 8
		}
		data, e := take(count, width)
		if e != nil {
			return nil, e
		}
		out := make([]ResourceInfo, int(count))
		for i := range out {
			p := data[uint64(i)*width:]
			out[i].Decision = le.Uint16(p)
			if large {
				if le.Uint16(p[2:]) != 0 {
					return nil, fmt.Errorf("pri: nonzero large item padding")
				}
				out[i].FirstValue = le.Uint32(p[4:])
			} else {
				out[i].FirstValue = uint32(le.Uint16(p[2:]))
			}
		}
		return out, nil
	}
	if m.directory, err = readPairs(uint64(le.Uint16(b[12:])), false); err != nil {
		return nil, err
	}
	if m.ranges, err = readPairs(uint64(le.Uint16(b[14:])), false); err != nil {
		return nil, err
	}
	if m.items, err = readItems(uint64(le.Uint16(b[16:])), false); err != nil {
		return nil, err
	}
	largeSize := uint64(le.Uint32(b[28:]))
	if largeSize != 0 {
		end := off + largeSize
		if largeSize < 12 || end > uint64(len(b)) {
			return nil, fmt.Errorf("pri: invalid large map extent")
		}
		h, e := take(1, 12)
		if e != nil {
			return nil, e
		}
		d, e := readPairs(uint64(le.Uint32(h)), true)
		if e != nil {
			return nil, e
		}
		r, e := readPairs(uint64(le.Uint32(h[4:])), true)
		if e != nil {
			return nil, e
		}
		it, e := readItems(uint64(le.Uint32(h[8:])), true)
		if e != nil {
			return nil, e
		}
		if off != end {
			return nil, fmt.Errorf("pri: large map counts disagree with extent")
		}
		m.directory = append(m.directory, d...)
		m.ranges = append(m.ranges, r...)
		m.items = append(m.items, it...)
	}
	width := uint64(8)
	if le.Uint16(b[18:])&1 != 0 {
		width = 10
	}
	if _, err = take(uint64(m.ValueCount), width); err != nil {
		return nil, err
	}
	if _, err = take(uint64(le.Uint32(b[24:])), 1); err != nil {
		return nil, err
	}
	if uint64(len(b))-off > 7 {
		return nil, fmt.Errorf("pri: trailing resource map data")
	}
	for _, v := range b[off:] {
		if v != 0 {
			return nil, fmt.Errorf("pri: nonzero resource map padding")
		}
	}
	var previousEnd uint64
	for _, d := range m.directory {
		count, first := uint64(1), uint64(d.second)-uint64(len(m.ranges))
		if uint64(d.second) < uint64(len(m.ranges)) {
			r := m.ranges[d.second]
			count, first = uint64(r.first), uint64(r.second)
		}
		if count == 0 || first > uint64(len(m.items)) || count > uint64(len(m.items))-first || uint64(d.first) < previousEnd || uint64(d.first)+count > 1<<32 {
			return nil, fmt.Errorf("pri: invalid resource map directory")
		}
		previousEnd = uint64(d.first) + count
	}
	for _, r := range m.ranges {
		if r.first == 0 || uint64(r.second)+uint64(r.first) > uint64(len(m.items)) {
			return nil, fmt.Errorf("pri: invalid resource map range")
		}
	}
	for _, it := range m.items {
		if it.FirstValue > m.ValueCount {
			return nil, fmt.Errorf("pri: candidate starts outside value table")
		}
	}
	return m, nil
}

func (m *ResourceMap) Resource(index uint32) (ResourceInfo, bool) {
	for _, d := range m.directory {
		if d.first > index {
			break
		}
		if uint64(d.second) < uint64(len(m.ranges)) {
			r := m.ranges[d.second]
			if index-d.first < r.first {
				return m.items[r.second+index-d.first], true
			}
		} else if d.first == index {
			return m.items[int(d.second)-len(m.ranges)], true
		}
	}
	return ResourceInfo{}, false
}
