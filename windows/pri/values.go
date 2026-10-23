package pri

import (
	"bytes"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// StringValue is a locally stored, sole neutral/default candidate. Path values
// are relative to the package unless already absolute; callers own path policy.
type StringValue struct {
	Value string
	Path  bool
}

// SingleString follows MRT's TryGetOnlyValue contract. nil means that the
// resource must retain its PRI index, not that it is missing. No locale choice,
// external PRI access or arbitrary candidate selection is performed.
func (m *ResourceMap) SingleString(index uint32, d *Decisions, sections []Section) (*StringValue, error) {
	count, err := m.CandidateCount(index, d)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, fmt.Errorf("pri: resource has no candidates")
	}
	item, _ := m.Resource(index)
	if count != 1 || !d.defaults[item.Decision] {
		return nil, nil
	}
	v := m.values[int(item.FirstValue)*m.valueWidth:][:m.valueWidth]
	typ := int(v[1])
	if typ >= len(m.valueTypes)/8 {
		return nil, fmt.Errorf("pri: invalid value type index")
	}
	// DEF_ATOM is pool,index; the resource type enumeration is fixed across
	// MRT environments (MrmEnvironment::GetResourceValueTypeForAtom).
	kind := le.Uint32(m.valueTypes[typ*8+4:])
	if kind == 2 {
		return nil, nil
	} // embedded binary cannot reduce to a string
	if kind > 6 {
		return nil, fmt.Errorf("pri: unsupported resource value type %d", kind)
	}
	detail, data := uint64(le.Uint16(v[2:])), uint64(le.Uint32(v[4:]))
	var raw []byte
	switch v[0] {
	case 0:
		if data > uint64(len(m.internal)) || detail > uint64(len(m.internal))-data {
			return nil, fmt.Errorf("pri: internal value outside data")
		}
		raw = m.internal[data : data+detail]
	case 1:
		if detail != 0 {
			return nil, fmt.Errorf("pri: external value file unsupported")
		}
		section, item := data>>16, data&0xffff
		if m.valueWidth == 10 {
			item |= uint64(le.Uint16(v[8:])) << 16
		}
		if section >= uint64(len(sections)) {
			return nil, fmt.Errorf("pri: value section outside container")
		}
		raw, err = dataItem(sections[section], item)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("pri: unsupported value locator %d", v[0])
	}
	text, err := decodeValue(raw, kind)
	if err != nil {
		return nil, err
	}
	return &StringValue{Value: text, Path: kind == 1 || kind == 5 || kind == 6}, nil
}

func dataItem(section Section, index uint64) ([]byte, error) {
	if string(section.Type[:]) != "[mrm_dataitem] \x00" {
		return nil, fmt.Errorf("pri: expected data items")
	}
	b, err := section.Payload()
	if err != nil {
		return nil, err
	}
	if len(b) < 12 {
		return nil, fmt.Errorf("pri: short data items")
	}
	flags := le.Uint32(b)
	if flags & ^uint32(0x00ff0001) != 0 || flags&1 == 0 && flags&0x00ff0000 != 0 {
		return nil, fmt.Errorf("pri: unsupported data item flags")
	}
	small, large, size := uint64(le.Uint16(b[4:])), uint64(le.Uint16(b[6:])), uint64(le.Uint32(b[8:]))
	if flags&1 != 0 {
		large |= uint64(flags & 0x00ff0000)
	}
	start := 12 + 4*small + 8*large
	if start > uint64(len(b)) || size > uint64(len(b))-start || index >= small+large {
		return nil, fmt.Errorf("pri: data item extent/index out of bounds")
	}
	var off, n uint64
	if index < small {
		p := b[12+4*index:]
		off, n = uint64(le.Uint16(p)), uint64(le.Uint16(p[2:]))
	} else {
		p := b[12+4*small+8*(index-small):]
		off, n = uint64(le.Uint32(p)), uint64(le.Uint32(p[4:]))
	}
	if off > size || n > size-off {
		return nil, fmt.Errorf("pri: data item outside payload")
	}
	return b[start+off : start+off+n], nil
}

func decodeValue(b []byte, kind uint32) (string, error) {
	if kind == 0 || kind == 1 {
		if len(b) < 2 || len(b)%2 != 0 || le.Uint16(b[len(b)-2:]) != 0 {
			return "", fmt.Errorf("pri: unterminated UTF-16 value")
		}
		u := make([]uint16, len(b)/2-1)
		for i := range u {
			u[i] = le.Uint16(b[2*i:])
			if u[i] == 0 {
				return "", fmt.Errorf("pri: embedded NUL")
			}
		}
		for i := 0; i < len(u); i++ {
			if u[i] >= 0xd800 && u[i] <= 0xdbff {
				if i+1 >= len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
					return "", fmt.Errorf("pri: invalid UTF-16")
				}
				i++
			} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
				return "", fmt.Errorf("pri: invalid UTF-16")
			}
		}
		return string(utf16.Decode(u)), nil
	}
	if len(b) == 0 || b[len(b)-1] != 0 || bytes.IndexByte(b[:len(b)-1], 0) >= 0 {
		return "", fmt.Errorf("pri: unterminated string")
	}
	b = b[:len(b)-1]
	if kind == 3 || kind == 5 {
		for _, c := range b {
			if c >= 128 {
				return "", fmt.Errorf("pri: non-ASCII value")
			}
		}
	} else if !utf8.Valid(b) {
		return "", fmt.Errorf("pri: invalid UTF-8")
	}
	return string(b), nil
}
