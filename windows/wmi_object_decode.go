package windows

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

func wmiUpperUTF16SHA256(value string) string {
	var b []byte
	for _, u := range utf16.Encode([]rune(strings.ToUpper(value))) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return fmt.Sprintf("%X", sha256.Sum256(b))
}

// The reader is used for existing class layouts, not for re-serializing base
// classes. Their method definitions, bytes, timestamps and keys remain intact.
type wmiDecodedProperty struct {
	feature       mofFeature
	index, offset uint32
	code          uint32
}
type wmiDecodedClass struct {
	class          mofClass
	revision       uint64
	properties     []wmiDecodedProperty
	defaults, heap []byte
}

type wmiObjectCursor struct {
	data   []byte
	offset int
	err    error
}

func (c *wmiObjectCursor) take(n uint64) []byte {
	if c.err != nil {
		return nil
	}
	if n > uint64(len(c.data)-c.offset) {
		c.err = fmt.Errorf("wmi object: truncated data at %d, need %d", c.offset, n)
		return nil
	}
	b := c.data[c.offset : c.offset+int(n)]
	c.offset += int(n)
	return b
}
func (c *wmiObjectCursor) u32() uint32 {
	b := c.take(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}
func (c *wmiObjectCursor) sized() []byte {
	n := c.u32()
	if c.err != nil {
		return nil
	}
	if n < 4 {
		c.err = fmt.Errorf("wmi object: invalid section length %d", n)
		return nil
	}
	return c.take(uint64(n - 4))
}
func wmiDecodeUTF16(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("wmi object: odd UTF16 byte count")
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(units)), nil
}
func wmiHeapString(heap []byte, offset uint32) (string, error) {
	if uint64(offset) >= uint64(len(heap)) {
		return "", fmt.Errorf("wmi object: string offset %d outside heap", offset)
	}
	b := heap[offset:]
	switch b[0] {
	case 0:
		n := bytes.IndexByte(b[1:], 0)
		if n >= 0 {
			return string(b[1 : 1+n]), nil
		}
	case 1:
		for i := 1; i+1 < len(b); i += 2 {
			if b[i] == 0 && b[i+1] == 0 {
				return wmiDecodeUTF16(b[1:i])
			}
		}
	default:
		return "", fmt.Errorf("wmi object: invalid string encoding %d", b[0])
	}
	return "", fmt.Errorf("wmi object: unterminated string")
}
func wmiDecodeType(code uint32) (mofType, int, error) {
	names := map[uint32]string{2: "sint16", 3: "sint32", 4: "real32", 5: "real64", 8: "string", 11: "boolean", 13: "object", 16: "sint8", 17: "uint8", 18: "uint16", 19: "uint32", 20: "sint64", 21: "uint64", 101: "datetime", 102: "reference", 103: "char16"}
	base := code & 0xfff
	name, ok := names[base]
	if !ok || code & ^uint32(0x6fff) != 0 {
		return mofType{}, 0, fmt.Errorf("wmi object: unsupported CIM type %#x", code)
	}
	size := 4
	switch base {
	case 2, 11, 18, 103:
		size = 2
	case 16, 17:
		size = 1
	case 5, 20, 21:
		size = 8
	}
	array := code&0x2000 != 0
	if array {
		size = 4
	}
	return mofType{Name: name, Array: array}, size, nil
}
func wmiDecodeValue(data, heap []byte, code uint32) (mofValue, error) {
	t, size, err := wmiDecodeType(code)
	if err != nil {
		return mofValue{}, err
	}
	if len(data) < size {
		return mofValue{}, fmt.Errorf("wmi object: truncated CIM value")
	}
	base := code & 0xfff
	if t.Array {
		offset := binary.LittleEndian.Uint32(data)
		if offset == 0xffffffff {
			return mofValue{Kind: mofValueNull}, nil
		}
		if uint64(offset)+4 > uint64(len(heap)) {
			return mofValue{}, fmt.Errorf("wmi object: array offset outside heap")
		}
		count := binary.LittleEndian.Uint32(heap[offset:])
		_, elementSize, err := wmiDecodeType(base)
		if err != nil {
			return mofValue{}, err
		}
		if uint64(count)*uint64(elementSize) > uint64(len(heap))-uint64(offset)-4 {
			return mofValue{}, fmt.Errorf("wmi object: truncated array")
		}
		v := mofValue{Kind: mofValueArray, Items: make([]mofValue, count)}
		for i := range v.Items {
			v.Items[i], err = wmiDecodeValue(heap[int(offset)+4+i*elementSize:], heap, base)
			if err != nil {
				return mofValue{}, err
			}
		}
		return v, nil
	}
	var u uint64
	switch size {
	case 1:
		u = uint64(data[0])
	case 2:
		u = uint64(binary.LittleEndian.Uint16(data))
	case 4:
		u = uint64(binary.LittleEndian.Uint32(data))
	case 8:
		u = binary.LittleEndian.Uint64(data)
	}
	switch base {
	case 8, 101, 102:
		if u == 0xffffffff {
			return mofValue{Kind: mofValueNull}, nil
		}
		s, err := wmiHeapString(heap, uint32(u))
		return mofValue{Kind: mofValueString, Text: s}, err
	case 13:
		return mofValue{}, fmt.Errorf("wmi object: embedded default objects not supported")
	case 11:
		return mofValue{Kind: mofValueBool, Bool: u != 0, Text: strings.ToUpper(strconv.FormatBool(u != 0))}, nil
	case 4:
		return mofValue{Kind: mofValueReal, Real: float64(math.Float32frombits(uint32(u)))}, nil
	case 5:
		return mofValue{Kind: mofValueReal, Real: math.Float64frombits(u)}, nil
	}
	v := mofValue{Kind: mofValueInteger, Unsigned: u, Integer: int64(u), Text: strconv.FormatUint(u, 10)}
	switch base {
	case 16:
		v.Integer = int64(int8(u))
	case 2:
		v.Integer = int64(int16(u))
	case 3:
		v.Integer = int64(int32(u))
	case 20:
		v.Integer = int64(u)
	}
	if v.Integer < 0 {
		v.Negative = true
		v.Text = strconv.FormatInt(v.Integer, 10)
	}
	return v, nil
}
func wmiDecodeQualifiers(data, heap []byte) ([]mofQualifier, error) {
	var result []mofQualifier
	c := wmiObjectCursor{data: data}
	for c.offset < len(data) && c.err == nil {
		nameOffset := c.u32()
		flavor := c.take(1)
		code := c.u32()
		_, size, err := wmiDecodeType(code)
		if err != nil {
			return nil, err
		}
		raw := c.take(uint64(size))
		if c.err != nil {
			return nil, c.err
		}
		var name string
		if nameOffset&0x80000000 != 0 {
			name = map[uint32]string{1: "Key", 3: "Read", 4: "Write", 5: "Volatile", 6: "Provider", 7: "Dynamic", 10: "CIMTYPE"}[nameOffset&0x7fffffff]
			if name == "" {
				return nil, fmt.Errorf("wmi object: unknown intrinsic qualifier %x", nameOffset)
			}
		} else {
			name, err = wmiHeapString(heap, nameOffset)
			if err != nil {
				return nil, err
			}
		}
		value, err := wmiDecodeValue(raw, heap, code)
		if err != nil {
			return nil, fmt.Errorf("qualifier %s: %w", name, err)
		}
		typ, _, _ := wmiDecodeType(code)
		q := mofQualifier{Name: name, DeclaredType: &typ, Values: []mofValue{value}}
		if value.Kind == mofValueArray {
			q.Values = value.Items
		}
		// Preserve declared propagation/override flavors for inherited properties.
		if flavor[0]&1 != 0 {
			q.Flavors = append(q.Flavors, "ToSubclass")
		}
		if flavor[0]&2 != 0 {
			q.Flavors = append(q.Flavors, "ToInstance")
		}
		if flavor[0]&0x10 != 0 {
			q.Flavors = append(q.Flavors, "DisableOverride")
		}
		result = append(result, q)
	}
	return result, c.err
}
func decodeWMIClassRecord(data []byte) (*wmiDecodedClass, error) {
	c := wmiObjectCursor{data: data}
	n := c.u32()
	superRaw := c.take(uint64(n) * 2)
	revisionRaw := c.take(8)
	part := c.sized()
	if c.err != nil {
		return nil, c.err
	}
	super, err := wmiDecodeUTF16(superRaw)
	if err != nil {
		return nil, err
	}
	r := &wmiDecodedClass{class: mofClass{Super: super}, revision: binary.LittleEndian.Uint64(revisionRaw)}
	p := wmiObjectCursor{data: part}
	p.take(1)
	nameOffset := p.u32()
	defaultsSize := p.u32()
	p.sized()
	qualifierData := p.sized()
	count := p.u32()
	refs := p.take(uint64(count) * 8)
	r.defaults = p.take(uint64(defaultsSize))
	heapSize := p.u32() & 0x7fffffff
	r.heap = p.take(uint64(heapSize))
	if p.err != nil {
		return nil, p.err
	}
	r.class.Name, err = wmiHeapString(r.heap, nameOffset)
	if err != nil {
		return nil, err
	}
	r.class.Qualifiers, err = wmiDecodeQualifiers(qualifierData, r.heap)
	if err != nil {
		return nil, err
	}
	for i := uint32(0); i < count; i++ {
		nameOffset := binary.LittleEndian.Uint32(refs[i*8:])
		desc := binary.LittleEndian.Uint32(refs[i*8+4:])
		var name string
		if nameOffset&0x80000000 != 0 {
			name = map[uint32]string{1: "Key", 3: "Read", 4: "Write", 5: "Volatile", 6: "Provider", 7: "Dynamic", 10: "CIMTYPE"}[nameOffset&0x7fffffff]
			if name == "" {
				return nil, fmt.Errorf("wmi object: unknown intrinsic property %#x", nameOffset)
			}
		} else {
			name, err = wmiHeapString(r.heap, nameOffset)
			if err != nil {
				return nil, err
			}
		}
		if uint64(desc)+18 > uint64(len(r.heap)) {
			return nil, fmt.Errorf("wmi object: property descriptor outside heap")
		}
		d := wmiObjectCursor{data: r.heap[desc:]}
		code := d.u32()
		rawIndex := d.take(2)
		offset := d.u32()
		d.u32()
		qdata := d.sized()
		if d.err != nil {
			return nil, d.err
		}
		typ, _, err := wmiDecodeType(code)
		if err != nil {
			return nil, err
		}
		quals, err := wmiDecodeQualifiers(qdata, r.heap)
		if err != nil {
			return nil, err
		}
		if code&0xfff == 102 {
			for _, q := range quals {
				if strings.EqualFold(q.Name, "CIMTYPE") && len(q.Values) == 1 {
					typ.Reference = strings.TrimPrefix(q.Values[0].Text, "ref:")
					typ.Name = typ.Reference
				}
			}
			if typ.Reference == "" && code&0x4000 == 0 {
				return nil, fmt.Errorf("wmi object: reference %s has no target type", name)
			}
		}
		r.properties = append(r.properties, wmiDecodedProperty{feature: mofFeature{Kind: "property", Name: name, Type: typ, Qualifiers: quals}, index: uint32(binary.LittleEndian.Uint16(rawIndex)), offset: offset, code: code})
	}
	sort.Slice(r.properties, func(i, j int) bool { return r.properties[i].index < r.properties[j].index })
	return r, nil
}
