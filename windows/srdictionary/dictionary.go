package srdictionary

import (
	"encoding/binary"
	"fmt"
)

const (
	mapType                = 21
	mapArrayType           = 42
	maximumDepth           = 32
	maximumDictionaryBytes = 64 << 20
)

// Dictionary preserves entry order. Values are strings, Dictionary values,
// or []Dictionary values. These are the types emitted for XML properties;
// other SRD1 types must not be silently coerced into this representation.
type Dictionary []Entry
type Entry struct {
	Key   string
	Value any
}

// Encode encodes the string/map/map-array subset used by manifest properties.
// In addition to native per-value/count limits, it bounds nesting to 32 levels
// and a complete dictionary to 64 MiB to limit construction memory use.
func Encode(d Dictionary) ([]byte, error) { return encode(d, 0) }

func encode(d Dictionary, depth int) ([]byte, error) {
	if depth >= maximumDepth || len(d) > maxPairs {
		return nil, fmt.Errorf("dictionary depth or entry limit exceeded")
	}
	out := make([]byte, 12)
	binary.LittleEndian.PutUint32(out, magic)
	binary.LittleEndian.PutUint32(out[8:], uint32(len(d)))
	seen := make(map[string]bool, len(d))
	for _, e := range d {
		if seen[e.Key] {
			return nil, fmt.Errorf("duplicate dictionary key %q", e.Key)
		}
		seen[e.Key] = true
		key, err := terminatedUTF16(e.Key, maxKeyBytes)
		if err != nil {
			return nil, err
		}
		var payload []byte
		var kind uint32
		count := -1
		switch v := e.Value.(type) {
		case string:
			kind = stringType
			payload, err = terminatedUTF16(v, maxValueBytes)
		case Dictionary:
			kind = mapType
			payload, err = encode(v, depth+1)
		case []Dictionary:
			kind, count = mapArrayType, len(v)
			if count > maxPairs {
				return nil, fmt.Errorf("dictionary map array exceeds entry limit")
			}
			for _, child := range v {
				data, childErr := encode(child, depth+1)
				if childErr != nil {
					return nil, childErr
				}
				if len(data) > maxValueBytes || len(payload) > maximumDictionaryBytes-4-len(data) {
					return nil, fmt.Errorf("dictionary map array exceeds byte limit")
				}
				payload = binary.LittleEndian.AppendUint32(payload, uint32(len(data)))
				payload = append(payload, data...)
			}
		default:
			return nil, fmt.Errorf("unsupported dictionary value %T", e.Value)
		}
		if err != nil {
			return nil, err
		}
		if count < 0 && len(payload) > maxValueBytes {
			return nil, fmt.Errorf("dictionary value exceeds byte limit")
		}
		size := 14 + len(key) + len(payload)
		if len(out) > maximumDictionaryBytes-size {
			return nil, fmt.Errorf("dictionary exceeds byte limit")
		}
		start := len(out)
		out = append(out, make([]byte, size)...)
		pair := out[start:]
		binary.LittleEndian.PutUint32(pair, uint32(size))
		binary.LittleEndian.PutUint32(pair[4:], kind)
		off := 8
		if count >= 0 {
			binary.LittleEndian.PutUint32(pair[off:], uint32(count))
			off += 4
		}
		binary.LittleEndian.PutUint16(pair[off:], uint16(len(key)))
		off += 2
		copy(pair[off:], key)
		off += len(key)
		if count < 0 {
			binary.LittleEndian.PutUint32(pair[off:], uint32(len(payload)))
			off += 4
		}
		copy(pair[off:], payload)
	}
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out, nil
}

// Decode validates complete extents at every nesting level. It does not retain
// references to the input buffer. Unknown types and duplicate keys are errors.
func Decode(data []byte) (Dictionary, error) { return decode(data, 0) }

func decode(data []byte, depth int) (Dictionary, error) {
	if depth >= maximumDepth || len(data) < 12 || len(data) > maximumDictionaryBytes || binary.LittleEndian.Uint32(data) != magic || uint64(binary.LittleEndian.Uint32(data[4:])) != uint64(len(data)) {
		return nil, fmt.Errorf("invalid dictionary depth, header or extent")
	}
	count := binary.LittleEndian.Uint32(data[8:])
	if count > maxPairs || uint64(count)*12 > uint64(len(data)-12) {
		return nil, fmt.Errorf("invalid dictionary entry count")
	}
	out := make(Dictionary, 0, count)
	seen := make(map[string]bool, count)
	rest := data[12:]
	for range count {
		if len(rest) < 14 {
			return nil, fmt.Errorf("truncated dictionary entry")
		}
		size := uint64(binary.LittleEndian.Uint32(rest))
		if size < 14 || size > uint64(len(rest)) {
			return nil, fmt.Errorf("invalid dictionary entry extent")
		}
		pair := rest[:int(size)]
		rest = rest[int(size):]
		kind := binary.LittleEndian.Uint32(pair[4:])
		off, arrayCount := 8, -1
		if kind == mapArrayType {
			n := binary.LittleEndian.Uint32(pair[8:])
			if n > maxPairs {
				return nil, fmt.Errorf("dictionary array exceeds entry limit")
			}
			arrayCount = int(n)
			off += 4
		} else if kind != stringType && kind != mapType {
			return nil, fmt.Errorf("unsupported dictionary type %d", kind)
		}
		keySize := int(binary.LittleEndian.Uint16(pair[off:]))
		off += 2
		if keySize > len(pair)-off {
			return nil, fmt.Errorf("invalid dictionary key extent")
		}
		key, err := readString(pair[off:off+keySize], maxKeyBytes)
		if err != nil {
			return nil, err
		}
		off += keySize
		if seen[key] {
			return nil, fmt.Errorf("duplicate dictionary key %q", key)
		}
		seen[key] = true
		var value any
		if arrayCount >= 0 {
			if uint64(arrayCount)*16 > uint64(len(pair)-off) {
				return nil, fmt.Errorf("truncated map array")
			}
			maps := make([]Dictionary, 0, arrayCount)
			for range arrayCount {
				if len(pair)-off < 4 {
					return nil, fmt.Errorf("truncated map array length")
				}
				n := uint64(binary.LittleEndian.Uint32(pair[off:]))
				off += 4
				if n > maxValueBytes || n > uint64(len(pair)-off) {
					return nil, fmt.Errorf("invalid map array extent")
				}
				child, err := decode(pair[off:off+int(n)], depth+1)
				if err != nil {
					return nil, err
				}
				maps = append(maps, child)
				off += int(n)
			}
			if off != len(pair) {
				return nil, fmt.Errorf("trailing map array bytes")
			}
			value = maps
		} else {
			if len(pair)-off < 4 {
				return nil, fmt.Errorf("truncated dictionary value length")
			}
			n := uint64(binary.LittleEndian.Uint32(pair[off:]))
			off += 4
			if n > maxValueBytes || n != uint64(len(pair)-off) {
				return nil, fmt.Errorf("invalid dictionary value extent")
			}
			if kind == stringType {
				value, err = readString(pair[off:], maxValueBytes)
			} else {
				value, err = decode(pair[off:], depth+1)
			}
			if err != nil {
				return nil, err
			}
		}
		out = append(out, Entry{key, value})
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing dictionary entries")
	}
	return out, nil
}
