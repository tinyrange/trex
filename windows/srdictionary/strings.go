// Package srdictionary implements State Repository dictionary wire primitives.
// It has no host filesystem or process dependencies.
package srdictionary

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	magic         = 0x31445253 // SRD1
	stringType    = 14
	maxPairs      = 1024
	maxKeyBytes   = 0xfffe
	maxValueBytes = 1 << 20
)

// StringPair is a string-valued wire entry, not an XML property projection.
// XML hierarchy and non-string State Repository data types are separate concerns.
type StringPair struct{ Key, Value string }

func terminatedUTF16(s string, maximum int) ([]byte, error) {
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) || len(s) > maximum*2 {
		return nil, fmt.Errorf("invalid dictionary string")
	}
	u := utf16.Encode([]rune(s))
	if len(u)+1 > maximum/2 {
		return nil, fmt.Errorf("dictionary string exceeds %d bytes", maximum)
	}
	b := make([]byte, (len(u)+1)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b, nil
}

// EncodeStrings encodes ordered string entries using the native SRD1 type-14
// representation. Duplicate keys are rejected, matching the reader's map insert
// check. The native format has no alignment padding between fields or entries.
func EncodeStrings(pairs []StringPair) ([]byte, error) {
	if len(pairs) > maxPairs {
		return nil, fmt.Errorf("dictionary exceeds %d entries", maxPairs)
	}
	out := make([]byte, 12)
	binary.LittleEndian.PutUint32(out, magic)
	binary.LittleEndian.PutUint32(out[8:], uint32(len(pairs)))
	seen := make(map[string]bool, len(pairs))
	for _, pair := range pairs {
		if seen[pair.Key] {
			return nil, fmt.Errorf("duplicate dictionary key %q", pair.Key)
		}
		seen[pair.Key] = true
		key, err := terminatedUTF16(pair.Key, maxKeyBytes)
		if err != nil {
			return nil, err
		}
		value, err := terminatedUTF16(pair.Value, maxValueBytes)
		if err != nil {
			return nil, err
		}
		size := 14 + len(key) + len(value)
		start := len(out)
		out = append(out, make([]byte, size)...)
		entry := out[start:]
		binary.LittleEndian.PutUint32(entry, uint32(size))
		binary.LittleEndian.PutUint32(entry[4:], stringType)
		binary.LittleEndian.PutUint16(entry[8:], uint16(len(key)))
		copy(entry[10:], key)
		binary.LittleEndian.PutUint32(entry[10+len(key):], uint32(len(value)))
		copy(entry[14+len(key):], value)
	}
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out, nil
}

func readString(b []byte, maximum int) (string, error) {
	if len(b) < 2 || len(b) > maximum || len(b)%2 != 0 || binary.LittleEndian.Uint16(b[len(b)-2:]) != 0 {
		return "", fmt.Errorf("invalid terminated UTF-16 dictionary string")
	}
	u := make([]uint16, len(b)/2-1)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
		if u[i] == 0 {
			return "", fmt.Errorf("embedded dictionary string terminator")
		}
	}
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xd800 && u[i] <= 0xdbff {
			if i+1 == len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return "", fmt.Errorf("unpaired UTF-16 surrogate")
			}
			i++
		} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
			return "", fmt.Errorf("unpaired UTF-16 surrogate")
		}
	}
	return string(utf16.Decode(u)), nil
}

// DecodeStrings validates a complete string-valued SRD1 dictionary. Other
// wire types are errors, never coerced to strings or silently discarded.
func DecodeStrings(data []byte) ([]StringPair, error) {
	if len(data) < 12 || binary.LittleEndian.Uint32(data) != magic || uint64(binary.LittleEndian.Uint32(data[4:])) != uint64(len(data)) {
		return nil, fmt.Errorf("invalid SRD1 header or extent")
	}
	count := binary.LittleEndian.Uint32(data[8:])
	if count > maxPairs {
		return nil, fmt.Errorf("dictionary exceeds entry limit")
	}
	pairs := make([]StringPair, 0, count)
	seen := make(map[string]bool, count)
	remaining := data[12:]
	for range count {
		if len(remaining) < 14 {
			return nil, fmt.Errorf("truncated dictionary entry")
		}
		size := uint64(binary.LittleEndian.Uint32(remaining))
		if size < 14 || size > uint64(len(remaining)) {
			return nil, fmt.Errorf("invalid dictionary entry extent")
		}
		entry := remaining[:int(size)]
		remaining = remaining[int(size):]
		if binary.LittleEndian.Uint32(entry[4:]) != stringType {
			return nil, fmt.Errorf("dictionary entry is not type-14 string")
		}
		keySize := int(binary.LittleEndian.Uint16(entry[8:]))
		if keySize > len(entry)-14 {
			return nil, fmt.Errorf("invalid dictionary key extent")
		}
		key, err := readString(entry[10:10+keySize], maxKeyBytes)
		if err != nil {
			return nil, err
		}
		valueSize := uint64(binary.LittleEndian.Uint32(entry[10+keySize:]))
		if valueSize != uint64(len(entry)-14-keySize) {
			return nil, fmt.Errorf("invalid dictionary value extent")
		}
		value, err := readString(entry[14+keySize:], maxValueBytes)
		if err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate dictionary key %q", key)
		}
		seen[key] = true
		pairs = append(pairs, StringPair{key, value})
	}
	if len(remaining) != 0 {
		return nil, fmt.Errorf("trailing dictionary entries")
	}
	return pairs, nil
}
