package dmr

import (
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Identity is a serialized DMR package identity. Version and Flags are wire
// values; this layer neither resolves dependencies nor infers package policy.
type Identity struct {
	Flags                                              uint32
	Version                                            uint64
	Architecture                                       uint32
	Name, PublisherID, Publisher, ResourceID, FullName string
}

// Empty native optional strings have zero length, unlike a present terminated
// string. All nonempty strings include their UTF-16 terminator in the length.
func identityString(s string) ([]byte, error) {
	return terminatedString(s, 65534)
}

func terminatedString(s string, maxBytes int) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) || len(s) > 2*maxBytes {
		return nil, fmt.Errorf("dmr: invalid identity string")
	}
	units := utf16.Encode([]rune(s))
	if len(units)+1 > maxBytes/2 {
		return nil, fmt.Errorf("dmr: string exceeds %d bytes", maxBytes)
	}
	b := make([]byte, 2*(len(units)+1))
	for i, u := range units {
		le.PutUint16(b[2*i:], u)
	}
	return b, nil
}

func parseIdentityString(b []byte) (string, error) {
	if len(b) == 0 {
		return "", nil
	}
	if len(b) < 4 || len(b)%2 != 0 || le.Uint16(b[len(b)-2:]) != 0 {
		return "", fmt.Errorf("dmr: invalid identity string extent/terminator")
	}
	units := make([]uint16, len(b)/2-1)
	for i := range units {
		units[i] = le.Uint16(b[2*i:])
		if units[i] == 0 {
			return "", fmt.Errorf("dmr: embedded identity string terminator")
		}
	}
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", fmt.Errorf("dmr: unpaired UTF-16 high surrogate")
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", fmt.Errorf("dmr: unpaired UTF-16 low surrogate")
		}
	}
	return string(utf16.Decode(units)), nil
}

// EncodeIdentity serializes the Windows 11 package-identity record, without
// node alignment padding. Empty optional strings are absent, as in the native
// Add_Dependency writer. The package name must be present.
func EncodeIdentity(identity Identity) ([]byte, error) {
	if identity.Name == "" {
		return nil, fmt.Errorf("dmr: missing identity name")
	}
	values := [...]string{identity.Name, identity.PublisherID, identity.Publisher, identity.ResourceID, identity.FullName}
	var fields [5][]byte
	size := 32
	for i, value := range values {
		b, err := identityString(value)
		if err != nil {
			return nil, fmt.Errorf("dmr: identity field %d: %w", i, err)
		}
		fields[i] = b
		size += len(b)
	}
	out := make([]byte, size)
	le.PutUint32(out, uint32(size))
	le.PutUint32(out[4:], identity.Flags)
	le.PutUint64(out[8:], identity.Version)
	le.PutUint32(out[16:], identity.Architecture)
	le.PutUint16(out[20:], uint16(len(fields[0])))
	le.PutUint16(out[22:], uint16(len(fields[1])))
	le.PutUint32(out[24:], uint32(len(fields[2])))
	le.PutUint16(out[28:], uint16(len(fields[3])))
	le.PutUint16(out[30:], uint16(len(fields[4])))
	offset := 32
	for _, field := range fields {
		copy(out[offset:], field)
		offset += len(field)
	}
	return out, nil
}

// ParseIdentity reads exactly one native identity, not its containing node.
// It checks all string extents before decoding and rejects lossy UTF-16.
func ParseIdentity(data []byte) (Identity, error) {
	var result Identity
	if len(data) < 32 || uint64(le.Uint32(data)) != uint64(len(data)) {
		return result, fmt.Errorf("dmr: invalid identity size")
	}
	lengths := [...]uint32{uint32(le.Uint16(data[20:])), uint32(le.Uint16(data[22:])), le.Uint32(data[24:]), uint32(le.Uint16(data[28:])), uint32(le.Uint16(data[30:]))}
	size := uint64(32)
	for _, n := range lengths {
		// The native serializer loads publisher length through a u16 even
		// though its output field is u32; preserve that supported contract.
		if n > 65534 {
			return result, fmt.Errorf("dmr: identity string too large")
		}
		size += uint64(n)
	}
	if size != uint64(len(data)) || lengths[0] == 0 {
		return result, fmt.Errorf("dmr: invalid identity string extents")
	}
	var values [5]string
	offset := 32
	for i, n := range lengths {
		value, err := parseIdentityString(data[offset : offset+int(n)])
		if err != nil {
			return result, fmt.Errorf("dmr: identity field %d: %w", i, err)
		}
		values[i] = value
		offset += int(n)
	}
	return Identity{Flags: le.Uint32(data[4:]), Version: le.Uint64(data[8:]), Architecture: le.Uint32(data[16:]),
		Name: values[0], PublisherID: values[1], Publisher: values[2], ResourceID: values[3], FullName: values[4]}, nil
}
