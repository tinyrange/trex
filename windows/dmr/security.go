package dmr

import "fmt"

// SecurityTag identifies a serialized SECU section.
const SecurityTag uint32 = 0x55434553

// SecurityContext contains the package SID and ordered capability SIDs recorded
// by the deployment writer. Flags are preserved wire values, not policy inferred
// from an application manifest. A framework/resource package may have no SECU
// section at all; callers must not synthesize one to replace that distinction.
type SecurityContext struct {
	Flags        uint32
	PackageSID   []byte
	Capabilities [][]byte
}

func sidSize(data []byte) (int, error) {
	if len(data) < 8 || data[0] != 1 || data[1] > 15 {
		return 0, fmt.Errorf("dmr: invalid SID header")
	}
	size := 8 + 4*int(data[1])
	if size > len(data) {
		return 0, fmt.Errorf("dmr: truncated SID")
	}
	return size, nil
}

// EncodeSecurityContext serializes the native Windows 11 SECU section. SID
// bytes must be complete revision-1 SID structures, not strings or host tokens.
func EncodeSecurityContext(context SecurityContext) ([]byte, error) {
	size, err := sidSize(context.PackageSID)
	if err != nil || size != len(context.PackageSID) {
		return nil, fmt.Errorf("dmr: invalid package SID")
	}
	if len(context.Capabilities) > 128 {
		return nil, fmt.Errorf("dmr: too many capability SIDs")
	}
	capSize := 0
	for _, sid := range context.Capabilities {
		n, err := sidSize(sid)
		if err != nil || n != len(sid) {
			return nil, fmt.Errorf("dmr: invalid capability SID")
		}
		capSize += n
	}
	out := make([]byte, 20+size+capSize)
	le.PutUint32(out, SecurityTag)
	le.PutUint32(out[4:], uint32(len(out)))
	le.PutUint32(out[8:], context.Flags)
	le.PutUint16(out[12:], uint16(size))
	le.PutUint16(out[14:], uint16(len(context.Capabilities)))
	le.PutUint16(out[16:], uint16(capSize))
	copy(out[20:], context.PackageSID)
	offset := 20 + size
	for _, sid := range context.Capabilities {
		copy(out[offset:], sid)
		offset += len(sid)
	}
	return out, nil
}

// ParseSecurityContext validates a SECU section, including every SID and the
// declared capability count. Returned SID slices alias data with capped lengths.
func ParseSecurityContext(data []byte) (SecurityContext, error) {
	var result SecurityContext
	if len(data) < 20 || len(data)%4 != 0 || le.Uint32(data) != SecurityTag ||
		uint64(le.Uint32(data[4:])) != uint64(len(data)) || le.Uint16(data[18:]) != 0 {
		return result, fmt.Errorf("dmr: invalid SECU header")
	}
	packageSize := int(le.Uint16(data[12:]))
	count := int(le.Uint16(data[14:]))
	capSize := int(le.Uint16(data[16:]))
	if packageSize > 68 || count > 128 || capSize > 8704 || 20+packageSize+capSize != len(data) {
		return result, fmt.Errorf("dmr: invalid SECU extents")
	}
	packageEnd := 20 + packageSize
	packageSID := data[20:packageEnd:packageEnd]
	if n, err := sidSize(packageSID); err != nil || n != packageSize {
		return result, fmt.Errorf("dmr: invalid package SID")
	}
	capabilities := make([][]byte, 0, count)
	offset := packageEnd
	for i := 0; i < count; i++ {
		n, err := sidSize(data[offset:])
		if err != nil {
			return result, fmt.Errorf("dmr: capability %d: %w", i, err)
		}
		capabilities = append(capabilities, data[offset:offset+n:offset+n])
		offset += n
	}
	if offset != len(data) {
		return result, fmt.Errorf("dmr: capability count does not consume extent")
	}
	return SecurityContext{Flags: le.Uint32(data[8:]), PackageSID: packageSID, Capabilities: capabilities}, nil
}
