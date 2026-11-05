package windows

import (
	"encoding/binary"
	"fmt"

	"go.starlark.net/starlark"
)

// SecurityDescriptorParts preserves the controls and bounded component bytes
// of a self-relative descriptor. Slices alias the input. A nil ACL with its
// presence bit set is NULL; without that bit it is absent. Neither is empty.
type SecurityDescriptorParts struct {
	Control                  uint16
	ResourceManagerControl   byte
	Owner, Group, SACL, DACL []byte
}

// ParseSecurityDescriptorParts validates component/ACE extents, alignment,
// presence and non-overlap without inheritance, access checks or defaults.
// Exact same-kind component aliases and unused trailing bytes are allowed.
// Unknown ACE bodies remain opaque, as in ParseACL.
func ParseSecurityDescriptorParts(data []byte) (SecurityDescriptorParts, error) {
	var p SecurityDescriptorParts
	if len(data) > 1<<20 {
		return p, fmt.Errorf("security descriptor too large")
	}
	if err := validateSelfRelativeSecurityDescriptor(data); err != nil {
		return p, err
	}
	p.Control = binary.LittleEndian.Uint16(data[2:])
	p.ResourceManagerControl = data[1]
	type region struct {
		start, end int
		acl        bool
	}
	var regions []region
	for _, f := range []struct {
		offset  int
		acl     bool
		present uint16
		dst     *[]byte
	}{
		{4, false, 0, &p.Owner}, {8, false, 0, &p.Group}, {12, true, 0x10, &p.SACL}, {16, true, 4, &p.DACL},
	} {
		start := int(binary.LittleEndian.Uint32(data[f.offset:]))
		if start == 0 {
			continue
		}
		if start%4 != 0 {
			return p, fmt.Errorf("unaligned security component")
		}
		if f.acl && p.Control&f.present == 0 {
			return p, fmt.Errorf("ACL offset without presence bit")
		}
		size := 8 + int(data[start+1])*4
		if f.acl {
			size = int(binary.LittleEndian.Uint16(data[start+2:]))
		}
		current := region{start, start + size, f.acl}
		for _, old := range regions {
			if current.start < old.end && old.start < current.end && current != old {
				return p, fmt.Errorf("overlapping security components")
			}
		}
		regions = append(regions, current)
		part := data[start : start+size : start+size]
		if f.acl {
			if _, _, err := ParseACL(part); err != nil {
				return p, err
			}
		} else if _, err := SIDString(part); err != nil {
			return p, err
		}
		*f.dst = part
	}
	return p, nil
}

func securityDescriptorPartsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	if err := starlark.UnpackArgs("security_descriptor_parts", args, kwargs, "source", &source); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(source, 1<<20)
	if err != nil {
		return nil, err
	}
	p, err := ParseSecurityDescriptorParts(data)
	if err != nil {
		return nil, err
	}
	out := starlark.NewDict(6)
	_ = out.SetKey(starlark.String("control"), starlark.MakeUint(uint(p.Control)))
	_ = out.SetKey(starlark.String("resource_manager_control"), starlark.MakeUint(uint(p.ResourceManagerControl)))
	for _, f := range []struct {
		name string
		data []byte
	}{{"owner", p.Owner}, {"group", p.Group}, {"sacl", p.SACL}, {"dacl", p.DACL}} {
		var value starlark.Value = starlark.None
		if f.data != nil {
			value = starlark.Bytes(f.data)
		}
		_ = out.SetKey(starlark.String(f.name), value)
	}
	return out, nil
}
