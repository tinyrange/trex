package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"go.starlark.net/starlark"
)

// AssignRegistrySecurity constructs the result of the bounded registry
// RtlpSetSecurityObject path (AutoInheritFlags=0). The request must explicitly
// select owner, group, DACL and audit SACL, with consistent protection flags.
// LABEL_SECURITY_INFORMATION additionally replaces mandatory labels; otherwise
// current labels survive even a protected empty requested audit SACL.
//
// This is descriptor assignment, not creation, parent inheritance, propagation,
// token authorization or a hive write. Effective generic rights use the kernel
// key mapping (execute=0x20039, unlike WCP's 0x20019). Inherit-only ACEs retain
// generic rights. Unlike NTFS's flags-0x4000 path, duplicate ACEs survive.
func AssignRegistrySecurity(current, request []byte, information uint32) ([]byte, error) {
	old, err := ParseSecurityDescriptorParts(current)
	if err != nil {
		return nil, fmt.Errorf("current registry security: %w", err)
	}
	next, err := ParseSecurityDescriptorParts(request)
	if err != nil {
		return nil, fmt.Errorf("requested registry security: %w", err)
	}
	for _, p := range []SecurityDescriptorParts{old, next} {
		if p.ResourceManagerControl != 0 || p.Control & ^uint16(0xbf14) != 0 {
			return nil, fmt.Errorf("unsupported registry security controls %#x", p.Control)
		}
	}
	expected := uint32(15)
	if next.Control&0x1000 != 0 {
		expected |= 0x80000000
	} else {
		expected |= 0x20000000
	}
	if next.Control&0x2000 != 0 {
		expected |= 0x40000000
	} else {
		expected |= 0x10000000
	}
	if information & ^uint32(0x10) != expected {
		return nil, fmt.Errorf("unsupported registry security information %#x", information)
	}
	if next.Owner == nil || next.Group == nil || next.DACL == nil {
		return nil, fmt.Errorf("registry assignment requires explicit principals and non-NULL DACL")
	}
	dacl, err := assignedRegistryACL(next.DACL, false)
	if err != nil {
		return nil, err
	}
	audit, labels, err := registryAssignmentSACL(next.SACL)
	if err != nil {
		return nil, err
	}
	_, oldLabels, err := registryAssignmentSACL(old.SACL)
	if err != nil {
		return nil, err
	}
	if information&0x10 == 0 {
		labels = oldLabels
	}
	sacl, err := registryAssignmentACLBytes(append(audit, labels...))
	if err != nil {
		return nil, err
	}
	// Native assignment normalizes an empty audit SACL to present-NULL. It
	// preserves AI/protection and consumes the caller's AR request bits.
	if len(sacl) == 8 {
		sacl = nil
	}
	output := make([]byte, 20)
	output[0] = 1
	binary.LittleEndian.PutUint16(output[2:], next.Control & ^uint16(0x300) | 0x10)
	for _, part := range []struct {
		offset int
		data   []byte
	}{
		{12, sacl}, {16, dacl}, {4, next.Owner}, {8, next.Group},
	} {
		if part.data == nil {
			continue
		}
		binary.LittleEndian.PutUint32(output[part.offset:], uint32(len(output)))
		output = append(output, part.data...)
	}
	return output, nil
}

func assignedRegistryACL(data []byte, audit bool) ([]byte, error) {
	revision, entries, err := ParseACL(data)
	if err != nil {
		return nil, err
	}
	if revision != 2 {
		return nil, fmt.Errorf("unsupported registry ACL revision")
	}
	var result [][]byte
	mapping := securityAccessMapping{0x20019, 0x20006, 0x20039, 0xf003f}
	for _, entry := range entries {
		if audit {
			if entry.Type != 2 || entry.Flags & ^byte(0xdf) != 0 {
				return nil, fmt.Errorf("unsupported registry audit ACE")
			}
		} else if (entry.Type != 0 && entry.Type != 1 && entry.Type != 9) || entry.Flags & ^byte(0x1f) != 0 {
			return nil, fmt.Errorf("unsupported registry DACL ACE")
		}
		raw := bytes.Clone(entry.Data)
		if entry.Flags&8 == 0 {
			mask := mapping.mapMask(entry.Mask)
			if !audit {
				mask &= mapping.all
			}
			binary.LittleEndian.PutUint32(raw[4:], mask)
		}
		result = append(result, raw)
	}
	return registryAssignmentACLBytes(result)
}

func registryAssignmentSACL(data []byte) (audit, labels [][]byte, err error) {
	if data == nil {
		return nil, nil, nil
	}
	revision, entries, err := ParseACL(data)
	if err != nil {
		return nil, nil, err
	}
	if revision != 2 {
		return nil, nil, fmt.Errorf("unsupported registry SACL revision")
	}
	for _, entry := range entries {
		switch entry.Type {
		case 2:
			single, e := registryAssignmentACLBytes([][]byte{entry.Data})
			if e != nil {
				return nil, nil, e
			}
			mapped, e := assignedRegistryACL(single, true)
			if e != nil {
				return nil, nil, e
			}
			audit = append(audit, mapped[8:])
		case 17:
			if len(entry.SID) != 12 || !bytes.Equal(entry.SID[:8], []byte{1, 1, 0, 0, 0, 0, 0, 16}) || entry.Mask & ^uint32(7) != 0 || entry.Flags & ^byte(0x1f) != 0 {
				return nil, nil, fmt.Errorf("unsupported registry mandatory label")
			}
			labels = append(labels, bytes.Clone(entry.Data))
		default:
			return nil, nil, fmt.Errorf("unsupported registry SACL category %d", entry.Type)
		}
	}
	if len(labels) > 1 {
		return nil, nil, fmt.Errorf("multiple registry mandatory labels require selection policy")
	}
	return audit, labels, nil
}

func registryAssignmentACLBytes(entries [][]byte) ([]byte, error) {
	result := []byte{2, 0, 8, 0, 0, 0, 0, 0}
	for _, entry := range entries {
		if len(entry) > 0xffff-len(result) {
			return nil, fmt.Errorf("registry ACL exceeds extent")
		}
		result = append(result, entry...)
	}
	binary.LittleEndian.PutUint16(result[2:], uint16(len(result)))
	binary.LittleEndian.PutUint16(result[4:], uint16(len(entries)))
	return result, nil
}

func assignRegistrySecurityBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var current, request starlark.Value
	var information uint32
	if err := starlark.UnpackArgs("assign_registry_security", args, kwargs, "current", &current, "request", &request, "security_information", &information); err != nil {
		return nil, err
	}
	old, err := bytesForBinaryValueLimited(current, 1<<20)
	if err != nil {
		return nil, err
	}
	next, err := bytesForBinaryValueLimited(request, 1<<20)
	if err != nil {
		return nil, err
	}
	result, err := AssignRegistrySecurity(old, next, information)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(result), nil
}
