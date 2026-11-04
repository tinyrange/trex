package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"go.starlark.net/starlark"
)

type fileSecurityParts struct {
	control                  uint16
	owner, group, sacl, dacl []byte
}

func readFileSecurityParts(data []byte, parent bool) (fileSecurityParts, error) {
	var p fileSecurityParts
	if _, err := fileSecurityMaskOffsets(data); err != nil {
		return p, err
	}
	p.control = binary.LittleEndian.Uint16(data[2:])
	// Defaulted principals/ACLs and resource-manager controls require caller
	// policy. A child NULL ACL also needs selection policy. A parent NULL
	// ACL supplies no ACEs, as in the native flags-0x101b path.
	if data[1] != 0 || p.control & ^uint16(0xbf14) != 0 {
		return p, fmt.Errorf("unsupported file security descriptor controls %#x", p.control)
	}
	for _, f := range []struct {
		offset  int
		acl     bool
		present uint16
		dst     *[]byte
	}{
		{4, false, 0, &p.owner}, {8, false, 0, &p.group}, {12, true, 0x10, &p.sacl}, {16, true, 4, &p.dacl},
	} {
		start := int(binary.LittleEndian.Uint32(data[f.offset:]))
		if start == 0 {
			if f.acl && p.control&f.present != 0 && !parent {
				return p, fmt.Errorf("NULL file ACL requires caller policy")
			}
			continue
		}
		size := 8 + int(data[start+1])*4
		if f.acl {
			size = int(binary.LittleEndian.Uint16(data[start+2:]))
			if data[start] != 2 {
				return p, fmt.Errorf("unsupported file ACL revision %d", data[start])
			}
		}
		*f.dst = data[start : start+size]
	}
	return p, nil
}

// InheritFileSecurity constructs a new file descriptor with both ACLs under
// auto-inheritance and explicit owner/group, without token defaults or access
// checks. It implements the bounded RtlNewSecurityObjectEx flags-0x101b path,
// not WCP's input defaulting or final control adjustment. The source must have
// owner and group; absent ACLs are supported, child NULL/defaulted ACLs rejected.
// Parent NULL ACLs contribute no entries; they do not install a child NULL ACL.
// Protected ACLs retain input inherited ACEs as explicit; unprotected ACLs drop
// them before parent inheritance. The result preserves absent versus empty ACLs.
func InheritFileSecurity(source, parent []byte, directory bool) ([]byte, error) {
	return inheritSecurity(source, parent, directory, fileAccessMapping)
}

// InheritRegistrySecurity constructs registry key security using the same bounded
// auto-inheritance path, with key generic rights and container inheritance.
// Owner and group must be explicit. It does not choose WCP defaults, adjust final
// request controls, authorize ownership, or assign the result to a registry hive.
func InheritRegistrySecurity(source, parent []byte) ([]byte, error) {
	return inheritSecurity(source, parent, true, registryAccessMapping)
}

func inheritSecurity(source, parent []byte, directory bool, mapping securityAccessMapping) ([]byte, error) {
	child, err := readFileSecurityParts(source, false)
	if err != nil {
		return nil, err
	}
	if child.owner == nil || child.group == nil {
		return nil, fmt.Errorf("file security requires explicit owner and group")
	}
	var inherited fileSecurityParts
	if parent != nil {
		inherited, err = readFileSecurityParts(parent, true)
		if err != nil {
			return nil, fmt.Errorf("parent file security: %w", err)
		}
	}
	control := uint16(0x8c00) | child.control&0x3000
	dacl, err := composeFileACL(child.dacl, inherited.dacl, child.owner, child.group, directory, child.control&0x1000 != 0, mapping)
	if err != nil {
		return nil, err
	}
	sacl, err := composeFileACL(child.sacl, inherited.sacl, child.owner, child.group, directory, child.control&0x2000 != 0, mapping)
	if err != nil {
		return nil, err
	}
	if dacl != nil {
		control |= 4
	} else {
		control |= 0x1000
	}
	if sacl != nil {
		control |= 0x10
	}
	out := make([]byte, 20)
	out[0] = 1
	binary.LittleEndian.PutUint16(out[2:], control)
	for _, part := range []struct {
		offset int
		data   []byte
	}{{4, child.owner}, {8, child.group}, {12, sacl}, {16, dacl}} {
		if part.data == nil {
			continue
		}
		binary.LittleEndian.PutUint32(out[part.offset:], uint32(len(out)))
		out = append(out, part.data...)
	}
	return out, nil
}

func composeFileACL(source, parent, owner, group []byte, directory, protected bool, mapping securityAccessMapping) ([]byte, error) {
	var explicit []byte
	if source != nil {
		_, entries, err := ParseACL(source)
		if err != nil {
			return nil, err
		}
		selected := []byte{2, 0, 8, 0, 0, 0, 0, 0}
		count := 0
		for _, entry := range entries {
			if entry.Flags & ^byte(0xdf) != 0 {
				return nil, fmt.Errorf("unsupported file ACE flags %#x", entry.Flags)
			}
			if entry.Flags&0x10 != 0 && !protected {
				continue
			}
			ace := bytes.Clone(entry.Data)
			ace[1] &^= 0x10
			selected = append(selected, ace...)
			count++
		}
		binary.LittleEndian.PutUint16(selected[2:], uint16(len(selected)))
		binary.LittleEndian.PutUint16(selected[4:], uint16(count))
		explicit, err = copyExplicitACL(selected, owner, group, directory, mapping)
		if err != nil {
			return nil, err
		}
	}
	if !protected && parent != nil {
		inherited, err := inheritSecurityACL(parent, owner, group, directory, mapping)
		if err != nil {
			return nil, err
		}
		if binary.LittleEndian.Uint16(inherited[4:]) != 0 {
			if explicit == nil {
				return inherited, nil
			}
			if len(inherited)-8 > 0xffff-len(explicit) {
				return nil, fmt.Errorf("composed file ACL exceeds size limit")
			}
			count := int(binary.LittleEndian.Uint16(explicit[4:])) + int(binary.LittleEndian.Uint16(inherited[4:]))
			explicit = append(explicit, inherited[8:]...)
			binary.LittleEndian.PutUint16(explicit[2:], uint16(len(explicit)))
			binary.LittleEndian.PutUint16(explicit[4:], uint16(count))
		}
	}
	return explicit, nil
}

func inheritFileSecurityBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	parent := starlark.Value(starlark.None)
	directory := false
	if err := starlark.UnpackArgs("inherit_file_security", args, kwargs, "source", &source, "parent?", &parent, "directory?", &directory); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(source, 1<<20)
	if err != nil {
		return nil, err
	}
	var parentData []byte
	if parent != starlark.None {
		parentData, err = bytesForBinaryValueLimited(parent, 1<<20)
		if err != nil {
			return nil, err
		}
	}
	result, err := InheritFileSecurity(data, parentData, directory)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(result), nil
}

func inheritRegistrySecurityBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	parent := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("inherit_registry_security", args, kwargs, "source", &source, "parent?", &parent); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(source, 1<<20)
	if err != nil {
		return nil, err
	}
	var parentData []byte
	if parent != starlark.None {
		parentData, err = bytesForBinaryValueLimited(parent, 1<<20)
		if err != nil {
			return nil, err
		}
	}
	result, err := InheritRegistrySecurity(data, parentData)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(result), nil
}
