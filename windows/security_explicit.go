package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"go.starlark.net/starlark"
)

// CopyExplicitFileACL constructs the effective and propagation ACEs of an
// explicit ACL for a file or directory under auto-inheritance. It maps and
// clips effective rights, substitutes creator owner/group, and preserves
// callback data. The input must contain only explicit ACEs; inherited ACEs
// require selection by the caller and are rejected. This does not select or
// merge parent ACLs, supply descriptor defaults, or represent absent/NULL ACLs.
// Supported layouts are allow, deny, audit, alarm and callback allow. Other
// layouts, creator identities and reserved flags fail closed.
func CopyExplicitFileACL(source, owner, group []byte, directory bool) ([]byte, error) {
	return copyExplicitACL(source, owner, group, directory, fileAccessMapping)
}

func copyExplicitACL(source, owner, group []byte, directory bool, mapping securityAccessMapping) ([]byte, error) {
	revision, entries, err := ParseACL(source)
	if err != nil {
		return nil, err
	}
	for _, sid := range [][]byte{owner, group} {
		if _, err := SIDString(sid); err != nil {
			return nil, fmt.Errorf("explicit file ACL principal: %w", err)
		}
	}
	out := make([]byte, 8)
	out[0] = revision
	count := 0
	appendACE := func(ace []byte) error {
		if len(ace) > 0xffff-len(out) {
			return fmt.Errorf("effective file ACL exceeds size limit")
		}
		out = append(out, ace...)
		count++
		return nil
	}
	for _, entry := range entries {
		if entry.Flags & ^byte(0xcf) != 0 {
			return nil, fmt.Errorf("unsupported explicit file ACE flags %#x", entry.Flags)
		}
		data, changed, creator, err := effectiveSecurityACE(entry, owner, group, mapping)
		if err != nil {
			return nil, err
		}
		originalMask := binary.LittleEndian.Uint32(entry.Data[4:])
		effective := entry.Flags&8 == 0 && data != nil
		propagate := directory && entry.Flags&3 != 0
		if effective {
			if propagate && !changed {
				data[1] |= entry.Flags & 0x1f
			}
			if err := appendACE(data); err != nil {
				return nil, err
			}
		}
		if propagate && (!effective || changed) {
			// A zero-mask ordinary ACE without a creator SID contributes no propagation.
			// Callback ACEs retain their application data even when the mask is zero.
			if !effective && entry.Type <= 8 && originalMask == 0 && !creator {
				continue
			}
			raw := bytes.Clone(entry.Data)
			raw[1] |= 8
			if err := appendACE(raw); err != nil {
				return nil, err
			}
		}
	}
	binary.LittleEndian.PutUint16(out[2:], uint16(len(out)))
	binary.LittleEndian.PutUint16(out[4:], uint16(count))
	return out, nil
}

// fileACESID validates supported mask/SID layouts, including callback suffixes.
func fileACESID(entry ACLEntry) (sid, tail []byte, err error) {
	switch entry.Type {
	case 0, 1, 2, 3, 9:
	default:
		return nil, nil, fmt.Errorf("unsupported file ACE type %d", entry.Type)
	}
	if len(entry.Data) < 16 {
		return nil, nil, fmt.Errorf("truncated file ACE")
	}
	end := 16 + int(entry.Data[9])*4
	if end > len(entry.Data) {
		return nil, nil, fmt.Errorf("truncated file ACE SID")
	}
	if entry.Type != 9 && end != len(entry.Data) {
		return nil, nil, fmt.Errorf("unexpected ordinary ACE suffix")
	}
	sid = entry.Data[8:end]
	if _, err := SIDString(sid); err != nil {
		return nil, nil, err
	}
	return sid, entry.Data[end:], nil
}

type securityAccessMapping struct {
	read, write, execute, all uint32
}

var fileAccessMapping = securityAccessMapping{0x120089, 0x120116, 0x1200a0, 0x1f01ff}
var registryAccessMapping = securityAccessMapping{0x20019, 0x20006, 0x20019, 0xf003f}

func (m securityAccessMapping) mapMask(mask uint32) uint32 {
	mapped := mask & 0x0fffffff
	for _, item := range []struct{ generic, specific uint32 }{{0x80000000, m.read}, {0x40000000, m.write}, {0x20000000, m.execute}, {0x10000000, m.all}} {
		if mask&item.generic != 0 {
			mapped |= item.specific
		}
	}
	return mapped
}

func mapGenericFileMask(mask uint32) uint32 { return fileAccessMapping.mapMask(mask) }

func copyExplicitFileACLBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source, owner, group starlark.Value
	directory := false
	if err := starlark.UnpackArgs("copy_explicit_file_acl", args, kwargs, "source", &source, "owner", &owner, "group", &group, "directory?", &directory); err != nil {
		return nil, err
	}
	acl, err := bytesForBinaryValueLimited(source, 0xffff)
	if err != nil {
		return nil, err
	}
	ownerBytes, err := bytesForBinaryValueLimited(owner, 68)
	if err != nil {
		return nil, err
	}
	groupBytes, err := bytesForBinaryValueLimited(group, 68)
	if err != nil {
		return nil, err
	}
	result, err := CopyExplicitFileACL(acl, ownerBytes, groupBytes, directory)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(result), nil
}
