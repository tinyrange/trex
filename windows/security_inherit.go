package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"go.starlark.net/starlark"
)

// InheritFileACL derives only the auto-inherited ACEs from a parent's ACL for
// a new file or directory. It honors OI/CI/NP, supplies ID, normalizes effective
// rights and creator principals, and prunes ordinary ACEs whose effective and
// propagation masks are already covered by prior inherited ACEs. Callback
// ACEs are not deduplicated. It does not merge explicit ACLs, select defaults,
// apply protection policy, or create a security descriptor. An empty result
// means no inherited entries, NOT an instruction to install an empty ACL.
// Supported layouts and creator identities are those of CopyExplicitFileACL,
// plus a single mandatory-label ACE with an integrity SID and mask 0..7. Label
// rights (including a zero mask) are preserved, not treated as file access bits.
// This does not select a token label or authorize an explicit label assignment.
func InheritFileACL(parent, owner, group []byte, directory bool) ([]byte, error) {
	return inheritSecurityACL(parent, owner, group, directory, fileAccessMapping)
}

func inheritSecurityACL(parent, owner, group []byte, directory bool, mapping securityAccessMapping) ([]byte, error) {
	revision, entries, err := ParseACL(parent)
	if err != nil {
		return nil, err
	}
	for _, sid := range [][]byte{owner, group} {
		if _, err := SIDString(sid); err != nil {
			return nil, fmt.Errorf("inherited file ACL principal: %w", err)
		}
	}
	output := [][]byte{}
	size := 8
	appendACE := func(ace []byte) error {
		if len(ace) > 0xffff-size {
			return fmt.Errorf("inherited file ACL exceeds size limit")
		}
		output = append(output, ace)
		size += len(ace)
		return nil
	}
	labels := 0
	for _, entry := range entries {
		if entry.Flags & ^byte(0xdf) != 0 {
			return nil, fmt.Errorf("unsupported parent file ACE flags %#x", entry.Flags)
		}
		var data []byte
		var changed bool
		if entry.Type == 17 {
			labels++
			if labels > 1 {
				return nil, fmt.Errorf("multiple parent mandatory labels require selection policy")
			}
			data, err = inheritedMandatoryLabelACE(entry)
		} else {
			data, changed, _, err = effectiveSecurityACE(entry, owner, group, mapping)
		}
		if err != nil {
			return nil, err
		}
		effective := entry.Flags&1 != 0
		propagate := false
		if directory {
			effective = entry.Flags&2 != 0
			propagate = entry.Flags&3 != 0 && entry.Flags&4 == 0
		}
		if effective && data != nil {
			data[1] |= 0x10
			if coveredInheritedFileACE(output, data) {
				data = nil
			}
		} else {
			data = nil
		}
		if data != nil {
			if propagate && !changed {
				data[1] |= entry.Flags & 3
			}
			if err := appendACE(data); err != nil {
				return nil, err
			}
		}
		if propagate && (data == nil || changed) {
			// Unlike explicit copying, parent propagation omits ordinary zero masks
			// even for creator SIDs. The effective creator ACE can still survive.
			if entry.Type <= 8 && binary.LittleEndian.Uint32(entry.Data[4:]) == 0 {
				continue
			}
			inherited := bytes.Clone(entry.Data)
			inherited[1] |= 0x18
			if !coveredInheritedFileACE(output, inherited) {
				if err := appendACE(inherited); err != nil {
					return nil, err
				}
			}
		}
	}
	out := make([]byte, 8, size)
	out[0] = revision
	binary.LittleEndian.PutUint16(out[2:], uint16(size))
	binary.LittleEndian.PutUint16(out[4:], uint16(len(output)))
	for _, ace := range output {
		out = append(out, ace...)
	}
	return out, nil
}

// Mandatory policy masks are not file rights. In particular, a zero mask
// still carries an integrity SID and survives native parent inheritance.
func inheritedMandatoryLabelACE(entry ACLEntry) ([]byte, error) {
	if len(entry.Data) != 20 || entry.Flags & ^byte(0x1f) != 0 ||
		!bytes.Equal(entry.Data[8:16], []byte{1, 1, 0, 0, 0, 0, 0, 16}) ||
		binary.LittleEndian.Uint32(entry.Data[4:]) & ^uint32(7) != 0 {
		return nil, fmt.Errorf("unsupported parent mandatory-label ACE")
	}
	out := bytes.Clone(entry.Data)
	out[1] = 0
	return out, nil
}

// This is coverage, not equality or mask union. Multiple earlier ACEs may
// jointly cover the new mask in each of the effective, OI and CI domains.
func coveredInheritedFileACE(previous [][]byte, candidate []byte) bool {
	if candidate[0] > 3 || candidate[1]&0x10 == 0 {
		return false
	}
	mask := binary.LittleEndian.Uint32(candidate[4:])
	var effective, objects, containers uint32
	if candidate[1]&8 == 0 {
		effective = mask
	}
	if candidate[1]&1 != 0 {
		objects = mask
	}
	if candidate[1]&2 != 0 {
		containers = mask
	}
	for _, earlier := range previous {
		if earlier[0] != candidate[0] || earlier[1]&0x10 == 0 || !bytes.Equal(earlier[8:], candidate[8:]) {
			continue
		}
		if candidate[0] >= 2 && (earlier[1]^candidate[1])&0xc0 != 0 {
			continue
		}
		covered := binary.LittleEndian.Uint32(earlier[4:])
		if earlier[1]&8 == 0 {
			effective &^= covered
		}
		if earlier[1]&1 != 0 {
			objects &^= covered
		}
		if earlier[1]&2 != 0 {
			containers &^= covered
		}
		if effective|objects|containers == 0 {
			return true
		}
	}
	return false
}

func effectiveSecurityACE(entry ACLEntry, owner, group []byte, mapping securityAccessMapping) (data []byte, changed, creator bool, err error) {
	sid, tail, err := fileACESID(entry)
	if err != nil {
		return nil, false, false, err
	}
	replacement := sid
	creator = len(sid) == 12 && bytes.Equal(sid[:8], []byte{1, 1, 0, 0, 0, 0, 0, 3})
	if creator {
		switch binary.LittleEndian.Uint32(sid[8:]) {
		case 0:
			replacement = owner
		case 1:
			replacement = group
		case 4:
			// OWNER RIGHTS is an effective identity, not a creator placeholder.
			// Preserve it in both effective and propagation ACEs.
			creator = false
		default:
			return nil, false, false, fmt.Errorf("unsupported creator SID in file ACL")
		}
	}
	original := binary.LittleEndian.Uint32(entry.Data[4:])
	mask := mapping.mapMask(original)
	allowed := mapping.all
	if entry.Type == 2 || entry.Type == 3 {
		allowed |= 0x01000000
	}
	mask &= allowed
	changed = mask != original || creator
	if mask == 0 && !creator {
		return nil, changed, creator, nil
	}
	return appxACE(entry.Type, entry.Flags&0xe0, mask, replacement, tail), changed, creator, nil
}

func inheritFileACLBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var parent, owner, group starlark.Value
	directory := false
	if err := starlark.UnpackArgs("inherit_file_acl", args, kwargs, "parent", &parent, "owner", &owner, "group", &group, "directory?", &directory); err != nil {
		return nil, err
	}
	acl, err := bytesForBinaryValueLimited(parent, 0xffff)
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
	result, err := InheritFileACL(acl, ownerBytes, groupBytes, directory)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(result), nil
}
