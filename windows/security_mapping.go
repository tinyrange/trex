package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"go.starlark.net/starlark"
)

func fileSecurityMaskOffsets(data []byte) (map[int]bool, error) {
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("file security descriptor too large")
	}
	if err := validateSelfRelativeSecurityDescriptor(data); err != nil {
		return nil, err
	}
	control := binary.LittleEndian.Uint16(data[2:])
	type region struct {
		start, end int
		acl        bool
	}
	regions := []region{}
	masks := map[int]bool{}
	for _, field := range []struct {
		offset  int
		acl     bool
		present uint16
	}{{4, false, 0}, {8, false, 0}, {12, true, 0x10}, {16, true, 4}} {
		start := int(binary.LittleEndian.Uint32(data[field.offset:]))
		if start == 0 {
			continue
		}
		if start%4 != 0 {
			return nil, fmt.Errorf("unaligned security component")
		}
		if field.acl && control&field.present == 0 {
			return nil, fmt.Errorf("ACL offset without presence bit")
		}
		size := 8 + int(data[start+1])*4
		if field.acl {
			size = int(binary.LittleEndian.Uint16(data[start+2:]))
		}
		// The header/extent validator above established both component extents.
		current := region{start, start + size, field.acl}
		for _, previous := range regions {
			if current.start < previous.end && previous.start < current.end && current != previous {
				return nil, fmt.Errorf("overlapping security components")
			}
		}
		regions = append(regions, current)
		if !field.acl {
			if _, err := SIDString(data[start : start+size]); err != nil {
				return nil, err
			}
			continue
		}
		_, entries, err := ParseACL(data[start : start+size])
		if err != nil {
			return nil, err
		}
		offset := start + 8
		for _, entry := range entries {
			if _, _, err := fileACESID(entry); err != nil {
				return nil, err
			}
			masks[offset+4] = true
			offset += len(entry.Data)
		}
	}
	return masks, nil
}

// MapFileSecurityRights maps generic bits in a self-relative descriptor's ACE
// access masks to file rights. It preserves the descriptor's layout, all other
// bytes, absent/NULL ACLs, and ACE ordering. It does not supply defaults,
// inherit ACEs, clear propagation flags, or decide whether an ACL is applicable.
// Unknown ACE layouts fail closed rather than guessing where their mask lives.
func MapFileSecurityRights(data []byte) ([]byte, error) {
	masks, err := fileSecurityMaskOffsets(data)
	if err != nil {
		return nil, err
	}
	out := bytes.Clone(data)
	for offset := range masks {
		mask := binary.LittleEndian.Uint32(out[offset:])
		binary.LittleEndian.PutUint32(out[offset:], mapGenericFileMask(mask))
	}
	return out, nil
}

func mapFileSecurityRightsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	if err := starlark.UnpackArgs("map_file_security_rights", args, kwargs, "source", &source); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(source, 1<<20)
	if err != nil {
		return nil, err
	}
	mapped, err := MapFileSecurityRights(data)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(mapped), nil
}
