package windows

import (
	"encoding/binary"
	"fmt"

	"go.starlark.net/starlark"
)

// ACLEntry preserves an ACE's bytes and exposes its common header. Mask and
// SID are decoded for simple allow, deny, audit, alarm and mandatory-label
// ACEs. Other ACE layouts remain explicitly opaque, not misidentified SIDs.
type ACLEntry struct {
	Type, Flags byte
	Data        []byte
	Mask        uint32
	SID         []byte
}

// ParseACL validates one complete ACL and its bounded ACE extents. Returned
// entry slices alias data; unused allocation space after the ACEs is allowed.
// No access decision, identity lookup or host security API is involved.
func ParseACL(data []byte) (byte, []ACLEntry, error) {
	if len(data) < 8 || len(data) > 0xffff || (data[0] != 2 && data[0] != 4) || int(binary.LittleEndian.Uint16(data[2:])) != len(data) {
		return 0, nil, fmt.Errorf("invalid ACL header or extent")
	}
	count := int(binary.LittleEndian.Uint16(data[4:]))
	if count > (len(data)-8)/4 {
		return 0, nil, fmt.Errorf("ACL entry count exceeds extent")
	}
	entries := make([]ACLEntry, 0, count)
	offset := 8
	for i := 0; i < count; i++ {
		if offset+4 > len(data) {
			return 0, nil, fmt.Errorf("truncated ACL entry %d", i)
		}
		size := int(binary.LittleEndian.Uint16(data[offset+2:]))
		if size < 4 || size%4 != 0 || size > len(data)-offset {
			return 0, nil, fmt.Errorf("invalid ACL entry %d extent", i)
		}
		raw := data[offset : offset+size : offset+size]
		entry := ACLEntry{Type: raw[0], Flags: raw[1], Data: raw}
		switch entry.Type {
		case 0, 1, 2, 3, 0x11:
			if size < 16 {
				return 0, nil, fmt.Errorf("truncated ACL entry %d principal", i)
			}
			if _, err := SIDString(raw[8:]); err != nil {
				return 0, nil, fmt.Errorf("ACL entry %d principal: %w", i, err)
			}
			entry.Mask = binary.LittleEndian.Uint32(raw[4:])
			entry.SID = raw[8:]
		}
		entries = append(entries, entry)
		offset += size
	}
	return data[0], entries, nil
}

func aclEntriesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	if err := starlark.UnpackArgs("acl_entries", args, kwargs, "source", &source); err != nil {
		return nil, err
	}
	raw, err := bytesForBinaryValueLimited(source, 0xffff)
	if err != nil {
		return nil, fmt.Errorf("acl_entries: %w", err)
	}
	revision, entries, err := ParseACL(raw)
	if err != nil {
		return nil, fmt.Errorf("acl_entries: %w", err)
	}
	values := make([]starlark.Value, 0, len(entries))
	for _, entry := range entries {
		value := starlark.NewDict(5)
		_ = value.SetKey(starlark.String("type"), starlark.MakeInt(int(entry.Type)))
		_ = value.SetKey(starlark.String("flags"), starlark.MakeInt(int(entry.Flags)))
		_ = value.SetKey(starlark.String("data"), starlark.Bytes(entry.Data))
		var mask, principal starlark.Value = starlark.None, starlark.None
		if entry.SID != nil {
			mask, principal = starlark.MakeUint(uint(entry.Mask)), starlark.Bytes(entry.SID)
		}
		_ = value.SetKey(starlark.String("mask"), mask)
		_ = value.SetKey(starlark.String("sid"), principal)
		values = append(values, value)
	}
	result := starlark.NewDict(2)
	_ = result.SetKey(starlark.String("revision"), starlark.MakeInt(int(revision)))
	_ = result.SetKey(starlark.String("entries"), starlark.NewList(values))
	return result, nil
}
