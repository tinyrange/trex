package windows

import (
	"encoding/binary"
	"fmt"

	"go.starlark.net/starlark"
)

const samAliasHeaderSize = 0x34

// SAMAliasMembers decodes the SID vector in an NT5 SAM alias C value. This
// operates on record bytes, not a host SAM or an operating-system account.
func SAMAliasMembers(record []byte) ([][]byte, error) {
	if len(record) < samAliasHeaderSize {
		return nil, fmt.Errorf("short SAM alias C record")
	}
	payload := record[samAliasHeaderSize:]
	for _, field := range [][2]int{{4, 8}, {0x10, 0x14}, {0x1c, 0x20}, {0x28, 0x2c}} {
		offset, size := binary.LittleEndian.Uint32(record[field[0]:]), binary.LittleEndian.Uint32(record[field[1]:])
		if uint64(offset)+uint64(size) > uint64(len(payload)) {
			return nil, fmt.Errorf("SAM alias field at %#x exceeds payload", field[0])
		}
	}
	offset, size := binary.LittleEndian.Uint32(record[0x28:]), binary.LittleEndian.Uint32(record[0x2c:])
	vector := payload[offset : offset+size]
	count := binary.LittleEndian.Uint32(record[0x30:])
	if uint64(count) > uint64(len(vector)/8) {
		return nil, fmt.Errorf("SAM alias member count exceeds vector")
	}
	members := make([][]byte, 0, int(count))
	for i := uint32(0); i < count; i++ {
		if len(vector) < 8 {
			return nil, fmt.Errorf("truncated SAM alias member %d", i)
		}
		size := 8 + int(vector[1])*4
		if size > len(vector) {
			return nil, fmt.Errorf("truncated SAM alias member %d SID", i)
		}
		member := vector[:size:size]
		if _, err := SIDString(member); err != nil {
			return nil, fmt.Errorf("SAM alias member %d: %w", i, err)
		}
		members = append(members, member)
		vector = vector[size:]
	}
	if len(vector) != 0 {
		return nil, fmt.Errorf("SAM alias member count leaves trailing vector data")
	}
	return members, nil
}

// SAMAliasWithMembers replaces an alias's SID vector while preserving the
// security descriptor, names and unknown record data. Reverse membership
// indexes in the SAM hive must be updated by the caller in the same operation.
func SAMAliasWithMembers(record []byte, members [][]byte) ([]byte, error) {
	if _, err := SAMAliasMembers(record); err != nil {
		return nil, err
	}
	var vector []byte
	seen := make(map[string]bool, len(members))
	for _, member := range members {
		if _, err := SIDString(member); err != nil {
			return nil, fmt.Errorf("SAM alias replacement member: %w", err)
		}
		if seen[string(member)] {
			return nil, fmt.Errorf("duplicate SAM alias member")
		}
		seen[string(member)] = true
		vector = append(vector, member...)
	}
	offset, size := int(binary.LittleEndian.Uint32(record[0x28:])), int(binary.LittleEndian.Uint32(record[0x2c:]))
	// Keep unrelated payload positions stable. Reuse a trailing vector's space;
	// for a non-trailing vector, append instead of relocating opaque fields.
	end := len(record)
	if samAliasHeaderSize+offset+size == end {
		end = samAliasHeaderSize + offset
	}
	if uint64(end-samAliasHeaderSize)+uint64(len(vector)) > 0xffffffff {
		return nil, fmt.Errorf("SAM alias replacement exceeds record extent")
	}
	output := append([]byte(nil), record[:end]...)
	binary.LittleEndian.PutUint32(output[0x28:], uint32(end-samAliasHeaderSize))
	binary.LittleEndian.PutUint32(output[0x2c:], uint32(len(vector)))
	binary.LittleEndian.PutUint32(output[0x30:], uint32(len(members)))
	return append(output, vector...), nil
}

func samAliasMembersBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	if err := starlark.UnpackArgs("sam_alias_members", args, kwargs, "source", &source); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(source, 16<<20)
	if err != nil {
		return nil, err
	}
	members, err := SAMAliasMembers(data)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(members))
	for i, member := range members {
		values[i] = starlark.Bytes(member)
	}
	return starlark.NewList(values), nil
}

func samAliasWithMembersBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var members *starlark.List
	if err := starlark.UnpackArgs("sam_alias_with_members", args, kwargs, "source", &source, "members", &members); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(source, 16<<20)
	if err != nil {
		return nil, err
	}
	principals := make([][]byte, members.Len())
	for i := range principals {
		principals[i], err = bytesForBinaryValueLimited(members.Index(i), 68)
		if err != nil {
			return nil, err
		}
	}
	output, err := SAMAliasWithMembers(data, principals)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(output), nil
}
