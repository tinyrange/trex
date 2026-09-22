package windows

import (
	"encoding/binary"
	"fmt"
	"go.starlark.net/starlark"
)

// ObjectACE constructs an allow, deny, audit or alarm object ACE. GUIDs are
// canonical textual identifiers; omitted GUIDs leave their presence bits clear.
func ObjectACE(kind, flags byte, mask uint32, sid []byte, objectType, inheritedType string) ([]byte, error) {
	if kind < 5 || kind > 8 {
		return nil, fmt.Errorf("object ACE: unsupported type %d", kind)
	}
	if _, err := SIDString(sid); err != nil {
		return nil, err
	}
	guids := make([]byte, 0, 32)
	var objectFlags uint32
	for i, value := range []string{objectType, inheritedType} {
		if value == "" {
			continue
		}
		guid, ok := parseWindowsGUID(value)
		if !ok {
			return nil, fmt.Errorf("object ACE: invalid GUID %q", value)
		}
		objectFlags |= 1 << i
		guids = append(guids, guid[:]...)
	}
	data := make([]byte, 12+len(guids)+len(sid))
	data[0], data[1] = kind, flags
	binary.LittleEndian.PutUint16(data[2:], uint16(len(data)))
	binary.LittleEndian.PutUint32(data[4:], mask)
	binary.LittleEndian.PutUint32(data[8:], objectFlags)
	copy(data[12:], guids)
	copy(data[12+len(guids):], sid)
	return data, nil
}

func objectACEBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kind, flags uint8
	var mask uint32
	var sid starlark.Bytes
	var objectType, inheritedType string
	if err := starlark.UnpackArgs("object_ace", args, kwargs, "type", &kind, "flags", &flags, "mask", &mask, "sid", &sid, "object_type?", &objectType, "inherited_type?", &inheritedType); err != nil {
		return nil, err
	}
	data, err := ObjectACE(kind, flags, mask, []byte(sid), objectType, inheritedType)
	return starlark.Bytes(data), err
}
