package os2

import (
	"encoding/binary"
	"fmt"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// ExtendedAttributes decodes the packed OS/2 FEA list (including cbList).
// Values remain opaque; this does not reinterpret typed EA value encodings.
func ExtendedAttributes(data []byte) ([]filesystemapi.ExtendedAttribute, error) {
	if len(data) < 4 || len(data) > 65535 || int(binary.LittleEndian.Uint32(data)) != len(data) {
		return nil, fmt.Errorf("invalid OS/2 FEA list length")
	}
	var result []filesystemapi.ExtendedAttribute
	for off := 4; off < len(data); {
		if len(data)-off < 5 {
			return nil, fmt.Errorf("truncated OS/2 FEA")
		}
		flags, n := data[off], int(data[off+1])
		v := int(binary.LittleEndian.Uint16(data[off+2:]))
		if n == 0 || n+5 > len(data)-off || v > len(data)-off-n-5 || data[off+4+n] != 0 {
			return nil, fmt.Errorf("invalid OS/2 FEA bounds/name")
		}
		result = append(result, filesystemapi.ExtendedAttribute{Name: string(data[off+4 : off+4+n]), Flags: flags, Value: append([]byte(nil), data[off+5+n:off+5+n+v]...)})
		off += 5 + n + v
	}
	if err := filesystemapi.ValidateExtendedAttributes(result); err != nil {
		return nil, err
	}
	return result, nil
}

func ExtendedAttributesBuiltin(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	var data []byte
	switch v := value.(type) {
	case starlark.Bytes:
		data = []byte(v)
	case starfile.File:
		if v.Size() > 65535 {
			return nil, fmt.Errorf("OS/2 FEA list exceeds 65535 bytes")
		}
		var err error
		data, err = starfile.ReadAll(v)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("OS/2 FEA input must be bytes or file")
	}
	eas, err := ExtendedAttributes(data)
	if err != nil {
		return nil, err
	}
	result := make([]starlark.Value, 0, len(eas))
	for _, ea := range eas {
		d := starlark.NewDict(3)
		_ = d.SetKey(starlark.String("name"), starlark.String(ea.Name))
		_ = d.SetKey(starlark.String("flags"), starlark.MakeInt(int(ea.Flags)))
		_ = d.SetKey(starlark.String("value"), starlark.Bytes(ea.Value))
		result = append(result, d)
	}
	return starlark.NewList(result), nil
}
