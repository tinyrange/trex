package windows

import (
	"encoding/hex"
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

func guidBytesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value string
	if err := starlark.UnpackArgs("guid_bytes", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	guid, ok := parseWindowsGUID(value)
	if !ok {
		return nil, fmt.Errorf("guid_bytes: invalid GUID %q", value)
	}
	return starlark.Bytes(guid[:]), nil
}

// windowsGUIDString formats the mixed-endian byte representation used by
// Windows binary formats as a canonical braced GUID.
func windowsGUIDString(raw [16]byte) string {
	return fmt.Sprintf("{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6],
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15])
}

func parseWindowsGUID(value string) ([16]byte, bool) {
	var raw [16]byte
	value = strings.Trim(value, "{}")
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(decoded) != len(raw) {
		return raw, false
	}
	raw[0], raw[1], raw[2], raw[3] = decoded[3], decoded[2], decoded[1], decoded[0]
	raw[4], raw[5] = decoded[5], decoded[4]
	raw[6], raw[7] = decoded[7], decoded[6]
	copy(raw[8:], decoded[8:])
	return raw, true
}
