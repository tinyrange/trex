package windows

import (
	"encoding/binary"
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

// SIDString validates a complete revision-1 SID and returns its Windows string
// representation. It does not resolve the identity or consult a host account.
// Identifier authorities are big-endian; subauthorities are little-endian.
// MS-DTYP 2.4.2.1 requires hexadecimal authorities at and above 2^32.
func SIDString(raw []byte) (string, error) {
	if len(raw) < 8 || raw[0] != 1 || int(raw[1]) > 15 || len(raw) != 8+int(raw[1])*4 {
		return "", fmt.Errorf("invalid SID")
	}
	authority := uint64(0)
	for _, value := range raw[2:8] {
		authority = authority<<8 | uint64(value)
	}
	prefix := fmt.Sprintf("S-1-%d", authority)
	if authority >= 1<<32 {
		prefix = fmt.Sprintf("S-1-0x%012x", authority)
	}
	parts := []string{prefix}
	for index := 0; index < int(raw[1]); index++ {
		parts = append(parts, fmt.Sprint(binary.LittleEndian.Uint32(raw[8+index*4:12+index*4])))
	}
	return strings.Join(parts, "-"), nil
}

func sidStringBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	if err := starlark.UnpackArgs("sid_string", args, kwargs, "source", &source); err != nil {
		return nil, err
	}
	raw, err := bytesForBinaryValueLimited(source, 8+15*4)
	if err != nil {
		return nil, fmt.Errorf("sid_string: %w", err)
	}
	value, err := SIDString(raw)
	if err != nil {
		return nil, fmt.Errorf("sid_string: %w", err)
	}
	return starlark.String(value), nil
}
