package windows

import (
	"encoding/hex"
	"fmt"
	"strings"
)

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
