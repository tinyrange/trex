package windows

import (
	"bytes"
	"fmt"
	"strings"
)

// MS-SHLLINK 2.5.3: fixed ANSI and Unicode copies of the Installer descriptor.
func writeDarwinDataBlock(out *bytes.Buffer, descriptor string) error {
	if len(descriptor) > 259 || strings.ContainsRune(descriptor, 0) {
		return fmt.Errorf("shortcut: invalid Darwin descriptor length")
	}
	for _, r := range descriptor {
		if r < 32 || r > 126 {
			return fmt.Errorf("shortcut: Darwin descriptor must be printable ASCII")
		}
	}
	writeLE(out, uint32(0x314))
	writeLE(out, uint32(0xa0000006))
	ansi := make([]byte, 260)
	copy(ansi, descriptor)
	out.Write(ansi)
	for i := 0; i < 260; i++ {
		writeLE(out, uint16(ansi[i]))
	}
	return nil
}
