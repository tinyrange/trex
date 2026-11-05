package windows

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestShortcutAppIDPropertyStore(t *testing.T) {
	for _, id := range []string{"SimonTatham.PuTTY", "A", "tool.\U0001f680"} {
		data, err := buildShellLink(shellLinkOptions{Target: `C:\Apps\tool.exe`, AppUserModelID: id})
		if err != nil {
			t.Fatal(err)
		}
		// Locate the ExtraData signature independently of variable IDList and strings.
		sig := []byte{9, 0, 0, 0xa0}
		off := bytes.Index(data, sig) - 4
		if off < 0 {
			t.Fatal("missing property store")
		}
		block := data[off:]
		u32 := func(pos int) int { return int(binary.LittleEndian.Uint32(block[pos:])) }
		if u32(0) != len(block)-4 || u32(8) != u32(0)-12 || u32(12) != 0x53505331 {
			t.Fatal("invalid storage bounds")
		}
		if u32(36) != 5 || block[40] != 0 || binary.LittleEndian.Uint16(block[41:]) != 31 {
			t.Fatal("wrong property type/id")
		}
		n := u32(45)
		chars := make([]uint16, n)
		for i := range chars {
			chars[i] = binary.LittleEndian.Uint16(block[49+2*i:])
		}
		if chars[n-1] != 0 || string(utf16.Decode(chars[:n-1])) != id {
			t.Fatal("invalid Unicode value")
		}
		if !bytes.Equal(block[len(block)-12:], make([]byte, 12)) {
			t.Fatal("missing property/store/link terminators")
		}
	}
	for _, id := range []string{"a\x00b", strings.Repeat("x", 129)} {
		if _, err := buildShellLink(shellLinkOptions{Target: `C:\x.exe`, AppUserModelID: id}); err == nil {
			t.Fatal("accepted invalid ID")
		}
	}
}
