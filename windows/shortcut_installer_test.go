package windows

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestInstallerShortcutDarwinBlock(t *testing.T) {
	descriptor := "01234567890123456789Main>abcdefghijklmnopqrst"
	data, err := buildShellLink(shellLinkOptions{Target: `C:\Program Files\Example\app.exe`, DarwinID: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(data[20:24])&0x1000 == 0 {
		t.Fatal("missing HasDarwinID")
	}
	block := data[len(data)-4-0x314 : len(data)-4]
	if binary.LittleEndian.Uint32(block[:4]) != 0x314 || binary.LittleEndian.Uint32(block[4:8]) != 0xa0000006 {
		t.Fatal("bad DarwinDataBlock header")
	}
	if !bytes.Equal(block[8:8+len(descriptor)], []byte(descriptor)) {
		t.Fatal("ANSI descriptor")
	}
	for i, c := range []byte(descriptor) {
		if binary.LittleEndian.Uint16(block[268+i*2:270+i*2]) != uint16(c) {
			t.Fatal("Unicode descriptor")
		}
	}
	if block[8+len(descriptor)] != 0 || binary.LittleEndian.Uint16(block[268+len(descriptor)*2:]) != 0 {
		t.Fatal("missing terminator")
	}
	for _, invalid := range []string{strings.Repeat("x", 260), "bad\x00id", "café"} {
		if _, err := buildShellLink(shellLinkOptions{Target: `C:\app.exe`, DarwinID: invalid}); err == nil {
			t.Fatal("accepted invalid descriptor")
		}
	}
}
