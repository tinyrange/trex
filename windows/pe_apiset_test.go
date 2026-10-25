package windows

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"unicode/utf16"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// The counted strings and shared host offsets reproduce a Windows 26100
// TerminalServices extension. In particular, adjacent WTS/WinStation hosts
// have no intervening NUL; scanning UTF-16 strings loses those boundaries.
func apiSetExtensionFixture(t *testing.T) []byte {
	t.Helper()
	b := delayImportFixture(false, false)
	clear(b[0x200:])
	clear(b[0x98+96+13*8 : 0x98+96+14*8])
	copy(b[0x98+224:], ".apiset\x00")
	header, err := hex.DecodeString("07000200eb0100001401000014000000170005002c010000780000002d00010000000000000000005c010000880000002200010000000000001000008001000098000000230001000000000000100000a4010000a8000000200001000000000006100000c801000098000000220001000000000002100000b8000000000000000700000000000000c8000000000000000f00000000000000e8000000000000000c0000000000000000010000000000000a00000000000000")
	if err != nil {
		t.Fatal(err)
	}
	copy(b[0x200:], header)
	for at, text := range map[int]string{184: "mpr.dll", 200: "userinitext.dll", 232: "wtsapi32.dll", 256: "winsta.dll"} {
		for i, u := range utf16.Encode([]rune(text)) {
			binary.LittleEndian.PutUint16(b[0x200+at+2*i:], u)
		}
	}
	for at, text := range map[int]string{276: "WinVOS-TerminalServices", 300: "api-ms-win-core-multipleproviderrouter-l1-1-0", 348: "ext-ms-win-session-userinit-l1-1-0", 384: "ext-ms-win-session-usertoken-l1-1-0", 420: "ext-ms-win-session-winsta-l1-1-6", 456: "ext-ms-win-session-wtsapi32-l1-1-2"} {
		copy(b[0x200+at:], text)
	}
	return b
}

func TestPEAPISetExtension(t *testing.T) {
	b := apiSetExtensionFixture(t)
	original := bytes.Clone(b)
	extension, err := parseAPISetExtension(b)
	if err != nil {
		t.Fatal(err)
	}
	if extension.name != "WinVOS-TerminalServices" || extension.flags != 2 || len(extension.contracts) != 5 || extension.contracts[2].hosts[0].host != "wtsapi32.dll" || extension.contracts[3].hosts[0].host != "winsta.dll" || extension.contracts[4].hosts[0].host != "wtsapi32.dll" {
		t.Fatalf("extension: %#v", extension)
	}
	object := &windowsPE{file: &starfile.Bytes{Data: b}, cache: make(starlark.StringDict)}
	view, err := object.Attr("api_set_extension")
	if err != nil {
		t.Fatal(err)
	}
	if err := view.(*starlark.Dict).SetKey(starlark.String("name"), starlark.String("changed")); err == nil {
		t.Fatal("mutable cached namespace")
	}
	if !bytes.Equal(original, b) {
		t.Fatal("inspection modified source")
	}
}

func TestPEAPISetExtensionRejectMalformed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"base namespace", 0, 6},
		{"oversized namespace", 4, 0xffffffff},
		{"table overflow", 12, 0xfffffff0},
		{"name overflow", 20, 0xffffffff},
		{"host table overflow", 24, 0xffffffff},
		{"host length overflow", 120 + 8, 0xffffffff},
		{"alias length overflow", 120 + 8, 0xffff0007},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := apiSetExtensionFixture(t)
			binary.LittleEndian.PutUint32(b[0x200+tc.offset:], tc.value)
			if _, err := parseAPISetExtension(b); err == nil {
				t.Fatal("accepted malformed namespace")
			}
		})
	}
}

func TestPEAPISetExtensionPackedHostLengths(t *testing.T) {
	b := apiSetExtensionFixture(t)
	// Reuse a counted UTF-16 string as an alias, retaining nonzero opaque
	// metadata. Neither field is part of the adjacent host length.
	v := b[0x200+120:]
	binary.LittleEndian.PutUint32(v[4:], 256)
	binary.LittleEndian.PutUint16(v[10:], 10)
	binary.LittleEndian.PutUint32(v[12:], 0x12345678)
	extension, err := parseAPISetExtension(b)
	if err != nil {
		t.Fatal(err)
	}
	want := apiSetHost{"mpr.dll", "winsta.dll", 0x12345678}
	if extension.contracts[0].hosts[0] != want {
		t.Fatalf("host: %#v", extension.contracts[0].hosts[0])
	}
}
