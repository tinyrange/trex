package windows

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"unicode/utf16"
)

func TestWinsockCatalogItem(t *testing.T) {
	// Windows 2000 SP1 wshtcpip WSHGetWSAProtocolInfo's TCP/IP record.
	fixed, err := hex.DecodeString("6600020000000000000000000000000008000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000002000000100000001000000001000000060000000000000000000000000000000000000000000000")
	if err != nil || len(fixed) != 116 {
		t.Fatal("invalid protocol fixture", err, len(fixed))
	}
	protocol := make([]byte, 628)
	copy(protocol, fixed)
	for i, c := range utf16.Encode([]rune("MSAFD Tcpip [TCP/IP]")) {
		binary.LittleEndian.PutUint16(protocol[116+i*2:], c)
	}
	provider, _ := hex.DecodeString("a01a0fe78babcf118ca300805f48a192")
	library := `%SystemRoot%\system32\msafd.dll`
	item, err := WinsockCatalogItem(library, protocol, provider, 1001)
	if err != nil {
		t.Fatal(err)
	}
	if len(item) != 888 || string(item[:len(library)]) != library || item[len(library)] != 0 ||
		!bytes.Equal(item[280:296], provider) || binary.LittleEndian.Uint32(item[296:]) != 1001 ||
		!bytes.Equal(item[260:280], protocol[:20]) || !bytes.Equal(item[300:], protocol[40:]) {
		t.Fatal("incorrect persisted catalog entry")
	}
	if !bytes.Equal(protocol[:116], fixed) {
		t.Fatal("modified transport helper input")
	}
	for _, bad := range []string{"", "a\x00b", "非ASCII.dll", string(bytes.Repeat([]byte{'x'}, 260))} {
		if _, err := WinsockCatalogItem(bad, protocol, provider, 1001); err == nil {
			t.Fatalf("accepted invalid library %q", bad)
		}
	}
	if _, err := WinsockCatalogItem(library, protocol[:627], provider, 1001); err == nil {
		t.Fatal("accepted truncated protocol")
	}
	binary.LittleEndian.PutUint32(protocol[40:], 8)
	if _, err := WinsockCatalogItem(library, protocol, provider, 1001); err == nil {
		t.Fatal("accepted oversized protocol chain")
	}
}
