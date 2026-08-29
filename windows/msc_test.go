package windows

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestMSCSnapins(t *testing.T) {
	text := `<MMC_ConsoleFile><Snapin CLSID="{74246bfc-4c96-11d0-abef-0020af6b0b7a}"/><String>{C96401CC-0E17-11D3-885B-00C04F72C717}</String></MMC_ConsoleFile>`
	units := utf16.Encode([]rune(text))
	data := make([]byte, 2+len(units)*2)
	data[0], data[1] = 0xff, 0xfe
	for index, unit := range units {
		binary.LittleEndian.PutUint16(data[2+index*2:], unit)
	}
	got := mscSnapins(data)
	if len(got) != 2 || got[0] != "{74246BFC-4C96-11D0-ABEF-0020AF6B0B7A}" {
		t.Fatalf("snap-ins = %#v", got)
	}
}
