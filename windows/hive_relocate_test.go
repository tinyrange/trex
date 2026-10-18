package windows

import (
	"bytes"
	"testing"
)

func TestDriveRelocationPreservesIdentifiers(t *testing.T) {
	for _, tc := range [][2]string{
		{`FX:{b05566ad-fe9c-4363-be05-7a4cbb7cb510}`, `FX:{b05566ad-fe9c-4363-be05-7a4cbb7cb510}`},
		{`ms-appx:///Assets/x.png`, `ms-appx:///Assets/x.png`},
		{`@X:\Windows\icons.dll,-1`, `@C:\Windows\icons.dll,-1`},
		{`"X:\Program Files\app.exe" /path=x:\data;X:\other`, `"C:\Program Files\app.exe" /path=c:\data;C:\other`},
		{`/MMC/SnapIns/FX:{guid}/X:path`, `/MMC/SnapIns/FX:{guid}/C:path`},
		{"X:\\a\x00fx:thing\x00x:\\b\x00\x00", "C:\\a\x00fx:thing\x00c:\\b\x00\x00"},
		{`\??\X:\Windows`, `\??\C:\Windows`},
		{`prefix: value X:`, `prefix: value C:`},
		{`éX: abcX: _X:`, `éX: abcX: _X:`},
	} {
		if got := relocateDriveText(tc[0], 'X', 'C'); got != tc[1] {
			t.Errorf("text %q: got %q want %q", tc[0], got, tc[1])
		}
		raw := append(utf16Bytes(tc[0]), 0xff)
		original := append([]byte(nil), raw...)
		want := append(utf16Bytes(tc[1]), 0xff)
		if got := relocateDriveUTF16(raw, 'X', 'C'); !bytes.Equal(got, want) {
			t.Errorf("UTF16 %q: got %x want %x", tc[0], got, want)
		}
		if !bytes.Equal(raw, original) {
			t.Fatal("modified source hive data")
		}
	}
	raw := []byte{0, 'X', 0, ':', 0, 0, 0xd8, 'X', 0, ':', 0}
	if got := relocateDriveUTF16(raw, 'X', 'C'); !bytes.Equal(got, raw) {
		t.Fatal("matched unaligned UTF16")
	}
}
