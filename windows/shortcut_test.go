package windows

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestBuildInternetShortcut(t *testing.T) {
	got, err := buildInternetShortcut("https://example.test/download", `C:\Program Files\Example\example.exe`, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := "[InternetShortcut]\r\nURL=https://example.test/download\r\nIconFile=C:\\Program Files\\Example\\example.exe\r\nIconIndex=2\r\n"
	if !bytes.Equal(got, []byte(want)) {
		t.Fatalf("internet shortcut = %q, want %q", got, want)
	}
}

func TestBuildInternetShortcutRejectsUnsafeFields(t *testing.T) {
	for _, test := range []struct {
		url  string
		icon string
	}{{}, {url: "https://example.test\r\nInjected=value"}, {url: "https://example.test", icon: "bad\nicon"}} {
		_, err := buildInternetShortcut(test.url, test.icon, 0)
		if err == nil || !strings.Contains(err.Error(), "empty") && !strings.Contains(err.Error(), "control character") {
			t.Fatalf("buildInternetShortcut(%q, %q) error = %v", test.url, test.icon, err)
		}
	}
}

func TestFileIDListItemLayout(t *testing.T) {
	item := fileIDListItem("winmine.exe", 1159168)
	if got, want := len(item), 74; got != want {
		t.Fatalf("file IDList item length = %d, want %d", got, want)
	}
	if got, want := binary.LittleEndian.Uint16(item[0:2]), uint16(74); got != want {
		t.Fatalf("file IDList item size = %d, want %d", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(item[4:8]), uint32(1159168); got != want {
		t.Fatalf("file size field = %d, want %d", got, want)
	}
	if got, want := item[25:30], []byte{0, 0, 0, 0x2e, 0}; string(got) != string(want) {
		t.Fatalf("unexpected extension offset bytes: % x", got)
	}
}

func TestDirectoryIDListItemLayoutWithSpaces(t *testing.T) {
	item := directoryIDListItem("Program Files")
	if got, want := len(item), 74; got != want {
		t.Fatalf("directory IDList item length = %d, want %d", got, want)
	}
	if got, want := binary.LittleEndian.Uint16(item[0:2]), uint16(len(item)); got != want {
		t.Fatalf("directory IDList item size = %d, want %d", got, want)
	}
	extensionOffset := int(binary.LittleEndian.Uint16(item[len(item)-2:]))
	if extensionOffset%2 != 0 {
		t.Fatalf("directory extension offset = %d, want even alignment", extensionOffset)
	}
	if got, want := int(binary.LittleEndian.Uint16(item[extensionOffset:extensionOffset+2])), len(item)-extensionOffset; got != want {
		t.Fatalf("directory extension size = %d, want %d", got, want)
	}
	if got, want := decodeUTF16Z(item[extensionOffset+20:len(item)-2]), "Program Files"; got != want {
		t.Fatalf("directory Unicode name = %q, want %q", got, want)
	}
}

func TestBuildShellLinkReactOSMetadata(t *testing.T) {
	link, err := buildShellLink(shellLinkOptions{
		Target:      `C:\ReactOS\system32\winmine.exe`,
		Description: "WineMine",
		TargetSize:  1159168,
		SystemRoot:  `C:\ReactOS`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := binary.LittleEndian.Uint32(link[0x14:0x18]), uint32(0x000002d7); got != want {
		t.Fatalf("link flags = %#x, want %#x", got, want)
	}
	pos := shellLinkTargetDataEnd(link)
	pos = checkShellLinkString(t, link, pos, "WineMine")
	pos = checkShellLinkString(t, link, pos, `C:\ReactOS\system32`)
	pos = checkShellLinkString(t, link, pos, `%SystemRoot%\system32\winmine.exe`)
	if got, want := binary.LittleEndian.Uint32(link[pos:pos+4]), uint32(0x314); got != want {
		t.Fatalf("environment block size = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(link[pos+4:pos+8]), uint32(0xa0000001); got != want {
		t.Fatalf("environment block signature = %#x, want %#x", got, want)
	}
	if got, want := string(link[pos+8:pos+8+33]), `%SystemRoot%\system32\winmine.exe`; got != want {
		t.Fatalf("environment ANSI target = %q, want %q", got, want)
	}
	pos += 0x314
	if got := binary.LittleEndian.Uint32(link[pos : pos+4]); got != 0 {
		t.Fatalf("terminal block = %#x, want 0", got)
	}
}

func TestBuildShellLinkArgumentsAndWindowsRoot(t *testing.T) {
	link, err := buildShellLink(shellLinkOptions{
		Target:     `C:\WINDOWS\system32\rundll32.exe`,
		Arguments:  `hnetwiz.dll,HomeNetWizardRunDll`,
		SystemRoot: `C:\WINDOWS`,
	})
	if err != nil {
		t.Fatal(err)
	}
	flags := binary.LittleEndian.Uint32(link[0x14:0x18])
	if flags&0x20 == 0 || flags&0x200 == 0 {
		t.Fatalf("link flags = %#x, want HasArguments and HasExpString", flags)
	}
	pos := shellLinkTargetDataEnd(link)
	pos = checkShellLinkString(t, link, pos, `C:\WINDOWS\system32`)
	pos = checkShellLinkString(t, link, pos, `hnetwiz.dll,HomeNetWizardRunDll`)
	checkShellLinkString(t, link, pos, `%SystemRoot%\system32\rundll32.exe`)
}

func TestBuildShellLinkSystemDriveTarget(t *testing.T) {
	link, err := buildShellLink(shellLinkOptions{
		Target:     `C:\Program Files\Windows NT\Accessories\wordpad.exe`,
		SystemRoot: `C:\WINDOWS`,
	})
	if err != nil {
		t.Fatal(err)
	}
	flags := binary.LittleEndian.Uint32(link[0x14:0x18])
	if flags&0x200 == 0 {
		t.Fatalf("link flags = %#x, want HasExpString", flags)
	}
	if flags&0x00000003 != 0x00000003 {
		t.Fatalf("link flags = %#x, want ID list and LinkInfo fallbacks", flags)
	}
	block := link[len(link)-0x318 : len(link)-4]
	if got, want := binary.LittleEndian.Uint32(block[4:8]), uint32(0xa0000001); got != want {
		t.Fatalf("environment block signature = %#x, want %#x", got, want)
	}
	if got, want := string(block[8:8+62]), `%SystemDrive%\Program Files\Windows NT\Accessories\wordpad.exe`; got != want {
		t.Fatalf("environment target = %q, want %q", got, want)
	}
}

func TestBuildShellLinkUsesFATShortTargetMetadata(t *testing.T) {
	shortTarget := `C:\PROGRA~1\WINDOW~2\ACCESS~1\WORDPAD.EXE`
	link, err := buildShellLink(shellLinkOptions{
		Target:      `C:\Program Files\Windows NT\Accessories\wordpad.exe`,
		ShortTarget: shortTarget,
		SystemRoot:  `C:\WINDOWS`,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range []string{"PROGRA~1", "WINDOW~2", "ACCESS~1", "WORDPAD.EXE"} {
		if !bytes.Contains(link, append([]byte(component), 0)) {
			t.Fatalf("link does not contain short-name component %q", component)
		}
	}
	if !bytes.Contains(link, append([]byte(shortTarget), 0)) {
		t.Fatalf("LinkInfo does not contain short target %q", shortTarget)
	}
}

func TestBuildShellLinkLiteralTargetKeepsIDListAndLinkInfo(t *testing.T) {
	link, err := buildShellLink(shellLinkOptions{
		Target:     `D:\Tools\viewer.exe`,
		SystemRoot: `C:\WINDOWS`,
	})
	if err != nil {
		t.Fatal(err)
	}
	flags := binary.LittleEndian.Uint32(link[0x14:0x18])
	if flags&0x00000003 != 0x00000003 {
		t.Fatalf("link flags = %#x, literal target must include an ID list and LinkInfo", flags)
	}
	if flags&(0x00000200|0x02000000) != 0 {
		t.Fatalf("link flags = %#x, literal target must not prefer an environment path", flags)
	}
}

func checkShellLinkString(t *testing.T, link []byte, pos int, want string) int {
	t.Helper()
	chars := int(binary.LittleEndian.Uint16(link[pos : pos+2]))
	pos += 2
	gotChars := make([]uint16, chars)
	for i := 0; i < chars; i++ {
		gotChars[i] = binary.LittleEndian.Uint16(link[pos+i*2 : pos+i*2+2])
	}
	wantChars := utf16.Encode([]rune(want))
	if len(gotChars) != len(wantChars) {
		t.Fatalf("string %q encoded length = %d, want %d", want, len(gotChars), len(wantChars))
	}
	for i := range wantChars {
		if gotChars[i] != wantChars[i] {
			t.Fatalf("string %q char %d = %#x, want %#x", want, i, gotChars[i], wantChars[i])
		}
	}
	return pos + chars*2
}

func shellLinkTargetDataEnd(link []byte) int {
	flags := binary.LittleEndian.Uint32(link[0x14:0x18])
	pos := 0x4c
	if flags&0x00000001 != 0 {
		pos += 2 + int(binary.LittleEndian.Uint16(link[pos:pos+2]))
	}
	if flags&0x00000002 != 0 {
		pos += int(binary.LittleEndian.Uint32(link[pos : pos+4]))
	}
	return pos
}

func decodeUTF16Z(data []byte) string {
	chars := make([]uint16, 0, len(data)/2)
	for len(data) >= 2 {
		char := binary.LittleEndian.Uint16(data[:2])
		data = data[2:]
		if char == 0 {
			break
		}
		chars = append(chars, char)
	}
	return string(utf16.Decode(chars))
}
