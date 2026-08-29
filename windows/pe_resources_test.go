package windows

import (
	"debug/pe"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
	"unicode/utf16"

	"go.starlark.net/starlark"
	"golang.org/x/arch/x86/x86asm"
)

func TestPEStringResources(t *testing.T) {
	var data []byte
	for _, value := range []string{"Network Connections", "Connects to other computers"} {
		units := utf16.Encode([]rune(value))
		entry := make([]byte, 2+len(units)*2)
		binary.LittleEndian.PutUint16(entry, uint16(len(units)))
		for index, unit := range units {
			binary.LittleEndian.PutUint16(entry[2+index*2:], unit)
		}
		data = append(data, entry...)
	}
	for index := 2; index < 16; index++ {
		data = append(data, 0, 0)
	}
	stringsByID := peStringResources([]peResource{{typ: "#6", name: "#76", data: data}})
	if got, want := stringsByID[1200], "Network Connections"; got != want {
		t.Fatalf("string 1200 = %q, want %q", got, want)
	}
	if got, want := stringsByID[1201], "Connects to other computers"; got != want {
		t.Fatalf("string 1201 = %q, want %q", got, want)
	}
}

func TestParsePEFixedVersion(t *testing.T) {
	key := utf16.Encode([]rune("VS_VERSION_INFO"))
	valueOffset := (6 + (len(key)+1)*2 + 3) &^ 3
	data := make([]byte, valueOffset+52)
	binary.LittleEndian.PutUint16(data[0:2], uint16(len(data)))
	binary.LittleEndian.PutUint16(data[2:4], 52)
	for index, unit := range key {
		binary.LittleEndian.PutUint16(data[6+index*2:], unit)
	}
	binary.LittleEndian.PutUint32(data[valueOffset:valueOffset+4], 0xfeef04bd)
	binary.LittleEndian.PutUint32(data[valueOffset+4:valueOffset+8], 0x00010000)
	binary.LittleEndian.PutUint32(data[valueOffset+8:valueOffset+12], 6<<16)
	binary.LittleEndian.PutUint32(data[valueOffset+12:valueOffset+16], 8447<<16)
	binary.LittleEndian.PutUint32(data[valueOffset+16:valueOffset+20], 1<<16|13)
	binary.LittleEndian.PutUint32(data[valueOffset+20:valueOffset+24], 2<<16|7)
	binary.LittleEndian.PutUint32(data[valueOffset+24:valueOffset+28], 0x3f)
	binary.LittleEndian.PutUint32(data[valueOffset+28:valueOffset+32], 0x2)
	binary.LittleEndian.PutUint32(data[valueOffset+32:valueOffset+36], 0x00040004)
	binary.LittleEndian.PutUint32(data[valueOffset+36:valueOffset+40], 0x2)

	version, ok := parsePEFixedVersion(data)
	if !ok {
		t.Fatal("parsePEFixedVersion rejected a valid VS_VERSION_INFO")
	}
	if got, want := version.file, [4]uint16{6, 0, 8447, 0}; got != want {
		t.Fatalf("file version = %v, want %v", got, want)
	}
	if got, want := version.product, [4]uint16{1, 13, 2, 7}; got != want {
		t.Fatalf("product version = %v, want %v", got, want)
	}
	if version.flagsMask != 0x3f || version.flags != 0x2 || version.os != 0x00040004 || version.fileType != 0x2 {
		t.Fatalf("fixed metadata = %#v", version)
	}

	data[6] = 'X'
	if _, ok := parsePEFixedVersion(data); ok {
		t.Fatal("parsePEFixedVersion accepted the wrong version-info key")
	}
}

func TestPEVersionReturnsNoneForNonPEFile(t *testing.T) {
	value, err := peVersionBuiltin(nil, nil, starlark.Tuple{
		&starfile.Bytes{Name: "readme.txt", Data: []byte("not a PE image")},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if value != starlark.None {
		t.Fatalf("pe version = %v, want None", value)
	}
}

func TestUpdatePEChecksum(t *testing.T) {
	data := make([]byte, 513)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:0x40], 0x80)
	copy(data[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(data[0x80+4+20:], 0x10b)
	for offset := 0x120; offset < len(data); offset++ {
		data[offset] = byte(offset*37 + 11)
	}

	if err := updatePEChecksum(data); err != nil {
		t.Fatal(err)
	}
	checksumOffset := 0x80 + 4 + 20 + 64
	first := binary.LittleEndian.Uint32(data[checksumOffset : checksumOffset+4])
	if first == 0 {
		t.Fatal("checksum was not populated")
	}
	if err := updatePEChecksum(data); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(data[checksumOffset : checksumOffset+4]); got != first {
		t.Fatalf("checksum is not stable: %#x then %#x", first, got)
	}
	data[len(data)-1] ^= 0x5a
	if err := updatePEChecksum(data); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(data[checksumOffset : checksumOffset+4]); got == first {
		t.Fatalf("checksum did not change after payload mutation: %#x", got)
	}
}

func TestPEMessageResources(t *testing.T) {
	ascii := []byte("first message\r\n\x00")
	unicodeText := utf16.Encode([]rune("second message\r\n\x00"))
	unicodeData := make([]byte, len(unicodeText)*2)
	for index, unit := range unicodeText {
		binary.LittleEndian.PutUint16(unicodeData[index*2:], unit)
	}
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:], 1)
	binary.LittleEndian.PutUint32(data[4:], 0x825a0066)
	binary.LittleEndian.PutUint32(data[8:], 0x825a0067)
	binary.LittleEndian.PutUint32(data[12:], 16)
	appendEntry := func(flags uint16, payload []byte) {
		entry := make([]byte, 4+len(payload))
		binary.LittleEndian.PutUint16(entry[0:], uint16(len(entry)))
		binary.LittleEndian.PutUint16(entry[2:], flags)
		copy(entry[4:], payload)
		data = append(data, entry...)
	}
	appendEntry(0, ascii)
	appendEntry(1, unicodeData)

	messages, err := peMessageResources([]peResource{{typ: "#11", name: "#1", lang: "#1033", data: data}})
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 {
		t.Fatalf("messages = %#v, want two entries", messages)
	}
	if got, want := messages[0].id, uint32(0x825a0066); got != want {
		t.Fatalf("first id = %#x, want %#x", got, want)
	}
	if got, want := messages[0].text, "first message\r\n"; got != want {
		t.Fatalf("first text = %q, want %q", got, want)
	}
	if messages[0].unicode {
		t.Fatal("first message unexpectedly marked Unicode")
	}
	if got, want := messages[1].text, "second message\r\n"; got != want {
		t.Fatalf("second text = %q, want %q", got, want)
	}
	if !messages[1].unicode {
		t.Fatal("second message not marked Unicode")
	}
}

func TestPEMessageResourcesRejectsInvalidEntry(t *testing.T) {
	data := make([]byte, 20)
	binary.LittleEndian.PutUint32(data[0:], 1)
	binary.LittleEndian.PutUint32(data[4:], 1)
	binary.LittleEndian.PutUint32(data[8:], 1)
	binary.LittleEndian.PutUint32(data[12:], 16)
	binary.LittleEndian.PutUint16(data[16:], 3)
	if _, err := peMessageResources([]peResource{{typ: "#11", data: data}}); err == nil {
		t.Fatal("invalid message entry was accepted")
	}
}

func TestRGSReplacementResourceID(t *testing.T) {
	const slot = uint32(0x76476b64)
	code := []byte{
		0x68, 0xb0, 0x04, 0x00, 0x00,
		0xe8, 0x12, 0x34, 0x56, 0x78,
		0x68, 0xb1, 0x04, 0x00, 0x00,
		0xa3, 0x64, 0x6b, 0x47, 0x76,
	}
	id, ok := rgsReplacementResourceID(code, slot, map[uint32]string{1200: "Network Connections", 1201: "Info tip"})
	if !ok || id != 1200 {
		t.Fatalf("resource ID = %d, %t; want 1200, true", id, ok)
	}
}

func TestRGSPlaceholders(t *testing.T) {
	got := rgsPlaceholders(`'%First%' '%Second%' '%first%'`)
	want := []string{"First", "Second"}
	if len(got) != len(want) {
		t.Fatalf("placeholders = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("placeholder %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestRGSParserExpandsRegistrationMap(t *testing.T) {
	parser := rgsParser{
		tokens: rgsTokenize(`HKCR { NoRemove CLSID { ForceRemove %CLSID% = s 'Example' { InprocServer32 = s '%MODULE%' } } }`),
		module: `C:\WINDOWS\system32\example.dll`,
		replacements: map[string]string{
			"CLSID": "{00000000-0000-0000-0000-000000000001}",
		},
	}
	patches, err := parser.parse()
	if err != nil {
		t.Fatal(err)
	}
	if len(patches) != 2 {
		t.Fatalf("patches = %#v, want 2", patches)
	}
	if got := patches[0].key; got != "/Classes/CLSID/{00000000-0000-0000-0000-000000000001}" {
		t.Fatalf("CLSID key = %q", got)
	}
	if got, _ := starlark.AsString(patches[1].value); got != `C:\WINDOWS\system32\example.dll` {
		t.Fatalf("module value = %q", got)
	}
}

func TestRGSParserSkipsUnresolvedRegistrationMapKeys(t *testing.T) {
	parser := rgsParser{tokens: rgsTokenize(`HKCR { CLSID { %UNKNOWN% = s 'ignored' } }`)}
	patches, err := parser.parse()
	if err != nil {
		t.Fatal(err)
	}
	if len(patches) != 0 {
		t.Fatalf("patches = %#v, want none", patches)
	}
}

func TestRGSParserExpandsModuleAliases(t *testing.T) {
	parser := rgsParser{
		tokens: rgsTokenize(`HKCR { Example { val ThisDLL = s '%THISDLL%' val ModulePath = s '%_SYS_MOD_PATH%' val ModuleDir = s '%_SYS_MOD_DIR%' } }`),
		module: `C:/WINDOWS/system32/example.dll`,
	}
	patches, err := parser.parse()
	if err != nil {
		t.Fatal(err)
	}
	if len(patches) != 3 {
		t.Fatalf("patches = %#v, want 3", patches)
	}
	want := []string{
		`C:\WINDOWS\system32\example.dll`,
		`C:\WINDOWS\system32\example.dll`,
		`C:\WINDOWS\system32`,
	}
	for index, patch := range patches {
		got, _ := starlark.AsString(patch.value)
		if got != want[index] {
			t.Fatalf("patch %d value = %q, want %q", index, got, want[index])
		}
	}
}

func TestPEDisasmOperandsAreStructured(t *testing.T) {
	relative, err := peDisasmOperand(x86asm.Rel(-5), 0x1200, 5)
	if err != nil {
		t.Fatal(err)
	}
	if got := testDictUint(t, relative, "target"); got != 0x1200 {
		t.Fatalf("relative target = %#x, want %#x", got, uint64(0x1200))
	}

	memory, err := peDisasmOperand(x86asm.Mem{Segment: x86asm.FS, Base: x86asm.EAX, Index: x86asm.ECX, Scale: 4, Disp: -8}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"kind": "memory", "segment": "fs", "base": "eax", "index": "ecx"} {
		value, found, err := memory.Get(starlark.String(name))
		if err != nil || !found {
			t.Fatalf("missing %s: %v", name, err)
		}
		if got, _ := starlark.AsString(value); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestPEDisasmSupportsAMD64(t *testing.T) {
	mode, err := peDisasmMode(pe.IMAGE_FILE_MACHINE_AMD64)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := decodeX86Instruction([]byte{0x48, 0x89, 0xe5}, mode)
	if err != nil {
		t.Fatal(err)
	}
	if mode != 64 || inst.Len != 3 || inst.Op != x86asm.MOV {
		t.Fatalf("mode = %d, instruction = %v", mode, inst)
	}
}

func testDictUint(t *testing.T, dictionary *starlark.Dict, name string) uint64 {
	t.Helper()
	value, found, err := dictionary.Get(starlark.String(name))
	if err != nil || !found {
		t.Fatalf("missing %s: %v", name, err)
	}
	integer, ok := value.(starlark.Int)
	if !ok {
		t.Fatalf("%s = %s, want int", name, value.Type())
	}
	result, ok := integer.Uint64()
	if !ok {
		t.Fatalf("%s = %s, want unsigned int", name, integer)
	}
	return result
}
