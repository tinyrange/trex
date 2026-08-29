package windows

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"

	"go.starlark.net/starlark"
)

func TestWindowsNEFastBootPlacesPreloadAndOverlaySegments(t *testing.T) {
	data := make([]byte, 194)
	binary.LittleEndian.PutUint16(data, 0x5a4d)
	binary.LittleEndian.PutUint32(data[0x3c:], 64)
	ne := 64
	binary.LittleEndian.PutUint16(data[ne:], 0x454e)
	binary.LittleEndian.PutUint16(data[ne+0x1c:], 2)
	binary.LittleEndian.PutUint16(data[ne+0x20:], 1)
	binary.LittleEndian.PutUint16(data[ne+0x22:], 64)
	binary.LittleEndian.PutUint16(data[ne+0x24:], 80)
	binary.LittleEndian.PutUint16(data[ne+0x26:], 80)
	binary.LittleEndian.PutUint32(data[ne+0x2c:], 160)
	binary.LittleEndian.PutUint16(data[ne+0x32:], 4)
	segmentTable := ne + 64
	binary.LittleEndian.PutUint16(data[segmentTable:], 11)
	binary.LittleEndian.PutUint16(data[segmentTable+2:], 3)
	binary.LittleEndian.PutUint16(data[segmentTable+4:], 0x40)
	binary.LittleEndian.PutUint16(data[segmentTable+6:], 5)
	binary.LittleEndian.PutUint16(data[segmentTable+8:], 12)
	binary.LittleEndian.PutUint16(data[segmentTable+10:], 2)
	binary.LittleEndian.PutUint16(data[segmentTable+14:], 2)
	data[160] = 0
	copy(data[176:], []byte{0xaa, 0xbb, 0xcc})
	copy(data[192:], []byte{0xdd, 0xee})

	module, err := parseWindowsNEModule(data)
	if err != nil {
		t.Fatal(err)
	}
	binImage, overlay, err := buildWindowsNEFastBoot([]windowsNEModule{module}, "X", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(binImage[ne+0x32:]); got != 4 {
		t.Fatalf("alignment shift = %d", got)
	}
	if got := binary.LittleEndian.Uint32(binImage[ne+0x2c:]); got != 1 {
		t.Fatalf("nonresident table paragraph = %d", got)
	}
	if got := binary.LittleEndian.Uint16(binImage[segmentTable:]); got != 10 {
		t.Fatalf("preload segment paragraph = %d", got)
	}
	if got := binary.LittleEndian.Uint16(binImage[segmentTable+8:]); got != 2 {
		t.Fatalf("overlay segment paragraph = %d", got)
	}
	if got := binary.LittleEndian.Uint32(binImage[ne+8:]); got != 11 {
		t.Fatalf("terminator paragraph = %d", got)
	}
	if got := binImage[160:163]; string(got) != string([]byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("preload segment = %x", got)
	}
	if got := overlay[32:34]; string(got) != string([]byte{0xdd, 0xee}) {
		t.Fatalf("overlay segment = %x", got)
	}
}

func TestWindowsSetverAddsVersionEntry(t *testing.T) {
	data := []byte{0xff, 0xff}
	for _, entry := range []struct {
		name         string
		major, minor byte
	}{{"ONE.EXE", 3, 30}, {"TWO.EXE", 3, 30}, {"THREE.EXE", 4, 0}, {"WIN200.BIN", 3, 40}} {
		data = append(data, byte(len(entry.name)))
		data = append(data, entry.name...)
		data = append(data, entry.major, entry.minor)
	}
	data = append(data, make([]byte, 32)...)
	source := &starfile.Bytes{Name: "SETVER.EXE", Data: data}
	value, err := windowsSetverBuiltin(nil, nil, starlark.Tuple{
		source, starlark.String("WIN100.BIN"), starlark.MakeInt(3), starlark.MakeInt(30),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	patched := value.(*starfile.Bytes).Data
	needle := []byte{10, 'W', 'I', 'N', '1', '0', '0', '.', 'B', 'I', 'N', 3, 30, 0}
	if len(patched) != len(data) || !containsBytes(patched, needle) {
		t.Fatalf("patched SETVER table does not contain WIN100.BIN 3.30: %x", patched)
	}
}

func containsBytes(data, needle []byte) bool {
	for offset := 0; offset+len(needle) <= len(data); offset++ {
		if string(data[offset:offset+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
