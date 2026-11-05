package windows

import (
	"encoding/binary"
	"testing"

	"go.starlark.net/starlark"
)

func neExportFixture() []byte {
	data := make([]byte, 1024)
	put := func(offset int, value uint16) { binary.LittleEndian.PutUint16(data[offset:], value) }
	put(0, 0x5a4d)
	binary.LittleEndian.PutUint32(data[0x3c:], 64)
	put(64, 0x454e)
	put(64+4, 160)
	put(64+6, 22)
	put(64+0x1c, 2)
	put(64+0x20, 8)
	put(64+0x22, 64)
	put(64+0x24, 80)
	put(64+0x26, 80)
	binary.LittleEndian.PutUint32(data[64+0x2c:], 320)
	put(64+0x32, 4)
	put(128, 32)
	put(130, 256)
	put(134, 256)
	put(138, 128)
	put(142, 128)
	copy(data[144:], []byte{5, 'F', 'I', 'X', 'E', 'D', 1, 0, 0})
	copy(data[320:], []byte{4, 'M', 'O', 'V', 'E', 3, 0, 0})
	// Fixed ordinal 1, absent ordinal 2, movable ordinal 3, constant 4.
	copy(data[224:], []byte{1, 1, 3, 7, 0, 1, 0, 1, 255, 1, 0xcd, 0x3f, 1, 9, 0, 1, 254, 1, 0x34, 0x12, 0})
	return data
}

func TestWindowsNEExportsPreserveOrdinalsAndStorage(t *testing.T) {
	data := neExportFixture()
	exports, err := parseWindowsNEExports(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(exports) != 3 || exports[0].Ordinal != 1 || exports[1].Ordinal != 3 || exports[2].Ordinal != 4 {
		t.Fatalf("exports = %+v", exports)
	}
	if e := exports[0]; e.FileOffset != 519 || e.Available != 249 || e.Movable || len(e.Names) != 1 || e.Names[0] != "FIXED" {
		t.Fatalf("fixed = %+v", e)
	}
	if e := exports[1]; e.FileOffset != 521 || !e.Movable || len(e.Names) != 1 || e.Names[0] != "MOVE" {
		t.Fatalf("movable = %+v", e)
	}
	if e := exports[2]; !e.Constant || e.Offset != 0x1234 || e.FileOffset != -1 || e.Segment != 0 {
		t.Fatalf("constant = %+v", e)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint16(b[128:], 0) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[132:], 8) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[130:], 4) },
	} {
		copyData := append([]byte(nil), data...)
		mutate(copyData)
		got, err := parseWindowsNEExports(copyData)
		if err != nil || got[0].FileOffset != -1 || got[0].Available != 0 {
			t.Fatalf("unbacked entry = %+v, %v", got, err)
		}
	}
	value, err := windowsNEExportsBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(data)}, nil)
	if err != nil || value.(*starlark.List).Len() != 3 {
		t.Fatalf("Starlark exports = %v, %v", value, err)
	}
}

func TestWindowsNEExportsRejectMalformedTables(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"entry-range": func(b []byte) { binary.LittleEndian.PutUint16(b[64+4:], 0xffff) },
		"bundle":      func(b []byte) { b[224] = 255 },
		"segment":     func(b []byte) { b[225] = 3 },
		"storage":     func(b []byte) { binary.LittleEndian.PutUint16(b[128:], 64) },
		"name":        func(b []byte) { b[320] = 255 },
		"termination": func(b []byte) { binary.LittleEndian.PutUint16(b[64+6:], 20) },
	} {
		t.Run(name, func(t *testing.T) {
			data := neExportFixture()
			mutate(data)
			if _, err := parseWindowsNEExports(data); err == nil {
				t.Fatal("malformed image accepted")
			}
		})
	}
}
