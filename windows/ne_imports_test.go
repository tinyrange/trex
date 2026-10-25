package windows

import (
	"encoding/binary"
	"testing"

	"go.starlark.net/starlark"
)

func neImportFixture() []byte {
	data := neExportFixture()
	put := func(at int, value uint16) { binary.LittleEndian.PutUint16(data[at:], value) }
	put(64+0x1e, 1)
	put(64+0x28, 116)
	put(64+0x2a, 118)
	put(180, 1)
	copy(data[182:], []byte{0, 6, 'D', 'I', 'B', 'E', 'N', 'G', 10, 'D', 'I', 'B', '_', 'O', 'U', 'T', 'P', 'U', 'T'})
	put(132, 0x100)
	put(768, 2)
	copy(data[770:], []byte{3, 2, 4, 0, 1, 0, 8, 0, 5, 5, 9, 0, 1, 0, 5, 0})
	return data
}

func TestWindowsNEImportsPreserveNamesAndRelocationHeads(t *testing.T) {
	data := neImportFixture()
	imports, err := parseWindowsNEImports(data, 2)
	if err != nil || len(imports) != 2 {
		t.Fatalf("imports = %+v, %v", imports, err)
	}
	if got := imports[0]; got.Module != "DIBENG" || got.Name != "DIB_OUTPUT" || got.Ordinal != 0 || got.Segment != 1 || got.Offset != 4 || got.Source != 3 || got.Additive {
		t.Fatalf("named import = %+v", got)
	}
	if got := imports[1]; got.Name != "" || got.Ordinal != 5 || !got.Additive || got.Offset != 9 {
		t.Fatalf("ordinal import = %+v", got)
	}
	value, err := windowsNEImportsBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(data)}, nil)
	if err != nil || value.(*starlark.List).Len() != 2 {
		t.Fatalf("Starlark imports = %v, %v", value, err)
	}
	if _, err := parseWindowsNEImports(data, 1); err == nil {
		t.Fatal("import bound ignored")
	}
}

func TestWindowsNEImportsRejectMalformedRelocations(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"module-table": func(b []byte) { binary.LittleEndian.PutUint16(b[64+0x28:], 0xffff) },
		"name-table":   func(b []byte) { binary.LittleEndian.PutUint16(b[64+0x2a:], 0xffff) },
		"module-name":  func(b []byte) { b[183] = 255 },
		"function":     func(b []byte) { binary.LittleEndian.PutUint16(b[776:], 0xffff) },
		"module-index": func(b []byte) { b[774] = 2 },
		"source":       func(b []byte) { binary.LittleEndian.PutUint16(b[772:], 256) },
		"source-width": func(b []byte) { binary.LittleEndian.PutUint16(b[772:], 253) },
		"iterated":     func(b []byte) { binary.LittleEndian.PutUint16(b[132:], 0x108) },
		"count":        func(b []byte) { binary.LittleEndian.PutUint16(b[768:], 65535) },
	} {
		t.Run(name, func(t *testing.T) {
			data := neImportFixture()
			mutate(data)
			if _, err := parseWindowsNEImports(data, 4096); err == nil {
				t.Fatal("malformed image accepted")
			}
		})
	}
}
