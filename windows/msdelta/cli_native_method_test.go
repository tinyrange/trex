package msdelta

import (
	"bytes"
	"testing"
)

func TestCLINativeMethodsUseHeaderOnlyEligibility(t *testing.T) {
	source, m := makeTestCLIImage(t)
	m.Rows[6] = 4
	for row, rva := range []uint32{0x1380, 0x1300, 0x1350, 0x1350} {
		off := m.tableOffsets[6] + row*m.rowSizes[6]
		put32(source, off, rva)
		put16(source, off+4, 0x85) // native, unmanaged, preserves signature
	}
	source[0x580] = 0x48 // ordinary native code: not a CLI header
	// Native RET imm16 happens to encode a tiny CLI header of 48 bytes.
	// NCServerPSProvider's MethodDef449 exposes the following JE operand as
	// the low byte of an apparent castclass TypeRef token.
	copy(source[0x500:], []byte{0xc2, 0, 0, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x48, 0x85, 0xc9, 0x74, 0x12, 0x48, 0x8b, 0x01})
	clear(source[0x514:0x531])
	source[0x530] = 0x72 // incomplete token at the end: retain earlier edits
	source[0x550] = 6<<2 | 2
	copy(source[0x551:], []byte{0x28, 1, 0, 0, 6, 0x2a})
	pe, err := parsePELayout(source)
	if err != nil {
		t.Fatal(err)
	}
	target := &CLIPreprocessInfo{}
	target.TableMaps[1] = []PERiftEntry{{Source: 0, Target: 0}, {Source: 0x8b4812, Target: 0x8b4813}}
	target.TableMaps[6] = []PERiftEntry{{Source: 1, Target: 2}}
	dst := bytes.Clone(source)
	if err := transformCLIMethodTokens(dst, source, pe, m, target); err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(source)
	want[0x510] = 0x13
	want[0x552] = 2 // next body still visited; final alias skipped
	if !bytes.Equal(dst, want) {
		t.Fatalf("native header enumeration: got %x / %x", dst[0x500:0x531], dst[0x550:0x557])
	}
	if source[0x510] != 0x12 {
		t.Fatal("source mutated")
	}
	marker := make([]byte, len(source))
	if err := markCLIMethodBodies(marker, source, pe, m); err != nil {
		t.Fatal(err)
	}
	for i, got := range marker {
		want := byte(0)
		if (i >= 0x500 && i < 0x531) || (i >= 0x550 && i < 0x557) {
			want = 3
		}
		if got != want {
			t.Fatalf("marker %#x = %d, want %d", i, got, want)
		}
	}
}
