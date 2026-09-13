package msdelta

import (
	"bytes"
	"testing"
)

func TestCLIMethodMarkingLeavesExceptionDataAndFinalRowUnclaimed(t *testing.T) {
	source, m := makeTestCLIImage(t)
	m.Rows[6] = 2
	put32(source, m.tableOffsets[6]+m.rowSizes[6], 0x1350)
	put16(source, 0x500, 0x300b) // fat header with trailing exception sections
	put32(source, 0x504, 6)
	source[0x550] = 6<<2 | 2
	for _, off := range []int{0x50c, 0x520, 0x551} {
		source[off] = 0xe8
		put32(source, off+1, uint32(0x580-off-5))
	}
	pe, err := parsePELayout(source)
	if err != nil {
		t.Fatal(err)
	}
	pe.machine = 0x14c
	pe.imageSize = 0x2000
	pe.sections[0].characteristics = 0x60000020
	marker := make([]byte, len(source))
	if err := markCLIMethodBodies(marker, source, pe, m); err != nil {
		t.Fatal(err)
	}
	for i, got := range marker {
		want := byte(0)
		if i >= 0x500 && i < 0x512 {
			want = 3
		}
		if got != want {
			t.Fatalf("marker at %#x = %d, want %d", i, got, want)
		}
	}
	rift := riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1380, target: 0x1390}}}
	for _, mark := range []bool{false, true} {
		data := bytes.Clone(source)
		flags := peTransformCallsX86
		if mark {
			flags |= peTransformMarkCode
		}
		if err := transformPESourceTraced(data, pe, rift, flags, peRestore{}, nil, m); err != nil {
			t.Fatal(err)
		}
		for _, off := range []int{0x50c, 0x520, 0x551} {
			want := get32(source, off+1) + 0x10
			if mark && off == 0x50c {
				want -= 0x10
			}
			if got := get32(data, off+1); got != want {
				t.Fatalf("MARK=%t CALL at %#x = %#x, want %#x", mark, off, got, want)
			}
		}
	}
}

func TestCLIInstructionTokensAndOperandBoundaries(t *testing.T) {
	source := []byte{
		0x20, 0x72, 1, 0, 0x70, // ldc.i4 containing token-looking bytes
		0x45, 1, 0, 0, 0, 0x28, 1, 0, 6, // switch displacement, not a token
		0x72, 1, 0, 0, 0x70, // ldstr
		0xfe, 0x16, 1, 0, 0, 1, // constrained. TypeRef
		0x28, 1, 0, 0, 6, // call MethodDef
		0x29, 1, 0, 0, 0x11, // calli StandAloneSig
		0x2a,
	}
	target := &CLIPreprocessInfo{}
	target.HeapMaps[1] = []PERiftEntry{{Source: 1, Target: 3}}
	target.TableMaps[1] = []PERiftEntry{{Source: 1, Target: 4}}
	target.TableMaps[6] = []PERiftEntry{{Source: 1, Target: 5}}
	target.TableMaps[17] = []PERiftEntry{{Source: 1, Target: 6}}
	r := newCLIRemap(target)
	want := bytes.Clone(source)
	want[15], want[21], want[26], want[31] = 3, 4, 5, 6
	dst := bytes.Clone(source)
	if err := transformCLIInstructions(dst, source, &r); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst, want) {
		t.Fatalf("got %x, want %x", dst, want)
	}
	for _, value := range []uint32{0, 0x06000000, 0x70000000, 0x71000001} {
		if got := r.token(value); got != value {
			t.Fatalf("null/reserved token %#x became %#x", value, got)
		}
	}
}

func TestCLIInstructionBounds(t *testing.T) {
	r := cliRemap{}
	for _, source := range [][]byte{
		{0xfe}, {0x72, 1, 0}, {0x45}, {0x45, 0xff, 0xff, 0xff, 0xff}, {0x21, 1}, {0xfe, 0x09, 1},
	} {
		if err := transformCLIInstructions(bytes.Clone(source), source, &r); err == nil {
			t.Fatalf("accepted truncated IL %x", source)
		}
	}
}

func TestCLIMethodTokensUseOriginalRVAAndSkipFinalAlias(t *testing.T) {
	source, m := makeTestCLIImage(t)
	put32(source, m.tableOffsets[6]+m.rowSizes[6], 0x1300)
	m.Rows[6] = 2
	source[0x500] = 6<<2 | 2
	copy(source[0x501:], []byte{0x72, 1, 0, 0, 0x70, 0x2a})
	target := &CLIPreprocessInfo{HeapMaps: [4][]PERiftEntry{1: {{Source: 1, Target: 2}}}}
	pe, err := parsePELayout(source)
	if err != nil {
		t.Fatal(err)
	}
	dst := bytes.Clone(source)
	put32(dst, m.tableOffsets[6], 0x1400) // already-normalized destination RVA
	if err := transformCLIMethodTokens(dst, source, pe, m, target); err != nil {
		t.Fatal(err)
	}
	if get32(dst, 0x502) != 0x70000002 || get32(source, 0x502) != 0x70000001 {
		t.Fatal("final alias was visited or immutable source changed")
	}
}

func TestCLIMethodTokensVisitSharedBodiesForEachNonfinalRow(t *testing.T) {
	source, m := makeTestCLIImage(t)
	m.Rows[6] = 3
	for row := 1; row < 3; row++ {
		put32(source, m.tableOffsets[6]+row*m.rowSizes[6], 0x1300)
	}
	source[0x500] = 6<<2 | 2
	copy(source[0x501:], []byte{0x28, 4, 1, 0, 6, 0x2a})
	target := &CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{6: {{Source: 0, Target: 0}, {Source: 260, Target: 261}}}}
	pe, err := parsePELayout(source)
	if err != nil {
		t.Fatal(err)
	}
	dst := bytes.Clone(source)
	put32(dst, m.tableOffsets[6], 0x1400)
	if err := transformCLIMethodTokens(dst, source, pe, m, target); err != nil {
		t.Fatal(err)
	}
	// FileHistory's rows128/129 share body0x255c: token06000104 is
	// rewritten to06000105, then06000106. The final row still is skipped.
	if got := get32(dst, 0x502); got != 0x06000106 {
		t.Fatalf("shared body token = %#x", got)
	}
	if get32(source, 0x502) != 0x06000104 {
		t.Fatal("source token changed")
	}
}

func TestCLIMethodBodyBoundsAndFatHeader(t *testing.T) {
	source, _ := makeTestCLIImage(t)
	pe, _ := parsePELayout(source)
	put16(source, 0x500, 0x300b) // fat, extra sections
	put32(source, 0x504, 1)
	put32(source, 0x508, 0x11000001)
	source[0x50c] = 0x2a
	start, end, ok := cliMethodCode(source, pe, 0x1300)
	if !ok || start != 0x50c || end != 0x50d {
		t.Fatalf("fat code = %#x:%#x, %t", start, end, ok)
	}
	for _, change := range []struct {
		off   int
		value uint32
	}{{0x500, 0x2003}, {0x504, 0xffffffff}} {
		b := bytes.Clone(source)
		put32(b, change.off, change.value)
		if _, _, ok := cliMethodCode(b, pe, 0x1300); ok {
			t.Fatal("accepted malformed fat header")
		}
	}
	// Even if the image includes another section's bytes, a body cannot use
	// the virtual-only tail of its own section.
	pe.sections[0].rawSize = 0x301
	if _, _, ok := cliMethodCode(source, pe, 0x1300); ok {
		t.Fatal("fat body crossed raw section boundary")
	}
}

func TestCLIMethodTokensSkipFinalRowNotFinalPhysicalBody(t *testing.T) {
	source, m := makeTestCLIImage(t)
	m.Rows[6] = 2
	for _, off := range []int{0x500, 0x510} {
		source[off] = 6<<2 | 2
		copy(source[off+1:], []byte{0x28, 0x41, 0, 0, 0x0a, 0x2a})
	}
	pe, err := parsePELayout(source)
	if err != nil {
		t.Fatal(err)
	}
	target := &CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{10: {{Source: 0, Target: 0}, {Source: 47, Target: 75}}}}
	for _, order := range [][2]uint32{{0x1300, 0x1310}, {0x1310, 0x1300}} {
		put32(source, m.tableOffsets[6], order[0])
		put32(source, m.tableOffsets[6]+m.rowSizes[6], order[1])
		dst := bytes.Clone(source)
		if err := transformCLIMethodTokens(dst, source, pe, m, target); err != nil {
			t.Fatal(err)
		}
		for row, rva := range order {
			off := int(rva) - 0x1300 + 0x502
			want := uint32(0x0a000041)
			if row == 0 {
				want = 0x0a00005d
			}
			if got := get32(dst, off); got != want {
				t.Fatalf("order %x row%d: got%x want%x", order, row, got, want)
			}
		}
	}
}
