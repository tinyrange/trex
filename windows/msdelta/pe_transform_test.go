package msdelta

import "testing"

func TestAMD64TransformWrapsRelativeTargetsBeforeRiftLookup(t *testing.T) {
	data := make([]byte, 0x100)
	layout := peLayout{machine: 0x8664,
		sections:    []peSection{{rawStart: 0x20, rawSize: 0xe0, rva: 0x20, virtualSize: 0xe0}},
		directories: [16]peDirectory{3: {rva: 0x80, size: 12}},
	}
	data[0x20] = 0xe8
	put32(data, 0x21, 0x8d4c0aef)
	put32(data, 0x80, 0x20)
	put32(data, 0x84, 0x25)
	rift := riftTable{entries: []riftEntry{
		{source: 0, target: 0},
		{source: 0x1000, target: 0x3000},
		{source: 0xc0000000, target: 0x80000000},
	}}
	transformDisasmX64(data, layout, rift, make([]byte, len(data)))
	if got := get32(data, 0x21); got != 0x8d4c2aef {
		t.Fatalf("high wrapped RVA used wrong segment: %#x", got)
	}
}

func TestImportNamesAreExcludedFromUnlistedPointerScan(t *testing.T) {
	data := make([]byte, 0x100)
	layout := peLayout{machine: 0x14c, imageBaseSize: 4, imageBase: 0x400000,
		imageSize: 0x20000, headerSize: 0x20,
		sections: []peSection{{rawStart: 0x20, rawSize: 0xe0, rva: 0x1000, virtualSize: 0xe0}},
	}
	put32(data, 0x20, 0x1020)
	put16(data, 0x40, 8)
	copy(data[0x42:], "VerLanguageNameA\x00")
	marker := make([]byte, len(data))
	rift := riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1000, target: 0x1100}}}
	walkImportThunks(data, layout, rift, 0x1000, false, true, 4, 1<<31, layout.imageBase, marker)
	for i := 0x40; i <= 0x52; i++ {
		if marker[i] != 3 {
			t.Fatalf("import name byte %#x has marker %d", i, marker[i])
		}
	}
	if marker[0x53] != 0 {
		t.Fatal("import name claimed alignment padding")
	}
	// The unaligned suffix "meA\\0" looks like VA 0x41656d. Keep
	// an identical unclaimed value as the positive pointer-scan control.
	put32(data, 0x70, 0x41656d)
	transformUnlistedPointersX86(data, layout, rift, uint32(layout.imageBase), marker)
	if got := get32(data, 0x4f); got != 0x41656d {
		t.Fatalf("import name changed to %#x", got)
	}
	if got := get32(data, 0x70); got != 0x41666d {
		t.Fatalf("unclaimed pointer control = %#x", got)
	}
}

func TestE8TargetRestorationIncludesFinalCompleteOperand(t *testing.T) {
	for remaining := 1; remaining <= 11; remaining++ {
		data := makeTestPE32(0x10000000, 0, 0)
		position := len(data) - remaining
		data[position] = 0xe8
		if remaining >= 5 {
			put32(data, position+1, uint32(position))
		}
		before := append([]byte(nil), data...)
		restoreX86E8(data)
		if remaining >= 5 {
			if got := get32(data, position+1); got != 0 {
				t.Fatalf("%d bytes remaining: operand = %#x", remaining, got)
			}
		} else {
			for i := position; i < len(data); i++ {
				if data[i] != before[i] {
					t.Fatalf("incomplete operand changed at %d", i)
				}
			}
		}
	}
}

func TestE8TargetRestorationIncludesILOnlyMetadataImages(t *testing.T) {
	for _, flags := range []uint32{0, 1, 9} {
		data, _ := makeTestCLIImage(t)
		put16(data, 0x40+4, 0x14c)
		put32(data, 0x210, flags)
		// E8 target restoration is a whole-buffer filter, even when the
		// containing section is non-executable metadata and CorFlags is ILONLY.
		data[0x400] = 0xe8
		put32(data, 0x401, 0x400)
		data[0x410] = 0xe8
		put32(data, 0x411, 0xfffffff0)
		restoreX86E8(data)
		if got := get32(data, 0x401); got != 0 {
			t.Fatalf("CorFlags %#x: positive E8 operand = %#x", flags, got)
		}
		if got := get32(data, 0x411); got != uint32(len(data)-16) {
			t.Fatalf("CorFlags %#x: negative E8 operand = %#x", flags, got)
		}
	}
}

func TestDirectoryMarkingIgnoresVirtualPaddingFileCoordinates(t *testing.T) {
	layout := peLayout{headerSize: 0x100,
		sections: []peSection{
			{rawStart: 0x100, rawSize: 0x100, rva: 0x100, virtualSize: 0x100},
			{rawStart: 0, rawSize: 0, rva: 0x200, virtualSize: 0xe00},
			{rawStart: 0x200, rawSize: 0x200, rva: 0x1000, virtualSize: 0x200, characteristics: 0x60000020},
		},
		directories: [16]peDirectory{4: {rva: 0x400, size: 0x80}},
	}
	marker := make([]byte, 0x480)
	markPEDirectories(marker, layout)
	// Security's numeric address falls in virtual Pad1. Giving Pad1 a false
	// raw origin at zero would claim the executable bytes at 0x200 instead.
	for _, b := range marker[0x200:0x400] {
		if b != 0 {
			t.Fatal("virtual-only padding redirected a directory mark into code")
		}
	}
}

func TestDirectoryMarkingUsesDeltaSecurityCoordinates(t *testing.T) {
	data := make([]byte, 0xa80)
	layout := peLayout{machine: 0x8664, headerSize: 0x200, imageSize: 0x3000,
		sections: []peSection{
			{rawStart: 0x200, rawSize: 0x600, rva: 0x800, virtualSize: 0x600, characteristics: 0x60000020},
			{rawStart: 0x800, rawSize: 0x200, rva: 0x2000, virtualSize: 0x200},
		},
		directories: [16]peDirectory{3: {rva: 0x2000, size: 24}, 4: {rva: 0xa00, size: 0x80}},
	}
	// The actual certificate is at file offset 0xa00, but delta MARK treats
	// that directory address as RVA 0xa00, claiming file bytes 0x400:0x480.
	for i, rva := range []uint32{0xa00, 0xb00} {
		put32(data, 0x800+i*12, rva)
		put32(data, 0x804+i*12, rva+5)
		off := 0x400 + i*0x100
		data[off] = 0xe8
		put32(data, off+1, 0x1b)
	}
	rift := riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0xa20, target: 0xa30}, {source: 0xb00, target: 0xb00}, {source: 0xb20, target: 0xb40}}}
	transformPESource(data, layout, rift, peTransformMarkCode|peTransformDisasmX64, peRestore{})
	if get32(data, 0x401) != 0x1b || get32(data, 0x501) != 0x3b {
		t.Fatalf("marked/control operands = %#x/%#x", get32(data, 0x401), get32(data, 0x501))
	}
	marker := make([]byte, len(data))
	markPEDirectories(marker, layout)
	if marker[0x400] != 3 || marker[0x47f] != 3 || marker[0x480] != 0 || marker[0xa00] != 0 {
		t.Fatal("directory marking did not preserve exact delta-coordinate extent")
	}
}

func TestNativeX86BranchScanIsNotDisabledByCorFlags(t *testing.T) {
	for _, corFlags := range []uint32{0, 2, 1, 9} {
		data := make([]byte, 0x180)
		layout := testX86TransformLayout()
		layout.directories[14] = peDirectory{rva: 0x10e0, size: 72}
		put32(data, 0x110, corFlags)
		// With MARK disabled, CorFlags alone does not claim these bytes.
		data[0x20], data[0x30] = 0xe8, 0xe9
		put32(data, 0x21, 0x1b)
		put32(data, 0x31, 0x8b)
		rift := riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1020, target: 0x1030}}}
		transformPESource(data, layout, rift, peTransformCallsX86|peTransformJmpsX86, peRestore{})
		wantCall, wantJump := uint32(0x2b), uint32(0x9b)
		if get32(data, 0x21) != wantCall || get32(data, 0x31) != wantJump {
			t.Fatalf("CorFlags %#x: CALL/JMP = %#x/%#x, want %#x/%#x", corFlags, get32(data, 0x21), get32(data, 0x31), wantCall, wantJump)
		}
	}
}

func TestHIGHLOWRelocationUses32BitAddressDomain(t *testing.T) {
	for _, imageBase := range []uint64{0x80000000, 0x180000000, 0xffffffff80000000} {
		data := make([]byte, 0x80)
		layout := peLayout{imageBase: imageBase, imageBaseSize: 8, sections: []peSection{{rawStart: 0x20, rawSize: 0x60, rva: 0x1000, virtualSize: 0x60}}}
		layout.directories[5] = peDirectory{rva: 0x1040, size: 12}
		put32(data, 0x20, uint32(imageBase)+0x1020)
		put32(data, 0x60, 0x1000)
		put32(data, 0x64, 12)
		put16(data, 0x68, 0x3000)
		// The final segment differs deliberately: a sign-extended address
		// would wrap below the first breakpoint and select that wrong segment.
		rift := riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1020, target: 0x1030}, {source: 0x2000, target: 0x2100}}}
		marker := make([]byte, len(data))
		transformRelocations(data, layout, rift, 0x190000000, marker)
		if got := get32(data, 0x20); got != 0x90001030 {
			t.Fatalf("base %#x: HIGHLOW = %#x", imageBase, got)
		}
		for _, mark := range marker[0x20:0x24] {
			if mark&1 == 0 {
				t.Fatal("HIGHLOW did not claim its operand")
			}
		}
	}
}

func TestWalkImportThunksMapsZeroTimestampImagePointers(t *testing.T) {
	data := make([]byte, 0x60)
	layout := peLayout{
		imageBase: 0x1c0000000, imageBaseSize: 8, imageSize: 0x4000,
		sections: []peSection{{rawStart: 0x20, rawSize: 0x40, rva: 0x1000, virtualSize: 0x40}},
	}
	put64(data, 0x20, layout.imageBase+0x1100)
	put64(data, 0x28, 0x1200)
	put64(data, 0x30, uint64(1)<<63|7)
	rift := riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1000, target: 0x1200}}}
	marker := make([]byte, len(data))
	walkImportThunks(data, layout, rift, 0x1000, false, false, 8, uint64(1)<<63, 0x180000000, marker)
	if got := get64(data, 0x20); got != layout.imageBase+0x1100 {
		t.Fatalf("import pass changed VA before relocation: %#x", got)
	}
	if got := get64(data, 0x28); got != 0x1400 {
		t.Fatalf("named IAT entry = %#x, want 0x1400", got)
	}
	if got := get64(data, 0x30); got != uint64(1)<<63|7 {
		t.Fatalf("ordinal IAT entry changed: %#x", got)
	}
	layout.directories[5] = peDirectory{rva: 0x1030, size: 12}
	put32(data, 0x50, 0x1000)
	put32(data, 0x54, 12)
	put16(data, 0x58, 0xa000)
	transformRelocations(data, layout, rift, 0x180000000, marker)
	if got := get64(data, 0x20); got != 0x180001300 {
		t.Fatalf("relocated IAT pointer = %#x, want %#x", got, uint64(0x180001300))
	}
}

func testX86TransformLayout() peLayout {
	return peLayout{
		machine:   0x14c,
		imageSize: 0x2000,
		sections: []peSection{{
			rawStart: 0x20, rawSize: 0x100,
			rva: 0x1000, virtualSize: 0x100,
			characteristics: 0x20000000,
		}},
	}
}

func TestX86BranchTargetsDoNotAliasHeaderAlignmentGap(t *testing.T) {
	// cntrtextmig.dll26100.1591 contains an embedded 0f89 whose apparent
	// target RVA2906 lies between SizeOfHeaders1024 and first section4096.
	// Native rejects that target, but accepts the same candidate aimed at
	// executable RVA0x8000. A header-gap RVA must not alias executable raw
	// bytes merely because its numeric value is also a valid file offset.
	for _, conditional := range []bool{false, true} {
		for _, target := range []uint32{0x100, 0xb00, 0x1800} {
			data := make([]byte, 0x2400)
			layout := peLayout{machine: 0x14c, headerSize: 0x200, imageSize: 0x4000,
				sections: []peSection{{rawStart: 0x200, rawSize: 0x2000, rva: 0x1000, virtualSize: 0x2000, characteristics: 0x20000000}},
			}
			position, width := 0x1800, 5
			data[position] = 0xe8
			if conditional {
				data[position], data[position+1] = 0x0f, 0x89
				width = 6
			}
			next := uint32(position + width - 0x200 + 0x1000)
			old := target - next
			put32(data, position+width-4, old)
			marker := make([]byte, len(data))
			markNonExecutablePE(marker, layout)
			rift := riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1800, target: 0x1900}, {source: 0x2600, target: 0x2800}}}
			if conditional {
				transformJmpsX86(data, layout, rift, marker)
			} else {
				transformCallsX86(data, layout, rift, marker)
			}
			want := old
			if target == 0x1800 {
				want -= 0x100
			}
			if got := get32(data, position+width-4); got != want {
				t.Fatalf("conditional=%t target=%#x: operand=%#x, want %#x", conditional, target, got, want)
			}
		}
	}
}

func TestX86BranchTargetMarkerIncludesExecutableRawPadding(t *testing.T) {
	// urefs.dll26100.1591 has an apparent CALL target inside .text raw
	// padding. Native rewrites it, but targeting the first byte beyond the
	// raw extent does not. Instruction scanning still excludes that padding.
	for _, target := range []uint32{0x1070, 0x10f0, 0x1100} {
		data := make([]byte, 0x140)
		layout := testX86TransformLayout()
		layout.sections[0].virtualSize = 0x80
		data[0x20], data[0xb0] = 0xe8, 0xe8
		old := target - 0x1005
		put32(data, 0x21, old)
		put32(data, 0xb1, 0xffffffa0)
		marker := make([]byte, len(data))
		markNonExecutablePE(marker, layout)
		if marker[0xa0] != 0 || marker[0x11f] != 0 || marker[0x120] != 1 {
			t.Fatal("executable ownership does not match exact raw extent")
		}
		rift := riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1070, target: 0x1080}, {source: 0x10f0, target: 0x1110}, {source: 0x1100, target: 0x1100}}}
		transformCallsX86(data, layout, rift, marker)
		want := old
		if target == 0x1070 {
			want += 0x10
		} else if target == 0x10f0 {
			want += 0x20
		}
		if got := get32(data, 0x21); got != want {
			t.Fatalf("target=%#x: operand=%#x, want %#x", target, got, want)
		}
		if get32(data, 0xb1) != 0xffffffa0 {
			t.Fatal("target ownership incorrectly expanded instruction scanning")
		}
	}
}

func TestTransformCallsX86MapsExecutableTarget(t *testing.T) {
	data := make([]byte, 0x140)
	layout := testX86TransformLayout()
	data[0x20] = 0xe8
	put32(data, 0x21, 0x5b) // next RVA 0x1005, target RVA 0x1060
	marker := make([]byte, len(data))
	markNonExecutablePE(marker, layout)
	transformCallsX86(data, layout, riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1060, target: 0x1070}}}, marker)
	if got := get32(data, 0x21); got != 0x6b {
		t.Fatalf("mapped CALL displacement = %#x, want %#x", got, 0x6b)
	}

	put32(data, 0x21, 0x5b)
	marker[0x80] = 1 // file offset of target RVA 0x1060
	transformCallsX86(data, layout, riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1060, target: 0x1070}}}, marker)
	if got := get32(data, 0x21); got != 0x5b {
		t.Fatalf("CALL with claimed target changed to %#x", got)
	}
}

func TestTransformJmpsX86RequiresByteAfterSectionBoundaryOperand(t *testing.T) {
	// Deviceflows.datamodel.dll26100.1591 ends .text with a five-byte E9.
	// Native preserves it, but extending VirtualSize by one byte makes it
	// remap. Both the initial scan and the conditional-prefix advance use a
	// strict end-5 bound; raw and virtual section limits both constrain it.
	for _, conditional := range []bool{false, true} {
		for _, rawLimited := range []bool{false, true} {
			for _, trailing := range []int{0, 1} {
				data := make([]byte, 0x180)
				layout := testX86TransformLayout()
				if rawLimited {
					layout.sections[0].rawSize = 0xe0
				} else {
					layout.sections[0].virtualSize = 0xe0
				}
				width := 5
				if conditional {
					width = 6
				}
				position := 0x100 - width - trailing
				data[position] = 0xe9
				if conditional {
					data[position], data[position+1] = 0x0f, 0x85
				}
				old := uint32(0x1000) - uint32(0x1000+position-0x20+width)
				put32(data, position+width-4, old)
				marker := make([]byte, len(data))
				markNonExecutablePE(marker, layout)
				rift := riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1000, target: 0x1010}, {source: 0x1080, target: 0x1080}}}
				transformJmpsX86(data, layout, rift, marker)
				want := old
				if trailing != 0 {
					want += 0x10
				}
				if got := get32(data, position+width-4); got != want {
					t.Fatalf("conditional=%t rawLimited=%t trailing=%d: operand=%#x, want %#x", conditional, rawLimited, trailing, got, want)
				}
			}
		}
	}
}

func TestTransformJmpsX86CollapsesMappedNearJump(t *testing.T) {
	data := make([]byte, 0x140)
	layout := testX86TransformLayout()
	data[0x20] = 0xe9
	put32(data, 0x21, 0x8b) // next RVA 0x1005, target RVA 0x1090
	marker := make([]byte, len(data))
	markNonExecutablePE(marker, layout)
	transformJmpsX86(data, layout, riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1090, target: 0x1060}}}, marker)
	if data[0x20] != 0xeb || data[0x21] != 0x5b {
		t.Fatalf("mapped JMP prefix = %x, want eb5b", data[0x20:0x22])
	}
}

func TestWalkImportThunksClassifiesLookupFromFirstEntry(t *testing.T) {
	data := make([]byte, 0x60)
	layout := peLayout{
		imageBaseSize: 8,
		sections: []peSection{{
			rawStart: 0x20, rawSize: 0x30,
			rva: 0x1000, virtualSize: 0x30,
		}},
	}
	ordinal := uint64(1) << 63
	put64(data, 0x20, ordinal|23)
	put64(data, 0x28, 0x1100)
	marker := make([]byte, len(data))
	rift := riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1000, target: 0xfe0}}}
	walkImportThunks(
		data, layout,
		rift, 0x1000, false, true, 8, ordinal, 0, marker,
	)
	if got := get64(data, 0x20); got != ordinal|23 {
		t.Fatalf("ordinal thunk = %#x, want unchanged", got)
	}
	if got := get64(data, 0x28); got != 0x1100 {
		t.Fatalf("named thunk after ordinal = %#x, want unchanged %#x", got, 0x1100)
	}

	marker = make([]byte, len(data))
	walkImportThunks(data, layout, rift, 0x1000, false, false, 8, ordinal, 0, marker)
	if got := get64(data, 0x28); got != 0x10e0 {
		t.Fatalf("IAT named thunk after ordinal = %#x, want mapped %#x", got, 0x10e0)
	}

	data = make([]byte, 0x60)
	put64(data, 0x20, 0x1100)
	put64(data, 0x28, ordinal|7)
	put64(data, 0x30, 0x1200)
	walkImportThunks(data, layout, rift, 0x1000, false, true, 8, ordinal, 0, make([]byte, len(data)))
	if got := get64(data, 0x20); got != 0x10e0 {
		t.Fatalf("name-led lookup first thunk = %#x, want mapped %#x", got, 0x10e0)
	}
	if got := get64(data, 0x28); got != ordinal|7 {
		t.Fatalf("name-led lookup ordinal = %#x, want unchanged", got)
	}
	if got := get64(data, 0x30); got != 0x11e0 {
		t.Fatalf("name-led lookup name after ordinal = %#x, want mapped %#x", got, 0x11e0)
	}
}

func TestDecodeDeltaX64UsesTransformInstructionBoundaries(t *testing.T) {
	for name, table := range map[string][]byte{
		"modrm-1": deltaX64ModRM1, "modrm-0f": deltaX64ModRM0F,
		"immediate-1": deltaX64Immediate1, "immediate-0f": deltaX64Immediate0F,
	} {
		if len(table) != 256 {
			t.Fatalf("%s table has %d entries, want 256", name, len(table))
		}
	}
	tests := []struct {
		name   string
		code   []byte
		length int
		field  int
		remap  bool
	}{
		{name: "rip-relative", code: []byte{0x48, 0x8b, 0x05, 1, 2, 3, 4}, length: 7, field: 3, remap: true},
		{name: "relative-call", code: []byte{0xe8, 1, 2, 3, 4}, length: 5, field: 1, remap: true},
		{name: "ret-imm16", code: []byte{0xc2, 0x34, 0x12}, length: 3, field: -1},
		{name: "enter-imm16-imm8", code: []byte{0xc8, 0x34, 0x12, 0x02}, length: 4, field: -1},
		{name: "rex-w-overrides-opsize-immediate", code: []byte{0x66, 0x48, 0x05, 1, 2, 3, 4}, length: 7, field: -1},
		{name: "rex-w-overrides-opsize-group-immediate", code: []byte{0x66, 0x48, 0xf7, 0xc0, 1, 2, 3, 4}, length: 8, field: -1},
		{name: "second-rex-stops", code: []byte{0x48, 0x49, 0xe8, 1, 2, 3, 4}, length: 1, field: -1},
		{name: "truncated-modrm", code: []byte{0x8b}, length: 1, field: -1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := decodeDeltaX64(test.code)
			if got.length != test.length || got.field != test.field || got.remap != test.remap {
				t.Fatalf("decoded = %#v, want length=%d field=%d remap=%t", got, test.length, test.field, test.remap)
			}
		})
	}
}

func TestTransformDisasmX64HonorsSharedByteMarkers(t *testing.T) {
	makeImage := func() ([]byte, peLayout) {
		data := make([]byte, 0x80)
		put32(data, 0x20, 0x1000)
		put32(data, 0x24, 0x1005)
		put32(data, 0x28, 0x3000)
		data[0x40] = 0xe8
		put32(data, 0x41, 0x1b) // next RVA 0x1005, target RVA 0x1020
		layout := peLayout{
			machine: 0x8664,
			directories: [16]peDirectory{
				3: {rva: 0x2000, size: 12},
			},
			sections: []peSection{
				{rawStart: 0x40, rawSize: 0x20, rva: 0x1000, virtualSize: 0x20},
				{rawStart: 0x20, rawSize: 0x0c, rva: 0x2000, virtualSize: 0x0c},
			},
		}
		return data, layout
	}
	rift := riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x1020, target: 0x1030}}}

	t.Run("unmarked instruction is remapped", func(t *testing.T) {
		data, layout := makeImage()
		transformDisasmX64(data, layout, rift, make([]byte, len(data)))
		if got := get32(data, 0x41); got != 0x2b {
			t.Fatalf("mapped displacement = %#x, want %#x", got, 0x2b)
		}
	})
	t.Run("claimed start is skipped", func(t *testing.T) {
		data, layout := makeImage()
		marker := make([]byte, len(data))
		marker[0x40] = 1
		transformDisasmX64(data, layout, rift, marker)
		if got := get32(data, 0x41); got != 0x1b {
			t.Fatalf("claimed instruction displacement = %#x, want unchanged %#x", got, 0x1b)
		}
	})
	t.Run("interior boundary truncates advancement", func(t *testing.T) {
		data, layout := makeImage()
		marker := make([]byte, len(data))
		marker[0x42] = 2
		transformDisasmX64(data, layout, rift, marker)
		if got := get32(data, 0x41); got != 0x1b {
			t.Fatalf("boundary-crossing displacement = %#x, want unchanged %#x", got, 0x1b)
		}
	})
}

func TestDisasmX64DoesNotUseRawExtentAsGlobalRVACutoff(t *testing.T) {
	// A global RVA-versus-raw-size cutoff fixes two Win11 records but breaks
	// ipmidrv/verifierext, whose PAGE functions follow large virtual .data gaps.
	data := make([]byte, 0x2000) // includes certificate/overlay after raw image
	layout := peLayout{machine: 0x8664, headerSize: 0x200, imageSize: 0x4000,
		directories: [16]peDirectory{3: {rva: 0x3000, size: 24}, 4: {rva: 0xa00, size: 0x1600}},
		sections: []peSection{
			{rawStart: 0x400, rawSize: 0x100, rva: 0x800, virtualSize: 0x100, characteristics: 0x62000020},
			{rawStart: 0x600, rawSize: 0x100, rva: 0x1800, virtualSize: 0x100, characteristics: 0x62000020},
			{rawStart: 0x800, rawSize: 0x200, rva: 0x3000, virtualSize: 0x200},
		}}
	put32(data, 0x800, 0x800)
	put32(data, 0x804, 0x805)
	put32(data, 0x80c, 0x1800)
	put32(data, 0x810, 0x1805)
	for _, off := range []int{0x400, 0x600} {
		data[off] = 0xe8
		put32(data, off+1, 0x1b)
	}
	rift := riftTable{entries: []riftEntry{{source: 0, target: 0}, {source: 0x820, target: 0x830}, {source: 0x1000, target: 0x1000}, {source: 0x1820, target: 0x1830}}}
	transformDisasmX64(data, layout, rift, make([]byte, len(data)))
	if get32(data, 0x401) != 0x2b {
		t.Fatal("in-domain discardable function was not normalized")
	}
	if get32(data, 0x601) != 0x2b {
		t.Fatal("valid late function excluded by conflating raw and RVA extents")
	}
}
