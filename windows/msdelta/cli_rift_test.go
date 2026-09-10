package msdelta

import (
	"sort"
	"testing"
)

func TestCLICompressionRiftKeepsRowsPastDeclaredTargetTable(t *testing.T) {
	// AppX26100.9168 narrows MethodDef's blob column. Native still maps
	// source row12907 to target row6068, past the declared5338 target rows;
	// this anchor affects copies in the following table's unmapped region.
	source := &cliMetadata{
		CLIPreprocessInfo: &CLIPreprocessInfo{Rows: [64]uint32{6: 4}, HeapWidths: [3]uint8{2, 2, 4}},
		tableOffsets:      [64]int{6: 0x100}, rowSizes: [64]int{6: 16},
	}
	target := &CLIPreprocessInfo{MetadataPresent: true, MetadataOffset: 0x1000, MetadataSize: 0x400,
		Rows: [64]uint32{6: 2}, HeapWidths: [3]uint8{2, 2, 2}, ValidTables: 1 << 6,
		Streams: [5]CLIStreamInfo{4: {Offset: 0x1000, Size: 0x200}},
	}
	layout, err := layoutCLIMetadata(target)
	if err != nil {
		t.Fatal(err)
	}
	r, err := cliCompressionRift(source, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(r.entries, func(i, j int) bool { return r.entries[i].source < r.entries[j].source })
	at := int64(layout.tableOffsets[6] + 2*14 + 12)
	if got, want := r.mapForward(at), int64(0x100+2*16+14); got != want {
		t.Fatalf("out-of-table row3 ParamList maps to %#x, want %#x", got, want)
	}
}

func TestCLICompressionRiftOmitsRedundantColumnAnchors(t *testing.T) {
	// Native Field rows can extend into MethodDef. Field's redundant string
	// column must not override MethodDef's row-start anchor two bytes later.
	source := &cliMetadata{
		CLIPreprocessInfo: &CLIPreprocessInfo{Rows: [64]uint32{4: 12, 6: 5}, HeapWidths: [3]uint8{2, 2, 4}},
		tableOffsets:      [64]int{4: 0x100, 6: 0x200}, rowSizes: [64]int{4: 8, 6: 16},
	}
	target := &CLIPreprocessInfo{MetadataPresent: true, MetadataOffset: 0x1000, MetadataSize: 0x400,
		Rows: [64]uint32{4: 1, 6: 4}, HeapWidths: [3]uint8{2, 2, 2}, ValidTables: 1<<4 | 1<<6,
		Streams: [5]CLIStreamInfo{4: {Offset: 0x1000, Size: 0x200}},
	}
	layout, err := layoutCLIMetadata(target)
	if err != nil {
		t.Fatal(err)
	}
	r, err := cliCompressionRift(source, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(r.entries, func(i, j int) bool { return r.entries[i].source < r.entries[j].source })
	at := int64(layout.tableOffsets[6] + 2)
	if got := r.mapForward(at); got != 0x202 {
		t.Fatalf("redundant Field column overrides MethodDef: %#x", got)
	}
	// Row4 begins at a Field anchor too. Although its displacement equals
	// the end of MethodDef row3, its row-start replacement is still required.
	at = int64(layout.tableOffsets[6] + 3*14)
	if got := r.mapForward(at); got != 0x230 {
		t.Fatalf("omitted row start leaves Field active: %#x", got)
	}
}

func TestCLICompressionRiftIncludesImplicitInitialHeapByte(t *testing.T) {
	// ReFS26100.8972 #US begins with implicit identity before its first
	// explicit permutation. The preceding #Strings displacement is one byte
	// different and must not shift the initial user-string length/data bytes.
	source := &cliMetadata{CLIPreprocessInfo: &CLIPreprocessInfo{
		HeapWidths: [3]uint8{2, 2, 2},
		Streams:    [5]CLIStreamInfo{0: {Offset: 0x1000, Size: 0x101}, 1: {Offset: 0x1101, Size: 0x100}},
	}}
	target := &CLIPreprocessInfo{MetadataPresent: true, MetadataOffset: 0x1800, MetadataSize: 0x1000,
		HeapWidths: [3]uint8{2, 2, 2},
		Streams:    [5]CLIStreamInfo{0: {Offset: 0x2000, Size: 0x100}, 1: {Offset: 0x2100, Size: 0x100}, 4: {Offset: 0x1800, Size: 24}},
		HeapMaps:   [4][]PERiftEntry{1: {{Source: 20, Target: 30}, {Source: 30, Target: 20}, {Source: 40, Target: 40}}},
	}
	r, err := cliCompressionRift(source, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(r.entries, func(i, j int) bool { return r.entries[i].source < r.entries[j].source })
	for _, test := range []struct{ target, source int64 }{{0, 0}, {1, 1}, {19, 19}, {20, 30}, {30, 20}, {40, 40}} {
		if got := r.mapForward(0x2100 + test.target); got != 0x1101+test.source {
			t.Fatalf("user-string byte%d maps to %#x, want %#x", test.target, got, 0x1101+test.source)
		}
	}
}

func TestCLICompressionRiftDoesNotMapSyntheticRowZero(t *testing.T) {
	// Native ReFS dedup commands 26100.1591 copies from 17657 at target
	// 75979 and from history 20453 at target 77912. With the patch's fixed
	// distances these require the two mappings below. A synthetic RID0
	// entry overrides the preceding table and shifts those copies by 816
	// and 192 bytes respectively.
	source := &cliMetadata{
		CLIPreprocessInfo: &CLIPreprocessInfo{Rows: [64]uint32{8: 274, 10: 139, 11: 24}, HeapWidths: [3]uint8{2, 2, 2}},
		tableOffsets:      [64]int{8: 15256, 10: 16900, 11: 17734},
		rowSizes:          [64]int{8: 6, 10: 6, 11: 6},
	}
	target := &CLIPreprocessInfo{
		MetadataPresent: true, MetadataOffset: 70000, MetadataSize: 20000,
		HeapWidths: [3]uint8{2, 2, 2}, ValidTables: 1<<8 | 1<<10 | 1<<11,
		Rows:    [64]uint32{8: 563, 10: 198, 11: 502},
		Streams: [5]CLIStreamInfo{4: {Offset: 72564, Size: 7614}},
		TableMaps: [64][]PERiftEntry{
			8:  {{Source: 0, Target: 0}, {Source: 6, Target: 64}, {Source: 58, Target: 117}, {Source: 63, Target: 123}, {Source: 274, Target: 427}},
			10: {{Source: 0, Target: 0}, {Source: 1, Target: 2}, {Source: 18, Target: 24}, {Source: 23, Target: 21}, {Source: 24, Target: 29}, {Source: 25, Target: 56}, {Source: 85, Target: 46}, {Source: 86, Target: 116}, {Source: 93, Target: 55}, {Source: 94, Target: 123}, {Source: 126, Target: 32}, {Source: 127, Target: 35}, {Source: 128, Target: 155}},
			11: {{Source: 0, Target: 0}, {Source: 1, Target: 400}},
		},
	}
	r, err := cliCompressionRift(source, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(r.entries, func(i, j int) bool { return r.entries[i].source < r.entries[j].source })
	if r.entries[0] != (riftEntry{source: 72600, target: 15256}) {
		t.Fatalf("initial null segment must start at real row1: %v", r.entries[0])
	}
	for _, test := range []struct{ at, want int64 }{{75979, 17717}, {77912, 18672}, {72600, 15256}} {
		if got := r.mapForward(test.at); got != test.want {
			t.Errorf("target %d maps to %d, want %d", test.at, got, test.want)
		}
	}
}

func TestCLICompressionRiftIncludesImplicitInitialRealRow(t *testing.T) {
	// PowerShell26100.1591 DeclSecurity starts with a real RID1 mapping
	// inherited from the final36->36 segment. Without that segment the
	// preceding FieldMarshal table maps the first row six bytes too late.
	source := &cliMetadata{
		CLIPreprocessInfo: &CLIPreprocessInfo{Rows: [64]uint32{13: 2, 14: 37}, HeapWidths: [3]uint8{2, 2, 2}},
		tableOffsets:      [64]int{13: 0x100, 14: 0x108},
		rowSizes:          [64]int{13: 4, 14: 6},
	}
	target := &CLIPreprocessInfo{
		MetadataPresent: true, MetadataOffset: 0x1000, MetadataSize: 0x1000,
		HeapWidths: [3]uint8{2, 2, 2}, ValidTables: 1<<13 | 1<<14,
		Rows: [64]uint32{13: 3, 14: 37}, Streams: [5]CLIStreamInfo{4: {Offset: 0x1000, Size: 0x1000}},
		TableMaps: [64][]PERiftEntry{14: {{Source: 2, Target: 30}, {Source: 8, Target: 2}, {Source: 36, Target: 36}}},
	}
	layout, err := layoutCLIMetadata(target)
	if err != nil {
		t.Fatal(err)
	}
	r, err := cliCompressionRift(source, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(r.entries, func(i, j int) bool { return r.entries[i].source < r.entries[j].source })
	for _, row := range []struct{ target, source int }{{1, 1}, {2, 8}, {30, 2}, {36, 36}} {
		at := int64(layout.tableOffsets[14] + (row.target-1)*6)
		want := int64(source.tableOffsets[14] + (row.source-1)*6)
		if got := r.mapForward(at); got != want {
			t.Fatalf("target row%d maps to %#x, want %#x", row.target, got, want)
		}
	}
}

func TestCLICompressionRiftUsesTargetFileCoordinatesAndOneBasedRows(t *testing.T) {
	_, source := makeTestCLIImage(t)
	target := *source.CLIPreprocessInfo
	target.MetadataOffset += 0x20
	target.MetadataSize += 14
	target.StreamHeadersEnd += 0x20
	target.Streams[4].Offset += 0x20
	target.Streams[4].Size += 14
	target.Rows[6] = 2
	target.TableMaps[6] = []PERiftEntry{{Source: 0, Target: 0}, {Source: 1, Target: 2}}
	r, err := cliCompressionRift(source, &target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.entries) != 1 {
		t.Fatalf("rift = %#v", r.entries)
	}
	if r.entries[0] != (riftEntry{source: 0x2fa, target: 0x2cc}) {
		t.Fatalf("row2 -> row1 = %#v", r.entries[0])
	}
}

func TestCLICompressionRiftMapsWidenedHeapColumns(t *testing.T) {
	_, source := makeTestCLIImage(t)
	source.Rows[6] = 2
	source.Streams[4].Size += uint32(source.rowSizes[6])
	target := *source.CLIPreprocessInfo
	target.HeapWidths[0] = 4
	target.Streams[4].Size += 4
	r, err := cliCompressionRift(source, &target, []byte{1, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(r.entries, func(i, j int) bool { return r.entries[i].source < r.entries[j].source })
	// MethodDef: RVA4, ImplFlags2, Flags2, Name(2->4), Signature2, Param2.
	for _, cell := range []struct{ source, target int64 }{{0, 0}, {4, 4}, {6, 6}, {8, 8}, {10, 12}, {12, 14}} {
		if got := r.mapForward(0x2cc + cell.target); got != 0x2cc+cell.source {
			t.Fatalf("target cell %d maps to %#x, want %#x", cell.target, got, 0x2cc+cell.source)
		}
	}
}

func TestCLICompressionRiftMapsWidenedAndNarrowedRows(t *testing.T) {
	for _, widen := range []bool{false, true} {
		// MethodImpl's two MethodDefOrRef cells cross their 15-bit RID limit.
		sourceMethods, targetMethods := uint32(32768), uint32(32767)
		if widen {
			sourceMethods, targetMethods = targetMethods, sourceMethods
		}
		makeMetadata := func(methods uint32, offset uint32) *CLIPreprocessInfo {
			return &CLIPreprocessInfo{MetadataPresent: true, MetadataOffset: offset, MetadataSize: 1 << 20,
				HeapWidths: [3]uint8{2, 2, 2}, ValidTables: 1<<6 | 1<<25,
				Rows: [64]uint32{6: methods, 25: 3}, Streams: [5]CLIStreamInfo{4: {Offset: offset, Size: 1 << 20}},
			}
		}
		source, err := layoutCLIMetadata(makeMetadata(sourceMethods, 0x1000))
		if err != nil {
			t.Fatal(err)
		}
		targetInfo := makeMetadata(targetMethods, 0x2000)
		targetInfo.TableMaps[25] = []PERiftEntry{{Source: 0, Target: 0}, {Source: 1, Target: 2}, {Source: 2, Target: 1}, {Source: 3, Target: 3}}
		target, err := layoutCLIMetadata(targetInfo)
		if err != nil {
			t.Fatal(err)
		}
		r, err := cliCompressionRift(source, targetInfo, []byte{1, 0, 0})
		if err != nil {
			t.Fatal(err)
		}
		sort.SliceStable(r.entries, func(i, j int) bool { return r.entries[i].source < r.entries[j].source })
		for sourceRow, targetRow := range []int{1, 0} {
			a := int64(source.tableOffsets[25] + sourceRow*source.rowSizes[25])
			b := int64(target.tableOffsets[25] + targetRow*target.rowSizes[25])
			for _, kind := range cliColumns[25] {
				if got := r.mapForward(b); got != a {
					t.Fatalf("widen=%t target=%#x maps to %#x, want %#x", widen, b, got, a)
				}
				if source.columnWidth(kind) < target.columnWidth(kind) {
					for high := int64(0); high < 2; high++ {
						if got := r.mapForward(b + 2 + high); got != 1+high {
							t.Fatalf("widened high byte maps to %#x, want %#x", got, 1+high)
						}
					}
				}
				a += int64(source.columnWidth(kind))
				b += int64(target.columnWidth(kind))
			}
		}
		finalRow := int64(target.tableOffsets[25] + 2*target.rowSizes[25])
		for _, entry := range r.entries {
			if entry.source >= finalRow {
				t.Fatalf("widen=%t: final source row must not contribute copy anchors: %v", widen, entry)
			}
		}
	}
}

func TestCLICompressionRiftWideningSelectsFirstPreparedZeroPair(t *testing.T) {
	_, source := makeTestCLIImage(t)
	source.Rows[6] = 2
	source.Streams[4].Size += uint32(source.rowSizes[6])
	target := *source.CLIPreprocessInfo
	target.HeapWidths[0] = 4
	target.Streams[4].Size += 4
	for _, test := range []struct {
		prepared []byte
		want     int64
	}{
		{[]byte{'M', 'Z', 0x90, 0, 3, 0, 0, 0}, 5},
		{[]byte{'M', 'Z', 0x90, 0, 3, 127, 0, 0}, 6},
		{[]byte{'M', 'Z', 0, 0, 3, 0, 0, 0}, 2},
	} {
		r, err := cliCompressionRift(source, &target, test.prepared)
		if err != nil {
			t.Fatal(err)
		}
		sort.SliceStable(r.entries, func(i, j int) bool { return r.entries[i].source < r.entries[j].source })
		for high := int64(0); high < 2; high++ {
			if got := r.mapForward(0x2cc + 10 + high); got != test.want+high {
				t.Fatalf("prepared %x: high byte %d maps to %d, want %d", test.prepared, high, got, test.want+high)
			}
		}
	}
	if _, err := cliCompressionRift(source, &target, []byte{1, 0, 1}); err == nil {
		t.Fatal("accepted widening without a source zero pair")
	}
}

func TestCLICompressionRiftOneRowWidthChangeContributesNoAnchors(t *testing.T) {
	_, source := makeTestCLIImage(t)
	target := *source.CLIPreprocessInfo
	target.HeapWidths[0] = 4
	target.Streams[4].Size += 2
	r, err := cliCompressionRift(source, &target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.entries) != 0 {
		t.Fatalf("one-row width conversion supplied copy anchors: %v", r.entries)
	}
}

func TestCLICompressionRiftWidenedTableContinuationIntoUnmappedRows(t *testing.T) {
	// vmconnect's MemberRef width conversion stops at its penultimate row.
	// Constant has no early target-row mapping, so it inherits that final
	// real column's continuation, not an extra final-source-row anchor.
	sourceInfo := &CLIPreprocessInfo{MetadataPresent: true, MetadataOffset: 0x1000, MetadataSize: 0x1000,
		HeapWidths: [3]uint8{2, 2, 2}, ValidTables: 1<<10 | 1<<11,
		Rows: [64]uint32{10: 3, 11: 2}, Streams: [5]CLIStreamInfo{4: {Offset: 0x1000, Size: 0x1000}},
	}
	source, err := layoutCLIMetadata(sourceInfo)
	if err != nil {
		t.Fatal(err)
	}
	targetInfo := *sourceInfo
	targetInfo.HeapWidths[0] = 4
	targetInfo.Rows[10], targetInfo.Rows[11] = 4, 4
	targetInfo.TableMaps[11] = []PERiftEntry{{Source: 0, Target: 0}, {Source: 1, Target: 3}}
	target, err := layoutCLIMetadata(&targetInfo)
	if err != nil {
		t.Fatal(err)
	}
	r, err := cliCompressionRift(source, &targetInfo, []byte{1, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(r.entries, func(i, j int) bool { return r.entries[i].source < r.entries[j].source })
	for delta := int64(0); delta < 12; delta++ {
		at := int64(target.tableOffsets[11]) + delta
		want := int64(source.tableOffsets[10]) + 28 + delta
		if got := r.mapForward(at); got != want {
			t.Fatalf("unmapped Constant byte%d maps to %#x, want %#x", delta, got, want)
		}
	}
}
