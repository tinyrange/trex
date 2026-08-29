package windows

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestBuildCREGWindows95Layout(t *testing.T) {
	root := newRegistryTree("")
	setRegistryValue(root, "/Software/OracleA", "Alpha", registryString(regSZ, "one"))
	setRegistryValue(root, "/Software/OracleB/Child", "Beta", registryData{typ: regBinary, data: []byte{1, 2, 3, 4}})

	data, err := buildCREG(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data[:4]), "CREG"; got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(data[4:8]), uint32(0x00010000); got != want {
		t.Fatalf("version = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(data[8:12]), uint32(0x1000); got != want {
		t.Fatalf("RGDB offset = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint16(data[18:20]), uint16(1); got != want {
		t.Fatalf("initialized state = %#x, want %#x", got, want)
	}
	if got := binary.LittleEndian.Uint32(data[12:16]); got != 0 {
		t.Fatalf("CREG header reserved field = %#x, want zero", got)
	}
	if got, want := string(data[32:36]), "RGKN"; got != want {
		t.Fatalf("navigation signature = %q, want %q", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(data[64+24:64+28]), uint32(0xffffffff); got != want {
		t.Fatalf("root identity = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(data[64+28+24:64+28+28]), uint32(0); got != want {
		t.Fatalf("first named-key identity = %#x, want %#x", got, want)
	}
	rgknUsed := int(binary.LittleEndian.Uint32(data[44:48]))
	freeNavigation := 32 + rgknUsed
	if got := binary.LittleEndian.Uint32(data[freeNavigation : freeNavigation+4]); got != 0x80000000 {
		t.Fatalf("free navigation marker = %#x, want free marker", got)
	}

	rgdbOffset := int(binary.LittleEndian.Uint32(data[8:12]))
	if got, want := string(data[rgdbOffset:rgdbOffset+4]), "RGDB"; got != want {
		t.Fatalf("data signature = %q, want %q", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(data[rgdbOffset+4:rgdbOffset+8]), uint32(0x1000); got != want {
		t.Fatalf("RGDB size = %#x, want %#x", got, want)
	}
	if got := binary.LittleEndian.Uint32(data[rgdbOffset+28 : rgdbOffset+32]); got != 0 {
		t.Fatalf("RGDB reserved field = %#x, want zero", got)
	}
	first := rgdbOffset + 32
	if got, want := binary.LittleEndian.Uint32(data[first+4:first+8]), uint32(0); got != want {
		t.Fatalf("first record identity = %#x, want %#x", got, want)
	}
	if got, want := string(data[first+20:first+28]), "Software"; got != want {
		t.Fatalf("first record name = %q, want %q", got, want)
	}

	// REGEDIT-created compact hives initialize value cache references to the
	// absent sentinel and store REG_SZ bytes without a trailing NUL.
	second := first + int(binary.LittleEndian.Uint32(data[first:first+4]))
	nameSize := int(binary.LittleEndian.Uint16(data[second+12 : second+14]))
	value := second + 20 + nameSize
	if got, want := binary.LittleEndian.Uint32(data[value+4:value+8]), uint32(0xffffffff); got != want {
		t.Fatalf("value cache = %#x, want %#x", got, want)
	}
	valueNameSize := int(binary.LittleEndian.Uint16(data[value+8 : value+10]))
	valueDataSize := int(binary.LittleEndian.Uint16(data[value+10 : value+12]))
	valueData := data[value+12+valueNameSize : value+12+valueNameSize+valueDataSize]
	if got, want := string(valueData), "one"; got != want {
		t.Fatalf("REG_SZ data = %q, want %q", got, want)
	}
}

func TestBuildCREGMarksOnlyDefaultValueLists(t *testing.T) {
	root := newRegistryTree("")
	setRegistryValue(root, "/Software/NamedOnly", "Value", registryString(regSZ, "data"))
	ensureRegistryKey(root, "/Software/Empty")

	data, err := buildCREGWithLayout(root, 1, true)
	if err != nil {
		t.Fatal(err)
	}

	// Writer traversal is root, Software, Empty, NamedOnly.  RGKN offsets are
	// relative to the start of RGKN and each navigation record is 28 bytes.
	const (
		emptyNavigation     = 32 + 2*28
		namedOnlyNavigation = 32 + 3*28
	)
	if got, want := binary.LittleEndian.Uint32(data[32+emptyNavigation+8:32+emptyNavigation+12]), uint32(0xffffffff); got != want {
		t.Fatalf("empty key value-list reference = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(data[32+namedOnlyNavigation+8:32+namedOnlyNavigation+12]), uint32(0xffffffff); got != want {
		t.Fatalf("named-only key value-list reference = %#x, want %#x", got, want)
	}
}

func TestBuildCREGWindowsMEDepthReferences(t *testing.T) {
	root := newRegistryTree("")
	ensureRegistryKey(root, "/Software/Empty/Child")
	setRegistryValue(root, "/Software/Valued", "Value", registryString(regSZ, "data"))

	data, err := buildCREGWithGeneration(root, 0x21, "windowsme")
	if err != nil {
		t.Fatal(err)
	}

	// Writer traversal is root, Software, Empty, Child, Valued. ME leaves only
	// direct children of the synthetic root at the absent sentinel.
	want := []uint32{0, 0xffffffff, 4, 4, 4}
	navCursor := 32
	for index, reference := range want {
		entry := 32 + navCursor
		if got := binary.LittleEndian.Uint32(data[entry+8 : entry+12]); got != reference {
			t.Fatalf("navigation record %d reference = %#x, want %#x", index, got, reference)
		}
		navCursor += 28
	}
	if got := int(binary.LittleEndian.Uint32(data[8:12])) % 0x1000; got != 0x20 {
		t.Fatalf("ME RGDB page displacement = %#x, want %#x", got, 0x20)
	}
	rgknUsed := int(binary.LittleEndian.Uint32(data[44:48]))
	secondFree := 32 + rgknUsed + 28
	if got := binary.LittleEndian.Uint32(data[secondFree : secondFree+4]); got != 0x80000000 {
		t.Fatalf("ME second free navigation marker = %#x, want %#x", got, uint32(0x80000000))
	}
	if got := binary.LittleEndian.Uint32(data[secondFree+8 : secondFree+12]); got != 4 {
		t.Fatalf("ME second free navigation record offset = %#x, want 4", got)
	}
	blockCount := int(binary.LittleEndian.Uint16(data[16:18]))
	offset := int(binary.LittleEndian.Uint32(data[8:12]))
	for block := 0; block < blockCount-1; block++ {
		offset += int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
	}
	if got, want := binary.LittleEndian.Uint32(data[offset+4:offset+8]), uint32(0x8000); got != want {
		t.Fatalf("ME reserve RGDB size = %#x, want %#x", got, want)
	}
	if got := binary.LittleEndian.Uint16(data[offset+22 : offset+24]); got != 0 {
		t.Fatalf("ME reserve RGDB entry count = %d, want zero", got)
	}
}

func TestBuildCREGNashvilleUsesPortableGrowthReserve(t *testing.T) {
	root := newRegistryTree("")
	setRegistryValue(root, "/Software/Named", "(default)", registryString(regSZ, "data"))
	setRegistryValue(root, "/Software/Named", "Value", registryString(regSZ, "named"))
	for index := 0; index < 300; index++ {
		setRegistryValue(root, fmt.Sprintf("/Other/K%04d", index), "Value", registryString(regSZ, "value"))
	}

	data, err := buildCREGWithGeneration(root, 1, "windows_nashville")
	if err != nil {
		t.Fatal(err)
	}
	if got := int(binary.LittleEndian.Uint32(data[8:12])) % 0x1000; got != 0 {
		t.Fatalf("Nashville RGDB page displacement = %#x, want zero", got)
	}
	if got, want := binary.LittleEndian.Uint32(data[12:16]), uint32(0xb8b49dbc); got != want {
		t.Fatalf("Nashville file marker = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(data[48:52]), uint32(0x09); got != want {
		t.Fatalf("Nashville RGKN flags = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(data[52:56]), uint32(0x31b49360); got != want {
		t.Fatalf("Nashville RGKN marker = %#x, want %#x", got, want)
	}
	if got := binary.LittleEndian.Uint32(data[64+8 : 64+12]); got != 0 {
		t.Fatalf("Nashville root cache reference = %#x, want zero", got)
	}
	// Traversal is root, Software, Named, Other, ...; native Nashville leaves
	// every named navigation cache absent, even when a key owns a default value.
	namedNavigation := 32 + 2*28
	if got, want := binary.LittleEndian.Uint32(data[32+namedNavigation+8:32+namedNavigation+12]), uint32(0xffffffff); got != want {
		t.Fatalf("Nashville named-key cache reference = %#x, want %#x", got, want)
	}

	rgdb := int(binary.LittleEndian.Uint32(data[8:12]))
	if got, want := binary.LittleEndian.Uint16(data[rgdb+12:rgdb+14]), uint16(0x09); got != want {
		t.Fatalf("Nashville RGDB flags = %#x, want %#x", got, want)
	}
	if got := binary.LittleEndian.Uint32(data[rgdb+8 : rgdb+12]); got < 0x1000 {
		t.Fatalf("Nashville RGDB growth reserve = %#x, want at least one page", got)
	}
	first := rgdb + 32
	second := first + int(binary.LittleEndian.Uint32(data[first:first+4]))
	nameSize := int(binary.LittleEndian.Uint16(data[second+12 : second+14]))
	value := second + 20 + nameSize
	if got := binary.LittleEndian.Uint32(data[value+4 : value+8]); got != 0 {
		t.Fatalf("Nashville value cache = %#x, want zero", got)
	}
	valueNameSize := int(binary.LittleEndian.Uint16(data[value+8 : value+10]))
	valueDataSize := int(binary.LittleEndian.Uint16(data[value+10 : value+12]))
	valueData := data[value+12+valueNameSize : value+12+valueNameSize+valueDataSize]
	if got, want := string(valueData), "data"; got != want {
		t.Fatalf("Nashville REG_SZ data = %q, want %q", got, want)
	}
}

func TestBuildCREGNashvilleKeepsCompactAllocatorForSmallHives(t *testing.T) {
	root := newRegistryTree("")
	setRegistryValue(root, "/Software/Alt", "Value", registryString(regSZ, "Different"))

	data, err := buildCREGWithGeneration(root, 1, "windows_nashville")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := binary.LittleEndian.Uint32(data[8:12]), uint32(0x1000); got != want {
		t.Fatalf("compact Nashville RGDB offset = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(data[36:40]), uint32(0x0fe0); got != want {
		t.Fatalf("compact Nashville RGKN size = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(data[48:52]), uint32(0x09); got != want {
		t.Fatalf("compact Nashville RGKN flags = %#x, want %#x", got, want)
	}
	rgdb := int(binary.LittleEndian.Uint32(data[8:12]))
	if got, want := binary.LittleEndian.Uint16(data[rgdb+12:rgdb+14]), uint16(0x09); got != want {
		t.Fatalf("compact Nashville RGDB flags = %#x, want %#x", got, want)
	}
}

func TestBuildCREGWindowsMEMatchesNativeAllocatorShape(t *testing.T) {
	root := newRegistryTree("")
	ensureRegistryKey(root, "/Software/Classes")
	for index := 0; index < 900; index++ {
		setRegistryValue(root, fmt.Sprintf("/Software/TrexScope/K%04d", index), "Named", registryString(regSZ, fmt.Sprintf("value-%04d", index)))
	}
	for index := 0; index < 700; index++ {
		setRegistryValue(root, "/Software/TrexScope/Large", fmt.Sprintf("V%04d", index), registryString(regSZ, fmt.Sprintf("payload-%d-%s", index, strings.Repeat("x", 48))))
	}

	data, err := buildCREGWithGeneration(root, 0x21, "windowsme")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(data), 172064; got != want {
		t.Fatalf("ME oracle-shaped hive size = %d, want %d", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(data[8:12]), uint32(0x7020); got != want {
		t.Fatalf("ME RGDB offset = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(data[44:48]), uint32(0x6348); got != want {
		t.Fatalf("ME RGKN used size = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint16(data[16:18]), uint16(5); got != want {
		t.Fatalf("ME RGDB block count = %d, want %d", got, want)
	}

	offset := 0x7020
	wantSizes := []uint32{0x4000, 0x4000, 0x4000, 0xf000, 0x8000}
	wantEntries := []uint16{255, 255, 255, 139, 0}
	for block := range wantSizes {
		if got := binary.LittleEndian.Uint32(data[offset+4 : offset+8]); got != wantSizes[block] {
			t.Fatalf("ME block %d size = %#x, want %#x", block, got, wantSizes[block])
		}
		if got := binary.LittleEndian.Uint16(data[offset+22 : offset+24]); got != wantEntries[block] {
			t.Fatalf("ME block %d entries = %d, want %d", block, got, wantEntries[block])
		}
		offset += int(wantSizes[block])
	}
	// Native ME exhausts its bounded first-page navigation cache at slot 145.
	entry := 32 + (32 + 145*28)
	if got := binary.LittleEndian.Uint32(data[entry+8 : entry+12]); got != 0 {
		t.Fatalf("ME navigation slot 145 cache reference = %#x, want zero", got)
	}
}

func TestBuildCREGUsesCompleteRecordIdentities(t *testing.T) {
	root := newRegistryTree("")
	for index := 0; index < 700; index++ {
		setRegistryValue(root, fmt.Sprintf("/Software/K%04d", index), "Value", registryString(regSZ, "data"))
	}
	data, err := buildCREG(root)
	if err != nil {
		t.Fatal(err)
	}
	blockCount := int(binary.LittleEndian.Uint16(data[16:18]))
	if blockCount < 3 {
		t.Fatalf("RGDB block count = %d, want at least 3", blockCount)
	}
	offset := int(binary.LittleEndian.Uint32(data[8:12]))
	for block := 0; block < blockCount; block++ {
		size := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		if size > 0x4000 {
			t.Fatalf("block %d size = %#x, want no more than %#x", block, size, 0x4000)
		}
		entryCount := int(binary.LittleEndian.Uint16(data[offset+22 : offset+24]))
		if entryCount == 0 || entryCount > 255 {
			t.Fatalf("block %d entry count = %d, want 1..255", block, entryCount)
		}
		identity := binary.LittleEndian.Uint32(data[offset+32+4 : offset+32+8])
		if got, want := identity, uint32(block)<<16; got != want {
			t.Fatalf("block %d first identity = %#x, want %#x", block, got, want)
		}
		offset += size
	}
}

func TestBuildCREGWindows95RTMUsesCompleteRecordIdentities(t *testing.T) {
	root := newRegistryTree("")
	for index := 0; index < 300; index++ {
		setRegistryValue(root, fmt.Sprintf("/Software/K%04d", index), "Value", registryString(regSZ, "data"))
	}
	data, err := buildCREGWithGeneration(root, 1, "windows95_rtm")
	if err != nil {
		t.Fatal(err)
	}
	offset := int(binary.LittleEndian.Uint32(data[8:12]))
	offset += int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
	if got, want := binary.LittleEndian.Uint32(data[offset+32+4:offset+32+8]), uint32(0x00010000); got != want {
		t.Fatalf("RTM second-block identity = %#x, want %#x", got, want)
	}
}

func TestCREGKeysPreserveSlashBearingPathComponents(t *testing.T) {
	root := newRegistryTree("")
	ensureRegistryKeyParts(root, []string{"Software", "Classes", "MIME", "text/html"})
	keys := starlark.NewList(nil)
	if err := appendCREGTreeKeys(root, nil, keys); err != nil {
		t.Fatal(err)
	}
	last, ok := keys.Index(keys.Len() - 1).(*starlark.List)
	if !ok {
		t.Fatalf("last key is %T, want component list", keys.Index(keys.Len()-1))
	}
	if got, want := last.Len(), 4; got != want {
		t.Fatalf("component count = %d, want %d", got, want)
	}
	if got, ok := starlark.AsString(last.Index(3)); !ok || got != "text/html" {
		t.Fatalf("final component = %v, want slash-bearing key name", last.Index(3))
	}
}

func TestBuildCREGWindows98SupportsLargeKeyRecords(t *testing.T) {
	root := newRegistryTree("")
	for index := 0; index < 400; index++ {
		setRegistryValue(root, "/Software/Schemes", fmt.Sprintf("Sound%04d", index), registryString(regSZ, strings.Repeat("tone", 12)))
	}
	setRegistryValue(root, "/Software/Following", "Value", registryString(regSZ, "data"))
	if _, err := buildCREG(root); err == nil || !strings.Contains(err.Error(), "exceeds an RGDB block") {
		t.Fatalf("Windows 95 large-record error = %v", err)
	}
	data, err := buildCREGWithLayout(root, 0x21, true)
	if err != nil {
		t.Fatal(err)
	}
	offset := int(binary.LittleEndian.Uint32(data[8:12]))
	if got, want := offset%0x1000, 0x20; got != want {
		t.Fatalf("first RGDB page offset = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint16(data[18:20]), uint16(0x21); got != want {
		t.Fatalf("initialized state = %#x, want %#x", got, want)
	}
	blockCount := int(binary.LittleEndian.Uint16(data[16:18]))
	largeBlocks := 0
	for block := 0; block < blockCount; block++ {
		size := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		if size > 0x4000 {
			largeBlocks++
			if got := size % 0x1000; got != 0 {
				t.Fatalf("large block size = %#x, want page alignment", size)
			}
			if got := binary.LittleEndian.Uint16(data[offset+22 : offset+24]); got == 0 || got > 255 {
				t.Fatalf("large block entry count = %d, want 1..255", got)
			}
		}
		offset += size
	}
	if largeBlocks != 1 {
		t.Fatalf("large block count = %d, want one", largeBlocks)
	}
}

func TestBuildCREGWindows98UsesPagedNavigationAndDenseBlocks(t *testing.T) {
	root := newRegistryTree("")
	for index := 0; index < 400; index++ {
		setRegistryValue(root, fmt.Sprintf("/Software/K%04d", index), "Value", registryString(regSZ, strings.Repeat("x", 29)))
	}
	data, err := buildCREGWithLayout(root, 0x21, true)
	if err != nil {
		t.Fatal(err)
	}
	offset := int(binary.LittleEndian.Uint32(data[8:12]))
	if got, want := offset%0x1000, 0x20; got != want {
		t.Fatalf("multi-page RGDB offset = %#x, want %#x", got, want)
	}
	rgknSize := int(binary.LittleEndian.Uint32(data[36:40]))
	rgknUsed := int(binary.LittleEndian.Uint32(data[44:48]))
	if free := rgknSize - rgknUsed; free < 0 || free >= 0x1000 {
		t.Fatalf("RGKN free space = %#x, want compact page tail", free)
	}
	blockCount := int(binary.LittleEndian.Uint16(data[16:18]))
	for block := 0; block < blockCount; block++ {
		blockSize := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		if blockSize > 0xffff {
			t.Fatalf("ordinary block %d size = %#x, want no more than %#x", block, blockSize, 0xffff)
		}
		if free := int(binary.LittleEndian.Uint32(data[offset+8 : offset+12])); free < 12 || free >= 0x1000+12 {
			t.Fatalf("block %d free space = %#x, want compact page tail", block, free)
		}
		entryCount := int(binary.LittleEndian.Uint16(data[offset+22 : offset+24]))
		if got := binary.LittleEndian.Uint32(data[offset+24 : offset+28]); got != 0 {
			t.Fatalf("block %d runtime field = %#x, want zero", block, got)
		}
		if got := binary.LittleEndian.Uint32(data[offset+28 : offset+32]); got != 0 {
			t.Fatalf("block %d checksum field = %#x, want zero", block, got)
		}
		cursor := offset + 32
		for entry := 0; entry < entryCount; entry++ {
			allocated := int(binary.LittleEndian.Uint32(data[cursor : cursor+4]))
			used := int(binary.LittleEndian.Uint32(data[cursor+8 : cursor+12]))
			if allocated < used {
				t.Fatalf("block %d record %d allocation = %#x, less than used size %#x", block, entry, allocated, used)
			}
			if allocated != used && (cursor-offset+allocated)%0x1000 != 0 {
				t.Fatalf("block %d padded record %d ends at %#x, want a page boundary", block, entry, cursor-offset+allocated)
			}
			cursor += allocated
		}
		offset += blockSize
	}
	const navigationRecords = 402 // empty root, Software, and the 400 generated keys
	navCursor := 32
	validOffsets := make(map[uint32]bool, navigationRecords)
	for index := 0; index < navigationRecords; index++ {
		if navCursor%0x1000+28 > 0x1000 {
			navCursor = alignCREG(navCursor, 0x1000)
		}
		validOffsets[uint32(navCursor)] = true
		navCursor += 28
	}
	if got := int(binary.LittleEndian.Uint32(data[44:48])); got != navCursor {
		t.Fatalf("RGKN used size = %#x, want %#x", got, navCursor)
	}
	for offset := range validOffsets {
		entry := 32 + int(offset)
		for _, field := range []int{12, 16, 20} {
			link := binary.LittleEndian.Uint32(data[entry+field : entry+field+4])
			if link != 0xffffffff && !validOffsets[link] {
				t.Fatalf("RGKN entry %#x field %d links to invalid offset %#x", offset, field, link)
			}
		}
	}
}

func TestBuildCREGNormalizesWindows1252INFText(t *testing.T) {
	root := newRegistryTree("")
	setRegistryValue(root, "/Software/TypeLib", "Description", registryString(regSZ, "Indeo"+string([]byte{0xae})))
	data, err := buildCREGWithLayout(root, 0x21, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Indeo\xae") {
		t.Fatal("Windows-1252 registry text was not preserved in CREG")
	}
}

func TestBuildCREGCoalescesDefaultValueSpellings(t *testing.T) {
	root := newRegistryTree("")
	setRegistryValue(root, "/Software/Class", "(default)", registryString(regSZ, "first"))
	setRegistryValue(root, "/Software/Class", "", registryString(regSZ, "second"))

	data, err := buildCREGWithLayout(root, 0x21, true)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseCREG(data)
	if err != nil {
		t.Fatal(err)
	}
	key := parsed.subkeys["SOFTWARE"].subkeys["CLASS"]
	if got, want := len(key.values), 1; got != want {
		t.Fatalf("default value count = %d, want %d", got, want)
	}
	value, ok := key.values["(default)"]
	if !ok {
		t.Fatal("parsed CREG is missing its default value")
	}
	if got, want := registryDataString(value), "second"; got != want {
		t.Fatalf("default value = %q, want %q", got, want)
	}
}
