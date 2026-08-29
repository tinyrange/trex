package windows

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"sort"
	"strings"

	"go.starlark.net/starlark"
)

func cregFromPatchesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var patches *starlark.List
	state := 1
	generation := "windows95"
	keysValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("creg_from_patches", args, kwargs, "name", &name, "patches", &patches, "keys?", &keysValue, "state?", &state, "generation?", &generation); err != nil {
		return nil, err
	}
	if state < 0 || state > 0xffff {
		return nil, fmt.Errorf("creg_from_patches: state %d exceeds 16-bit limits", state)
	}
	if generation != "windows95" && generation != "windows95_rtm" && generation != "windows_nashville" && generation != "windows98" && generation != "windowsme" {
		return nil, fmt.Errorf("creg_from_patches: unsupported generation %q", generation)
	}
	root := newRegistryTree("")
	if keysValue != starlark.None {
		keys, ok := keysValue.(*starlark.List)
		if !ok {
			return nil, fmt.Errorf("creg_from_patches: got %s for keys, want list", keysValue.Type())
		}
		for index := 0; index < keys.Len(); index++ {
			keyValue := keys.Index(index)
			parts, err := registryPathParts(keyValue)
			if err != nil {
				return nil, fmt.Errorf("creg_from_patches: keys[%d]: %w", index, err)
			}
			ensureRegistryKeyParts(root, parts)
		}
	}
	if err := applyCREGPatches(root, patches); err != nil {
		return nil, err
	}
	data, err := buildCREGWithGeneration(root, uint16(state), generation)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Name: strings.ToLower(name) + ".dat", Data: data}, nil
}

func applyCREGPatches(root *registryTree, patches *starlark.List) error {
	for index := 0; index < patches.Len(); index++ {
		patch, ok := patches.Index(index).(*starlark.Dict)
		if !ok {
			return fmt.Errorf("creg_from_patches: patch %d is %s, want dict", index, patches.Index(index).Type())
		}
		keyParts, _, err := registryPathFromDict(patch)
		if err != nil {
			return err
		}
		valueName, err := requiredPatchString(patch, "name")
		if err != nil {
			return err
		}
		typeValue, found, err := patch.Get(starlark.String("type"))
		if err != nil || !found {
			if err != nil {
				return err
			}
			return fmt.Errorf("creg_from_patches: patch %d missing type", index)
		}
		value, found, err := patch.Get(starlark.String("value"))
		if err != nil || !found {
			if err != nil {
				return err
			}
			return fmt.Errorf("creg_from_patches: patch %d missing value", index)
		}
		var data registryData
		if typeName, ok := starlark.AsString(typeValue); ok {
			data, err = registryDataFromStarlark(typeName, value)
		} else if typeInt, ok := typeValue.(starlark.Int); ok {
			typ, valid := typeInt.Uint64()
			if !valid || typ > 0xffffffff {
				return fmt.Errorf("creg_from_patches: patch %d has invalid numeric type", index)
			}
			bytes, dataErr := bytesForValue(value)
			if dataErr != nil {
				return dataErr
			}
			data = registryData{typ: uint32(typ), data: bytes}
		} else {
			return fmt.Errorf("creg_from_patches: patch %d type is %s, want string or int", index, typeValue.Type())
		}
		if err != nil {
			return fmt.Errorf("creg_from_patches: patch %d: %w", index, err)
		}
		flags, err := unpackAddRegBehaviorFlags(patch, "creg_from_patches")
		if err != nil {
			return fmt.Errorf("creg_from_patches: patch %d: %w", index, err)
		}
		if err := applyRegistryValueParts(root, keyParts, valueName, data, flags); err != nil {
			return fmt.Errorf("creg_from_patches: patch %d: %w", index, err)
		}
	}
	return nil
}

type cregKeyRecord struct {
	tree                         *registryTree
	parent, firstChild, nextPeer int
	depth                        int
	navOffset                    int
	block                        int
	id                           uint16
	record                       []byte
}

func buildCREG(root *registryTree) ([]byte, error) {
	return buildCREGWithLayout(root, 1, false)
}

func buildCREGWithLayout(root *registryTree, state uint16, windows98 bool) ([]byte, error) {
	generation := "windows95"
	if windows98 {
		generation = "windows98"
	}
	return buildCREGWithGeneration(root, state, generation)
}

func buildCREGWithGeneration(root *registryTree, state uint16, generation string) ([]byte, error) {
	windows95RTM := generation == "windows95_rtm"
	nashville := generation == "windows_nashville"
	if generation != "windows95" && !windows95RTM && !nashville && generation != "windows98" && generation != "windowsme" {
		return nil, fmt.Errorf("creg: unsupported generation %q", generation)
	}
	records := make([]cregKeyRecord, 0)
	var walk func(*registryTree, int, int) (int, error)
	walk = func(tree *registryTree, parent, depth int) (int, error) {
		minimumValueCapacity := 0
		if nashville {
			minimumValueCapacity = 13
		}
		encoded, err := encodeCREGKey(tree, windows95RTM || nashville, windows95RTM, minimumValueCapacity)
		if err != nil {
			return 0, err
		}
		index := len(records)
		records = append(records, cregKeyRecord{tree: tree, parent: parent, depth: depth, firstChild: -1, nextPeer: -1, record: encoded})
		children := make([]*registryTree, 0, len(tree.subkeys))
		for _, child := range tree.subkeys {
			children = append(children, child)
		}
		sort.Slice(children, func(i, j int) bool {
			left, right := strings.ToUpper(children[i].name), strings.ToUpper(children[j].name)
			priority := func(name string) int {
				if name == "SOFTWARE" || name == "MICROSOFT" || name == "WINDOWS" || name == "CURRENTVERSION" {
					return 0
				}
				return 1
			}
			if priority(left) != priority(right) {
				return priority(left) < priority(right)
			}
			return left < right
		})
		previous := -1
		for _, child := range children {
			childIndex, err := walk(child, index, depth+1)
			if err != nil {
				return 0, err
			}
			if records[index].firstChild < 0 {
				records[index].firstChild = childIndex
			}
			if previous >= 0 {
				records[previous].nextPeer = childIndex
			}
			previous = childIndex
		}
		return index, nil
	}
	if _, err := walk(root, -1, 0); err != nil {
		return nil, err
	}
	// Nashville can read the compact CREG allocation used by Windows 95. Its
	// native multi-page writer also persists opaque live-memory descriptors in
	// RGDB; a newly assembled hive must not invent those. Keep the portable
	// compact layout and reproduce Nashville's per-key growth reserve instead.
	modern := generation == "windows98" || generation == "windowsme"
	// The empty hierarchy root exists only in RGKN. Windows-created CREG hives
	// use the absent identity sentinel for it and begin RGDB identities with the
	// first named key.
	records[0].record = nil

	type blockRange struct{ first, end, size int }
	blocks := make([]blockRange, 0)
	// RGDB identities restart in every block. Windows 95 keeps blocks within a
	// 16 KiB extent. Windows 98 instead fills up to 255 records and then rounds
	// the result to a page, subject to the format's 16-bit block-size field.
	for first := 1; first < len(records); {
		size, end := 32, first
		blockLimit := 0x4000
		if modern || windows95RTM || nashville {
			blockLimit = 0xffff
		}
		for end < len(records) {
			if end-first == 255 {
				break
			}
			recordSize := len(records[end].record)
			if modern && recordSize <= 0x1000 && end > first {
				// RGDB starts with one 4 KiB allocation containing its header,
				// then grows in 8 KiB extents. A small key may not straddle one
				// of those allocation boundaries.
				boundary := 0x1000
				if size >= 0x1000 {
					boundary += ((size-0x1000)/0x2000 + 1) * 0x2000
				}
				if size+recordSize > boundary {
					if alignCREG(boundary+12, 0x1000) > blockLimit {
						break
					}
					// The later allocator never starts a small record in the tail of
					// one page and finishes it in the next. REGEDIT accounts for the
					// gap by extending the preceding record's allocation while leaving
					// that record's used-size field unchanged.
					padding := boundary - size
					previous := end - 1
					padded := make([]byte, len(records[previous].record)+padding)
					copy(padded, records[previous].record)
					binary.LittleEndian.PutUint32(padded[0:4], uint32(len(padded)))
					records[previous].record = padded
					size += padding
				}
			}
			next := size + recordSize
			alignment := 0x1000
			reserve := 12
			if windows95RTM || nashville {
				reserve += 0x1000
			}
			if alignCREG(next+reserve, alignment) > blockLimit {
				if end > first {
					break
				}
				return nil, fmt.Errorf("creg: key %q exceeds an RGDB block", records[end].tree.name)
			}
			if next+12 > defaultBinaryBuilderLimit {
				return nil, fmt.Errorf("creg: key %q exceeds the hive size limit", records[end].tree.name)
			}
			size, end = next, end+1
		}
		alignment := 0x1000
		reserve := 12
		if windows95RTM || nashville {
			reserve += 0x1000
		}
		blockSize := alignCREG(size+reserve, alignment)
		if blockSize > blockLimit {
			return nil, fmt.Errorf("creg: key %q exceeds the 16-bit RGDB block limit", records[first].tree.name)
		}
		for index := first; index < end; index++ {
			records[index].block = len(blocks)
			records[index].id = uint16(index - first)
		}
		blocks = append(blocks, blockRange{first, end, blockSize})
		first = end
	}
	if generation == "windowsme" {
		// ME's registry allocator keeps one empty 32 KiB block ready for the
		// first live transaction. REGEDIT /C emits this reserve even when the
		// preceding block has free space; without it, SetupX reports a disk-write
		// failure while creating its device index on the first graphical boot.
		blocks = append(blocks, blockRange{first: len(records), end: len(records), size: 0x8000})
	}
	if len(blocks) == 0 {
		blocks = append(blocks, blockRange{first: 0, end: 0, size: 0x1020})
	}
	if len(blocks) > 0xffff {
		return nil, fmt.Errorf("creg: too many RGDB blocks")
	}

	navCursor := 32
	for index := range records {
		// Windows 98 navigation records are addressed in 4 KiB pages and do
		// not straddle a page boundary.  Windows 95's writer uses a dense
		// navigation table instead.
		pageGap := modern && navCursor%0x1000+28 > 0x1000
		// ME's initial RGKN allocation includes the leading navigation header;
		// page-straddle avoidance begins with the second 4 KiB page.
		if generation == "windowsme" && navCursor < 0x1000 {
			pageGap = false
		}
		if pageGap {
			navCursor = alignCREG(navCursor, 0x1000)
		}
		records[index].navOffset = navCursor
		navCursor += 28
	}
	rgknUsed := navCursor
	// Windows 95 aligns RGDB itself. Later REGEDIT versions instead allocate
	// RGKN in whole pages, leaving RGDB 32 bytes past a file-page boundary.
	rgknSize := alignCREG(rgknUsed+32, 0x1000) - 32
	if windows95RTM {
		// RTM allocates RGKN in complete pages and begins RGDB 32 bytes past a
		// file-page boundary. This differs from later Windows 95 REGEDIT output,
		// which compacts the navigation tail so RGDB itself is page-aligned.
		rgknSize = alignCREG(rgknUsed, 0x1000)
	}
	if modern {
		rgknSize = alignCREG(rgknUsed, 0x1000)
	}
	rgdbOffset := 32 + rgknSize
	total := rgdbOffset
	for _, block := range blocks {
		total += block.size
	}
	output := make([]byte, total)
	copy(output[:4], "CREG")
	// Windows 9x stores the format version as minor,major words and repeats it
	// later in the header.  Leaving these fields zero produces a structurally
	// readable hive which CONFIGMG nevertheless rejects as an unknown format.
	binary.LittleEndian.PutUint16(output[4:6], 0)
	binary.LittleEndian.PutUint16(output[6:8], 1)
	binary.LittleEndian.PutUint32(output[8:12], uint32(rgdbOffset))
	binary.LittleEndian.PutUint16(output[16:18], uint16(len(blocks)))
	// Windows 95's real-mode registry loader requires the initialized-hive state
	// word. REGEDIT /C emits one here for both machine and user hives.
	binary.LittleEndian.PutUint16(output[18:20], state)
	binary.LittleEndian.PutUint16(output[20:22], 0)
	binary.LittleEndian.PutUint16(output[22:24], 1)
	if nashville {
		// Nashville's REGEDIT emits these generation markers unchanged for both
		// single-page and multi-page hives. They are part of its persistent CREG
		// header state, not content checksums.
		binary.LittleEndian.PutUint32(output[12:16], 0xb8b49dbc)
	}

	rgkn := output[32 : 32+rgknSize]
	copy(rgkn[:4], "RGKN")
	binary.LittleEndian.PutUint32(rgkn[4:8], uint32(rgknSize))
	binary.LittleEndian.PutUint32(rgkn[8:12], 32)
	binary.LittleEndian.PutUint32(rgkn[12:16], uint32(rgknUsed))
	rgknFlags := uint32(8)
	if windows95RTM {
		rgknFlags = 9
	} else if nashville {
		rgknFlags = 0x09
	}
	binary.LittleEndian.PutUint32(rgkn[16:20], rgknFlags)
	if nashville {
		binary.LittleEndian.PutUint32(rgkn[20:24], 0x31b49360)
	}
	for index, record := range records {
		entry := rgkn[record.navOffset : record.navOffset+28]
		binary.LittleEndian.PutUint32(entry[4:8], cregNameHash(record.tree.name))
		classReference := uint32(0xffffffff)
		if (windows95RTM || nashville) && index == 0 {
			// RTM's synthetic hierarchy root has a cleared cache link. Named
			// navigation records use the absent sentinel, including keys that own
			// values; their value-entry cache words are independently cleared.
			classReference = 0
		} else if windows95RTM || nashville {
			// RTM leaves the live value-cache link absent for every navigation
			// record. The registry manager populates it after loading the RGDB
			// record; pre-seeding offset 4 is only tolerated by later loaders.
			classReference = 0xffffffff
		} else if index == 0 {
			if generation == "windows98" {
				classReference = 0x3b000123
			} else {
				classReference = 0
			}
		} else if generation == "windowsme" {
			// REGEDIT initializes a bounded first-page key cache. Direct children
			// of the synthetic root retain the absent sentinel; descendants in the
			// first 145 navigation slots reference record offset 4, and later slots
			// are left clear for the live loader to populate.
			if record.depth >= 2 && index < 145 {
				classReference = 4
			} else if record.depth >= 2 {
				classReference = 0
			}
		} else if _, present := record.tree.values["(default)"]; present {
			// The original Windows 95/98 writers cache offset 4 only when the
			// key owns an unnamed default value. Marking every non-empty key as
			// cached makes the Windows 95 VXDLDR traversal follow named-value
			// metadata as though it were a resolved default-value entry.
			classReference = 4
		}
		binary.LittleEndian.PutUint32(entry[8:12], classReference)
		binary.LittleEndian.PutUint32(entry[12:16], cregNavOffset(records, record.parent))
		binary.LittleEndian.PutUint32(entry[16:20], cregNavOffset(records, record.firstChild))
		binary.LittleEndian.PutUint32(entry[20:24], cregNavOffset(records, record.nextPeer))
		id := uint32(record.block)<<16 | uint32(record.id)
		if index == 0 {
			id = 0xffffffff
		}
		binary.LittleEndian.PutUint32(entry[24:28], id)
	}
	freeNavigation := rgkn[rgknUsed:]
	binary.LittleEndian.PutUint32(freeNavigation[0:4], 0x80000000)
	binary.LittleEndian.PutUint32(freeNavigation[4:8], uint32(len(freeNavigation)))
	binary.LittleEndian.PutUint32(freeNavigation[8:12], 0xffffffff)
	if generation == "windowsme" {
		// ME preinitializes every remaining 28-byte navigation slot. The first
		// slot describes the whole free extent above; subsequent slots carry the
		// allocator's free marker and record-data offset.
		for cursor := 28; cursor+28 <= len(freeNavigation); cursor += 28 {
			binary.LittleEndian.PutUint32(freeNavigation[cursor:cursor+4], 0x80000000)
			binary.LittleEndian.PutUint32(freeNavigation[cursor+8:cursor+12], 4)
		}
	}
	offset := rgdbOffset
	for blockIndex, block := range blocks {
		data := output[offset : offset+block.size]
		copy(data[:4], "RGDB")
		binary.LittleEndian.PutUint32(data[4:8], uint32(block.size))
		cursor := 32
		for index := block.first; index < block.end; index++ {
			// All CREG generations persist the complete block/slot identity.
			// Omitting the block word remains readable offline, but Windows 95's
			// live allocator then resolves records in later RGDB blocks against
			// block zero and fails while VXDLDR initializes the static VxD graph.
			identity := uint32(records[index].block)<<16 | uint32(records[index].id)
			binary.LittleEndian.PutUint32(records[index].record[4:8], identity)
			copy(data[cursor:], records[index].record)
			cursor += len(records[index].record)
		}
		freeSize := block.size - cursor
		binary.LittleEndian.PutUint32(data[8:12], uint32(freeSize))
		blockFlags := uint16(0x0008)
		if windows95RTM {
			blockFlags = 0x0009
		} else if nashville {
			blockFlags = 0x0009
		}
		binary.LittleEndian.PutUint16(data[12:14], blockFlags)
		binary.LittleEndian.PutUint16(data[14:16], uint16(blockIndex))
		binary.LittleEndian.PutUint32(data[16:20], uint32(cursor))
		entryCount := block.end - block.first
		if entryCount > 0 {
			binary.LittleEndian.PutUint16(data[20:22], uint16(entryCount-1))
		}
		binary.LittleEndian.PutUint16(data[22:24], uint16(entryCount))
		// The final two header words are runtime/checksum state, not links to
		// the next RGDB section. REGEDIT and SCANREG emit them cleared; inventing
		// a chain marker here makes Windows 98's Registry Checker reject an
		// otherwise readable hive during its first integrity scan.
		binary.LittleEndian.PutUint32(data[cursor:cursor+4], uint32(freeSize))
		binary.LittleEndian.PutUint32(data[cursor+4:cursor+8], 0xffffffff)
		binary.LittleEndian.PutUint32(data[cursor+8:cursor+12], 0xffffffff)
		offset += block.size
	}
	return output, nil
}

func encodeCREGKey(tree *registryTree, clearedValueCache, terminateStrings bool, minimumValueCapacity int) ([]byte, error) {
	name, err := encodeWindows1252(tree.name)
	if err != nil {
		return nil, fmt.Errorf("creg: key name %q: %w", tree.name, err)
	}
	valueNames := make([]string, 0, len(tree.values))
	for name := range tree.values {
		valueNames = append(valueNames, name)
	}
	// REGEDIT keeps the value table in ascending case-insensitive order. The
	// unnamed default value sorts first and is identified by a zero name length.
	sort.Slice(valueNames, func(i, j int) bool {
		left, right := strings.ToUpper(valueNames[i]), strings.ToUpper(valueNames[j])
		return left < right
	})
	values := make([]byte, 0)
	for _, valueName := range valueNames {
		encodedName := []byte(nil)
		if valueName != "(default)" {
			encodedName, err = encodeWindows1252(valueName)
			if err != nil {
				return nil, err
			}
		}
		value := tree.values[valueName]
		encodedData, err := encodeCREGValueData(value, terminateStrings)
		if err != nil {
			return nil, fmt.Errorf("creg: key %q value %q type %d data %x: %w", tree.name, valueName, value.typ, value.data, err)
		}
		if len(encodedName) > 0xffff || len(encodedData) > 0xffff {
			return nil, fmt.Errorf("creg: value %q exceeds 16-bit limits", valueName)
		}
		entry := make([]byte, 12+len(encodedName)+len(encodedData))
		binary.LittleEndian.PutUint32(entry[0:4], value.typ)
		// Original Windows 95 stores a cleared live cache reference. Later
		// REGEDIT generations use the absent sentinel and populate it on demand.
		if !clearedValueCache {
			binary.LittleEndian.PutUint32(entry[4:8], 0xffffffff)
		}
		binary.LittleEndian.PutUint16(entry[8:10], uint16(len(encodedName)))
		binary.LittleEndian.PutUint16(entry[10:12], uint16(len(encodedData)))
		copy(entry[12:], encodedName)
		copy(entry[12+len(encodedName):], encodedData)
		values = append(values, entry...)
	}
	if len(name) > 0xffff || len(valueNames) > 0xffff {
		return nil, fmt.Errorf("creg: key %q metadata exceeds 16-bit limits", tree.name)
	}
	usedLength := 20 + len(name) + len(values)
	allocatedValueCapacity := max(len(values), minimumValueCapacity)
	allocatedLength := 20 + len(name) + allocatedValueCapacity
	record := make([]byte, allocatedLength)
	binary.LittleEndian.PutUint32(record[0:4], uint32(allocatedLength))
	// For records containing values, Windows stores the complete used record
	// size here as well as in the leading length field. Its allocator consumes
	// this value when the live registry grows during startup.
	binary.LittleEndian.PutUint32(record[8:12], uint32(usedLength))
	binary.LittleEndian.PutUint16(record[12:14], uint16(len(name)))
	binary.LittleEndian.PutUint16(record[14:16], uint16(len(valueNames)))
	copy(record[20:], name)
	copy(record[20+len(name):], values)
	return record, nil
}

func encodeCREGValueData(value registryData, terminateStrings bool) ([]byte, error) {
	switch value.typ {
	case regSZ, regExpandSZ:
		encoded, err := encodeWindows1252(strings.TrimSuffix(decodeUTF16LE(value.data), "\x00"))
		if err != nil {
			return nil, err
		}
		if terminateStrings {
			// The original Windows 95 writer terminates every REG_SZ payload in
			// CREG. Later 9x writers tolerate or deliberately emit unterminated
			// strings, but RTM's loader uses the terminator while populating its
			// value cache and can reject a multi-block machine hive without it.
			encoded = append(encoded, 0)
		}
		return encoded, nil
	case regMultiSZ:
		return encodeWindows1252(decodeUTF16LE(value.data))
	default:
		return append([]byte(nil), value.data...), nil
	}
}

func encodeWindows1252(value string) ([]byte, error) {
	var special = map[rune]byte{
		'€': 0x80, '‚': 0x82, 'ƒ': 0x83, '„': 0x84, '…': 0x85, '†': 0x86, '‡': 0x87,
		'ˆ': 0x88, '‰': 0x89, 'Š': 0x8a, '‹': 0x8b, 'Œ': 0x8c, 'Ž': 0x8e,
		'‘': 0x91, '’': 0x92, '“': 0x93, '”': 0x94, '•': 0x95, '–': 0x96, '—': 0x97,
		'˜': 0x98, '™': 0x99, 'š': 0x9a, '›': 0x9b, 'œ': 0x9c, 'ž': 0x9e, 'Ÿ': 0x9f,
	}
	out := make([]byte, 0, len(value))
	for _, character := range value {
		if character <= 0xff && !(character >= 0x80 && character <= 0x9f) {
			out = append(out, byte(character))
		} else if encoded, ok := special[character]; ok {
			out = append(out, encoded)
		} else {
			return nil, fmt.Errorf("character %U is not representable in Windows-1252", character)
		}
	}
	return out, nil
}

func cregNameHash(name string) uint32 {
	var hash uint32
	for _, character := range strings.ToUpper(name) {
		if character < 0x80 {
			hash += uint32(character)
		}
	}
	return hash
}

func cregNavOffset(records []cregKeyRecord, index int) uint32 {
	if index < 0 {
		return 0xffffffff
	}
	return uint32(records[index].navOffset)
}

func alignCREG(value, alignment int) int { return (value + alignment - 1) &^ (alignment - 1) }
