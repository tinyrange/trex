package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"sort"
	"strings"

	"go.starlark.net/starlark"
)

func cregCompareBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var leftValue, rightValue starlark.Value
	if err := starlark.UnpackArgs("creg_compare", args, kwargs, "left", &leftValue, "right", &rightValue); err != nil {
		return nil, err
	}
	leftFile, ok := leftValue.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("creg_compare: left is %s, want file", leftValue.Type())
	}
	rightFile, ok := rightValue.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("creg_compare: right is %s, want file", rightValue.Type())
	}
	left, err := starfile.ReadAll(leftFile)
	if err != nil {
		return nil, err
	}
	right, err := starfile.ReadAll(rightFile)
	if err != nil {
		return nil, err
	}
	return compareCREGLayout(left, right)
}

func compareCREGLayout(left, right []byte) (starlark.Value, error) {
	leftCategories, err := classifyCREGBytes(left)
	if err != nil {
		return nil, fmt.Errorf("creg_compare: left: %w", err)
	}
	rightCategories, err := classifyCREGBytes(right)
	if err != nil {
		return nil, fmt.Errorf("creg_compare: right: %w", err)
	}
	counts := make(map[string]int)
	samples := starlark.NewList(nil)
	common := min(len(left), len(right))
	for offset := 0; offset < common; offset++ {
		if left[offset] == right[offset] {
			continue
		}
		category := leftCategories[offset]
		if rightCategories[offset] != category {
			category = "layout_mismatch"
		}
		counts[category]++
		if samples.Len() < 64 {
			sample := starlark.NewDict(4)
			_ = sample.SetKey(starlark.String("category"), starlark.String(category))
			_ = sample.SetKey(starlark.String("offset"), starlark.MakeInt(offset))
			_ = sample.SetKey(starlark.String("left"), starlark.MakeInt(int(left[offset])))
			_ = sample.SetKey(starlark.String("right"), starlark.MakeInt(int(right[offset])))
			_ = samples.Append(sample)
		}
	}
	if len(left) != len(right) {
		counts["file_size"] = max(len(left), len(right)) - common
	}
	countDict := starlark.NewDict(len(counts))
	categoryNames := make([]string, 0, len(counts))
	for category := range counts {
		categoryNames = append(categoryNames, category)
	}
	sort.Strings(categoryNames)
	for _, category := range categoryNames {
		_ = countDict.SetKey(starlark.String(category), starlark.MakeInt(counts[category]))
	}
	result := starlark.NewDict(5)
	_ = result.SetKey(starlark.String("equal"), starlark.Bool(bytes.Equal(left, right)))
	_ = result.SetKey(starlark.String("left_size"), starlark.MakeInt(len(left)))
	_ = result.SetKey(starlark.String("right_size"), starlark.MakeInt(len(right)))
	_ = result.SetKey(starlark.String("differences"), countDict)
	_ = result.SetKey(starlark.String("samples"), samples)
	if recordSizes, err := compareCREGRecordSizes(left, right); err == nil {
		_ = result.SetKey(starlark.String("record_sizes"), recordSizes)
	}
	return result, nil
}

func compareCREGRecordSizes(left, right []byte) (starlark.Value, error) {
	leftOffset := int(binary.LittleEndian.Uint32(left[8:12]))
	rightOffset := int(binary.LittleEndian.Uint32(right[8:12]))
	leftBlocks := int(binary.LittleEndian.Uint16(left[16:18]))
	rightBlocks := int(binary.LittleEndian.Uint16(right[16:18]))
	if leftBlocks != rightBlocks {
		return starlark.None, nil
	}
	samples := starlark.NewList(nil)
	different := 0
	allocatedDelta := 0
	usedDelta := 0
	for block := 0; block < leftBlocks; block++ {
		leftEntries := int(binary.LittleEndian.Uint16(left[leftOffset+22 : leftOffset+24]))
		rightEntries := int(binary.LittleEndian.Uint16(right[rightOffset+22 : rightOffset+24]))
		if leftEntries != rightEntries {
			return starlark.None, nil
		}
		leftCursor, rightCursor := leftOffset+32, rightOffset+32
		for entry := 0; entry < leftEntries; entry++ {
			leftAllocated := int(binary.LittleEndian.Uint32(left[leftCursor : leftCursor+4]))
			leftUsed := int(binary.LittleEndian.Uint32(left[leftCursor+8 : leftCursor+12]))
			rightAllocated := int(binary.LittleEndian.Uint32(right[rightCursor : rightCursor+4]))
			rightUsed := int(binary.LittleEndian.Uint32(right[rightCursor+8 : rightCursor+12]))
			leftNameLength := int(binary.LittleEndian.Uint16(left[leftCursor+12 : leftCursor+14]))
			rightNameLength := int(binary.LittleEndian.Uint16(right[rightCursor+12 : rightCursor+14]))
			leftName := normalizeWindows1252Text(string(left[leftCursor+20 : leftCursor+20+leftNameLength]))
			rightName := normalizeWindows1252Text(string(right[rightCursor+20 : rightCursor+20+rightNameLength]))
			if leftAllocated != rightAllocated || leftUsed != rightUsed || leftName != rightName {
				different++
				allocatedDelta += rightAllocated - leftAllocated
				usedDelta += rightUsed - leftUsed
				if samples.Len() < 64 {
					sample := starlark.NewDict(8)
					_ = sample.SetKey(starlark.String("block"), starlark.MakeInt(block))
					_ = sample.SetKey(starlark.String("entry"), starlark.MakeInt(entry))
					_ = sample.SetKey(starlark.String("left_name"), starlark.String(leftName))
					_ = sample.SetKey(starlark.String("right_name"), starlark.String(rightName))
					_ = sample.SetKey(starlark.String("left_allocated"), starlark.MakeInt(leftAllocated))
					_ = sample.SetKey(starlark.String("right_allocated"), starlark.MakeInt(rightAllocated))
					_ = sample.SetKey(starlark.String("left_used"), starlark.MakeInt(leftUsed))
					_ = sample.SetKey(starlark.String("right_used"), starlark.MakeInt(rightUsed))
					_ = samples.Append(sample)
				}
			}
			leftCursor += leftAllocated
			rightCursor += rightAllocated
		}
		leftOffset += int(binary.LittleEndian.Uint32(left[leftOffset+4 : leftOffset+8]))
		rightOffset += int(binary.LittleEndian.Uint32(right[rightOffset+4 : rightOffset+8]))
	}
	result := starlark.NewDict(4)
	_ = result.SetKey(starlark.String("different"), starlark.MakeInt(different))
	_ = result.SetKey(starlark.String("allocated_delta"), starlark.MakeInt(allocatedDelta))
	_ = result.SetKey(starlark.String("used_delta"), starlark.MakeInt(usedDelta))
	_ = result.SetKey(starlark.String("samples"), samples)
	return result, nil
}

func classifyCREGBytes(data []byte) ([]string, error) {
	if _, err := parseCREG(data); err != nil {
		return nil, err
	}
	categories := make([]string, len(data))
	mark := func(start, end int, category string) {
		if start < 0 {
			start = 0
		}
		if end > len(categories) {
			end = len(categories)
		}
		for offset := start; offset < end; offset++ {
			categories[offset] = category
		}
	}
	mark(0, len(data), "unclassified")
	mark(0, 32, "creg_header")
	rgknSize := int(binary.LittleEndian.Uint32(data[36:40]))
	rgknUsed := int(binary.LittleEndian.Uint32(data[44:48]))
	mark(32, 64, "rgkn_header")
	mark(64, 32+rgknUsed, "rgkn_padding")
	mark(32+rgknUsed, 32+rgknSize, "rgkn_free")
	rootOffset := binary.LittleEndian.Uint32(data[40:44])
	seenNavigation := make(map[uint32]bool)
	var visitNavigation func(uint32) error
	visitNavigation = func(relative uint32) error {
		if relative == 0xffffffff || seenNavigation[relative] {
			return nil
		}
		if relative < 32 || uint64(relative)+28 > uint64(rgknUsed) {
			return fmt.Errorf("invalid RGKN record offset %#x", relative)
		}
		seenNavigation[relative] = true
		offset := 32 + int(relative)
		mark(offset, offset+28, "rgkn_record")
		mark(offset+8, offset+12, "rgkn_runtime")
		if err := visitNavigation(binary.LittleEndian.Uint32(data[offset+16 : offset+20])); err != nil {
			return err
		}
		return visitNavigation(binary.LittleEndian.Uint32(data[offset+20 : offset+24]))
	}
	if err := visitNavigation(rootOffset); err != nil {
		return nil, err
	}

	offset := int(binary.LittleEndian.Uint32(data[8:12]))
	blocks := int(binary.LittleEndian.Uint16(data[16:18]))
	for block := 0; block < blocks; block++ {
		blockSize := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		blockEnd := offset + blockSize
		mark(offset, offset+24, "rgdb_header")
		mark(offset+24, offset+32, "rgdb_runtime")
		entries := int(binary.LittleEndian.Uint16(data[offset+22 : offset+24]))
		cursor := offset + 32
		for entry := 0; entry < entries; entry++ {
			allocated := int(binary.LittleEndian.Uint32(data[cursor : cursor+4]))
			used := int(binary.LittleEndian.Uint32(data[cursor+8 : cursor+12]))
			nameLength := int(binary.LittleEndian.Uint16(data[cursor+12 : cursor+14]))
			valueCount := int(binary.LittleEndian.Uint16(data[cursor+14 : cursor+16]))
			mark(cursor, cursor+used, "key_record")
			mark(cursor+used, cursor+allocated, "key_slack")
			valueOffset := cursor + 20 + nameLength
			for value := 0; value < valueCount; value++ {
				valueNameLength := int(binary.LittleEndian.Uint16(data[valueOffset+8 : valueOffset+10]))
				valueDataLength := int(binary.LittleEndian.Uint16(data[valueOffset+10 : valueOffset+12]))
				mark(valueOffset+4, valueOffset+8, "value_runtime")
				valueOffset += 12 + valueNameLength + valueDataLength
			}
			cursor += allocated
		}
		mark(cursor, blockEnd, "rgdb_free")
		offset = blockEnd
	}
	return categories, nil
}

type cregDataRecord struct {
	name   string
	values map[string]registryData
}

type cregNavigationRecord struct {
	parent, child, peer uint32
	identity            uint32
}

func cregPatchesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	root, err := unpackCREGFile("creg_patches", args, kwargs)
	if err != nil {
		return nil, err
	}
	patches := starlark.NewList(nil)
	if err := appendCREGTreePatches(root, nil, patches); err != nil {
		return nil, err
	}
	return patches, nil
}

func cregKeysBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	root, err := unpackCREGFile("creg_keys", args, kwargs)
	if err != nil {
		return nil, err
	}
	keys := starlark.NewList(nil)
	if err := appendCREGTreeKeys(root, nil, keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func unpackCREGFile(operation string, args starlark.Tuple, kwargs []starlark.Tuple) (*registryTree, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs(operation, args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("%s: got %s, want file", operation, value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	root, err := parseCREG(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}
	return root, nil
}

func appendCREGTreePatches(key *registryTree, parts []string, patches *starlark.List) error {
	valueNames := make([]string, 0, len(key.values))
	for name := range key.values {
		valueNames = append(valueNames, name)
	}
	sort.Slice(valueNames, func(i, j int) bool { return strings.ToUpper(valueNames[i]) < strings.ToUpper(valueNames[j]) })
	for _, name := range valueNames {
		patch, err := registryPatchDict(registryDisplayPath(parts), parts, name, key.values[name])
		if err != nil {
			return err
		}
		if err := patches.Append(patch); err != nil {
			return err
		}
	}
	children := sortedRegistryChildren(key)
	for _, child := range children {
		if err := appendCREGTreePatches(child, appendRegistryPathPart(parts, child.name), patches); err != nil {
			return err
		}
	}
	return nil
}

func appendCREGTreeKeys(key *registryTree, parts []string, keys *starlark.List) error {
	// Preserve components rather than flattening them into a slash-delimited
	// display path. A slash is legal in a registry key name (MIME content-type
	// keys use it extensively), so the display form cannot be parsed back
	// without changing the tree.
	if err := keys.Append(registryPathList(parts)); err != nil {
		return err
	}
	for _, child := range sortedRegistryChildren(key) {
		if err := appendCREGTreeKeys(child, appendRegistryPathPart(parts, child.name), keys); err != nil {
			return err
		}
	}
	return nil
}

func parseCREG(data []byte) (*registryTree, error) {
	if len(data) < 64 || string(data[:4]) != "CREG" {
		return nil, fmt.Errorf("invalid CREG header")
	}
	rgdbOffset := int(binary.LittleEndian.Uint32(data[8:12]))
	blockCount := int(binary.LittleEndian.Uint16(data[16:18]))
	if string(data[32:36]) != "RGKN" {
		return nil, fmt.Errorf("invalid RGKN signature")
	}
	rgknSize := int(binary.LittleEndian.Uint32(data[36:40]))
	rootOffset := binary.LittleEndian.Uint32(data[40:44])
	rgknUsed := int(binary.LittleEndian.Uint32(data[44:48]))
	if rgknSize < 32 || 32+rgknSize > len(data) || rgdbOffset != 32+rgknSize || rgknUsed < 32 || rgknUsed > rgknSize {
		return nil, fmt.Errorf("invalid RGKN bounds")
	}
	if blockCount < 1 || rgdbOffset >= len(data) {
		return nil, fmt.Errorf("invalid RGDB table")
	}

	dataRecords := make(map[uint32]cregDataRecord)
	blockOffset := rgdbOffset
	for blockIndex := 0; blockIndex < blockCount; blockIndex++ {
		if blockOffset+32 > len(data) || string(data[blockOffset:blockOffset+4]) != "RGDB" {
			return nil, fmt.Errorf("RGDB block %d has invalid header", blockIndex)
		}
		blockSize := int(binary.LittleEndian.Uint32(data[blockOffset+4 : blockOffset+8]))
		blockIdentity := uint32(binary.LittleEndian.Uint16(data[blockOffset+14 : blockOffset+16]))
		entryCount := int(binary.LittleEndian.Uint16(data[blockOffset+22 : blockOffset+24]))
		if blockSize < 44 || blockOffset+blockSize > len(data) {
			return nil, fmt.Errorf("RGDB block %d has invalid size", blockIndex)
		}
		cursor := blockOffset + 32
		for entryIndex := 0; entryIndex < entryCount; entryIndex++ {
			if cursor+20 > blockOffset+blockSize {
				return nil, fmt.Errorf("RGDB block %d record %d is truncated", blockIndex, entryIndex)
			}
			allocated := int(binary.LittleEndian.Uint32(data[cursor : cursor+4]))
			used := int(binary.LittleEndian.Uint32(data[cursor+8 : cursor+12]))
			if allocated < 20 || cursor+allocated > blockOffset+blockSize || used < 20 || used > allocated {
				return nil, fmt.Errorf("RGDB block %d record %d has invalid bounds", blockIndex, entryIndex)
			}
			identity := binary.LittleEndian.Uint32(data[cursor+4 : cursor+8])
			// Early Windows writers store only the record-local low word and
			// rely on the RGDB header for the block number. Later writers cache
			// the complete identity in each record. Normalize both forms.
			if identity>>16 == 0 && blockIdentity != 0 {
				identity |= blockIdentity << 16
			}
			record, err := parseCREGDataRecord(data[cursor : cursor+used])
			if err != nil {
				return nil, fmt.Errorf("RGDB block %d record %d: %w", blockIndex, entryIndex, err)
			}
			// Windows leaves zeroed allocation records behind when a key is
			// deleted or moved. Their stale identities can duplicate a live
			// record, so discard an empty duplicate while still rejecting two
			// different live records with the same identity.
			if existing, exists := dataRecords[identity]; exists {
				if record.name == "" && len(record.values) == 0 {
					cursor += allocated
					continue
				}
				if existing.name == "" && len(existing.values) == 0 {
					dataRecords[identity] = record
					cursor += allocated
					continue
				}
				return nil, fmt.Errorf("duplicate RGDB identity %#x", identity)
			}
			dataRecords[identity] = record
			cursor += allocated
		}
		blockOffset += blockSize
	}
	if blockOffset != len(data) {
		return nil, fmt.Errorf("CREG has %d trailing bytes", len(data)-blockOffset)
	}

	navigation := func(relative uint32) (cregNavigationRecord, error) {
		if relative == 0xffffffff || relative < 32 || uint64(relative)+28 > uint64(rgknUsed) {
			return cregNavigationRecord{}, fmt.Errorf("invalid RGKN record offset %#x", relative)
		}
		offset := 32 + int(relative)
		return cregNavigationRecord{
			parent:   binary.LittleEndian.Uint32(data[offset+12 : offset+16]),
			child:    binary.LittleEndian.Uint32(data[offset+16 : offset+20]),
			peer:     binary.LittleEndian.Uint32(data[offset+20 : offset+24]),
			identity: binary.LittleEndian.Uint32(data[offset+24 : offset+28]),
		}, nil
	}
	visited := make(map[uint32]bool)
	var build func(uint32, uint32, bool) (*registryTree, error)
	build = func(relative, expectedParent uint32, isRoot bool) (*registryTree, error) {
		if visited[relative] {
			return nil, fmt.Errorf("RGKN cycle at %#x", relative)
		}
		visited[relative] = true
		nav, err := navigation(relative)
		if err != nil {
			return nil, err
		}
		if nav.parent != expectedParent {
			return nil, fmt.Errorf("RGKN record %#x has parent %#x, want %#x", relative, nav.parent, expectedParent)
		}
		tree := newRegistryTree("")
		if !isRoot {
			record, ok := dataRecords[nav.identity]
			if !ok {
				return nil, fmt.Errorf("RGKN record %#x references missing identity %#x", relative, nav.identity)
			}
			tree.name = record.name
			tree.values = record.values
		} else {
			// The synthetic hierarchy root has no RGDB key of its own, but the
			// original Windows 95 RTM writer leaves allocator/cache state in the
			// navigation record's final word. Later REGEDIT generations commonly
			// use the absent sentinel here. Neither value names the root, so do not
			// interpret it as an RGDB identity.
		}
		for childOffset := nav.child; childOffset != 0xffffffff; {
			child, err := build(childOffset, relative, false)
			if err != nil {
				return nil, err
			}
			key := strings.ToUpper(child.name)
			if _, exists := tree.subkeys[key]; exists {
				return nil, fmt.Errorf("duplicate CREG key %q", child.name)
			}
			tree.subkeys[key] = child
			childNavigation, err := navigation(childOffset)
			if err != nil {
				return nil, err
			}
			childOffset = childNavigation.peer
		}
		return tree, nil
	}
	return build(rootOffset, 0xffffffff, true)
}

func parseCREGDataRecord(record []byte) (cregDataRecord, error) {
	nameLength := int(binary.LittleEndian.Uint16(record[12:14]))
	valueCount := int(binary.LittleEndian.Uint16(record[14:16]))
	if 20+nameLength > len(record) {
		return cregDataRecord{}, fmt.Errorf("invalid key name length")
	}
	result := cregDataRecord{
		name:   normalizeWindows1252Text(string(record[20 : 20+nameLength])),
		values: make(map[string]registryData, valueCount),
	}
	cursor := 20 + nameLength
	for valueIndex := 0; valueIndex < valueCount; valueIndex++ {
		if cursor+12 > len(record) {
			return cregDataRecord{}, fmt.Errorf("value %d is truncated", valueIndex)
		}
		typ := binary.LittleEndian.Uint32(record[cursor : cursor+4])
		nameLength := int(binary.LittleEndian.Uint16(record[cursor+8 : cursor+10]))
		dataLength := int(binary.LittleEndian.Uint16(record[cursor+10 : cursor+12]))
		end := cursor + 12 + nameLength + dataLength
		if end > len(record) {
			return cregDataRecord{}, fmt.Errorf("value %d has invalid bounds", valueIndex)
		}
		name := "(default)"
		if nameLength != 0 {
			name = normalizeWindows1252Text(string(record[cursor+12 : cursor+12+nameLength]))
		}
		raw := append([]byte(nil), record[cursor+12+nameLength:end]...)
		var value registryData
		switch typ {
		case regSZ, regExpandSZ:
			value = registryString(typ, normalizeWindows1252Text(string(raw)))
		case regMultiSZ:
			text := strings.TrimRight(normalizeWindows1252Text(string(raw)), "\x00")
			parts := []string(nil)
			if text != "" {
				parts = strings.Split(text, "\x00")
			}
			value = registryMultiString(parts)
		default:
			value = registryData{typ: typ, data: raw}
		}
		for existing := range result.values {
			if strings.EqualFold(existing, name) {
				return cregDataRecord{}, fmt.Errorf("duplicate value %q", name)
			}
		}
		result.values[name] = value
		cursor = end
	}
	if cursor != len(record) {
		return cregDataRecord{}, fmt.Errorf("key record has %d unparsed bytes", len(record)-cursor)
	}
	return result, nil
}
