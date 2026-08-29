package ese

import (
	"encoding/binary"
	"fmt"
	"sort"
)

const (
	catalogTypeTable  = 1
	catalogTypeColumn = 2
	catalogTypeIndex  = 3

	indexFlagUniquePersisted  = 0x00000001
	indexFlagPrimaryPersisted = 0x00010000
)

var catalogColumns = []ColumnDefinition{
	{Name: "ObjidTable", Identifier: 1, Type: ColumnSignedLong, Maximum: 4, Flags: 1, CodePage: 1252},
	{Name: "Type", Identifier: 2, Type: ColumnSignedShort, Maximum: 2, Flags: 1, CodePage: 1252},
	{Name: "Id", Identifier: 3, Type: ColumnSignedLong, Maximum: 4, Flags: 1, CodePage: 1252},
	{Name: "ColtypOrPgnoFDP", Identifier: 4, Type: ColumnSignedLong, Maximum: 4, Flags: 1, CodePage: 1252},
	{Name: "SpaceUsage", Identifier: 5, Type: ColumnSignedLong, Maximum: 4, Flags: 1, CodePage: 1252},
	{Name: "Flags", Identifier: 6, Type: ColumnSignedLong, Maximum: 4, Flags: 1, CodePage: 1252},
	{Name: "PagesOrLocale", Identifier: 7, Type: ColumnSignedLong, Maximum: 4, Flags: 1, CodePage: 1252},
	{Name: "RootFlag", Identifier: 8, Type: ColumnBoolean, Maximum: 1, CodePage: 1252},
	{Name: "RecordOffset", Identifier: 9, Type: ColumnSignedShort, Maximum: 2, CodePage: 1252},
	{Name: "LCMapFlags", Identifier: 10, Type: ColumnSignedLong, Maximum: 4, CodePage: 1252},
	{Name: "KeyMost", Identifier: 11, Type: ColumnUnsignedShort, Maximum: 2, CodePage: 1252},
	{Name: "Name", Identifier: 128, Type: ColumnText, Maximum: 255, Flags: 1, CodePage: 1252},
	{Name: "Stats", Identifier: 129, Type: ColumnBinary, Maximum: 255, CodePage: 1252},
	{Name: "TemplateTable", Identifier: 130, Type: ColumnText, Maximum: 255, CodePage: 1252},
	{Name: "DefaultValue", Identifier: 131, Type: ColumnBinary, Maximum: 255, CodePage: 1252},
	{Name: "KeyFldIDs", Identifier: 132, Type: ColumnBinary, Maximum: 255, CodePage: 1252},
	{Name: "VarSegMac", Identifier: 133, Type: ColumnBinary, Maximum: 255, CodePage: 1252},
	{Name: "ConditionalColumns", Identifier: 134, Type: ColumnBinary, Maximum: 255, CodePage: 1252},
	{Name: "TupleLimits", Identifier: 135, Type: ColumnBinary, Maximum: 255, CodePage: 1252},
	{Name: "Version", Identifier: 136, Type: ColumnBinary, Maximum: 255, CodePage: 1252},
	{Name: "SortID", Identifier: 137, Type: ColumnBinary, Maximum: 255, CodePage: 1252},
	{Name: "CallbackData", Identifier: 256, Type: ColumnLongBinary, CodePage: 1252},
	{Name: "CallbackDependencies", Identifier: 257, Type: ColumnLongBinary, CodePage: 1252},
	{Name: "SeparateLV", Identifier: 258, Type: ColumnLongBinary, CodePage: 1252},
	{Name: "SpaceHints", Identifier: 259, Type: ColumnLongBinary, CodePage: 1252},
	{Name: "SpaceDeferredLVHints", Identifier: 260, Type: ColumnLongBinary, CodePage: 1252},
	{Name: "LocaleName", Identifier: 261, Type: ColumnLongBinary, CodePage: 1252},
}

var systemObjidColumns = []ColumnDefinition{
	{Name: "objid", Identifier: 256, Type: ColumnSignedLong, Maximum: 4},
	{Name: "objidTable", Identifier: 257, Type: ColumnSignedLong, Maximum: 4},
	{Name: "type", Identifier: 258, Type: ColumnSignedShort, Maximum: 2},
}

var systemLocaleColumns = []ColumnDefinition{
	{Name: "Type", Identifier: 1, Type: ColumnUnsignedByte, Maximum: 1, Flags: 1},
	{Name: "iValue", Identifier: 2, Type: ColumnSignedLong, Maximum: 4, Flags: 0x30},
	{Name: "Key", Identifier: 128, Type: ColumnBinary, Maximum: 255},
}

type catalogObject struct {
	fdp       uint32
	flags     uint32
	indexes   []*buildIndex
	name      string
	objid     uint32
	columns   []ColumnDefinition
	tableRows []Row
}

func catalogTableRow(object catalogObject, initialPages int32) Row {
	return Row{
		"ObjidTable": int32(object.objid), "Type": int16(catalogTypeTable),
		"Id": int32(object.objid), "ColtypOrPgnoFDP": int32(object.fdp),
		"SpaceUsage": initialPages, "Flags": int32(object.flags),
		"PagesOrLocale": int32(initialPages), "RootFlag": true, "Name": object.name,
	}
}

func catalogColumnRows(object catalogObject) []Row {
	rows := make([]Row, 0, len(object.columns))
	fixedOffset := int16(4)
	for _, column := range object.columns {
		maximum := column.Maximum
		if maximum == 0 {
			maximum = uint32(fixedColumnSize(column.Type))
		}
		row := Row{
			"ObjidTable": int32(object.objid), "Type": int16(catalogTypeColumn),
			"Id": int32(column.Identifier), "ColtypOrPgnoFDP": int32(column.Type),
			"SpaceUsage": int32(maximum), "Flags": int32(column.Flags),
			"PagesOrLocale": int32(column.CodePage), "Name": column.Name,
		}
		if column.Identifier < 128 {
			row["RecordOffset"] = fixedOffset
			fixedOffset += int16(fixedColumnSize(column.Type))
		}
		rows = append(rows, row)
	}
	return rows
}

func catalogKeySegments(columns []int32) []byte {
	data := make([]byte, len(columns)*4)
	for index, identifier := range columns {
		if identifier < 0 {
			data[index*4] = 1
			identifier = -identifier
		}
		binary.LittleEndian.PutUint16(data[index*4+2:index*4+4], uint16(identifier))
	}
	return data
}

func catalogIndexRows(object catalogObject) []Row {
	rows := make([]Row, 0, len(object.indexes))
	for _, index := range object.indexes {
		keyMost := index.definition.KeyMost
		if keyMost == 0 {
			keyMost = 255
		}
		row := Row{
			"ObjidTable": int32(object.objid), "Type": int16(catalogTypeIndex),
			"Id": int32(index.objid), "ColtypOrPgnoFDP": int32(index.fdp),
			"SpaceUsage": int32(80), "Flags": int32(index.definition.Flags),
			"PagesOrLocale": int32(index.definition.Locale), "LCMapFlags": int32(index.definition.LCMapFlags),
			"KeyMost": keyMost, "Name": index.definition.Name,
			"KeyFldIDs": catalogKeySegments(index.definition.Columns),
		}
		if len(index.definition.Version) != 0 {
			row["Version"] = index.definition.Version
		}
		if len(index.definition.SortID) != 0 {
			row["SortID"] = index.definition.SortID
		}
		if index.definition.LocaleName != "" {
			row["LocaleName"] = utf16Key(index.definition.LocaleName)
		}
		rows = append(rows, row)
	}
	return rows
}

func (b *builder) catalogRows(tables []*buildTable) ([]Row, error) {
	objects := []catalogObject{
		{
			name: "MSysObjects", objid: 2, fdp: catalogPage, flags: 0x80000002,
			columns: catalogColumns,
			indexes: []*buildIndex{
				{objid: 2, fdp: catalogPage, primary: true, definition: IndexDefinition{Name: "Id", Columns: []int32{1, 2, 3}, Flags: 0x10031, KeyMost: 255, Locale: 1033}},
				{objid: 4, fdp: catalogNamePage, definition: IndexDefinition{Name: "Name", Columns: []int32{1, 2, 128}, Flags: 0x10011, KeyMost: 255, Locale: 1033}},
				{objid: 5, fdp: catalogRootPageIndex, definition: IndexDefinition{Name: "RootObjects", Columns: []int32{8, 128}, Flags: 0x10009, KeyMost: 255, Locale: 1033}},
			},
		},
		{
			name: "MSysObjectsShadow", objid: 3, fdp: catalogShadowPage, flags: 0x80000002,
			columns: catalogColumns,
			indexes: []*buildIndex{{objid: 3, fdp: catalogShadowPage, primary: true, definition: IndexDefinition{Name: "Id", Columns: []int32{1, 2, 3}, Flags: 0x10031, KeyMost: 255, Locale: 1033}}},
		},
		{
			name: "MSysObjids", objid: 6, fdp: 33, flags: 0x80000002,
			columns: systemObjidColumns,
			indexes: []*buildIndex{{objid: 6, fdp: 33, primary: true, definition: IndexDefinition{Name: "primary", Columns: []int32{256}, Flags: 0x1002f, KeyMost: 255}}},
		},
		{
			name: "MSysLocales", objid: 7, fdp: 34, flags: 0x80000000,
			columns: systemLocaleColumns,
			indexes: []*buildIndex{{objid: 7, fdp: 34, primary: true, definition: IndexDefinition{Name: "KeyPrimary", Columns: []int32{128}, Flags: 0x1402f, KeyMost: 255}}},
		},
	}
	for _, table := range tables {
		objects = append(objects, catalogObject{
			name: table.definition.Name, objid: table.objid, fdp: table.fdp,
			flags: table.definition.Flags, columns: table.definition.Columns, indexes: table.indexes,
		})
	}
	rows := make([]Row, 0, 64)
	for _, object := range objects {
		initialPages := int32(5)
		if object.objid == 2 {
			initialPages = 20
		} else if object.objid == 3 {
			initialPages = 5
		} else if object.objid == 6 || object.objid == 7 {
			initialPages = 1
		}
		rows = append(rows, catalogTableRow(object, initialPages))
		rows = append(rows, catalogColumnRows(object)...)
		rows = append(rows, catalogIndexRows(object)...)
	}
	sort.SliceStable(rows, func(left, right int) bool {
		leftKey, _ := encodeIndexColumns(catalogColumns, rows[left], []int32{1, 2, 3})
		rightKey, _ := encodeIndexColumns(catalogColumns, rows[right], []int32{1, 2, 3})
		return string(leftKey) < string(rightKey)
	})
	return rows, nil
}

func (b *builder) buildSystemPages(rows []Row, tables []*buildTable) error {
	if err := b.buildSystemObjids(tables); err != nil {
		return err
	}
	if err := b.buildSystemLocales(tables); err != nil {
		return err
	}
	entries := make([]treeEntry, 0, len(rows))
	primaryKeys := make([][]byte, 0, len(rows))
	for index, row := range rows {
		key, err := encodeIndexColumns(catalogColumns, row, []int32{1, 2, 3})
		if err != nil {
			return fmt.Errorf("ese: catalog row %d key: %w", index, err)
		}
		record, err := encodeRecord(catalogColumns, row)
		if err != nil {
			return fmt.Errorf("ese: catalog row %d: %w", index, err)
		}
		entries = append(entries, treeEntry{key: key, data: record})
		primaryKeys = append(primaryKeys, key)
	}
	primary := &buildIndex{
		definition: IndexDefinition{Name: "Id", Columns: []int32{1, 2, 3}, Flags: 0x10031},
		fdp:        4, oe: 5, ae: 6, objid: 2, primary: true,
		extents:   []pageExtent{{first: 4, count: 20}},
		available: []pageExtent{{first: 13, count: 11}},
	}
	if err := b.buildTree(primary, entries); err != nil {
		return err
	}
	shadow := &buildIndex{
		definition: primary.definition, fdp: 24, oe: 25, ae: 26,
		objid: 3, primary: true, extents: []pageExtent{{first: 24, count: 5}},
		available: []pageExtent{{first: 27, count: 2}},
	}
	if err := b.buildTree(shadow, entries); err != nil {
		return err
	}
	owner := &buildTable{fdp: 4}
	nameEntries := make([]treeEntry, 0, len(rows))
	rootEntries := make([]treeEntry, 0, len(rows))
	for index, row := range rows {
		nameKey, err := encodeIndexColumns(catalogColumns, row, []int32{1, 2, 128})
		if err != nil {
			return err
		}
		nameEntries = append(nameEntries, treeEntry{key: nameKey, data: primaryKeys[index]})
		if _, present := row["RootFlag"]; present {
			rootKey, err := encodeIndexColumns(catalogColumns, row, []int32{8, 128})
			if err != nil {
				return err
			}
			rootEntries = append(rootEntries, treeEntry{key: rootKey, data: primaryKeys[index]})
		}
	}
	sort.SliceStable(nameEntries, func(left, right int) bool {
		return string(nameEntries[left].key) < string(nameEntries[right].key)
	})
	sort.SliceStable(rootEntries, func(left, right int) bool {
		return string(rootEntries[left].key) < string(rootEntries[right].key)
	})
	nameIndex := &buildIndex{
		definition: IndexDefinition{Name: "Name", Flags: 0x10011}, fdp: 7, oe: 8, ae: 9,
		objid: 4, owner: owner, extents: []pageExtent{{first: 7, count: 3}},
	}
	if err := b.buildTree(nameIndex, nameEntries); err != nil {
		return err
	}
	rootIndex := &buildIndex{
		definition: IndexDefinition{Name: "RootObjects", Flags: 0x10009}, fdp: 10, oe: 11, ae: 12,
		objid: 5, owner: owner, extents: []pageExtent{{first: 10, count: 3}},
	}
	if err := b.buildTree(rootIndex, rootEntries); err != nil {
		return err
	}
	return nil
}

func (b *builder) buildSystemObjids(tables []*buildTable) error {
	type object struct {
		id, table uint32
		kind      int16
	}
	objects := []object{
		{id: 2, table: 2, kind: catalogTypeTable},
		{id: 3, table: 3, kind: catalogTypeTable},
		{id: 4, table: 2, kind: catalogTypeIndex},
		{id: 5, table: 2, kind: catalogTypeIndex},
		{id: 6, table: 6, kind: catalogTypeTable},
		{id: 7, table: 7, kind: catalogTypeTable},
	}
	for _, table := range tables {
		objects = append(objects, object{id: table.objid, table: table.objid, kind: catalogTypeTable})
		for _, index := range table.indexes[1:] {
			objects = append(objects, object{id: index.objid, table: table.objid, kind: catalogTypeIndex})
		}
	}
	sort.Slice(objects, func(left, right int) bool { return objects[left].id < objects[right].id })
	values := [][]byte{spaceHeader(1, 1, 0, 0)}
	for _, object := range objects {
		row := Row{"objid": int32(object.id), "objidTable": int32(object.table), "type": object.kind}
		key, err := encodeIndexColumns(systemObjidColumns, row, []int32{256})
		if err != nil {
			return err
		}
		record, err := encodeRecord(systemObjidColumns, row)
		if err != nil {
			return err
		}
		entry, _ := recordLeafEntry(key, record)
		values = append(values, entry)
	}
	return b.put(encodedPage{dbtime: b.dbtime, flags: pageFlagRoot | pageFlagLeaf | pageFlagNewRecord, number: 33, objid: 6, values: values})
}

func utf16Key(value string) []byte {
	column := ColumnDefinition{Type: ColumnText, CodePage: 1200}
	data, _ := encodeColumn(column, value+"\x00")
	return data
}

func persistedSortID(value []byte) (string, error) {
	if len(value) != 16 {
		return "", fmt.Errorf("ese: persisted locale sort ID has %d bytes, want 16", len(value))
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%012x",
		binary.LittleEndian.Uint32(value[0:4]),
		binary.LittleEndian.Uint16(value[4:6]),
		binary.LittleEndian.Uint16(value[6:8]),
		value[8], value[9], value[10:16]), nil
}

func persistedLocaleKey(index IndexDefinition) (string, error) {
	if index.LocaleName == "" {
		return "", fmt.Errorf("ese: persisted locale has no name")
	}
	if len(index.Version) != 8 {
		return "", fmt.Errorf("ese: persisted locale %q version has %d bytes, want 8", index.LocaleName, len(index.Version))
	}
	sortID, err := persistedSortID(index.SortID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("LocaleName=%s,SortID=%s,Ver=%x",
		index.LocaleName, sortID, binary.LittleEndian.Uint64(index.Version)), nil
}

func (b *builder) buildSystemLocales(tables []*buildTable) error {
	rows := []Row{
		{"Key": utf16Key(".Schema\\Internal\\Major"), "Type": uint8(1), "iValue": int32(1)},
		{"Key": utf16Key(".Schema\\Internal\\Minor"), "Type": uint8(1), "iValue": int32(0)},
		{"Key": utf16Key(".Schema\\Internal\\Update"), "Type": uint8(1), "iValue": int32(0)},
		{"Key": utf16Key(".Schema\\External\\Major"), "Type": uint8(1), "iValue": int32(1)},
		{"Key": utf16Key(".Schema\\External\\Minor"), "Type": uint8(1), "iValue": int32(0)},
		{"Key": utf16Key(".Schema\\External\\Update"), "Type": uint8(1), "iValue": int32(0)},
	}
	localeCounts := make(map[string]int32)
	for _, table := range tables {
		for _, index := range table.indexes {
			if index.definition.LocaleName == "" {
				continue
			}
			key, err := persistedLocaleKey(index.definition)
			if err != nil {
				return fmt.Errorf("ese: table %q index %q: %w", table.definition.Name, index.definition.Name, err)
			}
			localeCounts[key]++
		}
	}
	localeKeys := make([]string, 0, len(localeCounts))
	for key := range localeCounts {
		localeKeys = append(localeKeys, key)
	}
	sort.Strings(localeKeys)
	for _, key := range localeKeys {
		rows = append(rows, Row{"Key": utf16Key(key), "Type": uint8(2), "iValue": localeCounts[key]})
	}
	rows = append(rows, Row{"Key": utf16Key("MSysLocalesConsistent"), "Type": uint8(2), "iValue": int32(1)})
	type keyed struct{ key, record []byte }
	encoded := make([]keyed, 0, len(rows))
	for _, row := range rows {
		key, err := encodeIndexColumns(systemLocaleColumns, row, []int32{128})
		if err != nil {
			return err
		}
		record, err := encodeRecord(systemLocaleColumns, row)
		if err != nil {
			return err
		}
		encoded = append(encoded, keyed{key: key, record: record})
	}
	sort.Slice(encoded, func(left, right int) bool { return string(encoded[left].key) < string(encoded[right].key) })
	values := [][]byte{spaceHeader(1, 1, 0, 0)}
	for _, value := range encoded {
		entry, _ := recordLeafEntry(value.key, value.record)
		values = append(values, entry)
	}
	return b.put(encodedPage{dbtime: b.dbtime, flags: pageFlagRoot | pageFlagLeaf | pageFlagNewRecord, number: 34, objid: 7, values: values})
}

func (b *builder) putSpacePair(oe, ae, objid uint32, owned, available []pageExtent, index bool) error {
	flags := uint32(pageFlagRoot | pageFlagLeaf | pageFlagSpaceTree | pageFlagNewRecord)
	if index {
		flags |= pageFlagIndex
	}
	oeValues := [][]byte{make([]byte, 16)}
	for _, extent := range owned {
		oeValues = append(oeValues, extentEntry(extent))
	}
	aeValues := [][]byte{make([]byte, 16)}
	for _, extent := range available {
		if extent.count != 0 {
			aeValues = append(aeValues, extentEntry(extent))
		}
	}
	if err := b.put(encodedPage{dbtime: b.dbtime, flags: flags, number: oe, objid: objid, values: oeValues}); err != nil {
		return err
	}
	return b.put(encodedPage{dbtime: b.dbtime, flags: flags, number: ae, objid: objid, values: aeValues})
}
