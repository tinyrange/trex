package ese

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
)

const (
	pageFlagParentOfLeaf = 0x00000004
	pageFlagNonUnique    = 0x00000400
	pageFlagNewRecord    = 0x00000800

	catalogPage          = 4
	catalogNamePage      = 7
	catalogRootPageIndex = 10
	catalogShadowPage    = 24
)

// IndexDefinition describes an ESE B+tree. Columns contains signed column
// identifiers; negative identifiers sort descending. Flags are the persisted
// catalog flags rather than API creation flags so historical schemas can be
// reproduced exactly.
type IndexDefinition struct {
	Columns    []int32
	Flags      uint32
	KeyMost    uint16
	LCMapFlags uint32
	Locale     uint32
	LocaleName string
	Name       string
	SortID     []byte
	Version    []byte
}

// TableDefinition describes one table and its already-logical rows.
type TableDefinition struct {
	Columns []ColumnDefinition
	Flags   uint32
	Indexes []IndexDefinition
	Name    string
	Rows    []Row
}

// BuildOptions selects the persisted ESE generation. This writer currently
// targets the 32 KiB Windows 8 generation because its large-page record flags
// and checksums are materially different from the older formats.
type BuildOptions struct {
	DatabasePages uint32
	PageSize      int
	Revision      uint32
	Version       uint32
}

type buildIndex struct {
	definition IndexDefinition
	fdp        uint32
	objid      uint32
	oe         uint32
	ae         uint32
	primary    bool
	owner      *buildTable
	extents    []pageExtent
	available  []pageExtent
}

type buildTable struct {
	definition TableDefinition
	fdp        uint32
	objid      uint32
	oe         uint32
	ae         uint32
	indexes    []*buildIndex
	extents    []pageExtent
	available  []pageExtent
}

type pageExtent struct{ first, count uint32 }

func (extent pageExtent) last() uint32 { return extent.first + extent.count - 1 }

type treeEntry struct {
	key  []byte
	data []byte
}

type treeLevel struct {
	first []byte
	last  []byte
	page  uint32
}

type builder struct {
	options   BuildOptions
	pages     map[uint32][]byte
	next      uint32
	dbtime    uint64
	objidLast uint32
}

// Build returns a complete, clean ESE database as a portable in-memory file.
// It does not invoke ESENT or any host database utility.
func Build(tables []TableDefinition, options BuildOptions) (*starfile.Bytes, error) {
	if options.PageSize == 0 {
		options.PageSize = 32768
	}
	if options.PageSize != 32768 {
		return nil, fmt.Errorf("ese: writer currently supports 32768-byte pages")
	}
	if options.Version == 0 {
		options.Version = 0x620
	}
	if options.Revision == 0 {
		options.Revision = 0x14
	}
	if options.Version != 0x620 || options.Revision != 0x14 {
		return nil, fmt.Errorf("ese: writer currently supports format 0x620 revision 0x14")
	}
	if len(tables) == 0 {
		return nil, fmt.Errorf("ese: at least one user table is required")
	}
	seen := make(map[string]bool)
	for index := range tables {
		if err := validateTableDefinition(&tables[index], seen); err != nil {
			return nil, err
		}
	}

	b := &builder{options: options, pages: make(map[uint32][]byte), next: 35, dbtime: 64, objidLast: 7}
	physical := make([]*buildTable, 0, len(tables))
	for _, definition := range tables {
		table := &buildTable{definition: definition, objid: b.nextObjectID()}
		table.fdp, table.oe, table.ae = b.reserveMultiple()
		table.extents = append(table.extents, pageExtent{first: table.fdp, count: 5})
		table.available = append(table.available, pageExtent{first: table.fdp + 3, count: 2})
		for index, definition := range definition.Indexes {
			if index == 0 {
				table.indexes = append(table.indexes, &buildIndex{
					definition: definition, fdp: table.fdp, objid: table.objid,
					oe: table.oe, ae: table.ae, primary: true, owner: table,
					extents: table.extents, available: table.available,
				})
				continue
			}
			secondary := &buildIndex{definition: definition, objid: b.nextObjectID(), owner: table}
			secondary.fdp, secondary.oe, secondary.ae = b.reserveMultiple()
			secondary.extents = append(secondary.extents, pageExtent{first: secondary.fdp, count: 5})
			secondary.available = append(secondary.available, pageExtent{first: secondary.fdp + 3, count: 2})
			table.extents = append(table.extents, secondary.extents...)
			table.indexes = append(table.indexes, secondary)
		}
		physical = append(physical, table)
	}

	for _, table := range physical {
		primaryKeys := make([][]byte, len(table.definition.Rows))
		for index, row := range table.definition.Rows {
			key, err := encodeIndexKey(table.definition.Columns, row, table.definition.Indexes[0].Columns)
			if err != nil {
				return nil, fmt.Errorf("ese: table %q row %d primary key: %w", table.definition.Name, index, err)
			}
			primaryKeys[index] = key
		}
		order := make([]int, 0, len(table.indexes))
		for index := 1; index < len(table.indexes); index++ {
			order = append(order, index)
		}
		order = append(order, 0)
		for _, index := range order {
			tree := table.indexes[index]
			if index == 0 {
				tree.extents = append([]pageExtent(nil), table.extents...)
				tree.available = append([]pageExtent(nil), table.available...)
			}
			entries := make([]treeEntry, 0, len(table.definition.Rows))
			for rowIndex, row := range table.definition.Rows {
				key, err := encodeIndexKey(table.definition.Columns, row, tree.definition.Columns)
				if err != nil {
					return nil, fmt.Errorf("ese: table %q index %q row %d: %w", table.definition.Name, tree.definition.Name, rowIndex, err)
				}
				var data []byte
				if index == 0 {
					data, err = encodeRecord(table.definition.Columns, row)
				} else {
					data = append([]byte(nil), primaryKeys[rowIndex]...)
				}
				if err != nil {
					return nil, fmt.Errorf("ese: table %q row %d: %w", table.definition.Name, rowIndex, err)
				}
				entries = append(entries, treeEntry{key: key, data: data})
			}
			sort.SliceStable(entries, func(left, right int) bool {
				order := bytes.Compare(entries[left].key, entries[right].key)
				if order != 0 {
					return order < 0
				}
				return bytes.Compare(entries[left].data, entries[right].data) < 0
			})
			if err := validateTreeEntries(entries, tree.definition.Flags&1 != 0); err != nil {
				return nil, fmt.Errorf("ese: table %q index %q: %w", table.definition.Name, tree.definition.Name, err)
			}
			if err := b.buildTree(tree, entries); err != nil {
				return nil, fmt.Errorf("ese: table %q index %q: %w", table.definition.Name, tree.definition.Name, err)
			}
		}
	}

	catalogRows, err := b.catalogRows(physical)
	if err != nil {
		return nil, err
	}
	if err := b.buildSystemPages(catalogRows, physical); err != nil {
		return nil, err
	}

	lastPage := b.next - 1
	databasePages := options.DatabasePages
	if databasePages == 0 {
		databasePages = max(uint32(256), alignPages(lastPage+64, 64))
	}
	if databasePages < lastPage {
		return nil, fmt.Errorf("ese: database_pages %d is smaller than allocated page %d", databasePages, lastPage)
	}
	if err := b.buildDatabaseSpace(databasePages, lastPage); err != nil {
		return nil, err
	}
	data := make([]byte, int(databasePages+2)*options.PageSize)
	header, err := b.databaseHeader()
	if err != nil {
		return nil, err
	}
	copy(data, header)
	copy(data[options.PageSize:], header)
	for number, page := range b.pages {
		copy(data[int(number+1)*options.PageSize:], page)
	}
	return &starfile.Bytes{Name: "database.edb", Data: data}, nil
}

func validateTableDefinition(table *TableDefinition, names map[string]bool) error {
	name := strings.ToLower(table.Name)
	if name == "" || names[name] {
		return fmt.Errorf("ese: duplicate or empty table name %q", table.Name)
	}
	names[name] = true
	if err := validateColumns(table.Columns); err != nil {
		return fmt.Errorf("ese: table %q: %w", table.Name, err)
	}
	if len(table.Indexes) == 0 || len(table.Indexes[0].Columns) == 0 {
		return fmt.Errorf("ese: table %q must have a primary index", table.Name)
	}
	indexes := make(map[string]bool)
	for index, definition := range table.Indexes {
		name := strings.ToLower(definition.Name)
		if name == "" || indexes[name] {
			return fmt.Errorf("ese: table %q has duplicate or empty index name %q", table.Name, definition.Name)
		}
		indexes[name] = true
		if index == 0 && definition.Flags&0x10000 == 0 {
			return fmt.Errorf("ese: table %q primary index flags do not contain persisted primary bit", table.Name)
		}
		for _, identifier := range definition.Columns {
			if identifier == 0 {
				return fmt.Errorf("ese: table %q index %q has zero column identifier", table.Name, definition.Name)
			}
			absolute := uint32(identifier)
			if identifier < 0 {
				absolute = uint32(-identifier)
			}
			if _, present := columnByIdentifier(table.Columns, absolute); !present {
				return fmt.Errorf("ese: table %q index %q uses undefined column %d", table.Name, definition.Name, absolute)
			}
		}
	}
	return nil
}

func (b *builder) nextObjectID() uint32 {
	b.objidLast++
	return b.objidLast
}

func (b *builder) reserveMultiple() (uint32, uint32, uint32) {
	fdp := b.next
	b.next += 5
	return fdp, fdp + 1, fdp + 2
}

func alignPages(value, alignment uint32) uint32 {
	return (value + alignment - 1) / alignment * alignment
}

func validateTreeEntries(entries []treeEntry, unique bool) error {
	for index := range entries {
		if len(entries[index].key) == 0 {
			return fmt.Errorf("empty key")
		}
		if index == 0 {
			continue
		}
		order := bytes.Compare(entries[index-1].key, entries[index].key)
		if order > 0 || unique && order == 0 {
			return fmt.Errorf("keys are not strictly ordered")
		}
		if order == 0 && bytes.Compare(entries[index-1].data, entries[index].data) >= 0 {
			return fmt.Errorf("non-unique bookmarks are not ordered")
		}
	}
	return nil
}

func (b *builder) put(spec encodedPage) error {
	page, err := spec.encode(b.options.PageSize)
	if err != nil {
		return err
	}
	if _, exists := b.pages[spec.number]; exists {
		return fmt.Errorf("ese: page %d was generated twice", spec.number)
	}
	b.pages[spec.number] = page
	return nil
}

func spaceHeader(primary, parent, flags, oe uint32) []byte {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], primary)
	binary.LittleEndian.PutUint32(data[4:8], parent)
	binary.LittleEndian.PutUint32(data[8:12], flags)
	binary.LittleEndian.PutUint32(data[12:16], oe)
	return data
}

func extentEntry(extent pageExtent) []byte {
	key := make([]byte, 4)
	binary.BigEndian.PutUint32(key, extent.last())
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, extent.count)
	entry, _ := recordLeafEntry(key, data)
	return entry
}

func (b *builder) allocateTreePage(tree *buildIndex) uint32 {
	for len(tree.available) > 0 {
		extent := &tree.available[0]
		page := extent.first
		extent.first++
		extent.count--
		if extent.count == 0 {
			tree.available = tree.available[1:]
		}
		return page
	}
	extent := pageExtent{first: b.next, count: 8}
	b.next += extent.count
	tree.extents = append(tree.extents, extent)
	tree.available = append(tree.available, pageExtent{first: extent.first + 1, count: extent.count - 1})
	if tree.owner != nil && !tree.primary {
		tree.owner.extents = append(tree.owner.extents, extent)
	}
	return extent.first
}

func (b *builder) buildTree(tree *buildIndex, entries []treeEntry) error {
	type packed struct {
		first, last []byte
		values      [][]byte
	}
	pack := func(entries []treeEntry, external []byte) ([]packed, error) {
		pages := make([]packed, 0, 1)
		current := packed{values: [][]byte{external}}
		used := 80 + len(external) + 4
		for _, entry := range entries {
			value, err := recordLeafEntry(entry.key, entry.data)
			if err != nil {
				return nil, err
			}
			if used+len(value)+4 > b.options.PageSize && len(current.values) > 1 {
				pages = append(pages, current)
				current = packed{values: [][]byte{nil}}
				used = 84
			}
			if used+len(value)+4 > b.options.PageSize {
				return nil, fmt.Errorf("entry exceeds page capacity")
			}
			if current.first == nil {
				current.first = append([]byte(nil), entry.key...)
			}
			current.last = append(current.last[:0], entry.key...)
			current.values = append(current.values, value)
			used += len(value) + 4
		}
		pages = append(pages, current)
		return pages, nil
	}

	flags := uint32(0)
	if !tree.primary {
		flags |= pageFlagIndex
	}
	if tree.definition.Flags&1 == 0 {
		flags |= pageFlagNonUnique
	}
	primaryPages := uint32(5)
	if len(tree.extents) > 0 {
		primaryPages = tree.extents[0].count
	}
	external := spaceHeader(primaryPages, 1, 1, tree.oe)
	if !tree.primary {
		external = spaceHeader(primaryPages, tree.owner.fdp, 1, tree.oe)
	}
	leafPages, err := pack(entries, external)
	if err != nil {
		return err
	}
	if len(leafPages) == 1 {
		return b.finishTree(tree, encodedPage{
			dbtime: b.dbtime, flags: flags | pageFlagRoot | pageFlagLeaf | pageFlagNewRecord,
			number: tree.fdp, objid: tree.objid, values: leafPages[0].values,
		})
	}
	leafPages, err = pack(entries, nil)
	if err != nil {
		return err
	}

	level := make([]treeLevel, len(leafPages))
	for index, leaf := range leafPages {
		level[index] = treeLevel{first: leaf.first, last: leaf.last, page: b.allocateTreePage(tree)}
	}
	for index, leaf := range leafPages {
		page := level[index].page
		prev, next := uint32(0), uint32(0)
		if index > 0 {
			prev = level[index-1].page
		}
		if index+1 < len(leafPages) {
			next = level[index+1].page
		}
		if err := b.put(encodedPage{
			dbtime: b.dbtime, flags: flags | pageFlagLeaf | pageFlagNewRecord,
			number: page, objid: tree.objid, prev: prev, next: next, values: leaf.values,
		}); err != nil {
			return err
		}
	}
	childrenAreLeaves := true
	for {
		values, groups, err := b.packBranch(level)
		if err != nil {
			return err
		}
		if len(groups) == 1 {
			rootFlags := flags | pageFlagRoot | pageFlagNewRecord
			if childrenAreLeaves {
				rootFlags |= pageFlagParentOfLeaf
			}
			return b.finishTree(tree, encodedPage{
				dbtime: b.dbtime, flags: rootFlags, number: tree.fdp,
				objid: tree.objid, values: append([][]byte{external}, values[0]...),
			})
		}
		nextLevel := make([]treeLevel, len(groups))
		for index, group := range groups {
			page := b.allocateTreePage(tree)
			pageFlags := flags | pageFlagNewRecord
			if childrenAreLeaves {
				pageFlags |= pageFlagParentOfLeaf
			}
			if err := b.put(encodedPage{
				dbtime: b.dbtime, flags: pageFlags, number: page, objid: tree.objid,
				values: append([][]byte{nil}, values[index]...),
			}); err != nil {
				return err
			}
			nextLevel[index] = treeLevel{first: group[0].first, last: group[len(group)-1].last, page: page}
		}
		level = nextLevel
		childrenAreLeaves = false
	}
}

func (b *builder) packBranch(level []treeLevel) ([][][]byte, [][]treeLevel, error) {
	groups := make([][]treeLevel, 0, 1)
	groupValues := make([][]byte, 0, len(level))
	group := make([]treeLevel, 0, len(level))
	used := 84
	allValues := make([][][]byte, 0, 1)
	for index, child := range level {
		var separator []byte
		if index+1 < len(level) {
			separator = level[index+1].first
		}
		entry, err := branchEntry(separator, child.page)
		if err != nil {
			return nil, nil, err
		}
		if used+len(entry)+4 > b.options.PageSize && len(group) > 0 {
			allValues = append(allValues, groupValues)
			groups = append(groups, group)
			groupValues = nil
			group = nil
			used = 84
		}
		if used+len(entry)+4 > b.options.PageSize {
			return nil, nil, fmt.Errorf("branch entry exceeds page capacity")
		}
		group = append(group, child)
		groupValues = append(groupValues, entry)
		used += len(entry) + 4
	}
	if len(group) > 0 {
		allValues = append(allValues, groupValues)
		groups = append(groups, group)
	}
	return allValues, groups, nil
}

func (b *builder) finishTree(tree *buildIndex, root encodedPage) error {
	if err := b.put(root); err != nil {
		return err
	}
	oeValues := [][]byte{make([]byte, 16)}
	for _, extent := range coalesceExtents(tree.extents) {
		oeValues = append(oeValues, extentEntry(extent))
	}
	aeValues := [][]byte{make([]byte, 16)}
	for _, extent := range coalesceExtents(tree.available) {
		if extent.count != 0 {
			aeValues = append(aeValues, extentEntry(extent))
		}
	}
	spaceFlags := uint32(pageFlagRoot | pageFlagLeaf | pageFlagSpaceTree | pageFlagNewRecord)
	if !tree.primary {
		spaceFlags |= pageFlagIndex
	}
	if err := b.put(encodedPage{dbtime: b.dbtime, flags: spaceFlags, number: tree.oe, objid: tree.objid, values: oeValues}); err != nil {
		return err
	}
	return b.put(encodedPage{dbtime: b.dbtime, flags: spaceFlags, number: tree.ae, objid: tree.objid, values: aeValues})
}

func coalesceExtents(input []pageExtent) []pageExtent {
	result := make([]pageExtent, 0, len(input))
	for _, extent := range input {
		if extent.count == 0 {
			continue
		}
		if len(result) > 0 && result[len(result)-1].last()+1 == extent.first {
			result[len(result)-1].count += extent.count
			continue
		}
		result = append(result, extent)
	}
	return result
}
