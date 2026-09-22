package ese

import (
	"encoding/binary"
	"fmt"
)

func (b *builder) legacy() bool { return b.options.Revision == 2 }

type separatedLongValue uint32

func (b *builder) encodeTableRecord(table *buildTable, row Row) ([]byte, error) {
	if !b.legacy() {
		return b.encodeRecord(table.definition.Columns, row)
	}
	copyRow := make(Row, len(row))
	for name, value := range row {
		copyRow[name] = value
	}
	for _, column := range table.definition.Columns {
		if column.Identifier < 256 || column.Type != ColumnLongBinary && column.Type != ColumnLongText || row[column.Name] == nil {
			continue
		}
		values, multiple := row[column.Name].([]any)
		if !multiple {
			values = []any{row[column.Name]}
		}
		encoded := make([]any, len(values))
		for index, value := range values {
			raw, err := encodeColumn(column, value)
			if err != nil {
				return nil, err
			}
			encoded[index] = value
			if len(raw) <= 512 {
				continue
			}
			if table.longValues == nil {
				tree := &buildIndex{longValue: true, owner: table, objid: b.nextObjectID(), definition: IndexDefinition{Flags: 1}}
				tree.fdp, tree.oe, tree.ae = b.reserveMultiple()
				tree.extents = []pageExtent{{first: tree.fdp, count: 5}}
				tree.available = []pageExtent{{first: tree.fdp + 3, count: 2}}
				table.extents = append(table.extents, tree.extents...)
				table.longValues = tree
			}
			table.nextLongID++
			id := table.nextLongID
			key := make([]byte, 4)
			binary.BigEndian.PutUint32(key, id)
			root := make([]byte, 8)
			binary.LittleEndian.PutUint32(root, 1)
			binary.LittleEndian.PutUint32(root[4:], uint32(len(raw)))
			table.longEntries = append(table.longEntries, treeEntry{key: key, data: root})
			for offset := 0; offset < len(raw); offset += 4096 {
				chunkKey := make([]byte, 8)
				copy(chunkKey, key)
				binary.BigEndian.PutUint32(chunkKey[4:], uint32(offset))
				table.longEntries = append(table.longEntries, treeEntry{key: chunkKey, data: raw[offset:min(offset+4096, len(raw))]})
			}
			encoded[index] = separatedLongValue(id)
		}
		if multiple {
			copyRow[column.Name] = encoded
		} else {
			copyRow[column.Name] = encoded[0]
		}
	}
	return b.encodeRecord(table.definition.Columns, copyRow)
}

func (b *builder) encodeRecord(columns []ColumnDefinition, row Row) ([]byte, error) {
	if !b.legacy() {
		return encodeRecord(columns, row)
	}
	var ordinary []ColumnDefinition
	for _, column := range columns {
		if column.Identifier < 256 {
			ordinary = append(ordinary, column)
		}
	}
	record, err := encodeRecord(ordinary, row)
	if err != nil {
		return nil, err
	}
	for _, column := range columns {
		if column.Identifier < 256 || row[column.Name] == nil {
			continue
		}
		values, multiple := row[column.Name].([]any)
		if !multiple {
			values = []any{row[column.Name]}
		}
		for _, value := range values {
			if id, ok := value.(separatedLongValue); ok {
				header := make([]byte, 9)
				binary.LittleEndian.PutUint16(header, uint16(column.Identifier))
				binary.LittleEndian.PutUint16(header[2:], 0x8005)
				header[4] = 1
				binary.LittleEndian.PutUint32(header[5:], uint32(id))
				record = append(record, header...)
				continue
			}
			raw, err := encodeColumn(column, value)
			if err != nil {
				return nil, err
			}
			flagged := column.Type == ColumnLongBinary || column.Type == ColumnLongText
			size := len(raw)
			if flagged {
				size++
			}
			if size > 0x1fff {
				return nil, fmt.Errorf("ese: revision 2 column %q requires a separated long value", column.Name)
			}
			length := uint16(size)
			if flagged {
				length |= 0x8000
			}
			header := [4]byte{}
			binary.LittleEndian.PutUint16(header[:2], uint16(column.Identifier))
			binary.LittleEndian.PutUint16(header[2:], length)
			record = append(record, header[:]...)
			if flagged {
				record = append(record, 0)
			}
			record = append(record, raw...)
		}
	}
	return record, nil
}

func (b *builder) catalogColumns() []ColumnDefinition {
	if !b.legacy() {
		return catalogColumns
	}
	var columns []ColumnDefinition
	for _, column := range catalogColumns {
		if column.Identifier <= 10 || column.Identifier >= 128 && column.Identifier <= 134 {
			columns = append(columns, column)
		}
	}
	return columns
}

func (b *builder) catalogIndexRows(object catalogObject) []Row {
	rows := catalogIndexRows(object)
	if !b.legacy() {
		return rows
	}
	for index, row := range rows {
		definition := object.indexes[index].definition
		row["Flags"] = int32(definition.Flags &^ 0x10000)
		segments := make([]byte, len(definition.Columns)*2)
		for i, identifier := range definition.Columns {
			flags := uint16(0)
			if identifier < 0 {
				identifier = -identifier
				flags = 0x8000
			}
			binary.LittleEndian.PutUint16(segments[i*2:], uint16(identifier)|flags)
		}
		row["KeyFldIDs"] = segments
	}
	return rows
}
