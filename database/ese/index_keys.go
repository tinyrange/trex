package ese

import "fmt"

// Sparse secondary indexes omit null keys according to the persisted IDB
// flags. One multi-valued segment produces a key for each attribute value.
func secondaryKeys(columns []ColumnDefinition, row Row, index IndexDefinition, collation UnicodeCollation) ([][]byte, error) {
	variants := []Row{row}
	multi := false
	for _, identifier := range index.Columns {
		if identifier < 0 {
			identifier = -identifier
		}
		column, _ := columnByIdentifier(columns, uint32(identifier))
		if values, ok := row[column.Name].([]any); ok {
			if multi {
				return nil, fmt.Errorf("ese: multiple multi-valued index segments are unsupported")
			}
			multi = true
			variants = nil
			for _, value := range values {
				variant := make(Row, len(row))
				for k, v := range row {
					variant[k] = v
				}
				variant[column.Name] = value
				variants = append(variants, variant)
			}
		}
	}
	var result [][]byte
	seen := make(map[string]bool)
	for _, variant := range variants {
		nulls, firstNull := 0, false
		for i, identifier := range index.Columns {
			if identifier < 0 {
				identifier = -identifier
			}
			column, _ := columnByIdentifier(columns, uint32(identifier))
			if variant[column.Name] == nil {
				nulls++
				if i == 0 {
					firstNull = true
				}
			}
		}
		if nulls > 0 && index.Flags&0x10 != 0 {
			return nil, fmt.Errorf("ese: null in a non-null index")
		}
		if nulls == len(index.Columns) && index.Flags&2 == 0 || firstNull && index.Flags&4 == 0 || nulls > 0 && nulls < len(index.Columns) && index.Flags&8 == 0 {
			continue
		}
		key, err := encodeIndexKey(columns, variant, index, collation)
		if err != nil {
			return nil, err
		}
		maximum := int(index.KeyMost)
		if maximum == 0 {
			maximum = 255
		}
		if len(key) > maximum {
			if index.Flags&0x4000 != 0 {
				return nil, fmt.Errorf("ese: index key exceeds its maximum")
			}
			key = key[:maximum]
		}
		if !seen[string(key)] {
			result = append(result, key)
			seen[string(key)] = true
		}
	}
	return result, nil
}
