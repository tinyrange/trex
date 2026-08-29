package ese

import (
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

// BuildBuiltin exposes the portable ESE writer to Starlark.
func BuildBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var tablesValue starlark.Value
	databasePages := 0
	if err := starlark.UnpackArgs("ese_build", args, kwargs, "tables", &tablesValue, "database_pages?", &databasePages); err != nil {
		return nil, err
	}
	if databasePages < 0 {
		return nil, fmt.Errorf("ese_build: database_pages must be non-negative")
	}
	tableValues, err := starlarkSequence(tablesValue, "tables")
	if err != nil {
		return nil, err
	}
	tables := make([]TableDefinition, 0, len(tableValues))
	for index, value := range tableValues {
		dictionary, ok := value.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("ese_build: tables[%d] is %s, want dict", index, value.Type())
		}
		table, err := starlarkTableDefinition(dictionary)
		if err != nil {
			return nil, fmt.Errorf("ese_build: tables[%d]: %w", index, err)
		}
		tables = append(tables, table)
	}
	return Build(tables, BuildOptions{DatabasePages: uint32(databasePages)})
}

func starlarkTableDefinition(value *starlark.Dict) (TableDefinition, error) {
	name, err := requiredString(value, "name")
	if err != nil {
		return TableDefinition{}, err
	}
	flags, err := optionalUint32(value, "flags", 0)
	if err != nil {
		return TableDefinition{}, err
	}
	columnsRaw, err := requiredSequence(value, "columns")
	if err != nil {
		return TableDefinition{}, err
	}
	columns := make([]ColumnDefinition, 0, len(columnsRaw))
	for index, raw := range columnsRaw {
		dictionary, ok := raw.(*starlark.Dict)
		if !ok {
			return TableDefinition{}, fmt.Errorf("columns[%d] is %s, want dict", index, raw.Type())
		}
		column, err := starlarkColumnDefinition(dictionary)
		if err != nil {
			return TableDefinition{}, fmt.Errorf("columns[%d]: %w", index, err)
		}
		columns = append(columns, column)
	}
	indexesRaw, err := requiredSequence(value, "indexes")
	if err != nil {
		return TableDefinition{}, err
	}
	indexes := make([]IndexDefinition, 0, len(indexesRaw))
	for index, raw := range indexesRaw {
		dictionary, ok := raw.(*starlark.Dict)
		if !ok {
			return TableDefinition{}, fmt.Errorf("indexes[%d] is %s, want dict", index, raw.Type())
		}
		definition, err := starlarkIndexDefinition(dictionary)
		if err != nil {
			return TableDefinition{}, fmt.Errorf("indexes[%d]: %w", index, err)
		}
		indexes = append(indexes, definition)
	}
	rowsRaw, err := requiredSequence(value, "rows")
	if err != nil {
		return TableDefinition{}, err
	}
	rows := make([]Row, 0, len(rowsRaw))
	for index, raw := range rowsRaw {
		dictionary, ok := raw.(*starlark.Dict)
		if !ok {
			return TableDefinition{}, fmt.Errorf("rows[%d] is %s, want dict", index, raw.Type())
		}
		row := make(Row)
		for _, column := range columns {
			field, present, err := dictionary.Get(starlark.String(column.Name))
			if err != nil {
				return TableDefinition{}, err
			}
			if !present || field == starlark.None {
				continue
			}
			logical, err := starlarkColumnValue(column, field)
			if err != nil {
				return TableDefinition{}, fmt.Errorf("rows[%d].%s: %w", index, column.Name, err)
			}
			row[column.Name] = logical
		}
		rows = append(rows, row)
	}
	return TableDefinition{Name: name, Flags: flags, Columns: columns, Indexes: indexes, Rows: rows}, nil
}

func starlarkColumnDefinition(value *starlark.Dict) (ColumnDefinition, error) {
	name, err := requiredString(value, "name")
	if err != nil {
		return ColumnDefinition{}, err
	}
	identifier, err := requiredUint32(value, "identifier")
	if err != nil {
		return ColumnDefinition{}, err
	}
	typeName, err := requiredString(value, "type")
	if err != nil {
		return ColumnDefinition{}, err
	}
	typeCode, present := columnTypesByName()[normalizeTypeName(typeName)]
	if !present {
		return ColumnDefinition{}, fmt.Errorf("unknown column type %q", typeName)
	}
	maximum, err := optionalUint32(value, "maximum", 0)
	if err != nil {
		return ColumnDefinition{}, err
	}
	flags, err := optionalUint32(value, "flags", 0)
	if err != nil {
		return ColumnDefinition{}, err
	}
	codePage, err := optionalUint32(value, "code_page", 1252)
	if err != nil {
		return ColumnDefinition{}, err
	}
	return ColumnDefinition{Name: name, Identifier: identifier, Type: typeCode, Maximum: maximum, Flags: flags, CodePage: codePage}, nil
}

func starlarkIndexDefinition(value *starlark.Dict) (IndexDefinition, error) {
	name, err := requiredString(value, "name")
	if err != nil {
		return IndexDefinition{}, err
	}
	flags, err := requiredUint32(value, "flags")
	if err != nil {
		return IndexDefinition{}, err
	}
	columnsRaw, err := requiredSequence(value, "columns")
	if err != nil {
		return IndexDefinition{}, err
	}
	columns := make([]int32, 0, len(columnsRaw))
	for index, raw := range columnsRaw {
		var identifier int32
		if err := starlark.AsInt(raw, &identifier); err != nil {
			return IndexDefinition{}, fmt.Errorf("columns[%d]: %w", index, err)
		}
		columns = append(columns, identifier)
	}
	keyMost, err := optionalUint32(value, "key_most", 255)
	if err != nil || keyMost > 0xffff {
		return IndexDefinition{}, fmt.Errorf("key_most must fit an unsigned short")
	}
	lcmap, err := optionalUint32(value, "lcmap_flags", 0)
	if err != nil {
		return IndexDefinition{}, err
	}
	locale, err := optionalUint32(value, "locale", 1033)
	if err != nil {
		return IndexDefinition{}, err
	}
	localeName, err := optionalString(value, "locale_name", "")
	if err != nil {
		return IndexDefinition{}, err
	}
	version, err := optionalBytes(value, "version")
	if err != nil {
		return IndexDefinition{}, err
	}
	sortID, err := optionalBytes(value, "sort_id")
	if err != nil {
		return IndexDefinition{}, err
	}
	return IndexDefinition{
		Name: name, Flags: flags, Columns: columns, KeyMost: uint16(keyMost),
		LCMapFlags: lcmap, Locale: locale, LocaleName: localeName, Version: version, SortID: sortID,
	}, nil
}

func starlarkColumnValue(column ColumnDefinition, value starlark.Value) (any, error) {
	switch column.Type {
	case ColumnBoolean:
		boolean, ok := value.(starlark.Bool)
		if !ok {
			return nil, fmt.Errorf("got %s, want bool", value.Type())
		}
		return bool(boolean), nil
	case ColumnUnsignedByte, ColumnUnsignedShort, ColumnUnsignedLong:
		var integer uint64
		if err := starlark.AsInt(value, &integer); err != nil {
			return nil, err
		}
		return integer, nil
	case ColumnSignedShort, ColumnSignedLong, ColumnCurrency, ColumnLongLong, ColumnDateTime:
		var integer int64
		if err := starlark.AsInt(value, &integer); err != nil {
			return nil, err
		}
		return integer, nil
	case ColumnSingle, ColumnDouble:
		if floating, ok := value.(starlark.Float); ok {
			return float64(floating), nil
		}
		var integer int64
		if err := starlark.AsInt(value, &integer); err != nil {
			return nil, err
		}
		return float64(integer), nil
	case ColumnText, ColumnLongText:
		text, ok := starlark.AsString(value)
		if !ok {
			return nil, fmt.Errorf("got %s, want string", value.Type())
		}
		return text, nil
	case ColumnBinary, ColumnLongBinary, ColumnGUID:
		switch value := value.(type) {
		case starlark.Bytes:
			return []byte(value), nil
		case starlark.String:
			return []byte(value), nil
		default:
			return nil, fmt.Errorf("got %s, want bytes", value.Type())
		}
	default:
		return nil, fmt.Errorf("unsupported column type %d", column.Type)
	}
}

func columnTypesByName() map[string]uint32 {
	return map[string]uint32{
		"boolean": ColumnBoolean, "unsignedbyte": ColumnUnsignedByte,
		"signedshort": ColumnSignedShort, "signedlong": ColumnSignedLong,
		"currency": ColumnCurrency, "single": ColumnSingle, "double": ColumnDouble,
		"datetime": ColumnDateTime, "binary": ColumnBinary, "text": ColumnText,
		"longbinary": ColumnLongBinary, "longtext": ColumnLongText,
		"unsignedlong": ColumnUnsignedLong, "longlong": ColumnLongLong,
		"guid": ColumnGUID, "unsignedshort": ColumnUnsignedShort,
	}
}

func normalizeTypeName(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "_", "")
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, " ", "")
	return value
}

func requiredSequence(value *starlark.Dict, name string) ([]starlark.Value, error) {
	raw, present, err := value.Get(starlark.String(name))
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, fmt.Errorf("missing %q", name)
	}
	return starlarkSequence(raw, name)
}

func starlarkSequence(value starlark.Value, context string) ([]starlark.Value, error) {
	iterator := starlark.Iterate(value)
	if iterator == nil {
		return nil, fmt.Errorf("%s is %s, want iterable", context, value.Type())
	}
	defer iterator.Done()
	values := make([]starlark.Value, 0)
	var item starlark.Value
	for iterator.Next(&item) {
		values = append(values, item)
	}
	return values, nil
}

func requiredString(value *starlark.Dict, name string) (string, error) {
	raw, present, err := value.Get(starlark.String(name))
	if err != nil {
		return "", err
	}
	if !present {
		return "", fmt.Errorf("missing %q", name)
	}
	text, ok := starlark.AsString(raw)
	if !ok {
		return "", fmt.Errorf("%s is %s, want string", name, raw.Type())
	}
	return text, nil
}

func optionalString(value *starlark.Dict, name, fallback string) (string, error) {
	raw, present, err := value.Get(starlark.String(name))
	if err != nil || !present {
		return fallback, err
	}
	text, ok := starlark.AsString(raw)
	if !ok {
		return "", fmt.Errorf("%s is %s, want string", name, raw.Type())
	}
	return text, nil
}

func requiredUint32(value *starlark.Dict, name string) (uint32, error) {
	raw, present, err := value.Get(starlark.String(name))
	if err != nil {
		return 0, err
	}
	if !present {
		return 0, fmt.Errorf("missing %q", name)
	}
	var integer uint32
	if err := starlark.AsInt(raw, &integer); err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return integer, nil
}

func optionalUint32(value *starlark.Dict, name string, fallback uint32) (uint32, error) {
	raw, present, err := value.Get(starlark.String(name))
	if err != nil || !present {
		return fallback, err
	}
	var integer uint32
	if err := starlark.AsInt(raw, &integer); err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return integer, nil
}

func optionalBytes(value *starlark.Dict, name string) ([]byte, error) {
	raw, present, err := value.Get(starlark.String(name))
	if err != nil || !present {
		return nil, err
	}
	switch raw := raw.(type) {
	case starlark.Bytes:
		return []byte(raw), nil
	case starlark.String:
		return []byte(raw), nil
	default:
		return nil, fmt.Errorf("%s is %s, want bytes", name, raw.Type())
	}
}
