package sqlite

import (
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const defaultMaximumRows = 100000

// BuildBuiltin exposes the portable SQLite writer to Starlark.
func BuildBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var objectsValue starlark.Value
	pageSize := 4096
	encoding := 1
	userVersion := 0
	applicationID := 0
	if err := starlark.UnpackArgs("sqlite_build", args, kwargs,
		"objects", &objectsValue,
		"page_size?", &pageSize,
		"encoding?", &encoding,
		"user_version?", &userVersion,
		"application_id?", &applicationID,
	); err != nil {
		return nil, err
	}
	values, err := sqliteSequence(objectsValue, "objects")
	if err != nil {
		return nil, fmt.Errorf("sqlite_build: %w", err)
	}
	objects := make([]Object, 0, len(values))
	for index, value := range values {
		dictionary, ok := value.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("sqlite_build: objects[%d] is %s, want dict", index, value.Type())
		}
		object, err := sqliteObjectValue(dictionary)
		if err != nil {
			return nil, fmt.Errorf("sqlite_build: objects[%d]: %w", index, err)
		}
		objects = append(objects, object)
	}
	if encoding < 0 || userVersion < 0 || applicationID < 0 {
		return nil, fmt.Errorf("sqlite_build: encoding, user_version, and application_id must be non-negative")
	}
	return Build(objects, BuildOptions{
		PageSize: pageSize, Encoding: uint32(encoding), UserVersion: uint32(userVersion), ApplicationID: uint32(applicationID),
	})
}

// Builtin exposes the portable SQLite reader to Starlark.
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var sourceValue starlark.Value
	walValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("sqlite", args, kwargs, "file", &sourceValue, "wal?", &walValue); err != nil {
		return nil, err
	}
	source, ok := sourceValue.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("sqlite: got %s, want file", sourceValue.Type())
	}
	var wal starfile.File
	if walValue != starlark.None {
		var ok bool
		wal, ok = walValue.(starfile.File)
		if !ok {
			return nil, fmt.Errorf("sqlite: wal got %s, want file or None", walValue.Type())
		}
	}
	database, err := Open(source, wal)
	if err != nil {
		return nil, err
	}
	return &databaseValue{database: database}, nil
}

type databaseValue struct{ database *Database }

func (*databaseValue) String() string        { return "<database.sqlite>" }
func (*databaseValue) Type() string          { return "database.sqlite" }
func (*databaseValue) Freeze()               {}
func (*databaseValue) Truth() starlark.Bool  { return starlark.True }
func (*databaseValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: database.sqlite") }
func (*databaseValue) AttrNames() []string   { return []string{"info", "rows", "schema"} }

func (d *databaseValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "info":
		info := d.database.Info()
		return sqliteStringDict(map[string]starlark.Value{
			"application_id": starlark.MakeUint64(uint64(info.ApplicationID)),
			"encoding":       starlark.MakeUint64(uint64(info.Encoding)),
			"page_count":     starlark.MakeUint64(uint64(info.PageCount)),
			"page_size":      starlark.MakeInt(info.PageSize),
			"user_version":   starlark.MakeUint64(uint64(info.UserVersion)),
			"wal_frames":     starlark.MakeInt(info.WALFrames),
		}), nil
	case "schema":
		entries := d.database.Schema()
		values := make([]starlark.Value, 0, len(entries))
		for _, entry := range entries {
			values = append(values, sqliteStringDict(map[string]starlark.Value{
				"name":       starlark.String(entry.Name),
				"root_page":  starlark.MakeUint64(uint64(entry.RootPage)),
				"sql":        starlark.String(entry.SQL),
				"table_name": starlark.String(entry.TableName),
				"type":       starlark.String(entry.Type),
			}))
		}
		return starlark.NewList(values), nil
	case "rows":
		return starlark.NewBuiltin("rows", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var object string
			maximum := defaultMaximumRows
			if err := starlark.UnpackArgs("rows", args, kwargs, "name", &object, "maximum?", &maximum); err != nil {
				return nil, err
			}
			rows, err := d.database.Rows(object, maximum)
			if err != nil {
				return nil, err
			}
			values := make([]starlark.Value, 0, len(rows))
			for _, row := range rows {
				fields := make([]starlark.Value, 0, len(row.Values))
				for _, field := range row.Values {
					value, err := sqliteStarlarkValue(field)
					if err != nil {
						return nil, fmt.Errorf("rows: object %q: %w", object, err)
					}
					fields = append(fields, value)
				}
				rowID := starlark.Value(starlark.None)
				if row.RowID != nil {
					rowID = starlark.MakeInt64(*row.RowID)
				}
				values = append(values, sqliteStringDict(map[string]starlark.Value{
					"rowid":  rowID,
					"values": starlark.NewList(fields),
				}))
			}
			return starlark.NewList(values), nil
		}), nil
	}
	return nil, nil
}

func sqliteStarlarkValue(value any) (starlark.Value, error) {
	switch value := value.(type) {
	case nil:
		return starlark.None, nil
	case int64:
		return starlark.MakeInt64(value), nil
	case float64:
		return starlark.Float(value), nil
	case string:
		return starlark.String(value), nil
	case []byte:
		return starlark.Bytes(value), nil
	default:
		return nil, fmt.Errorf("unsupported SQLite value type %T", value)
	}
}

func sqliteStringDict(values map[string]starlark.Value) *starlark.Dict {
	result := starlark.NewDict(len(values))
	for name, value := range values {
		_ = result.SetKey(starlark.String(name), value)
	}
	return result
}

func sqliteObjectValue(dictionary *starlark.Dict) (Object, error) {
	typeName, err := sqliteRequiredString(dictionary, "type")
	if err != nil {
		return Object{}, err
	}
	name, err := sqliteRequiredString(dictionary, "name")
	if err != nil {
		return Object{}, err
	}
	tableName, err := sqliteOptionalString(dictionary, "table_name", name)
	if err != nil {
		return Object{}, err
	}
	sql, err := sqliteOptionalString(dictionary, "sql", "")
	if err != nil {
		return Object{}, err
	}
	rowsValue, present, err := dictionary.Get(starlark.String("rows"))
	if err != nil {
		return Object{}, err
	}
	rows := []Row{}
	if present {
		rowValues, err := sqliteSequence(rowsValue, "rows")
		if err != nil {
			return Object{}, err
		}
		for index, rowValue := range rowValues {
			rowDictionary, ok := rowValue.(*starlark.Dict)
			if !ok {
				return Object{}, fmt.Errorf("rows[%d] is %s, want dict", index, rowValue.Type())
			}
			row, err := sqliteRowValue(rowDictionary)
			if err != nil {
				return Object{}, fmt.Errorf("rows[%d]: %w", index, err)
			}
			rows = append(rows, row)
		}
	}
	return Object{Type: typeName, Name: name, TableName: tableName, SQL: sql, Rows: rows}, nil
}

func sqliteRowValue(dictionary *starlark.Dict) (Row, error) {
	valuesValue, present, err := dictionary.Get(starlark.String("values"))
	if err != nil {
		return Row{}, err
	}
	if !present {
		return Row{}, fmt.Errorf("missing values")
	}
	fields, err := sqliteSequence(valuesValue, "values")
	if err != nil {
		return Row{}, err
	}
	values := make([]any, 0, len(fields))
	for index, field := range fields {
		value, err := sqliteLogicalValue(field)
		if err != nil {
			return Row{}, fmt.Errorf("values[%d]: %w", index, err)
		}
		values = append(values, value)
	}
	var rowID *int64
	rowIDValue, present, err := dictionary.Get(starlark.String("rowid"))
	if err != nil {
		return Row{}, err
	}
	if present && rowIDValue != starlark.None {
		var integer int64
		if err := starlark.AsInt(rowIDValue, &integer); err != nil {
			return Row{}, fmt.Errorf("rowid: %w", err)
		}
		rowID = &integer
	}
	return Row{RowID: rowID, Values: values}, nil
}

func sqliteLogicalValue(value starlark.Value) (any, error) {
	switch value := value.(type) {
	case starlark.NoneType:
		return nil, nil
	case starlark.Bool:
		return bool(value), nil
	case starlark.Int:
		var integer int64
		if err := starlark.AsInt(value, &integer); err != nil {
			return nil, err
		}
		return integer, nil
	case starlark.Float:
		return float64(value), nil
	case starlark.String:
		return string(value), nil
	case starlark.Bytes:
		return []byte(value), nil
	default:
		return nil, fmt.Errorf("got %s, want None, bool, int, float, string, or bytes", value.Type())
	}
}

func sqliteSequence(value starlark.Value, name string) ([]starlark.Value, error) {
	iterable, ok := value.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("%s is %s, want iterable", name, value.Type())
	}
	iterator := iterable.Iterate()
	defer iterator.Done()
	values := []starlark.Value{}
	var valueItem starlark.Value
	for iterator.Next(&valueItem) {
		values = append(values, valueItem)
	}
	return values, nil
}

func sqliteRequiredString(dictionary *starlark.Dict, name string) (string, error) {
	value, present, err := dictionary.Get(starlark.String(name))
	if err != nil {
		return "", err
	}
	if !present {
		return "", fmt.Errorf("missing %s", name)
	}
	text, ok := starlark.AsString(value)
	if !ok {
		return "", fmt.Errorf("%s is %s, want string", name, value.Type())
	}
	return text, nil
}

func sqliteOptionalString(dictionary *starlark.Dict, name, fallback string) (string, error) {
	value, present, err := dictionary.Get(starlark.String(name))
	if err != nil {
		return "", err
	}
	if !present {
		return fallback, nil
	}
	text, ok := starlark.AsString(value)
	if !ok {
		return "", fmt.Errorf("%s is %s, want string", name, value.Type())
	}
	return text, nil
}
