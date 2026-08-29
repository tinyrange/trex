package ese

import (
	"fmt"
	"reflect"
	"time"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const defaultMaximumRows = 100000

// Builtin exposes a portable ESE database reader to Starlark.
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("ese", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("ese: got %s, want file", value.Type())
	}
	database, err := Open(file)
	if err != nil {
		return nil, err
	}
	return &databaseValue{database: database}, nil
}

type databaseValue struct{ database *Database }

func (*databaseValue) String() string        { return "<database.ese>" }
func (*databaseValue) Type() string          { return "database.ese" }
func (*databaseValue) Freeze()               {}
func (*databaseValue) Truth() starlark.Bool  { return starlark.True }
func (*databaseValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: database.ese") }
func (*databaseValue) AttrNames() []string   { return []string{"info", "rows", "tables", "verify"} }

func (d *databaseValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "info":
		info := d.database.Info()
		return stringDict(map[string]starlark.Value{
			"page_size": starlark.MakeInt64(info.PageSize),
			"revision":  starlark.MakeUint64(uint64(info.Revision)),
			"version":   starlark.MakeUint64(uint64(info.Version)),
		}), nil
	case "tables":
		tables := d.database.Tables()
		values := make([]starlark.Value, 0, len(tables))
		for _, table := range tables {
			columns := make([]starlark.Value, 0, len(table.Columns))
			for _, column := range table.Columns {
				columns = append(columns, stringDict(map[string]starlark.Value{
					"code_page":   starlark.MakeUint64(uint64(column.CodePage)),
					"flags":       starlark.MakeUint64(uint64(column.Flags)),
					"identifier":  starlark.MakeUint64(uint64(column.Identifier)),
					"name":        starlark.String(column.Name),
					"space_usage": starlark.MakeInt64(column.SpaceUsage),
					"type":        starlark.String(column.Type),
				}))
			}
			indexes := make([]starlark.Value, 0, len(table.Indexes))
			for _, index := range table.Indexes {
				indexes = append(indexes, starlark.String(index))
			}
			values = append(values, stringDict(map[string]starlark.Value{
				"columns":  starlark.NewList(columns),
				"fdp_page": starlark.MakeUint64(uint64(table.FatherDataPageNumber)),
				"indexes":  starlark.NewList(indexes),
				"name":     starlark.String(table.Name),
			}))
		}
		return starlark.NewList(values), nil
	case "rows":
		return starlark.NewBuiltin("rows", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var table string
			maximum := defaultMaximumRows
			if err := starlark.UnpackArgs("rows", args, kwargs, "table", &table, "maximum?", &maximum); err != nil {
				return nil, err
			}
			if maximum < 0 {
				return nil, fmt.Errorf("rows: maximum must be non-negative")
			}
			rows, err := d.database.Rows(table, maximum)
			if err != nil {
				return nil, err
			}
			values := make([]starlark.Value, 0, len(rows))
			for _, row := range rows {
				record := starlark.NewDict(len(row))
				for _, field := range row {
					value, err := eseStarlarkValue(field.Value)
					if err != nil {
						return nil, fmt.Errorf("rows: table %q column %q: %w", table, field.Name, err)
					}
					if err := record.SetKey(starlark.String(field.Name), value); err != nil {
						return nil, err
					}
				}
				values = append(values, record)
			}
			return starlark.NewList(values), nil
		}), nil
	case "verify":
		return starlark.NewBuiltin("verify", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			maximum := int(d.database.source.Size() / d.database.info.PageSize)
			if err := starlark.UnpackArgs("verify", args, kwargs, "maximum_pages?", &maximum); err != nil {
				return nil, err
			}
			if err := d.database.Verify(maximum); err != nil {
				return nil, err
			}
			return starlark.None, nil
		}), nil
	}
	return nil, nil
}

func stringDict(values map[string]starlark.Value) *starlark.Dict {
	result := starlark.NewDict(len(values))
	for name, value := range values {
		_ = result.SetKey(starlark.String(name), value)
	}
	return result
}

func eseStarlarkValue(value any) (starlark.Value, error) {
	switch value := value.(type) {
	case nil:
		return starlark.None, nil
	case bool:
		return starlark.Bool(value), nil
	case string:
		return starlark.String(value), nil
	case []byte:
		return starlark.Bytes(value), nil
	case int:
		return starlark.MakeInt(value), nil
	case int8:
		return starlark.MakeInt64(int64(value)), nil
	case int16:
		return starlark.MakeInt64(int64(value)), nil
	case int32:
		return starlark.MakeInt64(int64(value)), nil
	case int64:
		return starlark.MakeInt64(value), nil
	case uint:
		return starlark.MakeUint64(uint64(value)), nil
	case uint8:
		return starlark.MakeUint64(uint64(value)), nil
	case uint16:
		return starlark.MakeUint64(uint64(value)), nil
	case uint32:
		return starlark.MakeUint64(uint64(value)), nil
	case uint64:
		return starlark.MakeUint64(value), nil
	case float32:
		return starlark.Float(value), nil
	case float64:
		return starlark.Float(value), nil
	case time.Time:
		return starlark.MakeInt64(value.UnixNano() / 100), nil
	case *string:
		if value == nil {
			return starlark.None, nil
		}
		return starlark.String(*value), nil
	}
	reflected := reflect.ValueOf(value)
	if reflected.IsValid() && (reflected.Kind() == reflect.Slice || reflected.Kind() == reflect.Array) {
		items := make([]starlark.Value, 0, reflected.Len())
		for index := 0; index < reflected.Len(); index++ {
			item, err := eseStarlarkValue(reflected.Index(index).Interface())
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return starlark.NewList(items), nil
	}
	return nil, fmt.Errorf("unsupported ESE value type %T", value)
}
