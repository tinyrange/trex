package msi

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var f starfile.File
	if err := starlark.UnpackArgs("msi", args, kwargs, "file", &f); err != nil {
		return nil, err
	}
	return Open(f)
}
func (d *Database) String() string      { return fmt.Sprintf("<msi tables=%d>", len(d.Tables)) }
func (*Database) Type() string          { return "msi" }
func (*Database) Freeze()               {}
func (*Database) Truth() starlark.Bool  { return starlark.True }
func (*Database) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: msi") }
func (*Database) AttrNames() []string {
	return []string{"tables", "table", "codepage", "schema", "plan"}
}
func (d *Database) Attr(name string) (starlark.Value, error) {
	switch name {
	case "plan":
		return starlark.NewBuiltin("msi.plan", d.planBuiltin), nil
	case "codepage":
		return starlark.MakeUint(uint(d.Codepage)), nil
	case "tables":
		out := []starlark.Value{}
		for _, name := range d.tableNames() {
			out = append(out, starlark.String(name))
		}
		return starlark.NewList(out), nil
	case "schema":
		dict := starlark.NewDict(len(d.Schema))
		for _, name := range d.tableNames() {
			cols := []starlark.Value{}
			for _, c := range d.Schema[name] {
				cols = append(cols, starlark.Tuple{starlark.String(c.Name), starlark.MakeUint(uint(c.Type))})
			}
			_ = dict.SetKey(starlark.String(name), starlark.NewList(cols))
		}
		return dict, nil
	case "table":
		return starlark.NewBuiltin("msi.table", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("msi.table", args, kwargs, "name", &name); err != nil {
				return nil, err
			}
			rows, ok := d.Tables[name]
			if !ok {
				return starlark.None, nil
			}
			out := []starlark.Value{}
			for _, row := range rows {
				dict := starlark.NewDict(len(row))
				for _, col := range d.Schema[name] {
					_ = dict.SetKey(starlark.String(col.Name), row[col.Name])
				}
				out = append(out, dict)
			}
			return starlark.NewList(out), nil
		}), nil
	}
	return nil, nil
}

func (d *Database) planBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var properties, media *starlark.Dict
	var features *starlark.List
	if err := starlark.UnpackArgs("msi.plan", args, kwargs, "properties?", &properties, "features?", &features, "media?", &media); err != nil {
		return nil, err
	}
	options := PlanOptions{Properties: map[string]string{}, Media: map[string]starfile.File{}}
	if properties != nil {
		for _, pair := range properties.Items() {
			key, ok := starlark.AsString(pair[0])
			value, valid := starlark.AsString(pair[1])
			if !ok || !valid {
				return nil, fmt.Errorf("msi.plan: properties must map strings to strings")
			}
			options.Properties[key] = value
		}
	}
	if media != nil {
		for _, pair := range media.Items() {
			key, ok := starlark.AsString(pair[0])
			value, valid := pair[1].(starfile.File)
			if !ok || !valid {
				return nil, fmt.Errorf("msi.plan: media must map relative names to files")
			}
			options.Media[key] = value
		}
	}
	if features != nil {
		options.Features = []string{}
		for i := 0; i < features.Len(); i++ {
			name, ok := starlark.AsString(features.Index(i))
			if !ok {
				return nil, fmt.Errorf("msi.plan: feature names must be strings")
			}
			options.Features = append(options.Features, name)
		}
	}
	return d.Plan(options)
}
