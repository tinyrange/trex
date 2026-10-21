package irix

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func pdStrings(values []string) *starlark.List {
	out := []starlark.Value{}
	for _, s := range values {
		out = append(out, starlark.String(s))
	}
	return starlark.NewList(out)
}
func pdMarks(values []Mark) *starlark.List {
	out := []starlark.Value{}
	for _, m := range values {
		out = append(out, starfile.NewRecord(starlark.StringDict{"product": starlark.String(m.Product), "image": starlark.String(m.Image), "subsystem": starlark.String(m.Subsystem), "low": starlark.MakeInt64(m.Low), "high": starlark.MakeInt64(m.High)}))
	}
	return starlark.NewList(out)
}
func productsValue(products []Product) starlark.Value {
	out := []starlark.Value{}
	for _, p := range products {
		images := []starlark.Value{}
		for _, im := range p.Images {
			subsystems := []starlark.Value{}
			for _, ss := range im.Subsystems {
				req := []starlark.Value{}
				for _, g := range ss.Prerequisites {
					req = append(req, pdMarks(g))
				}
				subsystems = append(subsystems, starfile.NewRecord(starlark.StringDict{"name": starlark.String(ss.Name), "description": starlark.String(ss.Description), "expression": starlark.String(ss.Expression), "alternate": starlark.String(ss.Alternate), "flags": starlark.MakeInt(int(ss.Flags)), "installed": starlark.MakeUint(uint(ss.Installed)), "replacements": pdMarks(ss.Replacements), "prerequisites": starlark.NewList(req), "extensions": pdMarks(ss.Extensions), "additional": pdMarks(ss.Additional), "final": pdMarks(ss.Final), "attributes": pdStrings(ss.Attributes)}))
			}
			images = append(images, starfile.NewRecord(starlark.StringDict{"name": starlark.String(im.Name), "description": starlark.String(im.Description), "alternate": starlark.String(im.Alternate), "flags": starlark.MakeInt(int(im.Flags)), "format": starlark.MakeInt(int(im.Format)), "order": starlark.MakeInt(int(im.Order)), "version": starlark.MakeUint(uint(im.Version)), "length": starlark.MakeUint(uint(im.Length)), "padding": starlark.MakeUint(uint(im.Padding)), "extensions": pdMarks(im.Extensions), "attributes": pdStrings(im.Attributes), "subsystems": starlark.NewList(subsystems)}))
		}
		out = append(out, starfile.NewRecord(starlark.StringDict{"name": starlark.String(p.Name), "description": starlark.String(p.Description), "alternate": starlark.String(p.Alternate), "flags": starlark.MakeInt(int(p.Flags)), "format": starlark.MakeInt(int(p.Format)), "date": starlark.MakeUint(uint(p.Date)), "extensions": pdMarks(p.Extensions), "attributes": pdStrings(p.Attributes), "images": starlark.NewList(images)}))
	}
	return starfile.NewRecord(starlark.StringDict{"products": starlark.NewList(out)})
}
func ProductBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	if err := starlark.UnpackArgs("irix_product", args, kwargs, "file", &value, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("irix_product: expected file")
	}
	products, err := ReadProducts(file, maximum)
	if err != nil {
		return nil, err
	}
	return productsValue(products), nil
}
