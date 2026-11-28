package nixstore

import (
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("nix_store", args, kwargs, "registration", &value); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("nix_store: expected a registration file")
	}
	db, err := Build(source)
	if err != nil {
		return nil, err
	}
	return starfile.NewReader("Nix store database", db), nil
}

func ClosureBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var roots *starlark.List
	if err := starlark.UnpackArgs("nix_store_closure", args, kwargs, "registration", &value, "roots", &roots); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("nix_store_closure: expected a registration file")
	}
	wanted := make([]string, 0, roots.Len())
	for root := range starlark.Elements(roots) {
		path, ok := starlark.AsString(root)
		if !ok {
			return nil, fmt.Errorf("nix_store_closure: expected a store path")
		}
		wanted = append(wanted, path)
	}
	db, paths, err := BuildClosure(source, wanted)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, 0, len(paths))
	for _, path := range paths {
		values = append(values, starlark.String(path))
	}
	return starfile.NewRecord(starlark.StringDict{
		"database": starfile.NewReader("Nix store database", db),
		"paths":    starlark.NewList(values),
	}), nil
}
