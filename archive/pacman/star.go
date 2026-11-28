package pacman

import (
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func MetadataBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var pkginfo bool
	if err := starlark.UnpackArgs("pacman_metadata", args, kwargs, "file", &source, "pkginfo?", &pkginfo); err != nil {
		return nil, err
	}
	reader, ok := source.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("pacman: expected a metadata file")
	}
	fields, err := readRecord(io.NewSectionReader(reader, 0, reader.Size()), pkginfo)
	if err != nil {
		return nil, err
	}
	result := starlark.NewDict(len(fields))
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		values := make([]starlark.Value, len(fields[name]))
		for i, value := range fields[name] {
			values[i] = starlark.String(value)
		}
		if err := result.SetKey(starlark.String(name), starlark.NewList(values)); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func CompareBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var left, right string
	if err := starlark.UnpackArgs("pacman_compare", args, kwargs, "left", &left, "right", &right); err != nil {
		return nil, err
	}
	return starlark.MakeInt(compareVersion(left, right)), nil
}

func InstalledBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var metadata *starlark.Dict
	var paths, backups *starlark.List
	var explicit bool
	if err := starlark.UnpackArgs("pacman_installed", args, kwargs, "metadata", &metadata, "paths", &paths, "backups", &backups, "explicit?", &explicit); err != nil {
		return nil, err
	}
	fields := make(Fields, metadata.Len())
	for _, pair := range metadata.Items() {
		name, nameOK := starlark.AsString(pair[0])
		values, valuesOK := pair[1].(*starlark.List)
		if !nameOK || !valuesOK {
			return nil, fmt.Errorf("pacman: expected a metadata field and string list")
		}
		list, err := stringList(values)
		if err != nil {
			return nil, err
		}
		fields[name] = list
	}
	filePaths, err := stringList(paths)
	if err != nil {
		return nil, err
	}
	backedUp, err := stringList(backups)
	if err != nil {
		return nil, err
	}
	desc, files, err := installedRecords(fields, filePaths, backedUp, explicit)
	if err != nil {
		return nil, err
	}
	return starfile.NewRecord(starlark.StringDict{"desc": starlark.String(desc), "files": starlark.String(files)}), nil
}

func stringList(list *starlark.List) ([]string, error) {
	values := make([]string, 0, list.Len())
	for item := range starlark.Elements(list) {
		value, ok := starlark.AsString(item)
		if !ok {
			return nil, fmt.Errorf("pacman: expected a string")
		}
		values = append(values, value)
	}
	return values, nil
}
