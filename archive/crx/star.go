package crx

import (
	"fmt"

	ziparchive "github.com/tinyrange/trex/archive/zip"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("crx", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("crx: got %s, want file", value.Type())
	}
	archive, err := Open(file)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, len(archive.ZIP.File))
	for i, entry := range archive.ZIP.File {
		entries[i] = ziparchive.NewEntry(entry)
	}
	files := starlark.NewList(entries)
	return starfile.NewRecord(starlark.StringDict{
		"id": starlark.String(archive.ID), "version": starlark.MakeUint64(uint64(archive.Version)),
		"files": files, "entries": files,
	}), nil
}
