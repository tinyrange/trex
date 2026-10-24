package appx

import (
	"fmt"
	ziparchive "github.com/tinyrange/trex/archive/zip"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("appx", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("appx: got %s, want file", value.Type())
	}
	a, err := Open(file)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, len(a.Entries))
	for i, e := range a.Entries {
		entries[i] = e
	}
	members := make([]starlark.Value, len(a.Packages))
	for i, m := range a.Packages {
		members[i] = starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(m.Name), "type": starlark.String(m.Type), "architecture": starlark.String(m.Architecture),
			"version": starlark.String(m.Version), "size": starlark.MakeUint64(m.Size), "file": m.File, "is_stub": starlark.Bool(m.IsStub),
		})
	}
	files := starlark.NewList(entries)
	return starfile.NewRecord(starlark.StringDict{
		"verify_block_map": starlark.NewBuiltin("verify_block_map", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			maximum := uint64(8 << 30)
			if err := starlark.UnpackArgs("verify_block_map", args, kwargs, "maximum?", &maximum); err != nil {
				return nil, err
			}
			if err := a.VerifyBlockMap(maximum); err != nil {
				return nil, err
			}
			return starlark.None, nil
		}),
		"full_name": starlark.String(a.FullName()), "family_name": starlark.String(a.Identity.FamilyName()),
		"kind": starlark.String(a.Kind), "files": files, "entries": files, "packages": starlark.NewList(members),
		"identity": starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(a.Identity.Name), "publisher": starlark.String(a.Identity.Publisher),
			"version": starlark.String(a.Identity.Version), "architecture": starlark.String(a.Identity.Architecture), "resource_id": starlark.String(a.Identity.ResourceID),
		}),
	}), nil
}

// Entry retains the OPC ZIP name separately from its one-pass decoded path.
// Decode at the package boundary only: consumers must not unescape Name again.
type Entry struct {
	*ziparchive.Entry
	Name        string
	ArchiveName string
	index       *indexedFile
}

func (e *Entry) Attr(name string) (starlark.Value, error) {
	switch name {
	case "name", "path":
		return starlark.String(e.Name), nil
	case "archive_name":
		return starlark.String(e.ArchiveName), nil
	}
	if value := starfile.Attr(e, name); value != nil {
		return value, nil
	}
	return e.Entry.Attr(name)
}
func (e *Entry) AttrNames() []string { return append(e.Entry.AttrNames(), "archive_name") }
