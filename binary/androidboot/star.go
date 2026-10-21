package androidboot

import (
	"fmt"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func section(s Section) *starfile.Record {
	return starfile.NewRecord(starlark.StringDict{"name": starlark.String(s.Name), "offset": starlark.MakeInt64(s.Offset), "size": starlark.MakeInt64(s.Size), "file": adapter.File(s.Data)})
}
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("android_boot", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("android_boot: expected file")
	}
	i, err := Open(source)
	if err != nil {
		return nil, err
	}
	sections := make([]starlark.Value, len(i.Sections))
	for j, s := range i.Sections {
		sections[j] = section(s)
	}
	fragments := make([]starlark.Value, len(i.Fragments))
	for j, f := range i.Fragments {
		ids := make([]starlark.Value, len(f.BoardID))
		for k, id := range f.BoardID {
			ids[k] = starlark.MakeUint(uint(id))
		}
		fragments[j] = starfile.NewRecord(starlark.StringDict{"name": starlark.String(f.Name), "type": starlark.MakeUint(uint(f.Type)), "board_id": starlark.NewList(ids), "section": section(f.Section)})
	}
	return starfile.NewRecord(starlark.StringDict{"kind": starlark.String(i.Kind), "version": starlark.MakeUint(uint(i.Version)), "page_size": starlark.MakeUint(uint(i.PageSize)), "os_version": starlark.MakeUint(uint(i.OSVersion)), "name": starlark.String(i.Name), "command_line": starlark.String(i.CommandLine), "sections": starlark.NewList(sections), "fragments": starlark.NewList(fragments)}), nil
}
