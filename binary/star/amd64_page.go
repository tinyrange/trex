package star

import (
	"fmt"

	"github.com/tinyrange/trex/memory"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func amd64TranslateBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var cr3, address uint64
	if err := starlark.UnpackArgs("amd64_translate", args, kwargs, "file", &source, "cr3", &cr3, "address", &address); err != nil {
		return nil, err
	}
	file, ok := source.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("amd64_translate: expected a physical memory file")
	}
	result, err := memory.TranslateAMD64(file, cr3, address)
	if err != nil {
		return nil, err
	}
	return starfile.NewRecord(starlark.StringDict{
		"physical_address": starlark.MakeUint64(result.Physical),
		"page_size":        starlark.MakeUint64(result.PageSize),
		"user":             starlark.Bool(result.User),
		"writable":         starlark.Bool(result.Writable),
		"execute":          starlark.Bool(result.Execute),
	}), nil
}

func amd64UserPageTablesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var root starlark.Bytes
	var base uint64
	var entries, supervisor *starlark.List
	if err := starlark.UnpackArgs("amd64_user_page_tables", args, kwargs, "kernel_root", &root, "base", &base, "mappings", &entries, "supervisor_mappings?", &supervisor); err != nil {
		return nil, err
	}
	mappings, err := amd64Mappings(entries)
	if err != nil {
		return nil, err
	}
	upper, err := amd64Mappings(supervisor)
	if err != nil {
		return nil, err
	}
	data, err := memory.AMD64UserPageTables([]byte(root), base, mappings, upper...)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Name: "AMD64 page tables", Data: data}, nil
}

func amd64Mappings(entries *starlark.List) ([]memory.AMD64Mapping, error) {
	if entries == nil {
		return nil, nil
	}
	if entries.Len() > 16384 {
		return nil, fmt.Errorf("amd64_user_page_tables: maximum 16384 mappings")
	}
	mappings := make([]memory.AMD64Mapping, entries.Len())
	for i := range mappings {
		tuple, ok := entries.Index(i).(starlark.Tuple)
		if !ok || len(tuple) != 5 {
			return nil, fmt.Errorf("amd64_user_page_tables: mapping %d must be a five-element tuple", i)
		}
		m := &mappings[i]
		if err := starlark.UnpackArgs("mapping", tuple, nil, "virtual", &m.Virtual, "physical", &m.Physical, "size", &m.Size, "writable", &m.Writable, "execute", &m.Execute); err != nil {
			return nil, err
		}
	}
	return mappings, nil
}
