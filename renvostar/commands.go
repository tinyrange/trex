package renvostar

import (
	"fmt"
	"path"

	"github.com/tinyrange/trex/filesystem"
	"github.com/tinyrange/trex/renvostar/toolchain"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"renvo.dev/driver"
)

func commandBuiltin(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if b.Name() == "archiver" {
		index := false
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "index?", &index); err != nil {
			return nil, err
		}
		return toolchain.Archiver(index), nil
	}
	target := ""
	arena := uint64(32 << 20)
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "target", &target, "arena_size?", &arena); err != nil {
		return nil, err
	}
	if target == "" || arena == 0 {
		return nil, fmt.Errorf("target and positive arena_size required")
	}
	return toolchain.Compiler(target, arena, b.Name() == "linker"), nil
}
func headersBuiltin(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
		return nil, err
	}
	source := driver.BundledSourceFS()
	if source == nil || !source.PathExists("/libc/include") {
		return nil, fmt.Errorf("renvo.headers: bundled libc headers unavailable (requires renvo_bundle)")
	}
	out := filesystem.New()
	var walk func(string) error
	walk = func(dir string) error {
		entries, ok := source.ReadDir(dir)
		if !ok {
			return fmt.Errorf("renvo.headers: cannot read %s", dir)
		}
		for _, entry := range entries {
			name := path.Join(dir, entry.Name)
			if entry.IsDir {
				if err := walk(name); err != nil {
					return err
				}
				continue
			}
			data, ok := source.ReadFile(name)
			if !ok {
				return fmt.Errorf("renvo.headers: cannot read %s", name)
			}
			out.PutFile(name, filesystem.FileRecord{File: &starfile.Bytes{Name: name, Data: data}})
		}
		return nil
	}
	if err := walk("/libc/include"); err != nil {
		return nil, err
	}
	return out, nil
}
