package shell

import (
	"fmt"
	"io/fs"
	"time"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// Files is a Unix namespace shared directly by shell, compiler and Linux
// actions. Files cross the recipe boundary using the standard portable File.
type Files struct{ *MemoryFS }

func (*Files) String() string        { return "<unix filesystem>" }
func (*Files) Type() string          { return "unix_filesystem" }
func (*Files) Freeze()               {} // resource, like directory and channel values
func (*Files) Truth() starlark.Bool  { return true }
func (*Files) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: unix_filesystem") }
func (*Files) AttrNames() []string   { return []string{"mkdir", "write", "find", "stat", "remove"} }
func (f *Files) Attr(name string) (starlark.Value, error) {
	switch name {
	case "mkdir", "write", "find", "stat", "remove":
		return starlark.NewBuiltin(name, f.call), nil
	}
	return nil, nil
}
func FilesBuiltin(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	maximum := int64(64 << 20)
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "maximum?", &maximum); err != nil {
		return nil, err
	}
	m, err := NewMemoryFS(maximum)
	if err != nil {
		return nil, err
	}
	return &Files{m}, nil
}
func (f *Files) call(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var value starlark.Value
	mode := uint32(0644)
	var modified starlark.Value = starlark.None
	var err error
	switch b.Name() {
	case "write":
		err = starlark.UnpackArgs("write", args, kwargs, "path", &name, "data", &value, "mode?", &mode, "mtime?", &modified)
	case "mkdir":
		mode = 0755
		err = starlark.UnpackArgs("mkdir", args, kwargs, "path", &name, "mode?", &mode, "mtime?", &modified)
	default:
		err = starlark.UnpackArgs(b.Name(), args, kwargs, "path", &name)
	}
	if err != nil {
		return nil, err
	}
	if mode > 0777 {
		return nil, fmt.Errorf("mode must be between 0 and 0777")
	}
	var timestamp int64
	if modified != starlark.None {
		if err := starlark.AsInt(modified, &timestamp); err != nil {
			return nil, err
		}
	}
	switch b.Name() {
	case "mkdir":
		err = f.MkdirMode(name, fs.FileMode(mode))
	case "remove":
		err = f.Remove(name)
	case "find":
		info, e := f.Stat(name)
		if e != nil {
			return nil, e
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("find: %s is not a regular file", name)
		}
		data, e := f.ReadFile(name)
		if e != nil {
			return nil, e
		}
		return &starfile.Bytes{Name: name, Data: data}, nil
	case "stat":
		info, e := f.Stat(name)
		if e != nil {
			return nil, e
		}
		return starlarkstruct.FromStringDict(starlark.String("unix_stat"), starlark.StringDict{"size": starlark.MakeInt64(info.Size()), "mode": starlark.MakeUint(uint(info.Mode().Perm())), "directory": starlark.Bool(info.IsDir()), "mtime": starlark.MakeInt64(info.ModTime().Unix())}), nil
	case "write":
		var data []byte
		switch v := value.(type) {
		case starlark.String:
			data = []byte(v)
		case starlark.Bytes:
			data = []byte(v)
		case starfile.File:
			if v.Size() < 0 || v.Size() > f.maximum {
				return nil, fmt.Errorf("file exceeds filesystem budget")
			}
			data, err = starfile.ReadAll(v)
		default:
			return nil, fmt.Errorf("write: expected file, bytes or string")
		}
		if err == nil {
			err = f.WriteFile(name, data, fs.FileMode(mode))
		}
	}
	if err == nil && modified != starlark.None {
		err = f.SetModTime(name, time.Unix(timestamp, 0))
	}
	return starlark.None, err
}
