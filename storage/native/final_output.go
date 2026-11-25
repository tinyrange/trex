package native

import (
	"errors"
	"fmt"
	"os"

	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
)

// finalOutput is an explicitly requested, retained final artifact. It is not a
// scratch file or overlay spill: no implicit temporary directory or deletion is
// used. In particular, this lets independent Setup/deployment controls produce
// useful raw disk images through the ordinary portable block interface.
type finalOutput struct{ *osFile }

func createOutputBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var size int64
	if err := starlark.UnpackArgs("create_output", args, kwargs, "name", &name, "size", &size); err != nil {
		return nil, err
	}
	if size <= 0 || size > defaultFinalOutputLimit {
		return nil, fmt.Errorf("create_output: size must be between 1 and %d", defaultFinalOutputLimit)
	}
	resources, registryErr := lifecycle.ForThread(thread)
	if registryErr == nil {
		if err := resources.Context().Err(); err != nil {
			return nil, err
		}
	}
	// Never overwrite an input, an existing output, or a symlink.
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	// Logical size only. Sparse-capable filesystems leave untouched ranges as
	// holes; no image builder, zero-fill pass, or intermediate file is involved.
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		return nil, err
	}
	out := &finalOutput{&osFile{name: name, file: file, size: size}}
	if registryErr == nil {
		out.metrics = resources.Metrics()
		if _, err := resources.Add(out); err != nil {
			_ = out.Close()
			return nil, err
		}
	}
	return out, nil
}

func (f *finalOutput) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off > f.size || int64(len(p)) > f.size-off {
		return 0, fmt.Errorf("final output write exceeds fixed logical size")
	}
	return f.file.WriteAt(p, off)
}
func (f *finalOutput) Sync() error { return f.file.Sync() }
func (f *finalOutput) Close() error {
	f.closeOnce.Do(func() { f.closeErr = errors.Join(f.file.Sync(), f.file.Close()) })
	return f.closeErr
}
func (f *finalOutput) Attr(name string) (starlark.Value, error) {
	switch name {
	case "flush", "close":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
				return nil, err
			}
			if name == "close" {
				return starlark.None, f.Close()
			}
			return starlark.None, f.Sync()
		}), nil
	}
	return fileAttr(f, name), nil
}
func (f *finalOutput) AttrNames() []string { return append(fileAttrNames(), "flush", "close") }
