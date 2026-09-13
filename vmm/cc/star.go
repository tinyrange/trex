package cc

import (
	"fmt"
	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

func (b *Backend) String() string          { return "<cc.backend bios pc>" }
func (b *Backend) Type() string            { return "vmm_backend" }
func (b *Backend) Freeze()                 {}
func (b *Backend) Truth() starlark.Bool    { return starlark.True }
func (b *Backend) Hash() (uint32, error)   { return 0, fmt.Errorf("unhashable: cc backend") }
func (b *Backend) VMMBackend() vmm.Backend { return b }
func Builtins() starlark.StringDict {
	return starlark.StringDict{"backend": starlark.NewBuiltin("cc.backend", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs("cc.backend", args, kwargs); err != nil {
			return nil, err
		}
		return &Backend{}, nil
	})}
}
