package star

import (
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

type darwinBootValue struct{ boot vmmapi.DarwinBoot }

func (v *darwinBootValue) String() string        { return "<vmm.darwin_boot>" }
func (v *darwinBootValue) Type() string          { return "vmm_darwin_boot" }
func (v *darwinBootValue) Freeze()               {}
func (v *darwinBootValue) Truth() starlark.Bool  { return starlark.True }
func (v *darwinBootValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: vmm_darwin_boot") }
func (v *darwinBootValue) AttrNames() []string   { return []string{"kernel", "command_line"} }
func (v *darwinBootValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "kernel":
		return starfile.NewReader("Darwin kernel", v.boot.Kernel), nil
	case "command_line":
		return starlark.String(v.boot.CommandLine), nil
	}
	return nil, nil
}
func darwinBootBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kernel starlark.Value
	commandLine := ""
	var osk starlark.Bytes
	if err := starlark.UnpackArgs("darwin_boot", args, kwargs, "kernel", &kernel, "command_line?", &commandLine, "smc_osk?", &osk); err != nil {
		return nil, err
	}
	file, ok := kernel.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("darwin_boot: kernel must be a file")
	}
	boot := vmmapi.DarwinBoot{Kernel: file, CommandLine: commandLine, SMCOSK: []byte(osk)}
	if err := boot.Validate(); err != nil {
		return nil, err
	}
	return &darwinBootValue{boot: boot}, nil
}
