package star

import (
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

type linuxBootValue struct{ boot vmmapi.LinuxBoot }

func (v *linuxBootValue) String() string        { return "<vmm.linux_boot>" }
func (v *linuxBootValue) Type() string          { return "vmm_linux_boot" }
func (v *linuxBootValue) Freeze()               {}
func (v *linuxBootValue) Truth() starlark.Bool  { return starlark.True }
func (v *linuxBootValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: vmm_linux_boot") }
func (v *linuxBootValue) AttrNames() []string   { return []string{"kernel", "initramfs", "command_line"} }
func (v *linuxBootValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "kernel":
		return starfile.NewReader("Linux kernel", v.boot.Kernel), nil
	case "initramfs":
		if v.boot.Initramfs == nil {
			return starlark.None, nil
		}
		return starfile.NewReader("Linux initramfs", v.boot.Initramfs), nil
	case "command_line":
		return starlark.String(v.boot.CommandLine), nil
	}
	return nil, nil
}
func linuxBootBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kernel starlark.Value
	var initramfs starlark.Value = starlark.None
	commandLine := ""
	if err := starlark.UnpackArgs("linux_boot", args, kwargs, "kernel", &kernel, "initramfs?", &initramfs, "command_line?", &commandLine); err != nil {
		return nil, err
	}
	file, ok := kernel.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("linux_boot: kernel must be a file")
	}
	boot := vmmapi.LinuxBoot{Kernel: file, CommandLine: commandLine}
	if initramfs != starlark.None {
		source, ok := initramfs.(storage.Reader)
		if !ok {
			return nil, fmt.Errorf("linux_boot: initramfs must be a file or None")
		}
		boot.Initramfs = source
	}
	if err := boot.Validate(); err != nil {
		return nil, err
	}
	return &linuxBootValue{boot: boot}, nil
}
