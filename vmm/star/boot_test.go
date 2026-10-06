package star

import (
	"testing"

	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

func TestLinuxBootValidationBeforeLaunch(t *testing.T) {
	kernel := &starfile.Bytes{Name: "kernel", Data: []byte("kernel")}
	for _, tc := range []struct {
		name         string
		boot         *vmmapi.LinuxBoot
		capabilities []string
		valid        bool
	}{
		{"firmware-default", nil, nil, true},
		{"unsupported-direct-boot", &vmmapi.LinuxBoot{Kernel: kernel}, nil, false},
		{"missing-kernel", &vmmapi.LinuxBoot{}, []string{"boot.linux"}, false},
		{"empty-initramfs", &vmmapi.LinuxBoot{Kernel: kernel, Initramfs: &starfile.Bytes{}}, []string{"boot.linux"}, false},
		{"nul-command-line", &vmmapi.LinuxBoot{Kernel: kernel, CommandLine: "console=ttyS0\x00-append"}, []string{"boot.linux"}, false},
		{"supported-direct-boot", &vmmapi.LinuxBoot{Kernel: kernel, CommandLine: "console=ttyS0"}, []string{"boot.linux"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			thread, _, _ := newStarlarkRuntime("-")
			resources, _ := lifecycle.ForThread(thread)
			defer resources.Close()
			backend := &fakeVMMBackend{capabilities: tc.capabilities}
			machine := &vmmMachineValue{machine: VMMMachine{
				Architecture: "x86_64", Memory: 64 << 20, CPUs: 1,
				Display: VMMDisplay{Mode: "none"}, Boot: tc.boot,
			}}
			_, err := vmmStartBuiltin(thread, nil, starlark.Tuple{machine, &fakeVMMBackendValue{backend: backend}}, nil)
			if tc.valid {
				if err != nil || backend.starts != 1 {
					t.Fatalf("start = %d, err = %v", backend.starts, err)
				}
			} else if err == nil || backend.starts != 0 {
				t.Fatalf("invalid boot reached backend: starts=%d err=%v", backend.starts, err)
			}
		})
	}
}

func TestLinuxBootStarlarkComposition(t *testing.T) {
	thread, _, _ := newStarlarkRuntime("-")
	resources, _ := lifecycle.ForThread(thread)
	defer resources.Close()
	globals, err := starlark.ExecFile(thread, "boot.star", `
boot = vmm.linux_boot(kernel, initramfs=initrd, command_line="console=ttyS0")
machine = vmm.machine(architecture="x86_64", memory=67108864, boot=boot)
assertion = "boot" in dir(machine) and machine.boot.command_line == boot.command_line and machine.boot.initramfs.size == initrd.size
`, starlark.StringDict{
		"vmm":    &starlarkstruct.Module{Name: "vmm", Members: Builtins()},
		"kernel": &starfile.Bytes{Name: "kernel", Data: []byte("kernel")},
		"initrd": &starfile.Bytes{Name: "initrd", Data: []byte("initrd")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if globals["assertion"] != starlark.True {
		t.Fatal("boot intent lost during composition or introspection")
	}
}
