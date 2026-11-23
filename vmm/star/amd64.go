package star

import (
	"fmt"

	"github.com/tinyrange/trex/storage"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

type amd64BootValue struct{ boot vmmapi.AMD64Boot }

func (*amd64BootValue) String() string        { return "<vmm.amd64_boot>" }
func (*amd64BootValue) Type() string          { return "vmm_amd64_boot" }
func (*amd64BootValue) Freeze()               {}
func (*amd64BootValue) Truth() starlark.Bool  { return starlark.True }
func (*amd64BootValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: vmm_amd64_boot") }

func amd64BootBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ram starlark.Value
	var registers *starlark.Dict
	var boot vmmapi.AMD64Boot
	boot.Registers.Rflags = 2
	if err := starlark.UnpackArgs("amd64_boot", args, kwargs, "ram", &ram, "registers", &registers,
		"cr3", &boot.PageTable, "gdt", &boot.GDT.Base, "gdt_limit", &boot.GDT.Limit,
		"user?", &boot.User, "fs_base?", &boot.FSBase, "gs_base?", &boot.GSBase,
		"idt?", &boot.IDT.Base, "idt_limit?", &boot.IDT.Limit); err != nil {
		return nil, err
	}
	var ok bool
	if boot.RAM, ok = ram.(storage.Reader); !ok {
		return nil, fmt.Errorf("amd64_boot: expected a portable RAM file")
	}
	r := &boot.Registers
	fields := map[string]*uint64{
		"rax": &r.Rax, "rbx": &r.Rbx, "rcx": &r.Rcx, "rdx": &r.Rdx,
		"rsi": &r.Rsi, "rdi": &r.Rdi, "rsp": &r.Rsp, "rbp": &r.Rbp,
		"r8": &r.R8, "r9": &r.R9, "r10": &r.R10, "r11": &r.R11,
		"r12": &r.R12, "r13": &r.R13, "r14": &r.R14, "r15": &r.R15,
		"rip": &r.Rip, "rflags": &r.Rflags,
	}
	for _, item := range registers.Items() {
		name, ok := starlark.AsString(item[0])
		if !ok || fields[name] == nil {
			return nil, fmt.Errorf("amd64_boot: unknown register %s", item[0])
		}
		if err := starlark.AsInt(item[1], fields[name]); err != nil {
			return nil, fmt.Errorf("amd64_boot: %s: %w", name, err)
		}
	}
	return &amd64BootValue{boot}, nil
}
