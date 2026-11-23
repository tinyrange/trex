package vmm

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/memory"
	"j5.nz/cc/hypervisor/x86state"
)

func TestAMD64BootValidatesUserEntryAndGDT(t *testing.T) {
	const root = 0x4000
	const gdt = 0xffffff8000001000
	ram := make([]byte, 0x10000)
	binary.LittleEndian.PutUint64(ram[0x1000:], 0x83)
	kernelRoot := make([]byte, 4096)
	binary.LittleEndian.PutUint64(kernelRoot[511*8:], 0x1003)
	mapping := memory.AMD64UserMapping{Virtual: 0x400000, Physical: 0x8000, Size: 4096, Execute: true}
	tables, err := memory.AMD64UserPageTables(kernelRoot, root, []memory.AMD64UserMapping{mapping})
	if err != nil {
		t.Fatal(err)
	}
	copy(ram[root:], tables)
	boot := AMD64Boot{
		RAM: bytes.NewReader(ram), PageTable: root, User: true,
		GDT:       x86state.DescriptorTable{Base: gdt, Limit: 55},
		Registers: x86state.Registers{Rip: mapping.Virtual}, SyscallEntry: gdt,
	}
	if err := boot.Validate(16 << 20); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*AMD64Boot)
	}{
		{"supervisor-only entry", func(b *AMD64Boot) { b.Registers.Rip = gdt }},
		{"user-accessible syscall entry", func(b *AMD64Boot) { b.SyscallEntry = mapping.Virtual }},
		{"unmapped GDT", func(b *AMD64Boot) { b.GDT.Base = 0x500000 }},
		{"root outside RAM", func(b *AMD64Boot) { b.PageTable = ^uint64(0) &^ 4095 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := boot
			test.mutate(&invalid)
			if err := invalid.Validate(16 << 20); err == nil {
				t.Fatal("accepted invalid AMD64 boot")
			}
		})
	}
}
