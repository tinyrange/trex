package rfe

import (
	"renvo.dev/rfe/x86"
	"testing"
)

func architecturalRoot(t *testing.T, c *cpu, root uint64) {
	t.Helper()
	copy(c.ram[0x900:], []byte{0x0f, 0x22, 0xd8})
	ins, err := x86.DecodeMode(c, 0x900, 32)
	if err != nil {
		t.Fatal(err)
	}
	c.core.R[0] = root
	if err = c.core.ExecuteCachedInstruction(ins); err != nil {
		t.Fatal(err)
	}
}
func TestNativeViewsSurviveManyRootsAndInactiveTableWrites(t *testing.T) {
	c := jitCPU(t, 32, []byte{0xeb, 0xfe})
	c.system.CR[0] = 0x80010011
	for i := 0; i < 12; i++ {
		root := uint64(0x10000 + i*8192)
		c.Write(root, 4, root+4096|0x67)
		c.Write(root+4096+6*4, 4, uint64(0x40000+i*4096)|0x67)
	}
	for i := 0; i < 12; i++ {
		architecturalRoot(t, c, uint64(0x10000+i*8192))
		c.jit.NativeRefill(0x6000)
	}
	for i := 0; i < 12; i++ {
		architecturalRoot(t, c, uint64(0x10000+i*8192))
		p, ok := c.jit.NativeContext().Memory.Lookup(6)
		if !ok || p.Data != (*[4096]byte)(c.ram[0x40000+i*4096:]) {
			t.Fatal("root view was evicted or aliased", i)
		}
	}
	// Root zero is inactive; its consumed PTE must nevertheless remain watched.
	c.Write(0x11000+6*4, 4, 0x70067)
	architecturalRoot(t, c, 0x10000)
	if _, ok := c.jit.NativeContext().Memory.Lookup(6); ok {
		t.Fatal("inactive root kept stale PTE grant")
	}
	c.jit.NativeRefill(0x6000)
	p, _ := c.jit.NativeContext().Memory.Lookup(6)
	if p.Data != (*[4096]byte)(c.ram[0x70000:]) {
		t.Fatal("refill used stale software translation")
	}
}
func TestINVLPGRevokesLargeMappingEvenWithoutAddressedSlice(t *testing.T) {
	c := jitCPU(t, 32, []byte{0xeb, 0xfe})
	c.system.CR[0], c.system.CR[3], c.system.CR[4] = 0x80010011, 0x3000, 16
	c.Write(0x3000, 4, 0xe7)
	c.Write(0x3004, 4, 0x4067)
	c.Write(0x4000, 4, 0x80067)
	c.jit.NativeRefill(0x6000)
	c.jit.NativeRefill(0x400000)
	m := c.jit.NativeContext().Memory
	copy(c.ram[0x900:], []byte{0x0f, 0x01, 0x38}) // invlpg [eax]
	ins, err := x86.DecodeMode(c, 0x900, 32)
	if err != nil {
		t.Fatal(err)
	}
	c.core.R[0] = 0x8000 // this 4 KiB slice is absent, same 4 MiB mapping
	if err = c.core.ExecuteCachedInstruction(ins); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Lookup(6); ok {
		t.Fatal("large-page sibling survived INVLPG")
	}
	if _, ok := m.Lookup(0x400); !ok {
		t.Fatal("unrelated small mapping was flushed")
	}
}
