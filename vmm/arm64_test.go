package vmm

import (
	"bytes"
	"testing"
)

func TestARM64BootBoundsAndEncodedRAM(t *testing.T) {
	valid := ARM64Boot{Image: bytes.NewReader(make([]byte, 16)), Address: 0x70000000, Entry: 0x70000004, MemoryBase: 0x70000000, MemorySize: 16 << 20}
	if err := valid.Validate(16 << 20); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ARM64Boot){func(b *ARM64Boot) { b.Entry += 1 }, func(b *ARM64Boot) { b.Address -= 4 }, func(b *ARM64Boot) { b.Entry = b.Address + 16 }, func(b *ARM64Boot) { b.MemorySize = 32 << 20 }, func(b *ARM64Boot) { b.MemoryBase = ^uint64(0) - 0x3fff }} {
		b := valid
		mutate(&b)
		if err := b.Validate(16 << 20); err == nil {
			t.Fatal("accepted invalid handoff")
		}
	}
}

func TestARM64PayloadBoundsAndOverlap(t *testing.T) {
	b := ARM64Boot{Image: bytes.NewReader(make([]byte, 16)), Address: 0x70000000, Entry: 0x70000000, MemoryBase: 0x70000000}
	load := ARM64Load{Image: bytes.NewReader(make([]byte, 16)), Address: 0x70004000}
	b.Loads = []ARM64Load{load}
	if e := b.Validate(16 << 20); e != nil {
		t.Fatal(e)
	}
	for _, loads := range [][]ARM64Load{{load, load}, {{Image: load.Image, Address: b.Address}}, {{Image: load.Image, Address: 0x71000000}}, {{Image: nil, Address: load.Address}}} {
		b.Loads = loads
		if e := b.Validate(16 << 20); e == nil {
			t.Fatal("invalid payload accepted")
		}
	}
}

func TestARM64GenericAlignmentIsIndependentOfHostPages(t *testing.T) {
	b := ARM64Boot{Image: bytes.NewReader(make([]byte, 16)), Address: 0x1004, Entry: 0x1004, MemoryBase: 0x1000, Loads: []ARM64Load{{Image: bytes.NewReader([]byte{1}), Address: 0x1017}}}
	if err := b.Validate(4096); err != nil {
		t.Fatal(err)
	}
}
