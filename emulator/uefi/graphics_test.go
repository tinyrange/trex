package uefi

import (
	"bytes"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestGraphicsBlitStrideOverlapAndBounds(t *testing.T) {
	memory := cpu.NewAddressSpace(16 << 20)
	if err := memory.Map(ramBase, make([]byte, 16<<20), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	m := &Machine{ramBase: ramBase, opts: Options{Memory: 16 << 20}, firmwareMemory: memory, services: map[uint64]string{}, protocols: map[uint64]map[string]uint64{}, nextService: ramBase + 0x1000, allocations: []allocation{{ramBase, 16, 6}}}
	f := &Firmware{machine: m}
	pixels := make([]byte, 6*3*4)
	if err := f.InstallGraphicsOutput(0xe0000000, pixels, 4, 3, 6); err != nil {
		t.Fatal(err)
	}
	p := f.graphics.protocol
	devicePath := m.protocols[p][devicePathGUID]
	path := m.get(devicePath, 24)
	if devicePath == 0 || path[0] != 1 || path[2] != 20 || !bytes.Equal(path[20:], []byte{0x7f, 0xff, 4, 0}) {
		t.Fatal("GOP handle has no complete hardware device path")
	}
	source := ramBase + 0x20000
	if err := memory.WriteMemory(source, []byte{1, 2, 3, 0}); err != nil {
		t.Fatal(err)
	}
	blit := func(a [10]uint64) uint64 {
		t.Helper()
		a[0] = p
		s, err := f.graphicsCall("GOP.Blt", a)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if s := blit([10]uint64{1: source, 2: 0, 5: 1, 6: 1, 7: 2, 8: 1}); s != 0 {
		t.Fatal(s)
	}
	if !bytes.Equal(pixels[28:36], []byte{1, 2, 3, 0, 1, 2, 3, 0}) || pixels[24] != 0 || pixels[36] != 0 {
		t.Fatal(pixels)
	}
	// Copy one row down with overlap, preserving both source pixels.
	if s := blit([10]uint64{2: 3, 3: 1, 4: 1, 5: 0, 6: 2, 7: 2, 8: 1}); s != 0 {
		t.Fatal(s)
	}
	if !bytes.Equal(pixels[48:56], pixels[28:36]) {
		t.Fatal(pixels)
	}
	before := bytes.Clone(pixels)
	if s := blit([10]uint64{1: source, 2: 0, 5: 3, 6: 0, 7: 2, 8: 1}); s != invalidParameter || !bytes.Equal(before, pixels) {
		t.Fatal(s)
	}
	// Copy to a buffer with nonzero destination and an explicit row stride.
	if s := blit([10]uint64{1: source, 2: 1, 3: 1, 4: 1, 5: 2, 6: 1, 7: 2, 8: 1, 9: 24}); s != 0 {
		t.Fatal(s)
	}
	got := make([]byte, 8)
	if err := memory.ReadMemory(source+32, got, cpu.Read); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pixels[28:36]) {
		t.Fatal(got)
	}
}
