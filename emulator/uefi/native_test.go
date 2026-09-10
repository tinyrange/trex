package uefi

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"image"
	"math/bits"
	"testing"

	"j5.nz/cc/hypervisor"
)

func TestNativeDisplayDamageOwnsPixels(t *testing.T) {
	n := &NativeExecution{ram: make([]byte, 4096)}
	if err := n.AttachRAMFB(0x09020000); err != nil {
		t.Fatal(err)
	}
	// Configure a 4x4 BGRX framebuffer via the same fw_cfg DMA transaction as
	// the Windows driver, then modify one row while reusing capture storage.
	binary.BigEndian.PutUint32(n.ram[16:], 0x20<<16|24)
	binary.BigEndian.PutUint32(n.ram[20:], 28)
	binary.BigEndian.PutUint64(n.ram[24:], 64)
	binary.BigEndian.PutUint64(n.ram[64:], 256)
	binary.BigEndian.PutUint32(n.ram[72:], 0x34325258)
	binary.BigEndian.PutUint32(n.ram[80:], 4)
	binary.BigEndian.PutUint32(n.ram[84:], 4)
	binary.BigEndian.PutUint32(n.ram[88:], 16)
	if err := n.Display.Write(0x09020010, 8, bits.ReverseBytes64(16)); err != nil {
		t.Fatal(err)
	}
	s := &NativeDisplaySession{Execution: n}
	first := s.Snapshot(image.Rectangle{}, 0, true)
	if len(first.Pixels) != 64 {
		t.Fatalf("initial pixels %d", len(first.Pixels))
	}
	n.ram[256+16] = 123
	second := s.Snapshot(image.Rectangle{}, first.Generation, true)
	if second.Rect != image.Rect(0, 1, 4, 2) || second.Pixels[0] != 123 || first.Pixels[16] != 0 {
		t.Fatal("damage or ownership was lost")
	}
	third := s.Snapshot(image.Rectangle{}, second.Generation, true)
	if len(third.Pixels) != 0 || third.Generation != second.Generation {
		t.Fatal("unchanged frame produced an update")
	}
}

func TestNativeRuntimeMapRelocation(t *testing.T) {
	m := machine(t, 0x14000000)
	ram := make([]byte, m.opts.Memory)
	if err := m.ReadMemory(m.ramBase, ram); err != nil {
		t.Fatal(err)
	}
	fw := *m
	n := &NativeExecution{base: m.ramBase, ram: ram, firmware: &fw}
	fw.runtimeMemory = n
	original := append([]byte(nil), ram[0x500:0x500+136]...)
	descriptor := ram[0x20000 : 0x20000+40]
	binary.LittleEndian.PutUint64(descriptor[8:], m.ramBase)
	binary.LittleEndian.PutUint64(descriptor[16:], 0xffff800000000000)
	binary.LittleEndian.PutUint64(descriptor[24:], 16)
	binary.LittleEndian.PutUint64(descriptor[32:], 1<<63|8)
	args := [8]uint64{40, 40, 1, m.ramBase + 0x20000}
	if status := n.setVirtualAddressMap(args); status != 0 {
		t.Fatalf("map: %#x", status)
	}
	if m.read64(m.ramBase+0x500+24) != binary.LittleEndian.Uint64(original[24:]) {
		t.Fatal("software checkpoint runtime was changed")
	}
	updated := ram[0x500 : 0x500+136]
	if got := binary.LittleEndian.Uint64(updated[24:]); got != 0xffff800000000000+binary.LittleEndian.Uint64(original[24:])-m.ramBase {
		t.Fatalf("runtime pointer: %#x", got)
	}
	for _, table := range [][]byte{updated, ram[m.systemTable-m.ramBase : m.systemTable-m.ramBase+120]} {
		copy := append([]byte(nil), table...)
		want := binary.LittleEndian.Uint32(copy[16:])
		clear(copy[16:20])
		if crc32.ChecksumIEEE(copy) != want {
			t.Fatal("relocated table checksum")
		}
	}
	if status := n.setVirtualAddressMap(args); status != invalidParameter {
		t.Fatal("accepted repeated virtual map")
	}
}

type executionStub struct {
	hypervisor.ARM64
	calls int
	pc    uint64
}

func (s *executionStub) Run(context.Context) (hypervisor.Exit, error) {
	s.calls++
	if s.calls == 1 {
		return hypervisor.Exit{Reason: hypervisor.ExitCanceled}, nil
	}
	return hypervisor.Exit{Reason: hypervisor.ExitException, PC: s.pc}, nil
}

func TestNativeInternalWakeupContinues(t *testing.T) {
	stub := &executionStub{pc: 0x1234}
	n := &NativeExecution{cpu: stub, Counts: map[string]uint64{}}
	ex, err := n.Run(context.Background())
	if err != nil || ex.PC != stub.pc || stub.calls != 2 {
		t.Fatalf("exit %+v calls%d err%v", ex, stub.calls, err)
	}
}

func TestBoundedMMIOObservation(t *testing.T) {
	n := &NativeExecution{MMIOLimit: 2}
	d := observedMMIO{owner: n}
	for i := uint64(0); i < 3; i++ {
		d.observe(MMIOAccess{Address: i})
	}
	if len(n.MMIO) != 2 || n.MMIO[0].Address != 1 || n.MMIO[1].Address != 2 {
		t.Fatal("incorrect bounded MMIO tail")
	}
	if err := (&NativeExecution{base: 0x1000, ram: bytes.Repeat([]byte{1}, 16)}).ReadMemory(0x100f, make([]byte, 2), 0); err == nil {
		t.Fatal("accepted out-of-range native memory")
	}
}
