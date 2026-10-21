package uefi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
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
	fw.exited = true // Native continuation requires ExitBootServices.
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

type powerStub struct {
	hypervisor.ARM64
	function uint64
	calls    int
}

func (s *powerStub) Run(context.Context) (hypervisor.Exit, error) {
	s.calls++
	return hypervisor.Exit{Reason: hypervisor.ExitException, Syndrome: 0x16 << 26, PC: 0x1234}, nil
}
func (s *powerStub) Register(uint32) (uint64, error) { return s.function, nil }
func (s *powerStub) HandlePSCI() (bool, error)       { return true, nil }

func TestNativePowerRequestIsTerminal(t *testing.T) {
	for _, request := range []struct {
		function uint64
		reason   uint32
	}{
		{0x84000008, hypervisor.ExitShutdown}, {0x84000009, hypervisor.ExitReset},
	} {
		stub := &powerStub{function: request.function}
		n := &NativeExecution{cpu: stub, Counts: map[string]uint64{}}
		for i := 0; i < 2; i++ {
			ex, err := n.Run(context.Background())
			if err != nil || ex.Reason != request.reason || stub.calls != 1 {
				t.Fatalf("request %#x: exit %+v calls %d err %v", request.function, ex, stub.calls, err)
			}
		}
		err := n.advanceDisplay(context.Background())
		if errors.Is(err, errNativeShutdown) != (request.reason == hypervisor.ExitShutdown) || err == nil {
			t.Fatalf("incorrect display result: %v", err)
		}
	}
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

type debugUnloadStub struct {
	hypervisor.ARM64
	regs [32]uint64
}

func (s *debugUnloadStub) Register(i uint32) (uint64, error)     { return s.regs[i], nil }
func (s *debugUnloadStub) SetRegister(i uint32, v uint64) error  { s.regs[i] = v; return nil }
func (s *debugUnloadStub) SystemRegister(uint16) (uint64, error) { return 0, nil }

func TestNativeBootServicesValidateExitAndUseNativeRAM(t *testing.T) {
	m := machine(t, 0x14000000)
	stub := &debugUnloadStub{}
	n := &NativeExecution{cpu: stub, base: m.ramBase, ram: make([]byte, m.opts.Memory), firmware: m, Counts: map[string]uint64{}}
	m.runtimeMemory = n
	stub.regs[0], stub.regs[1], stub.regs[2] = 4, 128, m.ramBase+0x30000
	stub.regs[30] = 0x12345678
	if err := n.runtimeCall("AllocatePool"); err != nil {
		t.Fatal(err)
	}
	if stub.regs[0] != 0 || stub.regs[31] != stub.regs[30] || binary.LittleEndian.Uint64(n.ram[0x30000:]) == 0 {
		t.Fatal("native boot allocation or return failed")
	}
	stub.regs[0], stub.regs[1] = m.imageHandle, m.mapKey+1
	if err := n.runtimeCall("ExitBootServices"); err != nil {
		t.Fatal(err)
	}
	if stub.regs[0] != invalidParameter || m.exited {
		t.Fatal("accepted stale map key")
	}
	stub.regs[0], stub.regs[1] = m.imageHandle, m.mapKey
	if err := n.runtimeCall("ExitBootServices"); err != nil {
		t.Fatal(err)
	}
	if stub.regs[0] != 0 || !m.exited {
		t.Fatal("valid native exit failed")
	}
	if err := n.runtimeCall("AllocatePool"); err == nil {
		t.Fatal("boot service accepted after exit")
	}
}

func TestNativeFirmwareTraceCapturesProtocolAndBoundedTail(t *testing.T) {
	m := machine(t, 0x14000000)
	n := &NativeExecution{cpu: &debugUnloadStub{}, base: m.ramBase, ram: make([]byte, m.opts.Memory), firmware: m, FirmwareLimit: 2}
	m.runtimeMemory = n
	// The GOP GUID in EFI byte order.
	raw := []byte{0xde, 0xa9, 0x42, 0x90, 0xdc, 0x23, 0x38, 0x4a, 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a}
	copy(n.ram[0x20000:], raw)
	args := [8]uint64{2, m.ramBase + 0x20000}
	n.observeFirmware("LocateHandle", args, bufferTooSmall)
	clear(n.ram[0x20000 : 0x20000+16])
	if n.FirmwareCalls[0].Protocol != graphicsOutputGUID || n.FirmwareCalls[0].Status != bufferTooSmall {
		t.Fatal("protocol/status were not captured at the call")
	}
	n.observeFirmware("GetTime", [8]uint64{}, 0)
	n.observeFirmware("ExitBootServices", [8]uint64{}, invalidParameter)
	if len(n.FirmwareCalls) != 2 || n.FirmwareCalls[0].Service != "GetTime" || n.FirmwareCalls[1].Status != invalidParameter {
		t.Fatal("firmware trace did not retain the bounded tail")
	}
	n.FirmwareLimit = 0
	n.observeFirmware("FreePages", [8]uint64{}, 0)
	if len(n.FirmwareCalls) != 2 {
		t.Fatal("disabled trace appended a call")
	}
}

func TestNativeGOPBltUsesARM64StackArguments(t *testing.T) {
	m := machine(t, 0x14000000)
	stub := &debugUnloadStub{}
	n := &NativeExecution{cpu: stub, base: m.ramBase, ram: make([]byte, m.opts.Memory), firmware: m, Counts: map[string]uint64{}}
	m.runtimeMemory = n
	// This stub has MMU disabled and SP=0; use RAM at zero for stack arguments.
	n.base = 0
	m.ramBase = 0
	m.allocations = []allocation{{Base: 0, Pages: 16, Type: 0}}
	m.processor.SetRegister("sctlr_el1", 0)
	if err := n.AttachGraphicsOutput(4, 3); err != nil {
		t.Fatal(err)
	}
	stub.regs[0], stub.regs[1], stub.regs[2] = n.graphics.graphics.protocol, 0x1000, 0
	stub.regs[5], stub.regs[6], stub.regs[7] = 1, 1, 2
	binary.LittleEndian.PutUint64(n.ram, 1) // Height is the ninth AAPCS64 argument.
	copy(n.ram[0x1000:], []byte{1, 2, 3, 0})
	if err := n.runtimeCall("GOP.Blt"); err != nil {
		t.Fatal(err)
	}
	frame, err := n.displaySnapshotInto(nil)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Width != 4 || frame.Height != 3 || !bytes.Equal(frame.Pixels[20:28], []byte{1, 2, 3, 0, 1, 2, 3, 0}) || frame.Pixels[16] != 0 || frame.Pixels[28] != 0 {
		t.Fatalf("bad GOP rectangle: %v", frame.Pixels)
	}
	frame.Pixels[20] = 99
	if n.graphics.graphics.pixels[20] != 1 {
		t.Fatal("snapshot aliases guest memory")
	}
}

func TestNativeDebugUnloadWithoutName(t *testing.T) {
	for _, base := range []uint64{0x1234, ^uint64(0)} {
		m := machine(t, 0x14000000)
		stub := &debugUnloadStub{}
		n := &NativeExecution{cpu: stub, base: m.ramBase, ram: make([]byte, m.opts.Memory), firmware: m,
			Modules: map[uint64]NativeModule{0x1234: {}, 0x5678: {}}}
		pc := m.ramBase + 0x20000
		for i, instruction := range []uint32{0xd43e0040, 0xd43e0000, 0xd65f03c0} {
			binary.LittleEndian.PutUint32(n.ram[0x20000+i*4:], instruction)
		}
		stub.regs[16], stub.regs[1] = 4, m.ramBase+0x21000
		binary.LittleEndian.PutUint64(n.ram[0x21000:], base)
		handled, err := n.debugSymbols(pc)
		if err != nil || !handled || stub.regs[31] != pc+8 {
			t.Fatalf("unload %#x: handled=%v pc=%#x err=%v", base, handled, stub.regs[31], err)
		}
		want := 1
		if base == ^uint64(0) {
			want = 0
		}
		if len(n.Modules) != want {
			t.Fatalf("unload %#x retained %v", base, n.Modules)
		}
	}
}
