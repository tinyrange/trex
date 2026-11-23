package r3000

import (
	"context"
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func testMachine(t *testing.T, instructions ...uint32) *Machine {
	t.Helper()
	var data []byte
	for _, word := range instructions {
		data = binary.LittleEndian.AppendUint32(data, word)
	}
	m, err := NewMachine(Config{Memory: 1 << 20, ROM: &starfile.Bytes{Data: data}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestR3000LoadAndBranchDelaySlots(t *testing.T) {
	m := testMachine(t,
		0x3c08a000, // lui t0, 0xa000
		0x2409002a, // addiu t1, zero, 42
		0xad090100, // sw t1, 256(t0)
		0x8d0a0100, // lw t2, 256(t0)
		0x01405821, // addu t3, t2, zero (load delay)
		0x01406021, // addu t4, t2, zero
		0x158b0002, // bne t4, t3, +2
		0x240d0001, // addiu t5, zero, 1 (branch delay)
		0x240d0002, // addiu t5, zero, 2 (skipped)
		0x0000000d, // break
	)
	stop, err := m.Run(context.Background(), 10, true)
	if err != nil || stop.Kind != "exception" || stop.Exception != 9 || stop.PC != resetPC+36 {
		t.Fatalf("unexpected stop %+v, %v", stop, err)
	}
	if c := &m.cpu; c.gpr[10] != 42 || c.gpr[11] != 0 || c.gpr[12] != 42 || c.gpr[13] != 1 || c.gpr[0] != 0 {
		t.Fatalf("delay slots yielded wrong registers: %x", c.gpr)
	}
}

func TestR3000ExceptionInBranchDelaySlot(t *testing.T) {
	m := testMachine(t, 0x10000002, 0x0000000d)
	stop, err := m.Run(context.Background(), 2, true)
	if err != nil || stop.Exception != 9 || m.cpu.cp0[epc] != resetPC || m.cpu.cp0[cause]&(1<<31) == 0 || m.cpu.pc != 0xbfc00180 {
		t.Fatalf("unexpected delay exception %+v, %v, CP0 %x", stop, err, m.cpu.cp0)
	}
}

func TestEffectiveReadDoesNotMutateCP0(t *testing.T) {
	m := testMachine(t, 0)
	m.cpu.cp0[10] = 0x80
	m.cpu.tlb[5] = tlbEntry{0x00004080, 0x00001600}
	m.ram[0x1000] = 0x42
	out := make([]byte, 1)
	if err := m.ReadEffective(0x4000, out); err != nil || out[0] != 0x42 {
		t.Fatalf("effective read %x, %v", out, err)
	}
	old := m.cpu.cp0
	if err := m.ReadEffective(0x5000, out); err == nil || m.cpu.cp0 != old {
		t.Fatal("debugger read altered CP0")
	}
}

func TestScreenCaptureUsesPixelMaskAndPalette(t *testing.T) {
	m := testMachine(t, 0)
	m.writeBus(0x40000000, 2, 0x0201)
	m.writeBus(0x60000a00, 1, 0xf)
	m.writeBus(0x60000008, 4, 0x00ccbbaa)
	frame := m.Screen()
	r, g, b, a := frame.At(0, 0).RGBA()
	if r != 0xaaaa || g != 0xbbbb || b != 0xcccc || a != 0xffff {
		t.Fatalf("palette color %x %x %x %x", r, g, b, a)
	}
	r, g, b, _ = frame.At(1, 0).RGBA()
	if r != 0x0202 || g != r || b != r {
		t.Fatalf("unwritten palette %x %x %x", r, g, b)
	}
	m.writeBus(0x60000a00, 1, 0)
	r, g, b, _ = m.Screen().At(0, 0).RGBA()
	if r|g|b != 0 {
		t.Fatalf("pixel mask %x %x %x", r, g, b)
	}
}

func TestNonzeroWriteWatchMatchesOnlyWatchedBytes(t *testing.T) {
	m := testMachine(t,
		0x3c08a000, // lui t0, 0xa000
		0x24090042, // addiu t1, zero, 0x42
		0xad090100, // sw t1, 256(t0), nonzero outside watched byte
		0xa1090101, // sb t1, 257(t0)
		0x00000000,
	)
	if err := m.WatchWrite(257, 1, true); err != nil {
		t.Fatal(err)
	}
	stop, err := m.Run(context.Background(), 4, false)
	if err != nil || stop.Kind != "write_watch" || stop.Physical != 257 || stop.Value != 0x42 ||
		stop.PC != resetPC+12 || stop.Instruction != 0xa1090101 || m.ram[257] != 0x42 {
		t.Fatalf("write watch %+v, RAM 0x%x, %v", stop, m.ram[257], err)
	}
	stop, err = m.Run(context.Background(), 1, false)
	if err != nil || stop.Kind != "budget" {
		t.Fatalf("one-shot watch persisted: %+v, %v", stop, err)
	}
}
