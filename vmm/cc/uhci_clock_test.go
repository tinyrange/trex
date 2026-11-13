package cc

import (
	"encoding/binary"
	"testing"
	"time"

	"j5.nz/cc/hypervisor"
)

// A register access is a hardware observation even when the owner's timer has
// not run. In particular, a driver can check FRNUM across a short delay while
// the host coordinator's periodic tick is late. No real sleeps are needed.
func TestUHCIRegisterAccessSynchronizesFrameClock(t *testing.T) {
	u, ram, level := usbTestController()
	start := time.Unix(1, 0)
	u.base, u.command, u.status, u.interrupt, u.last = 0x1000, 1, 0, 4, start
	for i := 0; i < 1024; i++ {
		binary.LittleEndian.PutUint32(ram[0x1000+i*4:], 1)
	}
	// An inactive IOC in the last elapsed frame also verifies that synchronizing
	// FRNUM executes the due schedule, rather than merely fabricating a counter.
	binary.LittleEndian.PutUint32(ram[0x1010:], 0x3000)
	binary.LittleEndian.PutUint32(ram[0x3000:], 1)
	binary.LittleEndian.PutUint32(ram[0x3004:], 1<<24)
	readFrame := func(now time.Time) uint16 {
		t.Helper()
		data := make([]byte, 2)
		if err := u.io(hypervisor.X86Exit{Port: uint16(u.ioBase() + 6), Size: 2, Count: 1, Data: data}, now); err != nil {
			t.Fatal(err)
		}
		return binary.LittleEndian.Uint16(data)
	}
	if got := readFrame(start); got != 0 {
		t.Fatalf("initial FRNUM = %d", got)
	}
	now := start.Add(5 * time.Millisecond)
	if got := readFrame(now); got != 5 {
		t.Fatalf("FRNUM after 5ms without owner tick = %d, want 5", got)
	}
	if u.frames != 5 || !*level || u.status&1 == 0 {
		t.Fatalf("due schedule was not executed: frames=%d status=%#x IRQ=%v", u.frames, u.status, *level)
	}
	// A W1C after the elapsed IOC must acknowledge it, not create a late IRQ
	// when the periodic owner next polls the same timestamp.
	if err := u.io(hypervisor.X86Exit{Port: uint16(u.ioBase() + 2), Size: 2, Count: 1, Write: true, Data: []byte{1, 0}}, now); err != nil {
		t.Fatal(err)
	}
	if err := u.poll(now); err != nil {
		t.Fatal(err)
	}
	if *level || u.status&1 != 0 || u.frames != 5 {
		t.Fatalf("same instant replayed schedule: frames=%d status=%#x IRQ=%v", u.frames, u.status, *level)
	}
	// Do not let a delayed status acknowledgment get applied before the
	// schedule that was already due at its access time.
	binary.LittleEndian.PutUint32(ram[0x1024:], 0x3000)
	now = now.Add(5 * time.Millisecond)
	if err := u.io(hypervisor.X86Exit{Port: uint16(u.ioBase() + 2), Size: 2, Count: 1, Write: true, Data: []byte{1, 0}}, now); err != nil {
		t.Fatal(err)
	}
	if u.frames != 10 || *level || u.status&1 != 0 {
		t.Fatalf("late W1C reordered with due IOC: frames=%d status=%#x IRQ=%v", u.frames, u.status, *level)
	}
	// Halting freezes FRNUM; observation is not itself a clock source.
	if err := u.io(hypervisor.X86Exit{Port: uint16(u.ioBase()), Size: 2, Count: 1, Write: true, Data: []byte{0, 0}}, now); err != nil {
		t.Fatal(err)
	}
	if got := readFrame(now.Add(20 * time.Millisecond)); got != 10 {
		t.Fatalf("halted FRNUM advanced to %d", got)
	}
}
