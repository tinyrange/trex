package cc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"j5.nz/cc/hypervisor"
	"testing"
	"time"
)

func usbTestController() (*uhci, []byte, *bool) {
	ram := make([]byte, 0x10000)
	level := false
	memory := func(a, n uint64) ([]byte, error) {
		if a > uint64(len(ram)) || n > uint64(len(ram))-a {
			return nil, fmt.Errorf("DMA outside guest RAM")
		}
		return ram[a : a+n], nil
	}
	return newUHCI(memory, func(irq uint32, v bool) error {
		if irq != 17 {
			panic("wrong route")
		}
		level = v
		return nil
	}), ram, &level
}
func usbTestTD(ram []byte, at, next uint32, pid, address, endpoint byte, length int) {
	binary.LittleEndian.PutUint32(ram[at:], next)
	binary.LittleEndian.PutUint32(ram[at+4:], 1<<23|1<<24|3<<27|1<<26)
	binary.LittleEndian.PutUint32(ram[at+8:], uint32(pid)|uint32(address)<<8|uint32(endpoint)<<15|uint32((length-1)&2047)<<21)
	binary.LittleEndian.PutUint32(ram[at+12:], 0x8000)
}

func TestUHCIEnumerationAndHIDTransitions(t *testing.T) {
	u, ram, _ := usbTestController()
	u.ports[0] |= 4
	packet := func(pid, address, ep byte, payload []byte, length int) []byte {
		t.Helper()
		copy(ram[0x8000:], payload)
		usbTestTD(ram, 0x2000, 1, pid, address, ep, length)
		binary.LittleEndian.PutUint32(ram[0x1000:], 1)
		binary.LittleEndian.PutUint32(ram[0x1004:], 0x2000)
		if err := u.schedule(0x1002); err != nil {
			t.Fatal(err)
		}
		status := binary.LittleEndian.Uint32(ram[0x2004:])
		if status&(1<<23|0x7f0000) != 0 {
			t.Fatalf("packet did not ACK: %#x", status)
		}
		n := int(status+1) & 2047
		return append([]byte(nil), ram[0x8000:0x8000+n]...)
	}
	// Firmware learns endpoint-zero max packet size, then assigns address.
	packet(0x2d, 0, 0, []byte{0x80, 6, 0, 1, 0, 0, 8, 0}, 8)
	first := packet(0x69, 0, 0, nil, 8)
	if !bytes.Equal(first, []byte{18, 1, 0x10, 1, 0, 0, 0, 8}) {
		t.Fatal("wrong device prefix", first)
	}
	packet(0xe1, 0, 0, nil, 0)
	packet(0x2d, 0, 0, []byte{0, 5, 7, 0, 0, 0, 0, 0}, 8)
	if u.devices[0].address != 0 {
		t.Fatal("address applied before status")
	}
	packet(0x69, 0, 0, nil, 0)
	if u.devices[0].address != 7 {
		t.Fatal("address missing after status")
	}
	packet(0x2d, 7, 0, []byte{0x80, 6, 0, 1, 0, 0, 18, 0}, 8)
	full := packet(0x69, 7, 0, nil, 8)
	full = append(full, packet(0x69, 7, 0, nil, 8)...)
	full = append(full, packet(0x69, 7, 0, nil, 8)...)
	if len(full) != 18 || binary.LittleEndian.Uint16(full[8:]) != 0x1234 {
		t.Fatal("multi-packet descriptor corrupted", full)
	}
	packet(0xe1, 7, 0, nil, 0)
	packet(0x2d, 7, 0, []byte{0, 9, 1, 0, 0, 0, 0, 0}, 8)
	packet(0x69, 7, 0, nil, 0)
	packet(0x69, 7, 1, nil, 8) // Initial idle report.
	if err := u.devices[0].key("shift", true); err != nil {
		t.Fatal(err)
	}
	if err := u.devices[0].key("a", true); err != nil {
		t.Fatal(err)
	}
	if err := u.devices[0].key("a", false); err != nil {
		t.Fatal(err)
	}
	a, b, c := packet(0x69, 7, 1, nil, 8), packet(0x69, 7, 1, nil, 8), packet(0x69, 7, 1, nil, 8)
	if a[0] != 2 || a[2] != 0 || b[0] != 2 || b[2] != 4 || c[0] != 2 || c[2] != 0 {
		t.Fatal("keyboard transition lost", a, b, c)
	}
	usbTestTD(ram, 0x2000, 1, 0x69, 7, 1, 8)
	if _, _, err := u.transfer(ram[0x2000:0x2010]); err != nil {
		t.Fatal(err)
	}
	if s := binary.LittleEndian.Uint32(ram[0x2004:]); s&(1<<23|1<<19) != (1<<23 | 1<<19) {
		t.Fatal("idle interrupt endpoint must NAK and remain active")
	}
}

func TestUHCIScheduleIRQAndReset(t *testing.T) {
	u, ram, level := usbTestController()
	now := time.Unix(1, 0)
	u.command = 1
	u.status = 0
	u.interrupt = 4
	u.last = now
	u.base = 0x4000
	u.ports[1] |= 4
	u.devices[1].address = 9
	u.devices[1].configuration = 1
	if err := u.devices[1].point(1234, 2345, 1, -2); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 1024; n++ {
		binary.LittleEndian.PutUint32(ram[0x4000+n*4:], 0x1002)
	}
	binary.LittleEndian.PutUint32(ram[0x1000:], 0x1002) // Legal reclamation loop.
	binary.LittleEndian.PutUint32(ram[0x1004:], 0x2000)
	usbTestTD(ram, 0x2000, 1, 0x69, 9, 1, 6)
	if err := u.poll(now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if !*level || u.frame != 1 || u.devices[1].reports != 1 || binary.LittleEndian.Uint16(ram[0x8001:]) != 1234 || ram[0x8005] != 254 {
		t.Fatal("frame DMA or interrupt/report failed")
	}
	ack := []byte{1, 0}
	if err := u.io(hypervisor.X86Exit{Port: 0xc102, Size: 2, Count: 1, Write: true, Data: ack}, now); err != nil {
		t.Fatal(err)
	}
	if *level || u.status&1 != 0 {
		t.Fatal("W1C completion did not deassert INTx")
	}
	reset := []byte{2, 0}
	if err := u.io(hypervisor.X86Exit{Port: 0xc100, Size: 2, Count: 1, Write: true, Data: reset}, now); err != nil {
		t.Fatal(err)
	}
	if u.command != 0 || u.status != 0x20 || u.base != 0 || u.frame != 0 {
		t.Fatal("HC reset not self-clearing/halted")
	}
}
func TestUHCIMalformedDMAAndCycles(t *testing.T) {
	u, ram, _ := usbTestController()
	if err := u.schedule(0xfffffff2); err == nil {
		t.Fatal("invalid QH DMA accepted")
	}
	binary.LittleEndian.PutUint32(ram[0x2000:], 0x2004)
	if err := u.schedule(0x2000); err == nil {
		t.Fatal("TD cycle did not reach bounded failure")
	}
	u.command = 1
	u.last = time.Unix(1, 0)
	u.base = 0xfffff000
	if err := u.poll(u.last.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if u.fault == "" || u.command&1 != 0 || u.status&0x28 != 0x28 {
		t.Fatal("invalid frame DMA did not halt controller")
	}
}
func TestUSBHIDStallRecoveryAndBounds(t *testing.T) {
	d := newUSBHID(false)
	if d.setup([]byte{0x80, 6, 0, 0xff, 0, 0, 8, 0}) {
		t.Fatal("unknown descriptor did not stall")
	}
	if !d.setup([]byte{0x80, 6, 0, 1, 0, 0, 8, 0}) || len(d.reply) != 8 {
		t.Fatal("new SETUP did not clear stall/limit length")
	}
	if d.setup([]byte{0, 5, 128, 0, 0, 0, 0, 0}) {
		t.Fatal("out-of-range address accepted")
	}
	d.configuration = 1
	for n := 0; n < 1024; n++ {
		if err := d.key("a", n%2 == 0); err != nil {
			t.Fatal(err)
		}
	}
	before := append([]byte(nil), d.report...)
	if err := d.key("b", true); err == nil || !bytes.Equal(before, d.report) {
		t.Fatal("queue overflow changed live key state")
	}
}
