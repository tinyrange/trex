package cc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/vmm/ethernet"
	"testing"
)

func testE1000(t *testing.T) (*e1000, []byte, *ethernet.Port, *bool) {
	t.Helper()
	sw := ethernet.NewSwitch()
	peer := sw.Connect()
	port := sw.Connect()
	t.Cleanup(func() { peer.Close(); port.Close() })
	ram := make([]byte, 1<<20)
	irq := new(bool)
	memory := func(a, n uint64) ([]byte, error) {
		if a > uint64(len(ram)) || n > uint64(len(ram))-a {
			return nil, fmt.Errorf("DMA outside RAM")
		}
		return ram[a : a+n], nil
	}
	return newE1000(port, [6]byte{2, 0, 0, 0, 0, 1}, memory, func(v bool) error { *irq = v; return nil }), ram, peer, irq
}
func e1000Put(t *testing.T, d *e1000, off, v uint32) {
	t.Helper()
	if err := d.writeReg(off, v); err != nil {
		t.Fatal(err)
	}
}
func TestE1000DMAAndInterrupts(t *testing.T) {
	d, ram, peer, irq := testE1000(t)
	frame := make([]byte, 60)
	copy(frame, []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 8, 6})
	copy(frame[14:], "bounded Ethernet DMA test")
	e1000Put(t, d, 0x2800, 0x1000)
	e1000Put(t, d, 0x2808, 128)
	e1000Put(t, d, 0x2818, 7)
	binary.LittleEndian.PutUint64(ram[0x1000:], 0x2000)
	e1000Put(t, d, 0x100, 2|1<<26)
	e1000Put(t, d, 0xd0, 0x81)
	if err := peer.Send(frame); err != nil {
		t.Fatal(err)
	}
	if err := d.poll(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ram[0x2000:0x203c], frame) || ram[0x100c] != 7 || binary.LittleEndian.Uint16(ram[0x1008:]) != 60 || !*irq {
		t.Fatal("RX completion missing")
	}
	if v, err := d.readReg(0xc0); err != nil || v != 0x80 || *irq {
		t.Fatal("ICR acknowledgement", v, err)
	}
	copy(ram[0x3000:], frame)
	binary.LittleEndian.PutUint64(ram[0x4000:], 0x3000)
	binary.LittleEndian.PutUint16(ram[0x4008:], 60)
	ram[0x400b] = 0xb
	e1000Put(t, d, 0x3800, 0x4000)
	e1000Put(t, d, 0x3808, 128)
	e1000Put(t, d, 0x400, 2)
	e1000Put(t, d, 0x3818, 1)
	if got := peer.Receive(); !bytes.Equal(got, frame) {
		t.Fatalf("TX mismatch %x", got)
	}
	if ram[0x400c]&1 == 0 || !*irq {
		t.Fatal("TX completion missing")
	}
	e1000Put(t, d, 0xd8, 0xffffffff)
	if *irq {
		t.Fatal("mask did not lower IRQ")
	}
	e1000Put(t, d, 0xd0, 1)
	if !*irq {
		t.Fatal("unmask lost pending interrupt")
	}
	e1000Put(t, d, 0, 1<<26)
	if *irq || len(d.txPacket) != 0 || d.regs[0x2808/4] != 0 {
		t.Fatal("reset did not clear device")
	}
}
func TestE1000EEPROMAndPHY(t *testing.T) {
	d, _, _, _ := testE1000(t)
	var sum uint16
	for a := 0; a < 64; a++ {
		e1000Put(t, d, 0x14, uint32(a)<<8|1)
		v, _ := d.readReg(0x14)
		sum += uint16(v >> 16)
		if v&16 == 0 {
			t.Fatal("EEPROM read not complete")
		}
		e1000Put(t, d, 0x10, 0)
		e1000Put(t, d, 0x10, 2)
		command := uint32(6<<6 | a)
		for bit := 8; bit >= 0; bit-- {
			v := uint32(2) | ((command>>bit)&1)<<2
			e1000Put(t, d, 0x10, v)
			e1000Put(t, d, 0x10, v|1)
		}
		var serial uint16
		for bit := 0; bit < 16; bit++ {
			e1000Put(t, d, 0x10, 2)
			e1000Put(t, d, 0x10, 3)
			v, _ := d.readReg(0x10)
			serial = serial<<1 | uint16(v>>3&1)
		}
		if serial != d.eeprom[a] {
			t.Fatalf("serial EEPROM word %d: %04x != %04x", a, serial, d.eeprom[a])
		}
	}
	if sum != 0xbaba {
		t.Fatalf("bad EEPROM checksum %x", sum)
	}
	e1000Put(t, d, 0x20, 1<<27|1<<21|2<<16)
	if v, _ := d.readReg(0x20); v&0x5000ffff != 0x10000141 {
		t.Fatalf("PHY read %x", v)
	}
}
func TestE1000RejectsInvalidDMA(t *testing.T) {
	d, ram, _, _ := testE1000(t)
	e1000Put(t, d, 0x3800, 0x1000)
	e1000Put(t, d, 0x3808, 128)
	e1000Put(t, d, 0x400, 2)
	binary.LittleEndian.PutUint64(ram[0x1000:], ^uint64(0)-2)
	binary.LittleEndian.PutUint16(ram[0x1008:], 60)
	ram[0x100b] = 0xb
	if err := d.writeReg(0x3818, 1); err == nil {
		t.Fatal("out-of-range DMA accepted")
	}
	if ram[0x100c] != 0 {
		t.Fatal("failed DMA completed descriptor")
	}
	if err := d.writeReg(0x3818, 8); err == nil {
		t.Fatal("out-of-range tail accepted")
	}
	d.config[4] &= ^byte(4)
	if err := d.writeReg(0x3818, 1); err != nil {
		t.Fatal("bus mastering disabled still performed DMA")
	}
}
func TestE1000TCPSegmentation(t *testing.T) {
	d, _, peer, _ := testE1000(t)
	p := make([]byte, 54+2500)
	copy(p, []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0})
	p[14] = 0x45
	p[22] = 64
	p[23] = 6
	copy(p[26:34], []byte{10, 0, 0, 1, 10, 0, 0, 2})
	binary.BigEndian.PutUint16(p[18:], 42)
	binary.BigEndian.PutUint32(p[38:], 100)
	p[46] = 0x50
	p[47] = 0x19
	for i := 54; i < len(p); i++ {
		p[i] = byte(i)
	}
	d.txContext[0] = 14
	d.txContext[4] = 34
	d.txContext[13] = 54
	binary.LittleEndian.PutUint16(d.txContext[14:], 1000)
	if err := d.segmentTCP(p); err != nil {
		t.Fatal(err)
	}
	var payload []byte
	for i, n := range []int{1000, 1000, 500} {
		f := peer.Receive()
		if len(f) != 54+n {
			t.Fatalf("segment %d size %d", i, len(f))
		}
		if ethernetChecksum(f[14:34], 0) != 0 {
			t.Fatal("invalid IPv4 checksum")
		}
		pseudo := uint32(^ethernetChecksum(f[26:34], 0)) + 6 + uint32(len(f)-34)
		if ethernetChecksum(f[34:], pseudo) != 0 {
			t.Fatal("invalid TCP checksum")
		}
		if binary.BigEndian.Uint32(f[38:]) != uint32(100+i*1000) || binary.BigEndian.Uint16(f[18:]) != uint16(42+i) {
			t.Fatal("segmentation sequence")
		}
		if (f[47]&9 == 9) != (i == 2) {
			t.Fatal("FIN/PSH misplaced")
		}
		payload = append(payload, f[54:]...)
	}
	if !bytes.Equal(payload, p[54:]) || peer.Receive() != nil {
		t.Fatal("TSO payload mismatch")
	}
}
