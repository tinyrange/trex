package cc

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
)

func TestVirtioPCIBlockWritableOverlayAndFlush(t *testing.T) {
	baseBytes := make([]byte, 1024)
	base, err := block.NewFileDevice(darwinTestSource{bytes.NewReader(baseBytes)}, block.FileDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := blockstar.NewOverlayDevice(base, 4096, 512)
	if err != nil {
		t.Fatal(err)
	}
	v := newVirtioPCIBlock(0x40008000, 0x50000000, overlay, nil, nil)
	if v.offered(0)&(1<<5) != 0 || v.offered(0)&(1<<9) == 0 {
		t.Fatal("writable and flush features")
	}
	header, payload, status := make([]byte, 16), bytes.Repeat([]byte{0x5a}, 512), []byte{255}
	binary.LittleEndian.PutUint32(header, 1)
	binary.LittleEndian.PutUint64(header[8:], 1)
	if n, err := v.request([]virtioBuffer{{data: header}, {data: payload}, {data: status, write: true}}); err != nil || n != 1 || status[0] != 0 {
		t.Fatalf("write completion=%d status=%d err=%v", n, status[0], err)
	}
	got := make([]byte, 512)
	overlay.ReadAt(got, 512)
	if !bytes.Equal(got, payload) || !bytes.Equal(baseBytes, make([]byte, 1024)) {
		t.Fatal("overlay write changed the base or lost data")
	}
	binary.LittleEndian.PutUint32(header, 4)
	if n, err := v.request([]virtioBuffer{{data: header}, {data: status, write: true}}); err != nil || n != 1 || status[0] != 0 {
		t.Fatalf("flush completion=%d status=%d err=%v", n, status[0], err)
	}
	readonly := newVirtioPCIBlock(0x40008000, 0x50000000, base, nil, nil)
	if readonly.offered(0)&(1<<5) == 0 {
		t.Fatal("read-only feature missing")
	}
	binary.LittleEndian.PutUint32(header, 1)
	if _, err := readonly.request([]virtioBuffer{{data: header}, {data: payload}, {data: status, write: true}}); err != nil || status[0] != 1 {
		t.Fatal("read-only device accepted write", err)
	}
}

func TestVirtioPCIBlockQueueAndMSIX(t *testing.T) {
	image := make([]byte, 1024)
	for i := 512; i < len(image); i++ {
		image[i] = byte(i)
	}
	disk, err := block.NewFileDevice(darwinTestSource{bytes.NewReader(image)}, block.FileDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ram := make([]byte, 4096)
	board := newProtocolTestBus(func(string, any) {})
	board.ramBase, board.ram = 0x70000000, ram
	interrupts := 0
	v := newVirtioPCIBlock(0x81000000, 0x90000000, disk, func(a, n uint64, w bool) ([]byte, error) {
		if w && !board.ctrr.writable(a, n) {
			return nil, block.ErrOutOfRange
		}
		return board.memory(a, n)
	}, func(a uint64, d uint32) error {
		if a != 0x03000040 || d != 65 {
			t.Fatalf("MSI %#x:%d", a, d)
		}
		interrupts++
		return nil
	})
	device := nativeARM64PCI(v.virtioPCI)
	write := func(a uint64, n int, x uint64) {
		t.Helper()
		if err := device.Write(a, n, x); err != nil {
			t.Fatal(err)
		}
	}
	write(0x81000010, 4, 0xffffffff)
	if x, e := v.read(0x81000010, 4); e != nil || x != 0xffff0000 {
		t.Fatal(x, e)
	}
	write(0x81000010, 4, 0x90000000)
	write(0x81000004, 2, 6)
	write(0x90000014, 1, 3)
	write(0x90000008, 4, 1)
	write(0x9000000c, 4, 1)
	write(0x90000014, 1, 11)
	write(0x90000018, 2, 8)
	write(0x9000001a, 2, 1)
	write(0x90000020, 8, 0x70000000)
	write(0x90000028, 8, 0x70000100)
	write(0x90000030, 8, 0x70000200)
	write(0x9000001c, 2, 1)
	write(0x90000014, 1, 15)
	write(0x90003010, 8, 0x03000040)
	write(0x90003018, 4, 65)
	write(0x9000301c, 4, 1)
	write(0x81000086, 2, 0x8001)
	for i, desc := range []struct {
		a           uint64
		n           uint32
		flags, next uint16
	}{{0x70000300, 16, 1, 1}, {0x70000400, 256, 3, 2}, {0x70000500, 256, 3, 3}, {0x70000600, 1, 2, 0}} {
		r := ram[i*16:]
		binary.LittleEndian.PutUint64(r, desc.a)
		binary.LittleEndian.PutUint32(r[8:], desc.n)
		binary.LittleEndian.PutUint16(r[12:], desc.flags)
		binary.LittleEndian.PutUint16(r[14:], desc.next)
	}
	binary.LittleEndian.PutUint64(ram[0x308:], 1)
	ram[0x600] = 0xff
	binary.LittleEndian.PutUint16(ram[0x102:], 1)
	// Publishing avail is not a notification. Generic platform polling must
	// not complete synchronous storage before the guest kicks its queue.
	if err := device.Poll(); err != nil {
		t.Fatal(err)
	}
	if ram[0x600] != 0xff || binary.LittleEndian.Uint16(ram[0x202:]) != 0 || interrupts != 0 {
		t.Fatal("unnotified block request completed during platform poll")
	}
	write(0x90001000, 2, 0)
	if !bytes.Equal(ram[0x400:0x600], image[512:]) || ram[0x600] != 0 || binary.LittleEndian.Uint16(ram[0x202:]) != 1 || binary.LittleEndian.Uint32(ram[0x208:]) != 513 {
		t.Fatal("split ring completion or data")
	}
	if interrupts != 0 || v.pending != 2 {
		t.Fatal("masked MSI-X not pending")
	}
	write(0x9000301c, 4, 0)
	if interrupts != 1 || v.pending != 0 {
		t.Fatal("MSI-X unmask did not deliver")
	}
	// A device error completes with IOERR, without copying any data.
	binary.LittleEndian.PutUint64(ram[0x308:], 2)
	ram[0x600] = 0xff
	clear(ram[0x400:0x600])
	binary.LittleEndian.PutUint16(ram[0x102:], 2)
	write(0x90001000, 2, 0)
	if ram[0x600] != 1 || !bytes.Equal(ram[0x400:0x600], make([]byte, 512)) || interrupts != 2 {
		t.Fatal("out of bounds completion")
	}
	// An unsafe DMA range fails before status/used publication.
	board.ctrr.banks[0] = ctrrBank{lower: 0x70000400, upper: 0x700005ff, control: 7}
	binary.LittleEndian.PutUint64(ram[0x308:], 1)
	binary.LittleEndian.PutUint16(ram[0x102:], 3)
	ram[0x600] = 0xff
	if e := v.write(0x90001000, 2, 0); e == nil || ram[0x600] != 0xff || binary.LittleEndian.Uint16(ram[0x202:]) != 2 {
		t.Fatal("protected DMA completed", e)
	}
	board.ctrr.banks[0] = ctrrBank{}
	for _, mutate := range []func(){
		func() { binary.LittleEndian.PutUint16(ram[14:], 0) }, // cycle
		func() { binary.LittleEndian.PutUint16(ram[12:], 5) }, // unnegotiated indirect
		func() { binary.LittleEndian.PutUint64(ram[16:], 0xfffffffffffffff0) },
	} {
		binary.LittleEndian.PutUint16(ram[12:], 1)
		binary.LittleEndian.PutUint16(ram[14:], 1)
		binary.LittleEndian.PutUint64(ram[16:], 0x70000400)
		mutate()
		if e := v.write(0x90001000, 2, 0); e == nil || ram[0x600] != 0xff || binary.LittleEndian.Uint16(ram[0x202:]) != 2 {
			t.Fatal("malformed chain completed", e)
		}
	}
}
