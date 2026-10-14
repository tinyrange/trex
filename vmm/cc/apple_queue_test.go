package cc

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/block"
	"testing"
)

func TestAppleQueueReadAndUntrustedDescriptors(t *testing.T) {
	image := make([]byte, 1024)
	copy(image[512:], "APFS sector data")
	disk, e := block.NewFileDevice(darwinTestSource{bytes.NewReader(image)}, block.FileDeviceOptions{})
	if e != nil {
		t.Fatal(e)
	}
	makeDevice := func() *protocolTestBus {
		d := newProtocolTestBus(func(string, any) {})
		d.ramBase = 0x70000000
		d.ram = make([]byte, 4096)
		d.disk = disk
		for i, desc := range []struct {
			off, size uint32
			flags     uint16
		}{{256, 16, 1}, {512, 512, 3}, {1024, 1, 2}} {
			r := d.ram[i*16:]
			binary.LittleEndian.PutUint64(r, d.ramBase+uint64(desc.off))
			binary.LittleEndian.PutUint32(r[8:], desc.size)
			binary.LittleEndian.PutUint16(r[12:], 1)
			binary.LittleEndian.PutUint16(r[14:], desc.flags)
		}
		binary.LittleEndian.PutUint64(d.ram[264:], 1)
		d.ram[1024] = 0xff
		return d
	}
	d := makeDevice()
	if e := d.Write(0x30000408, 8, d.ramBase); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(d.ram[512:1024], image[512:]) || d.ram[1024] != 0 {
		t.Fatal("data or virtio status incorrect")
	}
	if v, e := d.Read(0x30000010, 4); e != nil || v != 1 {
		t.Fatalf("completion: %d %v", v, e)
	}
	for i := 0; i < 3; i++ {
		if binary.LittleEndian.Uint16(d.ram[i*16+12:]) != 0 {
			t.Fatal("descriptor ownership not returned")
		}
	}
	for _, mutate := range []func(*protocolTestBus){
		func(d *protocolTestBus) { binary.LittleEndian.PutUint64(d.ram, ^uint64(0)-8) },
		func(d *protocolTestBus) { binary.LittleEndian.PutUint32(d.ram[8:], 9<<20) },
		func(d *protocolTestBus) { binary.LittleEndian.PutUint64(d.ram[264:], 3) },
		func(d *protocolTestBus) { binary.LittleEndian.PutUint16(d.ram[14:], 8) },
		func(d *protocolTestBus) { binary.LittleEndian.PutUint32(d.ram[256:], 1) },
	} {
		d := makeDevice()
		mutate(d)
		if e := d.Write(0x30000408, 8, d.ramBase); e == nil {
			t.Fatal("accepted unsafe or unsupported chain")
		}
		if d.completion || d.ram[1024] != 0xff {
			t.Fatal("failed request reported successful completion")
		}
	}
}
