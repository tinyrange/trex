package cc

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestAppleUtilityStorageReadWriteAndBounds(t *testing.T) {
	d := newProtocolTestBus(func(string, any) {})
	d.ramBase, d.ram = 0x70000000, make([]byte, 4096)
	if err := d.util.init(); err != nil {
		t.Fatal(err)
	}
	defer d.util.store.Close()
	if v, err := d.Read(0x30010000, 4); err != nil || v != 1 {
		t.Fatal(v, err)
	}
	request := func(kind uint32, sector uint64) error {
		flags := uint16(3)
		if kind == 1 {
			flags = 1
		}
		for i, desc := range []struct {
			off, size uint32
			flags     uint16
		}{{256, 16, 1}, {512, 512, flags}, {1024, 1, 2}} {
			r := d.ram[i*16:]
			binary.LittleEndian.PutUint64(r, d.ramBase+uint64(desc.off))
			binary.LittleEndian.PutUint32(r[8:], desc.size)
			binary.LittleEndian.PutUint16(r[12:], 1)
			binary.LittleEndian.PutUint16(r[14:], desc.flags)
		}
		binary.LittleEndian.PutUint32(d.ram[256:], kind)
		binary.LittleEndian.PutUint64(d.ram[264:], sector)
		d.ram[1024] = 0xff
		return d.Write(0x30010408, 8, d.ramBase)
	}
	data := bytes.Repeat([]byte{0xa7}, 512)
	copy(d.ram[512:], data)
	if err := request(1, (32<<20)/512-1); err != nil {
		t.Fatal(err)
	}
	clear(d.ram[512:1024])
	if err := request(0, (32<<20)/512-1); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.ram[512:1024], data) || d.ram[1024] != 0 {
		t.Fatal("utility data/status mismatch")
	}
	if v, err := d.Read(0x30010010, 4); err != nil || v != 1 {
		t.Fatal(v, err)
	}
	if err := request(0, 0); err != nil || !bytes.Equal(d.ram[512:1024], make([]byte, 512)) {
		t.Fatal("unwritten utility region", err)
	}
	if err := request(1, (32<<20)/512); err == nil || d.util.complete || d.ram[1024] != 0xff {
		t.Fatal("out-of-bounds operation completed", err)
	}
	d.ctrr.banks[0] = ctrrBank{lower: d.ramBase + 512, upper: d.ramBase + 1023, control: 7}
	if err := request(0, 0); err == nil || d.util.complete {
		t.Fatal("CTRR DMA accepted", err)
	}
}
