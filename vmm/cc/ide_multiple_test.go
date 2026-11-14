package cc

import (
	"bytes"
	"encoding/binary"
	"testing"

	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
)

func TestATAMultipleNegotiationAndIO(t *testing.T) {
	base := append(bytes.Repeat([]byte{0x31}, 512), bytes.Repeat([]byte{0x72}, 512)...)
	overlay, err := blockstar.NewOverlayDevice(testBlock(t, base), 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	level := false
	d := newIDE(vmm.Disk{Device: overlay}, vmm.CHSGeometry{Cylinders: 1, Heads: 1, Sectors: 2}, func(_ uint32, v bool) error { level = v; return nil })
	command := func(cmd byte) {
		t.Helper()
		if err := d.command(cmd); err != nil {
			t.Fatal(err)
		}
	}
	identify := func(want uint16) {
		t.Helper()
		command(0xec)
		if binary.LittleEndian.Uint16(d.buffer[94:]) != 0x8001 || binary.LittleEndian.Uint16(d.buffer[118:]) != want {
			t.Fatal("multiple mode not accurately advertised")
		}
	}
	identify(0x100)
	d.task[2] = 1
	command(0xc4)
	if d.status() != 0x51 {
		t.Fatal("READ MULTIPLE accepted before negotiation")
	}
	d.task[2] = 1
	command(0xc6)
	if d.status() != 0x50 || !level {
		t.Fatal("SET MULTIPLE did not complete")
	}
	identify(0x101)
	d.task[2] = 2
	command(0xc6)
	if d.status() != 0x51 {
		t.Fatal("unadvertised block size accepted")
	}
	identify(0x101)
	// Two one-sector blocks: IRQ for each DRQ, no extra read completion IRQ.
	d.task[2] = 2
	d.task[3] = 1
	command(0xc4)
	got := []byte{}
	for i := 0; i < 2; i++ {
		if !level || d.status() != 0x58 {
			t.Fatal("missing block-ready IRQ")
		}
		if err := d.io(ioByte(0x1f7, false, 0)); err != nil {
			t.Fatal(err)
		}
		ex := hypervisor.X86Exit{Port: 0x1f0, Size: 2, Count: 256, Data: make([]byte, 512)}
		if err := d.io(ex); err != nil {
			t.Fatal(err)
		}
		got = append(got, ex.Data...)
	}
	if !bytes.Equal(got, base) || d.status() != 0x50 || level {
		t.Fatal("READ MULTIPLE data/completion")
	}
	d.task[2] = 2
	d.task[3] = 1
	d.task[4] = 0
	d.task[6] = 0xa0
	command(0xc5)
	for i := 0; i < 2; i++ {
		if d.status() != 0x58 || level != (i != 0) {
			t.Fatal("WRITE MULTIPLE DRQ/IRQ")
		}
		if err := d.io(ioByte(0x1f7, false, 0)); err != nil {
			t.Fatal(err)
		}
		ex := hypervisor.X86Exit{Port: 0x1f0, Size: 2, Count: 256, Write: true, Data: bytes.Repeat([]byte{byte(i + 9)}, 512)}
		if err := d.io(ex); err != nil {
			t.Fatal(err)
		}
	}
	written := make([]byte, 1024)
	if _, err := overlay.ReadAt(written, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, append(bytes.Repeat([]byte{9}, 512), bytes.Repeat([]byte{10}, 512)...)) || d.status() != 0x50 || !level {
		t.Fatal("WRITE MULTIPLE data/completion")
	}
	d.task[2] = 0
	command(0xc6)
	identify(0x100)
	d.task[2] = 1
	command(0xc6)
	d.reset()
	identify(0x100)
}
