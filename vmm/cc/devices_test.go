package cc

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
)

func testBlock(t testing.TB, data []byte) block.Device {
	t.Helper()
	d, err := block.NewFileDevice(&starfile.Bytes{Data: data}, block.FileDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestATCMOSCenturySelection(t *testing.T) {
	p := &pc{ram: make([]byte, 64<<20), geometry: vmm.CHSGeometry{Cylinders: 520, Heads: 16, Sectors: 63}}
	p.initializeCMOS()
	var sum uint16
	for _, v := range p.cmos[0x10:0x2e] {
		sum += uint16(v)
	}
	if sum == 0 || binary.BigEndian.Uint16(p.cmos[0x2e:]) != sum {
		t.Fatal("invalid AT CMOS checksum selects the wrong century register")
	}
	if binary.LittleEndian.Uint16(p.cmos[0x1b:]) != 520 || p.cmos[0x1d] != 16 || p.cmos[0x23] != 63 {
		t.Fatal("CMOS drive geometry differs from BIOS/ATA")
	}
}
func ioByte(port uint16, write bool, value byte) hypervisor.X86Exit {
	return hypervisor.X86Exit{Reason: hypervisor.X86ExitIO, Port: port, Size: 1, Count: 1, Write: write, Data: []byte{value}}
}

func TestIDEMultiSectorAndOverlay(t *testing.T) {
	base := make([]byte, 4*512)
	for i := range base {
		base[i] = byte(i/512 + 1)
	}
	overlay, err := blockstar.NewOverlayDevice(testBlock(t, base), 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	level := false
	d := newIDE(vmm.Disk{Device: overlay}, vmm.CHSGeometry{Cylinders: 1, Heads: 1, Sectors: 4}, func(irq uint32, v bool) error {
		if irq != 14 {
			t.Fatalf("IRQ %d", irq)
		}
		level = v
		return nil
	})
	out := func(port uint16, value byte) {
		t.Helper()
		if err := d.io(ioByte(port, true, value)); err != nil {
			t.Fatal(err)
		}
	}
	in := func(port uint16) byte {
		t.Helper()
		ex := ioByte(port, false, 0)
		if err := d.io(ex); err != nil {
			t.Fatal(err)
		}
		return ex.Data[0]
	}
	out(0x1f2, 2)
	out(0x1f3, 2)
	out(0x1f7, 0x20)
	if !level || in(0x3f6) != 0x58 || !level {
		t.Fatal("alternate status acknowledged IRQ")
	}
	if in(0x1f7) != 0x58 || level {
		t.Fatal("status did not acknowledge IRQ")
	}
	for sector := 2; sector <= 3; sector++ {
		ex := hypervisor.X86Exit{Port: 0x1f0, Size: 2, Count: 256, Data: make([]byte, 512)}
		if err := d.io(ex); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ex.Data, bytes.Repeat([]byte{byte(sector)}, 512)) {
			t.Fatalf("sector %d mismatch", sector)
		}
		if sector == 2 {
			if !level {
				t.Fatal("next sector did not interrupt")
			}
			in(0x1f7)
		}
	}
	if d.task[2] != 0 || d.status() != 0x50 {
		t.Fatalf("read completion task=%x", d.task)
	}
	out(0x1f2, 2)
	out(0x1f3, 1)
	out(0x1f7, 0x30)
	for sector := 0; sector < 2; sector++ {
		ex := hypervisor.X86Exit{Port: 0x1f0, Size: 2, Count: 256, Write: true, Data: bytes.Repeat([]byte{byte(0xa0 + sector)}, 512)}
		if err := d.io(ex); err != nil {
			t.Fatal(err)
		}
		if !level {
			t.Fatal("write did not interrupt")
		}
		in(0x1f7)
	}
	actual := make([]byte, 1024)
	if _, err := overlay.ReadAt(actual, 0); err != nil {
		t.Fatal(err)
	}
	if actual[0] != 0xa0 || actual[512] != 0xa1 || base[0] != 1 || base[512] != 2 {
		t.Fatal("overlay writes lost or changed base")
	}
	out(0x1f2, 2)
	out(0x1f3, 4)
	out(0x1f7, 0x20)
	if d.status()&1 == 0 || d.task[1] != 0x10 {
		t.Fatal("out-of-range transfer was accepted")
	}
	out(0x1f6, 0xb0)
	if in(0x1f7) != 0 {
		t.Fatal("absent slave reports ready")
	}
}

// NT 3.1 uses mode 3 extensively for drawing. The CPU's byte is a mask,
// not the stored pixel data, so ordinary RAM cannot replace the aperture.
func TestVGAMaskedSetResetUsesLatches(t *testing.T) {
	v := newVGA(make([]byte, 0x8000))
	if err := v.setMode(0x12); err != nil {
		t.Fatal(err)
	}
	for i := range v.planes {
		v.planes[i][0] = 0xf0
	}
	v.read(0xa0000)
	v.gc[0], v.gc[5], v.gc[8] = 5, 3, 0x0f
	v.write(0xa0001, 0x0a)
	for i, want := range []byte{0xfa, 0xf0, 0xfa, 0xf0} {
		if got := v.planes[i][1]; got != want {
			t.Fatalf("plane %d: got %02x, want %02x", i, got, want)
		}
	}
}

func TestVGAPlanesLatchesAndCapture(t *testing.T) {
	v := newVGA(make([]byte, 0x8000))
	if err := v.setMode(0x12); err != nil {
		t.Fatal(err)
	}
	v.seq[2] = 1
	v.write(0xa0000, 0xa5)
	v.seq[2] = 2
	v.write(0xa0000, 0x3c)
	v.gc[4] = 0
	if v.read(0xa0000) != 0xa5 {
		t.Fatal("plane read")
	}
	v.seq[2] = 15
	v.gc[5] = 1
	v.write(0xa0001, 0)
	if v.planes[0][1] != 0xa5 || v.planes[1][1] != 0x3c {
		t.Fatal("write mode 1 did not copy all read latches")
	}
	v.gc[5] = 0
	v.gc[8] = 0x0f
	v.seq[2] = 1
	v.write(0xa0001, 0xff)
	if v.planes[0][1] != 0xaf {
		t.Fatalf("bit mask lost latch: %x", v.planes[0][1])
	}
	v.gc[5] = 2
	v.gc[8] = 255
	v.seq[2] = 15
	v.write(0xa0000, 4)
	v.gc[5] = 8
	v.gc[2] = 4
	v.gc[7] = 15
	if v.read(0xa0000) != 255 {
		t.Fatal("read mode 1 color compare")
	}
	img, err := v.screenshot()
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != 640 || img.Bounds().Dy() != 480 {
		t.Fatal(img.Bounds())
	}
	c := img.RGBAAt(0, 0)
	if c.R != 170 || c.G != 0 || c.B != 0 {
		t.Fatalf("palette conversion: %v", c)
	}
}

func TestKeyboardCommandAndIRQ(t *testing.T) {
	level := false
	k := newKeyboard(func(irq uint32, v bool) error {
		if irq == 1 {
			level = v
		}
		return nil
	})
	out := func(port uint16, value byte) {
		t.Helper()
		if err := k.io(ioByte(port, true, value)); err != nil {
			t.Fatal(err)
		}
	}
	in := func(port uint16) byte {
		t.Helper()
		ex := ioByte(port, false, 0)
		if err := k.io(ex); err != nil {
			t.Fatal(err)
		}
		return ex.Data[0]
	}
	out(0x60, 0xf3)
	if !level || in(0x60) != 0xfa || level {
		t.Fatal("typematic command ACK")
	}
	out(0x60, 0x20)
	if in(0x60) != 0xfa {
		t.Fatal("typematic parameter ACK")
	}
	out(0x64, 0x20)
	if in(0x60) != 0x45 {
		t.Fatal("command byte read")
	}
	if err := k.key("delete", true); err != nil {
		t.Fatal(err)
	}
	if in(0x60) != 0xe0 || !level || in(0x60) != 0x53 || level {
		t.Fatal("extended make and IRQ reassertion")
	}
	if err := k.key("delete", false); err != nil {
		t.Fatal(err)
	}
	if in(0x60) != 0xe0 || in(0x60) != 0xd3 {
		t.Fatal("extended break")
	}
}
