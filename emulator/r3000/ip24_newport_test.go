package r3000

import (
	"image/color"
	"testing"
)

func TestIP24NewportDCBByteLaneAndRetrace(t *testing.T) {
	m, err := newIP24(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	write := func(offset, size uint32, value uint64) {
		t.Helper()
		if !m.write64(newportBase+uint64(offset), size, value) {
			t.Fatalf("unmapped Newport store at %#x", offset)
		}
	}
	read := func(offset, size uint32) uint64 {
		t.Helper()
		data, ok := m.read64(newportBase+uint64(offset), size)
		if !ok {
			t.Fatalf("unmapped Newport load at %#x", offset)
		}
		return data
	}
	write(0x238, 4, 2<<7|6<<4|1) // CMAP0 revision, one byte.
	if got := read(0x243, 1); got != 0x42 {
		t.Fatalf("CMAP revision %#x, want %#x", got, 0x42)
	}
	write(0x238, 4, 3)
	write(0x240, 4, 0x10000100) // Enable VC2 vertical retrace interrupt.
	write(0x238, 4, 1)
	write(0x243, 1, 0x10) // VC2 register selection uses the low byte lane.
	write(0x238, 4, 1<<4|2)
	if got := read(0x242, 2); got != 1 {
		t.Fatalf("VC2 display control %#x, want 1", got)
	}
	m.cycles = newportFrame
	m.updateInterrupts()
	if m.int3.reg[2]&0x80 == 0 || read(0x133c, 4)&0x20 == 0 || read(0x1338, 4)&0x20 == 0 {
		t.Fatal("retrace did not raise GIO interrupt 2")
	}
	m.updateInterrupts()
	if m.int3.reg[2]&0x80 != 0 {
		t.Fatal("reading REX3 status failed to acknowledge retrace")
	}
}

func TestNewportIndexedRectangleAndOverlapCopy(t *testing.T) {
	var g newport
	g.reset()
	g.xmap[0].modes[0] = 0x400
	g.cmap[0].palette[0x12] = 0x83a542
	g.cmap[0].palette[0x13] = 0x194658
	write := func(offset, value uint32) {
		t.Helper()
		if _, ok := g.access(offset, 4, uint64(value), true, 0); !ok {
			t.Fatalf("unmapped Newport register %#x", offset)
		}
	}
	write(0, 0x30000009) // Source raster op, 8-bit RGB/CI planes.
	write(4, 0x306)      // Draw block with X and Y stops.
	write(0x150, 2<<16|5)
	write(0x224, 0x12)
	write(0x954, 5<<16|7)
	write(0x150, 5<<16|5)
	write(0x224, 0x13)
	write(0x954, 5<<16|7)

	write(4, 0x307) // Copy in the decreasing X direction.
	write(0x114, 1<<16)
	write(0x150, 5<<16|5)
	write(0x954, 2<<16|7)
	frame := g.screen()
	for _, sample := range []struct {
		x, y int
		want color.RGBA
	}{
		{2, 5, color.RGBA{0x83, 0xa5, 0x42, 255}},
		{5, 6, color.RGBA{0x83, 0xa5, 0x42, 255}},
		{6, 7, color.RGBA{0x19, 0x46, 0x58, 255}},
		{6, 8, color.RGBA{0, 0, 0, 255}},
	} {
		if got := frame.RGBAAt(sample.x, sample.y); got != sample.want {
			t.Errorf("pixel (%d, %d) = %v, want %v", sample.x, sample.y, got, sample.want)
		}
	}
}

func TestNewportPacksRGBComponentsForDoubleBufferedScanout(t *testing.T) {
	var g newport
	g.reset()
	g.xmap[0].modes[0] = 0x901 // RGB, 12 bits, upper buffer.
	g.write(0, 0x30008011, 0)
	g.write(4, 0x306, 0)
	g.write(0x150, 3<<16|4, 0)
	g.write(0x200, 0xa7<<11, 0)
	g.write(0x208, 0x94<<11, 0)
	g.write(0x20c, 0xf2<<11, 0)
	g.write(0x220, 0xfff000, 0)
	if _, ok := g.access(0x954, 4, 3<<16|4, true, 0); !ok {
		t.Fatal("Newport GO destination register was not mapped")
	}
	if got := g.rgb[4*newportStride+3]; got != 0xf9a000 {
		t.Fatalf("packed RGB pixel %#x, want 0xf9a000", got)
	}
	want := color.RGBA{0xaa, 0x99, 0xff, 255}
	if got := g.screen().RGBAAt(3, 4); got != want {
		t.Fatalf("12-bit scanout pixel %v, want %v", got, want)
	}
}
