package cc

import "testing"

func TestControllerOutputInjection(t *testing.T) {
	levels := map[uint32]bool{}
	k := newKeyboard(func(irq uint32, level bool) error { levels[irq] = level; return nil })
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
	// OS/2 probes the controller while the keyboard interface is inhibited.
	out(0x64, 0x60)
	out(0x60, 0x55)
	out(0x64, 0xd2)
	out(0x60, 0x55)
	if in(0x64)&0x31 != 0x11 || !levels[1] || in(0x60) != 0x55 || in(0x64)&1 != 0 {
		t.Fatal("inhibited controller injection was lost, translated, or ACKed")
	}
	out(0x64, 0xae)
	out(0x64, 0xd2)
	out(0x60, 0xf0)
	if !levels[1] || in(0x60) != 0xf0 || levels[1] || k.parameter != 0 {
		t.Fatal("injected byte was interpreted as a keyboard command")
	}
	out(0x64, 0x60)
	out(0x60, 0x47)
	out(0x64, 0xd3)
	out(0x60, 0xab)
	if in(0x64)&0x21 != 0x21 || !levels[12] || levels[1] || in(0x60) != 0xab || levels[12] {
		t.Fatal("auxiliary injection had incorrect status, data, or interrupt")
	}
}
