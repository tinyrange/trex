package cc

import "testing"

func TestKeyboardClockInhibitionBuffersTransitions(t *testing.T) {
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
	in := func() byte {
		t.Helper()
		ex := ioByte(0x60, false, 0)
		if err := k.io(ex); err != nil {
			t.Fatal(err)
		}
		return ex.Data[0]
	}
	out(0x64, 0xad)
	for _, down := range []bool{true, false} {
		if err := k.key("shift", down); err != nil {
			t.Fatal(err)
		}
	}
	if level || len(k.queue) != 0 || len(k.heldKeys) != 2 {
		t.Fatal("inhibited scan bytes reached controller")
	}
	out(0x64, 0xd2)
	out(0x60, 0x55)
	if !level || in() != 0x55 || level {
		t.Fatal("held keys obstructed controller injection")
	}
	// Both ways of releasing the clock must deliver the buffered transition.
	out(0x64, 0xae)
	if !level || in() != 0x2a || !level || in() != 0xaa || level || len(k.heldKeys) != 0 {
		t.Fatal("lost or reordered key transitions")
	}
	out(0x64, 0xad)
	if err := k.key("a", true); err != nil {
		t.Fatal(err)
	}
	out(0x64, 0x60)
	out(0x60, 0x45)
	if !level || in() != 0x1e || level {
		t.Fatal("command-byte clock enable did not drain held key")
	}
	out(0x64, 0xad)
	for i := 0; i < 1024; i++ {
		if err := k.key("a", true); err != nil {
			t.Fatal(err)
		}
	}
	if err := k.key("a", false); err == nil {
		t.Fatal("unbounded held key buffer")
	}
}
