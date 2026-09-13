package cc

import "testing"

func TestPS2MousePackets(t *testing.T) {
	k := newKeyboard(func(uint32, bool) error { return nil })
	k.command |= 2
	if err := k.mouseCommand(0xff); err != nil {
		t.Fatal(err)
	}
	if len(k.queue) != 3 || k.queue[1].value != 0xaa {
		t.Fatal(k.queue)
	}
	k.queue = nil
	k.mouseCommand(0xf4)
	k.queue = nil
	if err := k.mouseMove(-3, 4, 1); err != nil {
		t.Fatal(err)
	}
	for i, want := range []byte{0x19, 253, 4} {
		if k.queue[i].value != want || !k.queue[i].mouse {
			t.Fatal(k.queue)
		}
	}
	k.queue = nil
	k.mouseMove(0, 0, 0)
	if len(k.queue) != 3 || k.queue[0].value != 8 {
		t.Fatal("button release missing", k.queue)
	}
}
