package cc

import (
	"reflect"
	"testing"
	"time"
)

func TestHPETLegacyOwnershipAndRouteChanges(t *testing.T) {
	now := time.Unix(100, 0)
	var edges [][2]uint32
	var modes []bool
	h := newHPET(now, func(irq uint32, level bool) error {
		v := uint32(0)
		if level {
			v = 1
		}
		edges = append(edges, [2]uint32{irq, v})
		return nil
	})
	if h.read(0, now)&(1<<15) != 0 {
		t.Fatal("legacy advertised without accelerator control")
	}
	h.setLegacy = func(enabled bool) error { modes = append(modes, enabled); return nil }
	if h.read(0, now)&(1<<15) == 0 {
		t.Fatal("missing implemented legacy capability")
	}
	write := func(reg, value uint64) {
		t.Helper()
		if err := h.write(reg, value, ^uint64(0), now); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		write(uint64(0x100+i*32), uint64(20+i)<<9|6)
		write(uint64(0x108+i*32), 100)
	}
	write(0x10, 3)
	now = now.Add(time.Microsecond)
	if err := h.poll(now); err != nil {
		t.Fatal(err)
	}
	want := [][2]uint32{{0, 1}, {8, 1}, {22, 1}}
	if !reflect.DeepEqual(edges, want) {
		t.Fatalf("legacy routes %v", edges)
	}
	// Restore programmable routes with level status pending. Old routes must
	// lower before new routes assert; timer2 remains on its programmed route.
	write(0x10, 1)
	want = append(want, [2]uint32{0, 0}, [2]uint32{8, 0}, [2]uint32{22, 0}, [2]uint32{20, 1}, [2]uint32{21, 1}, [2]uint32{22, 1})
	if !reflect.DeepEqual(edges, want) || !reflect.DeepEqual(modes, []bool{true, false}) {
		t.Fatalf("ownership %v %v", edges, modes)
	}
	write(0x20, 7)
	if h.status != 0 {
		t.Fatal("legacy status not acknowledged")
	}
	for _, timer := range h.timers {
		if timer.asserted {
			t.Fatal("route still asserted")
		}
	}
}
