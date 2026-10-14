package cc

import (
	"errors"
	"testing"
)

func TestVirtualCTRRLockdown(t *testing.T) {
	var calls int
	d := virtualCTRR{address: 0x06000000, base: 0x70000000, size: 0x100000, protect: func(a, n uint64) error {
		calls++
		if a != 0x70004000 || n != 0x8000 {
			t.Fatalf("protection %#x+%#x", a, n)
		}
		return nil
	}}
	d.banks[3] = ctrrBank{lower: 0x70004000, upper: 0x7000bfff}
	if !d.writable(0x70004000, 1) {
		t.Fatal("premature protection")
	}
	for i := uint64(0); i < 8; i++ {
		v := uint64(7)
		if i >= 4 {
			v = 1
		}
		if err := d.Write(0x06000050+i*32, 8, v); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 || d.writable(0x70004000, 1) || d.writable(0x70003fff, 2) || !d.writable(0x7000c000, 1) {
		t.Fatal("incorrect protection boundaries", calls)
	}
	for _, a := range []uint64{0x060000a0, 0x060000a8, 0x060000b0} {
		if err := d.Write(a, 8, 0); err == nil {
			t.Fatal("locked bank changed")
		}
	}
	if v, e := d.Read(0x060000b0, 8); e != nil || v != 7 {
		t.Fatal(v, e)
	}
}
func TestVirtualCTRRRejectsUnenforcedProtection(t *testing.T) {
	d := virtualCTRR{address: 0x30260000, base: 0x70000000, size: 0x10000, protect: func(uint64, uint64) error { return errors.New("denied") }}
	d.banks[0] = ctrrBank{lower: 0x70000000, upper: 0x70003fff}
	if err := d.Write(0x30260050, 8, 7); err == nil || d.banks[0].control != 0 {
		t.Fatal("reported unenforced lockdown")
	}
	for _, v := range []uint64{0, 1, 2, 3, 4, 5, 6, 8} {
		if err := d.Write(0x30260050, 8, v); err == nil {
			t.Fatal("accepted unknown mode", v)
		}
	}
	d.banks[0].upper = 0x70004000
	if err := d.Write(0x30260050, 8, 7); err == nil {
		t.Fatal("accepted unaligned upper bound")
	}
}
