package s390

import (
	"strings"
	"testing"
)

func TestP390ESAKeyViewOfS370Blocks(t *testing.T) {
	p := newP390370Test(t)
	s := p.Machine.S
	const address = 0xbbf8
	first := (address >> 12) * 2
	s.Keys[first], s.Keys[first+1] = 0x54, 0x52
	var out [1]byte
	if err := p.ReadAperture(0x10000+(address>>12), out[:]); err != nil || out[0] != 0x56 {
		t.Fatalf("4K host key disagrees with 2K CPU keys: %x %v", out, err)
	}
	if s.KeyShift != 11 || s.Keys[first] != 0x54 || s.Keys[first+1] != 0x52 {
		t.Fatal("host inspection changed architectural keys")
	}
	// An opposite-half protection difference cannot be faithfully represented
	// by the ESA host. Fail explicitly rather than allowing or denying I/O on
	// an arbitrary half's key.
	s.Keys[first+1] = 0x62
	if err := p.ReadAperture(0x10000+(address>>12), out[:]); err == nil || !strings.Contains(err.Error(), "mixed S/370 protection") {
		t.Fatalf("mixed protection was silently flattened: %v", err)
	}
	if err := p.WriteAperture(0x10000+(address>>12), []byte{0xa8}); err != nil {
		t.Fatal(err)
	}
	if s.Keys[first] != 0xa8 || s.Keys[first+1] != 0xa8 || s.Keys[first-1] != 0 || s.Keys[first+2] != 0 {
		t.Fatal("4K host key write did not cover exactly two architectural blocks")
	}
}
