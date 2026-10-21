package cc

import (
	"j5.nz/cc/hypervisor"
	"testing"
	"time"
)

func TestATRefreshClockAndPort61Latch(t *testing.T) {
	start := time.Unix(100, 0)
	now := start
	p := &pc{started: start, now: func() time.Time { return now }, ports: map[uint16]byte{}}
	read := func() byte {
		b := []byte{0}
		if err := p.handleIO(hypervisor.X86Exit{Port: 0x61, Size: 1, Count: 1, Data: b}); err != nil {
			t.Fatal(err)
		}
		return b[0]
	}
	write := func(b byte) {
		if err := p.handleIO(hypervisor.X86Exit{Port: 0x61, Size: 1, Count: 1, Write: true, Data: []byte{b}}); err != nil {
			t.Fatal(err)
		}
	}
	write(0xff)
	for i := 0; i < 20; i++ {
		if read()&0x1f != 0x0f {
			t.Fatal("read-dependent refresh or lost latch")
		}
	}
	now = start.Add(16 * time.Microsecond)
	if read()&0x1f != 0x1f {
		t.Fatal("first refresh transition missing")
	}
	write(0)
	if read()&0x1f != 0x10 {
		t.Fatal("guest write changed refresh input")
	}
	now = start.Add(31 * time.Microsecond)
	if read()&0x1f != 0 {
		t.Fatal("second transition missing")
	}
}
