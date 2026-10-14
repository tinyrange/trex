package pl011

import (
	"bytes"
	"testing"
)

func TestPolledFIFOAndLoopback(t *testing.T) {
	var output []byte
	u := New(0x20010000, func(b byte) error { output = append(output, b); return nil })
	read := func(off uint64) uint64 {
		t.Helper()
		v, e := u.Read(u.Base+off, 4)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	write := func(off, value uint64) {
		t.Helper()
		if e := u.Write(u.Base+off, 4, value); e != nil {
			t.Fatal(e)
		}
	}
	if read(0x18) != 0x90 || read(0xfe0) != 0x11 {
		t.Fatal("wrong reset flags or PL011 identity")
	}
	write(0, 'X')
	if len(output) != 0 {
		t.Fatal("transmitted with UART disabled")
	}
	write(0x30, 0x301)
	write(0, 'A')
	if !bytes.Equal(output, []byte("A")) {
		t.Fatal(output)
	}
	if e := u.Receive([]byte("BC")); e != nil {
		t.Fatal(e)
	}
	if read(0x18)&0x10 != 0 || read(0) != 'B' || read(0) != 'C' || read(0x18)&0x10 == 0 {
		t.Fatal("FIFO receive state")
	}
	write(0x30, 0x381)
	write(0, 'D')
	if read(0) != 'D' || len(output) != 1 {
		t.Fatal("loopback escaped to external transmitter")
	}
	if e := u.Receive(make([]byte, 32)); e != nil {
		t.Fatal(e)
	}
	if read(0x18)&0x40 == 0 || u.Receive([]byte{1}) == nil {
		t.Fatal("FIFO full state")
	}
	if u.Contains(^uint64(0), 4) || u.Contains(u.Base+1, 4) || u.Contains(u.Base, 8) {
		t.Fatal("accepted invalid MMIO range")
	}
	if e := u.Write(u.Base+0x38, 4, 1); e == nil {
		t.Fatal("silently accepted unsupported interrupts")
	}
}
