package cc

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func inputFixture(t *testing.T) (*virtioInput, []byte, *bool) {
	t.Helper()
	ram := make([]byte, 65536)
	irq := new(bool)
	v := &virtioInput{memory: func(a, n uint64) ([]byte, error) {
		if a > uint64(len(ram)) || n > uint64(len(ram))-a {
			return nil, fmt.Errorf("outside RAM")
		}
		return ram[a : a+n], nil
	}, irq: func(_ uint32, level bool) error { *irq = level; return nil }}
	for _, w := range [][2]uint32{{0x70, 3}, {0x24, 1}, {0x20, 1}, {0x70, 11}, {0x30, 0}, {0x38, 8}, {0x80, 0x1000}, {0x90, 0x2000}, {0xa0, 0x3000}, {0x44, 1}, {0x70, 15}} {
		if err := v.write(uint64(w[0]), w[1]); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 8; i++ {
		d := ram[0x1000+i*16:]
		binary.LittleEndian.PutUint64(d, uint64(0x4000+i*8))
		binary.LittleEndian.PutUint32(d[8:], 8)
		binary.LittleEndian.PutUint16(d[12:], 2)
		binary.LittleEndian.PutUint16(ram[0x2004+i*2:], uint16(i))
	}
	binary.LittleEndian.PutUint16(ram[0x2002:], 8)
	return v, ram, irq
}

func TestVirtioInputReportAndReset(t *testing.T) {
	v, ram, irq := inputFixture(t)
	if !v.active() {
		t.Fatal("negotiation failed")
	}
	if err := v.pointer(65535, 12345, 1, -1); err != nil {
		t.Fatal(err)
	}
	want := []inputEvent{{3, 0, 65535}, {3, 1, 12345}, {1, 0x110, 1}, {2, 8, 0xffffffff}, {0, 0, 0}}
	for i, e := range want {
		b := ram[0x4000+i*8:]
		got := inputEvent{binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:]), binary.LittleEndian.Uint32(b[4:])}
		if got != e {
			t.Fatalf("event %d: %+v want %+v", i, got, e)
		}
	}
	if !*irq || binary.LittleEndian.Uint16(ram[0x3002:]) != 5 {
		t.Fatal("missing completion interrupt")
	}
	v.write(0x64, 1)
	if *irq {
		t.Fatal("ack did not deassert IRQ")
	}
	v.write(0x70, 0)
	if v.active() || *irq || v.queues[0].ready {
		t.Fatal("reset retained device state")
	}
}

func TestVirtioInputWholeReportAndMalformedDMA(t *testing.T) {
	v, ram, _ := inputFixture(t)
	binary.LittleEndian.PutUint16(ram[0x2002:], 2)
	if err := v.pointer(1, 2, 0, 0); err != nil {
		t.Fatal(err)
	}
	if v.reports != 0 || v.queues[0].written != 0 {
		t.Fatal("partial SYN report consumed")
	}
	binary.LittleEndian.PutUint16(ram[0x2002:], 3)
	v.write(0x50, 0)
	if v.reports != 1 {
		t.Fatal("replenishment did not flush report")
	}
	for _, fault := range []string{"outside", "cycle", "read-only", "overrun"} {
		t.Run(fault, func(t *testing.T) {
			v, ram, _ := inputFixture(t)
			switch fault {
			case "outside":
				binary.LittleEndian.PutUint64(ram[0x1000:], ^uint64(0)-3)
			case "cycle":
				binary.LittleEndian.PutUint16(ram[0x100c:], 3)
			case "read-only":
				binary.LittleEndian.PutUint16(ram[0x100c:], 0)
			case "overrun":
				binary.LittleEndian.PutUint16(ram[0x2002:], 9)
			}
			v.pointer(1, 2, 0, 0)
			if v.status&64 == 0 || v.queues[0].written != 0 {
				t.Fatal("malformed DMA was not rejected atomically")
			}
			for _, b := range ram[0x4000:0x4040] {
				if b != 0 {
					t.Fatal("DMA occurred before validation")
				}
			}
		})
	}
}
