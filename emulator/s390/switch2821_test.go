package s390

import (
	"bytes"
	"testing"
)

func Test2821SwitchReservationAndEndingStatus(t *testing.T) {
	const printerA, printerB, readerA, readerB = 0x28, 0x428, 0x29, 0x429
	newMachine := func() (*Machine, *CPU) {
		m, c := newTest360(t, true, nil)
		if err := m.CSS.AttachUnitRecord(printerA, &UnitRecord{Type: 0x1403}); err != nil {
			t.Fatal(err)
		}
		if err := m.CSS.AttachUnitRecord(readerA, &UnitRecord{Type: 0x2540}); err != nil {
			t.Fatal(err)
		}
		if err := m.CSS.Attach2821Switch([][2]uint16{{printerA, printerB}, {readerA, readerB}}); err != nil {
			t.Fatal(err)
		}
		return m, c
	}
	m, c := newMachine()
	status := func(op byte, dev uint16, want byte) {
		t.Helper()
		if cc := ioInstr(c, op, dev, 0x1000); cc != 1 || m.S.Mem[0x44] != want {
			t.Fatalf("%02X %04X: CC %d status %02X, want CC 1 status %02X", op, dev, cc, m.S.Mem[0x44], want)
		}
	}
	sense := func(cmd byte, dev uint16) {
		t.Helper()
		ccw0(m, 0x1000, cmd, 0x2000, 0, 1)
		if cc := ioInstr(c, 0x9c, dev, 0x1000); cc != 0 || !advance(m) {
			t.Fatalf("%02X %04X: sense CC %d", cmd, dev, cc)
		}
		status(0x9d, dev, usCE|usDE)
	}

	sense(0x74, printerA)
	status(0x9c, readerB, usSM|usBusy)

	var checkpoint bytes.Buffer
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	m, c = newMachine()
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}

	sense(0xd4, printerA)
	status(0x9c, readerB, usSM|usBusy|usCUE)
	status(0x9c, printerB, usBusy)
	sense(0x04, readerB)
	sense(0x94, printerA)
	status(0x9c, printerB, usBusy|usDE)
	sense(0x04, printerB)
}
