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

	// D6AA00 routine 10 reserves each unit on A before releasing the first.
	// B can see the control-unit end while the second unit is still reserved.
	m, c = newMachine()
	sense(0x74, printerA)
	sense(0x74, readerA)
	status(0x9c, readerB, usSM|usBusy)
	sense(0x14, printerA)
	status(0x9c, readerB, usSM|usBusy|usCUE)
	status(0x9c, readerB, usBusy)
	sense(0x14, readerA)
	status(0x9c, readerB, usBusy|usDE)
	sense(0x04, readerB)

	// One not-ready-to-ready indication can be collected from either path.
	reader := m.CSS.bydev[readerA].dev.(*UnitRecord)
	for _, selected := range []uint16{readerB, readerA} {
		reader.Submit([]string{"READY"})
		status(0x9d, selected, usDE)
		for _, dev := range []uint16{readerA, readerB} {
			if cc := ioInstr(c, 0x9d, dev, 0x1000); cc != 0 {
				t.Fatalf("duplicate ready interrupt on %04x: CC %d", dev, cc)
			}
		}
	}
	reader.Submit([]string{"RESTORE"})
	checkpoint.Reset()
	if err := m.Save(&checkpoint); err != nil {
		t.Fatal(err)
	}
	m, c = newMachine()
	if err := m.Restore(&checkpoint, false); err != nil {
		t.Fatal(err)
	}
	status(0x9d, readerB, usDE)
	if cc := ioInstr(c, 0x9d, readerA, 0x1000); cc != 0 {
		t.Fatalf("duplicate ready interrupt after restore: CC %d", cc)
	}
	sense(0xb4, readerA)
	reader = m.CSS.bydev[readerA].dev.(*UnitRecord)
	reader.Submit([]string{"RESERVED"})
	status(0x9d, readerB, usBusy)
	status(0x9d, readerA, usDE)
	sense(0x94, readerA)
	status(0x9d, readerB, usDE)
}

func Test2821SenseRetainedUntilNextCommand(t *testing.T) {
	u := &UnitRecord{Type: 0x2541}
	if _, _, status := u.Exec(0xff, nil, false); status != usUnitCheck {
		t.Fatalf("invalid command status %02x", status)
	}
	checkSense := func(want byte) {
		t.Helper()
		data, _, status := u.Exec(0x04, nil, false)
		if status != usCE|usDE || !bytes.Equal(data, []byte{want}) {
			t.Fatalf("sense %x status %02x, want %02x", data, status, want)
		}
	}
	checkSense(senseCmdRej)
	u.Exec(0x03, nil, false)
	checkSense(senseCmdRej)
	u.Exec(0xc2, nil, false)
	checkSense(0)
}
