package s390

import (
	"bytes"
	"testing"
)

func Test9020CTCRestoresWaitingTransfer(t *testing.T) {
	m, c := newTest360(t, true, nil)
	const writeDev, readDev = 0x320, 0x420
	if err := m.CSS.Attach9020CTC(writeDev, readDev); err != nil {
		t.Fatal(err)
	}
	ccw0(m, 0x1000, 0x01, 0x2000, 0, 4)
	ccw0(m, 0x1010, 0x14, 0x3000, ccwCC, 1)
	ccw0(m, 0x1018, 0x02, 0x3001, 0, 4)
	copy(m.S.Mem[0x2000:], "DATA")

	if cc := ioInstr(c, 0x9c, writeDev, 0x1000); cc != 0 {
		t.Fatalf("write SIO CC %d", cc)
	}
	if cc := ioInstr(c, 0x9d, readDev, 0); cc != 1 || m.S.Mem[0x44] != usAttention {
		t.Fatalf("attention TIO CC %d status %02X", cc, m.S.Mem[0x44])
	}
	var saved bytes.Buffer
	if err := m.Save(&saved); err != nil {
		t.Fatal(err)
	}
	m, c = newTest360(t, true, nil)
	if err := m.CSS.Attach9020CTC(writeDev, readDev); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(&saved, false); err != nil {
		t.Fatal(err)
	}

	if cc := ioInstr(c, 0x9c, readDev, 0x1010); cc != 0 {
		t.Fatalf("sense and read SIO CC %d", cc)
	}
	if !advance(m) || m.S.Mem[0x3000] != 0x01 {
		t.Fatalf("Sense Command Byte returned %02X", m.S.Mem[0x3000])
	}
	if !advance(m) || string(m.S.Mem[0x3001:0x3005]) != "DATA" {
		t.Fatalf("read data %q", m.S.Mem[0x3001:0x3005])
	}
	for _, tt := range []struct {
		dev uint16
		csw uint64
	}{{writeDev, 0x00001008_0C000000}, {readDev, 0x00001020_0C000000}} {
		cc := ioInstr(c, 0x9d, tt.dev, 0)
		if csw := be.Uint64(m.S.Mem[0x40:]); cc != 1 || csw != tt.csw {
			t.Fatalf("%04X TIO CC %d CSW %016X, wanted %016X", tt.dev, cc, csw, tt.csw)
		}
		if cc := ioInstr(c, 0x9d, tt.dev, 0); cc != 0 {
			t.Fatalf("%04X still signals status after completion CC %d", tt.dev, cc)
		}
	}
}
