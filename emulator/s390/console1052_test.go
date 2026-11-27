package s390

import (
	"bytes"
	"testing"
)

func Test1052OperatorControls(t *testing.T) {
	m, c := newTest360(t, true, nil)
	console := NewConsole1052()
	const dev = 0x1f
	if err := m.CSS.AttachConsole1052(dev, console); err != nil {
		t.Fatal(err)
	}
	tio := func(want byte) {
		t.Helper()
		if cc := ioInstr(c, 0x9d, dev, 0); cc != 1 || m.S.Mem[0x44] != want {
			t.Fatalf("TIO: cc %d status %02X, want CC 1 status %02X", cc, m.S.Mem[0x44], want)
		}
	}
	console.SetReady(false)
	tio(usUnitCheck)
	ccw0(m, 0x1000, 0x04, 0x2000, 0, 1)
	if cc := ioInstr(c, 0x9c, dev, 0x1000); cc != 0 || !advance(m) {
		t.Fatalf("Sense: cc %d", cc)
	}
	tio(usCE | usDE)
	if b := m.S.Mem[0x2000]; b != senseIntervReq {
		t.Fatalf("Not Ready sense %02X", b)
	}
	console.SetReady(true)
	tio(usDE)
	ccw0(m, 0x1000, 0x0a, 0x2000, ccwSLI, 5)
	if cc := ioInstr(c, 0x9c, dev, 0x1000); cc != 0 || !m.CSS.Waiting(dev) {
		t.Fatalf("Read inquiry: cc %d", cc)
	}
	if err := console.Cancel("ABC"); err != nil {
		t.Fatal(err)
	}
	if !advance(m) {
		t.Fatal("cancel did not schedule channel end")
	}
	tio(usCE | usUnitExcept)
	if got := m.S.Mem[0x2000:0x2003]; !bytes.Equal(got, EncodeEBCDIC("ABC")) {
		t.Fatalf("keyboard data %X", got)
	}
	if !advance(m) {
		t.Fatal("cancel did not schedule device end")
	}
	tio(usDE)

	if cc := ioInstr(c, 0x9c, dev, 0x1000); cc != 0 || !m.CSS.Waiting(dev) {
		t.Fatalf("read before keyboard parity fault: cc %d", cc)
	}
	if err := console.TypeWithParityError("XYZ"); err != nil {
		t.Fatal(err)
	}
	if !advance(m) {
		t.Fatal("keyboard parity fault did not schedule channel end")
	}
	tio(usCE | usUnitCheck)
	if got := m.S.Mem[0x2000:0x2003]; !bytes.Equal(got, EncodeEBCDIC("XYZ")) {
		t.Fatalf("keyboard data with parity fault %X", got)
	}
	ended := m.tod
	if !advance(m) || m.tod-ended != durationTOD(carrierReturn) {
		t.Fatal("keyboard parity fault did not wait for the carrier return")
	}
	tio(usDE)
	ccw0(m, 0x1000, 0x04, 0x2000, 0, 1)
	for _, want := range []byte{senseEquipCheck, 0} {
		if cc := ioInstr(c, 0x9c, dev, 0x1000); cc != 0 || !advance(m) {
			t.Fatalf("Sense after keyboard parity fault: cc %d", cc)
		}
		tio(usCE | usDE)
		if got := m.S.Mem[0x2000]; got != want {
			t.Fatalf("Sense after keyboard parity fault %02X, want %02X", got, want)
		}
	}
}

func Test1052CarrierAcrossWrites(t *testing.T) {
	console := NewConsole1052()
	console.Exec(0x01, append(EncodeEBCDIC("ABC"), 0x16, 0x16), false)
	console.Exec(0x01, append(EncodeEBCDIC("x"), 0x05), false)
	console.Exec(0x09, EncodeEBCDIC("y"), false)
	if len(console.Lines) != 1 || console.Lines[0] != "AxC     y" {
		t.Fatalf("printed lines %q, want [\"AxC     y\"]", console.Lines)
	}
}

func Test1052RibbonAndFeedControlsAcrossWrites(t *testing.T) {
	c := NewConsole1052()
	c.ribbonShift = true
	c.Exec(0x01, []byte{0x27}, false)
	c.Exec(0x01, []byte{0xc1, 0x27, 0xc4}, false)
	if !c.ribbon.Up || !c.ribbon.DoubleFeed {
		t.Fatalf("expected upper ribbon and double feed: %+v", c.ribbon)
	}
	c.Exec(0x01, append(EncodeEBCDIC("X"), 0x15, 0x27, 0xc2, 0x27, 0xc3), false)
	if c.ribbon.Up || c.ribbon.DoubleFeed || len(c.Lines) != 2 || c.Lines[0] != "X" || c.Lines[1] != "" {
		t.Fatalf("expected lower ribbon, single feed, and a double-spaced line: %+v %q", c.ribbon, c.Lines)
	}
}
