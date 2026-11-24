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
}
