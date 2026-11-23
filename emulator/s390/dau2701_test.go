package s390

import (
	"bytes"
	"testing"
)

func Test2701SharedBusyAndDiagnosticRegister(t *testing.T) {
	m, c := newTest360(t, true, nil)
	const source, peer = 0x21, 0x25
	if err := m.CSS.Attach2701(0x20); err != nil {
		t.Fatal(err)
	}
	ccw0(m, 0x1000, 0x09, 0x2000, 0, 3)
	ccw0(m, 0x1010, 0x0a, 0x3000, 0, 4)
	copy(m.S.Mem[0x2000:], []byte{0xab, 0xcd, 0xef})
	if cc := ioInstr(c, 0x9c, source, 0x1000); cc != 0 {
		t.Fatalf("diagnostic write CC %d", cc)
	}
	if cc := ioInstr(c, 0x9d, peer, 0); cc != 1 || m.S.Mem[0x44] != usSM|usBusy {
		t.Fatalf("peer TIO CC %d status %02X", cc, m.S.Mem[0x44])
	}

	var saved bytes.Buffer
	if err := m.Save(&saved); err != nil {
		t.Fatal(err)
	}
	m, c = newTest360(t, true, nil)
	if err := m.CSS.Attach2701(0x20); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(&saved, false); err != nil {
		t.Fatal(err)
	}
	if !advance(m) {
		t.Fatal("no diagnostic write completion deadline")
	}
	if cc := ioInstr(c, 0x9d, source, 0); cc != 1 || m.S.Mem[0x44] != usCE|usDE|usCUE {
		t.Fatalf("source TIO CC %d status %02X", cc, m.S.Mem[0x44])
	}
	if cc := ioInstr(c, 0x9c, peer, 0x1010); cc != 0 || !advance(m) {
		t.Fatalf("diagnostic read CC %d", cc)
	}
	if data := m.S.Mem[0x3000:0x3004]; !bytes.Equal(data, []byte{0xef, 0xef, 0xef, 0xef}) {
		t.Fatalf("peer read %X", data)
	}
}
