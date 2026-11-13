package s390

import (
	"bytes"
	"testing"
)

func TestCTCIBlocks(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, CPUs: 1, MIPS: 50})
	c, err := m.CSS.AttachCTCI(0x0e40)
	if err != nil {
		t.Fatal(err)
	}
	r, w := m.CSS.bydev[0x0e40].dev.(*ctciSide), m.CSS.bydev[0x0e41].dev.(*ctciSide)
	var sent [][]byte
	c.Out = func(p []byte) { sent = append(sent, p) }
	if id := r.SenseID(); !bytes.Equal(id[1:4], []byte{0x30, 0x88, 0x08}) {
		t.Fatalf("sense ID %X", id)
	}
	if !r.Blocked(0x02) {
		t.Fatal("READ with nothing queued does not wait")
	}
	// The program's initialization block carries nothing; a data block
	// carries each IP packet to Out.
	if _, _, st := w.Exec(0x01, []byte{0, 0}, false); st != usCE|usDE || len(sent) != 0 {
		t.Fatalf("init block: %X %d", st, len(sent))
	}
	block := []byte{0, 2 + 6 + 3 + 6 + 2, 0, 9, 0x08, 0, 0, 0, 'a', 'b', 'c', 0, 8, 0x08, 0, 0, 0, 'd', 'e', 0, 0}
	if _, _, st := w.Exec(0x01, block, false); st != usCE|usDE || len(sent) != 2 || string(sent[0]) != "abc" || string(sent[1]) != "de" {
		t.Fatalf("write: %X %q", st, sent)
	}
	if _, _, st := w.Exec(0x01, []byte{0, 20, 0, 3, 0x08, 0}, false); st&usUnitCheck == 0 {
		t.Fatal("malformed segment accepted")
	}
	// Delivered packets come back as one block ending in a zero offset.
	c.Deliver([]byte("IP1"))
	c.Deliver([]byte("PKT2"))
	if r.Blocked(0x02) {
		t.Fatal("READ waits with packets queued")
	}
	out, _, st := r.Exec(0x02, make([]byte, 0x5000), false)
	want := []byte{0, 2 + 9 + 10, 0, 9, 0x08, 0, 0, 0, 'I', 'P', '1', 0, 10, 0x08, 0, 0, 0, 'P', 'K', 'T', '2', 0, 0}
	if st != usCE|usDE || !bytes.Equal(out, want) {
		t.Fatalf("read %X\nwant %X", out, want)
	}
	if !r.Blocked(0x02) {
		t.Fatal("queue not drained")
	}
}
