package power

import (
	"bytes"
	"testing"
)

func TestCRQScatterOwnershipAndCheckpoint(t *testing.T) {
	m := NewMachine(Config{Memory: 0x10000})
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(m.CreateTCETable(1, 8))
	must(m.WriteTCEs(1, 2, []uint64{0x5801, 0x9801}))
	if m.RegisterCRQ(9, 1, 0x2001, 4096) == nil || m.RegisterCRQ(9, 1, 0x2000, 3*4096) == nil {
		t.Fatal("invalid queue accepted")
	}
	must(m.RegisterCRQ(9, 1, 0x2000, 2*4096))
	if m.RegisterCRQ(9, 1, 0x2000, 4096) == nil {
		t.Fatal("duplicate queue accepted")
	}
	entry := bytes.Repeat([]byte{0xc0}, 16)
	for i := 0; i < 256; i++ {
		must(m.PostCRQ(9, entry))
	}
	if m.crqs[9].producer != 4096 || !bytes.Equal(m.Mem[0x5000:0x5010], entry) {
		t.Fatal("first page wrong")
	}
	cp := m.Checkpoint()
	must(m.PostCRQ(9, entry))
	if !bytes.Equal(m.Mem[0x9000:0x9010], entry) {
		t.Fatal("second noncontiguous page wrong")
	}
	must(m.Restore(cp))
	if m.crqs[9].producer != 4096 || m.Mem[0x9000] != 0 {
		t.Fatal("checkpoint lost queue position/data")
	}
	for i := 0; i < 256; i++ {
		must(m.PostCRQ(9, entry))
	}
	before := bytes.Clone(m.Mem)
	if m.PostCRQ(9, entry) == nil || m.crqs[9].producer != 0 || !bytes.Equal(before, m.Mem) {
		t.Fatal("full queue overwrote unread data")
	}
	must(m.WriteReal(0x5000, []byte{0})) // consumer releases an entry
	must(m.PostCRQ(9, entry))
	if m.crqs[9].producer != 16 {
		t.Fatal("ring failed to reuse released entry")
	}
	must(m.WriteTCE(1, 2, 0))
	before = bytes.Clone(m.Mem)
	if m.PostCRQ(9, entry) == nil || m.crqs[9].producer != 16 || !bytes.Equal(before, m.Mem) {
		t.Fatal("DMA fault partially posted")
	}
	must(m.Restore(cp))
	if m.crqs[9].producer != 4096 {
		t.Fatal("queue checkpoint was mutated")
	}
	must(m.UnregisterCRQ(9))
	if m.PostCRQ(9, entry) == nil || m.UnregisterCRQ(9) == nil {
		t.Fatal("unregistered queue accepted")
	}
	if got, _ := m.ReadTCE(1, 2); got != 0x5801 {
		t.Fatal("queue release altered translation")
	}
}
