package power

import (
	"bytes"
	"testing"
)

func TestVirtualBusDMA(t *testing.T) {
	m := NewMachine(Config{Memory: 0x10000, CPUs: 2, Extensions: []string{"as"}})
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(m.CreateTCETable(2, 8))
	must(m.CreateTCETable(3, 8))
	if m.CreateTCETable(2, 8) == nil || m.CreateTCETable(4, 0) == nil || m.CreateTCETable(4, ^uint64(0)) == nil {
		t.Fatal("invalid/duplicate table accepted")
	}
	word := uint64(0x8000000000003803) // Cache bit, RPN3000, valid, owner0, writable.
	must(m.WriteTCE(2, 1, word))
	got, err := m.ReadTCE(2, 1)
	must(err)
	if got != word {
		t.Fatalf("TCE readback %x", got)
	}
	must(m.WriteTCE(2, 2, 0x8801)) // noncontiguous next real page
	data := []byte("scatter DMA")
	m.tags[0x3ff0>>4>>6] |= 1 << ((0x3ff0 >> 4) & 63)
	for _, c := range m.CPUs {
		c.reserve(0x3f80, 8)
	}
	must(m.WriteDMA(2, 0x1ffc, data, 0))
	if string(m.Mem[0x3ffc:0x4000]) != "scat" || string(m.Mem[0x8000:0x8007]) != "ter DMA" {
		t.Fatal("scatter data incorrect")
	}
	if m.Tag(0x3ff0) || m.CPUs[0].resValid || m.CPUs[1].resValid {
		t.Fatal("DMA retained tags/reservations")
	}
	dst := make([]byte, len(data))
	must(m.ReadDMA(2, 0x1ffc, dst, 0))
	if !bytes.Equal(dst, data) {
		t.Fatal("scatter read mismatch")
	}
	if m.WriteDMA(3, 0x1000, data, 0) == nil || m.ReadDMA(2, 0x1000, dst, 1) == nil {
		t.Fatal("table/partition isolation failed")
	}
	must(m.WriteTCE(2, 2, 0x8800)) // readable, not writable
	before := bytes.Clone(m.Mem)
	if m.WriteDMA(2, 0x1ffc, data, 0) == nil || !bytes.Equal(before, m.Mem) {
		t.Fatal("cross-page write was not atomic on permission fault")
	}
	must(m.ReadDMA(2, 0x1ffc, dst, 0))
	must(m.WriteTCE(2, 2, 0x8c00)) // all partitions, read only
	must(m.ReadDMA(2, 0x2000, dst, 255))
	if m.WriteTCE(2, 1, 0x10801) == nil {
		t.Fatal("out-of-memory RPN accepted")
	}
	got, err = m.ReadTCE(2, 1)
	must(err)
	if got != word {
		t.Fatal("failed update changed entry")
	}
	if m.WriteTCE(2, 8, word) == nil {
		t.Fatal("out-of-window slot accepted")
	}
	for _, a := range []uint64{0x8000, ^uint64(0) - 1} {
		if m.WriteDMA(2, a, data, 0) == nil {
			t.Fatal("out-of-window DMA accepted")
		}
	}
	must(m.WriteTCE(2, 2, 0))
	sentinel := bytes.Repeat([]byte{0x5a}, len(data))
	if m.ReadDMA(2, 0x1ffc, sentinel, 0) == nil || !bytes.Equal(sentinel, bytes.Repeat([]byte{0x5a}, len(data))) {
		t.Fatal("failed read partially changed destination")
	}
	cp := m.Checkpoint()
	must(m.WriteTCE(2, 1, 0))
	must(m.CreateTCETable(9, 1))
	must(m.Restore(cp))
	got, err = m.ReadTCE(2, 1)
	must(err)
	if got != word || m.tces[9] != nil {
		t.Fatal("checkpoint lost TCE state")
	}
	must(m.WriteTCE(2, 1, 0))
	must(m.Restore(cp))
	got, err = m.ReadTCE(2, 1)
	must(err)
	if got != word {
		t.Fatal("checkpoint aliased mutable TCE entries")
	}
}

func TestTCEBatchAtomic(t *testing.T) {
	m := NewMachine(Config{Memory: 0x10000})
	if err := m.CreateTCETable(1, 4); err != nil {
		t.Fatal(err)
	}
	if err := m.WriteTCEs(1, 1, []uint64{0x3801, 0x4801}); err != nil {
		t.Fatal(err)
	}
	for _, b := range []struct {
		start uint64
		words []uint64
	}{
		{1, []uint64{0x5801, 0x10801}}, {3, []uint64{0x5801, 0x6801}}, {^uint64(0), []uint64{0x5801}},
	} {
		if m.WriteTCEs(1, b.start, b.words) == nil {
			t.Fatal("invalid batch accepted")
		}
		if a, _ := m.ReadTCE(1, 1); a != 0x3801 {
			t.Fatal("failed batch partially changed entries")
		}
	}
	if err := m.WriteTCEs(1, 1, []uint64{0, 0x6801}); err != nil {
		t.Fatal(err)
	}
	if a, _ := m.ReadTCE(1, 1); a != 0 {
		t.Fatal("batch invalidation failed")
	}
	if a, _ := m.ReadTCE(1, 2); a != 0x6801 {
		t.Fatal("batch mapping failed")
	}
}
