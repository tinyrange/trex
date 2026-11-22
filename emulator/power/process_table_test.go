package power

import "testing"

func TestHashProcessRegistrationAndCheckpoint(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, CPUs: 2})
	if _, ok := m.HashProcessTable(); ok {
		t.Fatal("unexpected registration")
	}
	if err := m.SetHashedPageTable(2048); err != nil {
		t.Fatal(err)
	}
	if err := m.MapPage(0, 0, 0, 12, PTE{Real: 0x4000, Write: true, Execute: true}); err != nil {
		t.Fatal(err)
	}
	m.IdentitySegments = true
	const other = uint64(1) << 38
	for _, c := range m.CPUs {
		c.MSR |= MSRIR | MSRDR
		c.SPR[sprLPCR] = other | lpcrUPRT | lpcrHR | lpcrGTSE
	}
	before := m.Checkpoint()
	if err := m.RegisterHashProcessTable(0x1fffffe, 0, 4); err != nil {
		t.Fatal(err)
	}
	word, registered := m.HashProcessTable()
	if !registered || word != uint64(0x1fffffe)<<25|4 {
		t.Fatal(word, registered)
	}
	for _, c := range m.CPUs {
		if c.SPR[sprLPCR] != other || c.tlbGen == 0 {
			t.Fatal("registration did not update every hardware thread")
		}
		if real, err := c.Translate(0x123, false, accessWrite); err != nil || real != 0x4123 {
			t.Fatal("existing hash/SLB mapping lost", real, err)
		}
	}
	registeredState := m.Checkpoint()
	for _, args := range [][3]uint64{{1 << 38, 0, 4}, {1, 8, 4}, {1, 0, 25}} {
		if m.RegisterHashProcessTable(args[0], args[1], args[2]) == nil {
			t.Fatal("accepted malformed registration", args)
		}
		if got, ok := m.HashProcessTable(); !ok || got != word {
			t.Fatal("rejected registration mutated PATE")
		}
	}
	if err := m.RegisterHashProcessTable(0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if got, ok := m.HashProcessTable(); !ok || got != 0 {
		t.Fatal("zero registration confused with absent")
	}
	if err := m.Restore(registeredState); err != nil {
		t.Fatal(err)
	}
	if got, ok := m.HashProcessTable(); !ok || got != word {
		t.Fatal("registered PATE checkpoint")
	}
	if err := m.Restore(before); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.HashProcessTable(); ok {
		t.Fatal("absent PATE checkpoint")
	}
	if m.CPUs[1].SPR[sprLPCR] != other|lpcrUPRT|lpcrHR|lpcrGTSE {
		t.Fatal("LPCR checkpoint")
	}
}
