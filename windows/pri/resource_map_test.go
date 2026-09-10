package pri

import "testing"

func resourceSection(tag string, p []byte) Section {
	n := (32 + len(p) + 8 + 7) &^ 7
	s := Section{Data: make([]byte, n)}
	copy(s.Type[:], tag)
	copy(s.Data, s.Type[:])
	le.PutUint32(s.Data[24:], uint32(n))
	copy(s.Data[32:], p)
	le.PutUint32(s.Data[n-8:], 0xdef5fade)
	le.PutUint32(s.Data[n-4:], uint32(n))
	return s
}

func mapFixture(largeValues bool) Section {
	// Two schema items at 5..6; one standard and one large item/range.
	w := 8
	if largeValues {
		w = 10
	}
	b := make([]byte, 32+8+4+4+4+36+3*w)
	le.PutUint16(b[4:], 2)
	le.PutUint16(b[8:], 1)
	le.PutUint16(b[10:], 1)
	le.PutUint16(b[12:], 1)
	le.PutUint16(b[14:], 1)
	le.PutUint16(b[16:], 1)
	if largeValues {
		le.PutUint16(b[18:], 1)
	}
	le.PutUint32(b[20:], 3)
	le.PutUint32(b[28:], 36)
	le.PutUint16(b[40:], 5)
	le.PutUint16(b[44:], 1)
	le.PutUint16(b[48:], 1)
	for _, off := range []int{52, 56, 60} {
		le.PutUint32(b[off:], 1)
	}
	le.PutUint32(b[64:], 6)
	le.PutUint32(b[68:], 1)
	le.PutUint32(b[72:], 1)
	le.PutUint32(b[76:], 1)
	le.PutUint16(b[80:], 2)
	le.PutUint32(b[84:], 1)
	return resourceSection(ResourceMap2Type, b)
}

func decisionsFixture() Section {
	// Decisions [], [set0], [set0,set0]; set0 has no qualifiers.
	b := make([]byte, 12+12+4+6)
	le.PutUint16(b[4:], 1)
	le.PutUint16(b[6:], 3)
	le.PutUint16(b[8:], 3)
	le.PutUint16(b[18:], 1)
	le.PutUint16(b[20:], 1)
	le.PutUint16(b[22:], 2)
	return resourceSection(DecisionsType, b)
}

func TestResourceMapCandidates(t *testing.T) {
	d, err := ParseDecisions(decisionsFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, large := range []bool{false, true} {
		m, err := ParseResourceMap(mapFixture(large))
		if err != nil {
			t.Fatal(err)
		}
		for index, want := range map[uint32]int{0: 0, 4: 0, 5: 1, 6: 2, 7: 0} {
			got, err := m.CandidateCount(index, d)
			if err != nil || got != want {
				t.Fatalf("%d: %d %v", index, got, err)
			}
		}
	}
}

func TestResourceMapMalformed(t *testing.T) {
	for _, off := range []int{0, 2, 18, 28, 44, 56, 82} {
		s := mapFixture(false)
		le.PutUint16(s.Data[32+off:], 0xffff)
		if _, err := ParseResourceMap(s); err == nil {
			t.Fatalf("accepted malformed map field %d", off)
		}
	}
	for _, off := range []int{4, 6, 8, 16, 28} {
		s := decisionsFixture()
		le.PutUint16(s.Data[32+off:], 0xffff)
		if _, err := ParseDecisions(s); err == nil {
			t.Fatalf("accepted malformed decision field %d", off)
		}
	}
	s := mapFixture(false)
	le.PutUint16(s.Data[32+80:], 99)
	m, err := ParseResourceMap(s)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := ParseDecisions(decisionsFixture())
	if _, err = m.CandidateCount(6, d); err == nil {
		t.Fatal("accepted bad decision")
	}
	s = mapFixture(false)
	le.PutUint32(s.Data[32+84:], 3)
	m, err = ParseResourceMap(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.CandidateCount(6, d); err == nil {
		t.Fatal("accepted candidate overflow")
	}
}
