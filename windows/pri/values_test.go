package pri

import "testing"

func stringFixture(kind uint32, text []byte, external bool, large bool) (Section, []Section) {
	s := mapFixture(large)
	b := s.Data[32:]
	le.PutUint32(b[36:], kind) // type atom index
	w := 8
	if large {
		w = 10
	}
	v := b[88 : 88+w]
	v[0] = 1               // same-file data item
	le.PutUint32(v[4:], 0) // section 0, item 0
	if external {
		le.PutUint16(v[2:], 1)
	}
	p := make([]byte, 16+len(text))
	le.PutUint16(p[4:], 1)
	le.PutUint32(p[8:], uint32(len(text)))
	le.PutUint16(p[14:], uint16(len(text)))
	copy(p[16:], text)
	return s, []Section{resourceSection("[mrm_dataitem] \x00", p)}
}

func TestSingleString(t *testing.T) {
	d, err := ParseDecisions(decisionsFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, large := range []bool{false, true} {
		for _, tc := range []struct {
			kind uint32
			data []byte
			want string
			path bool
		}{
			{0, []byte{'A', 0, 0, 0}, "A", false},
			{1, []byte{'a', 0, 0, 0}, "a", true},
			{3, []byte("value\x00"), "value", false},
			{4, []byte("café\x00"), "café", false},
			{5, []byte("Assets/logo.png\x00"), "Assets/logo.png", true},
			{6, []byte("Assets/é.png\x00"), "Assets/é.png", true},
		} {
			s, sections := stringFixture(tc.kind, tc.data, false, large)
			m, e := ParseResourceMap(s)
			if e != nil {
				t.Fatal(e)
			}
			v, e := m.SingleString(5, d, sections)
			if e != nil || v == nil || v.Value != tc.want || v.Path != tc.path {
				t.Fatalf("large=%v kind=%d: %+v %v", large, tc.kind, v, e)
			}
			if v, e := m.SingleString(6, d, sections); e != nil || v != nil {
				t.Fatalf("multi-candidate reduced: %+v %v", v, e)
			}
			if _, e := m.SingleString(7, d, sections); e == nil {
				t.Fatal("missing resource reduced")
			}
		}
	}
}

func TestSingleStringRejectsMalformed(t *testing.T) {
	d, _ := ParseDecisions(decisionsFixture())
	for _, tc := range []struct {
		kind uint32
		data []byte
	}{
		{0, []byte{0, 0xd8, 0, 0}}, {0, []byte{0, 0xdc, 0, 0}}, {0, []byte{0}},
		{1, []byte{'a', 0}}, {3, []byte{0xff, 0}}, {4, []byte{0xff, 0}},
		{4, []byte("no terminator")}, {4, []byte("a\x00b\x00")}, {7, []byte{0}},
	} {
		s, sections := stringFixture(tc.kind, tc.data, false, false)
		m, e := ParseResourceMap(s)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = m.SingleString(5, d, sections); e == nil {
			t.Fatalf("accepted kind %d data %x", tc.kind, tc.data)
		}
	}
	s, sections := stringFixture(4, []byte("value\x00"), true, false)
	m, _ := ParseResourceMap(s)
	if _, err := m.SingleString(5, d, sections); err == nil {
		t.Fatal("accepted external PRI")
	}
	for _, mutate := range []func([]byte){
		func(p []byte) { le.PutUint32(p[8:], 0xffffffff) },
		func(p []byte) { le.PutUint16(p[12:], 100) },
		func(p []byte) { le.PutUint16(p[14:], 100) },
		func(p []byte) { le.PutUint32(p, 2) },
	} {
		s, sections = stringFixture(4, []byte("value\x00"), false, false)
		m, _ = ParseResourceMap(s)
		mutate(sections[0].Data[32:])
		if _, err := m.SingleString(5, d, sections); err == nil {
			t.Fatal("accepted malformed item")
		}
	}
}

func TestSoleQualifierMustHaveFallback(t *testing.T) {
	// One qualifier referencing one base, one set and one decision. References
	// 0 and 1 point to the set and qualifier respectively.
	for _, fallback := range []uint16{0, 500} {
		p := make([]byte, 44)
		for _, off := range []int{0, 2, 4, 6} {
			le.PutUint16(p[off:], 1)
		}
		le.PutUint16(p[8:], 2)
		le.PutUint16(p[14:], 1) // decision count
		le.PutUint16(p[16:], 1)
		le.PutUint16(p[18:], 1) // set first/count
		le.PutUint16(p[24:], fallback)
		d, err := ParseDecisions(resourceSection(DecisionsType, p))
		if err != nil {
			t.Fatal(err)
		}
		s, sections := stringFixture(4, []byte("value\x00"), false, false)
		le.PutUint16(s.Data[32+48:], 0) // resource decision 0
		m, err := ParseResourceMap(s)
		if err != nil {
			t.Fatal(err)
		}
		v, err := m.SingleString(5, d, sections)
		if err != nil || (v != nil) != (fallback != 0) {
			t.Fatalf("fallback=%d: %+v %v", fallback, v, err)
		}
	}
}

func TestLargeDataItemAndInternalValue(t *testing.T) {
	d, _ := ParseDecisions(decisionsFixture())
	s, _ := stringFixture(4, []byte("value\x00"), false, true)
	m, _ := ParseResourceMap(s)
	// Exercise the high item-index word and extended large-item count together.
	p := make([]byte, 12+8*65537+2)
	le.PutUint32(p, 0x10001)
	le.PutUint16(p[6:], 1)
	le.PutUint32(p[8:], 2)
	le.PutUint32(p[12+8*65536+4:], 2)
	copy(p[12+8*65537:], []byte{'x', 0})
	le.PutUint16(m.values[8:], 1)
	v, err := m.SingleString(5, d, []Section{resourceSection("[mrm_dataitem] \x00", p)})
	if err != nil || v == nil || v.Value != "x" {
		t.Fatalf("extended item: %+v %v", v, err)
	}
	m.values[0] = 0
	le.PutUint16(m.values[2:], 2)
	le.PutUint32(m.values[4:], 0)
	m.internal = []byte{'y', 0}
	v, err = m.SingleString(5, d, nil)
	if err != nil || v == nil || v.Value != "y" {
		t.Fatalf("internal: %+v %v", v, err)
	}
	le.PutUint32(m.values[4:], 0xffffffff)
	if _, err = m.SingleString(5, d, nil); err == nil {
		t.Fatal("internal out-of-bounds accepted")
	}
}
