package pri

import "testing"

func schemaFixture(extended bool) Section {
	tag, h := SchemaType, 8
	if extended {
		tag, h = ExtendedSchemaType, 24
	}
	names := namesFixture(extended, false)
	// Version, two identifiers ('A' and 'B'), then name tables.
	end := h + 20 + 8
	size := (32 + end + len(names) + 8 + 7) &^ 7
	s := Section{Data: make([]byte, size)}
	copy(s.Type[:], tag)
	copy(s.Data, s.Type[:])
	le.PutUint32(s.Data[24:], uint32(size))
	le.PutUint32(s.Data[size-8:], 0xdef5fade)
	le.PutUint32(s.Data[size-4:], uint32(size))
	p := s.Data[32:]
	le.PutUint16(p, 1)
	le.PutUint16(p[2:], 2)
	le.PutUint16(p[4:], 2)
	if extended {
		copy(p[8:], ExtendedNamesType)
	}
	le.PutUint16(p[h+20:], 'A')
	le.PutUint16(p[h+24:], 'B')
	copy(p[end:], names)
	return s
}

func TestSchema(t *testing.T) {
	for _, extended := range []bool{false, true} {
		s, err := ParseSchema(schemaFixture(extended))
		if err != nil {
			t.Fatal(err)
		}
		if s.Identifiers != [2]string{"A", "B"} || len(s.Versions) != 1 {
			t.Fatalf("schema: %+v", s)
		}
		name, err := s.Names.ItemName(0)
		if err != nil || name != "Files/logo.png" {
			t.Fatalf("name: %q %v", name, err)
		}
	}
}

func TestSchemaMalformed(t *testing.T) {
	for _, tc := range []struct {
		offset int
		value  uint16
	}{
		{32, 0}, {32, 65535}, {34, 1}, {34, 65535}, {36, 65535},
		{40, 0}, {32 + 24 + 20, 0xd800}, {32 + 24 + 22, 1},
	} {
		s := schemaFixture(true)
		le.PutUint16(s.Data[tc.offset:], tc.value)
		if _, err := ParseSchema(s); err == nil {
			t.Fatalf("accepted mutation %d", tc.offset)
		}
	}
}
