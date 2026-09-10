package pri

import "testing"

func sectionFixture() Section {
	s := Section{Data: make([]byte, 48), Metadata: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	copy(s.Type[:], "[mrm_hschemaex] ")
	copy(s.Data, s.Type[:])
	copy(s.Data[16:20], s.Metadata[4:])
	copy(s.Data[20:24], s.Metadata[:4])
	le.PutUint32(s.Data[24:], 48)
	le.PutUint32(s.Data[40:], 0xdef5fade)
	le.PutUint32(s.Data[44:], 48)
	return s
}

func TestSectionPayload(t *testing.T) {
	s := sectionFixture()
	p, err := s.Payload()
	if err != nil || len(p) != 8 || cap(p) != 8 {
		t.Fatalf("payload: %x %v", p, err)
	}
	s.Data[32] = 42
	if p[0] != 42 {
		t.Fatal("payload copied")
	}
	for _, offset := range []int{0, 15, 16, 19, 20, 23, 24, 27, 40, 43, 44, 47} {
		bad := sectionFixture()
		bad.Data[offset] ^= 1
		if _, err := bad.Payload(); err == nil {
			t.Fatalf("accepted mutation %d", offset)
		}
	}
	for i := 0; i < len(s.Data); i++ {
		bad := s
		bad.Data = bad.Data[:i]
		if _, err := bad.Payload(); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
}
