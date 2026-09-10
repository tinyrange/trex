package dmr

import "testing"

func TestApplicationResourceReferences(t *testing.T) {
	empty, err := EncodeLiteralResourceReference("")
	if err != nil {
		t.Fatal(err)
	}
	index, err := EncodeIndexResourceReference(123)
	if err != nil {
		t.Fatal(err)
	}
	refs := ApplicationResourceReferences{DisplayName: index, Description: empty, Square150x150Logo: index, Square44x44Logo: empty}
	for _, withStartPage := range []bool{false, true} {
		if withStartPage {
			refs.StartPage = empty
		}
		b, err := EncodeApplicationResources(33, refs)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseResources(b)
		count := 4
		if withStartPage {
			count++
		}
		if err != nil || !got.Application || got.Index != 33 || len(got.Entries) != count {
			t.Fatalf("RESA: %+v %v", got, err)
		}
		for i, entry := range got.Entries {
			kind := uint16(0)
			if i >= 2 {
				kind = 1
			}
			if entry.Value4 != []uint16{1, 3, 4, 5, 6}[i] || entry.Value6 != kind {
				t.Fatalf("entry %d: %+v", i, entry)
			}
		}
	}
	for field := 0; field < 5; field++ {
		bad := refs
		p := []*[]byte{&bad.DisplayName, &bad.Description, &bad.Square150x150Logo, &bad.Square44x44Logo, &bad.StartPage}[field]
		*p = []byte{}
		if _, err := EncodeApplicationResources(0, bad); err == nil {
			t.Fatalf("accepted empty reference %d", field)
		}
	}
	refs.Description = nil
	if _, err := EncodeApplicationResources(0, refs); err == nil {
		t.Fatal("accepted omitted mandatory Description")
	}
	refs.Description = empty
	if _, err := EncodeApplicationResources(641, refs); err == nil {
		t.Fatal("accepted out-of-range RESA index")
	}
}
