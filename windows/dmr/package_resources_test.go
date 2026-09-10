package dmr

import (
	"bytes"
	"testing"
)

func TestPackageResources(t *testing.T) {
	display, _ := EncodeLiteralResourceReference("Microsoft.UI.Xaml.CBS")
	publisher, _ := EncodeLiteralResourceReference("Microsoft Platform Extensions")
	description, _ := EncodeLiteralResourceReference("Microsoft.UI.Xaml")
	logo, _ := EncodeLiteralResourceReference(`C:\Windows\SystemApps\Microsoft.UI.Xaml.CBS_8wekyb3d8bbwe\logo.png`)
	for _, desc := range [][]byte{nil, description} {
		wire, err := EncodePackageResources(PackageResourceReferences{display, publisher, desc, logo})
		if err != nil {
			t.Fatal(err)
		}
		r, err := ParseResources(wire)
		if err != nil {
			t.Fatal(err)
		}
		ids := []uint16{1, 2, 4}
		if desc != nil {
			ids = []uint16{1, 2, 3, 4}
		}
		if r.Index != 0 || r.Application || len(r.Entries) != len(ids) {
			t.Fatalf("resources: %+v", r)
		}
		for i, id := range ids {
			kind := uint16(0)
			if id == 4 {
				kind = 1
			}
			if r.Entries[i].Value4 != id || r.Entries[i].Value6 != kind {
				t.Fatalf("entry: %+v", r.Entries[i])
			}
		}
		if !bytes.Equal(r.Entries[len(ids)-1].Data, logo) {
			t.Fatal("logo reference changed")
		}
	}
}

func TestPackageResourcesReferences(t *testing.T) {
	empty, _ := EncodeLiteralResourceReference("")
	index, _ := EncodeIndexResourceReference(123)
	wire, err := EncodePackageResources(PackageResourceReferences{index, empty, empty, index})
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseResources(wire)
	if err != nil || len(r.Entries) != 4 {
		t.Fatalf("empty description was omitted: %v", err)
	}
	for _, refs := range []PackageResourceReferences{
		{nil, empty, nil, empty}, {empty, nil, nil, empty}, {empty, empty, nil, nil},
		{empty, empty, []byte{}, empty}, {[]byte("ms-resource:Name"), empty, nil, empty},
	} {
		if _, err := EncodePackageResources(refs); err == nil {
			t.Fatal("accepted unresolved/invalid reference")
		}
	}
}
