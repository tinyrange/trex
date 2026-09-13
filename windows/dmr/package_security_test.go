package dmr

import (
	"bytes"
	"testing"
)

func TestRepositorySecurity(t *testing.T) {
	packageSID := []byte{1, 1, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0}
	for _, inbox := range []bool{false, true} {
		for bit, rid := range []uint32{1, 2, 3, 7, 4, 5, 6, 9, 8, 10} {
			data, err := EncodeRepositorySecurity(0x110, packageSID, inbox, 1<<bit)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseSecurityContext(data)
			if err != nil || !bytes.Equal(got.PackageSID, packageSID) || len(got.Capabilities) != 1 {
				t.Fatalf("bit %d: %+v %v", bit, got, err)
			}
			want := []byte{1, 2, 0, 0, 0, 0, 0, 15, 3, 0, 0, 0, byte(rid), 0, 0, 0}
			if !bytes.Equal(got.Capabilities[0], want) || (got.Flags == 1) != inbox || got.Flags > 1 {
				t.Fatalf("bit %d inbox %v: %+v", bit, inbox, got)
			}
		}
	}
	data, err := EncodeRepositorySecurity(0x110, packageSID, true, ^uint32(0))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSecurityContext(data)
	if err != nil || len(got.Capabilities) != 10 {
		t.Fatalf("complete table: %+v %v", got, err)
	}
	for i, rid := range []uint32{1, 2, 3, 7, 4, 5, 6, 9, 8, 10} {
		if le.Uint32(got.Capabilities[i][12:]) != rid {
			t.Fatalf("capability order at %d", i)
		}
	}
	for _, flags := range []uint32{0x111, 0x112} {
		if b, err := EncodeRepositorySecurity(flags, nil, true, ^uint32(0)); err != nil || b != nil {
			t.Fatalf("framework/resource presence: %x %v", b, err)
		}
	}
	if _, err := EncodeRepositorySecurity(0x110, nil, false, 0); err == nil {
		t.Fatal("accepted missing package SID")
	}
	data, err = EncodeRepositorySecurity(0x110, packageSID, false, 0xfffffc00)
	if err != nil {
		t.Fatal(err)
	}
	got, err = ParseSecurityContext(data)
	if err != nil || len(got.Capabilities) != 0 || got.Flags != 0 {
		t.Fatalf("unmapped capability bits: %+v %v", got, err)
	}
}

func TestPackageSecurityPresence(t *testing.T) {
	for _, flags := range []uint32{1, 2, 3, 0x11, 0x12, 0x10011} {
		b, err := EncodePackageSecurity(flags, nil)
		if err != nil || b != nil {
			t.Fatalf("flags %#x: %x %v", flags, b, err)
		}
	}
	for _, flags := range []uint32{0, 0x10, 0x10010} {
		if _, err := EncodePackageSecurity(flags, nil); err == nil {
			t.Fatalf("flags %#x accepted missing context", flags)
		}
	}
	// S-1-15-2: binary SID validity is checked by the section codec, while
	// real package SID derivation/identity selection belongs to construction.
	context := SecurityContext{PackageSID: []byte{1, 1, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0}}
	b, err := EncodePackageSecurity(0x10, &context)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSecurityContext(b); err != nil {
		t.Fatal(err)
	}
	context.PackageSID = nil
	if _, err := EncodePackageSecurity(0x10, &context); err == nil {
		t.Fatal("accepted invalid security context")
	}
}
