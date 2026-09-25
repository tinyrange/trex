package nsis

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"go.starlark.net/starlark"
)

func planList(t *testing.T, d *starlark.Dict, key string) *starlark.List {
	t.Helper()
	v, ok, err := d.Get(starlark.String(key))
	if err != nil || !ok {
		t.Fatalf("missing %s", key)
	}
	return v.(*starlark.List)
}

func TestArchiveBoundsDuplicatesAndPlan(t *testing.T) {
	// Make both later File instructions refer to the first stored member.
	metadata := metadataFixture()
	binary.LittleEndian.PutUint32(metadata[68+4*28+12:], 0)
	binary.LittleEndian.PutUint32(metadata[68+5*28+12:], 0)
	input := bytes.NewReader(fixture(t, metadata, false, 512))
	a, err := Open(input, Options{}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.names) != 3 || a.members[a.names[0]] != a.members[a.names[1]] {
		t.Fatal("duplicate data not preserved/shared")
	}
	if _, err := Open(input, Options{}, 2); !errors.Is(err, ErrLimit) {
		t.Fatalf("cumulative limit: %v", err)
	}
	a.Listing.Sections = []Section{{Flags: 1, Start: 0, Count: 6}}
	p, err := a.Plan(map[string]string{"<targetdir>": `C:\Apps`}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if planList(t, p, "unresolved").Len() != 1 || planList(t, p, "files").Len() != 0 {
		t.Fatal("control flow did not fail closed")
	}
	p, err = a.Plan(map[string]string{"<targetdir>": `C:\Apps`}, nil, []CodeRange{{3, 6}})
	if err != nil {
		t.Fatal(err)
	}
	if planList(t, p, "unresolved").Len() != 0 || planList(t, p, "files").Len() != 2 {
		t.Fatalf("plan %s", p)
	}
	v, _, _ := planList(t, p, "files").Index(0).(*starlark.Dict).Get(starlark.String("destination"))
	if v != starlark.String(`C:\Apps\bin\first.txt`) {
		t.Fatalf("destination %s", v)
	}
	a.Listing.Code[3] = Instruction{Opcode: 1}
	p, err = a.Plan(nil, nil, []CodeRange{{3, 6}})
	if err != nil || planList(t, p, "files").Len() != 0 {
		t.Fatal("Return did not end range")
	}
	if _, err := a.Plan(nil, nil, []CodeRange{{-1, 6}}); err == nil {
		t.Fatal("accepted invalid range")
	}
}

func TestPlanRegistryFailureStopsLaterWrites(t *testing.T) {
	a := &Archive{Listing: &Listing{strings: []byte("\x00key\x00name\x00invalid\x00")}}
	a.Listing.Code = []Instruction{
		{Opcode: 51, Operands: [6]int32{-2147483647, 1, 5, 10, 4}},
		{Opcode: 51, Operands: [6]int32{-2147483647, 1, 5, 10, 1}},
	}
	p, err := a.Plan(nil, nil, []CodeRange{{0, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if planList(t, p, "unresolved").Len() != 1 || planList(t, p, "registry_writes").Len() != 0 {
		t.Fatalf("not fail-closed: %s", p)
	}
	for _, invalid := range []string{`[:\bad`, `\\server\share`, `C:relative`, `\rooted`} {
		if _, err := guestPath(invalid, `C:\Apps`); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
}
