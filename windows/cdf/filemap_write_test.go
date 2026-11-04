package cdf

import (
	"reflect"
	"testing"
)

func TestFileMapWriterNativeRoot(t *testing.T) {
	d, e := Parse(nativeRoot(t))
	if e != nil {
		t.Fatal(e)
	}
	m, e := d.FileMap()
	if e != nil {
		t.Fatal(e)
	}
	out, e := m.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := Parse(out)
	if e != nil {
		t.Fatal(e)
	}
	got, e := decoded.FileMap()
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(m, got) {
		t.Fatalf("logical root changed: %+v", got)
	}
	// Reproduce the independently observed native root-path normalization.
	m.Path = `\??\C:`
	m.RootSelector = 0
	out, e = m.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	decoded, e = Parse(out)
	if e != nil {
		t.Fatal(e)
	}
	got, e = decoded.FileMap()
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(m, got) {
		t.Fatal("root-path edit lost")
	}
}

func TestFileMapWriterCollisionsAndPruning(t *testing.T) {
	m := &FileMap{RootSelector: 1, Path: "System32", Identities: [][]IdentityAttribute{
		{{Name: "Name", Value: "unused"}}, {{Name: "Name", Value: "used"}},
	}, Entries: []FileMapEntry{
		{Name: "cmd.exe", DisplayName: "cmd.exe", Identity: 1},
		{Name: "dwm.exe", DisplayName: "dwm.exe", Identity: 1},
	}}
	out, e := m.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	d, e := Parse(out)
	if e != nil {
		t.Fatal(e)
	}
	got, e := d.FileMap()
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Identities) != 1 || got.Identities[0][0].Value != "used" || got.Entries[0].Identity != 0 || got.Entries[1].Identity != 0 {
		t.Fatal("identity pruning/remapping failed")
	}
	if got.Entries[0].Name != "cmd.exe" || got.Entries[1].Name != "dwm.exe" {
		t.Fatal("equal-hash key order changed")
	}
	m.Entries[1].Name = "CMD.EXE"
	m.Entries[1].DisplayName = "CMD.EXE"
	if _, e := m.Marshal(); e == nil {
		t.Fatal("accepted duplicate folded key")
	}
	m.Entries = nil
	if _, e := m.Marshal(); e == nil {
		t.Fatal("invented empty-map policy")
	}
}
