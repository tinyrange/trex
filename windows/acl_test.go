package windows

import (
	"bytes"
	"encoding/binary"
	"testing"

	"go.starlark.net/starlark"
)

func aclFixture() []byte {
	return []byte{2, 0, 32, 0, 1, 0, 0, 0,
		0, 0x12, 24, 0, 0x19, 0, 2, 0,
		1, 2, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0, 1, 0, 0, 0}
}

func TestParseACL(t *testing.T) {
	raw := aclFixture()
	revision, entries, err := ParseACL(raw)
	if err != nil || revision != 2 || len(entries) != 1 {
		t.Fatalf("parse: revision=%d entries=%v error=%v", revision, entries, err)
	}
	ace := entries[0]
	if ace.Type != 0 || ace.Flags != 0x12 || ace.Mask != 0x20019 || !bytes.Equal(ace.Data, raw[8:]) {
		t.Fatalf("wrong ACE: %+v", ace)
	}
	if principal, err := SIDString(ace.SID); err != nil || principal != "S-1-15-2-1" {
		t.Fatalf("principal=%q error=%v", principal, err)
	}
	for _, kind := range []byte{1, 2, 3, 0x11} {
		raw[8] = kind
		_, entries, err = ParseACL(raw)
		if err != nil || entries[0].Type != kind || entries[0].Mask != 0x20019 {
			t.Fatalf("simple ACE %d: entries=%v error=%v", kind, entries, err)
		}
	}
	_, opaque, err := ParseACL([]byte{4, 0, 12, 0, 1, 0, 0, 0, 0x42, 0, 4, 0})
	if err != nil || len(opaque) != 1 || opaque[0].SID != nil || len(opaque[0].Data) != 4 {
		t.Fatalf("opaque ACE: %v, %v", opaque, err)
	}
	// ACL allocation space is not another ACE and need not contain zeroes.
	if _, entries, err := ParseACL([]byte{2, 0, 12, 0, 0, 0, 0, 0, 1, 2, 3, 4}); err != nil || len(entries) != 0 {
		t.Fatalf("padded empty ACL: %v, %v", entries, err)
	}
}

func TestParseACLRejectsMalformedExtents(t *testing.T) {
	for name, change := range map[string]func([]byte) []byte{
		"short header":    func(b []byte) []byte { return b[:7] },
		"revision":        func(b []byte) []byte { b[0] = 1; return b },
		"size":            func(b []byte) []byte { b[2]--; return b },
		"count":           func(b []byte) []byte { b[4] = 9; return b },
		"zero ACE":        func(b []byte) []byte { b[10] = 0; return b },
		"unaligned ACE":   func(b []byte) []byte { b[10] = 23; return b },
		"oversized ACE":   func(b []byte) []byte { b[10] = 28; return b },
		"short principal": func(b []byte) []byte { b[10] = 12; return b },
		"SID revision":    func(b []byte) []byte { b[16] = 2; return b },
		"SID extent":      func(b []byte) []byte { b[17] = 3; return b },
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseACL(change(aclFixture())); err == nil {
				t.Fatal("accepted malformed ACL")
			}
		})
	}
}

func TestACLEntriesBuiltin(t *testing.T) {
	env := Builtins()
	env["fixture"] = starlark.Bytes(aclFixture())
	value, err := starlark.Eval(&starlark.Thread{Name: "acl"}, "acl.star", `acl_entries(fixture)["entries"][0]["mask"]`, env)
	if err != nil || value.String() != "131097" {
		t.Fatalf("builtin: value=%v error=%v", value, err)
	}
}

func FuzzParseACL(f *testing.F) {
	f.Add(aclFixture())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, entries, err := ParseACL(data)
		if err != nil {
			return
		}
		if len(entries) != int(binary.LittleEndian.Uint16(data[4:])) {
			t.Fatal("entry count changed")
		}
		for _, entry := range entries {
			if len(entry.Data) < 4 || len(entry.Data) > len(data)-8 {
				t.Fatal("entry escaped ACL bounds")
			}
		}
	})
}
