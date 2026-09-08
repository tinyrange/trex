package cpu

import (
	"bytes"
	"testing"
)

func TestPermissionCacheInvalidationAndSubpages(t *testing.T) {
	m := NewAddressSpace(16384)
	if err := m.Map(0x1000, bytes.Repeat([]byte{1}, 8192), Read|Write|Execute); err != nil {
		t.Fatal(err)
	}
	read := func(address uint64, n int, access Access, allowed bool) {
		t.Helper()
		out := bytes.Repeat([]byte{0xaa}, n)
		err := m.ReadMemory(address, out, access)
		if (err == nil) != allowed {
			t.Fatalf("address=%x n=%d access=%v: %v", address, n, access, err)
		}
		if err != nil && !bytes.Equal(out, bytes.Repeat([]byte{0xaa}, n)) {
			t.Fatal("fault changed destination")
		}
	}
	read(0x1000, 15, Execute, true)
	if _, err := m.Protect(0x1007, 3, Read); err != nil {
		t.Fatal(err)
	}
	read(0x1000, 7, Execute, true)
	read(0x1000, 8, Execute, false)
	read(0x1007, 3, Read, true)
	read(0x1007, 1, Execute, false)
	read(0x100a, 15, Execute, true)
	if _, err := m.Protect(0x1008, 1, Read|Execute); err != nil {
		t.Fatal(err)
	}
	read(0x1008, 1, Execute, true)
	read(0x1008, 2, Execute, false)
	if _, err := m.Protect(0x1000, 4096, Execute); err != nil {
		t.Fatal(err)
	}
	read(0x1007, 15, Execute, true)
	read(0x1007, 1, Read, false)
	read(0x1fff, 2, Execute, true)
	clone := m.Clone()
	if err := m.Unmap(0x1000); err != nil {
		t.Fatal(err)
	}
	read(0x1000, 1, Execute, false)
	if err := m.Map(0x1000, []byte{2}, Read); err != nil {
		t.Fatal(err)
	}
	read(0x1000, 1, Execute, false)
	read(0x1000, 1, Read, true)
	var b [1]byte
	if err := clone.ReadMemory(0x1000, b[:], Execute); err != nil || b[0] != 1 {
		t.Fatalf("clone cache aliased source: %v %v", b, err)
	}
}

func TestPermissionCacheSeesWrites(t *testing.T) {
	m := NewAddressSpace(16)
	if err := m.Map(0x1000, make([]byte, 16), Read|Write|Execute); err != nil {
		t.Fatal(err)
	}
	var out [1]byte
	if err := m.ReadMemory(0x1000, out[:], Execute); err != nil {
		t.Fatal(err)
	}
	if err := m.WriteMemory(0x1000, []byte{42}); err != nil {
		t.Fatal(err)
	}
	if err := m.ReadMemory(0x1000, out[:], Execute); err != nil || out[0] != 42 {
		t.Fatalf("stale bytes: %v %v", out, err)
	}
}
