package cpu

import (
	"bytes"
	"math"
	"testing"
)

func TestCheckMemory(t *testing.T) {
	m := NewAddressSpace(16)
	if err := m.Map(0x1000, []byte{1, 2}, Read|Write); err != nil {
		t.Fatal(err)
	}
	if err := m.Map(0x1002, []byte{3, 4}, Read); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		address uint64
		size    int
		access  Access
		ok      bool
	}{
		{0x1000, 2, Write, true}, {0x1000, 4, Read, true},
		{0x1000, 3, Write, false}, {0x1004, 1, Read, false},
		{0x1000, -1, Read, false}, {0x1000, 1, 0, false},
		{0x1000, 1, Access(8), false}, {math.MaxUint64, 2, Read, false},
	} {
		if err := m.CheckMemory(test.address, test.size, test.access); (err == nil) != test.ok {
			t.Fatalf("check %+v: %v", test, err)
		}
	}
	var got [4]byte
	if err := m.ReadMemory(0x1000, got[:], Read); err != nil || got != [4]byte{1, 2, 3, 4} {
		t.Fatalf("probe changed data: %v %v", got, err)
	}
}

func TestMappingViewTracksPermissionsAndOwnership(t *testing.T) {
	m := NewAddressSpace(32)
	const base = 0x600000000
	if err := m.Map(base, make([]byte, 16), Read|Write); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Protect(base+4, 4, Read|Execute); err != nil {
		t.Fatal(err)
	}
	got := m.Mappings()
	want := []Mapping{{base, 4, base, Read | Write}, {base + 4, 4, base, Read | Execute}, {base + 8, 8, base, Read | Write}}
	if len(got) != len(want) {
		t.Fatalf("mapping view = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mapping %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	got[0].Size = 99
	if m.Mappings()[0].Size != 4 {
		t.Fatal("mapping view aliases internal state")
	}
	clone := m.Clone()
	if err := m.Unmap(base); err != nil {
		t.Fatal(err)
	}
	if len(m.Mappings()) != 0 || len(clone.Mappings()) != 3 {
		t.Fatal("free or snapshot mapping ownership is incorrect")
	}
}

func TestAddressSpaceHighAddressesAndAtomicAccess(t *testing.T) {
	m := NewAddressSpace(16)
	const base = 0x180000000
	input := []byte{1, 2, 3, 4}
	if err := m.Map(base, input, Read|Write); err != nil {
		t.Fatal(err)
	}
	input[0] = 99
	if err := m.Map(base+4, []byte{5, 6}, Read); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 6)
	if err := m.ReadMemory(base, got, Read); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("read = %x", got)
	}
	if err := m.WriteMemory(base+2, []byte{9, 9, 9}); err == nil {
		t.Fatal("write through read-only mapping succeeded")
	}
	if err := m.ReadMemory(base, got, Read); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("failed write changed memory: %x", got)
	}
	if err := m.ReadMemory(base+4, got, Read); err == nil {
		t.Fatal("read across gap succeeded")
	}
	if !bytes.Equal(got, []byte{1, 2, 3, 4, 5, 6}) {
		t.Fatal("failed read changed destination")
	}
	if err := m.ReadMemory(uint64(uint32(base&math.MaxUint32)), got[:1], Read); err == nil {
		t.Fatal("address truncated")
	}
	clone := m.Clone()
	if err := clone.WriteMemory(base, []byte{7}); err != nil {
		t.Fatal(err)
	}
	if err := m.ReadMemory(base, got[:1], Read); err != nil || got[0] != 1 {
		t.Fatalf("clone aliases original: %x, %v", got, err)
	}
}

func TestAddressSpaceBoundsAndPermissions(t *testing.T) {
	m := NewAddressSpace(3)
	if err := m.Map(math.MaxUint64, []byte{1, 2}, Read); err == nil {
		t.Fatal("overflow accepted")
	}
	if err := m.Map(math.MaxUint64, []byte{1}, Execute); err != nil {
		t.Fatal(err)
	}
	if err := m.Map(math.MaxUint64, []byte{1}, Execute); err == nil {
		t.Fatal("overlap accepted")
	}
	if err := m.Map(0, []byte{1, 2, 3}, Read); err == nil {
		t.Fatal("budget exceeded")
	}
	if err := m.ReadMemory(math.MaxUint64, make([]byte, 1), Read); err == nil {
		t.Fatal("execute-only read accepted")
	}
	if err := m.ReadMemory(math.MaxUint64, make([]byte, 1), Execute); err != nil {
		t.Fatal(err)
	}
	if err := m.ReadMemory(math.MaxUint64, make([]byte, 2), Execute); err == nil {
		t.Fatal("overflow read accepted")
	}
}

func TestProtectionOverlaysAndUnmap(t *testing.T) {
	m := NewAddressSpace(12)
	const base = 0x180000000
	for i := range 3 {
		if err := m.Map(base+uint64(i*4), []byte{1, 2, 3, 4}, Read|Write); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Protect(base+2, 8, Read); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Protect(base+3, 6, Read|Execute); err != nil {
		t.Fatal(err)
	}
	clone := m.Clone()
	previous, err := m.Protect(base+4, 4, 0)
	if err != nil || len(previous) != 1 || previous[0].Access != Read|Execute {
		t.Fatalf("prior permissions = %v, %v", previous, err)
	}
	buffer := bytes.Repeat([]byte{99}, 12)
	if err := m.ReadMemory(base, buffer, Read); err == nil || !bytes.Equal(buffer, bytes.Repeat([]byte{99}, 12)) {
		t.Fatal("denied read modified destination")
	}
	if err := clone.ReadMemory(base, buffer, Read); err != nil {
		t.Fatalf("protection changes leaked into clone: %v", err)
	}
	if err := m.Unmap(base + 5); err == nil {
		t.Fatal("partial unmap accepted")
	}
	if err := m.Unmap(base + 4); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Protect(base, 12, Read|Write); err == nil {
		t.Fatal("protection across an unmapped gap accepted")
	}
	if err := m.WriteMemory(base+2, []byte{9}); err == nil {
		t.Fatal("failed protection changed permissions")
	}
	if err := m.Map(base+4, []byte{5, 6, 7, 8}, Read|Write); err != nil {
		t.Fatalf("unmap did not release budget: %v", err)
	}
	if err := m.WriteMemory(base+4, []byte{9, 9, 9, 9}); err != nil {
		t.Fatalf("old protection survived unmap: %v", err)
	}
	for _, offset := range []uint64{3, 8} {
		if err := m.ReadMemory(base+offset, buffer[:1], Execute); err != nil {
			t.Fatalf("neighbor protection lost at %d: %v", offset, err)
		}
	}
}
