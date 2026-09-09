package cpu

import "testing"

func TestTrackedWritesAndMappingChanges(t *testing.T) {
	m := NewAddressSpace(0x10000)
	if err := m.Map(0, make([]byte, 0x4000), Read|Write); err != nil {
		t.Fatal(err)
	}
	m.TrackPageWrites(0x2008)
	v := m.TrackedWriteVersion()
	if err := m.WriteMemory(0x1000, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if m.TrackedWriteVersion() != v {
		t.Fatal("unrelated page invalidated dependencies")
	}
	if err := m.WriteMemory(0x1fff, []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	if m.TrackedWriteVersion() == v {
		t.Fatal("cross-page write missed tracked page")
	}
	v = m.TrackedWriteVersion()
	if _, err := m.Protect(0x2000, 4096, Read); err != nil {
		t.Fatal(err)
	}
	if m.TrackedWriteVersion() == v {
		t.Fatal("permission change did not invalidate dependencies")
	}
	v = m.TrackedWriteVersion()
	if err := m.WriteMemory(0x2000, []byte{3}); err == nil {
		t.Fatal("read-only write accepted")
	}
	if m.TrackedWriteVersion() != v {
		t.Fatal("failed write changed dependencies")
	}
	if err := m.Unmap(0); err != nil {
		t.Fatal(err)
	}
	if m.TrackedWriteVersion() == v {
		t.Fatal("unmap did not invalidate dependencies")
	}
}
