package uefi

import (
	"bytes"
	"testing"
)

func TestVariableEnumerationRetryAndRuntimeVisibility(t *testing.T) {
	m := machine(t, 0x14000000)
	for _, v := range []Variable{{Name: "A☃", GUID: loadedImageGUID, Attributes: 7, Data: []byte{1}}, {Name: "B", GUID: loadedImageGUID, Attributes: 2, Data: []byte{2}}, {Name: "C", GUID: loadedImageGUID, Attributes: 7, Data: []byte{3}}} {
		if err := m.SetVariable(v); err != nil {
			t.Fatal(err)
		}
	}
	size, name, identifier := ramBase+0x30000, ramBase+0x30100, ramBase+0x30200
	m.u64(size, 2)
	m.put(name, []byte{0, 0})
	m.put(identifier, bytes.Repeat([]byte{0xaa}, 16))
	args := [8]uint64{size, name, identifier}
	if status := m.getNextVariableName(args); status != bufferTooSmall {
		t.Fatal(status)
	}
	if m.read64(size) != 6 || !bytes.Equal(m.get(identifier, 16), bytes.Repeat([]byte{0xaa}, 16)) || m.text(name) != "" {
		t.Fatal("short-buffer call changed cursor")
	}
	m.u64(size, 64)
	if status := m.getNextVariableName(args); status != 0 || m.text(name) != "A☃" {
		t.Fatal(status, m.text(name))
	}
	m.u64(size, 64)
	if status := m.getNextVariableName(args); status != 0 || m.text(name) != "B" {
		t.Fatal(status, m.text(name))
	}
	// Begin again after ExitBootServices; boot-only B is no longer visible.
	m.exited = true
	m.u64(size, 64)
	m.put(name, []byte{0, 0})
	if status := m.getNextVariableName(args); status != 0 || m.text(name) != "A☃" {
		t.Fatal(status)
	}
	m.u64(size, 64)
	if status := m.getNextVariableName(args); status != 0 || m.text(name) != "C" {
		t.Fatal(status, m.text(name))
	}
	m.u64(size, 64)
	if status := m.getNextVariableName(args); status != notFound {
		t.Fatal(status)
	}
}
