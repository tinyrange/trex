package uefi

import (
	"encoding/binary"
	"testing"
)

func TestConsoleCursorAndCheckpoint(t *testing.T) {
	m := machine(t, 0x14000000)
	console := m.ramBase + 0xd00
	call := func(name string, x, y uint64) uint64 { return m.textCall(name, [8]uint64{console, x, y}) }
	if call("Text.SetCursorPosition", 79, 24) != 0 {
		t.Fatal("set cursor")
	}
	text := m.ramBase + 0x200000
	m.put(text, []byte{'a', 0, 'b', 0, 0, 0})
	call("Text.OutputString", text, 0)
	mode := m.get(console+80, 24)
	if binary.LittleEndian.Uint32(mode[12:]) != 1 || binary.LittleEndian.Uint32(mode[16:]) != 24 {
		t.Fatalf("cursor=%x", mode)
	}
	checkpoint, err := m.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	call("Text.SetAttribute", 15, 0)
	call("Text.ClearScreen", 0, 0)
	if err := m.Restore(checkpoint); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(m.get(console+92, 4)) != 1 {
		t.Fatal("cursor not restored")
	}
	if call("Text.SetCursorPosition", 80, 0) != unsupported || call("Text.SetAttribute", 128, 0) != unsupported {
		t.Fatal("invalid mode state accepted")
	}
}
