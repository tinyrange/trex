package uefi

import (
	"bytes"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestBulkMemoryOverlapFillAndFaults(t *testing.T) {
	m := machine(t, 0x14000000)
	defer m.Close()
	base := m.ramBase + 0x200000
	initial := make([]byte, 200000)
	for j := range initial {
		initial[j] = byte(j)
	}
	actual := make([]byte, len(initial))
	for _, size := range []int{0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 65, 4096, 65537} {
		for _, delta := range []int{-17, -1, 0, 1, 17, 100000} {
			if err := m.WriteVirtualMemory(base, initial); err != nil {
				t.Fatal(err)
			}
			expected := bytes.Clone(initial)
			copy(expected[32+delta:32+delta+size], expected[32:32+size])
			if err := m.CopyVirtualMemory(base+uint64(32+delta), base+32, uint64(size)); err != nil {
				t.Fatal(err)
			}
			if err := m.ReadVirtualMemory(base, actual); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(actual, expected) {
				t.Fatalf("copy size=%d delta=%d", size, delta)
			}
		}
		for _, value := range []byte{0, 0xa5} {
			if err := m.WriteVirtualMemory(base, initial); err != nil {
				t.Fatal(err)
			}
			if err := m.FillVirtualMemory(base+31, uint64(size), value); err != nil {
				t.Fatal(err)
			}
			if err := m.ReadVirtualMemory(base, actual); err != nil {
				t.Fatal(err)
			}
			expected := bytes.Clone(initial)
			for j := 31; j < 31+size; j++ {
				expected[j] = value
			}
			if !bytes.Equal(actual, expected) {
				t.Fatalf("fill size=%d value=%x", size, value)
			}
		}
	}
	if err := m.WriteVirtualMemory(base, initial); err != nil {
		t.Fatal(err)
	}
	if _, err := m.memory.Protect(base+4096, 4096, cpu.Read); err != nil {
		t.Fatal(err)
	}
	if err := m.FillVirtualMemory(base, 8192, 0); err == nil {
		t.Fatal("fill accepted read-only tail")
	}
	if err := m.CopyVirtualMemory(base, base+16384, 8192); err == nil {
		t.Fatal("copy accepted read-only tail")
	}
	if err := m.CopyVirtualMemory(base, 0xdead00000000, 16); err == nil {
		t.Fatal("copy accepted unmapped source")
	}
	if err := m.ReadVirtualMemory(base, actual); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, initial) {
		t.Fatal("failed preflight changed destination")
	}
}
