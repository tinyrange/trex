package cc

import (
	"github.com/tinyrange/trex/vmm"
	"testing"
)

func TestMemoryLimits(t *testing.T) {
	for _, tc := range []struct {
		name, arch     string
		memory         int64
		uefi, rejected bool
	}{
		{"i386-low-RAM-ceiling", "i386", 3 << 30, false, false},
		{"i386-no-high-RAM", "i386", (3 << 30) + 4096, false, true},
		{"x64-high-RAM", "x86_64", 8 << 30, false, false},
		{"x64-bound", "x86_64", (8 << 30) + 4096, false, true},
		{"unaligned", "x86_64", (3 << 30) - 1, false, true},
		{"UEFI-ceiling", "x86_64", 2 << 30, true, false},
		{"UEFI-unchanged", "x86_64", (2 << 30) + 4096, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rejected := false
			for _, issue := range (&Backend{UEFI: tc.uefi}).Validate(vmm.Machine{Architecture: tc.arch, Memory: tc.memory}) {
				if issue.Field == "memory" {
					rejected = true
				}
			}
			if rejected != tc.rejected {
				t.Fatalf("memory rejection = %v, want %v", rejected, tc.rejected)
			}
		})
	}
}

func TestRAMOffsetAcrossPCIWindow(t *testing.T) {
	for _, tc := range []struct {
		address, size, offset uint64
		valid                 bool
	}{
		{0xbffff000, 4096, 0xbffff000, true},
		{0xbffff000, 4097, 0, false},
		{0xc0000000, 1, 0, false},
		{0xe0001000, 4, 0, false},
		{0xffffffff, 2, 0, false},
		{0x100000000, 4096, 0xc0000000, true},
		{0x23ffff000, 4096, 0x1fffff000, true},
		{0x23ffff000, 4097, 0, false},
		{0x240000000, 1, 0, false},
		{^uint64(0) - 1, 4, 0, false},
	} {
		got, err := ramOffset(8<<30, tc.address, tc.size)
		if (err == nil) != tc.valid || tc.valid && got != tc.offset {
			t.Fatalf("range %#x+%#x: offset %#x err %v", tc.address, tc.size, got, err)
		}
	}
	if _, err := ramOffset(2<<30, highRAMBase, 1); err == nil {
		t.Fatal("invented high RAM on a small machine")
	}
}
