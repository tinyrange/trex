package memory

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestAMD64TranslationUsesEffectivePermissions(t *testing.T) {
	ram := make([]byte, 0x5000)
	const address = 0xffff800000001234
	for offset, entry := range map[int]uint64{
		0x1000 + 256*8: 0x2007,
		0x2000:         0x3005 | 1<<63,
		0x3000:         0x4003,
		0x3000 + 8:     0x200087,
		0x4000 + 8:     0x9007,
	} {
		binary.LittleEndian.PutUint64(ram[offset:], entry)
	}
	source := bytes.NewReader(ram)
	page, err := TranslateAMD64(source, 0x1000, address)
	if err != nil || page != (AMD64Translation{Physical: 0x9234, PageSize: 4096}) {
		t.Fatalf("4 KiB page %+v, %v", page, err)
	}
	large, err := TranslateAMD64(source, 0x1000, address+1<<21)
	if err != nil || large != (AMD64Translation{Physical: 0x201234, PageSize: 1 << 21, User: true}) {
		t.Fatalf("2 MiB page %+v, %v", large, err)
	}
	for _, test := range []struct {
		address     uint64
		kind, level string
	}{
		{address + 4096, "not-present", "pte"},
		{0x800000000000, "invalid-address", "virtual"},
	} {
		_, err := TranslateAMD64(source, 0x1000, test.address)
		var fault *Fault
		if !errors.As(err, &fault) || fault.Kind != test.kind || fault.Level != test.level {
			t.Fatalf("fault at %#x: %v", test.address, err)
		}
	}
}

func TestAMD64UserTablesAddSupervisorBranch(t *testing.T) {
	const base = 0x1000
	const vmemmap = 0xffffea0000000000
	root := make([]byte, 4096)
	mapping := AMD64Mapping{Virtual: vmemmap, Physical: 0x8000, Size: 8192, Writable: true}
	tables, err := AMD64UserPageTables(root, base, nil, mapping)
	if err != nil {
		t.Fatal(err)
	}
	ram := make([]byte, 0xa000)
	copy(ram[base:], tables)
	got, err := TranslateAMD64(bytes.NewReader(ram), base, vmemmap+4097)
	want := AMD64Translation{Physical: 0x9001, PageSize: 4096, Writable: true}
	if err != nil || got != want {
		t.Fatalf("supervisor translation = %+v, %v; want %+v", got, err, want)
	}
	entry := (vmemmap >> 39 & 511) * 8
	binary.LittleEndian.PutUint64(root[entry:], 0x6003)
	if _, err := AMD64UserPageTables(root, base, nil, mapping); err == nil {
		t.Fatal("replaced an existing supervisor PML4 branch")
	}
	if _, err := AMD64UserPageTables(root, base, []AMD64Mapping{mapping}); err == nil {
		t.Fatal("accepted a user mapping in the upper canonical half")
	}
}

func TestAMD64UserTablesPreserveSupervisorBranches(t *testing.T) {
	const base = 0x4000
	kernelRoot := make([]byte, 4096)
	binary.LittleEndian.PutUint64(kernelRoot, 0x2007)
	binary.LittleEndian.PutUint64(kernelRoot[511*8:], 0x1003)
	ram := make([]byte, 0xa000)
	binary.LittleEndian.PutUint64(ram[0x1000:], 0x83) // A 1 GiB kernel page.
	mappings := []AMD64UserMapping{
		{Virtual: 0x400000, Physical: 0x8000, Size: 4096, Execute: true},
		{Virtual: 0x401000, Physical: 0x9000, Size: 4096, Writable: true},
	}
	tables, err := AMD64UserPageTables(kernelRoot, base, mappings)
	if err != nil {
		t.Fatal(err)
	}
	copy(ram[base:], tables)
	for _, test := range []struct {
		address uint64
		want    AMD64Translation
	}{
		{0x400123, AMD64Translation{Physical: 0x8123, PageSize: 4096, User: true, Execute: true}},
		{0x401123, AMD64Translation{Physical: 0x9123, PageSize: 4096, User: true, Writable: true}},
		{0xffffff8000000123, AMD64Translation{Physical: 0x123, PageSize: 1 << 30, Writable: true, Execute: true}},
	} {
		got, err := TranslateAMD64(bytes.NewReader(ram), base, test.address)
		if err != nil || got != test.want {
			t.Fatalf("address %#x: %+v, %v, want %+v", test.address, got, err, test.want)
		}
	}
	if _, err := TranslateAMD64(bytes.NewReader(ram), base, 0); err == nil {
		t.Fatal("copied the kernel's lower-half identity mapping")
	}
	if _, err := AMD64UserPageTables(kernelRoot, base, append(mappings, mappings[0])); err == nil {
		t.Fatal("accepted overlapping virtual pages")
	}
	mappings[0].Physical = base + 4096
	if _, err := AMD64UserPageTables(kernelRoot, base, mappings); err == nil {
		t.Fatal("accepted a user alias for a table page")
	}
}
