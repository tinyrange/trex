package windows

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func triageFixture() []byte {
	b := make([]byte, 0x3000)
	copy(b, "PAGEDU64")
	u32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
	u64 := func(off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }
	u32(0x30, 0x8664)
	u32(0xf98, 4)
	u64(0xfa0, uint64(len(b)))
	u32(0x2004, uint32(len(b)))
	u32(0x2008, 0x2ffc)
	copy(b[0x2ffc:], "TRGD")
	u32(0x200c, 0x348)
	u64(0x348+248, 0xfffff80000123456)
	u64(0x348+152, 0xffff900000001000)
	u32(0x2028, 0x2100)
	u32(0x202c, 16)
	u64(0x2048, 0xffff900000001000)
	copy(b[0x2100:], "saved stack data")
	u32(0x2030, 0x2200)
	u32(0x2034, 1)
	u32(0x2038, 0x2300)
	u32(0x203c, 0x100)
	u32(0x2200, 0x2300)
	u64(0x2238, 0xfffff80000000000)
	u32(0x2248, 0x200000)
	u32(0x2280, 123)
	u32(0x2288, 456)
	u32(0x2300, 12)
	for i, c := range "ntoskrnl.exe" {
		binary.LittleEndian.PutUint16(b[0x2304+i*2:], uint16(c))
	}
	u32(0x2078, 0x2400)
	u32(0x207c, 1)
	u64(0x2400, 0xffff900000002000)
	u32(0x2408, 0x2500)
	u32(0x240c, 4)
	copy(b[0x2500:], "data")
	return b
}

func readTriage(b []byte) (starlark.Value, error) {
	return kernelTriageDumpBuiltin(nil, nil, starlark.Tuple{&starfile.Bytes{Data: b}}, nil)
}
func TestKernelTriageDump(t *testing.T) {
	value, err := readTriage(triageFixture())
	if err != nil {
		t.Fatal(err)
	}
	record := value.(starlark.HasAttrs)
	attr := func(v starlark.Value, name string) starlark.Value {
		t.Helper()
		a, e := v.(starlark.HasAttrs).Attr(name)
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	if attr(record, "pc").String() != "18446735277617722454" {
		t.Fatalf("pc=%v", attr(record, "pc"))
	}
	stack := attr(record, "stack").(starfile.File)
	raw, err := starfile.ReadAll(stack)
	if err != nil || string(raw) != "saved stack data" {
		t.Fatalf("stack=%q %v", raw, err)
	}
	modules := attr(record, "modules").(*starlark.List)
	if modules.Len() != 1 || attr(modules.Index(0), "name") != starlark.String("ntoskrnl.exe") || attr(modules.Index(0), "timestamp").String() != "456" {
		t.Fatal(modules)
	}
	regions := attr(record, "regions").(*starlark.List)
	if regions.Len() != 2 {
		t.Fatal(regions)
	}
	raw, err = starfile.ReadAll(attr(regions.Index(1), "file").(starfile.File))
	if err != nil || string(raw) != "data" {
		t.Fatalf("region=%q %v", raw, err)
	}
}
func TestKernelTriageRejectsInvalidRanges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"machine", func(b []byte) { binary.LittleEndian.PutUint32(b[0x30:], 0x14c) }},
		{"type", func(b []byte) { binary.LittleEndian.PutUint32(b[0xf98:], 1) }},
		{"incomplete", func(b []byte) { b[0x2ffc] = 0 }},
		{"extent", func(b []byte) { binary.LittleEndian.PutUint64(b[0xfa0:], 0x4000) }},
		{"driver-count", func(b []byte) { binary.LittleEndian.PutUint32(b[0x2034:], 0xffffffff) }},
		{"driver-offset", func(b []byte) { binary.LittleEndian.PutUint32(b[0x2030:], 0xfffffff0) }},
		{"string-length", func(b []byte) { binary.LittleEndian.PutUint32(b[0x2300:], 0xffffffff) }},
		{"string-pool", func(b []byte) { binary.LittleEndian.PutUint32(b[0x2200:], 0x2500) }},
		{"string-terminator", func(b []byte) { b[0x2304+24] = 1 }},
		{"stack-overflow", func(b []byte) { binary.LittleEndian.PutUint64(b[0x2048:], ^uint64(0)-7) }},
		{"stack-extent", func(b []byte) { binary.LittleEndian.PutUint32(b[0x2028:], 0x2ff8) }},
		{"block-count", func(b []byte) { binary.LittleEndian.PutUint32(b[0x207c:], 0xffffffff) }},
		{"block-overflow", func(b []byte) { binary.LittleEndian.PutUint64(b[0x2400:], ^uint64(0)-1) }},
		{"block-extent", func(b []byte) { binary.LittleEndian.PutUint32(b[0x2408:], 0x3000) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := triageFixture()
			tc.mutate(b)
			if _, err := readTriage(b); err == nil {
				t.Fatal("accepted malformed dump")
			}
		})
	}
	for _, n := range []int{0, 8191, 8192, 8319} {
		if _, err := readTriage(make([]byte, n)); err == nil {
			t.Fatalf("accepted %d bytes", n)
		}
	}
}
