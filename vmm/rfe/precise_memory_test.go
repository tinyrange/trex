package rfe

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func TestPTEWriteRevokesOnlyDependentNativeMappings(t *testing.T) {
	c := jitCPU(t, 32, []byte{0xeb, 0xfe})
	c.system.CR[0], c.system.CR[3] = 0x80010011, 0x3000
	c.Write(0x3000, 4, 0x4067)
	for i := 0; i < 256; i++ {
		c.Write(0x4000+uint64(i)*4, 4, uint64(i*4096)|0x67)
	}
	c.Write(0x6000, 4, 0x11223344)
	c.Write(0x7000, 4, 0x55667788)
	c.Write(0xa000, 4, 0xaabbccdd)
	c.jit.NativeRefill(0x6000)
	c.jit.NativeRefill(0x7000)
	memory := c.jit.NativeContext().Memory
	if _, ok := memory.Lookup(6); !ok {
		t.Fatal("first mapping not warm")
	}
	if _, ok := memory.Lookup(7); !ok {
		t.Fatal("second mapping not warm")
	}
	// Unconsumed words on the same table page are ordinary native data.
	c.Write(0x4000+250*4, 4, 0xe0067)
	if _, ok := memory.Lookup(6); !ok {
		t.Fatal("unused PTE evicted unrelated mapping")
	}
	// A borrowed host write takes exactly the same physical coherence path.
	c.BeforeRAMWrite(0x4000+6*4, 4)
	binary.LittleEndian.PutUint32(c.ram[0x4000+6*4:], 0xa067)
	if _, ok := memory.Lookup(6); ok {
		t.Fatal("changed mapping retained")
	}
	if _, ok := memory.Lookup(7); !ok {
		t.Fatal("unrelated native mapping discarded")
	}
	if v, err := c.system.Read(0x6000, 4, false); err != nil || v != 0xaabbccdd {
		t.Fatal("stale PTE frame", v, err)
	}
	// A directory write must revoke ALL translations that consumed it.
	c.Write(0x3000, 4, 0)
	if _, ok := memory.Lookup(7); ok {
		t.Fatal("PDE change did not revoke child mapping")
	}
}
func TestNativeStoresOnCodeAndTablePagesStayNativeWhenBytesAreDisjoint(t *testing.T) {
	for _, table := range []bool{false, true} {
		code := []byte{0x40, 0x01, 0x07, 0x49, 0x75, 0xfa, 0xe6, 0xf2}
		actual, expected := jitCPU(t, 16, code), jitCPU(t, 16, code)
		for _, c := range []*cpu{actual, expected} {
			c.core.R[1] = 2048
			c.core.R[3] = 0x900
			c.system.Segments[3].Base = 0x5000
			if table {
				c.system.Segments[3].Base = 0x4000
				c.MarkPageTable(0x4100)
			}
		}
		referenceToPort(t, expected)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := actual.Run(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		equalJITState(t, actual, expected)
		stats := actual.jit.Stats()
		if stats["native_memory"] < 1800 || stats["memory_exits"] > 4 {
			t.Fatal("page-wide native barrier survived", table, stats)
		}
	}
}
