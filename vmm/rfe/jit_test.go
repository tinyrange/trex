package rfe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strconv"
	"testing"
	"time"

	"j5.nz/cc/hypervisor"
)

func jitCPU(t testing.TB, bits int, code []byte) *cpu {
	t.Helper()
	raw, err := newCPU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*cpu)
	t.Cleanup(func() { c.Close() })
	if _, err = c.MapRAM(0, 1<<20); err != nil {
		t.Fatal(err)
	}
	c.core.PC = 0x1000
	c.core.Flags = 2
	c.core.R[1] = 256
	c.core.R[3] = 0x200
	c.core.R[4] = 0x300
	if bits != 16 {
		c.system.CR[0] |= 1
		c.system.Segments[1].Flags |= 1 << 14
		c.system.Segments[2].Flags |= 1 << 14
	}
	if bits == 64 {
		c.system.EFER = 1 << 10
		c.system.Segments[1].Flags |= 1 << 13
		c.core.R[4] = 0x8300
	} else {
		c.system.Segments[1].Base = 0x4000
		c.system.Segments[2].Base = 0x8000
		c.system.Segments[3].Base = 0x6000
	}
	at := 0x1000
	if bits != 64 {
		at += 0x4000
	}
	copy(c.ram[at:], code)
	c.SetRAMWriteTracking(true)
	return c
}
func referenceToPort(t *testing.T, c *cpu) {
	t.Helper()
	for n := 0; n < 10000 && c.pending == nil; n++ {
		if err := c.core.Step(); err != nil {
			t.Fatal(err)
		}
	}
	if c.pending == nil {
		t.Fatal("reference did not reach port exit")
	}
}
func equalJITState(t *testing.T, got, want *cpu) {
	t.Helper()
	if got.core.R != want.core.R || got.core.PC != want.core.PC || got.core.Flags != want.core.Flags || got.core.Retired != want.core.Retired || got.system.TSC != want.system.TSC || !bytes.Equal(got.ram, want.ram) {
		t.Fatalf("JIT mismatch R=%x/%x pc=%x/%x flags=%x/%x retired=%d/%d TSC=%d/%d memory=%v", got.core.R, want.core.R, got.core.PC, want.core.PC, got.core.Flags, want.core.Flags, got.core.Retired, want.core.Retired, got.system.TSC, want.system.TSC, bytes.Equal(got.ram, want.ram))
	}
}
func TestJITLegacyAndLongModeRAMStackDifferential(t *testing.T) {
	cases := []struct {
		bits int
		code []byte
	}{
		{16, []byte{0x40, 0x01, 0x07, 0x50, 0x5a, 0x49, 0x75, 0xf8, 0xe6, 0xf2}},
		{32, []byte{0x40, 0x01, 0x03, 0x50, 0x5a, 0x49, 0x75, 0xf8, 0xe6, 0xf2}},
		{64, []byte{0x48, 0xff, 0xc0, 0x48, 0x01, 0x03, 0x50, 0x5a, 0x48, 0xff, 0xc9, 0x75, 0xf3, 0xe6, 0xf2}},
	}
	for _, test := range cases {
		t.Run(strconv.Itoa(test.bits), func(t *testing.T) {
			actual := jitCPU(t, test.bits, test.code)
			expected := jitCPU(t, test.bits, test.code)
			referenceToPort(t, expected)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := actual.Run(ctx); err != nil {
				t.Fatal(err)
			}
			equalJITState(t, actual, expected)
			stats := actual.jit.Stats()
			if stats["native"] == 0 || stats["native_memory"] == 0 || stats["compile_failures"] != 0 {
				t.Fatalf("did not execute native RAM/stack blocks: %v", stats)
			}
			t.Logf("%d-bit JIT: %v", test.bits, stats)
		})
	}
}
func TestJITSelfModificationAndSegmentCacheInvalidation(t *testing.T) {
	code := []byte{0x40, 0x49, 0x75, 0xfc, 0xe6, 0xf2}
	actual := jitCPU(t, 16, code)
	expected := jitCPU(t, 16, code)
	for pass := 0; pass < 3; pass++ {
		referenceToPort(t, expected)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := actual.Run(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		equalJITState(t, actual, expected)
		if actual.jit.Stats()["native16"] == 0 {
			t.Fatal("real-mode loop never compiled")
		}
		if pass == 2 {
			break
		}
		// Modify warmed executable bytes through the physical write barrier;
		// then change the hidden CS base while keeping the logical PC identical.
		for _, c := range []*cpu{actual, expected} {
			c.pending = nil
			c.core.PC = 0x1000
			c.core.R[1] = 256
			base := uint64(0x5000)
			if pass == 1 {
				base = 0x7000
				c.system.Segments[1].Base = 0x6000
				c.BeforeRAMWrite(base, uint64(len(code)))
				copy(c.ram[base:], code)
			}
			if err := c.Write(base, 1, 0x48); err != nil {
				t.Fatal(err)
			} // DEC AX, not stale INC
		}
	}
}

// Ensure callers cannot publish a native RAM descriptor over an unmapped tail.
func TestJITRAMResolverRejectsPartialPages(t *testing.T) {
	c := &cpu{a20: true, regions: []hypervisor.RAMRegion{{Address: 0x1000, Size: 0x1800}}}
	if _, ok := c.nativeOffset(0x2000, 1); ok {
		t.Fatal("partial device page admitted as RAM")
	}
	if off, ok := c.nativeOffset(0x1000, 1); !ok || off != 0 {
		t.Fatal(off, ok)
	}
	c.regions = []hypervisor.RAMRegion{{Address: 0x1000, Offset: 1, Size: 0x2000}}
	if _, ok := c.nativeOffset(0x1000, 1); ok {
		t.Fatal("unaligned backing could invalidate the wrong physical code page")
	}
}

func TestJITPreciseSegmentAndPagedWriteFaults(t *testing.T) {
	code := []byte{0x40, 0x01, 0x07, 0x49, 0x75, 0xfa, 0xe6, 0xf2}
	for _, paged := range []bool{false, true} {
		t.Run(strconv.FormatBool(paged), func(t *testing.T) {
			actual := jitCPU(t, 16, code)
			expected := jitCPU(t, 16, code)
			actual.system.CR[0] |= 1
			expected.system.CR[0] |= 1
			if paged {
				for _, c := range []*cpu{actual, expected} {
					binary.LittleEndian.PutUint32(c.ram[0x3000:], 0x4007)
					for page := 0; page < 256; page++ {
						binary.LittleEndian.PutUint32(c.ram[0x4000+page*4:], uint32(page*4096)|7)
					}
					c.system.CR[0] = 1 | 1<<16 | 1<<31
					c.system.CR[3] = 0x3000
				}
			}
			referenceToPort(t, expected)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, err := actual.Run(ctx)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			equalJITState(t, actual, expected)
			if actual.jit.Stats()["native_memory"] == 0 {
				t.Fatal("no native memory before permission change")
			}
			for _, c := range []*cpu{actual, expected} {
				c.pending = nil
				c.core.PC = 0x1000
				c.core.R[1] = 256
				if paged {
					// Revoke RW and Dirty through the physical alias of a PTE.
					if err := c.Write(0x4000+6*4, 4, 0x6001); err != nil {
						t.Fatal(err)
					}
				} else {
					c.system.CR[0] |= 1
					c.system.Segments[3].Limit = 0x1ff
				}
			}
			before := actual.core.Retired
			nativeBefore := actual.jit.Stats()["native"]
			for n := 0; n < 10; n++ {
				err = expected.core.Step()
				if err != nil {
					break
				}
			}
			if err == nil {
				t.Fatal("reference did not fault")
			}
			ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
			_, err = actual.Run(ctx)
			cancel()
			if err == nil {
				t.Fatal("JIT bypassed revoked access")
			}
			equalJITState(t, actual, expected)
			if actual.jit.Stats()["native"] != nativeBefore+1 {
				t.Fatal("fault did not preserve a genuinely native prefix")
			}
			if actual.core.Retired != before+1 || actual.core.PC != 0x1001 {
				t.Fatal("native prefix duplicated or fault PC lost")
			}
			if paged && (actual.system.CR[2] != 0x6200 || actual.system.FaultCount != expected.system.FaultCount) {
				t.Fatal("speculation polluted architectural page-fault state")
			}
		})
	}
}

func TestJITWarmedMMIOExitKeepsNativePrefix(t *testing.T) {
	code := []byte{0x40, 0x01, 0x07, 0x49, 0x75, 0xfa, 0xe6, 0xf2}
	actual := jitCPU(t, 16, code)
	expected := jitCPU(t, 16, code)
	for _, c := range []*cpu{actual, expected} {
		c.regions = []hypervisor.RAMRegion{{Address: 0, Size: 0xa0000}, {Address: 0xc0000, Offset: 0xc0000, Size: 0x40000}}
		binary.LittleEndian.PutUint32(c.ram[0x3000:], 0x4007)
		for page := 0; page < 256; page++ {
			binary.LittleEndian.PutUint32(c.ram[0x4000+page*4:], uint32(page*4096)|7)
		}
		c.system.CR[0] = 1 | 1<<31
		c.system.CR[3] = 0x3000
	}
	referenceToPort(t, expected)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_, err := actual.Run(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	equalJITState(t, actual, expected)
	for _, c := range []*cpu{actual, expected} {
		c.pending = nil
		c.core.PC = 0x1000
		c.core.R[1] = 1
		if err := c.Write(0x4000+6*4, 4, 0xa0067); err != nil {
			t.Fatal(err)
		}
	}
	beforeNative := actual.jit.Stats()["native"]
	before := actual.core.Retired
	if err = expected.core.Step(); err != nil {
		t.Fatal(err)
	}
	referenceErr := expected.core.Step()
	// Remapping changes data, not the warmed executable proof. Enter the same
	// compiled block and require its committed INC prefix before the MMIO exit.
	actual.operationIndex = 0
	err = actual.jit.Run(16)
	var got, want *memoryExit
	if !errors.As(err, &got) || !errors.As(referenceErr, &want) {
		t.Fatalf("MMIO exit got %v, reference %v", err, referenceErr)
	}
	if got.ex.Address != 0xa0200 || got.ex.Address != want.ex.Address || got.ex.Write || got.ex.Size != 2 {
		t.Fatalf("wrong MMIO request %+v", got.ex)
	}
	equalJITState(t, actual, expected)
	if actual.core.Retired != before+1 || actual.jit.Stats()["native"] != beforeNative+1 {
		t.Fatal("prefix was lost, interpreted or duplicated")
	}
}

func TestJITTrackedHostWriteRevokesWarmedCode(t *testing.T) {
	code := []byte{0x40, 0x49, 0x75, 0xfc, 0xe6, 0xf2}
	c := jitCPU(t, 16, code)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_, err := c.Run(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if c.jit.Stats()["native16"] == 0 {
		t.Fatal("code was not warmed")
	}
	c.pending = nil
	c.core.PC = 0x1000
	c.core.R[1] = 256
	c.BeforeRAMWrite(0x5000, 1)
	c.ram[0x5000] = 0x48 // host firmware/DMA overwrites INC with DEC
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	_, err = c.Run(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if c.core.R[0] != 0 || c.jit.Stats()["invalidations"] == 0 {
		t.Fatal("host-write barrier did not revoke old native code")
	}
}

func TestJITMixedCodeDataStackPageKeepsNativeCode(t *testing.T) {
	code := []byte{0x40, 0x01, 0x07, 0x50, 0x5a, 0x49, 0x75, 0xf8, 0xe6, 0xf2}
	actual := jitCPU(t, 16, code)
	expected := jitCPU(t, 16, code)
	for _, c := range []*cpu{actual, expected} {
		c.system.Segments[2].Base = 0x5000
		c.core.R[4] = 0x800
		c.system.Segments[3].Base = 0x5000
		c.core.R[3] = 0x900
	}
	referenceToPort(t, expected)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := actual.Run(ctx); err != nil {
		t.Fatal(err)
	}
	equalJITState(t, actual, expected)
	stats := actual.jit.Stats()
	if stats["native16"] < 500 || stats["invalidations"] > 10 {
		t.Fatalf("data writes discarded unchanged code on the same page: %v", stats)
	}
}

func TestJITRuntimeFSAndTaskSwitchedBitKeepWarmedCode(t *testing.T) {
	code := []byte{0x64, 0x8b, 0x03, 0x49, 0x75, 0xfa, 0xe6, 0xf2}
	c := jitCPU(t, 32, code)
	for page := uint64(6); page <= 7; page++ {
		if err := c.Write(page*4096+0x200, 4, page); err != nil {
			t.Fatal(err)
		}
	}
	blocks, invalidations := uint64(0), uint64(0)
	for pass := 0; pass < 3; pass++ {
		base := uint64(0x6000)
		if pass != 0 {
			base = 0x7000
		}
		c.system.Segments[4].Base = base
		c.system.FSBase = base
		if pass == 2 {
			c.system.CR[0] ^= 8
		} // TS affects x87 slow paths, not this block
		c.pending = nil
		c.core.PC = 0x1000
		c.core.R[1] = 256
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := c.Run(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if c.core.R[0] != base/4096 {
			t.Fatal("native FS used a stale segment base")
		}
		if pass == 0 {
			// The first OUT is deliberately not decoded until actual reuse.
			// Finish warming that exit before comparing translation identities.
			c.pending = nil
			c.core.PC = 0x1000
			c.core.R[1] = 256
			warm, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, err := c.Run(warm)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
		}
		stats := c.jit.Stats()
		if stats["native32"] == 0 {
			t.Fatal("code was never native")
		}
		if pass == 0 {
			blocks, invalidations = stats["blocks"], stats["invalidations"]
		} else if stats["blocks"] != blocks || stats["invalidations"] != invalidations {
			t.Fatalf("runtime FS/TS state unnecessarily discarded warmed native code: %v", stats)
		}
	}
}
