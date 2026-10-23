package rfe

import (
	"context"
	"j5.nz/cc/hypervisor"
	"testing"
	"time"
)

func TestREPINSWritesMMIOExactlyOnceAndPreservesAccumulator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw, _ := newCPU(ctx)
	c := raw.(*cpu)
	defer c.Close()
	ram, _ := c.MapRAMRegions(1<<20, []hypervisor.RAMRegion{{Address: 0, Size: 0xa0000}, {Address: 0xc0000, Offset: 0xc0000, Size: 0x40000}})
	copy(ram[0x1000:], []byte{0xf3, 0x6c, 0xe6, 0xf2})
	c.core.PC = 0x1000
	c.core.Flags = 2
	c.core.R[0] = 0x1234
	c.core.R[1] = 2
	c.core.R[2] = 0x1f0
	c.system.Segments[0].Base = 0xa0000
	reads, writes := 0, 0
	ex, err := c.RunUntil(ctx, func(ex hypervisor.X86Exit) (bool, error) {
		if ex.Reason == hypervisor.X86ExitIO && ex.Port == 0x1f0 {
			reads++
			ex.Data[0] = byte(0x40 + reads)
			return true, nil
		}
		if ex.Reason == hypervisor.X86ExitMMIO {
			writes++
			if ex.Address != 0xa0000+uint64(writes-1) || ex.Data[0] != byte(0x40+writes) {
				t.Fatalf("MMIO %+v", ex)
			}
			return true, nil
		}
		return false, nil
	})
	if err != nil || ex.Port != 0xf2 || reads != 2 || writes != 2 || c.core.R[0] != 0x1234 || c.core.R[1] != 0 || c.core.R[7] != 2 {
		t.Fatalf("err %v exit%+v r%+v reads%d writes%d", err, ex, c.core.R, reads, writes)
	}
}
func TestREPOutsUsesSourceSegmentAddressWrapAndDF(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw, _ := newCPU(ctx)
	c := raw.(*cpu)
	defer c.Close()
	ram, _ := c.MapRAM(0, 1<<20)
	copy(ram[0x1000:], []byte{0x26, 0xf3, 0x6e, 0xe6, 0xf2})
	c.core.PC = 0x1000
	c.core.Flags = 2 | 1<<10
	c.core.R[1] = 2
	c.core.R[2] = 0x3c9
	c.core.R[6] = 0
	c.system.Segments[0].Base = 0x20000
	ram[0x20000], ram[0x2ffff] = 0x45, 0x67
	var out []byte
	ex, err := c.RunUntil(ctx, func(ex hypervisor.X86Exit) (bool, error) {
		if ex.Reason == hypervisor.X86ExitIO && ex.Port == 0x3c9 {
			out = append(out, ex.Data[0])
			return true, nil
		}
		return false, nil
	})
	if err != nil || ex.Port != 0xf2 || len(out) != 2 || out[0] != 0x45 || out[1] != 0x67 || c.core.R[6] != 0xfffe || c.core.R[1] != 0 {
		t.Fatalf("err%v exit%+v out%x r%+v", err, ex, out, c.core.R)
	}
}
