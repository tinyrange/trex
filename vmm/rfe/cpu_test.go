package rfe

import (
	"context"
	"encoding/binary"
	"j5.nz/cc/hypervisor"
	"testing"
	"time"
)

func TestMMIOReadModifyWriteRetiresWithoutDuplicateDeviceAccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw, err := newCPU(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*cpu)
	defer c.Close()
	ram, err := c.MapRAMRegions(1<<20, []hypervisor.RAMRegion{{Address: 0, Size: 0xa0000}, {Address: 0xc0000, Offset: 0xc0000, Size: 0x40000}})
	if err != nil {
		t.Fatal(err)
	}
	copy(ram[0x1000:], []byte{0xb8, 0x34, 0x12, 0x87, 0x07, 0xe6, 0xf2})
	c.core.PC = 0x1000
	c.core.Flags = 2
	c.system.Segments[3].Base = 0xa0000
	reads, writes := 0, 0
	device := uint16(0xabcd)
	ex, err := c.RunUntil(ctx, func(ex hypervisor.X86Exit) (bool, error) {
		if ex.Reason != hypervisor.X86ExitMMIO {
			return false, nil
		}
		if ex.Address != 0xa0000 || ex.Size != 2 {
			t.Fatalf("MMIO %+v", ex)
		}
		if ex.Write {
			writes++
			device = binary.LittleEndian.Uint16(ex.Data)
		} else {
			reads++
			c.CompleteMMIORead(uint64(device), 2)
		}
		if reads > 1 || writes > 1 {
			t.Fatalf("repeated device side effect read=%d write=%d", reads, writes)
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if ex.Port != 0xf2 || reads != 1 || writes != 1 || device != 0x1234 || c.core.R[0] != 0xabcd {
		t.Fatalf("exit=%+v read=%d write=%d device=%x ax=%x", ex, reads, writes, device, c.core.R[0])
	}
}
