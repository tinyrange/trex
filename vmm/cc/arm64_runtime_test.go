package cc

import (
	"context"
	"testing"
)

type permissionCPU struct{ arm64ChannelCPU }

func (*permissionCPU) ProtectRAM(uint64, uint64, bool, bool, bool) error { return nil }

func TestARM64RuntimeDMAHonorsProtectionAndPermissionUpdates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &arm64Driver{cpu: &permissionCPU{}, ctx: ctx, base: 0x10000, ram: make([]byte, 0x10000), permissions: []arm64Permission{{address: 0x10000, size: 0x10000, read: true, write: true, execute: true}}}
	if err := d.Protect(0x14000, 0x4000, true, false, true); err != nil {
		t.Fatal(err)
	}
	for _, a := range []uint64{0x14000, 0x17fff} {
		if _, err := d.Memory(a, 1, true); err == nil {
			t.Fatal("protected DMA accepted")
		}
	}
	if _, err := d.Memory(0x13fff, 2, true); err == nil {
		t.Fatal("cross-boundary DMA accepted")
	}
	if _, err := d.Memory(0x14000, 4, false); err != nil {
		t.Fatal(err)
	}
	if err := d.Protect(0x15000, 0x1000, true, true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Memory(0x15000, 0x1000, true); err != nil {
		t.Fatal("permission update ignored", err)
	}
	if _, err := d.Memory(0x14fff, 2, true); err == nil {
		t.Fatal("partial protection lost")
	}
	cancel()
	if _, err := d.Memory(0x10000, 1, false); err == nil {
		t.Fatal("stale runtime access")
	}
}
