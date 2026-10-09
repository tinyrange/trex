package cc

import (
	"bytes"
	"errors"
	"testing"

	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
)

type sleepFlushDevice struct {
	block.Device
	calls int
	err   error
}

func (d *sleepFlushDevice) Capabilities() block.Capabilities {
	c := d.Device.Capabilities()
	c.Flush = true
	return c
}
func (d *sleepFlushDevice) Flush() error { d.calls++; return d.err }

func TestIDESleepRequiresResetAndPreservesDisk(t *testing.T) {
	base := bytes.Repeat([]byte{0xa7}, 512*4)
	dev := &sleepFlushDevice{Device: testBlock(t, base)}
	level := false
	d := newIDE(vmm.Disk{Device: dev}, vmm.CHSGeometry{Cylinders: 1, Heads: 1, Sectors: 4}, func(_ uint32, v bool) error { level = v; return nil })
	call := func(ex hypervisor.X86Exit) {
		t.Helper()
		if err := d.io(ex); err != nil {
			t.Fatal(err)
		}
	}
	// A preceding IDENTIFY must not leave a phantom data transfer behind.
	call(ioByte(0x1f7, true, 0xec))
	call(ioByte(0x1f7, true, 0xe6))
	if !level || !d.sleeping || d.remaining != 0 || d.task[7] != 0x50 || dev.calls != 1 || len(d.failures) != 0 {
		t.Fatalf("sleep completion: task=%x irq=%v remaining=%d flush=%d failures=%v", d.task, level, d.remaining, dev.calls, d.failures)
	}
	call(ioByte(0x3f6, false, 0))
	if !level {
		t.Fatal("alternate status acknowledged sleep IRQ")
	}
	call(ioByte(0x1f7, false, 0))
	if level {
		t.Fatal("regular status failed to acknowledge sleep IRQ")
	}
	call(ioByte(0x1f7, true, 0xec))
	if level || !d.sleeping || d.identify || d.remaining != 0 {
		t.Fatal("command woke sleeping drive")
	}
	// Wake using the actual control-register software reset sequence.
	call(ioByte(0x3f6, true, 4))
	call(ioByte(0x3f6, true, 0))
	if d.sleeping || d.task[7] != 0x50 {
		t.Fatal("reset did not leave sleep")
	}
	call(ioByte(0x1f2, true, 1))
	call(ioByte(0x1f3, true, 0))
	call(ioByte(0x1f6, true, 0xe0))
	call(ioByte(0x1f7, true, 0x20))
	data := make([]byte, 512)
	call(hypervisor.X86Exit{Port: 0x1f0, Size: 2, Count: 256, Data: data})
	if !bytes.Equal(data, base[:512]) || d.task[7] != 0x50 {
		t.Fatal("disk bytes lost across sleep/reset")
	}
}

func TestIDESleepFlushFailureDoesNotEnterSleep(t *testing.T) {
	dev := &sleepFlushDevice{Device: testBlock(t, make([]byte, 2048)), err: errors.New("flush failed")}
	d := newIDE(vmm.Disk{Device: dev}, vmm.CHSGeometry{Cylinders: 1, Heads: 1, Sectors: 4}, func(uint32, bool) error { return nil })
	if err := d.command(0xe6); err != nil {
		t.Fatal(err)
	}
	if d.sleeping || d.task[7] != 0x51 || d.task[1] != 4 || len(d.failures) != 1 || d.failures[0].reason != "ATA cache flush: flush failed" {
		t.Fatalf("flush failure hidden by sleep: task=%x failures=%v", d.task, d.failures)
	}
	if err := d.command(0xec); err != nil {
		t.Fatal(err)
	}
	if !d.identify || d.task[7] != 0x58 {
		t.Fatal("failed sleep blocked later commands")
	}
}
