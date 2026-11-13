package cc

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"j5.nz/cc/hypervisor"
)

// A native run may remain in the host kernel while cancellation is pending.
// Its device owner must still service USB without sharing mutable device state
// with the CPU worker or depending on a guest I/O exit.
type usbCoordinatorCPU struct {
	hypervisor.X86
	entered, release chan struct{}
	once             sync.Once
	running          atomic.Bool
}

func (c *usbCoordinatorCPU) Run(ctx context.Context) (hypervisor.X86Exit, error) {
	c.running.Store(true)
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return hypervisor.X86Exit{}, ctx.Err()
}
func (c *usbCoordinatorCPU) RunUntil(ctx context.Context, _ func(hypervisor.X86Exit) (bool, error)) (hypervisor.X86Exit, error) {
	return c.Run(ctx)
}
func (c *usbCoordinatorCPU) Cancel() error { return nil }
func (c *usbCoordinatorCPU) Close() error  { return nil }

func TestSingleCPUUSBProgressDoesNotWaitForNativeExit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cpu := &usbCoordinatorCPU{entered: make(chan struct{}), release: make(chan struct{})}
	u, ram, _ := usbTestController()
	for n := 0; n < 1024; n++ {
		binary.LittleEndian.PutUint32(ram[n*4:], 1)
	}
	u.command = 1
	u.last = time.Now()
	progress := make(chan struct{})
	var once sync.Once
	memory := u.memory
	u.memory = func(a, n uint64) ([]byte, error) {
		if cpu.running.Load() {
			once.Do(func() { close(progress) })
		}
		return memory(a, n)
	}
	p := &pc{cpu: cpu, cpus: []hypervisor.X86{cpu}, now: time.Now, uhci: u}
	d := newDriver(ctx, p, false)
	defer func() { close(cpu.release); d.Close(context.Background()) }()
	select {
	case <-cpu.entered:
	case <-ctx.Done():
		t.Fatal("CPU did not enter native run")
	}
	select {
	case <-progress:
	case <-ctx.Done():
		t.Fatal("USB schedule waited for native CPU exit")
	}
}
