package cc

import (
	"bytes"
	"testing"

	"j5.nz/cc/hypervisor"
)

type dmaWakeCPU struct {
	hypervisor.X86
	wake func()
}

func (c dmaWakeCPU) Cancel() error { c.wake(); return nil }

// Cancellation can return the native CPU to its polling loop before Cancel
// itself returns. That poll must observe a completed storage read, while the
// transfer must still retain the wake target until cancellation has finished.
func TestIDEAsyncReadPublishesBeforeWakeAndJoinsWake(t *testing.T) {
	p, data := dmaTestPC(t)
	held := holdDMA(t, p)
	woke := make(chan struct{})
	releaseWake := make(chan struct{})
	type observation struct{ ready, done, mutated bool }
	observed := make(chan observation, 1)
	p.cpu = dmaWakeCPU{wake: func() {
		tr := p.dmaRead
		o := observation{mutated: p.ide.pending || p.ram[0x20000] != 0}
		select {
		case <-tr.ready:
			o.ready = true
		default:
		}
		select {
		case <-tr.done:
			o.done = true
		default:
		}
		observed <- o
		close(woke)
		<-releaseWake
	}}
	// Always release cancellation before holdDMA's cleanup joins the worker.
	defer close(releaseWake)
	dmaPRD(p, 0, 0x20000, 512, true)
	dmaCommand(t, p, false, 1)
	dmaStart(t, p, false)
	awaitDMA(t, held.entered)
	tr := p.dmaRead
	held.unblock()
	awaitDMA(t, woke)
	o := <-observed
	if !o.ready || o.done || o.mutated {
		t.Fatalf("wake before result publication or premature retirement: %+v", o)
	}
	// The ready event publishes the complete payload, not just a notification.
	if tr.n != 512 || tr.err != nil || !bytes.Equal(tr.data, data[1024:1536]) {
		t.Fatal("wake did not publish the completed storage result")
	}
}
