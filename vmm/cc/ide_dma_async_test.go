package cc

import (
	"bytes"
	"errors"
	"github.com/tinyrange/trex/block"
	"sync"
	"testing"
	"time"
)

type heldDMADevice struct {
	block.Device
	entered     chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
	failure     error
	short       bool
}

func (d *heldDMADevice) unblock() { d.releaseOnce.Do(func() { close(d.release) }) }
func (d *heldDMADevice) ReadAt(b []byte, offset int64) (int, error) {
	d.once.Do(func() { close(d.entered) })
	<-d.release
	if d.failure != nil {
		return 0, d.failure
	}
	n, err := d.Device.ReadAt(b, offset)
	if d.short {
		return n - 1, nil
	}
	return n, err
}
func holdDMA(t *testing.T, p *pc) *heldDMADevice {
	t.Helper()
	d := &heldDMADevice{Device: p.ide.disk.Device, entered: make(chan struct{}), release: make(chan struct{})}
	p.ide.disk.Device = d
	p.asyncDMAReads = true
	t.Cleanup(func() { d.unblock(); _ = p.completeIDEDMARead(true) })
	return d
}
func awaitDMA(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("DMA worker did not reach bounded checkpoint")
	}
}

func TestIDEAsyncReadOwnershipAndCompletion(t *testing.T) {
	for _, mode := range []string{"success", "error", "short"} {
		t.Run(mode, func(t *testing.T) {
			p, data := dmaTestPC(t)
			held := holdDMA(t, p)
			if mode == "error" {
				held.failure = errors.New("injected storage read failure")
			}
			held.short = mode == "short"
			dmaPRD(p, 0, 0x2ff00, 256, false)
			dmaPRD(p, 1, 0x40020, 768, true)
			dmaCommand(t, p, false, 2)
			dmaStart(t, p, false)
			awaitDMA(t, held.entered)
			if p.dmaRead == nil || p.ide.status() != 0x80 || p.pciIDE.bm[2]&1 == 0 || p.ide.pending {
				t.Fatal("slow storage read did not leave DMA busy without an interrupt")
			}
			if err := p.completeIDEDMARead(false); err != nil {
				t.Fatal(err)
			}
			if p.dmaRead == nil || !bytes.Equal(p.ram[0x2ff00:0x30000], make([]byte, 256)) {
				t.Fatal("premature DMA publication")
			}
			// The captured descriptors, not subsequent guest writes, own this transfer.
			dmaPRD(p, 0, 0x50000, 256, false)
			held.unblock()
			awaitDMA(t, p.dmaRead.done)
			if p.ide.pending || p.ram[0x2ff00] != 0 {
				t.Fatal("worker mutated guest-visible state")
			}
			if err := p.completeIDEDMARead(true); err != nil {
				t.Fatal(err)
			}
			if p.dmaRead != nil || p.ide.dmaPending || !p.ide.pending {
				t.Fatal("missing CPU-loop completion")
			}
			if mode != "success" {
				if p.pciIDE.bm[2]&7 != 6 || p.ide.status()&1 == 0 || p.ram[0x2ff00] != 0 {
					t.Fatal("failed read partially published guest data")
				}
				return
			}
			if p.pciIDE.bm[2]&7 != 4 || p.ide.status() != 0x50 || p.ide.lba != 4 || p.ide.remaining != 0 {
				t.Fatal("bad successful completion")
			}
			if !bytes.Equal(p.ram[0x2ff00:0x30000], data[1024:1280]) || !bytes.Equal(p.ram[0x40020:0x40320], data[1280:2048]) || p.ram[0x50000] != 0 {
				t.Fatal("incorrect scatter transfer")
			}
		})
	}
}

func TestIDEAsyncReadResetJoinsTransfer(t *testing.T) {
	p, _ := dmaTestPC(t)
	held := holdDMA(t, p)
	dmaPRD(p, 0, 0x20000, 512, true)
	dmaCommand(t, p, false, 1)
	dmaStart(t, p, false)
	awaitDMA(t, held.entered)
	held.unblock()
	if err := p.ideIO(ioByte(0x3f6, true, 4)); err != nil {
		t.Fatal(err)
	}
	if err := p.ideIO(ioByte(0x3f6, true, 0)); err != nil {
		t.Fatal(err)
	}
	if p.dmaRead != nil || p.ide.dmaPending || p.ide.pending || p.ide.status() != 0x50 {
		t.Fatal("reset left stale DMA work")
	}
	if err := p.completeIDEDMARead(false); err != nil {
		t.Fatal(err)
	}
	if p.ide.pending {
		t.Fatal("late completion interrupted reset device")
	}
}
