package cc

import "fmt"

type ideDMARegion struct{ address, size uint64 }

// The worker owns only a bounded host buffer and the storage read. All guest
// memory, task-file, bus-master, and IRQ changes belong to the CPU loop.
type ideDMARead struct {
	ready   chan struct{} // storage result published, before the CPU wake
	done    chan struct{} // worker and CPU wake have both finished
	regions []ideDMARegion
	data    []byte
	offset  int64
	n       int
	err     error
}

func (p *pc) startIDEDMARead(regions []ideDMARegion, offset int64, size int) {
	transfer := &ideDMARead{ready: make(chan struct{}), done: make(chan struct{}), regions: regions,
		data: make([]byte, size), offset: offset}
	p.dmaRead = transfer
	p.ide.task[7] = 0x80
	disk, cpu := p.ide.disk.Device, p.cpu
	go func() {
		defer close(transfer.done)
		transfer.n, transfer.err = disk.ReadAt(transfer.data, offset)
		// Publish readiness BEFORE waking the CPU. Otherwise the awakened
		// loop can see an unfinished transfer and reenter native execution,
		// delaying an already completed read until the next timer/slice.
		close(transfer.ready)
		// Cancel only wakes native execution; guest mutation stays on the
		// CPU loop. done also joins this wake before CPU teardown.
		if cpu != nil {
			_ = cpu.Cancel()
		}
	}()
}

func (p *pc) completeIDEDMARead(wait bool) error {
	transfer := p.dmaRead
	if transfer == nil {
		return nil
	}
	if !wait {
		select {
		case <-transfer.ready:
		default:
			return nil
		}
	}
	// Once storage is ready, join the nonblocking native cancellation too.
	// No storage wait is introduced into the poll path; the join prevents a
	// late Cancel from racing CPU close after this transfer is retired.
	<-transfer.done
	p.dmaRead = nil
	ata, bm := p.ide, p.pciIDE
	if transfer.err != nil || transfer.n != len(transfer.data) {
		ata.dmaError = fmt.Sprintf("block transfer at %#x: %d/%d bytes: %v",
			transfer.offset, transfer.n, len(transfer.data), transfer.err)
		ata.dmaPending = false
		bm.bm[2] = bm.bm[2]&^1 | 6
		return ata.fail(4)
	}
	offset := uint64(0)
	for _, region := range transfer.regions {
		buffer, err := p.memory(region.address, region.size)
		if err != nil {
			return err
		} // Validated before starting the worker.
		copy(buffer, transfer.data[offset:offset+region.size])
		offset += region.size
	}
	for ata.remaining > 0 {
		ata.advance()
	}
	ata.dmaPending = false
	ata.task[7] = 0x50
	bm.bm[2] = bm.bm[2]&^1 | 4
	return ata.signal(true)
}
