package cc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"j5.nz/cc/hypervisor"
)

type cpuExit struct {
	id   int
	exit hypervisor.X86Exit
	err  error
}

// cpuEpoch owns the cancellation lifetime shared by the current CPU runs.
// Replacing an epoch is allowed only after cancel-and-join in stop.
type cpuEpoch struct {
	context.Context
	cancel context.CancelFunc
}

func newCPUEpoch(parent context.Context) cpuEpoch {
	ctx, cancel := context.WithCancel(parent)
	return cpuEpoch{Context: ctx, cancel: cancel}
}

// loopSMP has one owner for all emulated devices. Workers execute only their
// own vCPU and retain borrowed exit data until the owner dispatches them again.
// Requests (including pause, capture and inspection) join every CPU first.
func (d *driver) loopSMP() {
	cpus := d.pc.cpus
	jobs := make([]chan context.Context, len(cpus))
	exits := make(chan cpuExit, len(cpus))
	var workers sync.WaitGroup
	for id, cpu := range cpus {
		jobs[id] = make(chan context.Context, 1)
		workers.Add(1)
		go func(id int, cpu hypervisor.X86) {
			defer workers.Done()
			for parent := range jobs[id] {
				ctx, cancel := context.WithTimeout(parent, 50*time.Millisecond)
				ex, err := cpu.Run(ctx)
				cancel()
				exits <- cpuExit{id, ex, err}
			}
		}(id, cpu)
	}
	defer func() {
		for _, job := range jobs {
			close(job)
		}
		workers.Wait()
	}()
	running := make([]bool, len(cpus))
	active := 0
	epoch := newCPUEpoch(d.ctx)
	defer func() { epoch.cancel() }()
	var failure error
	tripleFaultCPU := -1
	handle := func(result cpuExit) {
		running[result.id] = false
		active--
		if errors.Is(result.err, context.Canceled) || errors.Is(result.err, context.DeadlineExceeded) {
			return
		}
		if result.err != nil {
			if failure == nil {
				failure = fmt.Errorf("CPU%d: %w", result.id, result.err)
			}
			return
		}
		// Only the coordinator reads or changes pc.cpu. Public cancellation
		// uses the immutable cpus slice, not this temporary exit-owner view.
		d.pc.cpu = cpus[result.id]
		defer func() { d.pc.cpu = cpus[0] }()
		var err error
		switch result.exit.Reason {
		case 0:
		case hypervisor.X86ExitIO, hypervisor.X86ExitMMIO:
			var began time.Time
			stats := d.pc.performance
			if stats != nil {
				began = time.Now()
			}
			if result.exit.Reason == hypervisor.X86ExitIO {
				err = d.pc.handleIO(result.exit)
			} else {
				err = d.pc.handleMMIO(result.exit)
			}
			if stats != nil {
				address := result.exit.Address
				if result.exit.Reason == hypervisor.X86ExitIO {
					address = uint64(result.exit.Port)
				}
				stats.io(performanceIOKey(result.exit.Write, address, result.exit.Reason == hypervisor.X86ExitMMIO), time.Since(began))
				began = time.Now()
			}
			if err == nil {
				err = cpus[result.id].CompleteIO()
			}
			if stats != nil {
				stats.Completion.add(time.Since(began), 0)
			}
		case hypervisor.X86ExitShutdown:
			if failure == nil {
				tripleFaultCPU = result.id
			}
			err = fmt.Errorf("x86 triple fault")
		default:
			err = fmt.Errorf("unhandled x86 exit %d", result.exit.Reason)
		}
		if err != nil && failure == nil {
			failure = fmt.Errorf("CPU%d: %w", result.id, err)
		}
	}
	stop := func(pending ...cpuExit) {
		epoch.cancel()
		d.cancelCPUs()
		// Join before handling any pending exits, including machine-wide A20
		// remapping. No borrowed exit data is reused before its handler returns.
		for len(pending) < active {
			pending = append(pending, <-exits)
		}
		for _, result := range pending {
			handle(result)
		}
	}
	defer stop()
	finishFailure := func() {
		if tripleFaultCPU >= 0 {
			failure = fmt.Errorf("CPU%d: %s", tripleFaultCPU, d.pc.tripleFaultDetail(cpus[tripleFaultCPU]))
			tripleFaultCPU = -1
		}
		d.finish("guest_failure", failure.Error(), false)
	}
	start := func() {
		state, _ := d.Status(d.ctx)
		if !state.Running || failure != nil || d.ctx.Err() != nil {
			return
		}
		for id := range cpus {
			if !running[id] {
				jobs[id] <- epoch.Context
				running[id] = true
				active++
			}
		}
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if failure != nil || d.pc.acpi != nil && d.pc.acpi.poweroff {
			stop()
			if failure != nil {
				finishFailure()
			} else {
				d.finish("shutdown", "ACPI S5", true)
			}
		}
		start()
		// Storage readiness is an event, not a timer. Waiting for the 1ms
		// device poll adds a full serial latency to already-completed reads.
		var dmaReady <-chan struct{}
		if d.pc.dmaRead != nil {
			dmaReady = d.pc.dmaRead.ready
		}
		select {
		case <-dmaReady:
			if err := d.pc.completeIDEDMARead(false); err != nil && failure == nil {
				failure = err
			}
		case <-d.ctx.Done():
			stop()
			d.finish("closed", "", true)
			return
		case r := <-d.requests:
			stop()
			if failure != nil {
				finishFailure()
			}
			r.execute()
			epoch = newCPUEpoch(d.ctx)
		case result := <-exits:
			ex := result.exit
			if ex.Reason == hypervisor.X86ExitIO && ex.Write && (ex.Port == 0x92 || ex.Port == 0x60 || ex.Port == 0x64) {
				stop(result)
				epoch = newCPUEpoch(d.ctx)
			} else {
				handle(result)
			}
		case <-ticker.C:
			state, _ := d.Status(d.ctx)
			if state.Running {
				_, _, _, err := d.pc.pollDevices()
				if err != nil && failure == nil {
					failure = err
				}
			}
		}
	}
}

func (d *driver) cancelCPUs() {
	if len(d.pc.cpus) == 0 {
		_ = d.pc.cpu.Cancel()
		return
	}
	for _, cpu := range d.pc.cpus {
		_ = cpu.Cancel()
	}
}
