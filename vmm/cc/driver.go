package cc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/png"
	"sync"
	"time"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/ramfb"
	"j5.nz/cc/hypervisor"
)

type request struct {
	ctx   context.Context
	run   func() error
	reply chan error
}

func (r request) execute() {
	if err := r.ctx.Err(); err != nil {
		r.reply <- err
		return
	}
	r.reply <- r.run()
}

type driver struct {
	pc             *pc
	ctx            context.Context
	cancel         context.CancelFunc
	requests       chan request
	events         chan vmm.Event
	ready          chan struct{}
	done, finished chan struct{}
	mu             sync.Mutex
	state          vmm.State
	result         *vmm.Result
	closeErr       error
	breakpointHit  bool // owned by the native CPU loop
}

func newDriver(ctx context.Context, p *pc, paused bool) *driver {
	ctx, cancel := context.WithCancel(ctx)
	d := &driver{pc: p, ctx: ctx, cancel: cancel, requests: make(chan request, 16), events: make(chan vmm.Event, 32), ready: make(chan struct{}, 1), done: make(chan struct{}), finished: make(chan struct{}), state: vmm.State{Name: "running", Running: !paused}}
	if paused {
		d.state.Name = "paused"
	}
	go d.loop()
	return d
}
func (d *driver) BackendID() string           { return "cc.v1" }
func (d *driver) Capabilities() []string      { return Capabilities() }
func (d *driver) DebugReady() <-chan struct{} { return d.ready }
func (d *driver) Status(context.Context) (vmm.State, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state, nil
}
func (d *driver) emit(kind string, payload any) {
	select {
	case d.events <- vmm.Event{Kind: kind, Timestamp: d.pc.now(), Backend: d.BackendID(), Payload: payload}:
		select {
		case d.ready <- struct{}{}:
		default:
		}
	default:
	}
}
func (d *driver) finish(reason, detail string, clean bool) {
	d.mu.Lock()
	if d.result != nil {
		d.mu.Unlock()
		return
	}
	r := vmm.Result{Reason: reason, Detail: detail, Clean: clean, Backend: d.BackendID(), Finished: d.pc.now()}
	d.result = &r
	d.state = vmm.State{Name: "stopped"}
	d.mu.Unlock()
	d.emit("exit", r)
	close(d.finished)
}
func (d *driver) loop() {
	defer close(d.done)
	defer close(d.events)
	defer func() { d.mu.Lock(); d.closeErr = d.pc.cpu.Close(); d.mu.Unlock() }()
	d.emit("started", nil)
	for {
		state, _ := d.Status(d.ctx)
		if !state.Running {
			select {
			case <-d.ctx.Done():
				d.finish("closed", "", true)
				return
			case r := <-d.requests:
				r.execute()
			}
			continue
		}
		select {
		case <-d.ctx.Done():
			d.finish("closed", "", true)
			return
		case r := <-d.requests:
			r.execute()
			continue
		default:
		}
		// Bound each native slice so a command cannot be lost in the small
		// interval between enqueueing it and entering KVM_RUN.
		ctx, cancel := context.WithTimeout(d.ctx, 10*time.Millisecond)
		ex, err := d.pc.run(ctx)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			continue
		}
		if err == nil {
			switch ex.Reason {
			case hypervisor.X86ExitDebug:
				d.breakpointHit = true
				d.mu.Lock()
				d.state = vmm.State{Name: "paused"}
				d.mu.Unlock()
				d.emit("paused", "breakpoint")
			case 0:
				continue
			case hypervisor.X86ExitIO:
				err = d.pc.handleIO(ex)
			case hypervisor.X86ExitMMIO:
				err = d.pc.vga.mmio(ex, d.pc.cpu)
			case hypervisor.X86ExitShutdown:
				d.finish("guest_failure", "x86 triple fault", false)
				continue
			default:
				err = fmt.Errorf("unhandled x86 exit %d", ex.Reason)
			}
		}
		if err != nil {
			d.finish("guest_failure", err.Error(), false)
		}
	}
}
func (d *driver) call(ctx context.Context, fn func() error) error {
	r := request{ctx: ctx, run: fn, reply: make(chan error, 1)}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.done:
		return &vmm.Error{Code: vmm.ErrorState, Message: "cc VM is closed"}
	case d.requests <- r:
	}
	_ = d.pc.cpu.Cancel()
	select {
	case err := <-r.reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-d.done:
		return &vmm.Error{Code: vmm.ErrorState, Message: "cc VM is closed"}
	}
}
func (d *driver) Pause(ctx context.Context) error {
	return d.call(ctx, func() error {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.result != nil {
			return &vmm.Error{Code: vmm.ErrorState, Message: "VM has stopped"}
		}
		d.state = vmm.State{Name: "paused"}
		d.emit("paused", nil)
		return nil
	})
}
func (d *driver) Resume(ctx context.Context) error {
	return d.call(ctx, func() error {
		if d.breakpointHit {
			r, err := d.pc.cpu.Registers()
			if err != nil {
				return err
			}
			r.Rflags |= 1 << 16 // RF suppresses the current execution breakpoint once
			if err := d.pc.cpu.SetRegisters(r); err != nil {
				return err
			}
			d.breakpointHit = false
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.result != nil {
			return &vmm.Error{Code: vmm.ErrorState, Message: "VM has stopped"}
		}
		d.state = vmm.State{Name: "running", Running: true}
		d.emit("resumed", nil)
		return nil
	})
}
func (d *driver) Stop(ctx context.Context) error {
	return d.call(ctx, func() error { d.finish("stopped", "", true); return nil })
}
func (d *driver) Reset(context.Context) error {
	return &vmm.Error{Code: vmm.ErrorUnsupported, Message: "cc reset is not implemented"}
}
func (d *driver) Powerdown(context.Context) error {
	return &vmm.Error{Code: vmm.ErrorUnsupported, Message: "the legacy PC has no ACPI power button"}
}
func (d *driver) Close(ctx context.Context) error {
	d.cancel()
	_ = d.pc.cpu.Cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.done:
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.closeErr
	}
}
func (d *driver) Wait(ctx context.Context) (vmm.Result, error) {
	select {
	case <-ctx.Done():
		return vmm.Result{}, ctx.Err()
	case <-d.finished:
		d.mu.Lock()
		defer d.mu.Unlock()
		return *d.result, nil
	}
}
func (d *driver) NextEvent(ctx context.Context) (vmm.Event, error) {
	consume := func(e vmm.Event) vmm.Event {
		select {
		case <-d.ready:
		default:
		}
		if len(d.events) != 0 {
			select {
			case d.ready <- struct{}{}:
			default:
			}
		}
		return e
	}
	select {
	case e, ok := <-d.events:
		if !ok {
			return vmm.Event{}, &vmm.Error{Code: vmm.ErrorState, Message: "VM closed"}
		}
		return consume(e), nil
	default:
	}
	select {
	case <-ctx.Done():
		return vmm.Event{}, ctx.Err()
	case e, ok := <-d.events:
		if !ok {
			return vmm.Event{}, &vmm.Error{Code: vmm.ErrorState, Message: "VM closed"}
		}
		return consume(e), nil
	}
}
func (d *driver) Capture(ctx context.Context) (*image.RGBA, error) {
	var frame *image.RGBA
	err := d.call(ctx, func() error { var err error; frame, err = d.pc.capture(); return err })
	return frame, err
}

func (d *driver) Screenshot(ctx context.Context, format string) (starfile.File, error) {
	if format != "png" {
		return nil, &vmm.Error{Code: vmm.ErrorUnsupported, Message: "cc screenshots require PNG"}
	}
	var result starfile.File
	err := d.call(ctx, func() error {
		img, err := d.pc.capture()
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		if err = png.Encode(&buf, img); err != nil {
			return err
		}
		result = &starfile.Bytes{Name: "cc-vga.png", Data: buf.Bytes()}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *pc) capture() (*image.RGBA, error) {
	frame, err := ramfb.Capture(p.framebuffer)
	if frame != nil || err != nil {
		return frame, err
	}
	return p.vga.screenshot()
}
