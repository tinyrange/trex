package cc

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
)

func arm64Capabilities() []string {
	return []string{"boot.arm64", "lifecycle.stop", "disk", "disk.snapshot", "channel", "platform.arm64", "extension.cc.v1"}
}

func (b *Backend) validateARM64(m vmm.Machine) []vmm.ValidationIssue {
	var issues []vmm.ValidationIssue
	add := func(field, message string) {
		issues = append(issues, vmm.ValidationIssue{Code: "unsupported", Field: field, Message: message, Backend: b.ID()})
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		add("backend", "ARM64 execution requires the native macOS ARM64 HVF backend")
	}
	if m.CPUs != 1 {
		add("cpus", "ARM64 firmware execution requires one CPU")
	}
	page := int64(os.Getpagesize())
	if m.Memory <= 0 || m.Memory%page != 0 || m.ARM64Boot != nil && m.ARM64Boot.MemoryBase%uint64(page) != 0 {
		add("memory", "HVF RAM must align to host pages")
	}
	if m.ARM64Boot == nil || m.Boot != nil || m.DarwinBoot != nil {
		add("boot", "ARM64 requires an explicit arm64_boot firmware handoff")
	} else if err := m.ARM64Boot.Validate(m.Memory); err != nil {
		add("boot", err.Error())
	}
	if b.ACPI || b.PCIIDE || b.PCIDisplay || b.HPET || b.UEFI || b.USB || b.PIOOnly || b.IDEModel != "" && b.IDEModel != "synthetic" {
		add("backend", "PC device options do not apply to ARM64")
	}
	if len(m.Networks) != 0 {
		add("networks", "ARM64 network attachments are not implemented")
	}
	if m.ARM64Platform == nil && (len(m.Disks) != 0 || len(m.Channels) != 0) {
		add("platform", "attachments require an explicit ARM64 platform")
	}
	seen := map[string]bool{}
	for _, c := range m.Channels {
		if c.Name == "" || c.Kind == "" || seen[c.Name] {
			add("channels", "channel names must be nonempty and unique")
		}
		seen[c.Name] = true
	}
	for _, disk := range m.Disks {
		if disk.Device == nil {
			add("disks", "missing block device")
			continue
		}
		if disk.ReadOnly && (disk.Snapshot || disk.Device.Capabilities().Writable) || !disk.ReadOnly && !disk.Snapshot && !disk.Device.Capabilities().Writable {
			add("disks", "disk requires matching writable backing or snapshot overlay")
		}
	}
	if m.Display.Mode != "none" && m.Display.Mode != "" {
		add("display", "ARM64 firmware profile is headless")
	}
	if m.StartPaused {
		add("start_paused", "ARM64 paused startup is not implemented")
	}
	for _, required := range m.RequiredCapabilities {
		found := false
		for _, c := range arm64Capabilities() {
			if c == required {
				found = true
			}
		}
		if !found {
			add("required_capabilities", "unsupported capability "+required)
		}
	}
	return issues
}

type arm64Driver struct {
	cpu             hypervisor.ARM64
	ram             []byte
	base            uint64
	ctx             context.Context
	cancel          context.CancelFunc
	done            chan struct{}
	events          chan vmm.Event
	ready           chan struct{}
	mu              sync.Mutex
	result          *vmm.Result
	closeErr        error
	device          vmm.ARM64Device
	machine         vmm.Machine
	guestChannels   map[string]channel.ByteChannel
	epoch           uint64
	permissions     []arm64Permission
	channels        map[string]channel.ByteChannel
	registers       map[string]any
	resourcesClosed bool
}

// arm64Channel keeps portable channel operations independent of the native
// execution loop. Reads also wake it: draining a full host buffer can complete
// a guest transmit request that was left pending by the USB device.
type arm64Channel struct {
	stream *channel.Memory
	wake   func()
	close  sync.Once
}

func (c *arm64Channel) Read(p []byte) (int, error) {
	n, err := c.stream.Read(p)
	if n != 0 {
		c.wake()
	}
	return n, err
}
func (c *arm64Channel) Write(p []byte) (int, error) {
	n, err := c.stream.Write(p)
	if n != 0 {
		c.wake()
	}
	return n, err
}
func (c *arm64Channel) ReadAvailable(p []byte) (int, error)  { return c.Read(p) }
func (c *arm64Channel) WriteAvailable(p []byte) (int, error) { return c.Write(p) }
func (c *arm64Channel) Close() error {
	closed := false
	c.close.Do(func() {
		_ = c.stream.Close()
		closed = true
	})
	// Do not hold Once while waking: VM shutdown closes this endpoint while
	// holding the driver lock that also guards native cancellation.
	if closed {
		c.wake()
	}
	return nil
}

func (d *arm64Driver) wake() {
	select {
	case <-d.done:
		return
	default:
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.done:
		return
	default:
	}
	if !d.resourcesClosed {
		// HVF retains an exit requested before Run, so a channel operation
		// between polling and entering the guest cannot lose its wakeup.
		// IO has already happened; a cancellation failure must not turn it
		// into a retryable channel error that duplicates or discards bytes.
		_ = d.cpu.Cancel()
	}
}

func (b *Backend) startARM64(ctx context.Context, m vmm.Machine) (vmm.Driver, error) {
	config := hypervisor.ARM64Configuration{PrivateAppleISA: b.PrivateAppleISA}
	if m.ARM64Platform != nil {
		config.GICDistributor = m.ARM64Platform.GICDistributor
		config.GICRedistributor = m.ARM64Platform.GICRedistributor
	}
	cpu, err := hypervisor.NewARM64WithConfiguration(ctx, config)
	if err != nil {
		return nil, err
	}
	ok := false
	var d *arm64Driver
	defer func() {
		if !ok {
			if d == nil {
				_ = cpu.Close()
			} else {
				d.abortStart()
			}
		}
	}()
	boot := m.ARM64Boot
	ram, err := cpu.MapRAM(boot.MemoryBase, uint64(m.Memory))
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(io.NewSectionReader(boot.Image, 0, boot.Image.Size()), ram[boot.Address-boot.MemoryBase:boot.Address-boot.MemoryBase+uint64(boot.Image.Size())]); err != nil {
		return nil, err
	}
	for _, l := range boot.Loads {
		if _, err := io.ReadFull(io.NewSectionReader(l.Image, 0, l.Image.Size()), ram[l.Address-boot.MemoryBase:l.Address-boot.MemoryBase+uint64(l.Image.Size())]); err != nil {
			return nil, fmt.Errorf("load ARM64 payload: %w", err)
		}
	}
	state := hypervisor.ARM64State{PC: boot.Entry, PState: 0x3c5, X: boot.X, System: boot.System}
	if err := cpu.Restore(state); err != nil {
		return nil, err
	}
	if err := cpu.SetDebugExceptionTrapping(true); err != nil {
		return nil, err
	}
	limit := b.RunTimeout
	if limit == 0 {
		limit = 30 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, limit)
	d = &arm64Driver{cpu: cpu, ram: ram, base: boot.MemoryBase, ctx: runCtx, cancel: cancel, done: make(chan struct{}), events: make(chan vmm.Event, 32), ready: make(chan struct{}, 1)}
	d.machine = m
	d.epoch = uint64(time.Now().UnixMicro())
	d.permissions = []arm64Permission{{address: boot.MemoryBase, size: uint64(m.Memory), read: true, write: true, execute: true}}
	d.channels = make(map[string]channel.ByteChannel)
	d.guestChannels = make(map[string]channel.ByteChannel)
	for _, c := range m.Channels {
		host, guest, err := channel.NewMemoryPair(4 << 20)
		if err != nil {
			return nil, err
		}
		d.channels[c.Name] = &arm64Channel{stream: host, wake: d.wake}
		d.guestChannels[c.Name] = guest
	}
	if m.ARM64Platform != nil && m.ARM64Platform.New != nil {
		d.device, err = m.ARM64Platform.New(d)
		if err != nil {
			return nil, err
		}
	}
	ok = true
	go d.loop()
	return d, nil
}
func (d *arm64Driver) BackendID() string           { return "cc.v1" }
func (d *arm64Driver) Capabilities() []string      { return arm64Capabilities() }
func (d *arm64Driver) DebugReady() <-chan struct{} { return d.ready }
func (d *arm64Driver) emit(kind string, payload any) {
	e := vmm.Event{Kind: kind, Payload: payload, Backend: d.BackendID(), Timestamp: time.Now()}
	for {
		select {
		case d.events <- e:
			select {
			case d.ready <- struct{}{}:
			default:
			}
			return
		default:
			if kind != "arm64.stop" && kind != "serial" && kind != "exit" {
				return
			}
			// Preserve final stop evidence even if intermediate device events
			// filled the bounded queue before the caller started draining it.
			select {
			case <-d.events:
			default:
			}
		}
	}
}
func (d *arm64Driver) closeDevices() {
	if c, ok := d.device.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	for _, c := range d.guestChannels {
		_ = c.Close()
	}
}

// abortStart owns resources only until loop takes over their lifetime.
func (d *arm64Driver) abortStart() {
	d.cancel()
	d.closeDevices()
	close(d.done)
	_ = d.closeResources()
}

// closeResources is called after done, when no device can access RAM again.
func (d *arm64Driver) closeResources() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.resourcesClosed {
		for _, c := range d.channels {
			_ = c.Close()
		}
		d.closeErr = d.cpu.Close()
		d.resourcesClosed = true
		d.ram = nil
	}
	return d.closeErr
}

func (d *arm64Driver) loop() {
	defer close(d.done)
	defer close(d.events)
	defer d.cancel()
	defer d.closeDevices()
	d.emit("started", nil)
	reason, detail, clean := "guest_failure", "", false
	var ex hypervisor.Exit
	for {
		var err error
		if p, ok := d.device.(interface{ Poll() error }); ok {
			if err = p.Poll(); err != nil {
				detail = err.Error()
				break
			}
		}
		ex, err = d.cpu.Run(d.ctx)
		if d.ctx.Err() != nil {
			reason = "timeout"
			if d.ctx.Err() == context.Canceled {
				reason = "closed"
				clean = true
			}
			detail = d.ctx.Err().Error()
			break
		}
		if err != nil {
			detail = err.Error()
			break
		}
		if ex.Reason == hypervisor.ExitException && ex.Syndrome>>26 == 0x18 {
			handled, err := d.cpu.HandleSystemInstruction(ex.Syndrome)
			if err != nil {
				detail = err.Error()
				break
			}
			if handled {
				continue
			}
		}
		// Native interrupt injection wakes hv_vcpu_run with a canceled exit.
		// The run context controls termination; a wake alone is not a stop.
		if ex.Reason == hypervisor.ExitCanceled {
			continue
		}
		if ex.Reason == hypervisor.ExitException && ex.Syndrome>>26 == 0x16 {
			function, regErr := d.cpu.Register(0)
			if regErr != nil {
				detail = regErr.Error()
				break
			}
			if h, ok := d.device.(vmm.ARM64HypercallHandler); ok {
				handled, err := h.HVC(uint16(ex.Syndrome), function)
				if err != nil {
					detail = err.Error()
					break
				}
				if handled {
					continue
				}
			}
			if ex.Syndrome&0xffff == 0 && (function>>24 == 0x84 || function>>24 == 0xc4 || function == 0x80000000 || function == 0x80000001) {
				stop, callErr := d.cpu.HandlePSCI()
				if callErr != nil {
					detail = callErr.Error()
					break
				}
				if stop {
					reason, detail, clean = "shutdown", "guest PSCI power request", true
					break
				}
				continue
			}
		}
		if d.device != nil && ex.Reason == hypervisor.ExitException && ex.Syndrome>>26 == 0x24 {
			var handled bool
			var err error
			if ex.Syndrome&(1<<24) == 0 {
				word, fetchErr := d.readARM64Instruction(ex.PC)
				if fetchErr != nil {
					detail = fetchErr.Error()
					break
				}
				handled, err = d.cpu.EmulateMMIOInstruction(ex, word, d.device)
			} else {
				handled, err = d.cpu.EmulateMMIO(ex, d.device)
			}
			if err != nil {
				detail = err.Error()
				break
			}
			if handled {
				continue
			}
		}
		detail = fmt.Sprintf("unsupported ARM64 exit reason=%d pc=%#x esr=%#x va=%#x pa=%#x", ex.Reason, ex.PC, ex.Syndrome, ex.VirtualAddress, ex.PhysicalAddress)
		break
	}
	// Cancellation may occur inside a platform callback or device poll,
	// rather than inside Run. Preserve the same lifecycle stop classification.
	if err := d.ctx.Err(); err != nil {
		reason, detail = "timeout", err.Error()
		if err == context.Canceled {
			reason, clean = "closed", true
		}
	}
	pc, _ := d.cpu.Register(hypervisor.RegisterPC)
	registers := map[string]any{"pc": pc, "esr": ex.Syndrome, "virtual_address": ex.VirtualAddress, "physical_address": ex.PhysicalAddress}
	if pstate, err := d.cpu.Register(hypervisor.RegisterPState); err == nil {
		registers["pstate"] = pstate
	}
	if state, err := d.cpu.InterruptState(); err == nil {
		interrupts := make(map[string]any, len(state))
		for name, value := range state {
			interrupts[name] = value
		}
		registers["interrupts"] = interrupts
	}
	for i := uint32(0); i < 31; i++ {
		v, err := d.cpu.Register(i)
		if err == nil {
			registers[fmt.Sprintf("x%d", i)] = v
		}
	}
	for name, reg := range map[string]uint16{"esr_el2": 0xe290, "elr_el2": 0xe201, "hcr_el2": 0xe088, "vbar_el2": 0xe600, "sp": 0xc208, "sctlr": 0xc080, "vbar": 0xc600, "esr_el1": 0xc290, "elr_el1": 0xc201, "far_el1": 0xc300, "id_aa64isar1": 0xc031, "cntv_ctl": 0xdf19, "cntv_cval": 0xdf1a, "cntp_ctl": 0xdf11, "cntp_cval": 0xdf12, "ttbr0": 0xc100, "ttbr1": 0xc101, "tcr": 0xc102} {
		v, err := d.cpu.SystemRegister(reg)
		if err == nil {
			registers[name] = v
		}
	}
	d.emit("arm64.stop", registers)
	if f, ok := d.device.(interface{ Flush() }); ok {
		f.Flush()
	}

	d.mu.Lock()
	d.registers = registers
	d.result = &vmm.Result{Reason: reason, Detail: detail, Clean: clean, Backend: d.BackendID(), Finished: time.Now()}
	d.mu.Unlock()
	d.emit("exit", *d.result)
}
func (d *arm64Driver) Status(context.Context) (vmm.State, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.result != nil {
		return vmm.State{Name: "stopped"}, nil
	}
	return vmm.State{Name: "running", Running: true}, nil
}
func (d *arm64Driver) Wait(ctx context.Context) (vmm.Result, error) {
	select {
	case <-ctx.Done():
		return vmm.Result{}, ctx.Err()
	case <-d.done:
		d.mu.Lock()
		defer d.mu.Unlock()
		return *d.result, nil
	}
}
func (d *arm64Driver) Close(ctx context.Context) error {
	d.cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.done:
		return d.closeResources()
	}
}

func (d *arm64Driver) Channel(_ context.Context, name string) (channel.ByteChannel, error) {
	c, ok := d.channels[name]
	if !ok {
		return nil, fmt.Errorf("unknown cc ARM64 channel %q", name)
	}
	return c, nil
}

func (d *arm64Driver) Stop(ctx context.Context) error { return d.Close(ctx) }
func (*arm64Driver) Pause(context.Context) error {
	return &vmm.Error{Code: vmm.ErrorUnsupported, Message: "ARM64 pause is not implemented"}
}
func (*arm64Driver) Resume(context.Context) error {
	return &vmm.Error{Code: vmm.ErrorUnsupported, Message: "ARM64 resume is not implemented"}
}
func (*arm64Driver) Reset(context.Context) error {
	return &vmm.Error{Code: vmm.ErrorUnsupported, Message: "ARM64 reset is not implemented"}
}
func (*arm64Driver) Powerdown(context.Context) error {
	return &vmm.Error{Code: vmm.ErrorUnsupported, Message: "ARM64 powerdown is not implemented"}
}
func (d *arm64Driver) NextEvent(ctx context.Context) (vmm.Event, error) {
	consume := func(e vmm.Event, ok bool) (vmm.Event, error) {
		select {
		case <-d.ready:
		default:
		}
		if len(d.events) > 0 || !ok {
			select {
			case d.ready <- struct{}{}:
			default:
			}
		}
		if !ok {
			return vmm.Event{}, &vmm.Error{Code: vmm.ErrorState, Message: "ARM64 VM closed"}
		}
		return e, nil
	}
	select {
	case e, ok := <-d.events:
		return consume(e, ok)
	default:
	}
	select {
	case <-ctx.Done():
		return vmm.Event{}, ctx.Err()
	case e, ok := <-d.events:
		return consume(e, ok)
	}
}
