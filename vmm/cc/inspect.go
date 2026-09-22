package cc

import (
	"context"
	"fmt"

	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/ramfb"
	"go.starlark.net/starlark"
)

// inspection binds extension calls to the owning session context.
type inspection struct {
	driver *driver
	ctx    context.Context
}

func (d *driver) Extension(ctx context.Context, name string) (starlark.Value, error) {
	if name != d.BackendID() {
		return nil, &vmm.Error{Code: vmm.ErrorUnsupported, Message: "unknown cc extension " + name}
	}
	i := inspection{driver: d, ctx: ctx}
	return starvalue.NewRecord(starlark.StringDict{
		"breakpoint":    starlark.NewBuiltin("cc.breakpoint", i.breakpoint),
		"read_physical": starlark.NewBuiltin("cc.read_physical", i.readPhysical),
		"disk":          starlark.NewBuiltin("cc.disk", i.disk),
		"state":         starlark.NewBuiltin("cc.state", i.state),
	}), nil
}

func (i inspection) breakpoint(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	if err := starlark.UnpackArgs("cc.breakpoint", args, kwargs, "address", &address); err != nil {
		return nil, err
	}
	err := i.driver.call(i.ctx, func() error {
		debug, ok := i.driver.pc.cpu.(interface{ SetBreakpoint(uint64) error })
		if !ok {
			return fmt.Errorf("execution breakpoints unavailable")
		}
		return debug.SetBreakpoint(address)
	})
	return starlark.None, err
}

func (i inspection) readPhysical(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	var size int
	if err := starlark.UnpackArgs("cc.read_physical", args, kwargs, "address", &address, "size", &size); err != nil {
		return nil, err
	}
	if size < 0 || size > 65536 {
		return nil, fmt.Errorf("read_physical size must be 0..65536")
	}
	var result starlark.Value
	err := i.driver.call(i.ctx, func() error {
		memory := i.driver.pc.ram
		base := uint64(0)
		if address >= ramfb.Address {
			memory = i.driver.pc.framebuffer
			base = ramfb.Address
		}
		offset := address - base
		if offset > uint64(len(memory)) || uint64(size) > uint64(len(memory))-offset {
			return fmt.Errorf("physical range is not RAM")
		}
		result = starlark.Bytes(string(memory[offset : offset+uint64(size)]))
		return nil
	})
	return result, err
}

func (i inspection) disk(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("cc.disk", args, kwargs); err != nil {
		return nil, err
	}
	var file starfile.File
	err := i.driver.call(i.ctx, func() error {
		snapshot, ok := i.driver.pc.disk.Device.(interface{ Snapshot() (starfile.File, error) })
		if !ok {
			return &vmm.Error{Code: vmm.ErrorUnsupported, Message: "disk inspection requires a snapshot attachment"}
		}
		var err error
		file, err = snapshot.Snapshot()
		return err
	})
	return file, err
}

func (i inspection) state(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("cc.state", args, kwargs); err != nil {
		return nil, err
	}
	var value starlark.Value
	err := i.driver.call(i.ctx, func() error {
		var err error
		value, err = i.driver.pc.inspectState()
		return err
	})
	return value, err
}

// inspectState runs on the CPU loop so all fields describe one stop.
func (p *pc) inspectState() (starlark.Value, error) {
	r, err := p.cpu.Registers()
	if err != nil {
		return nil, err
	}
	s, err := p.cpu.SystemRegisters()
	if err != nil {
		return nil, err
	}
	irq, err := p.cpu.InterruptState()
	if err != nil {
		return nil, err
	}
	interrupts := map[string]any{}
	for k, v := range irq {
		interrupts[k] = int64(v)
	}
	keyboard := make([]any, len(p.inputTrace))
	for i, v := range p.inputTrace {
		keyboard[i] = v
	}
	keyboard = append(keyboard, fmt.Sprintf("controller=%02x mouse_enabled=%t remote=%t queue=%d",
		p.keyboard.command, p.keyboard.mouseEnabled, p.keyboard.mouseRemote, len(p.keyboard.queue)))
	registers := map[string]any{
		"eax": int64(r.Rax), "ebx": int64(r.Rbx), "ecx": int64(r.Rcx), "edx": int64(r.Rdx),
		"esi": int64(r.Rsi), "edi": int64(r.Rdi), "esp": int64(r.Rsp), "ebp": int64(r.Rbp),
		"eip": int64(r.Rip), "eflags": int64(r.Rflags),
	}
	var network any
	if n := p.nic; n != nil {
		network = map[string]any{"tx": int64(n.tx), "rx": int64(n.rx), "command": int(n.command), "isr": int(n.isr), "imr": int(n.imr), "start": int(n.start), "stop": int(n.stop), "current": int(n.current), "boundary": int(n.boundary), "mac": fmt.Sprintf("%x", n.physical)}
	}
	return starvalue.Starlark(map[string]any{
		"virtio_input": map[string]any{"status": int(p.input.status), "reports": int64(p.input.reports), "queue_ready": p.input.queues[0].ready, "used": int(p.input.queues[0].written), "descriptor": int64(p.input.queues[0].desc), "available": int64(p.input.queues[0].avail), "pending": len(p.input.pending)},
		"network":      network,
		"pc":           int64(s.Cs.Base + r.Rip), "cr0": int64(s.Cr0), "cr3": int64(s.Cr3),
		"cr2": int64(s.Cr2), "cr4": int64(s.Cr4),
		"registers": registers, "idt_base": int64(s.Idt.Base),
		"last_bios": p.lastService, "ata_commands": int64(p.ide.commands),
		"ata_task": fmt.Sprintf("%x", p.ide.task), "vga_accesses": int64(p.vga.accesses),
		"keyboard_commands": keyboard, "rtc": p.rtcTrace, "interrupts": interrupts,
	})
}
