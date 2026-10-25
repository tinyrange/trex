package cc

import (
	"context"
	"encoding/binary"
	"fmt"

	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/ramfb"
	"go.starlark.net/starlark"
	"j5.nz/cc/hypervisor"
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
		"step":          starlark.NewBuiltin("cc.step", i.step),
		"read_physical": starlark.NewBuiltin("cc.read_physical", i.readPhysical),
		"descriptors":   starlark.NewBuiltin("cc.descriptors", i.descriptors),
		"disk":          starlark.NewBuiltin("cc.disk", i.disk),
		"state":         starlark.NewBuiltin("cc.state", i.state),
		"cpus":          starlark.NewBuiltin("cc.cpus", i.cpus),
		"performance":   starlark.NewBuiltin("cc.performance", i.performance),
		"symbol":        starlark.NewBuiltin("cc.symbol", i.symbol),
		"symbols":       starlark.NewBuiltin("cc.symbols", i.symbols),
		"symbolize":     starlark.NewBuiltin("cc.symbolize", i.symbolize),
		"read_virtual":  starlark.NewBuiltin("cc.read_virtual", i.readVirtual),
		"disassemble":   starlark.NewBuiltin("cc.disassemble", i.disassemble),
	}), nil
}

func (i inspection) breakpoint(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	skip := 0
	if err := starlark.UnpackArgs("cc.breakpoint", args, kwargs, "address", &address, "skip?", &skip); err != nil {
		return nil, err
	}
	err := i.driver.call(i.ctx, func() error {
		if len(i.driver.pc.cpus) > 1 {
			return fmt.Errorf("execution breakpoints require a single-CPU machine")
		}
		debug, ok := i.driver.pc.cpu.(interface{ SetBreakpoint(uint64) error })
		if !ok {
			return fmt.Errorf("execution breakpoints unavailable")
		}
		if skip < 0 {
			return fmt.Errorf("breakpoint skip must be nonnegative")
		}
		if err := debug.SetBreakpoint(address); err != nil {
			return err
		}
		i.driver.breakpointSkip = skip
		return nil
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
		p := i.driver.pc
		var memory []byte
		if address >= ramfb.Address && address-ramfb.Address < uint64(len(p.framebuffer)) {
			offset := address - ramfb.Address
			if uint64(size) > uint64(len(p.framebuffer))-offset {
				return fmt.Errorf("physical range exceeds framebuffer")
			}
			memory = p.framebuffer[offset : offset+uint64(size)]
		} else {
			var err error
			memory, err = p.memory(address, uint64(size))
			if err != nil {
				return err
			}
		}
		result = starlark.Bytes(string(memory))
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
	biosGaps := map[string]any{}
	for name, count := range p.unsupportedBIOS {
		biosGaps[name] = int64(count)
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
		"rax": int64(r.Rax), "rbx": int64(r.Rbx), "rcx": int64(r.Rcx), "rdx": int64(r.Rdx),
		"rsi": int64(r.Rsi), "rdi": int64(r.Rdi), "rsp": int64(r.Rsp), "rbp": int64(r.Rbp),
		"rip": int64(r.Rip), "rflags": int64(r.Rflags),
		"r8": int64(r.R8), "r9": int64(r.R9), "r10": int64(r.R10), "r11": int64(r.R11),
		"r12": int64(r.R12), "r13": int64(r.R13), "r14": int64(r.R14), "r15": int64(r.R15),
	}
	var timer any
	if h := p.hpet; h != nil {
		comparators := make([]any, len(h.timers))
		for i, t := range h.timers {
			comparators[i] = map[string]any{"config": int64(t.config), "match": int64(t.match), "period": int64(t.period), "asserted": t.asserted}
		}
		timer = map[string]any{"config": int64(h.config), "counter": int64(h.counter(p.now())), "status": int64(h.status), "timers": comparators}
	}
	var smcState any
	if s := p.smc; s != nil {
		smcState = map[string]any{"status": int(s.status), "result": int(s.result), "command": int(s.command), "argument_bytes": s.argumentSize, "requests": s.trace}
	}
	var usbState any
	if u := p.uhci; u != nil {
		devices := []any{}
		for n, d := range u.devices {
			devices = append(devices, map[string]any{"port": n, "port_status": int(u.ports[n]), "address": int(d.address), "configuration": int(d.configuration), "controls": int64(d.controls), "reports": int64(d.reports), "pending": len(d.pending), "requests": d.trace})
		}
		usbState = map[string]any{"command": int(u.command), "status": int(u.status), "interrupt": int(u.interrupt), "frame": int(u.frame), "base": int64(u.base), "transactions": int64(u.transactions), "frames": int64(u.frames), "fault": u.fault, "config": fmt.Sprintf("%x", u.config[:]), "devices": devices}
	}
	var network any
	var nvmeState any
	if n := p.nvme; n != nil {
		regs := map[string]any{}
		for name, offset := range map[string]uint64{"cc": 0x14, "csts": 0x1c, "intms": 0x0c, "aqa": 0x24, "asq": 0x28, "acq": 0x30} {
			v, err := n.controller.ReadMMIO(offset, 8)
			if err != nil {
				return nil, err
			}
			regs[name] = int64(v)
		}
		stats := n.controller.IOStatistics()
		nvmeState = map[string]any{"read_commands": stats.ReadCommands, "read_bytes": stats.ReadBytes, "write_commands": stats.WriteCommands, "write_bytes": stats.WriteBytes, "config": fmt.Sprintf("%x", n.config[:]), "registers": regs, "intx_pending": n.pending}
	}
	var pciIDE any
	if d := p.pciIDE; d != nil {
		pciIDE = map[string]any{"config": fmt.Sprintf("%x", d.config[:]), "read_dwords": fmt.Sprintf("%016x", d.reads), "write_dwords": fmt.Sprintf("%016x", d.writes), "bus_master": fmt.Sprintf("%x", d.bm), "configuration_accesses": d.trace}
	}
	if n := p.nic; n != nil {
		network = map[string]any{"tx": int64(n.tx), "rx": int64(n.rx), "command": int(n.command), "isr": int(n.isr), "imr": int(n.imr), "start": int(n.start), "stop": int(n.stop), "current": int(n.current), "boundary": int(n.boundary), "mac": fmt.Sprintf("%x", n.physical)}
	}
	if n := p.pciNIC; n != nil {
		regs := map[string]any{}
		for name, off := range map[string]uint32{"ctrl": 0, "status": 8, "eecd": 0x10, "mdic": 0x20, "icr": 0xc0, "ims": 0xd0, "rctl": 0x100, "tctl": 0x400, "rdlen": 0x2808, "rdh": 0x2810, "rdt": 0x2818, "tdlen": 0x3808, "tdh": 0x3810, "tdt": 0x3818} {
			regs[name] = int64(n.regs[off/4])
		}
		network = map[string]any{"model": "82540em", "tx": int64(n.tx), "rx": int64(n.rx), "dropped": int64(n.dropped), "config": fmt.Sprintf("%x", n.config[:]), "registers": regs, "writes": n.trace}
	}
	failures := make([]any, len(p.ide.failures))
	for i, failure := range p.ide.failures {
		failures[i] = map[string]any{"command": int(failure.command), "feature": int(failure.feature), "error": int(failure.code), "reason": failure.reason, "task": fmt.Sprintf("%x", failure.task)}
	}
	text := make([]byte, 0, 2025)
	for row := 0; row < 25; row++ {
		for col := 0; col < 80; col++ {
			ch := p.ram[0xb8000+row*160+col*2]
			if ch < 32 {
				ch = ' '
			}
			text = append(text, ch)
		}
		text = append(text, '\n')
	}
	mapping := map[string]any{}
	linear := s.Cs.Base + r.Rip
	if physical, err := p.physical(linear, s); err == nil {
		mapping["physical"] = int64(physical)
	}
	if s.Cr0&(1<<31) != 0 && s.Cr4&(1<<5) == 0 {
		if b, err := p.memory((s.Cr3&0xfffff000)+(linear>>22&1023)*4, 4); err == nil {
			pde := binary.LittleEndian.Uint32(b)
			mapping["pde"] = int64(pde)
			if pte, err := p.memory(uint64(pde&0xfffff000)+(linear>>12&1023)*4, 4); err == nil {
				mapping["pte"] = int64(binary.LittleEndian.Uint32(pte))
			}
		}
	}
	var pcBytes []byte
	for j := uint64(0); j < 16; j++ {
		address, err := p.physical(s.Cs.Base+r.Rip+j, s)
		if err != nil {
			break
		}
		value, err := p.memory(address, 1)
		if err != nil {
			break
		}
		pcBytes = append(pcBytes, value[0])
	}
	biosCounts := map[string]any{}
	for vector, count := range p.biosCounts {
		if count != 0 {
			biosCounts[fmt.Sprintf("%02x", vector)] = int64(count)
		}
	}
	return starvalue.Starlark(map[string]any{
		"bios_counts": biosCounts,
		"text":        string(text), "instruction_bytes": fmt.Sprintf("%x", pcBytes), "bios_ticks": int64(binary.LittleEndian.Uint32(p.ram[0x46c:])),
		"code_mapping": mapping, "unsupported_bios": biosGaps,
		"virtio_input": map[string]any{"status": int(p.input.status), "reports": int64(p.input.reports), "queue_ready": p.input.queues[0].ready, "used": int(p.input.queues[0].written), "descriptor": int64(p.input.queues[0].desc), "available": int64(p.input.queues[0].avail), "pending": len(p.input.pending)},
		"serial":       map[string]any{"attached": p.serial.attached, "divisor": int(p.serial.dll) | int(p.serial.dlm)<<8, "ier": int(p.serial.ier), "iir": int(p.serial.cause()), "lcr": int(p.serial.lcr), "mcr": int(p.serial.mcr), "modem": int(p.serial.modem), "rx_bytes": p.serial.rxCount, "tx_bytes": len(p.serial.tx), "irq": p.serial.irq},
		"ata_failures": failures, "ata_sleeping": p.ide.sleeping, "ata_last_command": int(p.ide.lastCommand), "ata_dma_pending": p.ide.dmaPending, "ata_irq_pending": p.ide.pending,
		"pci_address": int64(p.pciAddress), "pci_ide": pciIDE, "nvme": nvmeState,
		"network": network, "hpet": timer, "smc": smcState, "usb": usbState,
		"pc": int64(s.Cs.Base + r.Rip), "cr0": int64(s.Cr0), "cr3": int64(s.Cr3),
		"cr2": int64(s.Cr2), "cr4": int64(s.Cr4), "efer": int64(s.Efer), "gs_base": int64(s.Gs.Base),
		"registers": registers, "idt_base": int64(s.Idt.Base),
		"segments": map[string]any{
			"cs": map[string]any{"base": int64(s.Cs.Base), "selector": int(s.Cs.Selector)},
			"ss": map[string]any{"base": int64(s.Ss.Base), "selector": int(s.Ss.Selector)},
			"ds": map[string]any{"base": int64(s.Ds.Base), "selector": int(s.Ds.Selector)},
			"es": map[string]any{"base": int64(s.Es.Base), "selector": int(s.Es.Selector)},
		},
		"console": string(p.console), "darwin": p.darwin,
		"bios_disk_calls": p.biosDiskCalls,
		"bios_calls":      p.biosCalls, "a20_enabled": !p.a20Disabled,
		"efi": p.efiTrace, "last_bios": p.lastService, "ata_commands": int64(p.ide.commands),
		"ata_task": fmt.Sprintf("%x", p.ide.task), "vga_accesses": int64(p.vga.accesses),
		"vga":               map[string]any{"attribute": fmt.Sprintf("%x", p.vga.attr[:]), "dac": fmt.Sprintf("%x", p.vga.dac[:64]), "sequencer": fmt.Sprintf("%x", p.vga.seq[:]), "graphics": fmt.Sprintf("%x", p.vga.gc[:])},
		"keyboard_commands": keyboard, "rtc": p.rtcTrace, "interrupts": interrupts,
	})
}

// cpus observes one all-CPU stop; CPU IDs are the firmware's local APIC IDs.
func (i inspection) cpus(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("cc.cpus", args, kwargs); err != nil {
		return nil, err
	}
	var result starlark.Value
	err := i.driver.call(i.ctx, func() error {
		cpus := i.driver.pc.cpus
		if len(cpus) == 0 {
			cpus = []hypervisor.X86{i.driver.pc.cpu}
		}
		values := make([]any, 0, len(cpus))
		for id, cpu := range cpus {
			r, err := cpu.Registers()
			if err != nil {
				return err
			}
			s, err := cpu.SystemRegisters()
			if err != nil {
				return err
			}
			values = append(values, map[string]any{"id": id, "rip": int64(r.Rip), "rsp": int64(r.Rsp), "cr0": int64(s.Cr0), "cr3": int64(s.Cr3), "cr4": int64(s.Cr4), "efer": int64(s.Efer)})
		}
		var err error
		result, err = starvalue.Starlark(values)
		return err
	})
	return result, err
}
