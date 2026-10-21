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
	}
	var timer any
	if h := p.hpet; h != nil {
		comparators := make([]any, len(h.timers))
		for i, t := range h.timers {
			comparators[i] = map[string]any{"config": int64(t.config), "match": int64(t.match), "period": int64(t.period), "asserted": t.asserted}
		}
		timer = map[string]any{"config": int64(h.config), "counter": int64(h.counter(p.now())), "status": int64(h.status), "timers": comparators}
	}
	var network any
	var pciIDE any
	if d := p.pciIDE; d != nil {
		pciIDE = map[string]any{"config": fmt.Sprintf("%x", d.config[:64]), "read_dwords": fmt.Sprintf("%016x", d.reads), "write_dwords": fmt.Sprintf("%016x", d.writes), "bus_master": fmt.Sprintf("%x", d.bm)}
	}
	if n := p.nic; n != nil {
		network = map[string]any{"tx": int64(n.tx), "rx": int64(n.rx), "command": int(n.command), "isr": int(n.isr), "imr": int(n.imr), "start": int(n.start), "stop": int(n.stop), "current": int(n.current), "boundary": int(n.boundary), "mac": fmt.Sprintf("%x", n.physical)}
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
	return starvalue.Starlark(map[string]any{
		"console": string(p.console[max(0, len(p.console)-2048):]), "text": string(text), "instruction_bytes": fmt.Sprintf("%x", pcBytes), "bios_ticks": int64(binary.LittleEndian.Uint32(p.ram[0x46c:])),
		"virtio_input": map[string]any{"status": int(p.input.status), "reports": int64(p.input.reports), "queue_ready": p.input.queues[0].ready, "used": int(p.input.queues[0].written), "descriptor": int64(p.input.queues[0].desc), "available": int64(p.input.queues[0].avail), "pending": len(p.input.pending)},
		"ata_failures": failures, "ata_last_command": int(p.ide.lastCommand), "ata_dma_pending": p.ide.dmaPending, "ata_irq_pending": p.ide.pending,
		"pci_address": int64(p.pciAddress), "pci_ide": pciIDE,
		"network": network, "hpet": timer,
		"code_mapping": mapping,
		"segments":     map[string]any{"cs": int64(s.Cs.Selector), "cs_base": int64(s.Cs.Base), "cs_flags": int64(s.Cs.Db)<<14 | int64(s.Cs.Type), "ss": int64(s.Ss.Selector), "ss_base": int64(s.Ss.Base), "ss_flags": int64(s.Ss.Db)<<14 | int64(s.Ss.Type), "ds": int64(s.Ds.Selector), "ds_base": int64(s.Ds.Base)},
		"pc":           int64(s.Cs.Base + r.Rip), "cr0": int64(s.Cr0), "cr3": int64(s.Cr3),
		"cr2": int64(s.Cr2), "cr4": int64(s.Cr4),
		"registers": registers, "idt_base": int64(s.Idt.Base),
		"efi": p.efiTrace, "unsupported_bios": biosGaps,
		"last_bios": p.lastService, "ata_commands": int64(p.ide.commands),
		"ata_task": fmt.Sprintf("%x", p.ide.task), "vga_accesses": int64(p.vga.accesses),
		"keyboard_commands": keyboard, "rtc": p.rtcTrace, "interrupts": interrupts,
	})
}
