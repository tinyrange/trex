package cc

import (
	"context"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/vmm/ramfb"

	starvalue "github.com/tinyrange/trex/script/value"
	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

func (d *driver) Extension(ctx context.Context, name string) (starlark.Value, error) {
	if name != "cc.v1" {
		return nil, &vmm.Error{Code: vmm.ErrorUnsupported, Message: "unknown cc extension " + name}
	}
	return starvalue.NewRecord(starlark.StringDict{"breakpoint": starlark.NewBuiltin("cc.breakpoint", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var address uint64
		if err := starlark.UnpackArgs("cc.breakpoint", args, kwargs, "address", &address); err != nil {
			return nil, err
		}
		err := d.call(ctx, func() error {
			debug, ok := d.pc.cpu.(interface{ SetBreakpoint(uint64) error })
			if !ok {
				return fmt.Errorf("execution breakpoints unavailable")
			}
			return debug.SetBreakpoint(address)
		})
		return starlark.None, err
	}), "read_physical": starlark.NewBuiltin("cc.read_physical", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var address uint64
		var size int
		if err := starlark.UnpackArgs("cc.read_physical", args, kwargs, "address", &address, "size", &size); err != nil {
			return nil, err
		}
		if size < 0 || size > 65536 {
			return nil, fmt.Errorf("read_physical size must be 0..65536")
		}
		var result starlark.Value
		err := d.call(ctx, func() error {
			memory := d.pc.ram
			base := uint64(0)
			if address >= ramfb.Address {
				memory = d.pc.framebuffer
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
	}), "disk": starlark.NewBuiltin("cc.disk", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs("cc.disk", args, kwargs); err != nil {
			return nil, err
		}
		var file starfile.File
		err := d.call(ctx, func() error {
			snapshot, ok := d.pc.disk.Device.(interface{ Snapshot() (starfile.File, error) })
			if !ok {
				return &vmm.Error{Code: vmm.ErrorUnsupported, Message: "disk inspection requires a snapshot attachment"}
			}
			var err error
			file, err = snapshot.Snapshot()
			return err
		})
		return file, err
	}), "state": starlark.NewBuiltin("cc.state", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs("cc.state", args, kwargs); err != nil {
			return nil, err
		}
		var value starlark.Value
		err := d.call(ctx, func() error {
			r, err := d.pc.cpu.Registers()
			if err != nil {
				return err
			}
			s, err := d.pc.cpu.SystemRegisters()
			if err != nil {
				return err
			}
			irq, err := d.pc.cpu.InterruptState()
			if err != nil {
				return err
			}
			interrupts := map[string]any{}
			for k, v := range irq {
				interrupts[k] = int64(v)
			}
			keyboard := make([]any, len(d.pc.inputTrace))
			for i, v := range d.pc.inputTrace {
				keyboard[i] = v
			}
			keyboard = append(keyboard, fmt.Sprintf("controller=%02x mouse_enabled=%t remote=%t queue=%d", d.pc.keyboard.command, d.pc.keyboard.mouseEnabled, d.pc.keyboard.mouseRemote, len(d.pc.keyboard.queue)))
			registers := map[string]any{"eax": int64(r.Rax), "ebx": int64(r.Rbx), "ecx": int64(r.Rcx), "edx": int64(r.Rdx), "esi": int64(r.Rsi), "edi": int64(r.Rdi), "esp": int64(r.Rsp), "ebp": int64(r.Rbp), "eip": int64(r.Rip), "eflags": int64(r.Rflags)}
			value, err = starvalue.Starlark(map[string]any{"pc": int64(s.Cs.Base + r.Rip), "cr0": int64(s.Cr0), "cr3": int64(s.Cr3), "registers": registers, "idt_base": int64(s.Idt.Base), "last_bios": d.pc.lastService, "ata_commands": int64(d.pc.ide.commands), "ata_task": fmt.Sprintf("%x", d.pc.ide.task), "vga_accesses": int64(d.pc.vga.accesses), "keyboard_commands": keyboard, "rtc": d.pc.rtcTrace, "interrupts": interrupts})
			return err
		})
		if err != nil {
			return nil, err
		}
		return value, nil
	})}), nil
}
