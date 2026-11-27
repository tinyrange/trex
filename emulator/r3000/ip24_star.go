package r3000

import (
	"bytes"
	"context"
	"fmt"
	"image/png"
	"sync"

	blockstar "github.com/tinyrange/trex/block/star"
	channelstar "github.com/tinyrange/trex/channel/star"
	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func IP24Builtin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var rom fileArg
	var graphics bool
	if err := starlark.UnpackArgs("ip24", args, kwargs, "rom?", &rom, "newport?", &graphics); err != nil {
		return nil, err
	}
	m, err := newIP24(rom.Reader, graphics)
	if err != nil {
		return nil, err
	}
	return registerIP24(thread, m)
}

func registerIP24(thread *starlark.Thread, m *IP24) (starlark.Value, error) {
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	v := &ip24Value{m: m, ctx: resources.Context()}
	v.unregister, err = resources.Add(v)
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	return v, nil
}

type ip24Value struct {
	mu         sync.Mutex
	m          *IP24
	ctx        context.Context
	unregister func()
	display    *ip24Display
}

func (v *ip24Value) Close() error {
	v.mu.Lock()
	if v.display != nil {
		v.display.cancel()
	}
	unregister := v.unregister
	v.unregister = nil
	err := v.m.Close()
	v.mu.Unlock()
	if unregister != nil {
		unregister()
	}
	return err
}

func (*ip24Value) String() string        { return "<SGI IP24 machine>" }
func (*ip24Value) Type() string          { return "ip24_machine" }
func (*ip24Value) Freeze()               {}
func (*ip24Value) Truth() starlark.Bool  { return starlark.True }
func (*ip24Value) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: ip24_machine") }
func (*ip24Value) AttrNames() []string {
	return []string{"attach_disk", "break_at", "checkpoint", "clear_breaks", "close", "graphics", "key", "load_executable", "mouse", "read", "read_effective", "read_pixel", "registers", "run", "screenshot", "serial", "status"}
}

func (v *ip24Value) Attr(name string) (starlark.Value, error) {
	switch name {
	case "status":
		v.mu.Lock()
		defer v.mu.Unlock()
		if v.m.closed {
			return starlark.String("stopped"), nil
		}
		if v.display != nil && v.display.stop != nil {
			return nil, v.display.stop
		}
		return starlark.String("running"), nil
	case "attach_disk", "break_at", "checkpoint", "clear_breaks", "close", "graphics", "key", "load_executable", "mouse", "read", "read_effective", "read_pixel", "registers", "run", "screenshot", "serial":
		return starlark.NewBuiltin(name, v.call), nil
	}
	return nil, nil
}

func mipsAddress(address uint64) uint64 {
	if address <= 0xffffffff {
		return mipsWord(uint32(address))
	}
	return address
}

func r4kRegisterTuple(registers [32]uint64) starlark.Tuple {
	out := make(starlark.Tuple, len(registers))
	for i, n := range registers {
		out[i] = starlark.MakeUint64(n)
	}
	return out
}

func (v *ip24Value) call(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	name, m := fn.Name(), v.m
	if name == "close" {
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		return starlark.None, v.Close()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if m.closed {
		return nil, fmt.Errorf("ip24: machine closed")
	}
	u64 := starlark.MakeUint64
	switch name {
	case "checkpoint":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		checkpoint, err := m.Checkpoint()
		if err != nil {
			return nil, err
		}
		return &ip24CheckpointValue{checkpoint}, nil
	case "attach_disk":
		var target int
		var source starlark.Value
		if err := starlark.UnpackArgs(name, args, kwargs, "target", &target, "device", &source); err != nil {
			return nil, err
		}
		device, err := blockstar.AsDevice(source)
		if err != nil {
			return nil, err
		}
		return starlark.None, m.AttachDisk(target, device)
	case "load_executable":
		file, vectors, err := loadMIPSArgs(name, args, kwargs)
		if err != nil {
			return nil, err
		}
		return starlark.None, m.Load(file.Reader, vectors[0], vectors[1])
	case "key":
		var key string
		down := true
		if err := starlark.UnpackArgs(name, args, kwargs, "key", &key, "down?", &down); err != nil {
			return nil, err
		}
		return starlark.None, m.Key(key, down)
	case "mouse":
		var dx, dy int
		var buttons uint8
		if err := starlark.UnpackArgs(name, args, kwargs, "dx", &dx, "dy", &dy, "buttons?", &buttons); err != nil {
			return nil, err
		}
		return starlark.None, m.Mouse(dx, dy, buttons)
	case "read_pixel":
		var x, y int
		if err := starlark.UnpackArgs(name, args, kwargs, "x", &x, "y", &y); err != nil {
			return nil, err
		}
		g := m.newport
		if g == nil || uint(x) >= newportStride || uint(y) >= newportRows {
			return nil, fmt.Errorf("ip24: pixel outside Newport video memory")
		}
		i := y*newportStride + x
		return starlark.Tuple{u64(uint64(g.rgb[i])), u64(uint64(g.aux[i]))}, nil
	case "graphics", "screenshot":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		if m.newport == nil {
			return nil, fmt.Errorf("ip24: no active Newport display")
		}
		if name == "graphics" {
			g := m.newport
			return starfile.NewRecord(starlark.StringDict{
				"commands": u64(g.commands), "pixels_written": u64(g.drawn),
				"display_control": u64(uint64(g.vc2[0x10])), "dcb_mode": u64(uint64(g.reg[0x238/4])),
				"draw_mode": u64(uint64(g.reg[0])<<32 | uint64(g.reg[1])),
				"cursor_x":  starlark.MakeInt(int(g.vc2[2])), "cursor_y": starlark.MakeInt(int(g.vc2[3])),
			}), nil
		}
		screen, err := m.Screen()
		if err != nil {
			return nil, err
		}
		var output bytes.Buffer
		if err := png.Encode(&output, screen); err != nil {
			return nil, err
		}
		return &starfile.Bytes{Name: "indy.png", Data: output.Bytes()}, nil
	case "break_at":
		var address uint64
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address); err != nil {
			return nil, err
		}
		if address&3 != 0 {
			return nil, fmt.Errorf("ip24: unaligned breakpoint %#x", address)
		}
		m.breaks[mipsAddress(address)] = true
	case "clear_breaks", "registers", "serial":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		switch name {
		case "clear_breaks":
			clear(m.breaks)
		case "serial":
			return channelstar.New("ip24:serial", m.Serial()), nil
		case "registers":
			c := &m.cpu
			return starfile.NewRecord(starlark.StringDict{
				"pc": u64(c.pc), "next_pc": u64(c.next), "hi": u64(c.hi), "lo": u64(c.lo), "cycles": u64(m.cycles),
				"gpr": r4kRegisterTuple(c.gpr), "cp0": r4kRegisterTuple(c.cp0), "fpr": r4kRegisterTuple(c.fpr),
				"fcsr": u32(c.fcsr), "scsi": starlark.Bytes(string(m.scsi.reg[:])), "scsi_irq": starlark.Bool(m.scsi.irq),
				"dma_control": u32(m.dma.control), "dma_pointer": u32(m.dma.next), "dma_buffer": u32(m.dma.buffer),
				"interrupts": starlark.Bytes(string(m.int3.reg[:])),
				"vdma": starfile.NewRecord(starlark.StringDict{
					"memory": u32(m.vdma.memory), "gio": u32(m.vdma.gio), "size": u32(m.vdma.size),
					"stride": u32(m.vdma.stride), "mode": u32(m.vdma.mode), "count": u32(m.vdma.count),
					"control": u32(m.mc[mcDMAControl]), "cause": u32(m.mc[mcDMACause]),
				}),
				"last_fault": starfile.NewRecord(starlark.StringDict{
					"pc": u64(m.lastFault.pc), "instruction": u32(m.lastFault.word),
					"code": starlark.MakeInt(m.lastFault.exception), "address": u64(m.lastFault.address), "physical": u64(m.lastFault.physical),
				}),
			}), nil
		}
	case "read", "read_effective":
		var address uint64
		var size int
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size); err != nil {
			return nil, err
		}
		if size < 0 || size > 8<<20 || address+uint64(size) < address {
			return nil, fmt.Errorf("ip24: invalid memory read")
		}
		data := make([]byte, size)
		read := m.ReadPhysical
		if name == "read_effective" {
			read, address = m.ReadEffective, mipsAddress(address)
		}
		if err := read(address, data); err != nil {
			return nil, err
		}
		return starlark.Bytes(data), nil
	case "run":
		var budget uint64
		var allExceptions bool
		var selected *starlark.List
		if err := starlark.UnpackArgs(name, args, kwargs, "budget", &budget, "stop_on_exception?", &allExceptions, "exception_codes?", &selected); err != nil {
			return nil, err
		}
		var exceptions uint32
		if allExceptions {
			exceptions = ^uint32(0)
		}
		if selected != nil {
			for i := range selected.Len() {
				var code uint8
				if err := starlark.AsInt(selected.Index(i), &code); err != nil || code > 31 {
					return nil, fmt.Errorf("ip24: exception codes must be integers from 0 to 31")
				}
				exceptions |= 1 << code
			}
		}
		stop, err := m.run(v.ctx, budget, exceptions)
		if err != nil {
			return nil, err
		}
		return starfile.NewRecord(starlark.StringDict{
			"kind": starlark.String(stop.Kind), "pc": u64(stop.PC), "cycles": u64(stop.Cycles),
			"instruction": u32(stop.Instruction), "exception": starlark.MakeInt(stop.Exception), "service": u32(stop.Service),
			"address": u64(stop.Address), "physical": u64(stop.Physical), "store": starlark.Bool(stop.Store),
		}), nil
	}
	return starlark.None, nil
}

type ip24CheckpointValue struct{ state *IP24Checkpoint }

func (*ip24CheckpointValue) String() string       { return "<SGI IP24 checkpoint>" }
func (*ip24CheckpointValue) Type() string         { return "ip24_checkpoint" }
func (*ip24CheckpointValue) Freeze()              {}
func (*ip24CheckpointValue) Truth() starlark.Bool { return starlark.True }
func (*ip24CheckpointValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: ip24_checkpoint")
}
func (*ip24CheckpointValue) AttrNames() []string { return []string{"restore"} }

func (v *ip24CheckpointValue) Attr(name string) (starlark.Value, error) {
	if name != "restore" {
		return nil, nil
	}
	return starlark.NewBuiltin(name, func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs(fn.Name(), args, kwargs); err != nil {
			return nil, err
		}
		m, err := v.state.Restore()
		if err != nil {
			return nil, err
		}
		return registerIP24(thread, m)
	}), nil
}
