package r3000

import (
	"bytes"
	"context"
	"fmt"
	"image/png"

	blockstar "github.com/tinyrange/trex/block/star"
	channelstar "github.com/tinyrange/trex/channel/star"
	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func IP12Builtin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var rom fileArg
	memory := 32 << 20
	if err := starlark.UnpackArgs("ip12", args, kwargs, "memory?", &memory, "rom?", &rom); err != nil {
		return nil, err
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	m, err := NewIP12(memory, rom.Reader)
	if err != nil {
		return nil, err
	}
	v := &ip12Value{m: m, ctx: resources.Context()}
	v.unregister, err = resources.Add(v)
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	return v, nil
}

type ip12Value struct {
	m          *IP12
	ctx        context.Context
	unregister func()
}

func (v *ip12Value) Close() error {
	if v.unregister != nil {
		v.unregister()
		v.unregister = nil
	}
	return v.m.Close()
}

func (*ip12Value) String() string        { return "<SGI IP12 machine>" }
func (*ip12Value) Type() string          { return "ip12_machine" }
func (*ip12Value) Freeze()               {}
func (*ip12Value) Truth() starlark.Bool  { return starlark.True }
func (*ip12Value) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: ip12_machine") }
func (*ip12Value) AttrNames() []string {
	return []string{"attach_disk", "break_at", "clear_breaks", "close", "load_executable", "read", "read_effective", "graphics", "key_code", "mouse", "registers", "run", "screenshot", "serial"}
}

func (v *ip12Value) Attr(name string) (starlark.Value, error) {
	switch name {
	case "attach_disk", "break_at", "clear_breaks", "close", "load_executable", "read", "read_effective", "graphics", "key_code", "mouse", "registers", "run", "screenshot", "serial":
		return starlark.NewBuiltin(name, v.call), nil
	default:
		return nil, nil
	}
}

func (v *ip12Value) call(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	name, m := fn.Name(), v.m
	if m.closed && name != "close" {
		return nil, fmt.Errorf("ip12: machine closed")
	}
	switch name {
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
	case "break_at":
		var address uint32
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address); err != nil {
			return nil, err
		}
		if address&3 != 0 {
			return nil, fmt.Errorf("ip12: unaligned breakpoint %#x", address)
		}
		m.breaks[address] = true
	case "clear_breaks", "close", "registers":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		switch name {
		case "close":
			return starlark.None, v.Close()
		case "clear_breaks":
			clear(m.breaks)
		case "registers":
			c := &m.cpu
			return starfile.NewRecord(starlark.StringDict{
				"pc": u32(c.pc), "next_pc": u32(c.next), "hi": u32(c.hi), "lo": u32(c.lo),
				"gpr": registerTuple(c.gpr), "cp0": registerTuple(c.cp0), "fpr": registerTuple(c.fpr),
				"fcsr": u32(c.fcsr), "cycles": starlark.MakeUint64(m.cycles),
				"scsi":     starlark.Bytes(string(m.scsi.reg[:])),
				"scsi_irq": starlark.Bool(m.scsi.irq),
			}), nil
		}
	case "read", "read_effective":
		var address uint32
		var size int
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size); err != nil {
			return nil, err
		}
		if size < 0 || size > 8<<20 {
			return nil, fmt.Errorf("ip12: invalid read size %d", size)
		}
		data := make([]byte, size)
		read := m.Read
		if name == "read_effective" {
			read = m.ReadEffective
		}
		if err := read(address, data); err != nil {
			return nil, err
		}
		return starlark.Bytes(data), nil
	case "key_code":
		var code uint8
		down := true
		if err := starlark.UnpackArgs(name, args, kwargs, "code", &code, "down?", &down); err != nil {
			return nil, err
		}
		return starlark.None, m.KeyCode(code, down)
	case "mouse":
		var dx, dy int
		var buttons uint8
		if err := starlark.UnpackArgs(name, args, kwargs, "dx", &dx, "dy", &dy, "buttons?", &buttons); err != nil {
			return nil, err
		}
		return starlark.None, m.Mouse(dx, dy, buttons)
	case "graphics":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		g := &m.graphics
		cursorX, cursorY := g.cursor[0].position()
		return starfile.NewRecord(starlark.StringDict{
			"pc": u32(uint32(g.ge.pc)), "word": starlark.MakeUint64(g.ge.code[g.ge.pc&0x3fff]),
			"fifo": u32(uint32(g.ge.queued)), "wait": u32(uint32(g.ge.wait)),
			"pixels_written":  starlark.MakeUint64(g.raster.drawn),
			"raster_register": u32(uint32(g.ge.reptr)), "raster_transfer": u32(uint32(g.raster.transfer)),
			"raster_command": u32(g.raster.reg[0x1f]), "raster_count": u32(g.raster.reg[0x1c]),
			"raster_block_mode": u32(g.raster.reg[0x3e]),
			"indirect_pc":       u32(uint32(g.ge.indirectPC)), "indirect_target": u32(uint32(g.ge.indirectTarget)),
			"host_pc": u32(uint32(g.ge.hostPC)), "fetch_pc": u32(uint32(g.ge.fetchPC)), "fetch_token": u32(uint32(g.ge.fetchToken)),
			"fifo_read": starlark.MakeUint64(g.ge.reads), "fifo_written": starlark.MakeUint64(g.ge.writes),
			"dma_words": starlark.MakeUint64(m.gdma.words), "dma_active": starlark.Bool(m.gdma.active),
			"dma_error": starlark.Bool(m.gdma.failed),
			"cursor_x":  starlark.MakeInt(cursorX), "cursor_y": starlark.MakeInt(cursorY),
		}), nil
	case "screenshot":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		var output bytes.Buffer
		if err := png.Encode(&output, m.Screen()); err != nil {
			return nil, err
		}
		return &starfile.Bytes{Name: "personal-iris.png", Data: output.Bytes()}, nil
	case "serial":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		c, err := m.Serial()
		if err != nil {
			return nil, err
		}
		return channelstar.New("ip12:serial", c), nil
	case "run":
		var budget uint64
		var exceptions bool
		if err := starlark.UnpackArgs(name, args, kwargs, "budget", &budget, "stop_on_exception?", &exceptions); err != nil {
			return nil, err
		}
		stop, err := m.Run(v.ctx, budget, exceptions)
		if err != nil {
			return nil, err
		}
		return recordStop(stop), nil
	}
	return starlark.None, nil
}

func loadMIPSArgs(name string, args starlark.Tuple, kwargs []starlark.Tuple) (fileArg, [2][]string, error) {
	var vectors [2][]string
	var file fileArg
	argv, envp := starlark.Iterable(starlark.Tuple{}), starlark.Iterable(starlark.Tuple{})
	if err := starlark.UnpackArgs(name, args, kwargs, "file", &file, "args?", &argv, "env?", &envp); err != nil {
		return file, vectors, err
	}
	for i, values := range []starlark.Iterable{argv, envp} {
		for value := range starlark.Elements(values) {
			s, ok := starlark.AsString(value)
			if !ok || len(vectors[i]) >= 8192 {
				return file, vectors, fmt.Errorf("%s: expected a bounded sequence of strings", name)
			}
			vectors[i] = append(vectors[i], s)
		}
	}
	return file, vectors, nil
}
