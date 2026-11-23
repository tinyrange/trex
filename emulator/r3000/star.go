package r3000

import (
	"bytes"
	"context"
	"fmt"
	"image/png"
	"time"

	blockstar "github.com/tinyrange/trex/block/star"
	channelstar "github.com/tinyrange/trex/channel/star"
	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type fileArg struct{ storage.Reader }

func (f *fileArg) Unpack(value starlark.Value) error {
	if value == starlark.None {
		f.Reader = nil
		return nil
	}
	r, ok := value.(storage.Reader)
	if !ok {
		return fmt.Errorf("expected file, got %s", value.Type())
	}
	f.Reader = r
	return nil
}

func Builtin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var rom, nvram, station fileArg
	memory := 64 << 20
	var epoch string
	if err := starlark.UnpackArgs("r3000", args, kwargs, "rom", &rom, "memory?", &memory, "nvram?", &nvram, "station_id?", &station, "start?", &epoch); err != nil {
		return nil, err
	}
	if rom.Reader == nil {
		return nil, fmt.Errorf("r3000: rom is required")
	}
	config := Config{ROM: rom.Reader, Memory: memory, NVRAM: nvram.Reader, StationID: station.Reader}
	if epoch != "" {
		var err error
		config.Start, err = time.Parse(time.RFC3339, epoch)
		if err != nil {
			return nil, err
		}
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	m, err := NewMachine(config)
	if err != nil {
		return nil, err
	}
	v := &machineValue{machine: m, ctx: resources.Context()}
	v.unregister, err = resources.Add(v)
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	return v, nil
}

type machineValue struct {
	machine    *Machine
	ctx        context.Context
	unregister func()
}

func (v *machineValue) Close() error {
	if v.unregister != nil {
		v.unregister()
	}
	return v.machine.Close()
}

func (*machineValue) String() string        { return "<R3000 Jazz machine>" }
func (*machineValue) Type() string          { return "r3000_machine" }
func (*machineValue) Freeze()               {}
func (*machineValue) Truth() starlark.Bool  { return starlark.True }
func (*machineValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: r3000_machine") }
func (*machineValue) AttrNames() []string {
	return []string{"attach_disk", "break_at", "clear_breaks", "clear_watch", "close", "key", "mop_status", "read", "read_effective", "registers", "run", "screenshot", "serial", "serve_mop", "step", "type", "watch_write"}
}

func (v *machineValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "attach_disk", "break_at", "clear_breaks", "clear_watch", "close", "key", "mop_status", "read", "read_effective", "registers", "run", "screenshot", "serial", "serve_mop", "step", "type", "watch_write":
		return starlark.NewBuiltin(name, v.call), nil
	default:
		return nil, nil
	}
}

func u32(value uint32) starlark.Int { return starlark.MakeUint64(uint64(value)) }

func registerTuple(regs [32]uint32) starlark.Tuple {
	out := make(starlark.Tuple, len(regs))
	for i, reg := range regs {
		out[i] = u32(reg)
	}
	return out
}

func recordStop(stop Stop) starlark.Value {
	return starfile.NewRecord(starlark.StringDict{
		"kind": starlark.String(stop.Kind), "pc": u32(stop.PC), "instruction": u32(stop.Instruction),
		"address": u32(stop.Address), "physical": u32(stop.Physical), "store": starlark.Bool(stop.Store),
		"value": u32(stop.Value), "exception": starlark.MakeInt(stop.Exception), "cycles": starlark.MakeUint64(stop.Cycles),
	})
}

func (v *machineValue) call(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	name, m := fn.Name(), v.machine
	if m.closed && name != "close" {
		return nil, fmt.Errorf("r3000: machine closed")
	}
	switch name {
	case "run":
		var budget uint64
		var exceptions bool
		if err := starlark.UnpackArgs(name, args, kwargs, "budget", &budget, "stop_on_exception?", &exceptions); err != nil {
			return nil, err
		}
		result, err := m.Run(v.ctx, budget, exceptions)
		if err != nil {
			return nil, err
		}
		return recordStop(result), nil
	case "step":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		result := m.step()
		if m.watchHit.Kind != "" {
			hit := m.watchHit
			m.watchHit = Stop{}
			hit.Instruction, hit.Cycles = result.Instruction, 1
			return recordStop(hit), nil
		}
		if m.fault != nil {
			return nil, m.fault
		}
		if result.Kind == "" {
			result.Kind = "step"
		}
		result.Cycles = 1
		return recordStop(result), nil
	case "break_at":
		var address uint32
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address); err != nil {
			return nil, err
		}
		return starlark.None, m.BreakAt(address)
	case "watch_write":
		var address, size uint32
		var nonzero bool
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size, "nonzero?", &nonzero); err != nil {
			return nil, err
		}
		return starlark.None, m.WatchWrite(address, size, nonzero)
	case "clear_watch":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		m.ClearWatch()
	case "clear_breaks":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		clear(m.breaks)
	case "close":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		return starlark.None, v.Close()
	case "registers":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		c := &m.cpu
		return starfile.NewRecord(starlark.StringDict{
			"pc": u32(c.pc), "next_pc": u32(c.next), "hi": u32(c.hi), "lo": u32(c.lo),
			"gpr": registerTuple(c.gpr), "cp0": registerTuple(c.cp0), "fpr": registerTuple(c.fpr), "fcsr": u32(c.fcsr),
			"cycles": starlark.MakeUint64(m.cycles), "led": starlark.MakeInt(int(m.led)),
		}), nil
	case "read", "read_effective":
		var address uint32
		var size int
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size); err != nil {
			return nil, err
		}
		if size < 0 || size > 8<<20 {
			return nil, fmt.Errorf("r3000: invalid read size %d", size)
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
	case "serve_mop":
		var softwareID string
		var file fileArg
		if err := starlark.UnpackArgs(name, args, kwargs, "name", &softwareID, "file", &file); err != nil {
			return nil, err
		}
		return starlark.None, m.ServeMOP(softwareID, file.Reader)
	case "mop_status":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		if m.mop == nil {
			return starlark.None, nil
		}
		return starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(m.mop.name), "entry": u32(m.mop.image.Entry),
			"bytes_acknowledged": starlark.MakeUint64(m.mop.acknowledged), "requests": starlark.MakeUint64(m.mop.requests),
			"complete": starlark.Bool(m.mop.complete),
		}), nil
	case "serial":
		port := 1
		if err := starlark.UnpackArgs(name, args, kwargs, "port?", &port); err != nil {
			return nil, err
		}
		c, err := m.Serial(port)
		if err != nil {
			return nil, err
		}
		return channelstar.New(fmt.Sprintf("jazz:com%d", port), c), nil
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
	case "screenshot":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		var output bytes.Buffer
		if err := png.Encode(&output, m.Screen()); err != nil {
			return nil, err
		}
		return &starfile.Bytes{Name: "jazz.png", Data: output.Bytes()}, nil
	case "key":
		var key string
		down := true
		if err := starlark.UnpackArgs(name, args, kwargs, "key", &key, "down?", &down); err != nil {
			return nil, err
		}
		return starlark.None, m.Key(key, down)
	case "type":
		var value string
		if err := starlark.UnpackArgs(name, args, kwargs, "text", &value); err != nil {
			return nil, err
		}
		return starlark.None, m.TypeText(value)
	}
	return starlark.None, nil
}
