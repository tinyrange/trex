// Package processor exposes bounded instruction experiments independently of
// executable formats, operating-system APIs and host processes.
package processor

import (
	"fmt"
	"io"
	"strings"

	"github.com/tinyrange/trex/emulator/amd64"
	"github.com/tinyrange/trex/emulator/arm64"
	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type value struct {
	cpu    cpu.Processor
	memory *cpu.AddressSpace
	plugin *starlark.Dict
	closed bool
}

func (*value) String() string        { return "emulator.processor" }
func (*value) Type() string          { return "emulator.processor" }
func (*value) Freeze()               {}
func (*value) Truth() starlark.Bool  { return starlark.True }
func (*value) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: emulator.processor") }
func (*value) AttrNames() []string {
	return []string{"architecture", "plugin", "map", "read", "write", "get_register", "set_register", "run", "close"}
}
func (v *value) Attr(name string) (starlark.Value, error) {
	if name == "plugin" {
		return v.plugin, nil
	}
	if name == "architecture" {
		if v.closed {
			return starlark.None, nil
		}
		return starlark.String(v.cpu.Architecture().Name), nil
	}
	for _, n := range v.AttrNames()[2:] {
		if n == name {
			return starlark.NewBuiltin("processor."+name, v.call), nil
		}
	}
	return nil, nil
}

func (v *value) call(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	name := strings.TrimPrefix(builtin.Name(), "processor.")
	if name == "close" {
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		v.cpu, v.memory, v.closed = nil, nil, true
		return starlark.None, nil
	}
	if v.closed {
		return nil, fmt.Errorf("processor: context is closed")
	}
	switch name {
	case "map":
		var address uint64
		var size int
		var data starlark.Value = starlark.None
		access := "rw"
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size, "data?", &data, "access?", &access); err != nil {
			return nil, err
		}
		if size < 1 || size > 64<<20 {
			return nil, fmt.Errorf("processor: mapping size must be 1..64 MiB")
		}
		var flags cpu.Access
		for _, ch := range access {
			switch ch {
			case 'r':
				flags |= cpu.Read
			case 'w':
				flags |= cpu.Write
			case 'x':
				flags |= cpu.Execute
			default:
				return nil, fmt.Errorf("processor: invalid memory permission")
			}
		}
		b := make([]byte, size)
		if data != starlark.None {
			switch data := data.(type) {
			case starlark.Bytes:
				if len(data) > size {
					return nil, fmt.Errorf("processor: initial bytes exceed mapping")
				}
				copy(b, data)
			case storage.Reader:
				if data.Size() < 0 || data.Size() > int64(size) {
					return nil, fmt.Errorf("processor: initial file exceeds mapping")
				}
				if _, err := io.ReadFull(io.NewSectionReader(data, 0, data.Size()), b[:data.Size()]); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("processor: initial data must be bytes or file")
			}
		}
		if err := v.memory.Map(address, b, flags); err != nil {
			return nil, err
		}
		return starlark.None, nil
	case "read":
		var address uint64
		var size int
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size); err != nil {
			return nil, err
		}
		if size < 0 || size > 1<<20 {
			return nil, fmt.Errorf("processor: read exceeds 1 MiB")
		}
		b := make([]byte, size)
		if err := v.memory.ReadMemory(address, b, cpu.Read); err != nil {
			return nil, err
		}
		return starlark.Bytes(b), nil
	case "write":
		var address uint64
		var data starlark.Bytes
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "data", &data); err != nil {
			return nil, err
		}
		if len(data) > 1<<20 {
			return nil, fmt.Errorf("processor: write exceeds 1 MiB")
		}
		if err := v.memory.WriteMemory(address, []byte(data)); err != nil {
			return nil, err
		}
		return starlark.None, nil
	case "get_register":
		var register string
		if err := starlark.UnpackArgs(name, args, kwargs, "name", &register); err != nil {
			return nil, err
		}
		n, err := v.cpu.Register(register)
		if err != nil {
			return nil, err
		}
		return starlark.MakeUint64(n), nil
	case "set_register":
		var register string
		var n uint64
		if err := starlark.UnpackArgs(name, args, kwargs, "name", &register, "value", &n); err != nil {
			return nil, err
		}
		if err := v.cpu.SetRegister(register, n); err != nil {
			return nil, err
		}
		return starlark.None, nil
	case "run":
		var maximum uint64
		var addresses *starlark.List
		if err := starlark.UnpackArgs(name, args, kwargs, "maximum_steps", &maximum, "stop_at?", &addresses); err != nil {
			return nil, err
		}
		if maximum == 0 || maximum > 10000000 || addresses != nil && addresses.Len() > 4096 {
			return nil, fmt.Errorf("processor: invalid execution/breakpoint bound")
		}
		stops := map[uint64]bool{}
		if addresses != nil {
			for i := 0; i < addresses.Len(); i++ {
				var address uint64
				if err := starlark.AsInt(addresses.Index(i), &address); err != nil {
					return nil, err
				}
				stops[address] = true
			}
		}
		result := func(reason, detail string, steps uint64) starlark.Value {
			return starfile.NewRecord(starlark.StringDict{"reason": starlark.String(reason), "detail": starlark.String(detail), "steps": starlark.MakeUint64(steps), "pc": starlark.MakeUint64(v.cpu.PC())})
		}
		for i := uint64(0); i < maximum; i++ {
			if stops[v.cpu.PC()] {
				return result("breakpoint", "", i), nil
			}
			effect, err := v.cpu.Step(v.memory)
			if err != nil {
				return result("fault", err.Error(), i), nil
			}
			if effect == cpu.Halt {
				return result("halt", "", i+1), nil
			}
		}
		if stops[v.cpu.PC()] {
			return result("breakpoint", "", maximum), nil
		}
		return result("budget", "instruction bound reached", maximum), nil
	}
	return nil, fmt.Errorf("processor: unknown method %s", name)
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	architecture := "arm64"
	memory := uint64(64 << 20)
	if err := starlark.UnpackArgs("processor", args, kwargs, "architecture?", &architecture, "memory?", &memory); err != nil {
		return nil, err
	}
	if memory == 0 || memory > 1<<30 {
		return nil, fmt.Errorf("processor: invalid memory bound")
	}
	var p cpu.Processor
	switch architecture {
	case "arm64":
		p = arm64.New()
	case "amd64":
		p = &amd64.CPU{}
	default:
		return nil, fmt.Errorf("processor: unsupported architecture %q", architecture)
	}
	return &value{cpu: p, memory: cpu.NewAddressSpace(memory), plugin: starlark.NewDict(0)}, nil
}
