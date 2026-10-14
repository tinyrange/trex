package star

import (
	"fmt"
	"sync"

	scriptvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

// ARM64DeviceFactory builds a protocol primitive for a single platform instance.
type ARM64DeviceFactory func(vmmapi.ARM64Runtime, *starlark.Thread, *starlark.Dict) (vmmapi.ARM64Device, error)

var arm64Factories = struct {
	sync.RWMutex
	factories map[string]ARM64DeviceFactory
}{factories: map[string]ARM64DeviceFactory{}}

// RegisterARM64Device exposes a reusable protocol through ctx.device.
// Backends register their implementations during initialization.
func RegisterARM64Device(kind string, factory ARM64DeviceFactory) {
	arm64Factories.Lock()
	defer arm64Factories.Unlock()
	arm64Factories.factories[kind] = factory
}

type arm64PlatformValue struct{ platform vmmapi.ARM64Platform }

func (*arm64PlatformValue) String() string        { return "<vmm.arm64_platform>" }
func (*arm64PlatformValue) Type() string          { return "vmm_arm64_platform" }
func (*arm64PlatformValue) Freeze()               {}
func (*arm64PlatformValue) Truth() starlark.Bool  { return starlark.True }
func (*arm64PlatformValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: arm64_platform") }

type arm64DeviceValue struct {
	device vmmapi.ARM64Device
	owner  *arm64RuntimeValue
}

func (*arm64DeviceValue) String() string        { return "<vmm.arm64_device>" }
func (*arm64DeviceValue) Type() string          { return "vmm_arm64_device" }
func (*arm64DeviceValue) Freeze()               {}
func (*arm64DeviceValue) Truth() starlark.Bool  { return starlark.True }
func (*arm64DeviceValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: arm64_device") }

type arm64RuntimeValue struct {
	runtime vmmapi.ARM64Runtime
	thread  *starlark.Thread
	created []*arm64DeviceValue
}

func (*arm64RuntimeValue) String() string        { return "<vmm.arm64_runtime>" }
func (*arm64RuntimeValue) Type() string          { return "vmm_arm64_runtime" }
func (*arm64RuntimeValue) Freeze()               {}
func (*arm64RuntimeValue) Truth() starlark.Bool  { return starlark.True }
func (*arm64RuntimeValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: arm64_runtime") }
func (*arm64RuntimeValue) AttrNames() []string {
	return []string{"memory_base", "memory_size", "disks", "epoch_microseconds", "read_memory", "write_memory", "protect_memory", "counter", "irq", "read_register", "write_register", "emit", "device"}
}
func (v *arm64RuntimeValue) Attr(name string) (starlark.Value, error) {
	known := false
	for _, n := range v.AttrNames() {
		if name == n {
			known = true
			break
		}
	}
	if !known {
		return nil, nil
	}
	m := v.runtime.Machine()
	switch name {
	case "memory_base":
		return starlark.MakeUint64(m.ARM64Boot.MemoryBase), nil
	case "memory_size":
		return starlark.MakeInt64(m.Memory), nil
	case "epoch_microseconds":
		return starlark.MakeUint64(v.runtime.EpochMicroseconds()), nil
	case "disks":
		return (&vmmMachineValue{machine: m}).Attr("disks")
	}
	return starlark.NewBuiltin("arm64_runtime."+name, func(caller *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if caller != v.thread {
			return nil, fmt.Errorf("ARM64 runtime operations require its platform callback thread")
		}
		if err := v.runtime.Context().Err(); err != nil {
			return nil, err
		}
		switch name {
		case "read_memory":
			var address, size uint64
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size); err != nil {
				return nil, err
			}
			if size > 8<<20 {
				return nil, fmt.Errorf("read_memory: exceeds 8 MiB")
			}
			b, err := v.runtime.Memory(address, size, false)
			if err != nil {
				return nil, err
			}
			return starlark.Bytes(b), nil
		case "write_memory":
			var address uint64
			var value starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "data", &value); err != nil {
				return nil, err
			}
			b, err := starfile.BytesForValue(value, 8<<20)
			if err != nil {
				return nil, err
			}
			dest, err := v.runtime.Memory(address, uint64(len(b)), true)
			if err != nil {
				return nil, err
			}
			copy(dest, b)
			return starlark.None, nil
		case "protect_memory":
			var address, size uint64
			read, write, execute := true, false, true
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size, "read?", &read, "write?", &write, "execute?", &execute); err != nil {
				return nil, err
			}
			return starlark.None, v.runtime.Protect(address, size, read, write, execute)
		case "counter":
			if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
				return nil, err
			}
			t, f, err := v.runtime.Counter()
			return starlark.Tuple{starlark.MakeUint64(t), starlark.MakeUint64(f)}, err
		case "irq":
			var id uint32
			var level bool
			if err := starlark.UnpackArgs(name, args, kwargs, "id", &id, "level", &level); err != nil {
				return nil, err
			}
			return starlark.None, v.runtime.SetSPI(id, level)
		case "read_register", "write_register":
			var id uint32
			var value uint64
			var err error
			if name == "read_register" {
				err = starlark.UnpackArgs(name, args, kwargs, "id", &id)
			} else {
				err = starlark.UnpackArgs(name, args, kwargs, "id", &id, "value", &value)
			}
			if err != nil {
				return nil, err
			}
			if id > 30 {
				return nil, fmt.Errorf("register must be X0..X30")
			}
			if name == "write_register" {
				return starlark.None, v.runtime.SetRegister(id, value)
			}
			value, err = v.runtime.Register(id)
			return starlark.MakeUint64(value), err
		case "emit":
			var kind string
			var payload starlark.Value = starlark.None
			if err := starlark.UnpackArgs(name, args, kwargs, "kind", &kind, "payload?", &payload); err != nil {
				return nil, err
			}
			native, err := scriptvalue.Native(payload)
			if err != nil {
				return nil, err
			}
			v.runtime.Emit(kind, native)
			return starlark.None, nil
		case "device":
			var kind string
			var options *starlark.Dict
			if err := starlark.UnpackArgs(name, args, kwargs, "kind", &kind, "options", &options); err != nil {
				return nil, err
			}
			arm64Factories.RLock()
			factory := arm64Factories.factories[kind]
			arm64Factories.RUnlock()
			if factory == nil {
				return nil, fmt.Errorf("unsupported ARM64 device %q", kind)
			}
			d, err := factory(v.runtime, v.thread, options)
			if err != nil {
				return nil, err
			}
			device := &arm64DeviceValue{device: d, owner: v}
			v.created = append(v.created, device)
			return device, nil
		}
		return nil, fmt.Errorf("unknown runtime operation %q", name)
	}), nil
}

type starARM64Devices struct {
	devices []vmmapi.ARM64Device
	thread  *starlark.Thread
	hvc     starlark.Callable
}

func (d *starARM64Devices) Contains(a uint64, n int) bool {
	for _, dev := range d.devices {
		if dev.Contains(a, n) {
			return true
		}
	}
	return false
}
func (d *starARM64Devices) Read(a uint64, n int) (uint64, error) {
	for _, dev := range d.devices {
		if dev.Contains(a, n) {
			return dev.Read(a, n)
		}
	}
	return 0, fmt.Errorf("unmapped MMIO read%d at %#x", n, a)
}
func (d *starARM64Devices) Write(a uint64, n int, v uint64) error {
	for _, dev := range d.devices {
		if dev.Contains(a, n) {
			return dev.Write(a, n, v)
		}
	}
	return fmt.Errorf("unmapped MMIO write%d at %#x", n, a)
}
func (d *starARM64Devices) Poll() error {
	for _, dev := range d.devices {
		if p, ok := dev.(interface{ Poll() error }); ok {
			if err := p.Poll(); err != nil {
				return err
			}
		}
	}
	return nil
}
func (d *starARM64Devices) Flush() {
	for _, dev := range d.devices {
		if p, ok := dev.(interface{ Flush() }); ok {
			p.Flush()
		}
	}
}
func (d *starARM64Devices) Close() error {
	var first error
	for i := len(d.devices) - 1; i >= 0; i-- {
		if c, ok := d.devices[i].(interface{ Close() error }); ok {
			if err := c.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}
func (d *starARM64Devices) HVC(imm uint16, function uint64) (bool, error) {
	if d.hvc == nil {
		return false, nil
	}
	v, err := starlark.Call(d.thread, d.hvc, starlark.Tuple{starlark.MakeUint(uint(imm)), starlark.MakeUint64(function)}, nil)
	if err != nil {
		return false, err
	}
	b, ok := v.(starlark.Bool)
	if !ok {
		return false, fmt.Errorf("HVC callback must return bool")
	}
	return bool(b), nil
}

func arm64PlatformBuiltin(parent *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var create starlark.Callable
	var distributor, redistributor uint64
	if err := starlark.UnpackArgs("arm64_platform", args, kwargs, "create", &create, "gic_distributor?", &distributor, "gic_redistributor?", &redistributor); err != nil {
		return nil, err
	}
	if (distributor == 0) != (redistributor == 0) || distributor&0xffff != 0 || redistributor&0xffff != 0 || distributor != 0 && distributor == redistributor {
		return nil, fmt.Errorf("arm64_platform: distinct aligned GIC ranges required")
	}
	p := vmmapi.ARM64Platform{GICDistributor: distributor, GICRedistributor: redistributor}
	p.New = func(runtime vmmapi.ARM64Runtime) (vmmapi.ARM64Device, error) {
		thread := &starlark.Thread{Name: "ARM64 platform"}
		thread.Print = func(_ *starlark.Thread, s string) { runtime.Emit("platform.log", s) }
		go func() { <-runtime.Context().Done(); thread.Cancel("VM stopped") }()
		ctx := &arm64RuntimeValue{runtime: runtime, thread: thread}
		retained := map[*arm64DeviceValue]bool{}
		complete := false
		defer func() {
			for i := len(ctx.created) - 1; i >= 0; i-- {
				v := ctx.created[i]
				if !complete || !retained[v] {
					if c, ok := v.device.(interface{ Close() error }); ok {
						_ = c.Close()
					}
				}
			}
		}()
		value, err := starlark.Call(thread, create, starlark.Tuple{ctx}, nil)
		if err != nil {
			return nil, err
		}
		dict, ok := value.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("platform create must return dictionary with devices and optional hvc")
		}
		var devices *starlark.List
		var hvc starlark.Value = starlark.None
		if err := starlark.UnpackArgs("platform result", nil, dict.Items(), "devices", &devices, "hvc?", &hvc); err != nil {
			return nil, err
		}
		d := &starARM64Devices{thread: thread}
		if hvc != starlark.None {
			d.hvc, ok = hvc.(starlark.Callable)
			if !ok {
				return nil, fmt.Errorf("hvc must be callable")
			}
		}
		for i := 0; i < devices.Len(); i++ {
			v, ok := devices.Index(i).(*arm64DeviceValue)
			if !ok {
				return nil, fmt.Errorf("platform devices must be MMIO or native device values")
			}
			if v.owner != nil && v.owner != ctx {
				return nil, fmt.Errorf("native device belongs to another platform instance")
			}
			if retained[v] {
				return nil, fmt.Errorf("duplicate platform device")
			}
			retained[v] = true
			if c, ok := v.device.(*starMMIO); ok {
				clone := *c
				clone.thread = thread
				d.devices = append(d.devices, &clone)
			} else {
				d.devices = append(d.devices, v.device)
			}
		}
		complete = true
		return d, nil
	}
	return &arm64PlatformValue{p}, nil
}

type starMMIO struct {
	address, size uint64
	widths        uint64
	read, write   starlark.Callable
	thread        *starlark.Thread
}

func (d *starMMIO) Contains(a uint64, n int) bool {
	return n > 0 && n <= 8 && d.widths&(1<<n) != 0 && a%uint64(n) == 0 && a >= d.address && uint64(n) <= d.size && a-d.address <= d.size-uint64(n)
}
func (d *starMMIO) Read(a uint64, n int) (uint64, error) {
	if d.read == nil {
		return 0, fmt.Errorf("MMIO read is unsupported")
	}
	v, err := starlark.Call(d.thread, d.read, starlark.Tuple{starlark.MakeUint64(a - d.address), starlark.MakeInt(n)}, nil)
	if err != nil {
		return 0, err
	}
	var x uint64
	if err := starlark.AsInt(v, &x); err != nil {
		return 0, err
	}
	if n < 8 && x>>(uint(n)*8) != 0 {
		return 0, fmt.Errorf("MMIO read exceeds access width")
	}
	return x, nil
}
func (d *starMMIO) Write(a uint64, n int, x uint64) error {
	if n < 8 && x>>(uint(n)*8) != 0 {
		return fmt.Errorf("MMIO write exceeds access width")
	}
	if d.write == nil {
		return fmt.Errorf("MMIO write is unsupported")
	}
	v, err := starlark.Call(d.thread, d.write, starlark.Tuple{starlark.MakeUint64(a - d.address), starlark.MakeInt(n), starlark.MakeUint64(x)}, nil)
	if err == nil && v != starlark.None {
		return fmt.Errorf("MMIO write must return None")
	}
	return err
}
func mmioBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	d := &starMMIO{widths: 1<<1 | 1<<2 | 1<<4 | 1<<8}
	var read, write starlark.Value = starlark.None, starlark.None
	var widths *starlark.List
	if err := starlark.UnpackArgs("mmio", args, kwargs, "address", &d.address, "size", &d.size, "read?", &read, "write?", &write, "widths?", &widths); err != nil {
		return nil, err
	}
	if d.size == 0 || d.address > ^uint64(0)-d.size {
		return nil, fmt.Errorf("mmio: invalid range")
	}
	if widths != nil {
		d.widths = 0
		for i := 0; i < widths.Len(); i++ {
			var n int
			if err := starlark.AsInt(widths.Index(i), &n); err != nil {
				return nil, err
			}
			if n != 1 && n != 2 && n != 4 && n != 8 {
				return nil, fmt.Errorf("mmio: width must be 1,2,4,8")
			}
			d.widths |= 1 << n
		}
	}
	for _, row := range []struct {
		value starlark.Value
		dest  *starlark.Callable
	}{{read, &d.read}, {write, &d.write}} {
		if row.value != starlark.None {
			c, ok := row.value.(starlark.Callable)
			if !ok {
				return nil, fmt.Errorf("mmio: callbacks must be callable")
			}
			*row.dest = c
		}
	}
	return &arm64DeviceValue{device: d}, nil
}
