package uefi

import (
	"bytes"
	"context"
	"fmt"
	"github.com/tinyrange/trex/emulator/cpu"
	"image"
	"image/png"
	"j5.nz/cc/hypervisor"
	"math"
	"time"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"golang.org/x/arch/arm64/arm64asm"
)

type value struct {
	machine   *Machine
	plugin    *starlark.Dict
	runThread *starlark.Thread
	native    *NativeExecution
}

func (*value) String() string        { return "uefi.arm64" }
func (*value) Type() string          { return "uefi.arm64" }
func (*value) Freeze()               {}
func (*value) Truth() starlark.Bool  { return starlark.True }
func (*value) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: uefi.arm64") }
func (*value) AttrNames() []string {
	return []string{"native_window", "native_key", "native_pointer", "native_close", "native_disk", "native_screenshot", "native_console", "native_mmio", "native_stats", "native_start", "native_run", "native_modules", "run", "rewrite", "register", "vector", "memory", "write_memory", "copy_memory", "fill_memory", "disassemble", "addresses", "block_device", "block_partition", "install_protocol", "configuration_table", "set_variable", "checkpoint", "restore", "plugin", "close"}
}
func record(kind string, fields starlark.StringDict) starlark.Value {
	return starlarkstruct.FromStringDict(starlark.String(kind), fields)
}
func numbers(values []uint64) starlark.Tuple {
	a := make(starlark.Tuple, len(values))
	for j, n := range values {
		a[j] = starlark.MakeUint64(n)
	}
	return a
}
func unsignedList(v starlark.Iterable) ([]uint64, error) {
	var result []uint64
	if v == nil {
		return result, nil
	}
	it := v.Iterate()
	defer it.Done()
	var item starlark.Value
	for it.Next(&item) {
		var n uint64
		if err := starlark.AsInt(item, &n); err != nil {
			return nil, err
		}
		result = append(result, n)
	}
	return result, nil
}
func stringList(v starlark.Iterable) ([]string, error) {
	var result []string
	if v == nil {
		return result, nil
	}
	it := v.Iterate()
	defer it.Done()
	var item starlark.Value
	for it.Next(&item) {
		s, ok := starlark.AsString(item)
		if !ok {
			return nil, fmt.Errorf("expected string, got %s", item.Type())
		}
		result = append(result, s)
	}
	return result, nil
}
func (v *value) Attr(name string) (starlark.Value, error) {
	if name == "plugin" {
		return v.plugin, nil
	}
	if name == "addresses" {
		if v.machine.memory == nil {
			return nil, fmt.Errorf("uefi: machine is closed")
		}
		fields := starlark.StringDict{}
		for n, a := range v.machine.Addresses() {
			fields[n] = starlark.MakeUint64(a)
		}
		return record("uefi.addresses", fields), nil
	}
	for _, n := range v.AttrNames() {
		if name == n {
			return starlark.NewBuiltin(name, v.call), nil
		}
	}
	return nil, nil
}
func (v *value) call(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	name := builtin.Name()
	if v.machine.memory == nil && name != "close" {
		return nil, fmt.Errorf("uefi: machine is closed")
	}
	switch name {
	case "native_window":
		title := "Validation OS"
		if err := starlark.UnpackArgs(name, args, kwargs, "title?", &title); err != nil {
			return nil, err
		}
		if v.native == nil {
			return nil, fmt.Errorf("native execution not started")
		}
		v.native.WindowsDebug = true
		return starlark.None, v.native.OpenWindow(title)
	case "native_key":
		var code uint16
		var down bool
		if err := starlark.UnpackArgs(name, args, kwargs, "code", &code, "down", &down); err != nil {
			return nil, err
		}
		if v.native == nil || v.native.Keyboard == nil {
			return nil, fmt.Errorf("native keyboard not attached")
		}
		return starlark.None, v.native.Keyboard.Key(code, down)
	case "native_pointer":
		var x, y uint32
		var buttons, previous uint8
		if err := starlark.UnpackArgs(name, args, kwargs, "x", &x, "y", &y, "buttons?", &buttons, "previous?", &previous); err != nil {
			return nil, err
		}
		if v.native == nil || v.native.Pointer == nil {
			return nil, fmt.Errorf("native pointer not attached")
		}
		if v.native.Display != nil {
			w, h := v.native.Display.Dimensions()
			if w > 0 && h > 0 {
				v.native.Pointer.SetDimensions(uint32(w), uint32(h))
			}
		}
		return starlark.None, v.native.Pointer.PointerEvent(x, y, buttons, previous)
	case "native_close":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		if v.native != nil {
			if err := v.native.Close(); err != nil {
				return nil, err
			}
			v.native = nil
		}
		return starlark.None, nil
	case "native_disk":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		if v.native == nil || v.native.Disk == nil {
			return nil, fmt.Errorf("native disk not attached")
		}
		return v.native.Disk.Snapshot()
	case "native_screenshot":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		if v.native == nil || v.native.Display == nil {
			return nil, fmt.Errorf("native RAMFB not attached")
		}
		frame, err := v.native.Display.Snapshot()
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(frame.Pixels); i += 4 {
			frame.Pixels[i], frame.Pixels[i+2] = frame.Pixels[i+2], frame.Pixels[i]
			frame.Pixels[i+3] = 255
		}
		img := &image.RGBA{Pix: frame.Pixels, Stride: frame.Width * 4, Rect: frame.Rect}
		var encoded bytes.Buffer
		if err := png.Encode(&encoded, img); err != nil {
			return nil, err
		}
		return &starfile.Bytes{Name: "native-screenshot.png", Data: encoded.Bytes()}, nil
	case "native_console":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		if v.native == nil {
			return nil, fmt.Errorf("native execution not started")
		}
		var out []starlark.Value
		for _, s := range v.native.Console {
			out = append(out, starlark.String(s))
		}
		return starlark.NewList(out), nil
	case "native_mmio":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		if v.native == nil {
			return nil, fmt.Errorf("native execution not started")
		}
		var out []starlark.Value
		for _, a := range v.native.MMIO {
			out = append(out, record("native.mmio", starlark.StringDict{"address": starlark.MakeUint64(a.Address), "value": starlark.MakeUint64(a.Value), "size": starlark.MakeInt(a.Size), "write": starlark.Bool(a.Write)}))
		}
		return starlark.NewList(out), nil
	case "native_stats":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		if v.native == nil {
			return nil, fmt.Errorf("native execution not started")
		}
		fields := starlark.StringDict{}
		for k, n := range v.native.Counts {
			fields[k] = starlark.MakeUint64(n)
		}
		for prefix, input := range map[string]hypervisor.InputDevice{"keyboard": v.native.Keyboard, "pointer": v.native.Pointer} {
			if input != nil {
				for k, n := range input.Stats() {
					fields[prefix+"_"+k] = starlark.MakeUint64(n)
				}
			}
		}
		irq, err := v.native.cpu.InterruptState()
		if err != nil {
			return nil, err
		}
		for k, n := range irq {
			fields["gic_"+k] = starlark.MakeUint64(n)
		}
		return record("native.stats", fields), nil
	case "native_start":
		var disk, ramfbBase uint64
		input := false
		config := hypervisor.NVMePCIConfiguration{ConfigBase: 0x20000000, ConfigSize: 0x1000000, WindowBase: 0x21000000, WindowSize: 0x1000000, BAR: 0x21000000, Device: 1, Interrupt: 78}
		if err := starlark.UnpackArgs(name, args, kwargs, "disk_handle?", &disk, "config_base?", &config.ConfigBase, "config_size?", &config.ConfigSize, "window_base?", &config.WindowBase, "window_size?", &config.WindowSize, "nvme_bar?", &config.BAR, "nvme_device?", &config.Device, "nvme_interrupt?", &config.Interrupt, "ramfb_base?", &ramfbBase, "input?", &input); err != nil {
			return nil, err
		}
		if v.native != nil {
			return nil, fmt.Errorf("native machine already started")
		}
		n, err := v.machine.StartNative(context.Background())
		if err != nil {
			return nil, err
		}
		if disk != 0 {
			if err := n.AttachNVMe(v.machine, disk, config); err != nil {
				_ = n.Close()
				return nil, err
			}
		}
		if ramfbBase != 0 {
			if err := n.AttachRAMFB(ramfbBase); err != nil {
				_ = n.Close()
				return nil, err
			}
		}
		if input {
			err := n.AttachInput(hypervisor.InputPCIConfiguration{Device: 2, BAR: 0x21004000, Interrupt: 79}, hypervisor.InputPCIConfiguration{Device: 3, BAR: 0x21008000, Interrupt: 80, Pointer: true, Width: 2560, Height: 1664})
			if err != nil {
				_ = n.Close()
				return nil, err
			}
		}
		v.native = n
		return starlark.None, nil
	case "native_modules":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		if v.native == nil {
			return nil, fmt.Errorf("native execution not started")
		}
		var modules []starlark.Value
		for _, m := range v.native.Modules {
			modules = append(modules, record("native.module", starlark.StringDict{"name": starlark.String(m.Name), "base": starlark.MakeUint64(m.Base), "size": starlark.MakeUint64(m.Size)}))
		}
		return starlark.NewList(modules), nil
	case "native_run":
		seconds := 5.0
		windowsDebug := false
		mmioLimit := 0
		if err := starlark.UnpackArgs(name, args, kwargs, "timeout?", &seconds, "windows_debug?", &windowsDebug, "mmio_trace?", &mmioLimit); err != nil {
			return nil, err
		}
		if seconds <= 0 || seconds > 3600 || math.IsNaN(seconds) {
			return nil, fmt.Errorf("native_run: timeout must be in (0,3600]")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds*float64(time.Second)))
		defer cancel()
		if v.native == nil {
			return nil, fmt.Errorf("call native_start before native_run")
		}
		if mmioLimit < 0 || mmioLimit > 4096 {
			return nil, fmt.Errorf("MMIO trace bound must be in [0,4096]")
		}
		v.native.MMIOLimit = mmioLimit
		v.native.MMIO = nil
		v.native.WindowsDebug = windowsDebug
		r, err := v.native.Run(ctx)
		if err != nil {
			return nil, err
		}
		return record("uefi.native_exit", starlark.StringDict{"reason": starlark.MakeUint64(uint64(r.Reason)), "pc": starlark.MakeUint64(r.PC), "syndrome": starlark.MakeUint64(r.Syndrome), "virtual_address": starlark.MakeUint64(r.VirtualAddress), "physical_address": starlark.MakeUint64(r.PhysicalAddress)}), nil
	case "rewrite":
		var address uint64
		var size int
		var digest starlark.Bytes
		var callback starlark.Callable
		label := "native routine"
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size, "digest", &digest, "callback", &callback, "name?", &label); err != nil {
			return nil, err
		}
		err := v.machine.AddDigestRewrite(address, size, []byte(digest), label, func(m *Machine) (uint64, error) {
			result, err := starlark.Call(v.runThread, callback, starlark.Tuple{v}, nil)
			if err != nil {
				return 0, err
			}
			if result == starlark.None {
				return 0, ErrDecline
			}
			var next uint64
			if err := starlark.AsInt(result, &next); err != nil {
				return 0, fmt.Errorf("rewrite: callback must return next PC: %w", err)
			}
			return next, nil
		})
		return starlark.None, err
	case "run":
		opts := RunOptions{Steps: 1_000_000}
		accelerate := true
		translationCache := true
		decodeCache := true
		var timeoutValue starlark.Value = starlark.MakeInt(0)
		var pcs, services, watches starlark.Iterable
		if err := starlark.UnpackArgs(name, args, kwargs, "steps?", &opts.Steps, "stop_pcs?", &pcs, "stop_services?", &services, "trace?", &opts.TraceLimit, "watch?", &watches, "timeout?", &timeoutValue, "accelerate?", &accelerate, "sample_interval?", &opts.SampleInterval, "translation_cache?", &translationCache, "decode_cache?", &decodeCache); err != nil {
			return nil, err
		}
		var err error
		opts.DisableAcceleration = !accelerate
		opts.DisableTranslationCache = !translationCache
		opts.DisableDecodeCache = !decodeCache
		timeout, ok := starlark.AsFloat(timeoutValue)
		if !ok {
			return nil, fmt.Errorf("run: timeout must be a number")
		}
		if math.IsNaN(timeout) || math.IsInf(timeout, 0) || timeout < 0 || timeout > float64(math.MaxInt64)/float64(time.Second) {
			return nil, fmt.Errorf("run: invalid timeout")
		}
		opts.Timeout = time.Duration(timeout * float64(time.Second))
		if timeout > 0 {
			var ok bool
			opts.Clock, ok = thread.Local("trex.runtime.clock").(interface{ Now() time.Duration })
			if !ok {
				return nil, fmt.Errorf("run: runtime monotonic clock unavailable")
			}
		}
		if watches != nil {
			it := watches.Iterate()
			defer it.Done()
			var item starlark.Value
			for it.Next(&item) {
				var address, size uint64
				var access string
				tuple, ok := item.(starlark.Tuple)
				if !ok {
					return nil, fmt.Errorf("watch: expected (address,size,access) tuple")
				}
				if err := starlark.UnpackArgs("watch", tuple, nil, "address", &address, "size", &size, "access", &access); err != nil {
					return nil, err
				}
				var flags cpu.Access
				for _, r := range access {
					switch r {
					case 'r':
						flags |= cpu.Read
					case 'w':
						flags |= cpu.Write
					case 'x':
						flags |= cpu.Execute
					default:
						return nil, fmt.Errorf("watch: invalid access %q", access)
					}
				}
				opts.Watches = append(opts.Watches, Watch{address, size, flags})
			}
		}
		opts.StopPCs, err = unsignedList(pcs)
		if err != nil {
			return nil, err
		}
		opts.StopServices, err = stringList(services)
		if err != nil {
			return nil, err
		}
		previousThread := v.runThread
		v.runThread = thread
		defer func() { v.runThread = previousThread }()
		r := v.machine.RunWithOptions(context.Background(), opts)
		return record("uefi.result", starlark.StringDict{"reason": starlark.String(r.Reason), "detail": starlark.String(r.Detail), "steps": starlark.MakeUint64(r.Steps), "pc": starlark.MakeUint64(r.PC), "map_key": starlark.MakeUint64(r.MapKey), "service": starlark.String(r.Service), "args": numbers(r.Args[:]), "trace": numbers(r.Trace)}), nil
	case "register":
		var register string
		native := false
		setting := starlark.Value(starlark.None)
		if err := starlark.UnpackArgs(name, args, kwargs, "name", &register, "value?", &setting, "native?", &native); err != nil {
			return nil, err
		}
		if native {
			if v.native == nil {
				return nil, fmt.Errorf("native execution not started")
			}
			if setting != starlark.None {
				return nil, fmt.Errorf("native register writes are not exposed")
			}
			n, err := v.native.Register(register)
			return starlark.MakeUint64(n), err
		}
		if setting != starlark.None {
			var n uint64
			if err := starlark.AsInt(setting, &n); err != nil {
				return nil, err
			}
			if err := v.machine.SetRegister(register, n); err != nil {
				return nil, err
			}
		}
		n, err := v.machine.Register(register)
		return starlark.MakeUint64(n), err
	case "vector":
		var index int
		setting := starlark.Value(starlark.None)
		if err := starlark.UnpackArgs(name, args, kwargs, "index", &index, "value?", &setting); err != nil {
			return nil, err
		}
		if setting != starlark.None {
			data, ok := setting.(starlark.Bytes)
			if !ok || len(data) != 16 {
				return nil, fmt.Errorf("vector: expected 16 bytes")
			}
			var value [16]byte
			copy(value[:], data)
			if err := v.machine.processor.SetVector(index, value); err != nil {
				return nil, err
			}
		}
		data, err := v.machine.processor.Vector(index)
		return starlark.Bytes(data[:]), err
	case "memory":
		native := false
		var address, size uint64
		physical := false
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size, "physical?", &physical, "native?", &native); err != nil {
			return nil, err
		}
		if size > 1<<20 {
			return nil, fmt.Errorf("memory: observation exceeds 1 MiB")
		}
		data := make([]byte, int(size))
		read := v.machine.ReadVirtualMemory
		if physical {
			read = v.machine.ReadMemory
		}
		if native {
			if v.native == nil {
				return nil, fmt.Errorf("native execution not started")
			}
			read = v.native.ReadVirtualMemory
			if physical {
				read = func(a uint64, b []byte) error { return v.native.ReadMemory(a, b, cpu.Read) }
			}
		}
		if err := read(address, data); err != nil {
			return nil, err
		}
		return starlark.Bytes(data), nil
	case "copy_memory":
		var destination, source, size uint64
		if err := starlark.UnpackArgs(name, args, kwargs, "destination", &destination, "source", &source, "size", &size); err != nil {
			return nil, err
		}
		return starlark.None, v.machine.CopyVirtualMemory(destination, source, size)
	case "fill_memory":
		var destination, size uint64
		var fill uint8
		if err := starlark.UnpackArgs(name, args, kwargs, "destination", &destination, "size", &size, "value?", &fill); err != nil {
			return nil, err
		}
		return starlark.None, v.machine.FillVirtualMemory(destination, size, fill)
	case "write_memory":
		var address uint64
		var data starlark.Bytes
		physical := false
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "data", &data, "physical?", &physical); err != nil {
			return nil, err
		}
		if physical {
			return starlark.None, v.machine.WriteMemory(address, []byte(data))
		}
		return starlark.None, v.machine.WriteVirtualMemory(address, []byte(data))
	case "disassemble":
		native := false
		var address uint64
		count := 1
		physical := false
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "count?", &count, "physical?", &physical, "native?", &native); err != nil {
			return nil, err
		}
		if count < 0 || count > 256 {
			return nil, fmt.Errorf("disassemble: count must be 0..256")
		}
		var result []starlark.Value
		for j := 0; j < count; j++ {
			pc := address + uint64(j)*4
			var data [4]byte
			read := v.machine.ReadVirtualMemory
			if physical {
				read = v.machine.ReadMemory
			}
			if native {
				if v.native == nil {
					return nil, fmt.Errorf("native execution not started")
				}
				read = v.native.ReadVirtualMemory
				if physical {
					read = func(a uint64, b []byte) error { return v.native.ReadMemory(a, b, cpu.Read) }
				}
			}
			if err := read(pc, data[:]); err != nil {
				return nil, err
			}
			inst, err := arm64asm.Decode(data[:])
			text := inst.String()
			if err != nil {
				text = err.Error()
			}
			result = append(result, record("instruction", starlark.StringDict{"pc": starlark.MakeUint64(pc), "bytes": starlark.Bytes(data[:]), "text": starlark.String(text)}))
		}
		return starlark.NewList(result), nil
	case "install_protocol":
		var identifier string
		var data starlark.Bytes
		var handle uint64
		if err := starlark.UnpackArgs(name, args, kwargs, "guid", &identifier, "data", &data, "handle?", &handle); err != nil {
			return nil, err
		}
		h, err := v.machine.InstallProtocol(handle, identifier, []byte(data))
		return starlark.MakeUint64(h), err
	case "set_variable":
		var variable Variable
		var data starlark.Bytes
		if err := starlark.UnpackArgs(name, args, kwargs, "name", &variable.Name, "guid", &variable.GUID, "attributes", &variable.Attributes, "data", &data); err != nil {
			return nil, err
		}
		variable.Data = []byte(data)
		return starlark.None, v.machine.SetVariable(variable)
	case "configuration_table":
		var identifier string
		var data starlark.Bytes
		typ := uint32(9)
		if err := starlark.UnpackArgs(name, args, kwargs, "guid", &identifier, "data", &data, "memory_type?", &typ); err != nil {
			return nil, err
		}
		p, err := v.machine.InstallConfigurationTable(identifier, []byte(data), typ)
		return starlark.MakeUint64(p), err
	case "checkpoint":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		state, err := v.machine.Checkpoint()
		if err != nil {
			return nil, err
		}
		c := &checkpointValue{owner: v, state: state}
		c.capture(v.plugin, map[starlark.Value]bool{})
		return c, nil
	case "restore":
		var c *checkpointValue
		if err := starlark.UnpackArgs(name, args, kwargs, "checkpoint", &c); err != nil {
			return nil, err
		}
		if c.owner != v {
			return nil, fmt.Errorf("uefi: checkpoint belongs to another machine")
		}
		if err := v.machine.Restore(c.state); err != nil {
			return nil, err
		}
		return starlark.None, c.restore()
	case "close":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		if v.native != nil {
			if err := v.native.Close(); err != nil {
				return nil, err
			}
			v.native = nil
		}
		v.machine.Close()
		return starlark.None, nil
	case "block_device":
		var source starfile.File
		opts := BlockOptions{}
		var path starlark.Bytes
		if err := starlark.UnpackArgs(name, args, kwargs, "source", &source, "device_path?", &path, "handle?", &opts.Handle, "read_only?", &opts.ReadOnly, "block_size?", &opts.BlockSize, "overlay_bytes?", &opts.OverlayBytes); err != nil {
			return nil, err
		}
		opts.DevicePath = []byte(path)
		handle, err := v.machine.AttachBlockDevice(source, opts)
		return starlark.MakeUint64(handle), err
	case "block_partition":
		var parent, handle uint64
		var offset, size int64
		var path starlark.Bytes
		if err := starlark.UnpackArgs(name, args, kwargs, "parent", &parent, "offset", &offset, "size", &size, "device_path", &path, "handle?", &handle); err != nil {
			return nil, err
		}
		h, err := v.machine.AttachBlockPartition(parent, offset, size, []byte(path), handle)
		return starlark.MakeUint64(h), err
	}
	return nil, fmt.Errorf("unknown method %s", name)
}

// Builtin creates a firmware execution context without starting a host VM.
func Builtin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var image starfile.File
	opts := Options{}
	var observe starlark.Callable
	var devicePath starlark.Bytes
	var eventKinds starlark.Value = starlark.None
	var registers *starlark.Dict
	if err := starlark.UnpackArgs("uefi", args, kwargs, "image", &image, "memory?", &opts.Memory, "memory_base?", &opts.MemoryBase, "image_base?", &opts.ImageBase, "stack_size?", &opts.StackSize, "time_unix?", &opts.TimeUnix, "image_path?", &opts.ImagePath, "registers?", &registers, "observe?", &observe, "device_path?", &devicePath, "event_kinds?", &eventKinds); err != nil {
		return nil, err
	}
	if eventKinds != starlark.None {
		iterable, ok := eventKinds.(starlark.Iterable)
		if !ok {
			return nil, fmt.Errorf("event_kinds must be an iterable of strings or None")
		}
		kinds, err := stringList(iterable)
		if err != nil {
			return nil, err
		}
		opts.EventKinds = append([]string{}, kinds...)
	}
	opts.DevicePath = []byte(devicePath)
	opts.Registers = map[string]uint64{}
	if registers != nil {
		for _, item := range registers.Items() {
			name, ok := starlark.AsString(item[0])
			if !ok {
				return nil, fmt.Errorf("register name must be string")
			}
			var n uint64
			if err := starlark.AsInt(item[1], &n); err != nil {
				return nil, err
			}
			opts.Registers[name] = n
		}
	}
	v := &value{plugin: starlark.NewDict(0)}
	if observe != nil {
		opts.Observe = func(e Event) error {
			event := record("uefi.event", starlark.StringDict{"machine": v, "kind": starlark.String(e.Kind), "name": starlark.String(e.Name), "text": starlark.String(e.Text), "pc": starlark.MakeUint64(e.PC), "args": numbers(e.Args[:]), "address": starlark.MakeUint64(e.Address), "size": starlark.MakeUint64(e.Size), "access": starlark.MakeUint64(uint64(e.Access)), "data": starlark.Bytes(e.Data)})
			_, err := starlark.Call(thread, observe, starlark.Tuple{event}, nil)
			return err
		}
	}
	m, err := New(image, opts)
	if err != nil {
		return nil, err
	}
	v.machine = m
	return v, nil
}

type savedDict struct {
	value *starlark.Dict
	items []starlark.Tuple
}
type savedList struct {
	value *starlark.List
	items []starlark.Value
}
type checkpointValue struct {
	owner *value
	state *Checkpoint
	dicts []savedDict
	lists []savedList
}

func (*checkpointValue) String() string        { return "uefi.checkpoint" }
func (*checkpointValue) Type() string          { return "uefi.checkpoint" }
func (*checkpointValue) Freeze()               {}
func (*checkpointValue) Truth() starlark.Bool  { return starlark.True }
func (*checkpointValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: uefi.checkpoint") }
func (c *checkpointValue) capture(v starlark.Value, seen map[starlark.Value]bool) {
	switch v := v.(type) {
	case *starlark.Dict:
		if seen[v] {
			return
		}
		seen[v] = true
		items := v.Items()
		c.dicts = append(c.dicts, savedDict{v, items})
		for _, pair := range items {
			c.capture(pair[0], seen)
			c.capture(pair[1], seen)
		}
	case *starlark.List:
		if seen[v] {
			return
		}
		seen[v] = true
		items := make([]starlark.Value, v.Len())
		for j := range items {
			items[j] = v.Index(j)
			c.capture(items[j], seen)
		}
		c.lists = append(c.lists, savedList{v, items})
	case starlark.Tuple:
		for _, item := range v {
			c.capture(item, seen)
		}
	}
}
func (c *checkpointValue) restore() error {
	for _, d := range c.dicts {
		if err := d.value.Clear(); err != nil {
			return err
		}
		for _, p := range d.items {
			if err := d.value.SetKey(p[0], p[1]); err != nil {
				return err
			}
		}
	}
	for _, l := range c.lists {
		if err := l.value.Clear(); err != nil {
			return err
		}
		for _, item := range l.items {
			if err := l.value.Append(item); err != nil {
				return err
			}
		}
	}
	return nil
}
