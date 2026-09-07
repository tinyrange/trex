// Package machine connects portable processors to a bounded Starlark execution
// environment. Architecture-specific instructions and Windows call marshaling
// are separate from memory, module records and semantic import dispatch.
package machine

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strings"

	binaryapi "github.com/tinyrange/trex/binary"
	"github.com/tinyrange/trex/emulator/amd64"
	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/emulator/peimage"
	"github.com/tinyrange/trex/emulator/windowsabi"
	starvalue "github.com/tinyrange/trex/script/value"
	windowsapi "github.com/tinyrange/trex/windows"
	"go.starlark.net/starlark"
)

type imported struct {
	module, name string
	ordinal      uint16
	iat, address uint64
}

type module struct {
	name    string
	image   *peimage.Image
	exports []windowsapi.PEExport
	tls     peimage.TLS
}

func (item module) record(primary bool) starlark.Value {
	callbacks := make([]starlark.Value, len(item.tls.Callbacks))
	for i, address := range item.tls.Callbacks {
		callbacks[i] = starlark.MakeUint64(address)
	}
	return record(starlark.StringDict{"name": starlark.String(item.name), "base": starlark.MakeUint64(item.image.Base), "entry": starlark.MakeUint64(item.image.Base + uint64(item.image.EntryRVA)), "primary": starlark.Bool(primary), "tls_index": starlark.MakeUint64(item.tls.IndexAddress), "tls_template": starlark.Bytes(item.tls.Template), "tls_zero_fill": starlark.MakeUint(uint(item.tls.ZeroFill)), "tls_callbacks": starlark.NewList(callbacks)})
}

type hook struct {
	module, name string
	argc         int
	callback     starlark.Callable
}

type Machine struct {
	processor                                  cpu.Processor
	memory                                     *cpu.AddressSpace
	entry, stackLow, stackHigh, nextAllocation uint64
	limit, memoryLimit                         uint64
	modules                                    []module
	imports                                    map[uint64]imported
	hooks                                      map[uint64]hook
	provided                                   map[string]uint64
	pluginStates                               []starlark.Value
	allocations                                map[uint64]bool
	allocationNames                            map[uint64]string
	recent                                     [64]uint64
	recentCount                                uint64
	frozen                                     bool
	transferSerial                             uint64
	hookDepth                                  int
	pendingStop, pendingStopDetail             string
	diagnostics
}

const stackTop = uint64(0x7fffff000000)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	imageValue, codeValue := starlark.Value(starlark.None), starlark.Value(starlark.None)
	base := starlark.MakeUint64(0x1000)
	entry := starlark.Value(starlark.None)
	name := "main"
	limit, memoryLimit, stackSize := 2000000, 32<<20, 1<<20
	diagnostic := diagnostics{traceLimit: 4096, profileInterval: 256, profileLimit: 16384}
	gsBase, fsBase := starlark.MakeUint64(0), starlark.MakeUint64(0)
	if err := starlark.UnpackArgs("machine", args, kwargs, "image?", &imageValue, "code?", &codeValue, "base?", &base, "entry?", &entry, "image_name?", &name, "instruction_limit?", &limit, "memory_limit?", &memoryLimit, "stack_size?", &stackSize, "gs_base?", &gsBase, "fs_base?", &fsBase, "trace?", &diagnostic.traceEnabled, "trace_limit?", &diagnostic.traceLimit, "profile?", &diagnostic.profileEnabled, "profile_interval?", &diagnostic.profileInterval, "profile_limit?", &diagnostic.profileLimit); err != nil {
		return nil, err
	}
	if (imageValue == starlark.None) == (codeValue == starlark.None) {
		return nil, fmt.Errorf("machine: provide exactly one of image or code")
	}
	if limit <= 0 || memoryLimit <= 0 || stackSize <= 0 || stackSize > memoryLimit {
		return nil, fmt.Errorf("machine: invalid resource budget")
	}
	if diagnostic.traceLimit < 1 || diagnostic.traceLimit > 65536 || diagnostic.profileInterval < 1 || diagnostic.profileLimit < 1 || diagnostic.profileLimit > 65536 {
		return nil, fmt.Errorf("machine: invalid diagnostic budget")
	}
	m := &Machine{processor: &amd64.CPU{}, memory: cpu.NewAddressSpace(uint64(memoryLimit)), limit: uint64(limit), memoryLimit: uint64(memoryLimit), imports: make(map[uint64]imported), hooks: make(map[uint64]hook), nextAllocation: 0x600000000000, stackHigh: stackTop, stackLow: stackTop - uint64(stackSize)}
	m.diagnostics = diagnostic
	m.profileCounts = make(map[uint64]uint64)
	if imageValue != starlark.None {
		data, err := binaryapi.BytesForValue(imageValue)
		if err != nil {
			return nil, err
		}
		loaded, err := m.load(data, name)
		if err != nil {
			return nil, err
		}
		m.entry = loaded.image.Base + uint64(loaded.image.EntryRVA)
	} else {
		address, ok := base.Uint64()
		if !ok {
			return nil, fmt.Errorf("machine: invalid base")
		}
		data, err := binaryapi.BytesForValue(codeValue)
		if err != nil {
			return nil, err
		}
		if err := m.memory.Map(address, data, cpu.Read|cpu.Execute); err != nil {
			return nil, err
		}
		m.entry = address
	}
	if entry != starlark.None {
		value, err := unsigned(entry)
		if err != nil {
			return nil, err
		}
		m.entry = value
	}
	if err := m.memory.Map(m.stackLow, make([]byte, stackSize), cpu.Read|cpu.Write); err != nil {
		return nil, err
	}
	for _, segment := range []struct {
		name  string
		value starlark.Int
	}{{"gs_base", gsBase}, {"fs_base", fsBase}} {
		address, ok := segment.value.Uint64()
		if !ok {
			return nil, fmt.Errorf("machine: invalid %s", segment.name)
		}
		if address != 0 {
			if err := m.memory.Map(address, make([]byte, 4096), cpu.Read|cpu.Write); err != nil {
				return nil, err
			}
			if err := m.processor.SetRegister(segment.name, address); err != nil {
				return nil, err
			}
		}
	}
	m.processor.SetPC(m.entry)
	if err := m.processor.SetRegister("rsp", m.stackHigh); err != nil {
		return nil, err
	}
	return m, nil
}

func canonical(name string) string {
	name = strings.ToLower(strings.ReplaceAll(name, "\\", "/"))
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	if name != "" && !strings.Contains(name, ".") {
		name += ".dll"
	}
	return name
}

func unsigned(value starlark.Value) (uint64, error) {
	if n, ok := value.(starlark.Int); ok {
		if v, ok := n.Uint64(); ok {
			return v, nil
		}
	}
	return 0, fmt.Errorf("machine: expected unsigned 64-bit integer, got %s", value)
}

func (m *Machine) load(data []byte, name string) (module, error) {
	name = canonical(name)
	if name == "" {
		return module{}, fmt.Errorf("machine: empty module name")
	}
	for _, loaded := range m.modules {
		if loaded.name == name {
			return loaded, nil
		}
	}
	image, err := peimage.Parse(data, m.memoryLimit)
	if err != nil {
		return module{}, err
	}
	if image.Architecture != m.processor.Architecture() {
		return module{}, fmt.Errorf("machine: %s image cannot be loaded into %s processor", image.Architecture.Name, m.processor.Architecture().Name)
	}
	base, err := m.imageBase(image.Base, uint64(len(image.Data)))
	if err != nil {
		return module{}, err
	}
	// Apply relocations before reading TLS VAs or resolving native imports.
	if err := image.Rebase(base); err != nil {
		return module{}, fmt.Errorf("machine: relocate %s: %w", name, err)
	}
	imports, err := windowsapi.PEImports(data)
	if err != nil {
		return module{}, err
	}
	exports, err := windowsapi.PEExports(data)
	if err != nil {
		return module{}, err
	}
	tls, err := image.TLS()
	if err != nil {
		return module{}, err
	}
	if uint64(len(tls.Template))+uint64(tls.ZeroFill) > m.memoryLimit {
		return module{}, fmt.Errorf("machine: TLS data exceeds memory budget")
	}
	// Resolve each IAT slot to a stable semantic-dispatch address. Missing APIs
	// remain explicit stops until a module or plugin actually supplies them.
	newImports := make([]imported, 0, len(imports))
	for _, item := range imports {
		if uint64(item.IATRVA)+8 > uint64(len(image.Data)) {
			return module{}, fmt.Errorf("machine: IAT exceeds image")
		}
		address := uint64(0x7fff00000000) + uint64(len(m.imports)+len(newImports))*16
		binary.LittleEndian.PutUint64(image.Data[item.IATRVA:], address)
		newImports = append(newImports, imported{canonical(item.DLL), item.Name, item.Ordinal, image.Base + uint64(item.IATRVA), address})
	}
	if err := m.memory.Map(image.Base, image.Data, cpu.Read|cpu.Write|cpu.Execute); err != nil {
		return module{}, err
	}
	loaded := module{name, image, exports, tls}
	m.modules = append(m.modules, loaded)
	for _, imported := range newImports {
		m.imports[imported.address] = imported
	}
	return loaded, nil
}

func (m *Machine) String() string {
	return fmt.Sprintf("<emulator.machine architecture=%s pc=%#x>", m.processor.Architecture().Name, m.processor.PC())
}
func (*Machine) Type() string          { return "emulator.machine" }
func (m *Machine) Freeze()             { m.frozen = true }
func (*Machine) Truth() starlark.Bool  { return starlark.True }
func (*Machine) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: emulator.machine") }
func (*Machine) AttrNames() []string {
	names := []string{"architecture", "pointer_size", "entry", "stack", "imports", "modules", "mappings", "run", "call", "call_export", "get_register", "set_register", "read", "write", "allocate", "free", "load_module", "hook", "provide_export", "resolve_export", "use", "segment_base", "read_cstring", "read_cbytes"}
	for _, codec := range binaryapi.ScalarCodecs {
		names = append(names, "read_"+codec.Name, "write_"+codec.Name)
	}
	names = append(names, "invoke", "read_pointer", "write_pointer", "protect", "snapshot", "profile", "local_unwind", "transfer", "arguments", "stop")
	sort.Strings(names)
	return names
}

func record(values starlark.StringDict) starlark.Value { return starvalue.NewRecord(values) }

func (m *Machine) Attr(name string) (starlark.Value, error) {
	if name == "read_pointer" {
		return m.Attr("read_u64le")
	}
	if name == "write_pointer" {
		return m.Attr("write_u64le")
	}
	switch name {
	case "architecture":
		return starlark.String(m.processor.Architecture().Name), nil
	case "pointer_size":
		return starlark.MakeInt(m.processor.Architecture().PointerSize), nil
	case "entry":
		return starlark.MakeUint64(m.entry), nil
	case "stack":
		return record(starlark.StringDict{"low": starlark.MakeUint64(m.stackLow), "high": starlark.MakeUint64(m.stackHigh)}), nil
	case "imports":
		keys := make([]uint64, 0, len(m.imports))
		for key := range m.imports {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		var values []starlark.Value
		for _, key := range keys {
			item := m.imports[key]
			values = append(values, record(starlark.StringDict{"module": starlark.String(item.module), "name": starlark.String(item.name), "ordinal": starlark.MakeUint(uint(item.ordinal)), "iat": starlark.MakeUint64(item.iat), "address": starlark.MakeUint64(item.address)}))
		}
		return starlark.NewList(values), nil
	case "modules":
		var values []starlark.Value
		for i, item := range m.modules {
			values = append(values, item.record(i == 0))
		}
		return starlark.NewList(values), nil
	case "mappings":
		var values []starlark.Value
		for _, mapping := range m.memory.Mappings() {
			name := m.allocationNames[mapping.Base]
			if name == "" {
				name = "memory"
				if mapping.Base == m.stackLow {
					name = "stack"
				}
				for _, module := range m.modules {
					if mapping.Base == module.image.Base {
						name = "module:" + module.name
					}
				}
			}
			values = append(values, record(starlark.StringDict{
				"name": starlark.String(name), "start": starlark.MakeUint64(mapping.Start),
				"size": starlark.MakeUint64(mapping.Size), "allocation_base": starlark.MakeUint64(mapping.Base),
				"readable":   starlark.Bool(mapping.Access&cpu.Read != 0),
				"writable":   starlark.Bool(mapping.Access&cpu.Write != 0),
				"executable": starlark.Bool(mapping.Access&cpu.Execute != 0),
			}))
		}
		return starlark.NewList(values), nil
	}
	for _, attr := range m.AttrNames() {
		if attr == name {
			return starlark.NewBuiltin("machine."+name, m.method), nil
		}
	}
	return nil, nil
}

func (m *Machine) result(reason string, steps uint64, detail string) starlark.Value {
	value, _ := m.processor.Register("rax")
	var recent []starlark.Value
	count := min(m.recentCount, uint64(len(m.recent)))
	for i := m.recentCount - count; i < m.recentCount; i++ {
		recent = append(recent, starlark.MakeUint64(m.recent[i%uint64(len(m.recent))]))
	}
	return record(starlark.StringDict{"reason": starlark.String(reason), "value": starlark.MakeUint64(value), "steps": starlark.MakeUint64(steps), "pc": starlark.MakeUint64(m.processor.PC()), "eip": starlark.MakeUint64(m.processor.PC()), "detail": starlark.String(detail), "recent": starlark.NewList(recent), "trace": m.traceValue()})
}

func (m *Machine) run(thread *starlark.Thread) (starlark.Value, error) {
	return m.runUntil(thread, nil)
}

// runUntil stops before the requested instruction, without changing guest state.
func (m *Machine) runUntil(thread *starlark.Thread, until *uint64) (starlark.Value, error) {
	savedStop, savedDetail := m.pendingStop, m.pendingStopDetail
	m.pendingStop, m.pendingStopDetail = "", ""
	defer func() { m.pendingStop, m.pendingStopDetail = savedStop, savedDetail }()
	for steps := uint64(0); steps < m.limit; steps++ {
		pc := m.processor.PC()
		if until != nil && pc == *until {
			return m.result("breakpoint", steps, ""), nil
		}
		if pc == 0 {
			return m.result("return", steps, ""), nil
		}
		m.recent[m.recentCount%uint64(len(m.recent))] = pc
		m.recentCount++
		m.observe(pc)
		if hook, ok := m.hooks[pc]; ok {
			arguments, err := windowsabi.AMD64IntegerArguments(m.processor, m.memory, hook.argc)
			if err != nil {
				return m.result("memory", steps, err.Error()), nil
			}
			values := make([]starlark.Value, len(arguments))
			for i, arg := range arguments {
				values[i] = starlark.MakeUint64(arg)
			}
			sp, _ := m.processor.Register("rsp")
			var data [8]byte
			if err := m.memory.ReadMemory(sp, data[:], cpu.Read); err != nil {
				return m.result("memory", steps, err.Error()), nil
			}
			event := record(starlark.StringDict{"machine": m, "module": starlark.String(hook.module), "name": starlark.String(hook.name), "address": starlark.MakeUint64(pc), "return_address": starlark.MakeUint64(binary.LittleEndian.Uint64(data[:])), "args": starlark.NewList(values)})
			transferSerial := m.transferSerial
			m.hookDepth++
			result, err := starlark.Call(thread, hook.callback, starlark.Tuple{event}, nil)
			m.hookDepth--
			if err != nil {
				return m.result("plugin", steps, err.Error()), nil
			}
			if m.pendingStop != "" {
				return m.result(m.pendingStop, steps, m.pendingStopDetail), nil
			}
			if m.transferSerial != transferSerial {
				continue // The callback resumed a different guest continuation.
			}
			value, _ := m.processor.Register("rax")
			if result != starlark.None {
				value, err = unsigned(result)
				if err != nil {
					if n, ok := result.(starlark.Int); ok {
						if signed, ok := n.Int64(); ok {
							value, err = uint64(signed), nil
						}
					}
				}
				if err != nil {
					return m.result("plugin", steps, err.Error()), nil
				}
			}
			if err := windowsabi.ReturnAMD64Integer(m.processor, m.memory, value); err != nil {
				return m.result("memory", steps, err.Error()), nil
			}
			continue
		}
		if imported, ok := m.imports[pc]; ok {
			// Resolve at dispatch as well as through the IAT. A machine may be
			// suspended at this thunk when a dependency or semantic export is
			// supplied, and updating the IAT alone cannot resume that call.
			if target := m.resolve(imported.module, imported.name, int(imported.ordinal), 0); target != 0 && target != pc {
				m.processor.SetPC(target)
				continue
			}
			return m.result("missing-import", steps, fmt.Sprintf("%s!%s (#%d)", imported.module, imported.name, imported.ordinal)), nil
		}
		effect, err := m.processor.Step(m.memory)
		if err != nil {
			return m.result("instruction", steps, err.Error()), nil
		}
		if effect == cpu.Halt {
			return m.result("halt", steps+1, ""), nil
		}
	}
	return m.result("instruction-limit", m.limit, ""), nil
}

func (m *Machine) method(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	name := strings.TrimPrefix(builtin.Name(), "machine.")
	if m.frozen && name != "get_register" && name != "read" && !strings.HasPrefix(name, "read_") {
		return nil, fmt.Errorf("machine is frozen")
	}
	switch name {
	case "stop":
		var reason, detail string
		value := starlark.Value(starlark.None)
		if err := starlark.UnpackArgs(name, args, kwargs, "reason", &reason, "detail?", &detail, "value?", &value); err != nil {
			return nil, err
		}
		if m.hookDepth == 0 || reason == "" || reason == "return" || reason == "plugin" || reason == "exception" {
			return nil, fmt.Errorf("stop: requires an active hook and a non-reserved reason")
		}
		if value != starlark.None {
			number, err := unsigned(value)
			if err != nil {
				return nil, err
			}
			if err := m.processor.SetRegister("rax", number); err != nil {
				return nil, err
			}
		}
		m.pendingStop, m.pendingStopDetail = reason, detail
		return starlark.None, nil
	case "arguments":
		var count int
		if err := starlark.UnpackArgs(name, args, kwargs, "count", &count); err != nil {
			return nil, err
		}
		if count < 0 || count > 4096 {
			return nil, fmt.Errorf("arguments: count must be between 0 and 4096")
		}
		arguments, err := windowsabi.AMD64IntegerArguments(m.processor, m.memory, count)
		if err != nil {
			return nil, err
		}
		values := make([]starlark.Value, len(arguments))
		for index, value := range arguments {
			values[index] = starlark.MakeUint64(value)
		}
		return starlark.NewList(values), nil
	case "local_unwind", "transfer":
		return m.controlMethod(thread, name, args, kwargs)
	case "snapshot", "profile":
		return m.diagnosticMethod(name, args, kwargs)
	case "provide_export", "resolve_export", "use", "segment_base", "read_cstring", "read_cbytes":
		return m.environmentMethod(thread, name, args, kwargs)
	case "get_register", "set_register":
		var register string
		value := starlark.Value(starlark.None)
		if name == "get_register" {
			if err := starlark.UnpackArgs(name, args, kwargs, "name", &register); err != nil {
				return nil, err
			}
			v, err := m.processor.Register(register)
			return starlark.MakeUint64(v), err
		}
		if err := starlark.UnpackArgs(name, args, kwargs, "name", &register, "value", &value); err != nil {
			return nil, err
		}
		v, err := unsigned(value)
		if err != nil {
			return nil, err
		}
		return starlark.None, m.processor.SetRegister(register, v)
	case "run":
		entry := starlark.Value(starlark.None)
		untilValue := starlark.Value(starlark.None)
		limit := m.limit
		if err := starlark.UnpackArgs(name, args, kwargs, "entry?", &entry, "instruction_limit?", &limit, "until?", &untilValue); err != nil {
			return nil, err
		}
		var until *uint64
		if untilValue != starlark.None {
			value, err := unsigned(untilValue)
			if err != nil {
				return nil, err
			}
			until = &value
		}
		if limit == 0 || limit > m.limit {
			return nil, fmt.Errorf("run: instruction limit must be within the machine budget")
		}
		previousLimit := m.limit
		m.limit = limit
		defer func() { m.limit = previousLimit }()
		if entry != starlark.None {
			value, err := unsigned(entry)
			if err != nil {
				return nil, err
			}
			m.processor.SetPC(value)
		}
		return m.runUntil(thread, until)
	case "call", "call_export", "invoke":
		address := starlark.Value(starlark.None)
		arguments := starlark.Value(starlark.None)
		var export string
		var err error
		if name == "invoke" {
			inherit := false
			err = starlark.UnpackArgs(name, args, kwargs, "address", &address, "args?", &arguments, "inherit_exceptions?", &inherit)
		} else if name == "call" {
			err = starlark.UnpackArgs(name, args, kwargs, "address", &address, "args?", &arguments)
		} else {
			err = starlark.UnpackArgs(name, args, kwargs, "name", &export, "args?", &arguments)
		}
		if err != nil {
			return nil, err
		}
		var target uint64
		if name == "call" || name == "invoke" {
			target, err = unsigned(address)
		} else if len(m.modules) > 0 {
			for _, item := range m.modules[0].exports {
				if strings.EqualFold(item.Name, export) && item.Forwarder == "" {
					target = m.modules[0].image.Base + uint64(item.RVA)
					break
				}
			}
		}
		if err != nil {
			return nil, err
		}
		if target == 0 {
			return nil, fmt.Errorf("%s: target not found", name)
		}
		var values []uint64
		if arguments != starlark.None {
			iterable, ok := arguments.(starlark.Iterable)
			if !ok {
				return nil, fmt.Errorf("call: args must be iterable")
			}
			iterator := iterable.Iterate()
			defer iterator.Done()
			var arg starlark.Value
			for iterator.Next(&arg) {
				value, err := unsigned(arg)
				if err != nil {
					return nil, err
				}
				values = append(values, value)
				if len(values) > 4096 {
					return nil, fmt.Errorf("call: too many arguments")
				}
			}
		}
		callStackTop := m.stackHigh
		if name == "invoke" {
			saved := m.processor.Clone()
			serial := m.transferSerial
			defer func() { m.processor = saved; m.transferSerial = serial }()
			callStackTop, err = m.processor.Register("rsp")
			if err != nil {
				return nil, err
			}
		}
		if err := windowsabi.PrepareAMD64IntegerCall(m.processor, m.memory, target, callStackTop, 0, values); err != nil {
			return nil, err
		}
		return m.run(thread)
	case "load_module":
		var value starlark.Value
		var moduleName string
		if err := starlark.UnpackArgs(name, args, kwargs, "image", &value, "name", &moduleName); err != nil {
			return nil, err
		}
		data, err := binaryapi.BytesForValue(value)
		if err != nil {
			return nil, err
		}
		loaded, err := m.load(data, moduleName)
		if err != nil {
			return nil, err
		}
		return loaded.record(len(m.modules) > 0 && loaded.name == m.modules[0].name), nil
	case "hook":
		var callback starlark.Callable
		moduleName, export, convention := "", "", "win64"
		argc, ordinal := 0, 0
		address := starlark.MakeUint64(0)
		if err := starlark.UnpackArgs(name, args, kwargs, "callback", &callback, "module?", &moduleName, "name?", &export, "ordinal?", &ordinal, "address?", &address, "argc?", &argc, "convention?", &convention); err != nil {
			return nil, err
		}
		if argc < 0 || argc > 4096 || ordinal < 0 || ordinal > math.MaxUint16 || (convention != "win64" && convention != "stdcall" && convention != "cdecl") {
			return nil, fmt.Errorf("hook: invalid arguments")
		}
		value, ok := address.Uint64()
		if !ok {
			return nil, fmt.Errorf("hook: invalid address")
		}
		var targets []starlark.Value
		if value != 0 {
			if item, ok := m.imports[value]; ok {
				if moduleName == "" {
					moduleName = item.module
				}
				if export == "" {
					export = item.name
				}
			}
			m.hooks[value] = hook{canonical(moduleName), export, argc, callback}
			targets = append(targets, starlark.MakeUint64(value))
		} else {
			for target, item := range m.imports {
				if (moduleName == "" || canonical(moduleName) == item.module) && (export != "" && strings.EqualFold(export, item.name) || ordinal != 0 && uint16(ordinal) == item.ordinal) {
					m.hooks[target] = hook{item.module, item.name, argc, callback}
					targets = append(targets, starlark.MakeUint64(target))
				}
			}
		}
		return starlark.NewList(targets), nil
	case "free":
		var address starlark.Int
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address); err != nil {
			return nil, err
		}
		location, ok := address.Uint64()
		if !ok || !m.allocations[location] {
			return nil, fmt.Errorf("free: not a live plugin allocation")
		}
		if err := m.memory.Unmap(location); err != nil {
			return nil, err
		}
		delete(m.allocations, location)
		delete(m.allocationNames, location)
		return starlark.None, nil
	case "allocate":
		value := starlark.Value(starlark.None)
		requested := starlark.Value(starlark.None)
		alignment := 16
		readable, writable, executable := true, true, false
		size := 0
		allocationName := "allocation"
		if err := starlark.UnpackArgs(name, args, kwargs, "value?", &value, "size?", &size, "name?", &allocationName, "address?", &requested, "alignment?", &alignment, "readable?", &readable, "writable?", &writable, "executable?", &executable); err != nil {
			return nil, err
		}
		var data []byte
		var err error
		if value != starlark.None {
			data, err = binaryapi.BytesForValue(value)
			if err != nil {
				return nil, err
			}
			size = max(size, len(data))
		}
		if size <= 0 || uint64(size) > m.memoryLimit || alignment <= 0 || alignment > 1<<20 || alignment&(alignment-1) != 0 {
			return nil, fmt.Errorf("allocate: invalid size")
		}
		allocation := make([]byte, size)
		copy(allocation, data)
		address := m.nextAllocation
		if requested != starlark.None {
			address, err = unsigned(requested)
			if err != nil {
				return nil, err
			}
		} else {
			if address > math.MaxUint64-uint64(alignment-1) {
				return nil, fmt.Errorf("allocate: address overflows")
			}
			address = (address + uint64(alignment-1)) &^ uint64(alignment-1)
		}
		if address&uint64(alignment-1) != 0 {
			return nil, fmt.Errorf("allocate: address is unaligned")
		}
		access := cpu.Access(0)
		if readable {
			access |= cpu.Read
		}
		if writable {
			access |= cpu.Write
		}
		if executable {
			access |= cpu.Execute
		}
		if err := m.memory.Map(address, allocation, access); err != nil {
			return nil, err
		}
		if requested == starlark.None {
			m.nextAllocation = address + uint64(size)
		}
		if m.allocations == nil {
			m.allocations = make(map[uint64]bool)
		}
		m.allocations[address] = true
		if m.allocationNames == nil {
			m.allocationNames = make(map[uint64]string)
		}
		m.allocationNames[address] = allocationName
		return starlark.MakeUint64(address), nil
	case "protect":
		var address starlark.Int
		size := 0
		readable, writable, executable := true, false, false
		if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size, "readable?", &readable, "writable?", &writable, "executable?", &executable); err != nil {
			return nil, err
		}
		location, ok := address.Uint64()
		if !ok {
			return nil, fmt.Errorf("protect: invalid address")
		}
		access := cpu.Access(0)
		if readable {
			access |= cpu.Read
		}
		if writable {
			access |= cpu.Write
		}
		if executable {
			access |= cpu.Execute
		}
		previous, err := m.memory.Protect(location, size, access)
		if err != nil {
			return nil, err
		}
		var values []starlark.Value
		for _, p := range previous {
			values = append(values, record(starlark.StringDict{"start": starlark.MakeUint64(p.Start), "size": starlark.MakeUint64(p.Size), "readable": starlark.Bool(p.Access&cpu.Read != 0), "writable": starlark.Bool(p.Access&cpu.Write != 0), "executable": starlark.Bool(p.Access&cpu.Execute != 0)}))
		}
		return starlark.NewList(values), nil
	case "read", "write":
		var address starlark.Int
		size := 0
		value := starlark.Value(starlark.None)
		var err error
		if name == "read" {
			err = starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size)
		} else {
			err = starlark.UnpackArgs(name, args, kwargs, "address", &address, "value", &value)
		}
		if err != nil {
			return nil, err
		}
		location, ok := address.Uint64()
		if !ok {
			return nil, fmt.Errorf("memory: invalid address")
		}
		if name == "write" {
			data, err := binaryapi.BytesForValue(value)
			if err != nil {
				return nil, err
			}
			return starlark.None, m.memory.WriteMemory(location, data)
		}
		if size < 0 || uint64(size) > m.memoryLimit {
			return nil, fmt.Errorf("read: invalid size")
		}
		data := make([]byte, size)
		if err := m.memory.ReadMemory(location, data, cpu.Read); err != nil {
			return nil, err
		}
		return starlark.Bytes(data), nil
	}
	for _, operation := range []string{"read_", "write_"} {
		if !strings.HasPrefix(name, operation) {
			continue
		}
		codec, ok := binaryapi.ScalarCodecNamed(strings.TrimPrefix(name, operation))
		if !ok {
			break
		}
		var address starlark.Int
		value := starlark.Value(starlark.None)
		var err error
		if operation == "read_" {
			err = starlark.UnpackArgs(name, args, kwargs, "address", &address)
		} else {
			err = starlark.UnpackArgs(name, args, kwargs, "address", &address, "value", &value)
		}
		if err != nil {
			return nil, err
		}
		location, ok := address.Uint64()
		if !ok {
			return nil, fmt.Errorf("memory: invalid address")
		}
		if operation == "write_" {
			data, err := codec.Encode(value)
			if err != nil {
				return nil, err
			}
			return starlark.None, m.memory.WriteMemory(location, data)
		}
		data := make([]byte, codec.Width)
		if err := m.memory.ReadMemory(location, data, cpu.Read); err != nil {
			return nil, err
		}
		return codec.Decode(data), nil
	}
	return nil, fmt.Errorf("machine: unsupported method %s", name)
}
