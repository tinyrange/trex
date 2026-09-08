package machine

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	binaryapi "github.com/tinyrange/trex/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	exportbatch "github.com/tinyrange/trex/emulator/internal/exports"
	"go.starlark.net/starlark"
)

func exportKey(module, name string, ordinal int) string {
	if name == "" {
		name = fmt.Sprintf("#%d", ordinal)
	}
	return canonical(module) + "!" + strings.ToLower(name)
}

func (m *Machine) environmentMethod(thread *starlark.Thread, name string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	switch name {
	case "provide_exports":
		return exportbatch.Provide(args, kwargs, func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return m.environmentMethod(thread, "provide_export", args, kwargs)
		})
	case "segment_base":
		var segment string
		if err := starlark.UnpackArgs(name, args, kwargs, "segment", &segment); err != nil {
			return nil, err
		}
		if segment != "fs" && segment != "gs" {
			return nil, fmt.Errorf("segment_base: expected fs or gs")
		}
		value, err := m.processor.Register(segment + "_base")
		return starlark.MakeUint64(value), err
	case "use":
		var plugins starlark.Value
		if err := starlark.UnpackArgs(name, args, kwargs, "plugins", &plugins); err != nil {
			return nil, err
		}
		iterable, ok := plugins.(starlark.Iterable)
		if !ok {
			iterable = starlark.Tuple{plugins}
		}
		iterator := iterable.Iterate()
		defer iterator.Done()
		var plugin starlark.Value
		for iterator.Next(&plugin) {
			attrs, ok := plugin.(starlark.HasAttrs)
			if !ok {
				return nil, fmt.Errorf("use: plugin has no attributes")
			}
			value, err := attrs.Attr("install")
			if err != nil {
				return nil, err
			}
			install, ok := value.(starlark.Callable)
			if !ok {
				return nil, fmt.Errorf("use: plugin install is not callable")
			}
			if _, err := starlark.Call(thread, install, starlark.Tuple{m}, nil); err != nil {
				return nil, err
			}
			state, err := attrs.Attr("state")
			if err != nil {
				return nil, err
			}
			if state != nil && state != starlark.None {
				m.pluginStates = append(m.pluginStates, state)
			}
		}
		return m, nil
	case "provide_export", "resolve_export":
		var moduleName, export string
		ordinal, argc := 0, 0
		convention := "win64"
		var callback starlark.Callable
		dataValue := starlark.Value(starlark.None)
		writable := true
		if name == "resolve_export" {
			if err := starlark.UnpackArgs(name, args, kwargs, "module", &moduleName, "name?", &export, "ordinal?", &ordinal); err != nil {
				return nil, err
			}
			return starlark.MakeUint64(m.resolve(moduleName, export, ordinal, 0)), nil
		}
		if err := starlark.UnpackArgs(name, args, kwargs, "callback?", &callback, "module", &moduleName, "name?", &export, "ordinal?", &ordinal, "argc?", &argc, "convention?", &convention, "value?", &dataValue, "writable?", &writable); err != nil {
			return nil, err
		}
		if canonical(moduleName) == "" || (export == "" && ordinal == 0) || (export != "" && ordinal != 0) || ordinal < 0 || ordinal > math.MaxUint16 || argc < 0 || argc > 4096 || (convention != "win64" && convention != "stdcall" && convention != "cdecl") {
			return nil, fmt.Errorf("provide_export: invalid arguments")
		}
		if m.provided == nil {
			m.provided = make(map[string]uint64)
		}
		if (callback == nil) == (dataValue == starlark.None) {
			return nil, fmt.Errorf("provide_export: specify exactly one of callback or value")
		}
		key := exportKey(moduleName, export, ordinal)
		address := m.provided[key]
		if dataValue != starlark.None {
			if address != 0 {
				return nil, fmt.Errorf("provide_export: data export already exists")
			}
			data, err := binaryapi.BytesForValue(dataValue)
			if err != nil {
				return nil, err
			}
			address = m.nextAllocation
			access := cpu.Read
			if writable {
				access |= cpu.Write
			}
			if err := m.memory.Map(address, data, access); err != nil {
				return nil, err
			}
			m.nextAllocation += (uint64(len(data)) + 15) &^ 15
		}
		if address == 0 {
			address = 0x7ffe00000000 + uint64(len(m.provided))*16
		}
		m.provided[key] = address
		hookName := export
		if hookName == "" {
			hookName = fmt.Sprintf("#%d", ordinal)
		}
		if callback != nil {
			m.setHook(address, hook{canonical(moduleName), hookName, argc, callback})
		}
		for _, iat := range m.importIATs[key] {
			var data [8]byte
			binary.LittleEndian.PutUint64(data[:], address)
			if err := m.memory.WriteMemory(iat, data[:]); err != nil {
				return nil, err
			}
		}
		return starlark.MakeUint64(address), nil
	case "read_cstring", "read_cbytes":
		var address starlark.Int
		maximum, unitWidth := 32768, 1
		encoding := "ascii"
		require := true
		if name == "read_cstring" {
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "maximum?", &maximum, "encoding?", &encoding); err != nil {
				return nil, err
			}
			if strings.HasPrefix(strings.ToLower(strings.ReplaceAll(encoding, "-", "")), "utf16") {
				unitWidth = 2
			}
		} else {
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "maximum?", &maximum, "require_terminator?", &require, "unit_width?", &unitWidth); err != nil {
				return nil, err
			}
		}
		location, ok := address.Uint64()
		if !ok || maximum < 0 || uint64(maximum) > m.memoryLimit || (unitWidth != 1 && unitWidth != 2) {
			return nil, fmt.Errorf("%s: invalid bounds", name)
		}
		data := make([]byte, 0, min(maximum, 256))
		terminated := false
		for offset := 0; offset+unitWidth <= maximum; offset += unitWidth {
			if location > math.MaxUint64-uint64(offset) {
				return nil, fmt.Errorf("%s: address overflows", name)
			}
			var unit [2]byte
			if err := m.memory.ReadMemory(location+uint64(offset), unit[:unitWidth], cpu.Read); err != nil {
				return nil, err
			}
			if unit[0] == 0 && (unitWidth == 1 || unit[1] == 0) {
				terminated = true
				break
			}
			data = append(data, unit[:unitWidth]...)
		}
		if require && !terminated {
			return nil, fmt.Errorf("%s: string has no terminator within bound", name)
		}
		if name == "read_cbytes" {
			return starlark.Bytes(data), nil
		}
		text, err := binaryapi.DecodeText(data, encoding, false)
		return starlark.String(text), err
	}
	return nil, fmt.Errorf("machine: unsupported environment method %s", name)
}

func (m *Machine) resolve(moduleName, name string, ordinal, depth int) uint64 {
	if depth >= 32 {
		return 0
	}
	if address := m.provided[exportKey(moduleName, name, ordinal)]; address != 0 {
		return address
	}
	for _, module := range m.modules {
		if module.name != canonical(moduleName) {
			continue
		}
		for _, export := range module.exports {
			if !(name != "" && strings.EqualFold(export.Name, name) || name == "" && int(export.Ordinal) == ordinal) {
				continue
			}
			if export.Forwarder == "" {
				return module.image.Base + uint64(export.RVA)
			}
			index := strings.LastIndexByte(export.Forwarder, '.')
			if index < 1 {
				return 0
			}
			moduleName, symbol := export.Forwarder[:index], export.Forwarder[index+1:]
			if strings.HasPrefix(symbol, "#") {
				var ordinal int
				if _, err := fmt.Sscanf(symbol, "#%d", &ordinal); err != nil {
					return 0
				}
				return m.resolve(moduleName, "", ordinal, depth+1)
			}
			return m.resolve(moduleName, symbol, 0, depth+1)
		}
	}
	return 0
}
