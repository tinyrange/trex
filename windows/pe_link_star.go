package windows

import (
	"fmt"

	"go.starlark.net/starlark"
)

func pe32LinkBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var object starlark.Value
	var imports, exports, callbacks *starlark.Dict
	entry := ""
	executable := false
	subsystem, major, minor, imageBase := uint32(3), uint32(3), uint32(10), uint32(0x62000000)
	if err := starlark.UnpackArgs("pe32_link", args, kwargs,
		"object", &object, "imports", &imports, "exports", &exports, "callbacks?", &callbacks,
		"entry?", &entry, "subsystem?", &subsystem, "version_major?", &major, "version_minor?", &minor, "image_base?", &imageBase, "executable?", &executable); err != nil {
		return nil, err
	}
	if subsystem != 1 && subsystem != 3 || major > 65535 || minor > 65535 {
		return nil, fmt.Errorf("invalid PE subsystem/version")
	}
	data, err := bytesForBinaryValue(object)
	if err != nil {
		return nil, err
	}
	opts := PE32LinkOptions{Entry: entry, Subsystem: uint16(subsystem), VersionMajor: uint16(major), VersionMinor: uint16(minor), ImageBase: imageBase, Imports: make(map[string]map[string]int)}
	opts.Executable = executable
	if opts.Exports, err = peStackWords(exports); err != nil {
		return nil, err
	}
	if opts.Callbacks, err = peStackWords(callbacks); err != nil {
		return nil, err
	}
	for _, item := range imports.Items() {
		dll, ok := starlark.AsString(item[0])
		if !ok {
			return nil, fmt.Errorf("import DLL must be a string")
		}
		functions, ok := item[1].(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("import functions must be a dictionary")
		}
		if opts.Imports[dll], err = peStackWords(functions); err != nil {
			return nil, err
		}
	}
	result, err := LinkPE32(data, opts)
	if err != nil {
		return nil, fmt.Errorf("pe32_link: %w", err)
	}
	return starlark.Bytes(result), nil
}

func peStackWords(dict *starlark.Dict) (map[string]int, error) {
	result := make(map[string]int)
	if dict == nil {
		return result, nil
	}
	for _, item := range dict.Items() {
		name, ok := starlark.AsString(item[0])
		if !ok {
			return nil, fmt.Errorf("symbol must be a string")
		}
		words, err := starlark.AsInt32(item[1])
		if err != nil || words < 0 || words > 64 {
			return nil, fmt.Errorf("invalid stack word count for %q", name)
		}
		result[name] = words
	}
	return result, nil
}
