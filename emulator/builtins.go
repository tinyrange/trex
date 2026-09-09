// Package emulator selects an instruction backend while keeping the existing
// x86 constructor available for callers that explicitly require PE32.
package emulator

import (
	"bytes"
	"debug/pe"
	"fmt"

	binaryapi "github.com/tinyrange/trex/binary"
	"github.com/tinyrange/trex/emulator/machine"
	"github.com/tinyrange/trex/emulator/uefi"
	"github.com/tinyrange/trex/emulator/x86"
	"go.starlark.net/starlark"
)

func Builtins() starlark.StringDict {
	values := x86.Builtins()
	values["machine"] = starlark.NewBuiltin("machine", Builtin)
	values["uefi"] = starlark.NewBuiltin("uefi", uefi.Builtin)
	return values
}

func Builtin(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	architecture := "auto"
	image := starlark.Value(starlark.None)
	if len(args) > 0 {
		image = args[0]
	}
	filtered := make([]starlark.Tuple, 0, len(kwargs))
	seen := false
	for _, item := range kwargs {
		if item[0] == starlark.String("architecture") {
			if seen {
				return nil, fmt.Errorf("machine: duplicate architecture")
			}
			seen = true
			var ok bool
			architecture, ok = starlark.AsString(item[1])
			if !ok {
				return nil, fmt.Errorf("machine: architecture must be a string")
			}
		} else {
			if item[0] == starlark.String("image") {
				image = item[1]
			}
			filtered = append(filtered, item)
		}
	}
	if architecture == "auto" {
		architecture = "x86"
		if image != starlark.None {
			data, err := binaryapi.BytesForValue(image)
			if err != nil {
				return nil, err
			}
			file, err := pe.NewFile(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			defer file.Close()
			switch file.Machine {
			case pe.IMAGE_FILE_MACHINE_I386:
				architecture = "x86"
			case pe.IMAGE_FILE_MACHINE_AMD64:
				architecture = "amd64"
			default:
				return nil, fmt.Errorf("machine: unsupported PE machine %#x", file.Machine)
			}
		}
	}
	switch architecture {
	case "x86":
		return x86.Builtin(thread, builtin, args, filtered)
	case "amd64":
		return machine.Builtin(thread, builtin, args, filtered)
	default:
		return nil, fmt.Errorf("machine: unsupported architecture %q", architecture)
	}
}
