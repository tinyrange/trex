package starlarkfrontend

import (
	"fmt"
	"sort"
	"strings"

	binaryapi "github.com/tinyrange/trex/binary"
	"go.starlark.net/starlark"
)

const starlarkEnvironmentKey = "trex.runtime.environment"

func helpBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	value := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("help", args, kwargs, "value?", &value); err != nil {
		return nil, err
	}
	console, err := consoleForThread(thread)
	if err != nil {
		return nil, fmt.Errorf("help: %w", err)
	}
	if text, ok := starlark.AsString(value); ok {
		resolved, err := resolveHelpValue(thread, text)
		if err != nil {
			return nil, err
		}
		value = resolved
	}
	documentation := starlarkValueHelp(thread, value)
	if err := console.WriteOutput(documentation); err != nil {
		return nil, fmt.Errorf("help: %w", err)
	}
	return starlark.None, nil
}

func resolveHelpValue(thread *starlark.Thread, name string) (starlark.Value, error) {
	environment, ok := thread.Local(starlarkEnvironmentKey).(starlark.StringDict)
	if !ok {
		return nil, fmt.Errorf("help: runtime API environment is unavailable")
	}
	parts := strings.Split(name, ".")
	value := environment[parts[0]]
	if value == nil {
		return nil, fmt.Errorf("help: unknown API %q", name)
	}
	for _, part := range parts[1:] {
		attributes, ok := value.(starlark.HasAttrs)
		if !ok {
			return nil, fmt.Errorf("help: %q has no attribute %q", strings.Join(parts[:len(parts)-1], "."), part)
		}
		var err error
		value, err = attributes.Attr(part)
		if err != nil {
			return nil, fmt.Errorf("help: %w", err)
		}
		if value == nil {
			return nil, fmt.Errorf("help: unknown API %q", name)
		}
	}
	return value, nil
}

func starlarkValueHelp(thread *starlark.Thread, value starlark.Value) string {
	if value == starlark.None {
		return "trex Starlark help\n\nUse help(namespace), help(value.method), or help(\"qualified.name\").\n"
	}
	if module, ok := value.(namespace); ok {
		names := module.AttrNames()
		sort.Strings(names)
		var output strings.Builder
		fmt.Fprintf(&output, "%s namespace\n\n", module.name)
		for _, name := range names {
			qualified := module.name + "." + name
			if _, ok := module.attrs[name].(*starlark.Builtin); ok {
				fmt.Fprintf(&output, "%s\n", nativeStarlarkSignature(qualified))
			} else {
				fmt.Fprintf(&output, "%s\n", qualified)
			}
		}
		return output.String()
	}
	if builtin, ok := value.(*starlark.Builtin); ok {
		name := builtin.Name()
		if !strings.ContainsRune(name, '.') {
			name = qualifiedStarlarkValueName(thread, value, name)
		}
		return nativeStarlarkSignature(name) + "\n"
	}
	if function, ok := value.(*starlark.Function); ok {
		doc := strings.TrimSpace(function.Doc())
		if doc == "" {
			doc = "No documentation is available for this Starlark function."
		}
		return fmt.Sprintf("%s(...)\n\n%s\n", function.Name(), doc)
	}
	if methods := nativeStarlarkTypes[value.Type()]; len(methods) > 0 {
		methods = append([]string(nil), methods...)
		if value.Type() == "binary.cursor" {
			for _, codec := range binaryapi.ScalarCodecs {
				methods = append(methods, codec.Name+"()")
			}
		}
		if value.Type() == "binary.builder" {
			for _, codec := range binaryapi.ScalarCodecs {
				methods = append(methods, codec.Name+"(value)", "patch_"+codec.Name+"(offset, value)")
			}
		}
		if value.Type() == "emulator.x86" {
			for _, codec := range binaryapi.ScalarCodecs {
				methods = append(methods, "read_"+codec.Name+"(address)", "write_"+codec.Name+"(address, value)")
			}
		}
		sort.Strings(methods)
		return fmt.Sprintf("%s value\n\n%s\n", value.Type(), strings.Join(methods, "\n"))
	}
	if attributes, ok := value.(starlark.HasAttrs); ok {
		names := attributes.AttrNames()
		sort.Strings(names)
		return fmt.Sprintf("%s value\n\n%s\n", value.Type(), strings.Join(names, "\n"))
	}
	return fmt.Sprintf("%s value\n", value.Type())
}

func qualifiedStarlarkValueName(thread *starlark.Thread, target starlark.Value, fallback string) string {
	environment, _ := thread.Local(starlarkEnvironmentKey).(starlark.StringDict)
	targetBuiltin, builtin := target.(*starlark.Builtin)
	targetFunction, function := target.(*starlark.Function)
	for namespaceName, candidate := range environment {
		module, ok := candidate.(namespace)
		if !ok {
			continue
		}
		for name, candidate := range module.attrs {
			if builtin {
				if candidateBuiltin, ok := candidate.(*starlark.Builtin); ok && candidateBuiltin == targetBuiltin {
					return namespaceName + "." + name
				}
			}
			if function {
				if candidateFunction, ok := candidate.(*starlark.Function); ok && candidateFunction == targetFunction {
					return namespaceName + "." + name
				}
			}
		}
	}
	return fallback
}
