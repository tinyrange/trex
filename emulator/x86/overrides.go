package x86

import (
	"fmt"
	"sort"
	"strings"

	"go.starlark.net/starlark"
)

// override changes semantic callbacks, never guest instruction bytes. The base
// plugin must already be installed. Its ABI and export addresses are retained.
// Wrap callbacks receive (event, previous); previous(event) invokes the base
// callback directly, without recursively entering the guest execution loop.
func (m *emulatorX86) overrideBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var callback starlark.Callable
	var module, name string
	ordinal := 0
	wrap := false
	if err := starlark.UnpackArgs("override", args, kwargs, "callback", &callback, "module", &module, "name?", &name, "ordinal?", &ordinal, "wrap?", &wrap); err != nil {
		return nil, err
	}
	if m.frozen || module == "" || (name == "") == (ordinal == 0) || ordinal < 0 || ordinal > 65535 {
		return nil, fmt.Errorf("override: specify a module and exactly one name or ordinal on a mutable machine")
	}
	module = canonicalEmulatorModuleName(module)
	symbol := name
	if symbol == "" {
		symbol = fmt.Sprintf("#%d", ordinal)
	}
	var targets []uint32
	var base emulatorHook
	for address, hook := range m.hooks {
		if canonicalEmulatorModuleName(hook.module) != module || !strings.EqualFold(hook.name, symbol) {
			continue
		}
		if len(targets) > 0 && (hook.argc != base.argc || hook.convention != base.convention || (wrap && hook.callback != base.callback)) {
			return nil, fmt.Errorf("override: ambiguous base bindings for %s!%s", module, symbol)
		}
		base = hook
		targets = append(targets, address)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("override: no semantic binding for %s!%s; install the base plugin first", module, symbol)
	}
	if wrap {
		replacement, previous := callback, base.callback
		// Only immutable callable references are captured. Mutable plugin state is
		// still registered through emulator.plugin and restored in place.
		callback = starlark.NewBuiltin("wrap:"+module+"!"+symbol, func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			return starlark.Call(thread, replacement, starlark.Tuple{args[0], previous}, nil)
		})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })
	values := make([]starlark.Value, len(targets))
	for i, address := range targets {
		hook := m.hooks[address]
		hook.callback = callback
		m.hooks[address] = hook
		values[i] = starlark.MakeUint(uint(address))
	}
	m.hookRules = append(m.hookRules, emulatorHookRule{module: module, name: strings.ToLower(name), ordinal: uint16(ordinal), argc: base.argc, convention: base.convention, callback: callback})
	return starlark.NewList(values), nil
}
