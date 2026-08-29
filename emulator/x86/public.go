package x86

import "go.starlark.net/starlark"

func (m *emulatorX86) UseBuiltin(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return m.useBuiltin(thread, builtin, args, kwargs)
}

func (m *emulatorX86) Run(thread *starlark.Thread) (starlark.Value, error) { return m.run(thread) }

func (m *emulatorX86) LoadModuleBuiltin(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return m.loadModuleBuiltin(thread, builtin, args, kwargs)
}

func (m *emulatorX86) AllocateBuiltin(thread *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return m.allocateBuiltin(thread, builtin, args, kwargs)
}

func (m *emulatorX86) ResolveExport(module, name string, ordinal uint32, depth int) uint32 {
	return m.resolveExport(module, name, ordinal, depth)
}

func (m *emulatorX86) CallAddress(thread *starlark.Thread, address uint32, args []uint32) (starlark.Value, error) {
	return m.callAddress(thread, address, args)
}

func (m *emulatorX86) ReadMemory(address uint32, size int, access byte) ([]byte, error) {
	return m.readMemory(address, size, access)
}
