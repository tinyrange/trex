"""Composable import-hook plugins for Windows self-registration emulation.

This module defines composition and calling-convention policy in Starlark. The
x86 execution loop, PE mapping, memory safety, and budgets remain generic Go.
"""

def import_plugin(name, bindings, state = None):
    """Builds a plugin from declarative import bindings.

    Each binding is a dict containing callback and optional module, name,
    ordinal, argc, and convention fields accepted by emulator.x86.hook().
    """
    def install(machine):
        for binding in bindings:
            machine.hook(
                binding["callback"],
                module = binding.get("module", ""),
                name = binding.get("name", ""),
                ordinal = binding.get("ordinal", 0),
                address = binding.get("address", 0),
                argc = binding.get("argc", 0),
                convention = binding.get("convention", "stdcall"),
            )
    return emulator.plugin(install, name = name, state = state)

def _success(event):
    return 0

def successful_imports(name, imports):
    """Builds a deterministic plugin whose selected imports return success."""
    bindings = []
    for item in imports:
        bindings.append({
            "module": item.get("module", ""),
            "name": item.get("name", ""),
            "ordinal": item.get("ordinal", 0),
            "argc": item.get("argc", 0),
            "convention": item.get("convention", "stdcall"),
            "callback": _success,
        })
    return import_plugin(name, bindings)
