"""Bounded code-range observation for live emulator investigations."""

def module_code_watch(module_name, rva, size, limit = 4096, stack_bytes = 0, captures = {}):
    """Returns a plugin that records executions within one mapped module range."""
    if rva < 0 or size <= 0 or limit <= 0 or stack_bytes < 0:
        fail("invalid module code watch bounds")
    watch_state = {}

    def install(machine):
        matches = [module for module in machine.modules if module.name.lower() == module_name.lower()]
        if len(matches) != 1:
            fail("expected exactly one mapped %s module, got %d" % (module_name, len(matches)))
        base = matches[0].base
        watch_state["base"] = base
        watch_state["watch"] = machine.watch_code(
            base + rva,
            size,
            limit = limit,
            stack_bytes = stack_bytes,
            captures = captures,
        )

    return {
        "plugin": emulator.plugin(install, name = "%s code watch" % module_name, state = watch_state),
        "state": watch_state,
    }
