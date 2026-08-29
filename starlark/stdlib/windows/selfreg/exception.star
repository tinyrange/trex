"""Structured-exception dispatch for bounded 32-bit registration execution."""

def _signed(value):
    return value - (1 << 32) if value & 0x80000000 else value

def _record(machine, address, size):
    return binary.cursor(machine.read(address, size))

def exception_plugin(kernel = None):
    """Dispatches RaiseException through active compiler SEH3 scope tables.

    The plugin deliberately supports the explicit x86 registration-chain
    contract only. Unknown frame layouts and unhandled exceptions fail closed.
    """
    state = {"exceptions": [], "generic_handlers": {}}

    def invoke(machine, address, frame):
        result = machine.invoke(address, registers = {"ebp": frame + 16})
        if result.reason != "return":
            fail("SEH funclet {} stopped with {}: {}".format(hex(address), result.reason, result.detail))
        return result.value

    def invoke_handler(machine, address, record, frame, context):
        result = machine.invoke(address, args = [record, frame, context, 0])
        if result.reason != "return":
            exception = _record(machine, record, 16)
            code = exception.u32le()
            exception.u32le()
            exception.u32le()
            origin = exception.u32le()
            count = min(_record(machine, record + 16, 4).u32le(), 15)
            parameters = [_record(machine, record + 20 + index * 4, 4).u32le() for index in range(count)]
            registers = {
                "eax": _record(machine, context + 176, 4).u32le(),
                "ecx": _record(machine, context + 172, 4).u32le(),
                "edx": _record(machine, context + 168, 4).u32le(),
                "esi": _record(machine, context + 160, 4).u32le(),
            }
            fail("SEH handler {} for frame {} ({}) handling {} at {} parameters {} registers {} stopped with {}: {}".format(
                hex(address), hex(frame), hex(machine.read(frame, 16)), hex(code), hex(origin),
                [hex(value) for value in parameters],
                {name: hex(value) for name, value in registers.items()},
                result.reason, result.detail,
            ))
        return result.value

    def write_context(machine, context, address):
        machine.write_u32le(context, 0x00010007)  # CONTEXT_CONTROL | INTEGER | SEGMENTS
        offsets = {
            "edi": 156, "esi": 160, "ebx": 164, "edx": 168,
            "ecx": 172, "eax": 176, "ebp": 180, "esp": 196,
        }
        for register, offset in offsets.items():
            machine.write_u32le(context + offset, machine.get_register(register))
        machine.write_u32le(context + 184, address)

    def resume_context(machine, context):
        offsets = {
            "edi": 156, "esi": 160, "ebx": 164, "edx": 168,
            "ecx": 172, "eax": 176,
        }
        for register, offset in offsets.items():
            machine.set_register(register, _record(machine, context + offset, 4).u32le())
        machine.transfer(
            _record(machine, context + 184, 4).u32le(),
            esp = _record(machine, context + 196, 4).u32le(),
            ebp = _record(machine, context + 180, 4).u32le(),
        )

    def scope_entry(machine, table, level):
        cursor = _record(machine, table + level * 12, 12)
        return {
            "outer": _signed(cursor.u32le()),
            "filter": cursor.u32le(),
            "handler": cursor.u32le(),
        }

    def valid_scope_chain(machine, table, level):
        if level < 0 or level >= 256:
            return False
        seen = {}
        current = level
        while current >= 0:
            if current in seen:
                return False
            seen[current] = True
            outer = scope_entry(machine, table, current)["outer"]
            if outer < -1 or outer >= current:
                return False
            current = outer
        return True

    def unwind_frame(machine, frame, table, level):
        seen = {}
        while level >= 0:
            if level in seen or level >= 256:
                fail("invalid SEH scope chain")
            seen[level] = True
            entry = scope_entry(machine, table, level)
            machine.write_u32le(frame + 12, entry["outer"] & 0xffffffff)
            if entry["filter"] == 0 and entry["handler"]:
                invoke(machine, entry["handler"], frame)
            level = entry["outer"]

    def dispatch(machine, code, flags, values, address):
        count = min(len(values), 15)
        record = binary.builder(capacity = 80)
        record.u32le(code)
        record.u32le(flags)
        record.u32le(0)
        record.u32le(address)
        record.u32le(count)
        for index in range(15):
            value = values[index] if index < count else 0
            record.u32le(value)
        record_address = machine.allocate(value = record.bytes(), name = "EXCEPTION_RECORD")
        context_address = machine.allocate(size = 716, name = "CONTEXT")
        write_context(machine, context_address, address)
        pointers = binary.builder(capacity = 8)
        pointers.u32le(record_address)
        pointers.u32le(context_address)
        pointers_address = machine.allocate(value = pointers.bytes(), name = "EXCEPTION_POINTERS")

        fs = machine.segment_base("fs")
        frame = _record(machine, fs, 4).u32le() if fs else 0xffffffff
        traversed = []
        while frame != 0xffffffff:
            registration = _record(machine, frame, 16)
            next_frame = registration.u32le()
            handler = registration.u32le()
            table = registration.u32le()
            level = _signed(registration.u32le())
            if handler in state["generic_handlers"] or not valid_scope_chain(machine, table, level):
                state["generic_handlers"][handler] = True
                disposition = invoke_handler(machine, handler, record_address, frame, context_address)
                if disposition == 0:  # ExceptionContinueExecution
                    state["exceptions"].append({
                        "code": code,
                        "disposition": "continue",
                        "frame": frame,
                        "handler": handler,
                        "resume": _record(machine, context_address + 184, 4).u32le(),
                        "edx": _record(machine, context_address + 168, 4).u32le(),
                    })
                    machine.write_u32le(fs, frame)
                    resume_context(machine, context_address)
                    return None
                if disposition != 1:  # ExceptionContinueSearch
                    fail("unsupported SEH disposition {}".format(disposition))
                frame = next_frame
                continue
            traversed.append({"frame": frame, "table": table, "level": level})
            current = level
            seen = {}
            while current >= 0:
                if current in seen or current >= 256:
                    fail("invalid SEH scope chain")
                seen[current] = True
                entry = scope_entry(machine, table, current)
                if entry["filter"]:
                    machine.write_u32le(frame - 4, pointers_address)
                    decision = _signed(invoke(machine, entry["filter"], frame))
                    if decision < 0:
                        state["exceptions"].append({"code": code, "disposition": "continue"})
                        return None
                    if decision > 0:
                        for item in traversed[:-1]:
                            unwind_frame(machine, item["frame"], item["table"], item["level"])
                        machine.write_u32le(frame + 12, entry["outer"] & 0xffffffff)
                        machine.write_u32le(fs, frame)
                        state["exceptions"].append({
                            "code": code,
                            "disposition": "handler",
                            "frame": frame,
                            "handler": entry["handler"],
                        })
                        machine.transfer(entry["handler"], ebp = frame + 16)
                        return None
                current = entry["outer"]
            frame = next_frame
        state["exceptions"].append({
            "code": code,
            "disposition": "unhandled",
            "address": address,
            "information": values[:count],
            "registers": {
                name: machine.get_register(name)
                for name in ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"]
            },
        })
        top_level = kernel.state["unhandled_exception_filter"] if kernel != None else 0
        if top_level:
            result = machine.invoke(top_level, args = [pointers_address])
            decision = _signed(result.value) if result.reason == "return" else 0
            state["exceptions"].append({
                "code": code,
                "disposition": "top-level",
                "filter": top_level,
                "result": decision,
                "stop_reason": result.reason,
                "stop_detail": result.detail,
            })
            if decision < 0:  # EXCEPTION_CONTINUE_EXECUTION
                resume_context(machine, context_address)
                return None
        fail("unhandled structured exception {} at {} parameters {}".format(
            hex(code),
            hex(address),
            [hex(value) for value in values[:count]],
        ))

    def raise_exception(event):
        code, flags, count, values_address = event.args
        values = []
        for index in range(min(count, 15)):
            values.append(_record(event.machine, values_address + index * 4, 4).u32le() if values_address else 0)
        return dispatch(event.machine, code, flags, values, event.machine.get_register("eip"))

    def hardware_exception(event):
        return dispatch(event.machine, event.code, 0, list(event.information), event.address)

    def install(machine):
        machine.on_exception(hardware_exception)
        for imported in machine.imports:
            if imported.module.lower() == "kernel32.dll" and imported.name.lower() == "raiseexception":
                machine.hook(raise_exception, address = imported.address, argc = 4)
    return emulator.plugin(install, name = "windows.seh3", state = state)
