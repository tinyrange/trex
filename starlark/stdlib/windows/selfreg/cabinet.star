"""In-memory Cabinet.dll extraction services for setup-time execution."""

def _normalized_path(path):
    normalized = path.replace("/", "\\")
    while "\\\\" in normalized:
        normalized = normalized.replace("\\\\", "\\")
    return normalized.rstrip("\\").lower()

def _joined_path(directory, name):
    directory = directory.replace("/", "\\")
    name = name.replace("/", "\\")
    return _normalized_path(directory.rstrip("\\") + ("\\" if directory else "") + name.lstrip("\\"))

def _cabinet_file(data):
    builder = binary.builder(capacity = len(data))
    builder.append(data)
    return builder.file()

def _notification(machine, user, filename, size, handle = 0):
    encoded_name = binary.encode(filename, encoding = "ascii", nul = True)
    name_address = machine.allocate(value = encoded_name, name = "FDI notification filename")
    record = binary.builder(capacity = 40)
    record.u32le(size)
    record.u32le(name_address)
    record.u32le(0)
    record.u32le(0)
    record.u32le(user)
    record.u32le(handle & 0xffffffff)
    record.reserve(16)
    address = machine.allocate(value = record.bytes(), name = "FDINOTIFICATION")
    return {"address": address, "name": name_address}

def _invoke(machine, address, arguments, label):
    result = machine.invoke(address, args = arguments)
    if result.reason != "return":
        fail("{} stopped with {}: {}".format(label, result.reason, result.detail))
    return result.value

def cabinet_plugin(kernel):
    """Provides FDI extraction over native CAB files in the virtual file view."""
    state = {"contexts": {}, "next_context": 0x5d000, "actions": []}

    def set_error(machine, context, operation, error):
        address = context.get("error", 0)
        if address:
            machine.write_u32le(address, operation & 0xffffffff)
            machine.write_u32le(address + 4, error & 0xffffffff)
            machine.write_u32le(address + 8, 1)

    def create(event):
        context = state["next_context"]
        state["next_context"] = context + 1
        state["contexts"][context] = {
            "alloc": event.args[0],
            "free": event.args[1],
            "open": event.args[2],
            "read": event.args[3],
            "write": event.args[4],
            "close": event.args[5],
            "seek": event.args[6],
            "cpu": event.args[7],
            "error": event.args[8],
        }
        if event.args[8]:
            event.machine.write(event.args[8], b"\x00" * 12)
        return context

    def copy(event):
        machine = event.machine
        context = state["contexts"].get(event.args[0])
        if context == None or not event.args[1] or not event.args[4]:
            return 0
        cabinet_name = machine.read_cstring(event.args[1])
        cabinet_path = machine.read_cstring(event.args[2]) if event.args[2] else ""
        path = _joined_path(cabinet_path, cabinet_name)
        entry = kernel.state["paths"].get(path)
        if entry == None or entry.get("directory", False):
            set_error(machine, context, 1, 2)
            state["actions"].append({"api": "fdicopy", "path": path, "found": False})
            return 0
        cabinet = archive.cab(_cabinet_file(kernel.state["file_data"](path)), cache = False)
        extracted = 0
        skipped = 0
        for archived_name in cabinet.files:
            filename = archived_name.replace("/", "\\").lstrip("\\")
            source = cabinet[archived_name]
            view = binary.view(source)
            notice = _notification(machine, event.args[6], filename, view.size)
            output = _invoke(machine, event.args[4], [2, notice["address"]], "FDI copy-file notification")
            machine.free(notice["address"])
            machine.free(notice["name"])
            if output != 0 and len(state["actions"]) < 256:
                state["actions"].append({"api": "fdinotify", "type": "copy", "file": filename, "size": view.size, "result": output})
            if output == 0:
                skipped += 1
                continue
            if output == 0xffffffff:
                set_error(machine, context, 2, 1)
                return 0
            data = view.slice(0, view.size).bytes()
            address = machine.allocate(value = data if data else b"\x00", name = "FDI decompressed file")
            written = _invoke(machine, context["write"], [output, address, len(data)], "FDI write callback")
            machine.free(address)
            if written != len(data):
                set_error(machine, context, 3, 112)
                return 0
            close_notice = _notification(machine, event.args[6], filename, view.size, handle = output)
            closed = _invoke(machine, event.args[4], [3, close_notice["address"]], "FDI close-file notification")
            machine.free(close_notice["address"])
            machine.free(close_notice["name"])
            if len(state["actions"]) < 256:
                state["actions"].append({"api": "fdinotify", "type": "close", "file": filename, "result": closed})
            if closed == 0:
                set_error(machine, context, 4, 1)
                return 0
            extracted += 1
        state["actions"].append({
            "api": "fdicopy",
            "path": path,
            "found": True,
            "extracted": extracted,
            "skipped": skipped,
        })
        return 1

    def destroy(event):
        if event.args[0] not in state["contexts"]:
            return 0
        state["contexts"].pop(event.args[0])
        return 1

    def install(machine):
        exports = [
            ("FDICreate", 20, 9, create),
            ("FDICopy", 22, 7, copy),
            ("FDIDestroy", 23, 1, destroy),
        ]
        for name, ordinal, argc, callback in exports:
            machine.provide_export(callback, module = "cabinet.dll", name = name, argc = argc, convention = "cdecl")
            machine.provide_export(callback, module = "cabinet.dll", ordinal = ordinal, argc = argc, convention = "cdecl")

    return emulator.plugin(install, name = "windows.cabinet", state = state)
