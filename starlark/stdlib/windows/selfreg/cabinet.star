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

def _notification(machine, user, filename, size, metadata, handle = 0):
    encoded_name = binary.encode(filename, encoding = "utf8" if metadata["attributes"] & 0x80 else "ascii", nul = True)
    name_address = machine.allocate(value = encoded_name, name = "FDI notification filename")
    # FDINOTIFICATION has pointer-sized strings, context and INT_PTR handle.
    record = binary.builder(capacity = 64 if machine.pointer_size == 8 else 40)
    record.u32le(size)
    if machine.pointer_size == 8:
        record.u32le(0)
    for pointer in [name_address, 0, 0, user, handle]:
        if machine.pointer_size == 8:
            record.u64le(pointer & 0xffffffffffffffff)
        else:
            record.u32le(pointer & 0xffffffff)
    for field in ["date", "time", "attributes", "set_id", "cabinet", "folder"]:
        record.u16le(metadata[field])
    record.u32le(0)
    address = machine.allocate(value = record.bytes(), name = "FDINOTIFICATION")
    return {"address": address, "name": name_address}

def _invoke(machine, address, arguments, label):
    result = machine.invoke(address, args = arguments)
    if result.reason != "return":
        fail("{} stopped with {} at {} after {} steps: {}".format(label, result.reason, hex(result.pc), result.steps, result.detail))
    return result.value

def _callback_cabinet(machine, context, path):
    """Read one bounded cabinet through the caller's actual FDI I/O callbacks."""
    if not all([context[name] for name in ["open", "read", "close"]]):
        fail("FDI callback stream requires open/read/close together")
    name = machine.allocate(value=binary.encode(path,encoding="ascii",nul=True))
    handle = _invoke(machine, context["open"], [name, 0x8000, 0], "FDI open callback")
    machine.free(name)
    if handle == (1 << (machine.pointer_size*8))-1:
        return dict(data=None, operation=1, error=2)
    buffer = machine.allocate(size=65536,name="FDI input buffer")
    data = binary.builder()
    required = 36
    invalid = False
    operation = 4
    while data.size < required:
        requested = min(65536,required-data.size)
        read = _invoke(machine,context["read"],[handle,buffer,requested],"FDI read callback") & 0xffffffff
        if read == 0 or read > requested:
            invalid = True
            break
        data.append(machine.read(buffer,read))
        if data.size == 36 and required == 36:
            header = data.bytes()
            if header[:4] != b"MSCF":
                operation = 2
                invalid = True
                break
            required = binary.read_u32le(header,8)
            if required < 36 or required > 256 << 20:
                invalid = True
                break
    closed = _invoke(machine,context["close"],[handle],"FDI close callback") & 0xffffffff
    machine.free(buffer)
    if closed != 0:
        fail("FDI input close callback failed")
    if invalid:
        return dict(data=None,operation=operation,error=0)
    return dict(data=data.bytes(),operation=0,error=0)

def cabinet_plugin(kernel):
    """Extract single cabinets from owned files or caller-supplied FDI streams.

    Callback input is bounded at 256 MiB; decoded output at 512 MiB. Real native
    read/write/notification callbacks execute in-process, including pointer-sized
    FDINOTIFICATION fields and raw CAB timestamp/attribute metadata. No child
    process or completion marker is implied by extraction.
    """
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
        if context["open"] or context["read"] or context["close"]:
            # Preserve the caller's spelling: an FDI name can identify a memory
            # stream rather than a filesystem path (MSRT uses this facility).
            supplied = cabinet_path + cabinet_name
            stream = _callback_cabinet(machine,context,supplied)
            if stream["data"] == None:
                set_error(machine,context,stream["operation"],stream["error"])
                state["actions"].append(dict(api="fdicopy",path=path,found=False,operation=stream["operation"]))
                return 0
            data = stream["data"]
        else:
            entry = kernel.state["paths"].get(path)
            if entry == None or entry.get("directory", False):
                set_error(machine, context, 1, 2)
                state["actions"].append({"api": "fdicopy", "path": path, "found": False})
                return 0
            data = kernel.state["file_data"](path)
        if len(data) < 4 or data[:4] != b"MSCF":
            # Setup may try FDICopy before falling back to an ordinary copy.
            # A non-cabinet is an FDI failure, not an emulator/parser failure.
            set_error(machine, context, 2, 0)  # FDIERROR_NOT_A_CABINET
            state["actions"].append({"api": "fdicopy", "path": path, "found": True, "operation": 2, "error": 0})
            return 0
        # FDI visits multiple entries in the same compressed folder. Keep the
        # bounded folder cache for this copy so each entry does not restart
        # decompression from the beginning of the folder.
        cabinet = archive.cab(_cabinet_file(data))
        extracted = 0
        skipped = 0
        total = 0
        if len(cabinet.files) > 65536: fail("FDI member count exceeds bound")
        for archived_name in cabinet.files:
            filename = archived_name.replace("/", "\\").lstrip("\\")
            source = cabinet[archived_name]
            view = binary.view(source)
            total += view.size
            if total > 512 << 20: fail("FDI decoded data exceeds bound")
            metadata = source.cab_metadata
            notice = _notification(machine, event.args[6], filename, view.size, metadata)
            output = _invoke(machine, event.args[4], [2, notice["address"]], "FDI copy-file notification")
            machine.free(notice["address"])
            machine.free(notice["name"])
            if output != 0 and len(state["actions"]) < 256:
                state["actions"].append({"api": "fdinotify", "type": "copy", "file": filename, "size": view.size, "result": output})
            if output == 0:
                skipped += 1
                continue
            if output == (1 << (machine.pointer_size*8))-1:
                set_error(machine, context, 11, 0)  # FDIERROR_USER_ABORT
                return 0
            address = machine.allocate(size = 65536, name = "FDI output buffer")
            for offset in range(0, view.size, 65536):
                chunk = view.bytes(offset, min(65536, view.size-offset))
                machine.write(address, chunk)
                written = _invoke(machine, context["write"], [output, address, len(chunk)], "FDI write callback") & 0xffffffff
                if written != len(chunk):
                    machine.free(address)
                    set_error(machine, context, 8, 112)  # FDIERROR_TARGET_FILE
                    return 0
            machine.free(address)
            close_notice = _notification(machine, event.args[6], filename, view.size, metadata, handle = output)
            closed = _invoke(machine, event.args[4], [3, close_notice["address"]], "FDI close-file notification")
            machine.free(close_notice["address"])
            machine.free(close_notice["name"])
            if len(state["actions"]) < 256:
                state["actions"].append({"api": "fdinotify", "type": "close", "file": filename, "result": closed})
            if closed == 0:
                set_error(machine, context, 11, 0)  # FDIERROR_USER_ABORT
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
