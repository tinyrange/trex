"""Process-local Windows Error Reporting registration semantics."""

_SIGNATURES = {
    "wergetflags": 2,
    "werreportadddump": 7,
    "werreportaddfile": 4,
    "werreportclosehandle": 1,
    "werreportcreate": 4,
    "werreportsetparameter": 4,
    "werreportsetuioption": 3,
    "werreportsubmit": 4,
    "werregisterfile": 3,
    "werregistercustommetadata": 2,
    "werregistermemoryblock": 2,
    "werregisterruntimeexceptionmodule": 2,
    "wersetflags": 1,
    "werunregisterfile": 1,
    "werunregistercustommetadata": 1,
    "werunregistermemoryblock": 1,
    "werunregisterruntimeexceptionmodule": 2,
}

def wer_plugin():
    """Models WER's in-process registration surface without reporting externally."""
    state = {"flags": 0, "files": {}, "custom_metadata": {}, "memory_blocks": {}, "runtime_modules": {}, "reports": {}, "next_report": 0x57000, "actions": []}

    def callback(event):
        name = event.name.lower()
        args = event.args
        if name == "wersetflags":
            state["flags"] = args[0]
            state["actions"].append({"api": name, "flags": args[0]})
            return 0
        if name == "wergetflags":
            if not args[1]:
                return 0x80070057  # E_INVALIDARG
            event.machine.write_u32le(args[1], state["flags"])
            state["actions"].append({"api": name, "process": args[0]})
            return 0
        if name == "werreportcreate":
            if not args[0] or not args[3]:
                return 0x80070057
            event_type = event.machine.read_cstring(args[0], encoding = "utf16le")
            handle = state["next_report"]
            state["next_report"] = handle + 1
            state["reports"][handle] = {
                "event_type": event_type,
                "type": args[1],
                "information": args[2],
                "parameters": {},
                "files": [],
                "dumps": [],
                "ui_options": {},
            }
            event.machine.write_u32le(args[3], handle)
            state["actions"].append({"api": name, "handle": handle, "event_type": event_type, "type": args[1]})
            return 0
        if name == "werreportsetparameter":
            report = state["reports"].get(args[0])
            if report == None or not args[2] or not args[3]:
                return 0x80070057
            parameter_name = event.machine.read_cstring(args[2], encoding = "utf16le")
            value = event.machine.read_cstring(args[3], encoding = "utf16le")
            report["parameters"][args[1]] = {"name": parameter_name, "value": value}
            state["actions"].append({"api": name, "handle": args[0], "id": args[1], "name": parameter_name, "value": value})
            return 0
        if name == "werreportaddfile":
            report = state["reports"].get(args[0])
            if report == None or not args[1]:
                return 0x80070057
            path = event.machine.read_cstring(args[1], encoding = "utf16le")
            report["files"].append({"path": path, "type": args[2], "flags": args[3]})
            state["actions"].append({"api": name, "handle": args[0], "path": path, "type": args[2], "flags": args[3]})
            return 0
        if name == "werreportadddump":
            report = state["reports"].get(args[0])
            if report == None:
                return 0x80070057
            dump = {"process": args[1], "thread": args[2], "type": args[3], "exception": args[4], "options": args[5], "flags": args[6]}
            report["dumps"].append(dump)
            state["actions"].append(dict(dump, api = name, handle = args[0]))
            return 0
        if name == "werreportsetuioption":
            report = state["reports"].get(args[0])
            if report == None:
                return 0x80070057
            value = event.machine.read_cstring(args[2], encoding = "utf16le") if args[2] else ""
            report["ui_options"][args[1]] = value
            state["actions"].append({"api": name, "handle": args[0], "option": args[1], "value": value})
            return 0
        if name == "werreportsubmit":
            report = state["reports"].get(args[0])
            if report == None:
                return 0x80070057
            if args[3]:
                event.machine.write_u32le(args[3], 1)  # WerReportQueued
            report["submitted"] = {"consent": args[1], "flags": args[2]}
            state["actions"].append({"api": name, "handle": args[0], "consent": args[1], "flags": args[2]})
            return 0
        if name == "werreportclosehandle":
            if state["reports"].pop(args[0], None) == None:
                return 0x80070006  # HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)
            state["actions"].append({"api": name, "handle": args[0]})
            return 0
        if name == "werregisterruntimeexceptionmodule":
            if not args[0]:
                return 0x80070057
            path = event.machine.read_cstring(args[0], encoding = "utf16le")
            state["runtime_modules"][path.lower()] = {"path": path, "context": args[1]}
            state["actions"].append({"api": name, "path": path, "context": args[1]})
            return 0
        if name == "werregistercustommetadata":
            if not args[0] or not args[1]:
                return 0x80070057
            key = event.machine.read_cstring(args[0], encoding = "utf16le")
            value = event.machine.read_cstring(args[1], encoding = "utf16le")
            state["custom_metadata"][key] = value
            state["actions"].append({"api": name, "key": key, "value": value})
            return 0
        if name == "werunregistercustommetadata":
            if not args[0]:
                return 0x80070057
            key = event.machine.read_cstring(args[0], encoding = "utf16le")
            state["custom_metadata"].pop(key, None)
            state["actions"].append({"api": name, "key": key})
            return 0
        if name == "werunregisterruntimeexceptionmodule":
            if not args[0]:
                return 0x80070057
            path = event.machine.read_cstring(args[0], encoding = "utf16le")
            state["runtime_modules"].pop(path.lower(), None)
            state["actions"].append({"api": name, "path": path, "context": args[1]})
            return 0
        if name == "werregisterfile":
            if not args[0]:
                return 0x80070057
            path = event.machine.read_cstring(args[0], encoding = "utf16le")
            state["files"][path.lower()] = {"path": path, "type": args[1], "flags": args[2]}
            state["actions"].append({"api": name, "path": path, "type": args[1], "flags": args[2]})
            return 0
        if name == "werunregisterfile":
            if not args[0]:
                return 0x80070057
            path = event.machine.read_cstring(args[0], encoding = "utf16le")
            state["files"].pop(path.lower(), None)
            state["actions"].append({"api": name, "path": path})
            return 0
        if name == "werregistermemoryblock":
            if not args[0] or not args[1]:
                return 0x80070057
            state["memory_blocks"][args[0]] = args[1]
            state["actions"].append({"api": name, "address": args[0], "size": args[1]})
            return 0
        if name == "werunregistermemoryblock":
            state["memory_blocks"].pop(args[0], None)
            state["actions"].append({"api": name, "address": args[0]})
            return 0
        return 0x80004001  # E_NOTIMPL

    def install(machine):
        for name, argc in _SIGNATURES.items():
            machine.provide_export(callback, module = "wer.dll", name = name, argc = argc)
            if name in ["werregistercustommetadata", "werunregistercustommetadata"]:
                machine.provide_export(callback, module = "kernel32.dll", name = name, argc = argc)
        for imported in machine.imports:
            name = imported.name.lower()
            if imported.module.lower() == "wer.dll" and name in _SIGNATURES or imported.module.lower() == "kernel32.dll" and name in ["werregistercustommetadata", "werunregistercustommetadata"]:
                machine.hook(callback, address = imported.address, argc = _SIGNATURES[name])

    return emulator.plugin(install, name = "windows.wer", state = state)
