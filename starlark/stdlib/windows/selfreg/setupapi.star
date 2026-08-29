"""SetupAPI services used by setup-time module execution."""

_INF_CONTEXT_MAGIC = 0x54525849  # "IXRT", private to the emulator model.

_SIGNATURES = {
    "setupclosefilequeue": 1,
    "setupaddinstallsectiontodiskspacelistw": 6,
    "setupcloseinffile": 1,
    "setupcloselog": 0,
    "setupcommitfilequeuea": 4,
    "setupdefaultqueuecallbacka": 4,
    "setupfindfirstlinea": 4,
    "setupfindfirstlinew": 4,
    "setupfindnextline": 2,
    "setupfindnextmatchlinew": 3,
    "setupgetlinebyindexa": 4,
    "setupgetlinetexta": 7,
    "setupgetlinetextw": 7,
    "setupgetstringfielda": 5,
    "setupgettargetpathw": 6,
    "setupinstallfilesfrominfsectionw": 6,
    "setupinitdefaultqueuecallbackex": 5,
    "setupinstallfrominfsectiona": 11,
    "setupinstallfrominfsectionw": 11,
    "setupinstallservicesfrominfsectionw": 3,
    "setuplogerrora": 2,
    "setupopenappendinffilea": 3,
    "setupopenfilequeue": 0,
    "setupopeninffilea": 4,
    "setupopenlog": 1,
    "setupqueuecopya": 9,
    "setupremoveinstallsectionfromdiskspacelistw": 6,
    "setupsetdirectoryida": 3,
    "setupsetdirectoryidw": 3,
    "setuptermdefaultqueuecallback": 1,
}

def _rows(value):
    if type(value) != "list":
        return []
    if not value or type(value[0]) != "list":
        return [value]
    return value

def _section_lines(inf, section_name):
    """Returns ordered SetupAPI-style lines from one parsed INF section."""
    section = inf.section(section_name)
    if section == None:
        return []
    lines = []
    for key, value in section.items():
        for row in _rows(value):
            lines.append({
                "key": "" if key.startswith("@") else key,
                "fields": [str(field) for field in row],
            })
    return lines

def _find_line(inf, section_name, key = "", after = -1):
    lines = _section_lines(inf, section_name)
    wanted = key.lower()
    for index in range(after + 1, len(lines)):
        if not wanted or lines[index]["key"].lower() == wanted:
            return {"section": section_name, "lines": lines, "index": index}
    return None

def _line_text(line):
    """Returns the value text exposed by SetupGetLineText, excluding the key."""
    return ",".join(line["lines"][line["index"]]["fields"])

def setupapi_plugin(infs = {}, directories = {}, registry = None, kernel = None):
    """Models INF access, install sections, queues, and process-local logging.

    `infs` maps explicit integer HINF values to parsed `windows.inf` objects.
    File operations stay inside the supplied virtual kernel backend and
    registry sections are applied through the live registration model.
    """
    state = {
        "contexts": {},
        "actions": [],
        "directories": dict(directories),
        "infs": dict(infs),
        "messages": [],
        "calls": [],
        "next_context": 1,
        "next_inf": 0x50000,
        "next_queue": 0x51000,
        "queues": {},
        "open": False,
    }

    def inf_for(handle):
        return state["infs"].get(handle)

    def write_context(machine, address, line):
        identifier = state["next_context"]
        state["next_context"] = identifier + 1
        state["contexts"][identifier] = line
        # INFCONTEXT is four DWORDs on 32-bit Windows. Never write beyond it.
        context = binary.builder(capacity = 16)
        context.u32le(_INF_CONTEXT_MAGIC)
        context.u32le(identifier)
        context.u32le(0)
        context.u32le(0)
        machine.write(address, context.bytes())

    def read_context(machine, address):
        if not address:
            return None
        cursor = binary.cursor(machine.read(address, 16))
        if cursor.u32le() != _INF_CONTEXT_MAGIC:
            return None
        return state["contexts"].get(cursor.u32le())

    def find(machine, handle, section_address, key_address, output, wide):
        inf = inf_for(handle)
        if inf == None or not section_address or not output:
            return 0
        encoding = "utf16le" if wide else "ascii"
        section = machine.read_cstring(section_address, encoding = encoding)
        key = machine.read_cstring(key_address, encoding = encoding) if key_address else ""
        line = _find_line(inf, section, key)
        if line == None:
            return 0
        write_context(machine, output, line)
        return 1

    def virtual_path(value):
        return value.replace("/", "\\").rstrip("\\").lower()

    def apply_registry_section(inf, section_name):
        section = inf.section(section_name)
        if section == None:
            return False
        if registry == None:
            return False
        for directive in ["AddReg", "DelReg"]:
            names = section.get(directive, [])
            if type(names) != "list":
                names = [names]
            for section in names:
                for patch in inf.section_patches(section):
                    if directive == "DelReg" or patch.get("delete", False):
                        registry.delete_value(patch["hive"], patch["key"], patch["name"])
                    else:
                        registry.set_value(patch["hive"], patch["key"], patch["name"], patch["type"], patch["value"])
        return True

    def callback(event):
        name = event.name.lower()
        args = event.args
        machine = event.machine
        call = {"api": name}
        if len(state["calls"]) < 4096:
            state["calls"].append(call)
        wide = name.endswith("w")
        encoding = "utf16le" if wide else "ascii"
        if name == "setupopeninffilea":
            if not args[0] or kernel == None:
                return 0xffffffff
            path = virtual_path(machine.read_cstring(args[0], encoding = "ascii"))
            data = kernel.state["file_data"](path)
            if not data:
                if args[3]:
                    machine.write_u32le(args[3], 0)
                return 0xffffffff
            handle = state["next_inf"]
            state["next_inf"] = handle + 1
            state["infs"][handle] = windows.inf(data)
            state["actions"].append({"kind": "open_inf", "path": path, "handle": handle, "sections": sorted(state["infs"][handle].json.keys())})
            return handle
        if name == "setupopenappendinffilea":
            # The Win9x ADVPack path uses this for optional layout metadata.
            # Its primary temporary INF is already complete and remains live.
            call["handle"] = args[1]
            call["result"] = 1 if inf_for(args[1]) != None else 0
            return call["result"]
        if name == "setupopenlog":
            state["open"] = True
            return 1
        if name == "setupcloselog":
            state["open"] = False
            return None
        if name == "setuplogerrora":
            message = machine.read_cstring(args[0]) if args[0] else ""
            state["messages"].append({"message": message, "severity": args[1]})
            return 1
        if name in ["setupfindfirstlinea", "setupfindfirstlinew"]:
            call["handle"] = args[0]
            call["section"] = machine.read_cstring(args[1], encoding = encoding) if args[1] else ""
            call["key"] = machine.read_cstring(args[2], encoding = encoding) if args[2] else ""
            call["result"] = find(machine, args[0], args[1], args[2], args[3], wide)
            return call["result"]
        if name == "setupfindnextline":
            current = read_context(machine, args[0])
            if current == None or not args[1]:
                return 0
            index = current["index"] + 1
            if index >= len(current["lines"]):
                return 0
            write_context(machine, args[1], {
                "section": current["section"],
                "lines": current["lines"],
                "index": index,
            })
            return 1
        if name == "setupfindnextmatchlinew":
            current = read_context(machine, args[0])
            if current == None or not args[1] or not args[2]:
                return 0
            key = machine.read_cstring(args[1], encoding = "utf16le").lower()
            for index in range(current["index"] + 1, len(current["lines"])):
                if current["lines"][index]["key"].lower() == key:
                    write_context(machine, args[2], {
                        "section": current["section"],
                        "lines": current["lines"],
                        "index": index,
                    })
                    return 1
            return 0
        if name in ["setupgetlinetexta", "setupgetlinetextw"]:
            line = read_context(machine, args[0])
            if line == None:
                inf = inf_for(args[1])
                if inf != None and args[2]:
                    section = machine.read_cstring(args[2], encoding = encoding)
                    key = machine.read_cstring(args[3], encoding = encoding) if args[3] else ""
                    line = _find_line(inf, section, key)
            if line == None:
                call["context"] = args[0]
                call["handle"] = args[1]
                call["section"] = machine.read_cstring(args[2], encoding = encoding) if args[2] else ""
                call["key"] = machine.read_cstring(args[3], encoding = encoding) if args[3] else ""
                call["result"] = 0
                return 0
            value = _line_text(line)
            required = len(value) + 1
            call["value"] = value
            call["capacity"] = args[5]
            call["required"] = required
            if args[6]:
                machine.write_u32le(args[6], required)
            if not args[4] or args[5] < required:
                call["result"] = 0
                return 0
            machine.write(args[4], binary.encode(value, encoding = encoding, nul = True))
            call["result"] = 1
            return 1
        if name == "setupgetlinebyindexa":
            inf = inf_for(args[0])
            if inf == None or not args[1] or not args[3]:
                return 0
            section = machine.read_cstring(args[1], encoding = "ascii")
            lines = _section_lines(inf, section)
            if args[2] >= len(lines):
                return 0
            write_context(machine, args[3], {"section": section, "lines": lines, "index": args[2]})
            return 1
        if name == "setupgetstringfielda":
            line = read_context(machine, args[0])
            if line == None:
                return 0
            item = line["lines"][line["index"]]
            value = item["key"] if args[1] == 0 else (item["fields"][args[1] - 1] if args[1] <= len(item["fields"]) else None)
            if value == None:
                return 0
            required = len(value) + 1
            if args[4]:
                machine.write_u32le(args[4], required)
            if not args[2] or args[3] < required:
                return 0
            machine.write(args[2], binary.encode(value, encoding = "ascii", nul = True))
            return 1
        if name in ["setupsetdirectoryida", "setupsetdirectoryidw"]:
            if inf_for(args[0]) == None or not args[2]:
                return 0
            state["directories"][(args[0], args[1])] = machine.read_cstring(args[2], encoding = encoding)
            return 1
        if name == "setupgettargetpathw":
            inf = inf_for(args[0])
            if inf == None or not args[4]:
                return 0
            section = machine.read_cstring(args[2], encoding = "utf16le") if args[2] else ""
            if not section and args[1]:
                context = read_context(machine, args[1])
                section = context["section"] if context != None else ""
            destination = _find_line(inf, "DestinationDirs", section)
            if destination == None:
                destination = _find_line(inf, "DestinationDirs", "DefaultDestDir")
            if destination == None:
                return 0
            fields = destination["lines"][destination["index"]]["fields"]
            if not fields:
                return 0
            directory_id = int(fields[0])
            root = state["directories"].get((args[0], directory_id), state["directories"].get(directory_id))
            if root == None:
                return 0
            suffix = fields[1].strip("\\/") if len(fields) > 1 else ""
            target = root.rstrip("\\/") + ("\\" + suffix if suffix else "")
            required = len(target) + 1
            if args[5]:
                machine.write_u32le(args[5], required)
            state["actions"].append({"kind": "target_path", "handle": args[0], "section": section, "path": target})
            if not args[3] or args[4] < required:
                return 0
            machine.write(args[3], binary.encode(target, encoding = "utf16le", nul = True))
            return 1
        if name in ["setupaddinstallsectiontodiskspacelistw", "setupremoveinstallsectionfromdiskspacelistw"]:
            inf = inf_for(args[1])
            if not args[0] or inf == None or not args[3]:
                return 0
            section = machine.read_cstring(args[3], encoding = "utf16le")
            if inf.section(section) == None:
                return 0
            state["actions"].append({
                "kind": "disk_space_add" if name.startswith("setupadd") else "disk_space_remove",
                "handle": args[1],
                "section": section,
            })
            return 1
        if name == "setupinstallfilesfrominfsectionw":
            inf = inf_for(args[0])
            if inf == None or not args[2] or not args[3]:
                return 0
            section = machine.read_cstring(args[3], encoding = "utf16le")
            if inf.section(section) == None:
                return 0
            state["actions"].append({"kind": "install_files", "handle": args[0], "section": section})
            return 1
        if name == "setupinstallservicesfrominfsectionw":
            inf = inf_for(args[0])
            if inf == None or not args[1]:
                return 0
            section = machine.read_cstring(args[1], encoding = "utf16le")
            if inf.section(section) == None:
                return 0
            state["actions"].append({"kind": "install_services", "handle": args[0], "section": section, "flags": args[2]})
            return 1
        if name in ["setupinstallfrominfsectiona", "setupinstallfrominfsectionw"]:
            inf = inf_for(args[1])
            if inf == None or not args[2]:
                return 0
            section = machine.read_cstring(args[2], encoding = encoding)
            if inf.section(section) == None:
                return 0
            if not apply_registry_section(inf, section):
                return 0
            state["actions"].append({"kind": "install", "handle": args[1], "section": section, "flags": args[3]})
            return 1
        if name == "setupinitdefaultqueuecallbackex":
            return machine.allocate(size = 4, name = "SetupAPI queue callback")
        if name == "setuptermdefaultqueuecallback":
            return None
        if name == "setupdefaultqueuecallbacka":
            return 1
        if name == "setupopenfilequeue":
            handle = state["next_queue"]
            state["next_queue"] = handle + 1
            state["queues"][handle] = []
            return handle
        if name == "setupclosefilequeue":
            state["queues"].pop(args[0], None)
            return None
        if name == "setupqueuecopya":
            queue = state["queues"].get(args[0])
            if queue == None:
                return 0
            def text_at(index):
                return machine.read_cstring(args[index], encoding = "ascii") if args[index] else ""
            queue.append({"source_root": text_at(1), "source_path": text_at(2), "source_name": text_at(3), "target_path": text_at(6), "target_name": text_at(7), "style": args[8]})
            return 1
        if name == "setupcommitfilequeuea":
            queue = state["queues"].get(args[1])
            if queue == None:
                return 0
            # REGINST sections used during DLL setup contain registry work;
            # preserve any explicit queue operations as auditable actions.
            state["actions"].append({"kind": "commit_file_queue", "entries": list(queue)})
            return 1
        if name == "setupcloseinffile":
            return None
        return 0

    def install(machine):
        for function, argc in _SIGNATURES.items():
            machine.provide_export(callback, module = "setupapi.dll", name = function, argc = argc)
        for imported in machine.imports:
            name = imported.name.lower()
            if imported.module.lower() == "setupapi.dll" and name in _SIGNATURES:
                machine.hook(callback, address = imported.address, argc = _SIGNATURES[name])

    return emulator.plugin(install, name = "windows.setupapi", state = state)
