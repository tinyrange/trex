"""Semantic ADVPack registration services for embedded REGINST resources."""

load(":common.star", "expand", "module_replacements")

def _rows(value):
    if type(value) != "list":
        return []
    if not value or type(value[0]) != "list":
        return [value]
    return value

def _module_image(machine, handle, module_images):
    loaded_name = None
    for loaded in machine.modules:
        if loaded.base == handle:
            loaded_name = loaded.name.replace("/", "\\").split("\\")[-1].lower()
            break
    if loaded_name == None:
        return None, ""
    for name, image in module_images.items():
        if name.replace("/", "\\").split("\\")[-1].lower() == loaded_name:
            return image, name
    return None, loaded_name

def _string_table(machine, address):
    output = {}
    if not address:
        return output
    count = machine.read_u32le(address)
    if count > 4096:
        return None
    entries = machine.read_u32le(address + 4)
    if count and not entries:
        return None
    for index in range(count):
        entry = entries + index * 8
        name = machine.read_u32le(entry)
        value = machine.read_u32le(entry + 4)
        if not name or not value:
            return None
        output[machine.read_cstring(name).upper()] = machine.read_cstring(value)
    return output

def _apply_registry_section(inf, section_name, registry):
    section = inf.section(section_name)
    if section == None:
        return None
    applied = []
    for directive in ["DelReg", "AddReg"]:
        names = section.get(directive, [])
        if type(names) != "list":
            names = [names]
        for referenced in names:
            raw_section = inf.section(referenced)
            if raw_section == None:
                return None
            raw_rows = []
            for unused_key, value in raw_section.items():
                raw_rows.extend(_rows(value))
            patches = inf.section_patches(referenced)
            for index, patch in enumerate(patches):
                if directive == "DelReg":
                    raw = raw_rows[index] if index < len(raw_rows) else []
                    if len(raw) <= 2:
                        registry.delete_tree(patch["hive"], patch["key"])
                    else:
                        registry.delete_value(patch["hive"], patch["key"], patch["name"])
                else:
                    registry.set_value(patch["hive"], patch["key"], patch["name"], patch["type"], patch["value"])
                applied.append({"directive": directive, "section": referenced, "patch": patch})
    return applied

def _fixed_file_version(file):
    if file == None:
        return None
    selected = None
    for resource in windows.pe(file).resources:
        if resource["type"] != "#16":
            continue
        selected = resource["data"]
        if resource["lang"] == "#1033":
            break
    if selected == None or len(selected) < 40:
        return None
    # VS_VERSION_INFO's fixed value begins after its UTF-16 key, aligned to a
    # DWORD. Validate VS_FIXEDFILEINFO before exposing its version halves.
    cursor = binary.cursor(selected)
    cursor.seek(6)
    offset = 6
    while offset + 2 <= len(selected):
        cursor.seek(offset)
        if cursor.u16le() == 0:
            break
        offset += 2
    value = (offset + 2 + 3) & ~3
    if value + 16 > len(selected):
        return None
    cursor.seek(value)
    if cursor.u32le() != 0xfeef04bd:
        return None
    cursor.u32le()
    return cursor.u32le(), cursor.u32le()

def _bytes_file(data):
    if not data:
        return None
    output = binary.builder(capacity = len(data))
    output.append(data)
    return output.file()

def advpack_plugin(registry, module_images, kernel = None, setup = None):
    """Implements RegInstall directly from a loaded module's REGINST data.

    The embedded INF stays in memory throughout parsing, substitution, and
    registry application. This avoids running ADVPack as an image-building
    helper while preserving the selected section and caller-supplied string
    table semantics.
    """
    state = {"actions": []}

    def callback(event):
        name = event.name.lower()
        machine = event.machine
        if name == "getversionfromfile":
            filename = machine.read_cstring(event.args[0]) if event.args[0] else ""
            normalized = filename.replace("/", "\\").lower()
            data = kernel.state["file_data"](normalized) if kernel != None else b""
            version = _fixed_file_version(_bytes_file(data))
            state["actions"].append({"api": "GetVersionFromFile", "file": filename, "found": version != None})
            if version == None:
                return 1
            if event.args[1]:
                machine.write_u32le(event.args[1], version[0])
            if event.args[2]:
                machine.write_u32le(event.args[2], version[1])
            return 0
        if name == "runsetupcommand":
            command = machine.read_cstring(event.args[1]) if event.args[1] else ""
            section = machine.read_cstring(event.args[2]) if event.args[2] else ""
            flags = event.args[6]
            action = {
                "api": "RunSetupCommand",
                "command": command,
                "section": section,
                "directory": machine.read_cstring(event.args[3]) if event.args[3] else "",
                "title": machine.read_cstring(event.args[4]) if event.args[4] else "",
                "flags": flags,
                "result": 0x80070002,
            }
            state["actions"].append(action)
            # RSC_FLAG_INF selects an in-memory INF section rather than a
            # child process. This is the path used by IE4UINIT on Windows 98.
            if not (flags & 1) or kernel == None or not command or not section:
                return action["result"]
            data = kernel.state["file_data"](command.replace("/", "\\").lower())
            source = _bytes_file(data)
            if source == None:
                return action["result"]
            inf = windows.inf(source)
            selected = inf.section(section)
            if selected == None:
                return action["result"]
            applied = _apply_registry_section(inf, section, registry)
            if applied == None:
                return 0x8007000d
            updates = []
            for referenced in selected.get("UpdateInis", []):
                update = inf.section(referenced)
                if update == None:
                    return 0x8007000d
                updates.append({"section": referenced, "entries": update})
            # File directives require queue/copy semantics and must not be
            # silently accepted by this setup-time model.
            if selected.get("CopyFiles", []) or selected.get("DelFiles", []):
                return 0x80004001
            action["patches"] = len(applied)
            action["update_inis"] = updates
            action["result"] = 0
            return 0
        if name == "executecab":
            info = event.args[1]
            action = {"api": "ExecuteCab", "result": 0x80070057}
            state["actions"].append(action)
            if not info:
                return action["result"]
            cab = machine.read_u32le(info)
            inf = machine.read_u32le(info + 4)
            section = machine.read_u32le(info + 8)
            cab_name = machine.read_cstring(cab) if cab else ""
            inf_name = machine.read_cstring(inf) if inf else ""
            section_name = machine.read_cstring(section) if section else ""
            action.update({
                "cab": cab_name,
                "inf": inf_name,
                "section": section_name,
                "source": machine.read_cstring(info + 12),
                "flags": machine.read_u32le(info + 272),
            })
            # A CABINFO with no cabinet names an already-installed INF. Apply
            # its platform-specific registry phase directly from the virtual
            # guest filesystem. Cabinet extraction remains a distinct, explicit
            # operation and is never reported as successful here.
            if cab_name or kernel == None or not inf_name:
                return 0x80004001 if cab_name else action["result"]
            source = _bytes_file(kernel.state["file_data"](inf_name.replace("/", "\\").lower()))
            if source == None:
                return 0x80070002
            parsed = windows.inf(source)
            requested = section_name if section_name else "DefaultInstall"
            selected = parsed.section(requested)
            if selected == None:
                requested += ".Win"
                selected = parsed.section(requested)
            if selected == None:
                return 0x8007000d
            applied = _apply_registry_section(parsed, requested, registry)
            if applied == None:
                return 0x8007000d
            action["resolved_section"] = requested
            action["patches"] = len(applied)
            action["directives"] = sorted(selected.keys())
            action["result"] = 0
            return 0
        image, module_name = _module_image(machine, event.args[0], module_images)
        section_name = machine.read_cstring(event.args[1]) if event.args[1] else ""
        replacements = _string_table(machine, event.args[2])
        action = {"module": module_name, "section": section_name, "result": 0x80004005}
        state["actions"].append(action)
        if image == None or not section_name or replacements == None:
            return action["result"]
        variables = module_replacements(module_name)
        for name, value in replacements.items():
            variables[name] = value
        for resource in windows.pe(image).resources:
            if resource["type"].upper() != "REGINST":
                continue
            inf = windows.inf(expand(resource["text"], variables))
            applied = _apply_registry_section(inf, section_name, registry)
            if applied == None:
                continue
            action["patches"] = len(applied)
            action["result"] = 0
            return 0
        return action["result"]

    def install(machine):
        machine.provide_export(callback, module = "advpack.dll", name = "RegInstall", argc = 3)
        machine.provide_export(callback, module = "advpack.dll", name = "GetVersionFromFile", argc = 4)
        machine.provide_export(callback, module = "advpack.dll", name = "RunSetupCommand", argc = 8)
        machine.provide_export(callback, module = "advpack.dll", name = "ExecuteCab", argc = 3)

    return emulator.plugin(install, name = "windows.advpack", state = state)
