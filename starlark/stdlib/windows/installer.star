"""Portable analysis of Windows installer plans and packaged PE side effects."""

load("@stdlib//windows/selfreg:policy.star", "registration_patches")
load("@stdlib//windows/emulation:runner.star", _run = "run")

def _base(value):
    return value.replace("/", "\\").split("\\")[-1]

def _service_patches(patches):
    output = []
    for patch in patches:
        key = patch.get("key", "").replace("\\", "/").lower()
        if "/services/" in key:
            output.append(patch)
    return output

def _custom_execution(file, module, action, modules, files, environment, version, instruction_limit, memory_limit):
    def prepare(machine):
        output = []
        arguments = action["arguments"]
        types = action["argument_types"]
        for index in range(len(arguments)):
            value = arguments[index]
            argument_type = types[index] if index < len(types) else {}
            concrete = argument_type.get("concrete_type", 0)
            if argument_type.get("by_reference", False):
                storage = binary.builder(capacity = 4)
                storage.u32le(0 if value == None else value)
                output.append(machine.allocate(value = storage.bytes(), name = "installer numeric argument"))
            elif concrete in [2, 5]:
                output.append(machine.allocate(value = binary.encode(value + "\x00", encoding = "ascii"), name = "installer argument"))
            elif value == None:
                output.append(machine.allocate(size = 4, name = "installer output argument"))
            else:
                output.append(value)
        return output
    return _run(
        file,
        module,
        export = action["callee"],
        prepare = prepare,
        # Custom bootstrap helpers are separate from the installed payload.
        # Do not initialize every packaged DLL merely because it is available
        # in the eventual target directory.
        modules = {},
        files = files,
        registry_values = action.get("registry_values", []),
        registry_keys = action.get("registry_keys", []),
        environment = environment,
        version = version,
        initialize = True,
        instruction_limit = action.get("instruction_limit", instruction_limit),
        memory_limit = action.get("memory_limit", memory_limit),
        system_time = action.get("system_time", 946684800),
    )

def _custom_preparable(action):
    arguments = action["arguments"]
    types = action["argument_types"]
    for index in range(len(arguments)):
        if arguments[index] != None:
            continue
        concrete = types[index]["concrete_type"] if index < len(types) else 0
        if concrete not in [3, 6]:
            return False
    return True

def _installed_artifact_module(plan_files, source, fallback):
    matches = {}
    for entry in plan_files:
        if entry.get("resolved", False) and entry.get("source", "").lower() == source.lower():
            matches[entry["destination"].lower()] = entry["destination"]
    if len(matches) == 1:
        return matches.values()[0]
    return fallback

def analyze(installer, plan = None, execute_registration = True, environment = {}, version = {}, instruction_limit = 250000, memory_limit = 32 << 20):
    """Analyzes script, driver, custom-DLL, and self-registration effects.

    Every input and dependency remains a trex file. Registration exports
    run in the bounded in-memory x86 emulator with semantic Win32 APIs; no
    payload is staged on the host and no native installer code is launched.
    """
    if plan == None:
        plan = installer.plan()
    guest_files = {}
    modules = {}
    for entry in plan["files"]:
        source = installer.container.find(entry["source"]) if entry.get("container", False) else installer.find(entry["source"])
        if source == None:
            continue
        destination = entry["destination"] if entry["resolved"] else entry["source"]
        guest_files[destination] = source
        name = _base(destination).lower()
        if name.endswith(".dll"):
            modules[name] = source

    registrations = []
    services = []
    for artifact in plan["artifacts"]:
        if artifact["kind"] not in ["self_registration", "self_registration_metadata"]:
            continue
        source = installer.find(artifact["source"])
        if source == None or source.size == 0:
            continue
        module = _installed_artifact_module(plan["files"], artifact["source"], artifact["name"])
        result = registration_patches(
            source,
            module,
            execute = execute_registration,
            execute_with_static = True,
            environment = environment,
            version = version,
            modules = modules,
            files = guest_files,
            instruction_limit = instruction_limit,
            memory_limit = memory_limit,
        )
        registrations.append({"source": artifact["source"], "module": module, "result": result})
        services.extend(_service_patches(result["patches"]))

    container_modules = {}
    for source_path in installer.container.files:
        name = _base(source_path).lower()
        if name.endswith(".dll"):
            container_modules[name] = installer.container[source_path]
    custom_executions = []
    custom_seen = {}
    for action in plan["custom_actions"]:
        module_name = action["dll"].lower()
        if not module_name.endswith(".dll"):
            module_name += ".dll"
        image = container_modules.get(module_name, modules.get(module_name))
        identity = module_name + ":" + action["callee"] + ":" + repr(action["arguments"])
        if image == None or not _custom_preparable(action) or identity in custom_seen:
            continue
        exports = {item.get("name", "").lower(): True for item in windows.pe(image).exports}
        if action["callee"].lower() not in exports:
            continue
        custom_seen[identity] = True
        action_files = dict(guest_files)
        for argument in action["arguments"]:
            if type(argument) != "string" or "." in _base(argument):
                continue
            for dependency_name, dependency in container_modules.items():
                action_files[argument.rstrip("\\/") + "\\" + dependency_name] = dependency
        execution = _custom_execution(image, module_name, action, modules, action_files, environment, version, instruction_limit, memory_limit)
        custom_executions.append({"action": action, "execution": execution})
        services.extend(_service_patches(execution["patches"]))

    return {
        "registry": plan["registry"],
        "registry_writes": plan["registry_writes"],
        "definitive_registry_writes": plan["definitive_registry_writes"],
        "registrations": registrations,
        "services": services,
        "drivers": [item for item in plan["artifacts"] if item["kind"] == "driver"],
        "custom_actions": plan["custom_actions"],
        "custom_executions": custom_executions,
        "target_defaults": plan["target_defaults"],
        "script_evaluation": plan["script_evaluation"],
    }

def _default_components(package):
    output = []
    if package.payload == None or not hasattr(package.payload, "components"):
        return None
    for component in package.payload.components:
        name = component["name"]
        folded = name.lower()
        if folded.startswith("<data>/") and not folded.startswith("<data>/disk<"):
            output.append(name)
    return output if output else None

def _safe_filename(name):
    result = name
    invalid = '<>:"/\\|?*'
    for index in range(len(invalid)):
        result = result.replace(invalid[index], "_")
    return result

def _versioned_image_name(name):
    folded = name.lower()
    return any([folded.endswith(extension) for extension in [".cpl", ".dll", ".drv", ".exe", ".ocx", ".scr"]])

def _portable_pe_image(file):
    view = binary.view(file)
    if view.size < 0x40 or view.slice(0, 2).bytes() != b"MZ":
        return False
    offset = binary.read_u32le(view, 0x3c)
    return offset <= view.size - 4 and view.slice(offset, 4).bytes() == b"PE\x00\x00"

def _casefold_get(mapping, name):
    folded = name.lower()
    for key, value in mapping.items():
        if key.lower() == folded:
            return value
    return None

def _inf_rows(value):
    if type(value) != "list":
        return []
    return value if value and type(value[0]) == "list" else [value]

def _inf_value(section, name, default = None):
    if section == None:
        return default
    folded = name.lower()
    for key, value in section.items():
        if key.lower() == folded:
            return value
    return default

def _inf_directives(section, name):
    value = _inf_value(section, name, [])
    if type(value) != "list":
        return []
    if value and type(value[0]) == "list":
        output = []
        for row in value:
            output.extend(row)
        return output
    return value

def _advanced_inf_expand(value, directories, strings):
    if type(value) == "list":
        return [_advanced_inf_expand(item, directories, strings) for item in value]
    if type(value) != "string":
        return value
    result = value
    for unused in range(8):
        previous = result
        for name, replacement in strings.items():
            for token in ["%" + name + "%", "%" + name.lower() + "%", "%" + name.upper() + "%"]:
                result = result.replace(token, replacement)
        for identifier, replacement in directories.items():
            result = result.replace("%" + identifier + "%", replacement)
        if result == previous:
            break
    return result

def _advanced_inf_unquote(value):
    """Removes balanced INF field quotes retained by the generic parser."""
    if type(value) != "string" or len(value) < 2:
        return value
    if value[0] == value[-1] and value[0] in ["'", '"']:
        return value[1:-1]
    return value

def _advanced_inf_csv(value):
    """Splits the comma-separated value nested inside an INF string field."""
    output = []
    field = ""
    quoted = False
    skip = False
    for index in range(len(value)):
        if skip:
            skip = False
            continue
        character = value[index]
        if character == '"':
            if quoted and index + 1 < len(value) and value[index + 1] == '"':
                field += '"'
                skip = True
            else:
                quoted = not quoted
        elif character == "," and not quoted:
            output.append(field.strip())
            field = ""
        else:
            field += character
    output.append(field.strip())
    return output

def _advanced_inf_section_line(section, name, default = ""):
    rows = _inf_rows(_inf_value(section, name, []))
    if not rows:
        return default
    return ",".join([str(field) for field in rows[0]])

def _advanced_inf_per_user_modifications(section, directories, strings):
    """Returns the Active Setup values written by PerUserInstall."""
    guid = _advanced_inf_expand(_advanced_inf_section_line(section, "GUID"), directories, strings)
    if not guid:
        return []
    key = r"SOFTWARE\Microsoft\Active Setup\Installed Components" + "\\" + guid
    values = [
        ("StubPath", "StubPath"),
        ("Version", "Version"),
        ("Locale", "Locale"),
        ("ComponentID", "ComponentID"),
        ("DisplayName", "(default)"),
    ]
    output = []
    for source_name, registry_name in values:
        value = _advanced_inf_expand(_advanced_inf_section_line(section, source_name), directories, strings)
        if value:
            output.append({
                "operation": "registry_set_value",
                "root": "HKEY_LOCAL_MACHINE",
                "key": key,
                "name": registry_name,
                "type": "REG_SZ",
                "value": value,
            })
    installed = _advanced_inf_section_line(section, "IsInstalled", "0")
    output.append({
        "operation": "registry_set_value",
        "root": "HKEY_LOCAL_MACHINE",
        "key": key,
        "name": "IsInstalled",
        "type": "REG_DWORD",
        "value": int(installed),
    })
    return output

def _parent_path(value):
    fields = value.replace("/", "\\").split("\\")
    return "\\".join(fields[:-1])

def _advanced_inf_update_inis(inf, section_names, directories, strings, installed_files, system_root):
    """Models Setup.ini Program Manager groups as native shell links."""
    groups = {}
    modifications = []
    programs = system_root + r"\Start Menu\Programs"
    for section_name in section_names:
        section = inf.section(section_name)
        if section == None:
            continue
        for value in section.values():
            for raw_row in _inf_rows(value):
                row = _advanced_inf_expand(raw_row, directories, strings)
                if len(row) < 4 or row[0].lower() != "setup.ini":
                    continue
                ini_section = row[1]
                new_entry = row[3]
                if ini_section.lower() == "progman.groups":
                    assignment = _advanced_inf_csv(new_entry)
                    if not assignment:
                        continue
                    fields = assignment[0].split("=")
                    group = fields[0].strip()
                    if group:
                        groups[group.lower()] = "=".join(fields[1:]).strip()
                    continue
                group_name = groups.get(ini_section.lower())
                if group_name == None:
                    continue
                fields = _advanced_inf_csv(new_entry)
                if not fields or not fields[0]:
                    continue
                link_name = fields[0]
                directory = programs + ("\\" + group_name if group_name else "")
                link_path = directory + "\\" + _safe_filename(link_name) + ".lnk"
                target = fields[1] if len(fields) > 1 else ""
                if not target or target.lower() == "null":
                    modifications.append({"operation": "delete_file", "path": link_path})
                    continue
                target_file = _casefold_get(installed_files, target)
                working_directory = fields[5] if len(fields) > 5 and fields[5] else _parent_path(target)
                icon = fields[2] if len(fields) > 2 and fields[2] else target
                icon_index = int(fields[3]) if len(fields) > 3 and fields[3] else 0
                description = fields[6] if len(fields) > 6 and fields[6] else link_name
                modifications.append({
                    "operation": "write_file",
                    "path": link_path,
                    "source": windows.shortcut(
                        target = target,
                        description = description,
                        working_dir = working_directory,
                        icon_location = icon,
                        icon_index = icon_index,
                        target_size = target_file.size if target_file != None else 0,
                        system_root = system_root,
                    ),
                    "replace": "always",
                })
    return modifications

def _advanced_inf_directories(inf, system_root):
    directories = {
        "10": system_root,
        "11": system_root + r"\SYSTEM",
        "12": system_root + r"\SYSTEM\IOSUBSYS",
        "13": system_root + r"\COMMAND",
        "17": system_root + r"\INF",
        "18": system_root + r"\HELP",
        "20": system_root + r"\FONTS",
        "21": system_root + r"\SYSTEM\VIEWERS",
        "22": system_root + r"\SYSTEM\VMM32",
        "23": system_root + r"\SYSTEM\COLOR",
        # Advanced INF uses DIRID 24 for the drive root.  In particular,
        # Microsoft's media installers express Program Files as
        # %24%\Program Files and use DIRID 25 for the Windows directory.
        "24": "C:",
        "25": system_root,
        "26": system_root + r"\COMMAND",
        "27": system_root + r"\TEMP",
        "28": system_root,
        "30": "C:\\",
        "36": system_root + r"\CURSORS",
        "28700": r"C:\Program Files",
        "28701": r"C:\Program Files",
        "28702": r"C:\Program Files",
        "28730": r"C:\Program Files\Common Files",
        "28732": r"C:\Program Files\Common Files",
        "28740": r"C:\Program Files\Common Files\Microsoft Shared",
        "28742": r"C:\Program Files\Common Files\Microsoft Shared",
    }
    strings = {}
    for name, value in (inf.section("Strings") or {}).items():
        rows = _inf_rows(value)
        if rows and rows[0]:
            strings[name] = str(rows[0][0])
    default = inf.section("DefaultInstall")
    for destination_section in _inf_directives(default, "CustomDestination"):
        custom = inf.section(destination_section)
        if custom == None:
            continue
        pending = []
        for identifiers, resolver in custom.items():
            pending.append((identifiers.split(","), resolver[0] if resolver else ""))
        for unused in range(len(pending) + 2):
            progressed = False
            remaining = []
            for identifiers, resolver_name in pending:
                resolver = inf.section(resolver_name)
                rows = [] if resolver == None else [row for value in resolver.values() for row in _inf_rows(value)]
                fallback = rows[0][4] if rows and len(rows[0]) > 4 else None
                if fallback == None:
                    remaining.append((identifiers, resolver_name))
                    continue
                # Advanced INF custom-destination records commonly use single
                # quotes around their prompt and fallback fields. SetupAPI
                # treats those as field delimiters even though ordinary INF
                # string values preserve apostrophes.
                resolved = _advanced_inf_expand(_advanced_inf_unquote(fallback), directories, strings)
                if "%" in resolved:
                    remaining.append((identifiers, resolver_name))
                    continue
                for identifier in identifiers:
                    directories[identifier.strip()] = resolved.rstrip("\\")
                progressed = True
            pending = remaining
            if not pending or not progressed:
                break
    return directories, strings

def _advanced_inf_member(package, name):
    normalized = name.replace("\\", "/").split("/")[-1].lower()
    for path in package.files:
        if path.replace("\\", "/").split("/")[-1].lower() == normalized:
            return package.find(path)
    return None

def _advanced_inf_destination(inf, section_name, directories, strings):
    destinations = inf.section("DestinationDirs")
    row = _inf_value(destinations, section_name)
    if row == None:
        row = _inf_value(destinations, "DefaultDestDir", ["11"])
    rows = _inf_rows(row)
    fields = rows[0] if rows else ["11"]
    root = directories.get(str(fields[0]), directories["11"])
    if len(fields) > 1 and fields[1]:
        root += "\\" + _advanced_inf_expand(fields[1], directories, strings).strip("\\")
    return root.rstrip("\\")

def _advanced_inf_file_rows(inf, section_name):
    section = inf.section(section_name)
    return [] if section == None else [row for value in section.values() for row in _inf_rows(value)]

def _advanced_inf_registry_modification(patch, directories, strings, delete = False):
    hive = patch["hive"]
    key = patch["key"].replace("\\", "/").strip("/")
    if hive == "SOFTWARE":
        root = "HKEY_LOCAL_MACHINE"
        key = "SOFTWARE" + ("\\" + key.replace("/", "\\") if key else "")
    elif hive == "SYSTEM":
        root = "HKEY_LOCAL_MACHINE"
        key = "SYSTEM" + ("\\" + key.replace("/", "\\") if key else "")
    elif hive == "DEFAULT":
        root = "HKEY_CURRENT_USER"
        key = key.replace("/", "\\")
    else:
        return None
    modification = {
        "operation": "registry_delete_value" if delete else "registry_set_value",
        "root": root,
        "key": key,
        "name": patch["name"],
    }
    if not delete:
        modification["type"] = patch["type"]
        modification["value"] = _advanced_inf_expand(patch["value"], directories, strings)
    return modification

def _advanced_inf_registry_patch(modification):
    """Converts one public image modification into self-registration state."""
    operation = modification.get("operation", "")
    if operation not in ["registry_set_value", "registry_delete_value"]:
        return None
    root = modification.get("root", "").upper()
    key = modification.get("key", "").replace("/", "\\").strip("\\")
    if root == "HKEY_LOCAL_MACHINE" and key.upper().startswith("SOFTWARE"):
        hive = "SOFTWARE"
        key = key[8:].strip("\\")
    elif root == "HKEY_LOCAL_MACHINE" and key.upper().startswith("SYSTEM"):
        hive = "SYSTEM"
        key = key[6:].strip("\\")
    elif root == "HKEY_CURRENT_USER":
        hive = "DEFAULT"
    else:
        return None
    patch = {
        "hive": hive,
        "key": "/" + key.replace("\\", "/") if key else "/",
        "name": modification.get("name", "(default)"),
        "type": modification.get("type", "REG_SZ"),
        "value": modification.get("value", ""),
    }
    if operation == "registry_delete_value":
        patch["delete"] = True
    return patch

def _advanced_inf_registry_state(modifications):
    return [
        patch
        for patch in [_advanced_inf_registry_patch(item) for item in modifications]
        if patch != None
    ]

def _advanced_inf_command(section, directories, strings):
    """Returns command lines from one Advanced INF command section."""
    if section == None:
        return []
    commands = []
    for value in section.values():
        for row in _inf_rows(value):
            if row:
                commands.append(_advanced_inf_expand(",".join([str(field) for field in row]), directories, strings))
    return commands

def _advanced_inf_command_target(command, installed_files):
    """Resolves a command's executable against the package-installed files."""
    value = command.strip()
    if not value:
        return None
    if value.startswith('"'):
        end = value.find('"', 1)
        if end < 0:
            return None
        requested = value[1:end]
    else:
        requested = value.split(" ", 1)[0]
    requested = requested.replace("/", "\\")
    requested_name = _base(requested).lower()
    requested_path = requested.lower()
    candidates = []
    for path, source in installed_files.items():
        if _base(path).lower() != requested_name:
            continue
        if "\\" in requested and path.lower() != requested_path:
            continue
        if _portable_pe_image(source):
            candidates.append((path, source))
    if len(candidates) > 1:
        fail("Advanced INF command target is ambiguous: " + command)
    return candidates[0] if candidates else None

def _advanced_inf_run_commands(commands, modifications, installed_files, version):
    """Derives durable effects from package-owned Advanced INF helpers."""
    for command in commands:
        target = _advanced_inf_command_target(command, installed_files)
        # System-owned launchers (for example rundll32.exe) are outside this
        # package's construction graph. Their declarative INF targets are
        # already traversed directly by the planner.
        if target == None:
            continue
        path, source = target
        effects = registration_patches(
            source,
            path,
            execute = True,
            executable = True,
            command_line = command,
            files = installed_files,
            registry_values = _advanced_inf_registry_state(modifications),
            version = version,
            instruction_limit = 3000000,
        )
        executions = effects["executions"]
        if not executions:
            fail("Advanced INF command did not execute: " + command)
        result = executions[-1]["result"]
        if result.reason not in ["return", "process-exit"] or result.value != 0:
            fail("Advanced INF command failed (%s, %s): %s" % (result.reason, result.detail, command))
        for patch in effects["patches"]:
            modification = _advanced_inf_registry_modification(
                patch,
                {},
                {},
                delete = patch.get("delete", False),
            )
            if modification != None:
                modifications.append(modification)
        for generated_path, generated_source in effects["generated_files"].items():
            installed_files[generated_path] = generated_source
            modifications.append({
                "operation": "write_file",
                "path": generated_path,
                "source": generated_source,
                "replace": "always",
            })

def _advanced_inf_installer(package, system_root, version):
    modifications = []
    installed = {}
    installed_names = {}
    installed_files = {}
    registrations = {}
    pre_commands = []
    post_commands = []
    target = None
    for inf_path in sorted([path for path in package.files if path.lower().endswith(".inf")]):
        member = package.find(inf_path)
        inf = windows.inf(member)
        if inf.section("DefaultInstall") == None:
            continue
        directories, strings = _advanced_inf_directories(inf, system_root)
        if target == None and "49300" in directories:
            target = directories["49300"]
        for install in inf.install_sections("DefaultInstall"):
            section = install.section
            for directive, output in [("RunPreSetupCommands", pre_commands), ("RunPostSetupCommands", post_commands)]:
                for command_section in _inf_directives(section, directive):
                    output.extend(_advanced_inf_command(inf.section(command_section), directories, strings))
            # SetupAPI applies the file queue in delete, rename, copy order.
            # Preserve those operations so native image construction also
            # upgrades an existing installation rather than only fresh disks.
            for delete_name in _inf_directives(section, "DelFiles"):
                destination = _advanced_inf_destination(inf, delete_name, directories, strings)
                for row in _advanced_inf_file_rows(inf, delete_name):
                    if row:
                        modifications.append({
                            "operation": "delete_file",
                            "path": destination + "\\" + row[0],
                        })
            for rename_name in _inf_directives(section, "RenFiles"):
                destination = _advanced_inf_destination(inf, rename_name, directories, strings)
                rename_section = inf.section(rename_name)
                if rename_section == None:
                    continue
                for output_name, value in rename_section.items():
                    rows = _inf_rows(value)
                    if output_name.startswith("@"):
                        for row in rows:
                            if len(row) >= 2:
                                modifications.append({
                                    "operation": "rename_file",
                                    "source": destination + "\\" + row[1],
                                    "path": destination + "\\" + row[0],
                                })
                    else:
                        for row in rows:
                            if row:
                                modifications.append({
                                    "operation": "rename_file",
                                    "source": destination + "\\" + row[0],
                                    "path": destination + "\\" + output_name,
                                })
            for copy_name in _inf_directives(section, "CopyFiles"):
                destination = _advanced_inf_destination(inf, "DefaultDestDir" if copy_name.startswith("@") else copy_name, directories, strings)
                if copy_name.startswith("@"):
                    rows = [[copy_name[1:]]]
                else:
                    copy_section = inf.section(copy_name)
                    rows = [] if copy_section == None else [row for value in copy_section.values() for row in _inf_rows(value)]
                for row in rows:
                    if not row:
                        continue
                    output_name = row[0]
                    source_name = row[1] if len(row) > 1 and row[1] else output_name
                    source = _advanced_inf_member(package, source_name)
                    if source == None:
                        continue
                    path = destination + "\\" + output_name
                    identity = path.lower()
                    if identity in installed:
                        continue
                    installed[identity] = True
                    installed_files[path] = source
                    installed_names[_base(path).lower()] = True
                    modifications.append({
                        "operation": "write_file",
                        "path": path,
                        "source": source,
                        "replace": "if_newer" if _versioned_image_name(path) and _portable_pe_image(source) else "always",
                    })
            for directive, delete in [("AddReg", False), ("DelReg", True)]:
                for registry_section in _inf_directives(section, directive):
                    for patch in inf.section_patches(registry_section):
                        modification = _advanced_inf_registry_modification(patch, directories, strings, delete = delete)
                        if modification != None:
                            modifications.append(modification)
            modifications.extend(_advanced_inf_update_inis(
                inf,
                _inf_directives(section, "UpdateInis"),
                directories,
                strings,
                installed_files,
                system_root,
            ))
            for per_user_section in _inf_directives(section, "PerUserInstall"):
                modifications.extend(_advanced_inf_per_user_modifications(
                    inf.section(per_user_section),
                    directories,
                    strings,
                ))
            for registration_section in _inf_directives(section, "RegisterOCXs"):
                registration = inf.section(registration_section)
                if registration == None:
                    continue
                for value in registration.values():
                    for row in _inf_rows(value):
                        if not row:
                            continue
                        path = _advanced_inf_expand(row[0], directories, strings)
                        registrations[path.lower()] = path
    _advanced_inf_run_commands(pre_commands, modifications, installed_files, version)
    # RegisterOCXs is declarative installer metadata, not a request to run a
    # guest helper.  Derive each module's registry effects directly from its
    # resources and, where necessary, the bounded in-memory x86 emulator.
    for identity, path in sorted(registrations.items()):
        source = None
        for installed_path, installed_source in installed_files.items():
            if installed_path.lower() == identity:
                source = installed_source
                break
        if source == None:
            fail("Advanced INF registration target was not installed: " + path)
        if not _portable_pe_image(source):
            fail("Advanced INF registration target is not a PE image: " + path)
        effects = registration_patches(
            source,
            path,
            execute = True,
            execute_with_static = True,
            files = installed_files,
            registry_values = _advanced_inf_registry_state(modifications),
            version = version,
            instruction_limit = 500000,
        )
        for patch in effects["patches"]:
            modification = _advanced_inf_registry_modification(
                patch,
                {},
                {},
                delete = patch.get("delete", False),
            )
            if modification != None:
                modifications.append(modification)
    _advanced_inf_run_commands(post_commands, modifications, installed_files, version)
    if target == None:
        for path in installed_files:
            if path.lower().endswith(".exe") and not path.lower().startswith(system_root.lower() + "\\"):
                target = _parent_path(path)
                break
    if target == None:
        target = r"C:\Program Files"
    requirements = {}
    for modification in modifications:
        if modification["operation"] != "write_file" or not _versioned_image_name(modification["path"]) or not _portable_pe_image(modification["source"]):
            continue
        for imported in windows.pe(modification["source"]).imports:
            name = imported["dll"].lower()
            if name not in installed_names:
                requirements[name] = True
    return {
        "format": package.format,
        "target": target,
        "modifications": modifications,
        "requirements": sorted(requirements.keys()),
        "clock": None,
    }

def _profile_value(profiles, filename, section, key):
    profile = _casefold_get(profiles, filename)
    if profile == None:
        return None
    values = _casefold_get(profile, section)
    if values == None:
        return None
    return _casefold_get(values, key)

def _symbolic_name(value):
    if not value:
        return False
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    for index in range(len(value)):
        character = value[index]
        if character not in allowed:
            return False
    return value[0] in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def _shortcut_variables(package, variables):
    resolved = dict(variables)
    if package.payload == None or not hasattr(package.payload, "shortcuts"):
        return resolved
    inferred = {}
    for shortcut in package.payload.shortcuts:
        symbol = shortcut["display"]
        fallback = shortcut["name"]
        if not _symbolic_name(symbol) or not fallback or _casefold_get(variables, symbol) != None:
            continue
        key = symbol.lower()
        previous = inferred.get(key)
        if previous != None and previous != fallback:
            fail("installer shortcut variable has ambiguous media defaults: " + symbol)
        inferred[key] = fallback
        resolved[symbol] = fallback
    return resolved

def _installshield5_uninstall_locations(entries, locations, system_root):
    candidates = {}
    for entry in entries:
        if entry.get("name", "").lower() != "uninst.dll":
            continue
        for component in entry.get("components", []):
            destination = _casefold_get(locations, component)
            if destination != None:
                candidates[destination.lower()] = destination
    if len(candidates) > 1:
        fail("installer has ambiguous InstallShield 5 uninstall locations: " + repr(sorted(candidates.values())))
    for destination in candidates.values():
        return {
            "<UNINST>": system_root + r"\IsUninst.exe",
            "<UninstPath>": destination,
        }
    return {}

def _expand_location(value, locations):
    result = value
    for token, replacement in locations.items():
        result = result.replace(token, replacement)
        result = result.replace(token.lower(), replacement)
    return result

def _single_target_default(plan, locations, conditional):
    candidates = {}
    for item in plan["target_defaults"]:
        if item.get("variable", "").lower() != "targetdir" or item.get("conditional", False) != conditional:
            continue
        value = _expand_location(item["value"], locations)
        if "<" not in value:
            candidates[value.lower()] = value
    if len(candidates) > 1:
        fail("installer has ambiguous default install locations: " + repr(sorted(candidates.values())))
    for value in candidates.values():
        return value
    return None

def _default_target(package, selected, locations, variables):
    discovery = package.plan(locations = locations, variables = variables, components = selected)
    target = _single_target_default(discovery, locations, False)
    if target == None:
        target = _single_target_default(discovery, locations, True)
    if target != None:
        return target
    app_name = _profile_value(discovery.get("profiles", {}), "Setup.ini", "Startup", "AppName")
    if package.format.startswith("installshield") and app_name:
        # InstallShield's Setup.ini Startup/AppName is the product-directory
        # name used by standard SdAskDestPath installations when their
        # compiled script leaves TARGETDIR symbolic.
        return locations["<PROGRAMFILES>"] + "\\" + _safe_filename(app_name)
    fail("installer does not declare a default install location; pass target= explicitly")

def _installshield5_media_component_locations(entries, media_files, target):
    media_by_identity = {}
    for item in media_files:
        identity = _base(item["path"]).lower() + "\x00" + str(item["size"])
        media_by_identity.setdefault(identity, []).append(item["path"])

    candidates = {}
    names = {}
    for entry in entries:
        identity = entry.get("name", "").lower() + "\x00" + str(entry.get("size", -1))
        paths = media_by_identity.get(identity, [])
        if len(paths) != 1:
            continue
        media_directory = paths[0].replace("\\", "/").rsplit("/", 1)[0]
        entry_directory = entry.get("directory", "").replace("\\", "/").strip("/")
        if entry_directory:
            suffix = "/" + entry_directory
            if not media_directory.lower().endswith(suffix.lower()):
                continue
            media_directory = media_directory[:-len(suffix)]
        destination = target + media_directory.replace("/", "\\")
        for component in entry.get("components", []):
            folded = component.lower()
            names[folded] = component
            candidates.setdefault(folded, {})[destination.lower()] = destination

    output = {}
    for folded, destinations in candidates.items():
        if len(destinations) == 1:
            output[names[folded]] = destinations.values()[0]
    return output

def _installshield5_component_locations(components, target, system_directory, entries = [], media_files = []):
    """Infers conventional InstallShield 5 component destinations."""
    application_components = {
        "program files": True,
        "help files": True,
        "example files": True,
    }
    system_components = {
        "mfc dlls": True,
        "ocx files": True,
        "system files": True,
        "windows system": True,
        "shellextdlls": True,
    }
    output = {}
    for component in components:
        name = component["name"]
        folded = name.lower()
        if folded in application_components:
            output[name] = target
        elif folded in system_components:
            output[name] = system_directory
        else:
            # InstallShield 5 leaves ordinary application-component targets
            # blank for the compiled script to inherit from TARGETDIR.
            output[name] = target
    output.update(_installshield5_media_component_locations(entries, media_files, target))
    # Runtime libraries carried under an application's media directory still
    # follow InstallShield's conventional system-component destination.
    for component in components:
        if component["name"].lower() in system_components:
            output[component["name"]] = system_directory
    return output

def _expanded_custom_action(action, locations):
    output = dict(action)
    output["arguments"] = [
        _expand_location(value, locations) if type(value) == "string" else value
        for value in action.get("arguments", [])
    ]
    return output

def _additional_registry_modification(value, locations):
    root = value["root"]
    if root not in ["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"]:
        fail("unsupported additional registry root: " + root)
    data = value.get("value", "")
    return {
        "operation": "registry_set_value",
        "root": root,
        "key": _expand_location(value["key"], locations),
        "name": value.get("name", ""),
        "type": value.get("type", "REG_SZ"),
        "value": _expand_location(data, locations) if type(data) == "string" else data,
    }

def _additional_file_entries(package_files, item, locations):
    source_prefix = item.get("source_prefix")
    if source_prefix == None:
        return [{
            "source": item["source"],
            "destination": _expand_location(item["destination"], locations),
            "resolved": True,
            "container": item.get("container", True),
        }]
    if item.get("container", False):
        fail("additional source_prefix only supports decoded package files")
    destination_prefix = _expand_location(item["destination_prefix"], locations)
    matches = sorted([name for name in package_files if name.startswith(source_prefix)])
    if not matches:
        fail("additional source_prefix matched no package files: " + source_prefix)
    return [{
        "source": name,
        "destination": destination_prefix + name[len(source_prefix):],
        "resolved": True,
        "container": False,
    } for name in matches]

def _registry_modification(write):
    operation = write["operation"]
    if operation not in ["set_value", "delete_value"]:
        fail("unsupported definitive registry operation: " + operation)
    root = write["root"]
    key = write["key"].strip("\\/")
    if root == "HKEY_CLASSES_ROOT":
        root = "HKEY_LOCAL_MACHINE"
        key = "Software\\Classes" + ("\\" + key if key else "")
    modification = {
        "operation": "registry_" + operation,
        "root": root,
        "key": key,
        "name": write.get("name", ""),
    }
    if operation == "set_value":
        modification["type"] = "REG_SZ"
        modification["value"] = write.get("data", "")
    return modification

def _analyzed_registry_modifications(effects):
    output = []
    executions = [item["result"] for item in effects["registrations"]]
    executions += [item["execution"] for item in effects["custom_executions"]]
    for execution in executions:
        for patch in execution["patches"]:
            hive = patch.get("hive", "SOFTWARE").upper()
            key = patch["key"].replace("/", "\\").strip("\\")
            if hive == "SOFTWARE":
                root = "HKEY_LOCAL_MACHINE"
                key = "Software" + ("\\" + key if key else "")
            elif hive == "SYSTEM":
                root = "HKEY_LOCAL_MACHINE"
                key = "System" + ("\\" + key if key else "")
            elif hive == "DEFAULT":
                root = "HKEY_CURRENT_USER"
            else:
                fail("unsupported analyzed registry hive: " + hive)
            modification = {
                "operation": "registry_delete_value" if patch.get("delete", False) else "registry_set_value",
                "root": root,
                "key": key,
                "name": patch["name"],
            }
            if not patch.get("delete", False):
                modification["type"] = patch["type"]
                modification["value"] = patch["value"]
            output.append(modification)
    return output

def _ieval_key_identity(file):
    """Returns the product/date fields stored by the IEval key format."""
    data = file.bytes()
    identity = None
    for offset in range(1, len(data) - 10):
        raw = data[offset:offset + 10]
        if raw[4:5] != b"." or raw[7:8] != b"." or data[offset + 10:offset + 11] != b"\x00":
            continue
        if any([raw[index:index + 1] not in b"0123456789" for index in [0, 1, 2, 3, 5, 6, 8, 9]]):
            continue
        printable = b"\t\r\n !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
        start = offset - 2
        while start >= 0 and data[start:start + 1] in printable and offset - start <= 128:
            start -= 1
        if offset - start > 128:
            continue
        product_raw = data[start + 1:offset - 1]
        if any([product_raw[index:index + 1] not in printable for index in range(len(product_raw))]):
            continue
        product = binary.text(product_raw, encoding = "ascii")
        if product:
            identity = (product, binary.text(raw, encoding = "ascii"))
    return identity

def _calendar_timestamp(date):
    """Converts YYYY.MM.DD to a portable noon UTC timestamp."""
    parts = date.split(".")
    if len(parts) != 3:
        fail("installer calendar date must use YYYY.MM.DD")
    year, month, day = [int(part) for part in parts]
    if year < 1970 or year > 2099 or month < 1 or month > 12:
        fail("installer calendar date is outside the supported range")
    month_days = [31, 28 + (1 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 0), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if day < 1 or day > month_days[month - 1]:
        fail("installer calendar date has an invalid day")
    days = 0
    for current in range(1970, year):
        days += 366 if current % 4 == 0 and (current % 100 != 0 or current % 400 == 0) else 365
    for index in range(month - 1):
        days += month_days[index]
    days += day - 1
    return days * 86400 + 12 * 3600

def _two_digits(value):
    return str(100 + value)[1:]

def _rtc_timestamp(timestamp):
    fields = clock.utc(timestamp)
    return "{}-{}-{}T{}:{}:{}".format(
        fields["year"],
        _two_digits(fields["month"]),
        _two_digits(fields["day"]),
        _two_digits(fields["hour"]),
        _two_digits(fields["minute"]),
        _two_digits(fields["second"]),
    )

def _ieval_support(package, plan, target, system_time):
    reached = False
    evaluation = plan.get("script_evaluation")
    if evaluation != None:
        for call in evaluation.get("calls", []):
            if call.get("dll", "").lower() == "ieval" and call.get("callee", "").lower() == "ishield":
                reached = True
                break
    if not reached:
        return ([], [], None)
    keys = [name for name in package.container.files if _base(name).lower() == "key.dat"]
    modules = [name for name in package.files if _base(name).lower() == "ieval.dll"]
    if len(keys) != 1 or len(modules) != 1:
        fail("reachable IEval action requires one key.dat and one ieval.dll")
    identity = _ieval_key_identity(package.container.find(keys[0]))
    if identity == None:
        fail("IEval key.dat does not contain a product identity")
    product, release = identity
    derived_time = system_time == None
    action_time = _calendar_timestamp(release) if derived_time else system_time
    return ([{
        "source": keys[0],
        "destination": target + r"\key.dat",
        "resolved": True,
        "container": True,
    }], [{
        "dll": _base(modules[0]),
        "callee": "ISHIELD",
        "arguments": [0, 3, product + "|" + release + "|" + target],
        "argument_types": [{"concrete_type": 1}, {"concrete_type": 3, "by_reference": True}, {"concrete_type": 2}],
        "registry_keys": [{"hive": "SOFTWARE", "key": "/Classes/CLSID"}],
        "instruction_limit": 10000000,
        "system_time": action_time,
    }], {
        "unix": action_time,
        # The IEval action records its installation timestamp and rejects a
        # first launch whose wall clock is not later (including exact equality)
        # as a rollback. Keep construction deterministic while booting the
        # completed image on the following day, beyond guest clock granularity
        # and local-time conversion differences.
        "rtc": _rtc_timestamp(action_time + 86400),
        "source": "installer evaluation key" if derived_time else "explicit installer system_time",
    })

def _nested_installer_locations(nested, inherited, target):
    locations = dict(inherited)
    if nested.format == "installshield5" and nested.payload != None and hasattr(nested.payload, "components"):
        locations.update(_installshield5_component_locations(nested.payload.components, target, locations["<WINSYSDIR>"]))
    discovery = nested.plan(locations = locations)
    data_dir = None
    for write in discovery["definitive_registry_writes"]:
        if write.get("operation") == "set_value" and write.get("name", "").lower() == "datadir" and type(write.get("data")) == "string":
            data_dir = write["data"].rstrip("\\/")
    if data_dir != None and nested.payload != None and hasattr(nested.payload, "components"):
        for component in nested.payload.components:
            name = component["name"]
            leaf = name.replace("\\", "/").split("/")[-1]
            if component["groups"] and leaf.lower() != "preinstall":
                locations[name] = data_dir + "\\" + leaf
    return locations

def _nested_installers(package, plan, resolved_locations, target, system_root, system_time, version):
    script = package.installscript
    references = {_base(value).lower(): True for value in script.strings} if script != None else {}
    output = []
    for entry in plan["files"]:
        name = _base(entry["destination"]).lower()
        if not name.endswith(".exe") or name not in references or entry.get("container", False):
            continue
        source = package.find(entry["source"])
        if source == None:
            continue
        probe = archive.installer_probe(source)
        if not probe["supported"]:
            continue
        nested = archive.installer(source)
        output.append(installer(
            nested,
            target = target,
            locations = _nested_installer_locations(nested, resolved_locations, target),
            system_root = system_root,
            system_time = system_time,
            nested_installers = False,
            version = version,
        ))
    return output

def installer(source, target = None, components = None, locations = {}, variables = {}, system_root = r"C:\WINDOWS", additional_files = [], directories = [], registry_values = [], custom_actions = [], system_time = None, nested_installers = True, version = {}):
    """Returns declarative modifications and requirements for one installer.

    The result contains no host paths or staged files. Package members remain
    trex files and can be applied directly while an image is assembled.
    """
    package = source if type(source) == "installer" else archive.installer(source)
    if package.format == "embedded_cab":
        if target != None or components != None or locations or variables or additional_files or directories or registry_values or custom_actions:
            fail("Advanced INF bundles derive their installation plan from package metadata")
        return _advanced_inf_installer(package, system_root, version)
    selected = _default_components(package) if components == None else components
    resolved_variables = _shortcut_variables(package, variables)
    resolved_locations = {
        "<PROGRAMFILES>": r"C:\Program Files",
        "<WINSYSDIR>": system_root + r"\SYSTEM",
        "<DESKTOP_FOLDER>": system_root + r"\Desktop",
        "<START_MENU_FOLDER>": system_root + r"\Start Menu",
        "<SHELL_OBJECT_FOLDER>": system_root + r"\Start Menu\Programs",
        "<STARTUP_FOLDER>": system_root + r"\Start Menu\Programs\StartUp",
        "<APPDATA>": system_root + r"\Application Data",
    }
    resolved_locations.update(locations)
    if target == None:
        target = resolved_locations.get("<TARGETDIR>")
    if target == None:
        target = _default_target(package, selected, resolved_locations, resolved_variables)
    resolved_locations["<TARGETDIR>"] = target
    # Component destinations may be expressed relative to the automatically
    # discovered product directory without forcing a recipe to repeat it.
    for name, destination in list(resolved_locations.items()):
        resolved_locations[name] = destination.replace("<TARGETDIR>", target).replace("<targetdir>", target)
    if package.format == "installshield5" and package.payload != None and hasattr(package.payload, "components"):
        media_files = [{"path": path, "size": package.container.find(path).size} for path in package.container.files]
        inferred_locations = _installshield5_component_locations(
            package.payload.components,
            target,
            resolved_locations["<WINSYSDIR>"],
            entries = package.payload.entries if hasattr(package.payload, "entries") else [],
            media_files = media_files,
        )
        for name, destination in inferred_locations.items():
            if _casefold_get(resolved_locations, name) == None:
                resolved_locations[name] = destination
        if package.container.find("/_INST32I.EX_") != None and hasattr(package.payload, "entries"):
            inferred_uninstall = _installshield5_uninstall_locations(package.payload.entries, resolved_locations, system_root)
            for name, destination in inferred_uninstall.items():
                if _casefold_get(resolved_locations, name) == None:
                    resolved_locations[name] = destination
    plan = package.plan(locations = resolved_locations, variables = resolved_variables, components = selected)
    if plan["unresolved"]:
        fail("installer modification plan is incomplete: " + repr(plan["unresolved"]))
    ieval_files, ieval_actions, package_clock = _ieval_support(package, plan, target, system_time)
    if system_time == None:
        system_time = package_clock["unix"] if package_clock != None else int(clock.unix())
    if additional_files or custom_actions or ieval_files or ieval_actions:
        plan = dict(plan)
        plan["files"] = list(plan["files"])
        for item in additional_files:
            # Support files beside the embedded package (for example an
            # evaluation key) live in the installer container. Exact decoded
            # members and bounded file-group prefixes can model a compiled
            # setup script copying package templates to a second location.
            plan["files"].extend(_additional_file_entries(package.files, item, resolved_locations))
        plan["files"].extend(ieval_files)
        plan["custom_actions"] = list(plan["custom_actions"]) + [
            _expanded_custom_action(action, resolved_locations)
            for action in custom_actions
        ] + ieval_actions
    effects = analyze(package, plan, version = version)
    if effects["drivers"]:
        fail("installer modification plan contains unsupported drivers: " + repr(effects["drivers"]))
    if len(effects["custom_executions"]) != len(effects["custom_actions"]):
        fail("installer modification plan contains custom actions that could not be evaluated")

    modifications = []
    installed_names = {}
    target_sizes = {}
    packaged = []
    for directory in directories:
        modifications.append({
            "operation": "create_directory",
            "path": _expand_location(directory, resolved_locations),
        })
    for entry in plan["files"]:
        member = package.container.find(entry["source"]) if entry.get("container", False) else package.find(entry["source"])
        if member == None or type(member) != "file":
            fail("installer payload member is missing: " + entry["source"])
        version = windows.pe(member).version if _versioned_image_name(entry["destination"]) else None
        modifications.append({
            "operation": "write_file",
            "path": entry["destination"],
            "source": member,
            # Versioned destination files are retained unless the package is
            # strictly newer. The image adapter performs the comparison because
            # it owns the base image and can inspect the existing destination.
            "replace": "if_newer" if version != None else "always",
        })
        installed_names[_base(entry["destination"]).lower()] = True
        target_sizes[entry["destination"].lower()] = member.size
        packaged.append({"path": entry["destination"], "source": member})

    for write in plan["definitive_registry_writes"]:
        if not write["resolved"]:
            fail("installer contains an unresolved definitive registry write")
        modifications.append(_registry_modification(write))
    modifications.extend(_analyzed_registry_modifications(effects))
    for value in registry_values:
        modifications.append(_additional_registry_modification(value, resolved_locations))

    for shortcut in plan["shortcuts"]:
        if not shortcut["resolved"]:
            fail("installer contains an unresolved shortcut: " + shortcut["name"])
        target_path = shortcut["target"]
        shortcut_type = shortcut.get("type", 0)
        if shortcut_type == 0:
            extension = ".lnk"
            shortcut_file = windows.shortcut(
                target = target_path,
                description = shortcut["display"],
                arguments = shortcut["arguments"],
                working_dir = shortcut["working_directory"],
                icon_location = shortcut["icon"] if shortcut["icon"] else target_path,
                icon_index = shortcut["icon_index"],
                target_size = target_sizes.get(target_path.lower(), 0),
                system_root = system_root,
            )
        elif shortcut_type == 1:
            extension = ".url"
            shortcut_file = windows.internet_shortcut(
                url = target_path,
                icon_location = shortcut["icon"],
                icon_index = shortcut["icon_index"],
            )
        else:
            fail("installer contains an unsupported shortcut type: " + str(shortcut_type))
        modifications.append({
            "operation": "write_file",
            "path": shortcut["destination_folder"] + "\\" + _safe_filename(shortcut["display"]) + extension,
            "source": shortcut_file,
        })

    nested_results = _nested_installers(package, plan, resolved_locations, target, system_root, system_time, version) if nested_installers else []
    for result in nested_results:
        modifications.extend(result["modifications"])

    requirements = {}
    for item in packaged:
        folded = item["path"].lower()
        if not folded.endswith(".exe") and not folded.endswith(".dll"):
            continue
        for imported in windows.pe(item["source"]).imports:
            name = imported["dll"].lower()
            if name not in installed_names:
                requirements[name] = True
    for result in nested_results:
        for name in result["requirements"]:
            requirements[name] = True
    return {
        "format": package.format,
        "target": target,
        "modifications": modifications,
        "requirements": sorted(requirements.keys()),
        "clock": package_clock,
    }
