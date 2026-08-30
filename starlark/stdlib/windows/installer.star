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
        module = artifact["name"]
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

def _casefold_get(mapping, name):
    folded = name.lower()
    for key, value in mapping.items():
        if key.lower() == folded:
            return value
    return None

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

def _installshield5_component_locations(components, target, system_directory):
    """Infers conventional InstallShield 5 component destinations."""
    application_components = {
        "program files": True,
        "help files": True,
        "example files": True,
    }
    system_components = {
        "mfc dlls": True,
        "ocx files": True,
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

def _nested_installers(package, plan, resolved_locations, target, system_root, system_time):
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
        ))
    return output

def installer(source, target = None, components = None, locations = {}, variables = {}, system_root = r"C:\WINDOWS", additional_files = [], directories = [], registry_values = [], custom_actions = [], system_time = None, nested_installers = True):
    """Returns declarative modifications and requirements for one installer.

    The result contains no host paths or staged files. Package members remain
    trex files and can be applied directly while an image is assembled.
    """
    package = source if type(source) == "installer" else archive.installer(source)
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
        inferred_locations = _installshield5_component_locations(package.payload.components, target, resolved_locations["<WINSYSDIR>"])
        for name, destination in inferred_locations.items():
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
    effects = analyze(package, plan)
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

    nested_results = _nested_installers(package, plan, resolved_locations, target, system_root, system_time) if nested_installers else []
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
