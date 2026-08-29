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
            concrete = types[index]["concrete_type"] if index < len(types) else 0
            if concrete in [2, 5]:
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
        environment = environment,
        version = version,
        initialize = True,
        instruction_limit = instruction_limit,
        memory_limit = memory_limit,
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
        source = installer.find(entry["source"])
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
        image = container_modules.get(module_name)
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
    return output

def _registry_modification(write):
    operation = write["operation"]
    if operation not in ["set_value", "delete_value"]:
        fail("unsupported definitive registry operation: " + operation)
    modification = {
        "operation": "registry_" + operation,
        "root": write["root"],
        "key": write["key"],
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

def installer(source, target = None, components = None, locations = {}, variables = {}, system_root = r"C:\WINDOWS"):
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
    }
    resolved_locations.update(locations)
    if target == None:
        target = resolved_locations.get("<TARGETDIR>")
    if target == None:
        target = _default_target(package, selected, resolved_locations, resolved_variables)
    if package.format == "installshield5" and package.payload != None and hasattr(package.payload, "components"):
        inferred_locations = _installshield5_component_locations(package.payload.components, target, resolved_locations["<WINSYSDIR>"])
        for name, destination in inferred_locations.items():
            if _casefold_get(resolved_locations, name) == None:
                resolved_locations[name] = destination
    resolved_locations["<TARGETDIR>"] = target
    plan = package.plan(locations = resolved_locations, variables = resolved_variables, components = selected)
    if plan["unresolved"]:
        fail("installer modification plan is incomplete: " + repr(plan["unresolved"]))
    effects = analyze(package, plan)
    if effects["drivers"]:
        fail("installer modification plan contains unsupported drivers: " + repr(effects["drivers"]))
    if len(effects["custom_executions"]) != len(effects["custom_actions"]):
        fail("installer modification plan contains custom actions that could not be evaluated")

    modifications = []
    installed_names = {}
    target_sizes = {}
    packaged = []
    for entry in plan["files"]:
        member = package.find(entry["source"])
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

    requirements = {}
    for item in packaged:
        folded = item["path"].lower()
        if not folded.endswith(".exe") and not folded.endswith(".dll"):
            continue
        for imported in windows.pe(item["source"]).imports:
            name = imported["dll"].lower()
            if name not in installed_names:
                requirements[name] = True
    return {
        "format": package.format,
        "target": target,
        "modifications": modifications,
        "requirements": sorted(requirements.keys()),
    }
