"""High-level, data-first Windows self-registration policy."""

load(":common.star", "deduplicate", "expand")
load(":facts.star", "class_ids")
load(":mmc.star", "mmc_registration_patches")
load(":reginst.star", "reginst_registration_patches")
load(":runner.star", _run_export = "run")
load(":script.star", "script_engine_patches")
load(":typelib.star", "typelib_registration_patches")

def _expand_patches(patches, replacements, default_hive = ""):
    output = []
    for item in patches:
        copy = dict(item)
        if default_hive and "hive" not in copy:
            copy["hive"] = default_hive
        copy["value"] = expand(copy["value"], replacements)
        output.append(copy)
    return output

def _referenced_typelibs(patches):
    output = {}
    for item in patches:
        parts = item["key"].replace("\\", "/").split("/")
        if parts[-1].lower() == "typelib" and item["name"] in ["", "(default)"] and type(item["value"]) == "string":
            value = item["value"].upper()
            if len(value) == 38 and value[0] == "{" and value[-1] == "}":
                output[value] = True
    return output

def _registration_exports(pe):
    output = []
    for item in pe.exports:
        # A forwarded entry has no executable registrar body in this image.
        # Its target module owns the implementation and is registered through
        # that module's own metadata/action; invoking the forwarding RVA as
        # local code produces a false missing-export failure.
        if item.get("forwarder", ""):
            continue
        name = item.get("name", "")
        if name.lower().endswith("dllregisterserver"):
            if name == "DllRegisterServer":
                output.insert(0, name)
            else:
                output.append(name)
    return output

def _succeeded(hresult):
    return hresult >= 0 and hresult < 0x80000000

def _registration_succeeded(value, executable):
    """Applies the result convention used by the selected entry point."""
    return value == 0 if executable else _succeeded(value)

def _execution_succeeded(reason, value, executable):
    """Validates both the stop reason and the selected result convention."""
    if executable:
        return reason in ["return", "process-exit"] and _registration_succeeded(value, True)
    return reason == "return" and _registration_succeeded(value, False)

def _run_entry(machine):
    return machine.run()

def _merge_execution_patches(static, runtime):
    """Rejects incomplete dynamic values when static metadata is authoritative."""
    server_paths = {}
    for item in static:
        if (
            item["key"].replace("\\", "/").lower().endswith("/inprocserver32") and
            item["name"] in ["", "(default)"] and
            type(item["value"]) == "string" and
            item["value"] != ""
        ):
            identity = (item.get("hive", "SOFTWARE").upper(), item["key"].upper(), item["name"].upper())
            server_paths[identity] = True
    usable = []
    for item in runtime:
        identity = (item.get("hive", "SOFTWARE").upper(), item["key"].upper(), item["name"].upper())
        if identity in server_paths and item["value"] == "":
            continue
        usable.append(item)
    return static + usable

def _partial_class_registration_patches(static, runtime, hresult):
    """Keeps completed HKCR writes from a registrar reporting SELFREG_E_CLASS.

    This HRESULT is an aggregate class-registration failure. When authoritative
    static COM metadata already covers the module's classes, successful sibling
    writes such as ProgIDs still complete that metadata. Rollback deletions and
    non-HKCR side effects remain rejected.
    """
    if hresult != 0x80040201:
        return []
    has_static_classes = False
    for item in static:
        if (
            item.get("hive", "SOFTWARE").upper() == "SOFTWARE" and
            item["key"].replace("\\", "/").lower().startswith("/classes/clsid/") and
            not item.get("delete", False)
        ):
            has_static_classes = True
            break
    if not has_static_classes:
        return []
    return [
        item
        for item in runtime
        if (
            item.get("hive", "SOFTWARE").upper() == "SOFTWARE" and
            item["key"].replace("\\", "/").lower().startswith("/classes/") and
            not item.get("delete", False)
        )
    ]

def _unregistered_classes(patches, classes):
    """Returns served in-process classes not represented by registry metadata."""
    registered = {}
    prefix = "/classes/clsid/"
    suffix = "/inprocserver32"
    for item in patches:
        key = item["key"].replace("\\", "/").lower()
        if (
            item.get("hive", "SOFTWARE").upper() != "SOFTWARE" or
            not key.startswith(prefix) or
            not key.endswith(suffix) or
            item["name"] not in ["", "(default)"] or
            item.get("delete", False) or
            type(item["value"]) != "string" or
            item["value"] == ""
        ):
            continue
        registered[key[len(prefix):-len(suffix)].strip("/")] = True
    return [class_name for class_name in classes if class_name.lower() not in registered]

def registration_patches(file, module, mmc_snapins = [], replacements = {}, execute = True, execute_with_static = False, executable = False, command_line = "", plugins = [], registry_values = [], registry_keys = [], prepared_registry_state = None, environment = {}, version = {}, modules = {}, deferred_modules = [], files = {}, prepared_file_entries = None, instruction_limit = 250000, memory_limit = 32 << 20, profile = False, profile_interval = 256, profile_limit = 16384):
    """Returns registry patches for one PE without loading system DLL images.

    Structured resources and static PE facts are preferred. The bounded x86
    runner is used only as a fallback. Its writes require success, except for
    completed HKCR writes guarded by static class metadata when a registrar
    reports the aggregate SELFREG_E_CLASS result.
    """
    structured = []
    pe = windows.pe(file)
    source = pe.data
    resource = windows.selfreg_patches(pe, module)
    structured += _expand_patches(resource, replacements, default_hive = "SOFTWARE")
    structured += reginst_registration_patches(file, module, replacements, pe = pe)

    script = script_engine_patches(source, module, pe = pe)
    structured += _expand_patches(script, replacements)
    structured += mmc_registration_patches(source, module, mmc_snapins, pe = pe)
    output = list(structured)
    output += typelib_registration_patches(file, module, referenced = _referenced_typelibs(structured), pe = pe)
    missing_classes = _unregistered_classes(output, class_ids(source, pe = pe))

    executions = []
    generated_files = {}
    performance_actions = []
    keys = []
    # Static resources and executable registration are usually alternative
    # representations.  Some registrars also perform runtime-only work such
    # as creating a service; callers that detect those capabilities can ask
    # for both without making every image build emulate every registrar.
    # A type library describes classes and interfaces, but not ProgIDs,
    # categories, or module-specific setup. It is therefore a fallback, not
    # evidence that DllRegisterServer has been fully represented.
    if execute and (executable or not structured or execute_with_static or missing_classes):
        registration_entries = [None] if executable else _registration_exports(pe)
        for export in registration_entries:
            for initialize in ([True] if executable else [True, False]):
                execution = _run_export(
                    source,
                    module,
                    export = export or "DllRegisterServer",
                    execute = _run_entry if executable else None,
                    plugins = plugins,
                    # Executable registration complements the metadata we
                    # already derived from this image. Give the registrar that
                    # same registry view so opens of standard parent keys such
                    # as HKCR\CLSID observe the state that will exist on disk.
                    registry_values = output if prepared_registry_state != None else registry_values + output,
                    registry_keys = registry_keys,
                    prepared_registry_state = prepared_registry_state,
                    environment = environment,
                    version = version,
                    modules = modules,
                    deferred_modules = deferred_modules,
                    files = files,
                    prepared_file_entries = prepared_file_entries,
                    initialize = initialize,
                    executable = executable,
                    command_line = command_line or module,
                    instruction_limit = instruction_limit,
                    memory_limit = memory_limit,
                    profile = profile,
                    profile_interval = profile_interval,
                    profile_limit = profile_limit,
                )
                executions.append(execution)
                result = execution["result"]
                if result.reason == "return" or (executable and result.reason == "process-exit"):
                    succeeded = _execution_succeeded(result.reason, result.value, executable)
                    patches = execution["patches"] if succeeded else _partial_class_registration_patches(
                        output,
                        execution["patches"],
                        result.value,
                    )
                    patches = _expand_patches(patches, replacements)
                    if succeeded:
                        generated_files = execution["generated_files"]
                        performance_actions = execution["performance_actions"]
                        keys = execution["registry_keys"]
                    output = _merge_execution_patches(output, patches)
                    if patches or keys:
                        break
                initialization = execution["initialization"]
                if not initialize or (initialization != None and initialization.reason == "return" and initialization.value != 0):
                    break
            if output or keys:
                break
    return {
        "patches": deduplicate(output),
        "keys": keys,
        "execution": executions[0] if executions else None,
        "executions": executions,
        "generated_files": generated_files,
        "performance_actions": performance_actions,
    }
