"""Composable execution of Windows PE modules with semantic system APIs."""

load("@stdlib//windows/selfreg:transactions.star", "registry_transactions_plugin")
load("@stdlib//windows/selfreg:objects.star", "object_directories_plugin")

load(":rpc.star", "rpc_plugin")
load(":abi.star", "teb_layout")
load("@stdlib//windows/selfreg:registry.star", "registry_plugin", "registry_handles_plugin")
load("@stdlib//windows/selfreg:cabinet.star", "cabinet_plugin")
load("@stdlib//windows/selfreg:exception.star", "exception_plugin")
load("@stdlib//windows/selfreg:crypto.star", "crypto_registration_plugin", "cryptoapi_plugin", "bcrypt_hash_plugin")
load("@stdlib//windows/selfreg:service.star", "service_manager_plugin")
load("@stdlib//windows/selfreg:setupapi.star", "setupapi_plugin")
load("@stdlib//windows/selfreg:advpack.star", "advpack_plugin")
load("@stdlib//windows/selfreg:loadperf.star", "loadperf_plugin")
load("@stdlib//windows/selfreg:facts.star", "class_ids")
load("@stdlib//windows/selfreg:win32.star", "com_plugin", "common_controls_plugin", "environment_plugin", "event_log_plugin", "gdi32_plugin", "kernel32_plugin", "lz32_plugin", "msvcrt_plugin", "netapi_plugin", "ole32_plugin", "oleaut_plugin", "resource_plugin", "security_plugin", "shell32_plugin", "shell_plugin", "user32_plugin", "userenv_plugin", "version_plugin", "winsock_helper_plugin", "winsock_plugin")
load("@stdlib//windows/selfreg:msxml.star", "msxml_dom_provider")
load("@stdlib//windows/selfreg:comcat.star", "component_categories_provider")
load("@stdlib//windows/selfreg:wer.star", "wer_plugin")
load("@stdlib//windows/selfreg:appmodel.star", "appmodel_plugin")

def run(file, module, export = "DllRegisterServer", arguments = [], prepare = None, execute = None, plugins = [], plugin_factories = [], modules = {}, deferred_modules = [], files = {}, directories = [], prepared_file_entries = None, registry_values = [], registry_keys = [], registry_hives = {}, registry_output_key_case = "preserve", prepared_registry_state = None, setup_infs = {}, setup_directories = {}, type_libraries = {}, environment = {}, volumes = {}, user_name = "Administrator", user_sid = "S-1-5-21-1-2-3-500", version = {}, initialize = False, executable = False, command_line = "regsvr32.exe", on_class_registration = None, on_thread_create = None, process_create_provider = None, instruction_limit = 2000000, target_instruction_limit = 0, target_continuation_limit = 4, rpc_continuation_limit = 64, rpc_manager_trace = False, rpc_manager_trace_limit = 4096, rpc_manager_call_trace = False, rpc_manager_call_trace_limit = 4096, rpc_manager_call_trace_start = 0, rpc_manager_call_trace_size = 0, rpc_client_observer = None, system_query_observer = None, system_query_provider = None, service_continuation_limit = 64, memory_limit = 32 << 20, trace = False, trace_limit = 4096, profile = False, profile_interval = 256, profile_limit = 16384, system_time = 946684800, network_hosts = {}, network_connect = None, stack_size = 1 << 20, virtual_modules = [], token_privileges = {}, api_set_namespace = None, loader_lookup_observer = None, module_paths = {}, object_directories = {}, object_security_module = "ntdll.dll", token_facts = {}, registry_creation_provider = None, registry_hive_mounts = [], maximum_file_size = 16 << 20, redirection_trust_policy = None):
    """Runs one target export or executable using semantic system-DLL plugins.

    `prepare(machine)` may allocate target memory and return the integer
    arguments passed to one export. `execute(machine)` may instead make a
    stateful sequence of calls on the configured machine. These keep
    command-specific marshaling in Starlark while preserving the bounded
    emulator and plugin policy here. `files` supplies memory-backed guest
    paths to target file APIs; no host staging is performed. Modules named in
    `deferred_modules` are mapped but skip eager process attach. Their private
    import graph is initialized lazily if COM or SCM activates the module.
    Set `executable` when the primary image is a process: dependency DLLs still
    receive process attach, but the PE entry point is not called as DllMain.
    `redirection_trust_policy` declares initial policy-16 flags for the modeled
    process. It admits get/set only in a junction-free virtual namespace and
    is not evidence of a real service process mitigation configuration.
    `maximum_file_size` explicitly bounds virtual file writes (16 MiB by default,
    at most 512 MiB); increasing it does not relax the emulator memory limit.
    `command_line` is returned by both GetCommandLine variants. `environment`
    augments a minimal standard Windows process environment and may override
    any of its values. `process_create_provider(machine, request)` supplies a
    bounded semantic result for child-process creation. Each `plugin_factories`
    callback runs after the core
    runtime plugins are constructed and receives a record containing `crt`,
    `cryptoapi`, `bcrypt`, `kernel`, `registry`, and `module_files`; it must return
    one emulator plugin. Registry security changes must use the registry plugin
    so subsequent operations and returned effects share the same state. This lets callers add
    semantic system APIs without coupling the public runner to target policy.
    `object_directories` maps exact NT directory names to explicit allowed access
    masks (or records with access and explicit self-relative security bytes).
    Queries execute RtlQuerySecurityObject in the explicit `object_security_module`.
    This grants no host namespace access or synthetic security descriptors.
    `module_paths` supplies explicit guest filenames for module-handle filename
    queries; it does not load images or infer paths from host file objects.
    `virtual_modules` explicitly adds semantic DLL names to LoadLibrary lookup;
    callers must supply their exports through plugins. No native DLL is loaded. Keys
    missing from those plugins still fail on resolution or invocation.
    `api_set_namespace` supplies the parsed target Windows API-set schema to
    loader lookup, including importer-specific hosts. It neither admits host
    modules nor supplies exports: use explicit virtual_modules or actual module
    sources. `loader_lookup_observer(machine, query)` observes module/procedure
    lookup before return, and may stop a missing required capability before a
    native delay-loader exception. No exception is suppressed or handled for it.
    `token_privileges` is an explicit LUID-to-attribute inventory for the
    modeled caller's primary token (enabled bit 2, enabled-by-default bit 1).
    Native backup/restore registry opens consult the current effective token,
    including subsequent privilege changes and thread impersonation.
    It defaults empty: AdjustTokenPrivileges cannot grant an unowned privilege.
    This is emulator caller policy, not a change to the offline target image.
    `registry_key_deletions` retains successful key-removal events, including
    empty keys and names later recreated. Reconcile them with final registry
    keys and value patches; they are effects, not a committed hive image.
    `registry_effects` additionally captures only surviving touched value bytes,
    final key metadata and removals. Use it rather than replaying historical
    sets after key deletion. Missing key-creation security remains explicit.
    `registry_hive_mounts` supplies explicit static source-hive namespace mounts
    to registry_plugin. It does not emulate hive loading or infer user profiles;
    effects preserve namespace paths for caller-directed hive publication.
    `registry_creation_provider(machine, request)` is passed to registry_plugin's
    on_create_key boundary, including the exact view's existing parent security.
    It must supply all missing descriptors before any key mutation; the runner
    never infers inheritance policy or falls back to copying a parent ACL.
    `generated_entries` retains newly created or changed files and directories
    as path-keyed records with `directory`, file `data`, and optional DOS
    `attributes`, raw file times, `extended_attributes` name/flags/value dictionaries,
    and owned self-relative `security` bytes. EA records are copied, not shared
    with mutable execution state. `generated_files`
    is the content-only compatibility view; use entries to preserve metadata.
    A `hardlink_to` entry names the canonical generated path of the same file
    object. Content-only consumers deliberately lose this identity information.
    """
    if target_instruction_limit < 0 or target_instruction_limit > instruction_limit:
        fail("target_instruction_limit must not exceed instruction_limit")
    if target_instruction_limit == 0:
        target_instruction_limit = min(instruction_limit, 100000)
    if target_continuation_limit < 0 or target_continuation_limit > 64:
        fail("target_continuation_limit must be between 0 and 64")
    if rpc_continuation_limit < 0 or rpc_continuation_limit > 4096:
        fail("rpc_continuation_limit must be between 0 and 4096")
    if service_continuation_limit < 0 or service_continuation_limit > 1024:
        fail("service_continuation_limit must be between 0 and 1024")
    primary = windows.pe(file)
    amd64 = primary.info["machine"] == 0x8664
    # All metadata plugins observe the same immutable image as the loader.
    # Share this run's owned snapshots instead of copying each source again
    # for imports, versions, resources, messages, and string tables.
    file = primary.data
    modules = {name: windows.pe(image).data for name, image in modules.items()}
    teb = 0x7fffffdde000 if amd64 else 0x7ffde000
    segment = {"gs_base": teb} if amd64 else {"fs_base": teb}
    machine = emulator.machine(
        image = file,
        image_name = module,
        instruction_limit = instruction_limit,
        memory_limit = memory_limit,
        stack_size = stack_size,
        trace = trace,
        trace_limit = trace_limit,
        profile = profile,
        profile_interval = profile_interval,
        profile_limit = profile_limit,
        **segment
    )
    # Programs compiled against the Win32 TLS ABI may access the TEB's slot
    # array directly instead of calling TlsGetValue. Keep that conventional
    # view backed by the same storage used by the semantic kernel APIs.
    tls_slots = machine.allocate(size = 64 * machine.pointer_size, name = "thread local storage slots")
    fields = teb_layout(machine.pointer_size)["fields"]
    for field, value in [("Self", teb), ("ProcessId", 4), ("ThreadId", 8), ("ThreadLocalStoragePointer", tls_slots)]:
        machine.write_pointer(teb + fields[field], value)
    loaded_target_modules = []
    for name, image in modules.items():
        loaded_target_modules.append(machine.load_module(image = image, name = name))

    def canonical_module_name(name):
        value = name.replace("/", "\\").split("\\")[-1].lower()
        return value if "." in value else value + ".dll"

    deferred = {canonical_module_name(name): True for name in deferred_modules}
    virtual_system_modules = [
        "advapi32.dll", "advapi32_vista.dll", "advpack.dll", "api-ms-win-core-com-l1-1-0.dll", "api-ms-win-core-com-l1-1-1.dll", "api-ms-win-core-processthreads-l1-1-0.dll", "cabinet.dll", "comctl32.dll", "crypt32.dll", "gdi32.dll",
        "kernel32.dll", "loadperf.dll", "lz32.dll", "msvcrt.dll", "netapi32.dll", "ntdll.dll",
        "api-ms-win-core-registry-l1-1-0.dll",
        "ole32.dll", "oleaut32.dll", "rpcrt4.dll", "setupapi.dll", "api-ms-win-crt-private-l1-1-0.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-string-l1-1-0.dll", "api-ms-win-security-base-l1-1-0.dll",
        "shell32.dll", "shlwapi.dll", "user32.dll", "userenv.dll", "version.dll",
        "api-ms-win-core-shlwapi-legacy-l1-1-0.dll", "api-ms-win-core-shlwapi-obsolete-l1-1-0.dll",
        "winmm.dll", "wintrust.dll", "ws2_32.dll",
    ]
    virtual_system_modules.extend([canonical_module_name(name) for name in virtual_modules])
    module_images = dict(modules)
    module_images[module] = file
    module_sources = windows.module_sources(files, exclude = virtual_system_modules)
    # Use the same first-match selection as the file-backed loader. These are
    # declared guest paths, not filesystem names attached to host file objects.
    source_paths = windows.module_sources({path: path for path in files}, exclude = virtual_system_modules)
    source_paths.update({canonical_module_name(name): name for name in modules})
    source_paths.update({canonical_module_name(name): path for name, path in module_paths.items()})
    source_paths[canonical_module_name(module)] = module
    module_records = {}
    for loaded in machine.modules:
        if loaded.entry != 0:
            module_records[canonical_module_name(loaded.name)] = loaded

    def target_module_dependencies(image, owner):
        dependencies = []
        seen_dependencies = {}
        for imported in windows.pe(image).imports:
            dependency = canonical_module_name(imported["dll"])
            if dependency != owner and dependency not in seen_dependencies and (dependency in module_records or dependency in module_sources):
                dependencies.append(dependency)
                seen_dependencies[dependency] = True
        return dependencies

    module_dependencies = {}
    for name, image in module_images.items():
        owner = canonical_module_name(name)
        module_dependencies[owner] = target_module_dependencies(image, owner)
    module_initializations = []
    module_initialization_state = {}
    static_tls_state = {}

    def initialize_static_tls(loaded):
        """Installs one PE32 static-TLS template and runs process-attach callbacks."""
        if loaded.tls_index == 0 or static_tls_state.get(loaded.name, False):
            return None
        allocate = machine.resolve_export("kernel32.dll", name = "TlsAlloc")
        set_value = machine.resolve_export("kernel32.dll", name = "TlsSetValue")
        allocated = machine.invoke(allocate)
        if allocated.reason != "return" or allocated.value == 0xffffffff:
            return allocated
        template = binary.builder(capacity = len(loaded.tls_template) + loaded.tls_zero_fill)
        template.append(loaded.tls_template)
        template.append(b"\x00" * loaded.tls_zero_fill)
        thread_data = machine.allocate(value = template.bytes(), name = loaded.name + ".static-tls")
        installed = machine.invoke(set_value, args = [allocated.value, thread_data])
        if installed.reason != "return" or installed.value == 0:
            return installed
        machine.write_u32le(loaded.tls_index, allocated.value)
        static_tls_state[loaded.name] = True
        for callback in loaded.tls_callbacks:
            result = machine.invoke(callback, args = [loaded.base, 1, 0])
            if result.reason != "return":
                return result
        return None

    def initialize_target_module(name):
        """Runs one mapped module's process attach after its private imports."""
        if not initialize:
            return None
        name = canonical_module_name(name)
        state = module_initialization_state.get(name, 0)
        if state == 2:
            return None
        if state == 1:
            # Import cycles are legal; the loader exposes the mapped image
            # while its process attach is in progress.
            return None
        if state == 3:
            for item in module_initializations:
                if item["module"].lower() == name:
                    return item["result"]
            return None
        loaded = module_records.get(name)
        if loaded == None and name in module_sources:
            source = windows.pe(module_sources[name]).data
            loaded = machine.load_module(image = source, name = name)
            module_records[name] = loaded
            process_environment_plugin.state["refresh_modules"](machine)
            module_images[name] = source
            module_dependencies[name] = target_module_dependencies(source, name)
        if loaded == None:
            module_initialization_state[name] = 2
            return None
        module_initialization_state[name] = 1
        for dependency in module_dependencies.get(name, []):
            current = initialize_target_module(dependency)
            if current != None and (current.reason != "return" or current.value == 0):
                module_initialization_state[name] = 3
                return current
        current = initialize_static_tls(loaded)
        if current != None:
            module_initialization_state[name] = 3
            return current
        if loaded.primary or loaded.entry == 0 or loaded.entry == loaded.base:
            module_initialization_state[name] = 2
            return None
        current = machine.invoke(loaded.entry, args = [loaded.base, 1, 0])
        module_initializations.append({"module": loaded.name, "result": current})
        module_initialization_state[name] = 2 if current.reason == "return" and current.value != 0 else 3
        return current

    def map_target_module(name):
        """Maps PE resources without running process attach or dependencies."""
        canonical = canonical_module_name(name)
        loaded = module_records.get(canonical)
        if loaded == None and canonical in module_sources:
            source = windows.pe(module_sources[canonical]).data
            loaded = machine.load_module(image = source, name = canonical)
            module_records[canonical] = loaded
            process_environment_plugin.state["refresh_modules"](machine)
            module_images[canonical] = source
            module_dependencies[canonical] = target_module_dependencies(source, canonical)
        return loaded.base if loaded != None else None

    def load_target_module(name):
        """Maps and initializes one media-backed DLL, returning its image base."""
        canonical = canonical_module_name(name)
        loaded = module_records.get(canonical)
        if loaded == None and canonical not in module_sources:
            return None
        initialized = initialize_target_module(canonical)
        loaded = module_records.get(canonical)
        if loaded == None or (initialized != None and (initialized.reason != "return" or initialized.value == 0)):
            return 0
        return loaded.base

    process_environment = {
        "SystemDrive": "C:",
        "SystemRoot": "C:\\Windows",
        "TEMP": "C:\\Windows\\Temp",
        "TMP": "C:\\Windows\\Temp",
        "windir": "C:\\Windows",
    }
    process_environment.update(environment)
    def effective_registry_privileges():
        return security.effective_privileges()
    registry = registry_plugin(effective_token_privileges = effective_registry_privileges, values = registry_values, keys = registry_keys, hives = registry_hives, mounts = registry_hive_mounts, user_sid = user_sid, output_key_case = registry_output_key_case, prepared_state = prepared_registry_state, environment = process_environment, on_create_key = registry_creation_provider)
    versions = version_plugin(file, module_path = module, module_files = module_images)
    kernel = kernel32_plugin(module, version = version, environment = process_environment, volumes = volumes, virtual_modules = virtual_system_modules, files = files, directories = directories, prepared_file_entries = prepared_file_entries, on_thread_create = on_thread_create, on_module_load = load_target_module, on_module_map = map_target_module, on_process_create = process_create_provider, command_line = command_line, thread_instruction_limit = target_instruction_limit, on_system_query = system_query_observer, system_query_provider = system_query_provider, system_time = system_time, tls_slots = tls_slots, api_set_namespace = api_set_namespace, on_loader_lookup = loader_lookup_observer, module_paths = source_paths, maximum_file_size = maximum_file_size, redirection_trust_policy = redirection_trust_policy)
    setup = setupapi_plugin(infs = setup_infs, directories = setup_directories, registry = registry, kernel = kernel)
    advpack = advpack_plugin(registry, module_images, kernel = kernel, setup = setup)
    performance = loadperf_plugin(registry, kernel)
    cabinet = cabinet_plugin(kernel)
    def generated_files(entries):
        # Entries already contain only changed/new paths. Do not scan the
        # entire initial filesystem again for the content-only view.
        return {path: entry["data"] for path, entry in entries.items() if not entry["directory"]}
    def generated_entries():
        output = {}
        link_targets = {}
        for path, entry in sorted(kernel.state["paths"].items()):
            if entry.get("initial", False) and not entry.get("dirty", False):
                continue
            value = {"directory": entry.get("directory", False)}
            if not value["directory"]:
                value["data"] = kernel.state["file_data"](entry)
                identity = entry.get("file_id")
                if identity != None:
                    if identity in link_targets:
                        value["hardlink_to"] = link_targets[identity]
                    else:
                        link_targets[identity] = path
            for key in ["security", "attributes", "creation_time", "access_time", "write_time", "extended_attributes"]:
                if key in entry:
                    value[key] = [dict(ea) for ea in entry[key]] if key == "extended_attributes" else entry[key]
            output[path] = value
        return output
    available_type_libraries = dict(type_libraries)
    registered_type_libraries = []
    for name, image in module_images.items():
        normalized_name = name.replace("/", "\\").lower()
        if normalized_name not in available_type_libraries:
            available_type_libraries[normalized_name] = image
        for library in windows.pe(image).typelibs:
            registered_type_libraries.append({
                "path": normalized_name,
                "library": library,
            })
    automation = oleaut_plugin(
        type_libraries = available_type_libraries,
        registered_type_libraries = registered_type_libraries,
    )
    crt = msvcrt_plugin(kernel = kernel)
    exceptions = exception_plugin(kernel = kernel)
    cryptoapi = cryptoapi_plugin(kernel = kernel)
    bcrypt = bcrypt_hash_plugin()
    server_classes = {}
    for name, image in module_images.items():
        classes = class_ids(image)
        if classes:
            server_classes[name.lower()] = classes
    services = service_manager_plugin(registry, continuation_limit = service_continuation_limit, instruction_limit = target_instruction_limit, initialize_module = initialize_target_module, pump_background = kernel.state["pump_thread_slice"], kernel = kernel)
    def pump_background_slice(machine):
        service_progress = services.state["pump_execution_slice"](machine)
        thread_progress = kernel.state["pump_thread_slice"](machine)
        return service_progress or thread_progress
    xml_dom = msxml_dom_provider(kernel)
    class_activators = {class_name: xml_dom["activate"] for class_name in xml_dom["classes"]}
    component_categories = component_categories_provider(registry)
    for class_name in component_categories["classes"]:
        class_activators[class_name] = component_categories["activate"]
    user_interface = user32_plugin(file, module_files = module_images, kernel = kernel)
    def class_registration(event, registration):
        if on_class_registration != None:
            on_class_registration(event, registration)
        if services.state["starting_class"] == registration["class"]:
            event.machine.stop("service-ready", detail = registration["class"])
    def class_activation(event, activation):
        return services.activate_class(event.machine, activation["class"], activation["context"])
    def class_server(class_name):
        return registry.get_value(
            "SOFTWARE",
            "/Classes/CLSID/" + class_name + "/InprocServer32",
            "(default)",
            "",
        )
    ole = ole32_plugin(
        on_class_registration = class_registration,
        on_class_activation = class_activation,
        on_server_activation = initialize_target_module,
        class_server_resolver = class_server,
        server_classes = server_classes,
        class_activators = class_activators,
        target_budget_handler = pump_background_slice,
        target_instruction_limit = target_instruction_limit,
        target_continuation_limit = target_continuation_limit,
        kernel = kernel,
    )
    accounts = {}
    security = security_plugin(user_name = user_name, user_sid = [int(part) for part in user_sid.split("-")[3:]], kernel = kernel, object_security = registry.set_security, accounts = accounts, token_privileges = token_privileges, token_facts = token_facts, computer_name = environment.get("COMPUTERNAME", environment.get("ComputerName", "TREX")))
    network = netapi_plugin(
        user_name = user_name,
        user_sid = [int(part) for part in user_sid.split("-")[3:]],
        product_type = version.get("product_type", "WinNT"),
        domain = process_environment.get("USERDOMAIN", ""),
        accounts = accounts,
    )
    extension_plugins = [factory({
        "crt": crt,
        "cryptoapi": cryptoapi,
        "bcrypt": bcrypt,
        "kernel": kernel,
        "registry": registry,
        "module_files": modules,
    }) for factory in plugin_factories]
    # `module_images` is extended by load_target_module. Resource lookup keeps
    # this live view so DLLs loaded after plugin installation expose their PE
    # resources without eagerly mapping the process's complete file set.
    resources = resource_plugin(file, module_files = module_images, kernel = kernel)
    rpc = rpc_plugin(
        registry,
        module,
        target_instruction_limit = target_instruction_limit,
        target_continuation_limit = rpc_continuation_limit,
        on_budget = pump_background_slice,
        on_client_call = rpc_client_observer,
        manager_trace = rpc_manager_trace,
        manager_trace_limit = rpc_manager_trace_limit,
        manager_call_trace = rpc_manager_call_trace,
        manager_call_trace_limit = rpc_manager_call_trace_limit,
        manager_call_trace_start = rpc_manager_call_trace_start,
        manager_call_trace_size = rpc_manager_call_trace_size,
    )
    crypto = crypto_registration_plugin(registry, module, file = file)
    common_controls = common_controls_plugin()
    def service_execution_statistics():
        return {
            "slices": services.state["execution_slices"],
            "steps": services.state["execution_steps"],
        }
    def rpc_statistics():
        return {
            "background_pumps": rpc.state["background_pumps"],
            "target_slices": rpc.state["target_slices"],
            "target_steps": rpc.state["target_steps"],
        }
    process_environment_plugin=environment_plugin(process_environment, system_time=system_time, module_paths=source_paths)
    machine.use([
        registry,
        services,
        setup,
        advpack,
        exceptions,
        kernel,
        registry_handles_plugin(registry, kernel),
        registry_transactions_plugin(registry, kernel),
        object_directories_plugin(kernel, object_directories, security_module = object_security_module),
        lz32_plugin(kernel),
        cabinet,
        process_environment_plugin,
        event_log_plugin(),
        performance,
        ole,
        automation,
        com_plugin(registry),
        crypto,
        cryptoapi,
        bcrypt,
        rpc,
        crt,
        security,
        network,
        winsock_plugin(hosts = network_hosts, user_interface = user_interface, kernel = kernel, connect = network_connect),
        winsock_helper_plugin(),
        resources,
        versions,
        appmodel_plugin(),
        wer_plugin(),
        gdi32_plugin(),
        shell32_plugin(module_path = module, environment = process_environment, malloc = ole.state, kernel = kernel),
        common_controls,
        shell_plugin(module, kernel = kernel),
        user_interface,
        userenv_plugin(environment = process_environment, kernel = kernel),
    ] + extension_plugins + plugins)
    initialization = None
    if initialize:
        primary = None
        for loaded in machine.modules:
            if loaded.primary:
                primary = loaded
                break
        if primary == None:
            fail("target module is not mapped")
        # Import cycles may refer back to the primary during process attach.
        module_initialization_state[canonical_module_name(primary.name)] = 1
        # The image recipe supplies explicit target modules in dependency-first
        # order. Keep those loader records separate from sorted virtual modules.
        for loaded in loaded_target_modules:
            # Semantic plugins publish virtual modules with no executable
            # entry point. PE images can also intentionally omit DllMain.
            if loaded.primary or loaded.entry == 0 or loaded.entry == loaded.base:
                continue
            if canonical_module_name(loaded.name) in deferred:
                continue
            current = initialize_target_module(loaded.name)
            if current != None and (current.reason != "return" or current.value == 0):
                entries = generated_entries()
                return {
                    "patches": registry.patches(),
                    "queries": registry.queries(),
                    "registry_opens": registry.opens(),
                    "registry_transactions": registry.transactions(),
                    "registry_keys": registry.keys(),
                    "registry_key_deletions": registry.key_deletions(),
                    "registry_effects": registry.effects(),
                    "result": current,
                    "initialization": current,
                    "module_initializations": module_initializations,
                    "snapshot": machine.snapshot(),
                    "profile": machine.profile(),
                    "setup_actions": setup.state["actions"],
                    "setup_calls": setup.state["calls"],
                    "advpack_actions": advpack.state["actions"],
                    "crypto_actions": crypto.state["actions"],
                    "setup_directories": setup.state["directories"],
                    "version_queries": versions.state["queries"],
                    "file_queries": kernel.state["file_queries"],
                    "module_queries": kernel.state["module_queries"],
                    "procedure_queries": kernel.state["procedure_queries"],
                    "delay_load_queries": kernel.state["delay_load_queries"],
                    "process_queries": kernel.state["process_queries"],
                    "system_queries": kernel.state["system_queries"],
                    "cabinet_actions": cabinet.state["actions"],
                    "threads": kernel.state["threads"],
                    "timer_callbacks": kernel.state["timer_callbacks"],
                    "generated_files": generated_files(entries),
                    "generated_entries": entries,
                    "performance_actions": performance.state["actions"],
                    "resource_queries": resources.state["queries"],
                    "type_library_actions": automation.state["actions"],
                    "exceptions": exceptions.state["exceptions"],
                    "security_actions": security.state["actions"],
                    "cryptoapi_actions": cryptoapi.state["actions"],
                    "network_actions": network.state["actions"],
                    "service_activations": services.state["activations"],
                    "service_execution_statistics": service_execution_statistics(),
                    "rpc_actions": rpc.state["actions"],
                    "rpc_client_calls": rpc.state["client_calls"],
                    "rpc_interfaces": rpc.state["interfaces"],
                    "rpc_statistics": rpc_statistics(),
                    "com_activations": ole.state["activations"],
                    "xml_actions": xml_dom["state"]["actions"],
                    "component_category_actions": component_categories["state"]["actions"],
                    "user_dialogs": user_interface.state["dialogs"],
                    "user_windows": dict(user_interface.state["windows"]),
                    "crt_actions": crt.state["actions"],
                    "crt_calls": crt.state["calls"],
                }
        initialization = initialize_static_tls(primary)
        if initialization == None and not executable:
            initialization = machine.call(machine.entry, args = [primary.base, 1, 0])
        if initialization != None and (initialization.reason != "return" or initialization.value == 0):
            entries = generated_entries()
            return {
                "patches": registry.patches(),
                "queries": registry.queries(),
                "registry_opens": registry.opens(),
                "registry_transactions": registry.transactions(),
                "registry_keys": registry.keys(),
                "registry_key_deletions": registry.key_deletions(),
                "registry_effects": registry.effects(),
                "result": initialization,
                "initialization": initialization,
                "module_initializations": module_initializations,
                "snapshot": machine.snapshot(),
                "profile": machine.profile(),
                "setup_actions": setup.state["actions"],
                "setup_calls": setup.state["calls"],
                "advpack_actions": advpack.state["actions"],
                "crypto_actions": crypto.state["actions"],
                "setup_directories": setup.state["directories"],
                "version_queries": versions.state["queries"],
                "file_queries": kernel.state["file_queries"],
                "volume_queries": kernel.state["volume_queries"],
                "module_queries": kernel.state["module_queries"],
                "procedure_queries": kernel.state["procedure_queries"],
                "delay_load_queries": kernel.state["delay_load_queries"],
                "process_queries": kernel.state["process_queries"],
                "system_queries": kernel.state["system_queries"],
                "cabinet_actions": cabinet.state["actions"],
                "threads": kernel.state["threads"],
                "timer_callbacks": kernel.state["timer_callbacks"],
                "generated_files": generated_files(entries),
                "generated_entries": entries,
                "performance_actions": performance.state["actions"],
                "resource_queries": resources.state["queries"],
                "type_library_actions": automation.state["actions"],
                "exceptions": exceptions.state["exceptions"],
                "security_actions": security.state["actions"],
                "cryptoapi_actions": cryptoapi.state["actions"],
                "network_actions": network.state["actions"],
                "service_activations": services.state["activations"],
                "service_execution_statistics": service_execution_statistics(),
                "rpc_actions": rpc.state["actions"],
                "rpc_client_calls": rpc.state["client_calls"],
                "rpc_interfaces": rpc.state["interfaces"],
                "rpc_statistics": rpc_statistics(),
                "com_activations": ole.state["activations"],
                "xml_actions": xml_dom["state"]["actions"],
                "component_category_actions": component_categories["state"]["actions"],
                "user_dialogs": user_interface.state["dialogs"],
                "user_windows": dict(user_interface.state["windows"]),
                "user_messages": user_interface.state["sent_messages"],
                "property_sheets": common_controls.state["property_sheets"],
                "crt_actions": crt.state["actions"],
                "crt_calls": crt.state["calls"],
            }
        module_initialization_state[canonical_module_name(primary.name)] = 2
    if execute != None and (arguments or prepare != None):
        fail("run execute cannot be combined with arguments or prepare")
    call_arguments = arguments
    if prepare != None:
        if arguments:
            fail("run accepts either arguments or prepare, not both")
        call_arguments = prepare(machine)
    result = execute(machine) if execute != None else machine.call_export(export, args = call_arguments)
    entries = generated_entries()
    return {
        "patches": registry.patches(),
        "queries": registry.queries(),
        "registry_opens": registry.opens(),
        "registry_transactions": registry.transactions(),
        "registry_keys": registry.keys(),
        "registry_key_deletions": registry.key_deletions(),
        "registry_effects": registry.effects(),
        "result": result,
        "initialization": initialization,
        "module_initializations": module_initializations,
        "snapshot": machine.snapshot(),
        "profile": machine.profile(),
        "setup_actions": setup.state["actions"],
        "setup_calls": setup.state["calls"],
        "advpack_actions": advpack.state["actions"],
        "crypto_actions": crypto.state["actions"],
        "setup_directories": setup.state["directories"],
        "version_queries": versions.state["queries"],
        "file_queries": kernel.state["file_queries"],
        "volume_queries": kernel.state["volume_queries"],
        "module_queries": kernel.state["module_queries"],
        "procedure_queries": kernel.state["procedure_queries"],
        "delay_load_queries": kernel.state["delay_load_queries"],
        "process_queries": kernel.state["process_queries"],
        "system_queries": kernel.state["system_queries"],
        "cabinet_actions": cabinet.state["actions"],
        "threads": kernel.state["threads"],
        "timer_callbacks": kernel.state["timer_callbacks"],
        "generated_files": generated_files(entries),
        "generated_entries": entries,
        "performance_actions": performance.state["actions"],
        "resource_queries": resources.state["queries"],
        "type_library_actions": automation.state["actions"],
        "exceptions": exceptions.state["exceptions"],
        "security_actions": security.state["actions"],
        "cryptoapi_actions": cryptoapi.state["actions"],
        "network_actions": network.state["actions"],
        "service_activations": services.state["activations"],
        "service_execution_statistics": service_execution_statistics(),
        "rpc_actions": rpc.state["actions"],
        "rpc_client_calls": rpc.state["client_calls"],
        "rpc_interfaces": rpc.state["interfaces"],
        "rpc_statistics": rpc_statistics(),
        "com_activations": ole.state["activations"],
        "xml_actions": xml_dom["state"]["actions"],
        "component_category_actions": component_categories["state"]["actions"],
        "user_dialogs": user_interface.state["dialogs"],
        "user_windows": dict(user_interface.state["windows"]),
        "user_messages": user_interface.state["sent_messages"],
        "property_sheets": common_controls.state["property_sheets"],
        "crt_actions": crt.state["actions"],
        "crt_calls": crt.state["calls"],
    }
