"""Composable execution of Windows PE modules with semantic system APIs."""

load(":rpc.star", "rpc_plugin")
load("@stdlib//windows/selfreg:registry.star", "registry_plugin")
load("@stdlib//windows/selfreg:cabinet.star", "cabinet_plugin")
load("@stdlib//windows/selfreg:exception.star", "exception_plugin")
load("@stdlib//windows/selfreg:crypto.star", "crypto_registration_plugin", "cryptoapi_plugin")
load("@stdlib//windows/selfreg:service.star", "service_manager_plugin")
load("@stdlib//windows/selfreg:setupapi.star", "setupapi_plugin")
load("@stdlib//windows/selfreg:advpack.star", "advpack_plugin")
load("@stdlib//windows/selfreg:loadperf.star", "loadperf_plugin")
load("@stdlib//windows/selfreg:facts.star", "class_ids")
load("@stdlib//windows/selfreg:win32.star", "com_plugin", "common_controls_plugin", "environment_plugin", "event_log_plugin", "gdi32_plugin", "kernel32_plugin", "lz32_plugin", "msvcrt_plugin", "netapi_plugin", "ole32_plugin", "oleaut_plugin", "resource_plugin", "security_plugin", "shell32_plugin", "shell_plugin", "user32_plugin", "version_plugin", "winsock_helper_plugin", "winsock_plugin")
load("@stdlib//windows/selfreg:msxml.star", "msxml_dom_provider")
load("@stdlib//windows/selfreg:comcat.star", "component_categories_provider")
load("@stdlib//windows/selfreg:wer.star", "wer_plugin")
load("@stdlib//windows/selfreg:appmodel.star", "appmodel_plugin")

def run(file, module, export = "DllRegisterServer", arguments = [], prepare = None, execute = None, plugins = [], plugin_factories = [], modules = {}, deferred_modules = [], files = {}, directories = [], prepared_file_entries = None, registry_values = [], registry_keys = [], registry_hives = {}, registry_output_key_case = "preserve", prepared_registry_state = None, setup_infs = {}, setup_directories = {}, type_libraries = {}, environment = {}, volumes = {}, user_name = "Administrator", user_sid = "S-1-5-21-1-2-3-500", version = {}, initialize = False, executable = False, command_line = "regsvr32.exe", on_class_registration = None, on_thread_create = None, instruction_limit = 2000000, target_instruction_limit = 0, target_continuation_limit = 4, rpc_continuation_limit = 64, rpc_manager_trace = False, rpc_manager_trace_limit = 4096, rpc_manager_call_trace = False, rpc_manager_call_trace_limit = 4096, rpc_manager_call_trace_start = 0, rpc_manager_call_trace_size = 0, rpc_client_observer = None, system_query_observer = None, system_query_provider = None, service_continuation_limit = 64, memory_limit = 32 << 20, trace = False, trace_limit = 4096, profile = False, profile_interval = 256, profile_limit = 16384, system_time = 946684800):
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
    `command_line` is returned by both GetCommandLine variants. `environment`
    augments a minimal standard Windows process environment and may override
    any of its values. Each `plugin_factories` callback runs after the core
    runtime plugins are constructed and receives a record containing `crt` and
    `module_files`; it must return one emulator plugin. This lets callers add
    semantic system APIs without coupling the public runner to target policy.
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
    machine = emulator.x86(
        image = file,
        image_name = module,
        instruction_limit = instruction_limit,
        memory_limit = memory_limit,
        trace = trace,
        trace_limit = trace_limit,
        profile = profile,
        profile_interval = profile_interval,
        profile_limit = profile_limit,
        fs_base = 0x7ffde000,
    )
    # Programs compiled against the Win32 TLS ABI may access the TEB's slot
    # array directly instead of calling TlsGetValue. Keep that conventional
    # view backed by the same storage used by the semantic kernel APIs.
    tls_slots = machine.allocate(size = 64 * 4, name = "thread local storage slots")
    machine.write_u32le(0x7ffde000 + 0x18, 0x7ffde000)
    machine.write_u32le(0x7ffde000 + 0x20, 4)
    machine.write_u32le(0x7ffde000 + 0x24, 8)
    machine.write_u32le(0x7ffde000 + 0x2c, tls_slots)
    loaded_target_modules = []
    for name, image in modules.items():
        loaded_target_modules.append(machine.load_module(image = image, name = name))

    def canonical_module_name(name):
        value = name.replace("/", "\\").split("\\")[-1].lower()
        return value if "." in value else value + ".dll"

    deferred = {canonical_module_name(name): True for name in deferred_modules}
    virtual_system_modules = [
        "advapi32.dll", "api-ms-win-core-com-l1-1-1.dll", "cabinet.dll", "comctl32.dll", "crypt32.dll", "gdi32.dll",
        "kernel32.dll", "loadperf.dll", "lz32.dll", "msvcrt.dll", "netapi32.dll", "ntdll.dll",
        "ole32.dll", "oleaut32.dll", "rpcrt4.dll", "setupapi.dll",
        "shell32.dll", "shlwapi.dll", "user32.dll", "version.dll",
        "winmm.dll", "wintrust.dll", "ws2_32.dll",
    ]
    virtual_system_module_names = {name: True for name in virtual_system_modules}
    module_images = dict(modules)
    module_images[module] = file
    module_sources = {}
    for path, source in files.items():
        name = canonical_module_name(path)
        if name.endswith(".dll") and name not in virtual_system_module_names and name not in module_sources:
            module_sources[name] = source
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
            source = module_sources[name]
            loaded = machine.load_module(image = source, name = name)
            module_records[name] = loaded
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
    registry = registry_plugin(values = registry_values, keys = registry_keys, hives = registry_hives, user_sid = user_sid, output_key_case = registry_output_key_case, prepared_state = prepared_registry_state)
    versions = version_plugin(file, module_path = module, module_files = module_images)
    kernel = kernel32_plugin(module, version = version, environment = process_environment, volumes = volumes, virtual_modules = virtual_system_modules, files = files, directories = directories, prepared_file_entries = prepared_file_entries, on_thread_create = on_thread_create, on_module_load = load_target_module, command_line = command_line, thread_instruction_limit = target_instruction_limit, on_system_query = system_query_observer, system_query_provider = system_query_provider, system_time = system_time, tls_slots = tls_slots)
    setup = setupapi_plugin(infs = setup_infs, directories = setup_directories, registry = registry, kernel = kernel)
    advpack = advpack_plugin(registry, module_images, kernel = kernel, setup = setup)
    performance = loadperf_plugin(registry, kernel)
    cabinet = cabinet_plugin(kernel)
    def generated_files():
        output = {}
        for path, entry in kernel.state["paths"].items():
            if not entry.get("directory", False) and (not entry.get("initial", False) or entry.get("dirty", False)):
                output[path] = entry.get("data", b"")
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
    server_classes = {}
    for name, image in module_images.items():
        classes = class_ids(image)
        if classes:
            server_classes[name.lower()] = classes
    services = service_manager_plugin(registry, continuation_limit = service_continuation_limit, instruction_limit = target_instruction_limit, initialize_module = initialize_target_module, pump_background = kernel.state["pump_thread_slice"])
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
    security = security_plugin(user_name = user_name, user_sid = [int(part) for part in user_sid.split("-")[3:]], kernel = kernel, object_security = registry.set_security, accounts = accounts)
    network = netapi_plugin(
        user_name = user_name,
        user_sid = [int(part) for part in user_sid.split("-")[3:]],
        product_type = version.get("product_type", "WinNT"),
        domain = process_environment.get("USERDOMAIN", ""),
        accounts = accounts,
    )
    extension_plugins = [factory({
        "crt": crt,
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
    machine.use([
        registry,
        services,
        setup,
        advpack,
        exceptions,
        kernel,
        lz32_plugin(kernel),
        cabinet,
        environment_plugin(process_environment, system_time = system_time),
        event_log_plugin(),
        performance,
        ole,
        automation,
        com_plugin(registry),
        crypto,
        cryptoapi,
        rpc,
        crt,
        security,
        network,
        winsock_plugin(),
        winsock_helper_plugin(),
        resources,
        versions,
        appmodel_plugin(),
        wer_plugin(),
        gdi32_plugin(),
        shell32_plugin(module_path = module, environment = process_environment, malloc = ole.state),
        common_controls,
        shell_plugin(module, kernel = kernel),
        user_interface,
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
                return {
                    "patches": registry.patches(),
                    "queries": registry.queries(),
                    "registry_opens": registry.opens(),
                    "registry_transactions": registry.transactions(),
                    "registry_keys": registry.keys(),
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
                    "process_queries": kernel.state["process_queries"],
                    "system_queries": kernel.state["system_queries"],
                    "cabinet_actions": cabinet.state["actions"],
                    "threads": kernel.state["threads"],
                    "timer_callbacks": kernel.state["timer_callbacks"],
                    "generated_files": generated_files(),
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
            return {
                "patches": registry.patches(),
                "queries": registry.queries(),
                "registry_opens": registry.opens(),
                "registry_transactions": registry.transactions(),
                "registry_keys": registry.keys(),
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
                "process_queries": kernel.state["process_queries"],
                "system_queries": kernel.state["system_queries"],
                "cabinet_actions": cabinet.state["actions"],
                "threads": kernel.state["threads"],
                "timer_callbacks": kernel.state["timer_callbacks"],
                "generated_files": generated_files(),
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
    if execute != None and (arguments or prepare != None):
        fail("run execute cannot be combined with arguments or prepare")
    call_arguments = arguments
    if prepare != None:
        if arguments:
            fail("run accepts either arguments or prepare, not both")
        call_arguments = prepare(machine)
    result = execute(machine) if execute != None else machine.call_export(export, args = call_arguments)
    return {
        "patches": registry.patches(),
        "queries": registry.queries(),
        "registry_opens": registry.opens(),
        "registry_transactions": registry.transactions(),
        "registry_keys": registry.keys(),
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
        "process_queries": kernel.state["process_queries"],
        "system_queries": kernel.state["system_queries"],
        "cabinet_actions": cabinet.state["actions"],
        "threads": kernel.state["threads"],
        "timer_callbacks": kernel.state["timer_callbacks"],
        "generated_files": generated_files(),
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
