"""Service Control Manager semantics for setup-time PE execution."""

_SIGNATURES = {
    "changeserviceconfiga": 11,
    "changeserviceconfigw": 11,
    "changeserviceconfig2a": 3,
    "changeserviceconfig2w": 3,
    "closeservicehandle": 1,
    "controlservice": 3,
    "createservicea": 13,
    "createservicew": 13,
    "deleteservice": 1,
    "openscmanagera": 3,
    "openscmanagerw": 3,
    "openservicea": 3,
    "openservicew": 3,
    "queryserviceconfig2a": 5,
    "queryserviceconfig2w": 5,
    "queryservicestatus": 2,
    "registerservicectrlhandlera": 2,
    "registerservicectrlhandlerw": 2,
    "registerservicectrlhandlerexa": 3,
    "registerservicectrlhandlerexw": 3,
    "setservicestatus": 2,
    "setserviceobjectsecurity": 3,
    "startservicectrldispatchera": 1,
    "startservicectrldispatcherw": 1,
    "startservicea": 3,
    "startservicew": 3,
}

_NO_CHANGE = 0xffffffff

def _create_service_default_account(service_type, account_address):
    """Returns the SCM-persisted default account for a new Win32 service."""
    if account_address or not (service_type & 0x30):
        return ""
    return "LocalSystem"

def _cstring(machine, address, wide):
    if not address:
        return ""
    return machine.read_cstring(address, encoding = "utf16le" if wide else "ascii")

def _self_relative_security_descriptor(machine, address):
    """Reads one bounded self-relative SECURITY_DESCRIPTOR from target memory."""
    if not address:
        return None
    header = machine.read(address, 20)
    cursor = binary.cursor(header)
    if cursor.u8() != 1:
        return None
    cursor.u8()
    if (cursor.u16le() & 0x8000) == 0:
        return None
    offsets = [cursor.u32le(), cursor.u32le(), cursor.u32le(), cursor.u32le()]
    size = 20
    for index, offset in enumerate(offsets):
        if not offset:
            continue
        if offset < 20 or offset > (1 << 20):
            return None
        if index < 2:
            sid = machine.read(address + offset, 8)
            component_size = 8 + binary.read_u8(sid, 1) * 4
        else:
            acl = machine.read(address + offset, 4)
            component_size = binary.read_u16le(acl, 2)
            if component_size < 8:
                return None
        size = max(size, offset + component_size)
    if size > (1 << 20):
        return None
    return machine.read(address, size)

def _multi_string(machine, address, wide):
    if not address:
        return []
    encoding = "utf16le" if wide else "ascii"
    width = 2 if wide else 1
    values = []
    cursor = address
    while True:
        value = machine.read_cstring(cursor, encoding = encoding)
        if not value:
            return values
        values.append(value)
        cursor += (len(value) + 1) * width

def _service_is_active(status):
    return status != None and len(status) >= 2 and status[1] >= 2 and status[1] <= 7

def service_manager_plugin(registry, continuation_limit = 64, instruction_limit = 100000, initialize_module = None, pump_background = None):
    """Models SCM configuration and registry-directed service activation.

    Local COM servers hosted by a service are resolved through CLSID/AppID and
    the service's `ServiceDll`/`ServiceMain` values. The selected target module
    remains an in-memory PE mapped by the caller; no host process is launched.
    """
    if continuation_limit < 0 or continuation_limit > 1024 or instruction_limit < 1 or instruction_limit > 10000000:
        fail("invalid service execution limits")
    state = {"handles": {}, "services": {}, "next_handle": 0x50000, "status": {}, "activations": [], "executions": [], "execution_results": [], "execution_slices": 0, "execution_steps": 0, "settled_dispatchers": {}, "starting_class": ""}

    def retain_execution(execution, result):
        state["executions"].append(execution)
        state["execution_results"].append(result)

    def pump_execution_slice(machine):
        """Advances retained service dispatchers at cooperative budget stops."""
        progressed = False
        for index, execution in enumerate(state["executions"]):
            result = state["execution_results"][index]
            if not execution.done and result.reason == "budget":
                result = execution.run(instruction_limit = min(instruction_limit, execution.instruction_limit))
                state["execution_results"][index] = result
                state["execution_slices"] += 1
                state["execution_steps"] += result.steps
                progressed = True
        return progressed

    state["pump_execution_slice"] = pump_execution_slice

    def handle(kind, value):
        number = state["next_handle"]
        state["next_handle"] = number + 1
        state["handles"][number] = {"kind": kind, "value": value}
        return number

    def service_key(name):
        return "/ControlSet001/Services/" + name

    def set_value(name, value_name, value_type, value):
        registry.set_value("SYSTEM", service_key(name), value_name, value_type, value)

    def configure(machine, name, wide, service_type, start_type, error_control, binary_path, group, tag, dependencies, account):
        if service_type != _NO_CHANGE:
            set_value(name, "Type", "REG_DWORD", service_type)
        if start_type != _NO_CHANGE:
            set_value(name, "Start", "REG_DWORD", start_type)
        if error_control != _NO_CHANGE:
            set_value(name, "ErrorControl", "REG_DWORD", error_control)
        if binary_path:
            set_value(name, "ImagePath", "REG_EXPAND_SZ", _cstring(machine, binary_path, wide))
        if group:
            group_name = _cstring(machine, group, wide)
            if group_name:
                set_value(name, "Group", "REG_SZ", group_name)
        if tag:
            machine.write_u32le(tag, 0)
        if dependencies:
            services = []
            groups = []
            for dependency in _multi_string(machine, dependencies, wide):
                if dependency.startswith("+"):
                    groups.append(dependency[1:])
                else:
                    services.append(dependency)
            if services:
                set_value(name, "DependOnService", "REG_MULTI_SZ", services)
            if groups:
                set_value(name, "DependOnGroup", "REG_MULTI_SZ", groups)
        if account:
            account_name = _cstring(machine, account, wide)
            if account_name:
                set_value(name, "ObjectName", "REG_SZ", account_name)

    def service_for(handle_number):
        entry = state["handles"].get(handle_number)
        if entry == None or entry["kind"] != "service":
            return None
        return entry["value"]

    def callback(event):
        name = event.name.lower()
        args = event.args
        machine = event.machine
        wide = name.endswith("w")
        if name.startswith("openscmanager"):
            return handle("manager", {})
        if name.startswith("createservice"):
            manager = state["handles"].get(args[0])
            if manager == None or manager["kind"] != "manager":
                return 0
            service = _cstring(machine, args[1], wide)
            if not service:
                return 0
            display = _cstring(machine, args[2], wide) if args[2] else ""
            state["services"][service.lower()] = service
            if display:
                set_value(service, "DisplayName", "REG_SZ", display)
            configure(machine, service, wide, args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11])
            default_account = _create_service_default_account(args[4], args[11])
            if default_account:
                set_value(service, "ObjectName", "REG_SZ", default_account)
            return handle("service", service)
        if name.startswith("openservice"):
            manager = state["handles"].get(args[0])
            service = _cstring(machine, args[1], wide)
            known = state["services"].get(service.lower())
            return handle("service", known) if manager != None and manager["kind"] == "manager" and known != None else 0
        if name.startswith("changeserviceconfig2"):
            service = service_for(args[0])
            if service == None:
                return 0
            if args[1] == 1 and args[2]:
                description = machine.read_u32le(args[2])
                if description:
                    set_value(service, "Description", "REG_SZ", _cstring(machine, description, wide))
            elif args[1] == 3 and args[2]:
                set_value(service, "DelayedAutoStart", "REG_DWORD", machine.read_u32le(args[2]))
            return 1
        if name.startswith("changeserviceconfig"):
            service = service_for(args[0])
            if service == None:
                return 0
            configure(machine, service, wide, args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8])
            if args[10]:
                set_value(service, "DisplayName", "REG_SZ", _cstring(machine, args[10], wide))
            return 1
        if name.startswith("queryserviceconfig2"):
            service = service_for(args[0])
            if service == None or not args[4]:
                return 0
            if args[1] == 1:  # SERVICE_CONFIG_DESCRIPTION
                description = registry.get_value("SYSTEM", service_key(service), "Description", "")
                encoded = binary.encode(description, encoding = "utf16le" if wide else "ascii", nul = True) if description else b""
                required = 4 + len(encoded)
                machine.write_u32le(args[4], required)
                if not args[2] or args[3] < required:
                    return 0
                machine.write_u32le(args[2], args[2] + 4 if description else 0)
                if description:
                    machine.write(args[2] + 4, encoded)
                return 1
            if args[1] == 3:  # SERVICE_CONFIG_DELAYED_AUTO_START_INFO
                machine.write_u32le(args[4], 4)
                if not args[2] or args[3] < 4:
                    return 0
                delayed = registry.get_value("SYSTEM", service_key(service), "DelayedAutoStart", 0)
                machine.write_u32le(args[2], int(delayed))
                return 1
            machine.write_u32le(args[4], 0)
            return 0
        if name == "closeservicehandle":
            return 1 if state["handles"].pop(args[0], None) != None else 0
        if name == "deleteservice":
            service = service_for(args[0])
            if service == None:
                return 0
            state["services"].pop(service.lower(), None)
            return 1
        if name == "queryservicestatus":
            service = service_for(args[0])
            if service == None:
                return 0
            machine.write(args[1], b"\x00" * 28)
            machine.write_u32le(args[1], 0x20)
            machine.write_u32le(args[1] + 4, 1)
            return 1
        if name.startswith("registerservicectrlhandler"):
            service = _cstring(machine, args[0], wide)
            if not service or not args[1]:
                return 0
            return handle("service_status", {"service": service, "handler": args[1], "context": args[2] if name.startswith("registerservicectrlhandlerex") else 0})
        if name == "setservicestatus":
            entry = state["handles"].get(args[0])
            if entry == None or entry["kind"] != "service_status" or not args[1]:
                return 0
            status = [machine.read_u32le(args[1] + offset) for offset in range(0, 28, 4)]
            state["status"][entry["value"]["service"].lower()] = status
            return 1
        if name == "setserviceobjectsecurity":
            service = service_for(args[0])
            descriptor = _self_relative_security_descriptor(machine, args[2])
            if service == None or descriptor == None:
                return 0
            return 1 if registry.set_key_security("SYSTEM", service_key(service), descriptor) == 0 else 0
        if name.startswith("startservicectrldispatcher"):
            table = args[0]
            if state["settled_dispatchers"].pop(table, False):
                return 1
            if not table:
                state["activations"].append({"service": "", "result": "invalid-table", "detail": "null service table", "steps": 0})
                return 0
            service_name_address = machine.read_u32le(table)
            target = machine.read_u32le(table + 4)
            if not target:
                state["activations"].append({"service": "", "result": "invalid-table", "detail": "null ServiceMain", "steps": 0})
                return 0
            service_name = _cstring(machine, service_name_address, wide)
            if not service_name:
                state["activations"].append({"service": "", "result": "invalid-table", "detail": "empty service name", "steps": 0})
                return 0
            name_copy = machine.allocate(
                value = binary.encode(service_name, encoding = "utf16le" if wide else "ascii", nul = True),
                name = "service dispatcher name",
            )
            arguments = binary.builder(capacity = 4)
            arguments.u32le(name_copy)
            argv = machine.allocate(value = arguments.bytes(), name = "service dispatcher argv")
            execution = machine.spawn(target, args = [1, argv])
            result = execution.run(instruction_limit = instruction_limit)
            continuations = 0
            while result.reason == "budget" and continuations < continuation_limit:
                result = execution.run(instruction_limit = instruction_limit)
                continuations += 1
            startup = result
            # SERVICE_RUNNING is an observable scheduling boundary, not a
            # place where the service thread remains suspended. Let it leave
            # startup locks and settle at its next wait/listen point before
            # exposing the endpoint to in-memory clients.
            if startup.reason == "service-ready":
                while result.reason in ["service-ready", "budget"] and continuations < continuation_limit:
                    result = execution.run(instruction_limit = instruction_limit)
                    continuations += 1
            retain_execution(execution, result)
            activation = {
                "service": service_name,
                "result": startup.reason,
                "detail": startup.detail,
                "value": startup.value,
                "eip": startup.eip,
                "steps": startup.steps,
                "recent": startup.recent,
                "registers": startup.registers,
                "trace": startup.trace,
            }
            if result != startup:
                activation["background"] = {
                    "result": result.reason,
                    "detail": result.detail,
                    "value": result.value,
                    "eip": result.eip,
                    "steps": result.steps,
                }
            state["activations"].append(activation)
            status = state["status"].get(service_name.lower())
            if startup.reason == "return" and _service_is_active(status):
                for unused in range(continuation_limit):
                    if pump_background == None or not pump_background(machine):
                        break
                    status = state["status"].get(service_name.lower())
                    if not _service_is_active(status):
                        break
                if _service_is_active(status):
                    state["settled_dispatchers"][table] = True
                    machine.stop("service-ready", detail = service_name + " is running")
                    return None
            # StartServiceCtrlDispatcher does not return while a dispatched
            # service remains active. Preserve its initialized process state
            # when a semantic service endpoint becomes ready so a caller can
            # issue in-memory RPC or COM work before resuming shutdown.
            if startup.reason in ["rpc-listening", "service-ready"]:
                state["settled_dispatchers"][table] = True
                machine.stop(startup.reason, detail = startup.detail)
                return None
            return 1
        if name in ["controlservice", "startservicea", "startservicew"]:
            return 1 if service_for(args[0]) != None else 0
        return 0

    def resolve_class(class_name, context = 0x17):
        if not (context & 4):  # CLSCTX_LOCAL_SERVER
            return None
        class_key = "/Classes/CLSID/" + class_name
        service = registry.get_value("SOFTWARE", class_key, "LocalService")
        app_id = registry.get_value("SOFTWARE", class_key, "AppId")
        if service == None and app_id != None:
            service = registry.get_value("SOFTWARE", "/Classes/AppID/" + app_id, "LocalService")
        if service == None or service == "":
            return None
        parameters = "/ControlSet001/Services/" + service + "/Parameters"
        module_path = registry.get_value("SYSTEM", parameters, "ServiceDll")
        entry = registry.get_value("SYSTEM", parameters, "ServiceMain", "ServiceMain")
        if module_path == None or module_path == "":
            return None
        normalized = module_path.replace("/", "\\")
        return {
            "class": class_name,
            "service": service,
            "module_path": module_path,
            "module": normalized.split("\\")[-1].lower(),
            "entry": entry,
        }

    def activate_class(machine, class_name, context):
        activation = resolve_class(class_name, context)
        if activation == None:
            return None
        if initialize_module != None:
            initialized = initialize_module(activation["module"])
            if initialized != None and (initialized.reason != "return" or initialized.value == 0):
                activation["result"] = "module-initialization-failed"
                activation["detail"] = initialized.detail
                activation["steps"] = initialized.steps
                state["activations"].append(activation)
                return activation
        target = 0
        for module in machine.modules:
            if module.name.lower() == activation["module"]:
                target = machine.resolve_export(module.name, name = activation["entry"])
                break
        if not target:
            activation["result"] = "module-unavailable"
            state["activations"].append(activation)
            return activation

        service_name = machine.allocate(value = binary.encode(activation["service"], encoding = "utf16le", nul = True), name = "service name")
        arguments = binary.builder(capacity = 4)
        arguments.u32le(service_name)
        argv = machine.allocate(value = arguments.bytes(), name = "service argv")
        execution = machine.spawn(target, args = [1, argv])
        state["starting_class"] = class_name
        result = execution.run()
        continuations = 0
        while result.reason == "budget" and continuations < continuation_limit:
            result = execution.run()
            continuations += 1
        state["starting_class"] = ""
        activation["result"] = result.reason
        activation["detail"] = result.detail
        activation["steps"] = result.steps
        state["activations"].append(activation)
        retain_execution(execution, result)
        return activation

    def install(machine):
        for name, argc in _SIGNATURES.items():
            machine.provide_export(callback, module = "advapi32.dll", name = name, argc = argc)

    return emulator.plugin(
        install,
        name = "windows.service_manager",
        state = state,
        attrs = {"resolve_class": resolve_class, "activate_class": activate_class},
    )
