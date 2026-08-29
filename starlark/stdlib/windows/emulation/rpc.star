"""In-memory Windows RPC runtime and semantic proxy registration.

This module models the public NdrDllRegisterProxy contract. It parses the
MIDL-generated ProxyFileInfo tables already mapped in the target DLL and emits
registry operations; RPCRT4 itself is never loaded or executed.
"""

load("@stdlib//windows/selfreg:facts.star", "guid_bytes")

_RPC_RUNTIME_SIGNATURES = {
    "i_rpcexceptionfilter": 1,
    "i_rpcmapwin32status": 1,
    "rpcbindingfree": 1,
    "rpcbindingfromstringbindingw": 2,
    "rpcbindingsetauthinfoexw": 7,
    "rpcbindingvectorfree": 1,
    "rpcepregisterw": 4,
    "rpcimpersonateclient": 1,
    "rpcmgmtstopserverlistening": 1,
    "rpcmgmtsetserverstacksize": 1,
    "rpcraiseexception": 1,
    "rpcreverttoself": 0,
    "rpcreverttoselfex": 1,
    "rpcserverinqbindings": 1,
    "rpcserverinqcallattributesw": 2,
    "rpcserverinterfacegroupactivate": 1,
    "rpcserverinterfacegroupclose": 1,
    "rpcserverinterfacegroupcreatew": 8,
    "rpcserverlisten": 3,
    "rpcserverregisterauthinfow": 4,
    "rpcserverregisterif": 3,
    "rpcserveruseprotseqepw": 4,
    "rpcserveruseprotseqw": 3,
    "rpcserverregisterifex": 6,
    "rpcserverunregisterif": 3,
    "rpcstringbindingcomposew": 6,
    "rpcstringfreew": 1,
    "uuidcreate": 1,
    "uuidfromstringw": 2,
    "uuidtostringw": 2,
}

_NDR_PROXY_SIGNATURES = {
    "ndrdllgetclassobject": 6,
    "ndrdllregisterproxy": 3,
}

def _hex(value, width):
    text = hex(value)[2:].upper()
    return "0" * (width - len(text)) + text

def _guid(machine, address):
    cursor = binary.cursor(machine.read(address, 16))
    return "{%s-%s-%s-%s-%s}" % (
        _hex(cursor.u32le(), 8),
        _hex(cursor.u16le(), 4),
        _hex(cursor.u16le(), 4),
        hex(cursor.bytes(2)).upper(),
        hex(cursor.bytes(6)).upper(),
    )

def _uuid_bytes(value):
    if len(value) == 36:
        value = "{" + value + "}"
    return guid_bytes(value)

def _uuid_text(value):
    cursor = binary.cursor(value)
    # Windows RPC accepts either case on input but its runtime formatting
    # contract always emits lower-case hexadecimal characters.
    return ("%s-%s-%s-%s-%s" % (
        _hex(cursor.u32le(), 8),
        _hex(cursor.u16le(), 4),
        _hex(cursor.u16le(), 4),
        hex(cursor.bytes(2)).upper(),
        hex(cursor.bytes(6)).upper(),
    )).lower()

def _created_uuid(module, counter):
    seed = binary.builder()
    seed.append(binary.encode(module.lower(), encoding = "utf8", nul = True))
    seed.u64le(counter)
    digest = crypto.hash("sha256", seed.bytes())
    output = binary.builder(capacity = 16)
    output.append(digest[:7])
    output.u8((binary.read_u8(digest, 7) & 0x0f) | 0x40)
    output.u8((binary.read_u8(digest, 8) & 0x3f) | 0x80)
    output.append(digest[9:16])
    return output.bytes()

def _set_string(registry, key, name, value):
    registry.set_value(
        hive = "SOFTWARE",
        key = key,
        name = name,
        type = "REG_SZ",
        value = value,
    )

def rpc_plugin(registry, module, maximum_files = 4096, maximum_interfaces = 65535, target_instruction_limit = 100000, target_continuation_limit = 64, on_budget = None, on_client_call = None, manager_trace = False, manager_trace_limit = 4096, manager_call_trace = False, manager_call_trace_limit = 4096, manager_call_trace_start = 0, manager_call_trace_size = 0):
    """Provides semantic NdrDllRegisterProxy registration.

    The limits bound pointer-table traversal independently of emulator memory
    permissions. Malformed target structures fail closed through machine.read.
    """
    def register_proxy(event):
        proxy_files = event.args[1]
        proxy_clsid = _guid(event.machine, event.args[2])
        class_key = "/Classes/CLSID/" + proxy_clsid
        _set_string(registry, class_key, "(default)", "PSFactoryBuffer")
        _set_string(registry, class_key + "/InprocServer32", "(default)", module)
        _set_string(registry, class_key + "/InprocServer32", "ThreadingModel", "Both")

        seen = {}
        for file_index in range(maximum_files):
            info = event.machine.read_u32le(proxy_files + file_index * 4)
            if info == 0:
                break
            proxy_vtables = event.machine.read_u32le(info)
            names = event.machine.read_u32le(info + 8)
            table = event.machine.read_u32le(info + 20)
            table_size = table & 0xffff
            table_version = table >> 16
            if table_version not in [1, 2] or table_size > maximum_interfaces:
                fail("unsupported ProxyFileInfo table version/size %d/%d" % (table_version, table_size))
            for interface_index in range(table_size):
                proxy_vtable = event.machine.read_u32le(proxy_vtables + interface_index * 4)
                if proxy_vtable == 0:
                    continue
                iid_address = event.machine.read_u32le(proxy_vtable + 4)
                if iid_address == 0:
                    continue
                iid = _guid(event.machine, iid_address)
                if iid in seen:
                    continue
                seen[iid] = True
                key = "/Classes/Interface/" + iid
                if names:
                    name_address = event.machine.read_u32le(names + interface_index * 4)
                    if name_address:
                        _set_string(registry, key, "(default)", event.machine.read_cstring(name_address))
                _set_string(registry, key + "/ProxyStubClsid32", "(default)", proxy_clsid)
        return 0

    def get_class_object(event):
        requested_class, requested_interface, output, _, proxy_class, _ = event.args
        if output:
            event.machine.write(output, b"\x00\x00\x00\x00")
        if not requested_class or not requested_interface or not output or not proxy_class:
            return 0x80070057  # E_INVALIDARG
        if event.machine.read(requested_class, 16) != event.machine.read(proxy_class, 16):
            return 0x80040111  # CLASS_E_CLASSNOTAVAILABLE
        # The matching path requires an IPSFactoryBuffer implementation. Keep
        # the ABI handled while failing the unsupported interface explicitly.
        return 0x80004002  # E_NOINTERFACE

    if target_instruction_limit < 1 or target_instruction_limit > 10000000 or target_continuation_limit < 0 or target_continuation_limit > 4096 or manager_trace_limit < 1 or manager_trace_limit > 65536 or manager_call_trace_limit < 1 or manager_call_trace_limit > 65536:
        fail("invalid RPC target execution limits")
    state = {
        "server_stack_size": 0,
        "protocols": [],
        "interfaces": {},
        "listening": False,
        "impersonating": False,
        "strings": {},
        "bindings": {},
        "interface_groups": {},
        "actions": [],
        "client_calls": [],
        "target_slices": 0,
        "target_steps": 0,
        "background_pumps": 0,
        "uuid_counter": 0,
    }

    def read_wstring(event, address):
        return event.machine.read_cstring(address, encoding = "utf16le") if address else ""

    def invoke_target(machine, target, arguments, trace = False, call_trace = False):
        previous_trace = None
        previous_call_trace = None
        if trace:
            previous_trace = machine.configure_trace(enabled = True, limit = manager_trace_limit)
        if call_trace:
            previous_call_trace = machine.configure_call_trace(enabled = True, limit = manager_call_trace_limit, start = manager_call_trace_start, size = manager_call_trace_size)
        execution = machine.spawn(target, args = arguments)
        result = execution.run(instruction_limit = target_instruction_limit)
        state["target_slices"] += 1
        state["target_steps"] += result.steps
        continuations = 0
        while result.reason in ["budget", "wait"] and continuations < target_continuation_limit:
            if result.reason == "wait" and on_budget == None:
                break
            if on_budget != None:
                on_budget(machine)
                state["background_pumps"] += 1
            result = execution.run(instruction_limit = target_instruction_limit)
            state["target_slices"] += 1
            state["target_steps"] += result.steps
            continuations += 1
        if previous_trace != None:
            machine.configure_trace(enabled = previous_trace.enabled, limit = previous_trace.limit)
        if previous_call_trace != None:
            machine.configure_call_trace(enabled = previous_call_trace.enabled, limit = previous_call_trace.limit, start = previous_call_trace.start, size = previous_call_trace.size)
        if not execution.done:
            # The caller receives the bounded diagnostic result, not the
            # resumable execution. Release its private stack before retrying
            # the RPC operation from its stable client call boundary.
            execution.close()
        return result

    def allocate_rpc_string(event, value):
        data = binary.encode(value, encoding = "utf16le", nul = True)
        address = event.machine.allocate(value = data, name = "RPC string binding")
        state["strings"][address] = True
        return address

    def runtime(event):
        name = event.name.lower()
        state["actions"].append({"action": "runtime", "name": name, "arguments": list(event.args)})
        if name == "i_rpcexceptionfilter":
            # RPC-generated exception guards handle RPC runtime exceptions.
            return 1  # EXCEPTION_EXECUTE_HANDLER
        if name == "i_rpcmapwin32status":
            return 0 if event.args[0] == 0 else 0xc0020000 | (event.args[0] & 0xffff)
        if name == "rpcstringbindingcomposew":
            if not event.args[5] or not event.args[1]:
                return 87  # RPC_S_INVALID_ARG
            parts = {
                "object": read_wstring(event, event.args[0]),
                "protocol": read_wstring(event, event.args[1]),
                "network": read_wstring(event, event.args[2]),
                "endpoint": read_wstring(event, event.args[3]),
                "options": read_wstring(event, event.args[4]),
            }
            value = parts["protocol"] + ":" + parts["network"]
            if parts["endpoint"] or parts["options"]:
                value += "[" + parts["endpoint"]
                if parts["options"]:
                    value += "," + parts["options"]
                value += "]"
            address = allocate_rpc_string(event, value)
            event.machine.write(event.args[5], binary.u32le(address))
            state["actions"].append(dict(parts, action = "compose", value = value))
            return 0
        if name == "rpcbindingfromstringbindingw":
            if not event.args[0] or not event.args[1]:
                return 87
            value = read_wstring(event, event.args[0])
            handle = event.machine.allocate(size = 4, name = "RPC binding handle")
            state["bindings"][handle] = {"string": value, "authentication": None}
            event.machine.write(event.args[1], binary.u32le(handle))
            state["actions"].append({"action": "bind", "binding": handle, "value": value})
            return 0
        if name == "rpcbindingsetauthinfoexw":
            binding = state["bindings"].get(event.args[0])
            if binding == None:
                state["actions"].append({
                    "action": "authenticate-invalid",
                    "binding": event.args[0],
                    "known_bindings": list(state["bindings"].keys()),
                })
                return 1702  # RPC_S_INVALID_BINDING
            binding["authentication"] = {
                "principal": read_wstring(event, event.args[1]),
                "level": event.args[2],
                "service": event.args[3],
                "identity": event.args[4],
                "authorization": event.args[5],
                "security_qos": event.args[6],
            }
            state["actions"].append(dict(binding["authentication"], action = "authenticate", binding = event.args[0]))
            return 0
        if name == "rpcbindingfree":
            if not event.args[0]:
                return 87
            handle = event.machine.read_u32le(event.args[0])
            state["bindings"].pop(handle, None)
            if handle:
                event.machine.free(handle)
            event.machine.write(event.args[0], b"\x00" * 4)
            state["actions"].append({"action": "unbind", "binding": handle})
            return 0
        if name == "uuidfromstringw":
            if not event.args[1]:
                return 87  # RPC_S_INVALID_ARG
            if not event.args[0]:
                event.machine.write(event.args[1], b"\x00" * 16)
                return 0
            value = _uuid_bytes(event.machine.read_cstring(event.args[0], encoding = "utf16le"))
            if value == None:
                return 1705  # RPC_S_INVALID_STRING_UUID
            event.machine.write(event.args[1], value)
            return 0
        if name == "uuidcreate":
            if not event.args[0]:
                return 87
            value = _created_uuid(module, state["uuid_counter"])
            state["uuid_counter"] += 1
            event.machine.write(event.args[0], value)
            state["actions"].append({"action": "uuid-create", "value": _uuid_text(value)})
            return 0
        if name == "uuidtostringw":
            if not event.args[0] or not event.args[1]:
                return 87
            value = binary.encode(_uuid_text(event.machine.read(event.args[0], 16)), encoding = "utf16le", nul = True)
            address = event.machine.allocate(value = value, name = "RPC UUID string")
            state["strings"][address] = True
            event.machine.write(event.args[1], binary.u32le(address))
            return 0
        if name == "rpcstringfreew":
            if not event.args[0]:
                return 87
            address = event.machine.read_u32le(event.args[0])
            if address in state["strings"]:
                state["strings"].pop(address)
                event.machine.free(address)
            event.machine.write(event.args[0], b"\x00" * 4)
            return 0
        if name == "rpcmgmtsetserverstacksize":
            state["server_stack_size"] = event.args[0]
            return 0  # RPC_S_OK
        if name == "rpcserverinqcallattributesw":
            attributes = event.args[1]
            if not attributes:
                return 87  # RPC_S_INVALID_ARG
            version = event.machine.read_u32le(attributes)
            if version not in [1, 2]:
                return 87
            # In-memory calls are authenticated, private, and local. Preserve
            # caller-owned buffers while publishing only the scalar fields
            # consumed by RPC_CALL_ATTRIBUTES_V2_W clients.
            event.machine.write_u32le(attributes + 0x18, 6)  # RPC_C_AUTHN_LEVEL_PKT_PRIVACY
            if version >= 2:
                event.machine.write_u16le(attributes + 0x40, 1)  # rcclClientLocal
            state["actions"].append({
                "action": "call-attributes",
                "version": version,
                "authentication_level": 6,
                "local": True,
            })
            return 0
        if name == "rpcserveruseprotseqepw":
            if not event.args[0] or not event.args[2]:
                return 87  # RPC_S_INVALID_ARG
            state["protocols"].append({
                "protocol": event.machine.read_cstring(event.args[0], encoding = "utf16le"),
                "maximum_calls": event.args[1],
                "endpoint": event.machine.read_cstring(event.args[2], encoding = "utf16le"),
                "security_descriptor": event.args[3],
            })
            return 0
        if name == "rpcserveruseprotseqw":
            if not event.args[0]:
                return 87
            state["protocols"].append({
                "protocol": event.machine.read_cstring(event.args[0], encoding = "utf16le"),
                "maximum_calls": event.args[1],
                "endpoint": "",
                "security_descriptor": event.args[2],
            })
            return 0
        if name == "rpcserverregisterif":
            if not event.args[0]:
                return 87
            state["interfaces"][event.args[0]] = {"manager_type": event.args[1], "manager_epv": event.args[2]}
            return 0
        if name == "rpcserverregisterifex":
            if not event.args[0]:
                return 87
            state["interfaces"][event.args[0]] = {
                "manager_type": event.args[1], "manager_epv": event.args[2],
                "flags": event.args[3], "maximum_calls": event.args[4], "callback": event.args[5],
            }
            return 0
        if name == "rpcserverinterfacegroupcreatew":
            interface_templates, interface_count, endpoint_templates, endpoint_count, idle_period, idle_callback, security_descriptor, output = event.args
            if not interface_templates or not interface_count or interface_count > maximum_interfaces or not output:
                return 87  # RPC_S_INVALID_ARG
            if endpoint_count > 65535 or (endpoint_count and not endpoint_templates):
                return 87
            interfaces = []
            for index in range(interface_count):
                template = interface_templates + index * 40
                interface = event.machine.read_u32le(template + 4)
                if not interface:
                    return 87
                registration = {
                    "manager_type": event.machine.read_u32le(template + 8),
                    "manager_epv": event.machine.read_u32le(template + 12),
                    "flags": event.machine.read_u32le(template + 16),
                    "maximum_calls": event.machine.read_u32le(template + 20),
                    "maximum_rpc_size": event.machine.read_u32le(template + 24),
                    "callback": event.machine.read_u32le(template + 28),
                    "uuid_vector": event.machine.read_u32le(template + 32),
                    "annotation": read_wstring(event, event.machine.read_u32le(template + 36)),
                }
                state["interfaces"][interface] = registration
                interfaces.append({"address": interface, "registration": registration})
            endpoints = []
            for index in range(endpoint_count):
                template = endpoint_templates + index * 12
                endpoint = {
                    "protocol": read_wstring(event, event.machine.read_u32le(template + 4)),
                    "endpoint": read_wstring(event, event.machine.read_u32le(template + 8)),
                }
                endpoints.append(endpoint)
                state["protocols"].append(dict(endpoint, maximum_calls = 0, security_descriptor = security_descriptor))
            handle = event.machine.allocate(size = 4, name = "RPC interface group")
            state["interface_groups"][handle] = {
                "interfaces": interfaces,
                "endpoints": endpoints,
                "idle_period": idle_period,
                "idle_callback": idle_callback,
                "security_descriptor": security_descriptor,
                "active": False,
            }
            event.machine.write_u32le(output, handle)
            state["actions"].append({
                "action": "interface-group-create",
                "handle": handle,
                "interfaces": interfaces,
                "endpoints": endpoints,
            })
            return 0
        if name == "rpcserverinterfacegroupactivate":
            group = state["interface_groups"].get(event.args[0])
            if group == None:
                return 1702  # RPC_S_INVALID_BINDING
            group["active"] = True
            state["listening"] = True
            state["actions"].append({
                "action": "interface-group-activate",
                "handle": event.args[0],
            })
            # Interface-group activation publishes the endpoints but does not
            # block the caller. Services commonly finish constructing state
            # after this returns; only RpcServerListen is a listening wait.
            return 0
        if name == "rpcserverinterfacegroupclose":
            group = state["interface_groups"].pop(event.args[0], None)
            if group == None:
                return 1702
            for interface in group["interfaces"]:
                state["interfaces"].pop(interface["address"], None)
            event.machine.free(event.args[0])
            state["listening"] = False
            return 0
        if name == "rpcserverunregisterif":
            if event.args[0]:
                state["interfaces"].pop(event.args[0], None)
            else:
                state["interfaces"] = {}
            return 0
        if name == "rpcserverlisten":
            state["listening"] = True
            event.machine.stop("rpc-listening", detail = "RPC server is accepting in-memory calls")
            return None
        if name == "rpcmgmtstopserverlistening":
            state["listening"] = False
            return 0
        if name == "rpcimpersonateclient":
            state["impersonating"] = True
            return 0
        if name in ["rpcreverttoself", "rpcreverttoselfex"]:
            state["impersonating"] = False
            return 0
        if name == "rpcserverregisterauthinfow":
            return 0
        if name == "rpcserverinqbindings":
            if not event.args[0]:
                return 87
            binding = event.machine.allocate(size = 4, name = "RPC binding")
            vector = binary.builder(capacity = 8)
            vector.u32le(1)
            vector.u32le(binding)
            address = event.machine.allocate(value = vector.bytes(), name = "RPC binding vector")
            event.machine.write(event.args[0], binary.u32le(address))
            return 0
        if name == "rpcbindingvectorfree":
            if event.args[0]:
                event.machine.write(event.args[0], b"\x00\x00\x00\x00")
            return 0
        if name == "rpcepregisterw":
            return 0
        if name == "rpcraiseexception":
            event.machine.stop("rpc-exception", detail = "RPC exception {}".format(event.args[0]), value = event.args[0])
            return None
        return 1764  # RPC_S_CANNOT_SUPPORT

    def ndr_client_call(event):
        stub = event.args[0]
        procedure = event.args[1]
        client_interface = event.machine.read_u32le(stub) if stub else 0
        argument_address = event.args[2] if len(event.args) > 2 else 0
        servers = []
        for address, registration in state["interfaces"].items():
            servers.append({
                "address": address,
                "registration": registration,
                "interface_id": _guid(event.machine, address + 4),
                "interface_version": (
                    event.machine.read_u16le(address + 20),
                    event.machine.read_u16le(address + 22),
                ),
            })
        call = {
            "stub": stub,
            "client_interface_address": client_interface,
            "client_interface_id": _guid(event.machine, client_interface + 4) if client_interface else "",
            "client_interface_version": (
                event.machine.read_u16le(client_interface + 20),
                event.machine.read_u16le(client_interface + 22),
            ) if client_interface else (0, 0),
            "procedure": procedure,
            "arguments": list(event.args[2:]),
            "argument_address": argument_address,
            "servers": servers,
        }
        state["client_calls"].append(call)
        state["actions"].append(dict(call, action = "client-call"))

        if not client_interface or not procedure or not argument_address:
            return 87  # RPC_S_INVALID_ARG

        client_id = event.machine.read(client_interface + 4, 20)
        client_format = event.machine.read(procedure, 20)
        for interface_address in state["interfaces"]:
            if event.machine.read(interface_address + 4, 20) != client_id:
                continue
            server_info = event.machine.read_u32le(interface_address + 60)
            if not server_info:
                continue
            manager_table = event.machine.read_u32le(server_info + 4)
            format_base = event.machine.read_u32le(server_info + 8)
            offset_table = event.machine.read_u32le(server_info + 12)
            dispatch_table = event.machine.read_u32le(interface_address + 44)
            procedure_count = event.machine.read_u32le(dispatch_table) if dispatch_table else 0
            if not manager_table or not format_base or not offset_table or procedure_count > 4096:
                continue
            for operation in range(procedure_count):
                server_format = format_base + event.machine.read_u16le(offset_table + operation * 2)
                if event.machine.read(server_format, 20) != client_format:
                    continue
                registration = state["interfaces"][interface_address]
                interface_callback = registration.get("callback", 0)
                if interface_callback:
                    callback_result = invoke_target(
                        event.machine,
                        interface_callback,
                        [interface_address, 0],
                        trace = manager_trace,
                        call_trace = manager_call_trace,
                    )
                    call["interface_callback"] = {
                        "address": interface_callback,
                        "reason": callback_result.reason,
                        "detail": callback_result.detail,
                        "value": callback_result.value,
                        "eip": callback_result.eip,
                        "registers": callback_result.registers,
                        "steps": callback_result.steps,
                        "calls": callback_result.calls,
                        "call_trace": callback_result.call_trace,
                        "recent": callback_result.recent,
                        "trace": callback_result.trace,
                    }
                    if callback_result.reason != "return":
                        event.machine.stop("rpc-interface-callback", detail = callback_result.reason + ": " + callback_result.detail)
                        return None
                    if callback_result.value:
                        return callback_result.value
                stack_size = event.machine.read_u16le(procedure + 8)
                if stack_size < 4 or stack_size % 4 or stack_size > 4096:
                    return 1766  # RPC_S_INTERNAL_ERROR
                argument_count = stack_size // 4 - 1
                arguments = []
                for index in range(argument_count):
                    arguments.append(event.machine.read_u32le(argument_address + index * 4))
                target = event.machine.read_u32le(manager_table + operation * 4)
                if not target:
                    return 1745  # RPC_S_PROCNUM_OUT_OF_RANGE
                call["operation"] = operation
                call["manager"] = target
                call["manager_arguments"] = arguments
                if on_client_call != None:
                    call["observation"] = on_client_call(event.machine, {
                        "interface_id": call["client_interface_id"],
                        "interface_version": call["client_interface_version"],
                        "operation": operation,
                        "manager": target,
                        "arguments": list(arguments),
                    })
                result = invoke_target(event.machine, target, arguments, trace = manager_trace, call_trace = manager_call_trace)
                call["result"] = {
                    "reason": result.reason,
                    "detail": result.detail,
                    "value": result.value,
                    "eip": result.eip,
                    "steps": result.steps,
                    "calls": result.calls,
                    "call_trace": result.call_trace,
                    "recent": result.recent,
                    "registers": result.registers,
                    "trace": result.trace,
                }
                if result.reason == "return":
                    return result.value
                event.machine.stop("rpc-manager", detail = "%s: %s" % (result.reason, result.detail), value = result.value)
                return None
        return 1722  # RPC_S_SERVER_UNAVAILABLE

    def install(machine):
        machine.provide_export(
            get_class_object,
            module = "rpcrt4.dll",
            name = "NdrDllGetClassObject",
            argc = _NDR_PROXY_SIGNATURES["ndrdllgetclassobject"],
        )
        machine.provide_export(
            register_proxy,
            module = "rpcrt4.dll",
            name = "NdrDllRegisterProxy",
            argc = _NDR_PROXY_SIGNATURES["ndrdllregisterproxy"],
        )
        for name, argc in _RPC_RUNTIME_SIGNATURES.items():
            machine.provide_export(runtime, module = "rpcrt4.dll", name = name, argc = argc)
        machine.provide_export(
            ndr_client_call,
            module = "rpcrt4.dll",
            name = "NdrClientCall2",
            argc = 18,
            convention = "cdecl",
        )
        for imported in machine.imports:
            name = imported.name.lower()
            if imported.module.lower() == "rpcrt4.dll" and name == "ndrdllgetclassobject":
                machine.hook(get_class_object, address = imported.address, argc = _NDR_PROXY_SIGNATURES[name])
            elif imported.module.lower() == "rpcrt4.dll" and name == "ndrdllregisterproxy":
                machine.hook(register_proxy, address = imported.address, argc = _NDR_PROXY_SIGNATURES[name])
            elif imported.module.lower() == "rpcrt4.dll" and name in _RPC_RUNTIME_SIGNATURES:
                machine.hook(runtime, address = imported.address, argc = _RPC_RUNTIME_SIGNATURES[name])
            elif imported.module.lower() == "rpcrt4.dll" and name == "ndrclientcall2":
                machine.hook(ndr_client_call, address = imported.address, argc = 18, convention = "cdecl")

    return emulator.plugin(install, name = "windows.rpc-proxy-registration", state = state)

# Compatibility name for registration-focused callers.
rpc_proxy_plugin = rpc_plugin
