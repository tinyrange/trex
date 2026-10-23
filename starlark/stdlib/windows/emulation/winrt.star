"""Bounded Windows Runtime string-reference semantics."""

def string_reference_plugin():
    """Provides caller-owned UTF-16 HSTRING references, not runtime activation.

    Headers and source buffers remain caller-owned and immutable until their
    last use. Deleting a reference never frees either. Owned/duplicated strings
    and other Windows Runtime APIs are deliberately not supplied.
    """
    state = {"references": {}, "empty": 0}
    def create(event):
        m = event.machine
        source, length, header, output = event.args
        length &= 0xffffffff
        if not output:
            return 0x80070057
        m.write_pointer(output, 0)
        if not header:
            return 0x80070057
        if not source and length:
            return 0x80004003  # E_POINTER
        if length > 16 << 20:
            fail("HSTRING reference exceeds the bounded 16M UTF-16 code units")
        if length and m.read_u16le(source + length * 2) != 0:
            return 0x80070057
        if not length:
            return 0
        # The header is opaque to callers; keep all state checkpoint-visible.
        m.write(header, b"\x00" * (24 if m.pointer_size == 8 else 20))
        m.write_u32le(header, 1)
        m.write_u32le(header + 4, length)
        m.write_pointer(header + (16 if m.pointer_size == 8 else 12), source)
        state["references"][header] = {"source": source, "length": length}
        m.write_pointer(output, header)
        return 0
    def raw(event):
        handle, output = event.args
        if not handle:
            if output:
                event.machine.write_u32le(output, 0)
            return state["empty"]
        reference = state["references"].get(handle)
        if reference == None:
            fail("unknown HSTRING reference")
        if output:
            event.machine.write_u32le(output, reference["length"])
        return reference["source"]
    def delete(event):
        if event.args[0] and event.args[0] not in state["references"]:
            fail("owned or unknown HSTRING deletion is not modeled")
        return 0
    def install(machine):
        state["empty"] = machine.allocate(value = b"\x00\x00", name = "empty-hstring", writable = False)
        for module in ["combase.dll", "api-ms-win-core-winrt-string-l1-1-0.dll"]:
            machine.provide_export(create, module = module, name = "WindowsCreateStringReference", argc = 4)
            machine.provide_export(raw, module = module, name = "WindowsGetStringRawBuffer", argc = 2)
            machine.provide_export(delete, module = module, name = "WindowsDeleteString", argc = 1)
    return emulator.plugin(install, name = "windows.winrt.string-reference", state = state)

def disconnected_network_information_plugin(strings):
    """Exposes only the no-Internet-profile NetworkInformation static query.

    This explicitly selected machine has no connected network. No activation
    or networking fallback is installed for other classes or methods.
    """
    state = {"objects": {}, "vtable": 0, "queries": []}
    iid = b"\x51\xf8\x74\x50\x0d\x95\x65\x41\x9c\x15\x36\x56\x19\x48\x1e\xea"
    unknown = b"\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    inspectable = b"\xe0\xe2\x86\xaf\x2d\xb1\x6a\x4c\x9c\x5a\xd7\xaa\x65\x10\x1e\x90"
    def method(event):
        m = event.machine
        this = event.args[0]
        if this not in state["objects"]:
            fail("NetworkInformation method requires a live interface")
        name = event.name
        if name == "QueryInterface":
            if not event.args[2]:
                return 0x80004003
            m.write_pointer(event.args[2], 0)
            if not event.args[1]:
                return 0x80004003
            if m.read(event.args[1], 16) not in [iid, unknown, inspectable]:
                return 0x80004002
            state["objects"][this] += 1
            m.write_pointer(event.args[2], this)
            return 0
        if name == "AddRef":
            state["objects"][this] += 1
            return state["objects"][this]
        if name == "Release":
            state["objects"][this] -= 1
            count = state["objects"][this]
            if not count:
                state["objects"].pop(this)
                m.free(this)
            return count
        if name == "GetInternetConnectionProfile":
            if not event.args[1]:
                return 0x80004003
            m.write_pointer(event.args[1], 0)
            state["queries"].append({"method": name, "profile": None})
            return 0
        fail("unsupported disconnected NetworkInformation method: " + name)
    def activate(event):
        m = event.machine
        name, requested, output = event.args
        if not output or not requested:
            return 0x80004003
        m.write_pointer(output, 0)
        reference = strings.state["references"].get(name)
        if reference == None:
            fail("runtime activation requires a known HSTRING reference")
        class_name = binary.text(m.read(reference["source"], reference["length"] * 2), encoding = "utf16le")
        if class_name != "Windows.Networking.Connectivity.NetworkInformation":
            fail("unsupported runtime activation: " + class_name)
        if m.read(requested, 16) != iid:
            fail("unsupported NetworkInformation static interface")
        obj = m.allocate(size = m.pointer_size, name = "NetworkInformationStatics")
        m.write_pointer(obj, state["vtable"])
        state["objects"][obj] = 1
        m.write_pointer(output, obj)
        return 0
    def install(machine):
        signatures = [("QueryInterface", 3), ("AddRef", 1), ("Release", 1),
                      ("GetIids", 3), ("GetRuntimeClassName", 2), ("GetTrustLevel", 2),
                      ("GetConnectionProfiles", 2), ("GetInternetConnectionProfile", 2),
                      ("GetLanIdentifiers", 2), ("GetHostNames", 2),
                      ("GetProxyConfigurationAsync", 3), ("GetSortedEndpointPairs", 4),
                      ("NetworkStatusChanged", 3), ("RemoveNetworkStatusChanged", 2)]
        vtable = machine.allocate(size = len(signatures) * machine.pointer_size, name = "NetworkInformationStatics.vtable")
        for i in range(len(signatures)):
            name, argc = signatures[i]
            address = machine.provide_export(method, module = "trex-network-information", name = name, argc = argc)
            machine.write_pointer(vtable + i * machine.pointer_size, address)
        state["vtable"] = vtable
        for module in ["combase.dll", "api-ms-win-core-winrt-l1-1-0.dll"]:
            machine.provide_export(activate, module = module, name = "RoGetActivationFactory", argc = 3)
    return emulator.plugin(install, name = "windows.winrt.disconnected-network-information", state = state)
