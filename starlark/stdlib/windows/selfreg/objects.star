"""Explicit object-manager directory facts, independent of the host namespace."""
load("@stdlib//windows/emulation:abi.star", "object_attributes_layout", "counted_string_layout")

def object_directories_plugin(kernel, directories = {}, security_module = "ntdll.dll"):
    """Open declared absolute directories with caller-supplied allowed access.

    `directories` maps exact NT names to allowed specific/standard access masks.
    Values may also be records with `access` and explicit self-relative `security`
    bytes. NtQuerySecurityObject checks owned-handle rights and delegates projection
    to the real mapped target NTDLL RtlQuerySecurityObject. `security_module` may
    name a separately admitted native implementation image, without exposing its
    unrelated optional exports to the target loader. Missing security facts
    or native implementation fail closed. These are admission facts, not an ACL
    access evaluator. No default objects, host namespace, enumeration, mutation, generic access,
    inheritance or symbolic links are supplied. Relative opens require an owned
    directory root. Unknown names in this closed namespace return not-found.
    """
    facts = {name: dict(value) if type(value) == "dict" else {"access": value} for name, value in directories.items()}
    folded = {}
    for name, fact in facts.items():
        if any([key not in ["access", "security"] for key in fact]): fail("unknown object directory fact")
        access = fact.get("access")
        security = fact.get("security")
        if security != None:
            if type(security) != "bytes" or len(security) < 20 or len(security) > 65536 or binary.read_u8(security, 0) != 1 or not binary.read_u16le(security, 2) & 0x8000:
                fail("object directory security requires a bounded self-relative descriptor")
        if type(name) != "string" or not name.startswith("\\") or name == "\\" or any([not part or part in [".", ".."] for part in name[1:].split("\\")]) or "\x00" in name or "/" in name:
            fail("object directory fact requires a canonical absolute NT name")
        if type(access) != "int" or access < 0 or access & ~0xf000f:
            fail("object directory fact requires specific/standard directory access")
        if name.lower() in folded: fail("case-ambiguous object directory facts")
        folded[name.lower()] = name
    state = {"handles": {}, "next_handle": 0x31000000, "opens": []}
    def close(handle):
        entry = state["handles"].get(handle)
        if entry == None: return None
        if entry["closed"]: return False
        entry["closed"] = True
        return True
    def query_security(event):
        m = event.machine
        handle, information, output, length, required = event.args
        information &= 0xffffffff
        entry = state["handles"].get(handle)
        if entry == None or entry["closed"]: return 0xc0000008
        if not required: return 0xc000000d
        if information & ~0x17: fail("object directory security query class is not modeled")
        if information and not entry["access"] & 0x20000: return 0xc0000022
        descriptor = facts[entry["name"]].get("security")
        if descriptor == None: fail("object directory has no explicit security descriptor")
        # Native NTDLL projects owner/group/DACL/mandatory-label information.
        # Require a real mapped implementation, never a success-only fallback.
        target = m.resolve_export(security_module, name = "RtlQuerySecurityObject")
        if not any([image.name.lower() == security_module.lower() and image.image_size and target >= image.base and target < image.base + image.image_size for image in m.modules]):
            fail("object security queries require target NTDLL RtlQuerySecurityObject")
        address = m.allocate(value = descriptor, name = "object directory security fact")
        result = m.invoke(target, args = [address, information, output, length & 0xffffffff, required])
        m.free(address)
        if result.reason != "return": fail("native directory security projection stopped: " + result.reason + " " + result.detail)
        return result.value
    def callback(event):
        if event.name.lower() == "ntquerysecurityobject": return query_security(event)
        m = event.machine
        output, access, attrs = event.args
        access &= 0xffffffff
        if not output or not attrs: return 0xc000000d
        oa = object_attributes_layout(m.pointer_size)
        if m.read_u32le(attrs) != oa["Size"]: return 0xc000000d
        flags = m.read_u32le(attrs + oa["Attributes"])
        if flags & ~0x40 or m.read_pointer(attrs + oa["SecurityDescriptor"]) or m.read_pointer(attrs + oa["SecurityQualityOfService"]):
            fail("object directory open attributes/security options are not modeled")
        if access & ~0xf000f: fail("object directory generic/unsupported access is not modeled")
        string = m.read_pointer(attrs + oa["ObjectName"])
        if not string: return 0xc000000d
        us = counted_string_layout(m.pointer_size)
        length, capacity = m.read_u16le(string), m.read_u16le(string + 2)
        pointer = m.read_pointer(string + us["Buffer"])
        if not length or length % 2 or length > capacity or not pointer: return 0xc000000d
        if length > 4096: fail("object directory name exceeds bound")
        name = binary.text(m.read(pointer, length), encoding = "utf16le")
        if "\x00" in name or "/" in name: fail("object directory name form is not modeled")
        root = m.read_pointer(attrs + oa["RootDirectory"])
        if root:
            parent = state["handles"].get(root)
            if parent == None or parent["closed"]: return 0xc0000008
            if name.startswith("\\"): return 0xc000003b
            name = parent["name"] + "\\" + name
        elif not name.startswith("\\"):
            return 0xc000003b
        if any([not part or part in [".", ".."] for part in name[1:].split("\\")]):
            fail("object directory path normalization is not modeled")
        exact = folded.get(name.lower()) if flags & 0x40 else name
        if exact not in facts: return 0xc0000034
        if access & ~facts[exact]["access"]: return 0xc0000022
        handle = state["next_handle"]
        if handle >= 0x31001000: fail("object directory handle limit")
        state["handles"][handle] = dict(name = exact, access = access, closed = False)
        state["next_handle"] += 1
        state["opens"].append(dict(name = exact, access = access, handle = handle))
        m.write_pointer(output, handle)
        return 0
    def install(machine):
        kernel.state.setdefault("handle_closers", []).append(close)
        signatures = {"ntopendirectoryobject": 3, "ntquerysecurityobject": 5}
        machine.provide_exports(callback, module = "ntdll.dll", signatures = signatures)
        for imported in machine.imports_named(list(signatures)):
            if imported.module.lower() == "ntdll.dll": machine.hook(callback, address = imported.address, argc = signatures[imported.name.lower()])
    return emulator.plugin(install, name = "windows.object-directories", state = state)
