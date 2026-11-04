"""Commit captured native registry effects, not historical sets or CBS success.

Bindings identify an exact source hive and an optional encoded emulator mount
prefix. Capture registry.effects() while each hive is mounted, before teardown.
All newly materialized keys require separately established final security; the
writer's parent-copy fallback is deliberately not used as native creation policy.
"""


def _parts(key):
    if not key.startswith("/") or key.endswith("/") and key != "/":
        fail("native registry effect requires a canonical encoded key")
    result = []
    for part in key[1:].split("/") if key != "/" else []:
        decoded = part.replace("%2f", "/").replace("%2F", "/").replace("%25", "%")
        if not part or decoded in [".", ".."] or chr(92) in decoded or chr(0) in decoded or decoded.replace("%", "%25").replace("/", "%2f").lower() != part.lower():
            fail("unsupported native registry effect key component")
        result.append(decoded)
    return result


def _route(record, bindings):
    key = record["key"]
    selected = []
    for binding in bindings:
        prefix = binding["prefix"].rstrip("/")
        if record["hive"].upper() == binding["hive"].upper() and (key.lower() == prefix.lower() or key.lower().startswith(prefix.lower() + "/")):
            selected.append(binding)
    if len(selected) != 1:
        fail("native registry effect has no unique explicit hive binding: " + key)
    binding = selected[0]
    suffix = key[len(binding["prefix"].rstrip("/")):]
    return binding["target"], _parts(suffix or "/")


def _identity(parts):
    return tuple([part.lower() for part in parts])


def _deleted(parts, removals):
    folded = _identity(parts)
    return any([folded[:len(prior)] == prior for prior in removals])


def plan_update_registry_effects(root, effects, bindings, key_security = {}):
    """Build and read back all final hive bytes before modifying the image."""
    states = {}
    for binding in bindings:
        _parts(binding["prefix"])
        target = binding["target"]
        if target in states:
            fail("one captured hive epoch requires one binding per target")
        file = root.find(binding["path"])
        if file == None or digest(file) != digest(binding["source"]):
            fail("native registry source hive changed before planning")
        states[target] = dict(path=binding["path"], source=file, source_hash=digest(file), hive=windows.hive(file), keys={}, patches=[], deletes=[], removed={}, required={})
    for record in effects["key_deletions"]:
        target, parts = _route(record, bindings)
        if not parts:
            fail("native registry key deletion cannot remove a hive root")
        states[target]["removed"][_identity(parts)] = parts
    for record in effects["keys"]:
        target, parts = _route(record, bindings)
        item = dict(key_parts=parts)
        if "security" in record:
            windows.security_descriptor_parts(record["security"])
            item["security"] = record["security"]
        identity = _identity(parts)
        previous = states[target]["keys"].get(identity)
        if previous != None and previous != item:
            fail("conflicting native registry key metadata")
        states[target]["keys"][identity] = item
        states[target]["required"][identity] = parts
    values = {}
    for record in effects["values"]:
        target, parts = _route(record, bindings)
        if type(record["type"]) != "int" or type(record["value"]) != "bytes":
            fail("native registry effects require numeric types and raw bytes")
        name = "" if record["name"] == "(default)" else record["name"]
        identity = (target, _identity(parts), name.lower())
        if identity in values:
            fail("duplicate native final registry value")
        values[identity] = True
        states[target]["patches"].append(dict(key_parts=parts, name=name, type=record["type"], value=record["value"]))
        states[target]["required"][_identity(parts)] = parts
    for record in effects["value_deletions"]:
        target, parts = _route(record, bindings)
        name = "" if record["name"] == "(default)" else record["name"]
        if (target, _identity(parts), name.lower()) in values:
            fail("native final registry value is both written and deleted")
        states[target]["deletes"].append(dict(key_parts=parts, name=name))
    plans = []
    for target, state in states.items():
        required = {}
        for parts in state["required"].values():
            for count in range(len(parts) + 1):
                parent = parts[:count]
                required[_identity(parent)] = parent
        for identity, parts in required.items():
            item = state["keys"].setdefault(identity, dict(key_parts=parts))
            supplied = key_security.get((target, identity))
            if supplied != None:
                if "security" in item and item["security"] != supplied:
                    fail("conflicting native registry final security")
                windows.security_descriptor_parts(supplied)
                item["security"] = supplied
            if state["hive"].find(parts) == None or _deleted(parts, state["removed"]):
                if "security" not in item:
                    fail("native registry key creation security is missing: " + target + ":/" + "/".join(parts))
        file = windows.hive_from_patches(target, state["patches"], keys=list(state["keys"].values()), source=state["source"], exclude_keys=[dict(key_parts=p) for p in state["removed"].values()], exclude_values=state["deletes"])
        after = windows.hive(file)
        for identity, item in state["keys"].items():
            node = after.find(item["key_parts"])
            if node == None or ("security" in item and node.security != item["security"]):
                fail("native registry final key readback disagrees")
        for patch in state["patches"]:
            node = after.find(patch["key_parts"])
            found = [v for n, v in node.value_records.items() if n.lower() == (patch["name"] or "(default)").lower()] if node != None else []
            value = found[0] if len(found) == 1 else None
            if value == None or value.type != patch["type"] or value.raw != patch["value"]:
                fail("native registry final value readback disagrees")
        for identity, parts in state["removed"].items():
            if identity not in required and after.find(parts) != None:
                fail("native registry deleted key survived")
        for deletion in state["deletes"]:
            node = after.find(deletion["key_parts"])
            if node != None and any([n.lower() == (deletion["name"] or "(default)").lower() for n in node.value_records]):
                fail("native registry deleted value survived")
        plans.append(dict(target=target, path=state["path"], source_hash=state["source_hash"], file=file, values=len(state["patches"]), deleted_values=len(state["deletes"]), removed_keys=len(state["removed"])))
    return plans


def apply_update_registry_effects(root, plans):
    """Recheck all source-hive digests before publishing the prepared registry batch; return hive/value/key effect counts."""
    for plan in plans:
        current = root.find(plan["path"])
        if current == None or digest(current) != plan["source_hash"]:
            fail("native registry source hive changed before commit")
    counts = dict(hives=len(plans), values=0, deleted_values=0, removed_keys=0)
    for plan in plans:
        root.write(plan["path"], plan["file"])
        for key in ["values", "deleted_values", "removed_keys"]:
            counts[key] += plan[key]
    return counts


# Actual ntoskrnl C29EBFB0-6B78-B3C0-20DC-A66D99713F9E age6:
# SeAssignSecurity, High SYSTEM, registry mapping, container=1. Explicit
# device-property creator 9407 -> protected 9004; NULL child -> 8004 fixed point.
_DRIVER_PROPERTY_CREATOR = binary.decode("01000794300000003c000000000000001400000002001c0001000000000214003f000f00010100000000000512000000010100000000000512000000010100000000000512000000", "hex")
_DRIVER_PROPERTY_PROTECTED = binary.decode("01000490300000003c000000000000001400000002001c0001000000000214003f000f00010100000000000512000000010100000000000512000000010100000000000512000000", "hex")
_DRIVER_PROPERTY_INHERITED = binary.decode("01000480300000003c000000000000001400000002001c0001000000000214003f000f00010100000000000512000000010100000000000512000000010100000000000512000000", "hex")


_DRIVER_WMI_AUTOLOGGER_PARENT = binary.decode("0100149c3801000048010000140000003000000002001c000100000002c3140006000d00010100000000000100000000020008010a000000000014001900020001010000000000050b000000000a14000000008001010000000000050b000000000018003f000f0001020000000000052000000025020000000a18000000001001020000000000052000000025020000000018003f000f0001020000000000052000000020020000000a18000000001001020000000000052000000020020000000014003f000f00010100000000000512000000000a140000000010010100000000000512000000000028003f000f0001060000000000055000000023907c344178e16e778dc41c993c33a68a68d65b000a28000000001001060000000000055000000023907c344178e16e778dc41c993c33a68a68d65b01020000000000052000000020020000010100000000000512000000", "hex")
_DRIVER_WMI_AUTOLOGGER_CHILD = binary.decode("0100148c3801000044010000140000003000000002001c000100000002d3140006000d00010100000000000100000000020008010a000000001014001900020001010000000000050b000000001a14000000008001010000000000050b000000001018003f000f0001020000000000052000000025020000001a18000000001001020000000000052000000025020000001018003f000f0001020000000000052000000020020000001a18000000001001020000000000052000000020020000001014003f000f00010100000000000512000000001a140000000010010100000000000512000000001028003f000f0001060000000000055000000023907c344178e16e778dc41c993c33a68a68d65b001a28000000001001060000000000055000000023907c344178e16e778dc41c993c33a68a68d65b010100000000000512000000010100000000000512000000", "hex")

def build_update_driver_property_key_security(parent, creator):
    """Require the established native property creator and parent descriptor before returning protected device-property security."""
    if creator != _DRIVER_PROPERTY_CREATOR:
        fail("unestablished native device-property creator descriptor")
    # This is the exact measured DriverDatabase parent, not any permissive ACL.
    native = build_update_driver_key_security(parent)
    if len(native) != 112 or parent != native:
        fail("unestablished native device-property creation parent")
    return _DRIVER_PROPERTY_PROTECTED


def build_update_driver_key_security(parent):
    """Measured NULL-creator SYSTEM key policy for this exact driver database.

    Original kernel CmpCreateChild -> SeAssignSecurity, legacy parent control
    8004, either the three-ACE DriverDatabase policy or the independently
    captured seven-ACE COMPONENTS policy. The latter is a fixed point
    under actual native creation at INF/hash depth and for new CSI component,
    deployment and catalog keys. Unlike NTFS, no 4000
    normalization or AI flags are added. Child owner/group come from the
    declared subject, not arbitrary parent principals. The independently measured Print PackagesToAdd parent also produces the
    seven-ACE child. Other ACLs/controls require their own evidence.
    """
    # Actual WMI AutoLogger: protected DACL, inherited audit SACL and BA
    # owner are transformed by SeAssignSecurity, not copied or relaxed.
    if parent in [_DRIVER_WMI_AUTOLOGGER_PARENT, _DRIVER_WMI_AUTOLOGGER_CHILD]:
        return _DRIVER_WMI_AUTOLOGGER_CHILD
    if parent in [_DRIVER_PROPERTY_PROTECTED, _DRIVER_PROPERTY_INHERITED]:
        return _DRIVER_PROPERTY_INHERITED
    native = binary.decode("01000480580000006400000000000000140000000200440003000000000214003f000f0001010000000000051200000000021400000002000101000000000003040000000002140019000200010100000000000100000000010100000000000512000000010100000000000512000000", "hex")
    selected = windows.security_descriptor_parts(parent)
    components = binary.decode("01000480d8000000e400000000000000140000000200c40007000000000218001900020001020000000000052000000021020000000218003f000f0001020000000000052000000020020000000214003f000f00010100000000000512000000000014003f000f00010100000000000512000000000a14003f000f000101000000000003000000000002180019000200010200000000000f02000000010000000002380019000200010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce010100000000000512000000010100000000000512000000", "hex")
    if selected["control"] == 0x8004 and not selected["resource_manager_control"] and selected["sacl"] == None:
        for captured in [native, components]:
            if selected["dacl"] == windows.security_descriptor_parts(captured)["dacl"]:
                return captured
        # Independently measured PackagesToAdd parent: its inherited BA ACE
        # does not inherit; CREATOR_OWNER creates a SYSTEM ACE. The native
        # result is the same seven-ACE descriptor, not a copy of this parent.
        print_parent = binary.decode("01000480dc000000ec00000000000000140000000200c80007000000000218001900020001020000000000052000000021020000000218003f000f0001020000000000052000000020020000000214003f000f00010100000000000512000000000018003f000f0001020000000000052000000020020000000a14003f000f000101000000000003000000000002180019000200010200000000000f02000000010000000002380019000200010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce010200000000000520000000200200000105000000000005150000009a58dcef44cb6506d87e569e01020000", "hex")
        if selected["dacl"] == windows.security_descriptor_parts(print_parent)["dacl"]:
            return components
    # Actual null-creator High-integrity SYSTEM inheritance of WUDF Services:
    # fourteen ACEs survive byte-for-byte; native creation clears the parent's
    # NULL-SACL-present bit. The resulting descriptor is a native fixed point.
    wudf = binary.decode("0100048cbc010000c801000000000000140000000200a8010e000000001314003f000f0001010000000000051200000000131400190002000101000000000005130000000013140019000200010100000000000514000000001318003f000f0001020000000000052000000020020000001318001900020001020000000000052000000021020000001028003f000f00010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487001a280000000010010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487001a140000000010010100000000000512000000001a18000000001001020000000000052000000020020000001a180000000080010200000000000520000000210200000010180019000200010200000000000f0200000001000000001a180000000080010200000000000f02000000010000000010380019000200010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce001a380000000080010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce010100000000000512000000010100000000000512000000", "hex")
    if selected["control"] in [0x8c04,0x8c14] and not selected["resource_manager_control"] and selected["sacl"] == None and selected["dacl"] == windows.security_descriptor_parts(wudf)["dacl"]:
        return wudf
    # Original-kernel SeAssignSecurity on actual WINEVT/Publishers: the
    # eleven ACEs are a native fixed point; only NULL-SACL-present is cleared.
    winevt = binary.decode("0100048c58010000640100000000000014000000020044010b000000001018001900020001020000000000052000000021020000001a18000000008001020000000000052000000021020000001018003f000f0001020000000000052000000020020000001a18000000001001020000000000052000000020020000001014003f000f00010100000000000512000000001a140000000010010100000000000512000000001a1400000000100101000000000003000000000010180019000200010200000000000f0200000001000000001a180000000080010200000000000f02000000010000000010380019000200010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce001a380000000080010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce010100000000000512000000010100000000000512000000", "hex")
    if selected["control"] in [0x8c04, 0x8c14] and not selected["resource_manager_control"] and selected["sacl"] == None and selected["dacl"] == windows.security_descriptor_parts(winevt)["dacl"]:
        return winevt
    # Actual EventLog/System parent: measured eight-ACE fixed point.
    eventlog = binary.decode("0100048ccc000000d800000000000000140000000200b80008000000001014001900020001010000000000050b000000001a14000000008001010000000000050b000000001018001900020001020000000000052000000025020000001a18000000008001020000000000052000000025020000001018003f000f0001020000000000052000000020020000001a18000000001001020000000000052000000020020000001014003f000f00010100000000000512000000001a140000000010010100000000000512000000010100000000000512000000010100000000000512000000", "hex")
    if selected["control"] in [0x8c04, 0x8c14] and not selected["resource_manager_control"] and selected["sacl"] == None and selected["dacl"] == windows.security_descriptor_parts(eventlog)["dacl"]:
        return eventlog
    fail("unestablished native driver key creation parent policy")


def _validate_native_owner_creation(machine, request):
    # Actual CBS9703 first-owner request: backup/restore open and an explicit
    # O:SYG:SY descriptor with no ACLs. Kernel explicit-creator capture produces
    # the seven-ACE COMPONENTS descriptor; NULL-creator evidence is not enough.
    if request["api"] != "regcreatekeyexw" or request["options"] != 4 or request["access"] != 0x2001f or request["class_address"] or not request["creator_security"]:
        fail("unestablished native owner creation request")
    expected = windows.compile_sddl("O:SYG:SY")
    if machine.read(request["creator_security"],len(expected)) != expected:
        fail("unestablished native owner creator descriptor")
    output = machine.allocate(size=machine.pointer_size)
    opened = machine.invoke(machine.resolve_export("advapi32.dll",name="OpenThreadToken"),args=[0xfffffffffffffffe if machine.pointer_size==8 else 0xfffffffe,8,1,output])
    if opened.reason!="return" or not opened.value:
        machine.free(output)
        fail("native owner creation requires its actual owned thread token")
    token = machine.read_pointer(output)
    data = machine.allocate(size=256)
    needed = machine.allocate(size=4)
    queried = machine.invoke(machine.resolve_export("advapi32.dll",name="GetTokenInformation"),args=[token,3,data,256,needed])
    count = machine.read_u32le(data) if queried.reason=="return" and queried.value else 0
    valid = queried.reason=="return" and queried.value and count<=21 and machine.read_u32le(needed)==4+12*count
    privileges = {}
    if valid:
        for index in range(count):
            offset=data+4+12*index
            if machine.read_u32le(offset+4) or machine.read_u32le(offset) in privileges:
                valid=False
                break
            privileges[machine.read_u32le(offset)]=machine.read_u32le(offset+8)
    closed=machine.invoke(machine.resolve_export("kernel32.dll",name="CloseHandle"),args=[token])
    for address in [output,data,needed]: machine.free(address)
    if closed.reason!="return" or not closed.value or not valid:
        fail("native owner creation could not validate its actual token inventory")
    if privileges.get(17,0)&2==0 or privileges.get(18,0)&2==0:
        fail("native owner creation requires enabled owned backup/restore privileges")


def update_driver_key_creation_provider(registry_ref, subject_sid, primary_group_sid, integrity_rid):
    """Bind only the explicitly declared SYSTEM subject, not arbitrary tokens."""
    if subject_sid != "S-1-5-18" or primary_group_sid != "S-1-5-18" or integrity_rid not in [0x3000, 0x4000]:
        fail("native driver creation requires the established SYSTEM subject")
    def create(machine, request):
        property_creation = bool(request["creator_security"]) and request["api"] == "ntcreatekey" and request["options"] == 0 and request["access"] == 4 and not request["class_address"]
        creator = None
        if property_creation:
            if len(request["missing_keys"]) != 1:
                fail("unestablished native device-property intermediate creation")
            creator = machine.read(request["creator_security"], len(_DRIVER_PROPERTY_CREATOR))
        explicit_owner = not property_creation and bool(request["creator_security"] or request["options"])
        if explicit_owner:
            _validate_native_owner_creation(machine,request)
        elif request["api"] not in ["ntcreatekey", "regcreatekeyexw", "regcreatekeyexa", "regcreatekeyw", "regcreatekeya"] or request["class_address"]:
            fail("unestablished native driver key creation request")
        registry = registry_ref["registry"]
        result = {}
        for key in request["missing_keys"]:
            parent = key.rsplit("/", 1)[0] or "/"
            descriptor = result.get(parent)
            if descriptor == None:
                existing = registry.state["security"].get(request["hive"].upper() + chr(0) + parent.lower())
                if existing != None:
                    descriptor = existing["security"]
            if descriptor == None:
                source = registry.state["sources"].get(request["hive"].upper())
                node = source.find(_parts(parent)) if source != None else None
                descriptor = node.security if node != None else None
            if descriptor == None:
                fail("native driver key creation has no actual parent descriptor")
            result[key] = build_update_driver_property_key_security(descriptor, creator) if property_creation else build_update_driver_key_security(descriptor)
            if explicit_owner and len(result[key])!=240:
                fail("unestablished explicit-owner creation parent policy")
        return result
    return create
