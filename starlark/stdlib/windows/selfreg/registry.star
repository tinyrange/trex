"""Registry API plugin for deterministic Windows self-registration emulation."""

load(":common.star", "expand_environment")
load("@stdlib//windows/emulation:abi.star", "counted_string_layout", "object_attributes_layout")

_ROOTS = {
    0x80000000: ("SOFTWARE", "/Classes"),
    0x80000001: ("DEFAULT", "/"),
    0x80000002: ("SOFTWARE", "/"),
    0x80000003: ("DEFAULT", "/@users"),
}

def _predefined_handle(handle):
    # Win64's predefined HKEY constants sign-extend a signed 32-bit LONG.
    # Do not truncate arbitrary handles: only normalize documented roots.
    low = handle & 0xffffffff
    return low if handle >> 32 == 0xffffffff and low in _ROOTS else handle

def _write_handle(machine, address, value):
    machine.write_pointer(address, value)

_BASELINE_KEYS = [
    ("SOFTWARE", "/Classes/AppID"),
    ("SOFTWARE", "/Classes/CLSID"),
    ("SOFTWARE", "/Classes/Interface"),
    ("SOFTWARE", "/Classes/TypeLib"),
]

_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}

_TYPE_NUMBERS = {symbolic: numeric for numeric, symbolic in _TYPES.items()}

_CALLS = {
    "regopenkeyw": 3,
    "regopenkeya": 3,
    "regopenkeyexw": 5,
    "regopenkeyexa": 5,
    "regopencurrentuser": 2,
    "regcreatekeyw": 3,
    "regcreatekeya": 3,
    "regcreatekeyexw": 9,
    "regcreatekeyexa": 9,
    "regsetvaluew": 5,
    "regsetvaluea": 5,
    "regsetvalueexw": 6,
    "regsetvalueexa": 6,
    "regsetkeyvaluew": 6,
    "regsetkeyvaluea": 6,
    "regclosekey": 1,
    "regflushkey": 1,
    "regdeletekeyw": 2,
    "regdeletekeya": 2,
    "regdeletekeyexw": 4,
    "regdeletekeyexa": 4,
    "regdeletetreew": 2,
    "regdeletetreea": 2,
    "reggetvaluew": 7,
    "reggetvaluea": 7,
    "regdeletevaluew": 2,
    "regdeletevaluea": 2,
    "regenumkeya": 4,
    "regenumkeyw": 4,
    "regenumkeyexa": 8,
    "regenumkeyexw": 8,
    "regenumvaluea": 8,
    "regenumvaluew": 8,
    "regqueryvalueexa": 6,
    "regqueryvalueexw": 6,
    "regqueryvaluea": 4,
    "regqueryvaluew": 4,
    "regqueryinfokeya": 12,
    "regqueryinfokeyw": 12,
    "regnotifychangekeyvalue": 5,
    "regdisablepredefinedcache": 0,
    "regoverridepredefkey": 2,
}

_NATIVE_CALLS = {
    "ldrqueryimagefileexecutionoptions": 6,
    "ntenumeratekey": 6,
    "ntopenkey": 3,
    "ntopenkeyex": 4,
    "ntqueryvaluekey": 6,
    "ntquerykey": 5,
    "ntenumeratevaluekey": 6,
    "ntsetvaluekey": 6,
    "ntdeletevaluekey": 2,
    "ntdeletekey": 1,
    "ntflushkey": 1,
    "ntcreatekey": 7,
    # NT 3.x exports private wrappers with one trailing compatibility
    # argument.  Their object and result arguments match NtOpenKey.
    "rtlpntopenkey": 4,
    "rtlpntenumeratesubkey": 4,
    "rtlpntcreatekey": 6,
    "rtlpntqueryvaluekey": 5,
    "rtlqueryregistryvalues": 5,
    "rtlabortrxact": 1,
    "rtladdactiontorxact": 6,
    "rtladdattributeactiontorxact": 8,
    "rtlapplyrxact": 1,
    "rtlapplyrxactnoflush": 1,
    "rtlinitializerxact": 3,
    "rtlstartrxact": 1,
}

_SHLWAPI_REGISTRY_WRAPPERS = {
    119: ("regcreatekeyw", 3),
    120: ("regcreatekeyexw", 9),
    121: ("regdeletekeyw", 2),
    122: ("regenumkeyw", 4),
    123: ("regenumkeyexw", 8),
    124: ("regopenkeyw", 3),
    125: ("regopenkeyexw", 5),
    126: ("regqueryinfokeyw", 12),
    127: ("regqueryvaluew", 4),
    128: ("regqueryvalueexw", 6),
    129: ("regsetvaluew", 5),
    130: ("regsetvalueexw", 6),
    347: ("regdeletevaluew", 2),
}

_SHLWAPI_NAMED_REGISTRY_WRAPPERS = {
    "shregcloseuskey": ("shregcloseuskey", 1),
    "shregcreateuskeya": ("shregcreateuskeya", 5),
    "shregcreateuskeyw": ("shregcreateuskeyw", 5),
    "shreggetvaluea": ("shreggetvaluea", 7),
    "shreggetvaluew": ("shreggetvaluew", 7),
    "shreggetusvaluea": ("shreggetusvaluea", 8),
    "shreggetusvaluew": ("shreggetusvaluew", 8),
    "shregopenuskeya": ("shregopenuskeya", 5),
    "shregopenuskeyw": ("shregopenuskeyw", 5),
    "shregqueryusvaluea": ("shregqueryusvaluea", 8),
    "shregqueryusvaluew": ("shregqueryusvaluew", 8),
    "shqueryvalueexa": ("regqueryvalueexa", 6),
    "shqueryvalueexw": ("regqueryvalueexw", 6),
    "shgetvaluea": ("shgetvaluea", 6),
    "shgetvaluew": ("shgetvaluew", 6),
    "shdeletekeya": ("shdeletekeya", 2),
    "shdeletekeyw": ("shdeletekeyw", 2),
    "shdeleteorphankeya": ("shdeleteorphankeya", 2),
    "shdeleteorphankeyw": ("shdeleteorphankeyw", 2),
    "shdeletevaluea": ("shdeletevaluea", 3),
    "shdeletevaluew": ("shdeletevaluew", 3),
    "shregsetpatha": ("shregsetpatha", 5),
    "shregsetpathw": ("shregsetpathw", 5),
    "shsetvaluea": ("shsetvaluea", 6),
    "shsetvaluew": ("shsetvaluew", 6),
}

def _registry_provider_module(name):
    """Reports whether a module imports the Win32 registry contract."""
    normalized = name.replace("/", "\\").split("\\")[-1].lower()
    return normalized in ["advapi32.dll", "advapi32_vista.dll", "kernel32.dll", "kernelbase.dll"] or normalized.startswith("api-ms-win-core-registry-") or normalized.startswith("ext-ms-win-advapi32-registry-")

def _join(parent, child):
    parent = parent.replace("\\", "/").rstrip("/")
    child = child.replace("\\", "/").strip("/")
    if not child:
        return parent if parent else "/"
    return (parent + "/" + child) if parent else "/" + child

def _encode_key_part(part):
    return part.replace("%", "%25").replace("/", "%2f")

def _decode_key_part(part):
    return part.replace("%2f", "/").replace("%2F", "/").replace("%25", "%")

def _key_from_parts(parts):
    return "/" + "/".join([_encode_key_part(str(part)) for part in parts]) if parts else "/"

def _display_key(key):
    return "/" + "/".join([_decode_key_part(part) for part in key.strip("/").split("/")]) if key != "/" else "/"

def _initial_key(item):
    parts = item.get("key_parts")
    return _key_from_parts(parts) if parts != None else item["key"]

def _join_key(parent, child):
    hive, key = parent
    parts = [part for part in child.strip("\\").split("\\") if part]
    normalized = "/".join([_encode_key_part(part) for part in parts])
    if hive == "SOFTWARE" and key == "/":
        first = _decode_key_part(parts[0]).lower() if parts else ""
        if first == "software":
            normalized = "/".join([_encode_key_part(part) for part in parts[1:]])
        elif first == "system" and len(parts) == 1:
            return "SYSTEM", "/"
        elif first == "system":
            system_parts = parts[1:]
            if system_parts and system_parts[0].lower() == "currentcontrolset":
                system_parts[0] = "ControlSet001"
            normalized = "/".join([_encode_key_part(part) for part in system_parts])
            return "SYSTEM", "/" + normalized
    return hive, _join(key, normalized)

def _cstring(machine, address, wide):
    if not address:
        return ""
    return machine.read_cstring(address, encoding = "utf16le" if wide else "ascii")

def _unicode_string(machine, address):
    if not address:
        return ""
    layout = counted_string_layout(machine.pointer_size)
    length = machine.read_u16le(address + layout["Length"])
    data = machine.read_pointer(address + layout["Buffer"])
    if not data or not length:
        return ""
    return binary.text(machine.read(data, length), encoding = "utf16le")

def _native_absolute_key(path):
    # NT registry names use backslashes only. A forward slash is a valid
    # literal key-name character (including base64 driver hashes and mounts).
    normalized = path.strip("\\")
    folded = normalized.lower()
    machine_prefix = "registry\\machine"
    if folded == machine_prefix:
        return "SOFTWARE", "/"
    if folded.startswith(machine_prefix + "\\"):
        relative = normalized[len(machine_prefix) + 1:]
        parts = relative.split("\\")
        hive = parts[0].upper()
        if hive in ["SYSTEM", "SOFTWARE", "SAM", "SECURITY"]:
            return hive, _key_from_parts(parts[1:])
        # Other HKLM children, including explicitly loaded offline hives,
        # share the same modeled namespace as relative predefined-HKLM opens.
        return "SOFTWARE", _key_from_parts(parts)
    user_prefix = "registry\\user"
    if folded == user_prefix:
        return "DEFAULT", "/@users"
    if folded.startswith(user_prefix + "\\"):
        relative = normalized[len(user_prefix) + 1:]
        return "DEFAULT", _key_from_parts(["@users"] + relative.split("\\"))
    return None

def _decode_value(raw, registry_type, wide):
    if registry_type in [1, 2]:
        return binary.text(raw, encoding = "utf16le" if wide else "ascii", nul = True)
    if registry_type == 4:
        return binary.read_u32le(raw) if len(raw) >= 4 else 0
    if registry_type == 7:
        values = binary.text(raw, encoding = "utf16le" if wide else "ascii").split("\x00")
        while values and values[-1] == "":
            values.pop()
        return values
    if registry_type == 11:
        return binary.read_u64le(raw) if len(raw) >= 8 else 0
    return raw

def _value_name(name):
    return "(default)" if name == None or name == "" else name

def _identity(hive, key, name):
    return hive.upper() + "\x00" + key.replace("\\", "/").lower() + "\x00" + _value_name(name).lower()

def _key_identity(hive, key):
    normalized = "/" + key.replace("\\", "/").strip("/").lower()
    return hive.upper() + "\x00" + normalized

def _source_node(state, target):
    hive,key=target
    identity=_key_identity(hive,key)
    for mount in state.get("mounts",[]):
        prefix=_key_identity(mount["hive"],mount["key"])
        if identity==prefix or identity.startswith(prefix+"/"):
            parts=key.strip("/").split("/")[len(mount["key"].strip("/").split("/")):]
            return mount["source"].find([_decode_key_part(part) for part in parts])
    source=state.get("sources",{}).get(hive.upper())
    return source.find([_decode_key_part(part) for part in key.strip("/").split("/") if part]) if source!=None else None

def _source_entry(state, target):
    hive, key = target
    identity = _key_identity(hive, key)
    cache = state.get("source_cache")
    if cache == None:
        cache = {}
        state["source_cache"] = cache
    cached = cache.get(identity)
    if cached != None:
        return cached if cached["found"] else None
    node = _source_node(state,target)
    if node == None:
        cache[identity] = {"found": False}
        return None
    state["source_cache_serial"] = state.get("source_cache_serial", 0) + 1
    entry = {
        "found": True,
        "cache_id": state["source_cache_serial"],
        "subkeys": [child.name for child in node.children],
        "values": {
            name.lower(): {"name": name, "type": record.type, "raw": record.raw}
            for name, record in node.value_records.items()
        },
    }
    cache[identity] = entry
    return entry

def _key_metadata(state, target):
    # Metadata belongs to the source object, not a deleted/recreated pathname.
    if _key_deleted(state, _key_identity(target[0], target[1])):
        return {"class": b"", "last_write_time": 0}
    node = _source_node(state,target)
    return {"class": node.class_bytes, "last_write_time": node.last_write_time} if node != None else {"class": b"", "last_write_time": 0}

def _key_deleted(state, identity):
    # _delete_tree stores canonical identities without a trailing separator.
    # Check the key and its component ancestors, not every deleted sibling.
    # Literal slashes in key names are percent-encoded before this boundary.
    deleted = state.get("deleted_keys", {})
    for _ in range(identity.count("/") + 1):
        if identity in deleted:
            return True
        separator = identity.rfind("/")
        if separator < 0:
            return False
        identity = identity[:separator]
    return False

def _key_exists(state, target):
    identity = _key_identity(target[0], target[1])
    if identity in state["keys"]:
        return True
    if _key_deleted(state, identity):
        return False
    return _source_entry(state, target) != None

def _lookup_value(state, target, name):
    name = _value_name(name)
    identity = _identity(target[0], target[1], name)
    current = state["values"].get(identity)
    if current != None:
        return current
    if identity in state.get("deleted_values", {}) or _key_deleted(state, _key_identity(target[0], target[1])):
        return None
    source = _source_entry(state, target)
    item = source["values"].get(name.lower()) if source != None else None
    return {"type": item["type"], "raw": item["raw"]} if item != None else None

def _invalidate_key_names(state):
    state["key_names_revision"] = state.get("key_names_revision", 0) + 1

def _direct_subkeys(state, target):
    hive, key = target
    source = _source_entry(state, target)
    identity = _key_identity(hive, key)
    revision = state.get("key_names_revision", 0)
    source_id = source.get("cache_id") if source != None else 0
    cache = state.setdefault("subkeys_cache", {})
    cached = cache.get(identity)
    if source_id != None and cached != None and cached["revision"] == revision and cached["source_id"] == source_id:
        return list(cached["names"])
    output = {}
    if source != None:
        for name in source["subkeys"]:
            child = _key_identity(hive, _join(key, _encode_key_part(name)))
            if not _key_deleted(state, child):
                output[name.lower()] = name
    output.update(windows.registry_children(state["keys"], hive, key))
    for mount in state.get("mounts",[]):
        parent=mount["key"].rsplit("/",1)[0] or "/"
        if _key_identity(mount["hive"],parent)==identity:
            name=_decode_key_part(mount["key"].rsplit("/",1)[1])
            output[name.lower()]=name
    names = [output[name] for name in sorted(output.keys())]
    if source_id != None:
        # Source records are immutable for one lazy-source cache incarnation.
        # Key creation/deletion invalidates names; source-cache clear/reload
        # supplies a new serial even when the namespace revision is unchanged.
        if len(cache) >= 256:
            cache.clear()
        cache[identity] = dict(revision=revision, source_id=source_id, names=tuple(names))
    return names

def _direct_values(state, target):
    hive, key = target
    output = {}
    source = _source_entry(state, target)
    if source != None:
        for name, value in source["values"].items():
            identity = _identity(hive, key, name)
            if identity not in state.get("deleted_values", {}):
                output[name] = {"name": "" if name == "(default)" else value["name"], "value": {"type": value["type"], "raw": value["raw"]}}
    for name, value in windows.registry_children(state["values"], hive, key, values = True).items():
        output[name] = {"name": "" if name == "(default)" else name, "value": value}
    return sorted(output.values(), key = lambda item: item["name"].lower())

def _key_information(state, target):
    """Returns direct child and value cardinalities for RegQueryInfoKey."""
    subkeys = _direct_subkeys(state, target)
    values = _direct_values(state, target)
    return {
        "subkeys": len(subkeys),
        "max_subkey_length": max([len(name) for name in subkeys] or [0]),
        "values": len(values),
        "max_value_name_length": max([len(item["name"]) for item in values] or [0]),
        "max_value_length": max([len(item["value"]["raw"]) for item in values] or [0]),
    }

def _encoded_value(registry_type, value):
    if registry_type in ["REG_SZ", "REG_EXPAND_SZ"]:
        return binary.encode(value, encoding = "utf16le", nul = True)
    if registry_type == "REG_DWORD":
        return binary.u32le(value)
    if registry_type == "REG_MULTI_SZ":
        return binary.encode("\x00".join(value) + "\x00\x00", encoding = "utf16le")
    if registry_type == "REG_QWORD":
        return binary.u64le(value)
    return value

def _api_value_raw(value, wide):
    """Encodes canonical registry data for one A/W query API."""
    if wide or value["type"] not in [1, 2, 7]:
        return value["raw"]
    decoded = _decode_value(value["raw"], value["type"], True)
    if value["type"] == 7:
        return binary.encode("\x00".join(decoded) + "\x00\x00", encoding = "ascii")
    return binary.encode(decoded, encoding = "ascii", nul = True)

def _check_delete_mount(state, target):
    base = _key_identity(target[0], target[1]).rstrip("/")
    for mount in state.get("mounts", []):
        mounted = _key_identity(mount["hive"], mount["key"])
        if mounted == base or mounted.startswith(base + "/"):
            fail("registry deletion crosses a static hive mount")

def _delete_tree(state, target):
    """Deletes a known registry key tree and records its removed values."""
    hive, key = target
    base = _key_identity(hive, key).rstrip("/")
    _check_delete_mount(state, target)
    deleted = _key_exists(state, target)
    removed, retained = windows.registry_partition(state["values"], hive, key, values = True)
    for identity, value in removed.items():
        deleted = True
        separator = identity.rfind("\x00")
        value_key = identity[len(hive) + 1:separator]
        value_name = identity[separator + 1:]
        state["patches"].append({
            "hive": hive,
            "key": value_key,
            "name": value_name,
            "type": _TYPES.get(value["type"], value["type"]),
            "value": _decode_value(value["raw"], value["type"], True),
            "delete": True,
        })
    state["values"] = retained
    _, state["keys"] = windows.registry_partition(state["keys"], hive, key)
    _invalidate_key_names(state)
    state.setdefault("deleted_keys", {})[base] = True
    if deleted:
        # Retain successful deletion history even when ensure_key later
        # recreates the name and removes the live tombstone. Value patches
        # alone cannot describe deletion of an empty source key.
        state.setdefault("key_deletions", []).append({"hive": hive, "key": key})
    if "created_keys" in state:
        _, state["created_keys"] = windows.registry_partition(state["created_keys"], hive, key)
    if "security" in state:
        _, state["security"] = windows.registry_partition(state["security"], hive, key)
    return 0 if deleted else 2

def _delete_value(state, target, name):
    """Deletes a known registry value and records the removal."""
    name = _value_name(name)
    hive, key = target
    identity = _identity(hive, key, name)
    value = _lookup_value(state, target, name)
    if value == None:
        return 2
    state["values"].pop(identity, None)
    state.setdefault("deleted_values", {})[identity] = True
    state["patches"].append({
        "hive": hive,
        "key": key,
        "name": name,
        "type": _TYPES.get(value["type"], value["type"]),
        "value": _decode_value(value["raw"], value["type"], True),
        "delete": True,
    })
    return 0

def _registry_store_native_value(state, target, value_name, registry_type, raw, output_key):
    """Preserve unknown ULONG registry types and their uninterpreted data bytes."""
    type_name = _TYPES.get(registry_type)
    value = _decode_value(raw, registry_type, True)
    if type_name != None and _encoded_value(type_name, value) != raw:
        fail("NtSetValueKey: noncanonical raw value requires raw registry patches")
    identity = _identity(target[0], target[1], value_name)
    state["deleted_values"].pop(identity, None)
    state["values"][identity] = dict(type=registry_type, raw=raw)
    state["patches"].append(dict(hive=target[0],key=output_key(target[1]),name=value_name,type=type_name if type_name != None else registry_type,value=value))

def _registry_create_keys_with_security(state, hive, key, missing, descriptors, output_key):
    """Materialize a native provider result only after complete SD validation."""
    if type(descriptors) != "dict" or sorted(descriptors.keys()) != sorted(missing):
        fail("registry creation provider must cover exactly the missing keys")
    for descriptor in descriptors.values():
        if type(descriptor) != "bytes":
            fail("registry creation provider must return descriptor bytes")
        windows.security_descriptor_parts(descriptor)
    _invalidate_key_names(state)
    prefix = hive.upper() + "\x00"
    paths = ["/"]
    current = ""
    for part in key.strip("/").split("/") if key != "/" else []:
        current += "/" + part
        paths.append(current)
    for path in paths:
        identity = prefix + path.lower()
        state["keys"][identity] = True
        state["deleted_keys"].pop(identity, None)
    for path in missing:
        identity = _key_identity(hive, path)
        item = dict(hive=hive,key=output_key(path))
        state["created_keys"][identity] = item
        state["security"][identity] = dict(item,security=descriptors[path])

# Registry forks retain immutable source hives but own every mutable overlay.
def _clone_registry_overlay(value):
    if type(value) == "dict": return {key:_clone_registry_overlay(item) for key,item in value.items()}
    if type(value) == "list": return [_clone_registry_overlay(item) for item in value]
    if type(value) == "tuple": return tuple([_clone_registry_overlay(item) for item in value])
    return value

_TRANSACTION_FIELDS = ["keys", "created_keys", "values", "deleted_keys", "deleted_values", "security", "patches", "key_deletions"]

def registry_plugin(values = [], keys = [], hives = {}, user_sid = "", output_key_case = "preserve", prepared_state = None, environment = {}, on_create_key = None, effective_token_privileges = None, mounts = [], on_open_key = None):
    """Returns a registry plugin initialized from hive-style dictionaries.

    Initial values are queryable but are not reported as writes. Each value uses
    the same `hive`, `key`, `name`, `type`, and `value` fields as a hive patch.
    Initial keys use `hive` and `key`; they make empty setup-created namespaces
    observable without being reported as writes. `hives` may map hive names to
    parsed `windows.hive` objects; these are consulted lazily and overridden by
    explicit keys, values, and subsequent writes. Static `mounts` entries
    contain hive, key (encoded non-root namespace path), and parsed source hive.
    Mounts are nonoverlapping immutable inputs, not RegLoadKey/NtLoadKey emulation.
    Their metadata and values remain source-backed; effects retain mounted
    namespace paths for caller-directed publication. Removing a mount or an
    ancestor is unsupported, rather than deleting across hive boundaries.
    RegDeleteKey(A/W/Ex) deletes only leaves, including lazy source values;
    open references remain owned and cannot alias a recreated name. Ex accepts
    default/native views only. Alternate views, empty-name self-deletion and
    complete NT ACL authorization are not modeled. key_deletions() reports
    successful key removals, including empty source keys and names later
    recreated; callers must reconcile those events with final keys/values.
    effects() captures surviving owned value bytes, final key metadata and
    removals before hive teardown; unlike patches(), it cannot resurrect a
    write made to an earlier deleted key object. Neither report supplies
    missing key-creation security or implies a committed hive image.
    on_create_key(machine, request) may supply exact final descriptors for
    every missing key in one native create request. It runs before mutation
    and must return an encoded-key-to-bytes dictionary covering missing_keys.
    Request metadata includes API, creator descriptor address, class/options
    and access. parent_key and parent_security identify the nearest existing
    ancestor in this exact view, including transacted security; an unknown
    descriptor stays None. Caller-specific inheritance/identity policy stays outside this
    registry namespace model. Without a provider, creation security is unknown.
    on_open_key(machine, request) optionally resolves existing-key opens against
    the exact overlay/source descriptor. Return concrete granted rights or None
    for access denied. Unknown descriptors remain None, never a null DACL.
    This callback does not establish new-key authorization or inheritance.
    effective_token_privileges() supplies a fresh LUID-to-attributes mapping for
    backup/restore opens of existing keys. No provider fails closed; no enabled
    backup/restore privilege returns access denied. New backup/restore keys
    remain unsupported rather than inventing privileged creation security.
    """
    if output_key_case not in ["preserve", "folded"]:
        fail("registry output_key_case must be preserve or folded")
    state = {
        "handles": dict(_ROOTS),
        "handle_access": {},
        "deleted_handles": {},
        "overrides": {},
        "next_handle": 0x10000,
        "patches": [],
        "keys": dict(prepared_state.get("keys", {})) if prepared_state != None else {},
        "created_keys": {},
        "values": dict(prepared_state.get("values", {})) if prepared_state != None else {},
        "sources": {name.upper(): source for name, source in hives.items()},
        "mounts": [],
        "source_cache": {},
        "deleted_keys": {},
        "key_deletions": [],
        "deleted_values": {},
        "queries": [],
        "opens": [],
        "flushes": [],
        "notifications": [],
        "security": {},
        "transactions": {},
        "transaction_actions": [],
        "us_handles": {},
    }

    if len(mounts)>128: fail("registry static mount bound")
    for item in mounts:
        if sorted(item)!=["hive","key","source"]: fail("registry mount requires hive, key and source")
        hive=item["hive"].upper()
        key=item["key"]
        if not hive or chr(0) in hive or not key.startswith("/") or key=="/" or any([part in ["",".",".."] for part in key[1:].split("/")]) or chr(92) in key or chr(0) in key:
            fail("registry mount requires a canonical non-root key")
        identity=_key_identity(hive,key)
        for existing in state["mounts"]:
            other=_key_identity(existing["hive"],existing["key"])
            if identity==other or identity.startswith(other+"/") or other.startswith(identity+"/"):
                fail("overlapping registry static mounts")
        if item["source"].find([])==None: fail("registry mount has no source root")
        state["mounts"].append(dict(hive=hive,key=key,source=item["source"]))

    def backup_restore_access():
        if effective_token_privileges == None:
            fail("registry backup/restore requires explicit effective token privileges")
        privileges = effective_token_privileges()
        access = 0
        # REG_OPTION_BACKUP_RESTORE ignores DesiredAccess. Only enabled
        # privileges contribute, and the effective token is queried per call.
        if privileges.get(17, 0) & 2: access |= 0x1020019  # SeBackupPrivilege
        if privileges.get(18, 0) & 2: access |= 0x1030006  # SeRestorePrivilege
        return access

    def output_key(key):
        normalized = "/" + key.replace("\\", "/").strip("/")
        return normalized.lower() if output_key_case == "folded" else normalized

    def ensure_key(hive, key):
        normalized = "/" + key.replace("\\", "/").strip("/")
        hive_prefix = hive.upper() + "\x00"
        identity = hive_prefix + normalized.lower()
        # A present leaf proves that its complete parent chain is live.
        if identity in state["keys"] and identity not in state["deleted_keys"]:
            return
        _invalidate_key_names(state)
        root_identity = hive_prefix + "/"
        state["keys"][root_identity] = True
        state["deleted_keys"].pop(root_identity, None)
        current = ""
        for part in normalized.strip("/").lower().split("/") if normalized != "/" else []:
            current += "/" + part
            current_identity = hive_prefix + current
            state["keys"][current_identity] = True
            state["deleted_keys"].pop(current_identity, None)

    def record_created_key(hive, key):
        normalized = "/" + key.replace("\\", "/").strip("/")
        state["created_keys"][_key_identity(hive, normalized)] = {
            "hive": hive,
            "key": output_key(normalized),
        }

    def create_new_key(event, hive, key, request):
        if on_create_key == None:
            ensure_key(hive, key)
            record_created_key(hive, key)
            return
        missing = []
        parts = key.strip("/").split("/") if key != "/" else []
        for count in range(1, len(parts) + 1):
            path = "/" + "/".join(parts[:count])
            if not _key_exists(state, (hive, path)):
                missing.append(path)
        request = dict(request)
        parent = missing[0].rsplit("/",1)[0] or "/" if missing else key
        identity = _key_identity(hive,parent)
        supplied = state["security"].get(identity)
        parent_security = supplied["security"] if supplied!=None else None
        if parent_security==None and identity not in state["created_keys"] and not _key_deleted(state,identity):
            node=_source_node(state,(hive,parent))
            parent_security=node.security if node!=None else None
        request.update(hive=hive, key=key, missing_keys=missing, parent_key=parent, parent_security=parent_security)
        descriptors = on_create_key(event.machine, request)
        _registry_create_keys_with_security(state,hive,key,missing,descriptors,output_key)

    def store_value(hive, key, name, registry_type, value, record):
        name = _value_name(name)
        numeric_type = _TYPE_NUMBERS.get(registry_type)
        if numeric_type == None:
            fail("unsupported registry type " + str(registry_type))
        ensure_key(hive, key)
        identity = _identity(hive, key, name)
        state["deleted_values"].pop(identity, None)
        state["values"][identity] = {
            "type": numeric_type,
            "raw": _encoded_value(registry_type, value),
        }
        if record:
            state["patches"].append({
                "hive": hive,
                "key": output_key(key),
                "name": name,
                "type": registry_type,
                "value": value,
            })

    def load_values(initial):
        for value in initial:
            key = _initial_key(value)
            name = _value_name(value["name"])
            registry_type = _TYPES.get(value["type"], value["type"])
            if value.get("delete", False):
                identity = _identity(value["hive"], key, name)
                state["values"].pop(identity, None)
                state["deleted_values"][identity] = True
                continue
            append_value = value.get("append", False)
            if_absent = value.get("if_absent", False)
            overwrite_only = value.get("overwrite_only", False)
            # Ordinary assignments do not depend on the old value. Avoid
            # normalizing and looking it up before store_value does its work.
            current = _lookup_value(state, (value["hive"], key), name) if append_value or if_absent or overwrite_only else None
            if append_value and current != None:
                if current["type"] != 7 or registry_type != "REG_MULTI_SZ":
                    fail("registry append requires REG_MULTI_SZ values")
                merged = _decode_value(current["raw"], current["type"], True)
                folded = {item.lower(): True for item in merged}
                for item in value["value"]:
                    if item.lower() not in folded:
                        folded[item.lower()] = True
                        merged.append(item)
                store_value(value["hive"], key, name, registry_type, merged, False)
                continue
            if if_absent and current != None:
                continue
            if overwrite_only and current == None:
                continue
            store_value(
                value["hive"],
                key,
                name,
                registry_type,
                value["value"],
                False,
            )

    def load_keys(initial):
        for item in initial:
            ensure_key(item["hive"], _initial_key(item))

    for root in _ROOTS.values():
        ensure_key(root[0], root[1])
    for hive in ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"]:
        ensure_key(hive, "/")
    # These empty HKCR namespaces are part of a normal COM-capable Windows
    # installation. Keep them in baseline state so opening a standard parent
    # does not manufacture an output patch.
    for hive, key in _BASELINE_KEYS:
        ensure_key(hive, key)
    for mount in state["mounts"]: ensure_key(mount["hive"],mount["key"])
    load_keys(keys)
    load_values(values)

    def open_access(event, target, access):
        if on_open_key == None or access == None:
            return access
        identity = _key_identity(target[0], target[1])
        supplied = state["security"].get(identity)
        security = supplied["security"] if supplied != None else None
        if security == None and identity not in state["created_keys"] and not _key_deleted(state, identity):
            node = _source_node(state, target)
            security = node.security if node != None else None
        granted = on_open_key(event.machine, dict(hive=target[0], key=target[1], security=security, access=access & 0xfffffcff))
        if granted != None and (type(granted) != "int" or granted < 0 or granted & ~0x10f003f):
            fail("registry open provider returned non-concrete access")
        return granted

    def allocate_handle(hive, key, access = None):
        handle = state["next_handle"]
        state["next_handle"] = handle + 1
        state["handles"][handle] = (hive, key)
        # KEY_WOW64_32KEY/64KEY select a registry view at open time; they
        # are not granted object rights and must not survive duplication.
        state["handle_access"][handle] = access & 0xfffffcff if access != None else None
        return handle

    def duplicate_handle(handle, desired_access, inherit, options):
        # Predefined HKEY constants are not kernel handles. A duplicated key
        # retains the same object, granted access, and deletion tombstone.
        if _predefined_handle(handle) in _ROOTS: return (6, 0)
        if handle not in state["handles"]: return None
        target=state["handles"][handle]
        if target==None: return (6, 0)
        if inherit or options not in [0, 1, 2, 3]:
            fail("registry handle duplication requires supported non-inheritable options")
        access=state["handle_access"].get(handle)
        if not options&2:
            # Only an explicit subset of already granted concrete rights is
            # established here. Elevation requires a real access check;
            # generic/MAXIMUM_ALLOWED and unknown source grants fail closed.
            if access==None or access&~0x10f003f or desired_access&~0x10f003f or desired_access&~access:
                fail("registry handle duplication access expansion or unresolved grant is not modeled")
            access=desired_access
        duplicate=allocate_handle(target[0],target[1],access)
        if handle in state["deleted_handles"]: state["deleted_handles"][duplicate]=True
        if options&1: close_handle(handle)
        return (0, duplicate)

    def close_handle(handle):
        if handle in _ROOTS or handle not in state["handles"]: return None
        if state["handles"][handle]==None: return False
        state["handles"][handle]=None
        state["handle_access"].pop(handle,None)
        state["deleted_handles"].pop(handle,None)
        return True

    def allocate_us_handle(targets):
        handle = state["next_handle"]
        state["next_handle"] = handle + 1
        state["us_handles"][handle] = targets
        return handle

    def key_for(handle):
        handle = _predefined_handle(handle)
        if handle in state["deleted_handles"]:
            return None
        if handle in _ROOTS and handle in state["overrides"]:
            return state["overrides"][handle]
        return state["handles"].get(handle)

    def us_targets(handle, ignore_user = False):
        targets = state["us_handles"].get(handle, [])
        if ignore_user:
            return [target for target in targets if target[0] != "DEFAULT"]
        return targets

    def join_key(parent, child):
        hive, key = _join_key(parent, child)
        if hive != "DEFAULT" or not key.lower().startswith("/@users/"):
            return hive, key
        # Explicit source mounts take precedence over the legacy HKCU alias,
        # including when the caller omitted user_sid. Relative opens must stay
        # in the same mounted hive as the parent handle.
        identity = _key_identity(hive, key)
        for mount in state["mounts"]:
            prefix = _key_identity(mount["hive"], mount["key"])
            if identity == prefix or identity.startswith(prefix + "/"):
                return hive, key
        relative = key[len("/@users/"):]
        parts = relative.split("/")
        if not parts:
            return hive, "/"
        account = parts[0]
        if user_sid and account.lower() != user_sid.lower() and account.lower() != ".default":
            return hive, key
        return hive, "/" + "/".join(parts[1:])

    def native_object_key(machine, object_attributes):
        if not object_attributes:
            return None
        layout = object_attributes_layout(machine.pointer_size)
        if machine.read_u32le(object_attributes + layout["Length"]) < layout["Size"]:
            return None
        root = machine.read_pointer(object_attributes + layout["RootDirectory"])
        name = _unicode_string(machine, machine.read_pointer(object_attributes + layout["ObjectName"]))
        if root:
            parent = key_for(root)
            return join_key(parent, name) if parent != None else None
        return _native_absolute_key(name)

    def relative_registry_key(relative_to, path):
        mode = relative_to & 0xff
        if mode == 0:
            return _native_absolute_key(path)
        roots = {
            1: ("SYSTEM", "/ControlSet001/Services"),
            2: ("SYSTEM", "/ControlSet001/Control"),
            3: ("SOFTWARE", "/Microsoft/Windows NT/CurrentVersion"),
            4: ("SYSTEM", "/ControlSet001/Hardware Profiles/Current"),
            5: ("DEFAULT", "/"),
        }
        root = roots.get(mode)
        return join_key(root, path) if root != None else None

    def delete_leaf(target):
        if not _key_exists(state, target):
            return 2  # ERROR_FILE_NOT_FOUND
        if target[1] == "/" or _direct_subkeys(state, target):
            return 5  # ERROR_ACCESS_DENIED: never recurse
        identity = _key_identity(target[0], target[1])
        _check_delete_mount(state, target)
        # Include lazy source values, not only writes made in this run.
        for item in _direct_values(state, target):
            _delete_value(state, target, item["name"])
        _delete_tree(state, target)
        # Never resurrect baseline values when this name is recreated.
        state["source_cache"][identity] = {"found": False}
        for other, key in state["handles"].items():
            if other not in _ROOTS and key != None and _key_identity(key[0], key[1]) == identity:
                state["deleted_handles"][other] = True
        return 0

    def query(machine, target, value_name, type_address, data_address, size_address, wide):
        if target == None:
            return 6
        identity = _identity(target[0], target[1], value_name)
        value = _lookup_value(state, target, value_name)
        if len(state["queries"]) < 4096:
            state["queries"].append({"hive": target[0], "key": target[1], "name": value_name, "found": value != None})
        if value == None:
            return 2
        if type_address:
            machine.write(type_address, binary.u32le(value["type"]))
        raw = _api_value_raw(value, wide)
        required = len(raw)
        capacity = binary.read_u32le(machine.read(size_address, 4)) if size_address else 0
        if size_address:
            machine.write(size_address, binary.u32le(required))
        if not data_address:
            return 0
        if capacity < required:
            return 234  # ERROR_MORE_DATA
        machine.write(data_address, raw)
        return 0

    def query_us(machine, targets, value_name, type_address, data_address, size_address, wide, default_address = 0, default_size = 0):
        for target in targets:
            result = query(machine, target, value_name, type_address, data_address, size_address, wide)
            if result != 2:  # ERROR_FILE_NOT_FOUND
                return result
        if not default_address or not default_size:
            return 2
        capacity = binary.read_u32le(machine.read(size_address, 4)) if size_address else 0
        if size_address:
            machine.write(size_address, binary.u32le(default_size))
        if not data_address:
            return 0
        if capacity < default_size:
            return 234  # ERROR_MORE_DATA
        machine.write(data_address, machine.read(default_address, default_size))
        return 0

    def callback(event, function = ""):
        name = function or event.name.lower()
        router = state.get("native_transaction_router")
        if router != None:
            result = router(event, name)
            if result != None: return result
        args = event.args
        wide = name.endswith("w")
        # A deleted key object stays owned until close. Its old handles must
        # never resolve a new key later created at the same path. Keep the
        # handle-to-path entry for reference accounting, but reject operations
        # on that object before reading or writing any caller buffers.
        native_open = name in ["ntopenkey", "ntopenkeyex", "rtlpntopenkey", "ntcreatekey", "rtlpntcreatekey"]
        if native_open and args[2]:
            layout = object_attributes_layout(event.machine.pointer_size)
            if event.machine.read_u32le(args[2]) >= layout["Size"]:
                root = event.machine.read_pointer(args[2] + layout["RootDirectory"])
                if root in state["deleted_handles"]:
                    return 0xc000017c  # STATUS_KEY_DELETED
        native_handle = name in ["ntenumeratekey", "ntquerykey", "ntqueryvaluekey", "ntenumeratevaluekey", "ntsetvaluekey", "ntdeletevaluekey", "ntflushkey", "rtlpntenumeratesubkey", "rtlpntqueryvaluekey"]
        if native_handle and args[0] in state["deleted_handles"]:
            return 0xc000017c
        native_access = {"ntquerykey": 1, "ntqueryvaluekey": 1, "ntenumeratevaluekey": 1, "ntsetvaluekey": 2, "ntdeletevaluekey": 2, "ntenumeratekey": 8}.get(name)
        if native_access != None and args[0] in state["handle_access"]:
            granted = state["handle_access"][args[0]]
            if granted & 0xf2000000: fail("native registry operation has unresolved handle access")
            if not granted & native_access: return 0xc0000022
        win32_handle = name.startswith("reg") and name not in ["regclosekey", "regopencurrentuser", "regdisablepredefinedcache"]
        if win32_handle and args and _predefined_handle(args[0]) in state["deleted_handles"]:
            return 1018  # ERROR_KEY_DELETED
        if name == "ldrqueryimagefileexecutionoptions":
            if not args[0] or not args[1]: return 0xc000000d
            image=_unicode_string(event.machine,args[0]).replace(chr(92),"/").split("/")[-1]
            if not image or image in [".",".."]: return 0xc000000d
            value_name=_cstring(event.machine,args[1],True)
            key="/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/"+image
            current=_lookup_value(state,("SOFTWARE",key),value_name)
            if len(state["queries"])<4096:
                state["queries"].append(dict(api=name,hive="SOFTWARE",key=key,name=value_name,found=current!=None))
            if current==None: return 0xc0000034  # STATUS_OBJECT_NAME_NOT_FOUND
            if args[2]&0xffffffff!=4 or current["type"]!=4 or len(current["raw"])!=4 or not args[3] or args[4]&0xffffffff<4:
                fail("IFEO query currently requires a matching DWORD and four-byte output")
            event.machine.write(args[3],current["raw"])
            if args[5]: event.machine.write_u32le(args[5],4)
            return 0
        if name == "ntdeletekey":
            handle = args[0]
            if handle in _ROOTS or state["handles"].get(handle) == None:
                return 0xc0000008  # STATUS_INVALID_HANDLE
            access = state["handle_access"].get(handle)
            if access == None or access & 0xf2000000:
                fail("NtDeleteKey: unresolved handle access mask")
            if not access & 0x10000:  # DELETE
                return 0xc0000022  # STATUS_ACCESS_DENIED
            if handle in state["deleted_handles"]:
                return 0  # Deleting the same deleted object is idempotent.
            target = state["handles"][handle]
            if target[1] == "/" or _direct_subkeys(state, target):
                return 0xc0000121  # STATUS_CANNOT_DELETE: not recursive
            result = delete_leaf(target)
            return 0 if result == 0 else 0xc0000034  # STATUS_OBJECT_NAME_NOT_FOUND
        if name in ["ntopenkey", "ntopenkeyex", "rtlpntopenkey"]:
            if name == "ntopenkeyex" and args[3] & 0xffffffff not in [0, 4, 8, 12]:
                fail("NtOpenKeyEx: unsupported open options")
            # REG_OPTION_OPEN_LINK opens the named key object itself, not its
            # symbolic-link target. That is exactly the path lookup below;
            # this does not implement ordinary link-following or intermediate
            # link traversal, nor grant access to a linked target.
            if not args[0]:
                return 0xc000000d  # STATUS_INVALID_PARAMETER
            target = native_object_key(event.machine, args[2])
            if target == None:
                return 0xc0000034  # STATUS_OBJECT_NAME_NOT_FOUND
            existing = _key_exists(state, target)
            if len(state["opens"]) < 4096:
                state["opens"].append({"api": name, "hive": target[0], "key": target[1], "found": existing})
            if not existing:
                return 0xc0000034
            access = args[1]
            if name == "ntopenkeyex" and args[3] & 4:
                access = backup_restore_access()
                if not access: return 0xc0000022  # STATUS_ACCESS_DENIED
            else:
                access = open_access(event, target, access)
                if access == None: return 0xc0000022
            _write_handle(event.machine, args[0], allocate_handle(target[0], target[1], access))
            return 0
        if name in ["ntcreatekey", "rtlpntcreatekey"]:
            if name == "ntcreatekey" and args[5] & 0xffffffff not in [0, 4]:
                fail("NtCreateKey: nonzero create options are not implemented")
            if not args[0]:
                return 0xc000000d
            target = native_object_key(event.machine, args[2])
            if target == None:
                return 0xc0000034
            existing = _key_exists(state, target)
            access = args[1]
            backup_restore = name == "ntcreatekey" and args[5] & 4
            if backup_restore:
                access = backup_restore_access()
                if not access: return 0xc0000022
                if not existing: fail("backup/restore key creation security is not implemented")
            if existing and not backup_restore:
                access = open_access(event, target, access)
                if access == None: return 0xc0000022
            if not existing:
                if on_open_key != None and access & 0xf2000000:
                    fail("new registry key requires concrete creation access")
                layout = object_attributes_layout(event.machine.pointer_size)
                create_new_key(event, target[0], target[1], dict(api=name, creator_security=event.machine.read_pointer(args[2]+layout["SecurityDescriptor"]), class_address=args[4], options=args[5] & 0xffffffff if name == "ntcreatekey" else 0, access=args[1] & 0xffffffff))
            _write_handle(event.machine, args[0], allocate_handle(target[0], target[1], access))
            disposition = args[6] if name == "ntcreatekey" else args[5]
            if disposition:
                event.machine.write_u32le(disposition, 2 if existing else 1)
            return 0
        if name == "ntenumeratekey":
            target = key_for(args[0])
            if target == None:
                return 0xc0000008  # STATUS_INVALID_HANDLE
            if args[2] & 0xffffffff != 0:
                fail("NtEnumerateKey: only basic information is implemented")
            subkeys = _direct_subkeys(state, target)
            index = args[1] & 0xffffffff
            if index >= len(subkeys):
                return 0x8000001a  # STATUS_NO_MORE_ENTRIES
            encoded = binary.encode(subkeys[index], encoding = "utf16le")
            # KEY_BASIC_INFORMATION: last-write time, title index, then name.
            result = binary.builder(capacity = 16 + len(encoded))
            result.u64le(0)
            result.u32le(0)
            result.u32le(len(encoded))
            result.append(encoded)
            data = result.bytes()
            if args[5]:
                event.machine.write(args[5], binary.u32le(len(data)))
            capacity = args[4] & 0xffffffff
            if capacity < 16:
                return 0xc0000023  # STATUS_BUFFER_TOO_SMALL: fixed header does not fit
            if not args[3]:
                return 0xc0000005
            event.machine.write(args[3], data[:min(capacity, len(data))])
            # Native consumers use the returned NameLength even when the
            # counted name is partial. Without this header and warning they
            # can retry the same undersized buffer forever.
            return 0 if capacity >= len(data) else 0x80000005
        if name == "ntenumeratevaluekey":
            target = key_for(args[0])
            if target == None:
                return 0xc0000008
            information_class = args[2] & 0xffffffff
            if information_class not in [0, 1]:
                fail("NtEnumerateValueKey: only basic/full information is implemented")
            values = _direct_values(state, target)
            index = args[1] & 0xffffffff
            if index >= len(values):
                return 0x8000001a
            if not args[5]:
                return 0xc000000d
            machine = event.machine
            item = values[index]
            encoded = binary.encode(item["name"], encoding = "utf16le")
            raw = item["value"]["raw"]
            header_size = 12 if information_class == 0 else 20
            offset = (20 + len(encoded) + 3) & ~3
            required = 12 + len(encoded) if information_class == 0 else offset + len(raw)
            machine.write_u32le(args[5], required)
            capacity = args[4] & 0xffffffff
            if capacity < header_size:
                return 0xc0000023
            if not args[3]:
                return 0xc0000005
            data = binary.builder(capacity = required)
            data.u32le(0)
            data.u32le(item["value"]["type"])
            if information_class == 1:
                data.u32le(offset)
                data.u32le(len(raw))
            data.u32le(len(encoded))
            data.append(encoded)
            if information_class == 1:
                data.reserve(offset - 20 - len(encoded))
                data.append(raw)
            machine.write(args[3], data.bytes()[:min(required, capacity)])
            return 0 if capacity >= required else 0x80000005
        if name == "ntquerykey":
            target = key_for(args[0])
            if target == None:
                return 0xc0000008
            information_class = args[1] & 0xffffffff
            if information_class not in [2, 4]:
                fail("NtQueryKey: only KeyFullInformation and KeyCachedInformation are implemented")
            if not args[4]:
                return 0xc000000d
            machine = event.machine
            subkeys = _direct_subkeys(state, target)
            values = _direct_values(state, target)
            metadata = _key_metadata(state, target)
            class_bytes = metadata["class"]
            header = 44 if information_class == 2 else 40
            required = header + (len(class_bytes) if information_class == 2 else 0)
            machine.write_u32le(args[4], required)
            capacity = args[3] & 0xffffffff
            if capacity < header:
                return 0xc0000023
            if not args[2]:
                return 0xc0000005
            data = binary.builder(capacity = required)
            # Source timestamps are preserved. Overlay writes have no clock;
            # newly created keys retain the deterministic zero-time model.
            data.u64le(metadata["last_write_time"])
            data.u32le(0)
            if information_class == 2:
                data.u32le(44 if class_bytes else 0xffffffff)
                data.u32le(len(class_bytes))
            data.u32le(len(subkeys))
            data.u32le(max([len(binary.encode(s, encoding = "utf16le")) for s in subkeys] or [0]))
            if information_class == 2:
                data.u32le(max([len(_key_metadata(state, (target[0], _join(target[1], _encode_key_part(s))))["class"]) for s in subkeys] or [0]))
            data.u32le(len(values))
            data.u32le(max([len(binary.encode(v["name"], encoding = "utf16le")) for v in values] or [0]))
            data.u32le(max([len(v["value"]["raw"]) for v in values] or [0]))
            if information_class == 2:
                data.append(class_bytes)
            else:
                basename = _decode_key_part(target[1].rstrip("/").rsplit("/", 1)[-1])
                data.u32le(len(binary.encode(basename, encoding = "utf16le")))
            machine.write(args[2], data.bytes()[:min(required, capacity)])
            return 0 if capacity >= required else 0x80000005
        if name == "ntdeletevaluekey":
            target = key_for(args[0])
            if target == None:
                return 0xc0000008
            if not args[1] or event.machine.read_u16le(args[1]) & 1:
                return 0xc000000d
            value_name = _unicode_string(event.machine, args[1]) or "(default)"
            result = _delete_value(state, target, value_name)
            return 0 if result == 0 else 0xc0000034
        if name == "ntsetvaluekey":
            target = key_for(args[0])
            if target == None:
                return 0xc0000008
            machine = event.machine
            if not args[1] or machine.read_u16le(args[1]) & 1:
                return 0xc000000d
            value_name = _unicode_string(machine, args[1]) or "(default)"
            registry_type = args[3] & 0xffffffff
            size = args[5] & 0xffffffff
            if size and not args[4]:
                return 0xc0000005
            raw = machine.read(args[4], size) if size else b""
            _registry_store_native_value(state, target, value_name, registry_type, raw, output_key)
            return 0
        if name == "ntqueryvaluekey":
            target = key_for(args[0])
            if target == None:
                return 0xc0000008  # STATUS_INVALID_HANDLE
            information_class = args[2] & 0xffffffff
            if information_class != 2:  # KeyValuePartialInformation
                fail("NtQueryValueKey: information class " + str(information_class) + " is not implemented")
            value_name = _unicode_string(event.machine, args[1]) or "(default)"
            value = _lookup_value(state, target, value_name)
            if len(state["queries"]) < 4096:
                state["queries"].append({"api": name, "hive": target[0], "key": target[1], "name": value_name, "found": value != None})
            if value == None:
                return 0xc0000034  # STATUS_OBJECT_NAME_NOT_FOUND
            if not args[5]:
                return 0xc000000d  # STATUS_INVALID_PARAMETER
            raw = value["raw"]
            required = 12 + len(raw)
            event.machine.write_u32le(args[5], required)
            capacity = args[4] & 0xffffffff
            if capacity < 12:
                return 0xc0000023  # STATUS_BUFFER_TOO_SMALL; no output data
            if not args[3]:
                return 0xc0000005  # STATUS_ACCESS_VIOLATION
            data = binary.builder(capacity = required)
            data.u32le(0)  # TitleIndex
            data.u32le(value["type"])
            data.u32le(len(raw))
            data.append(raw)
            event.machine.write(args[3], data.bytes()[:min(required, capacity)])
            return 0 if capacity >= required else 0x80000005  # STATUS_BUFFER_OVERFLOW
        if name == "rtlpntqueryvaluekey":
            target = key_for(args[0])
            if target == None:
                return 0xc0000008
            value = _lookup_value(state, target, "(default)")
            if value == None:
                return 0xc0000034
            capacity = binary.read_u32le(event.machine.read(args[3], 4)) if args[3] else 0
            raw = value["raw"]
            if len(state["opens"]) < 4096:
                state["opens"].append({"api": name, "hive": target[0], "key": target[1], "capacity": capacity, "data": args[2]})
            if args[1]:
                event.machine.write(args[1], binary.u32le(value["type"]))
            if args[3]:
                event.machine.write(args[3], binary.u32le(len(raw)))
            if not args[2] or capacity < len(raw):
                return 0x80000005  # STATUS_BUFFER_OVERFLOW
            event.machine.write(args[2], raw)
            return 0
        if name == "rtlpntenumeratesubkey":
            target = key_for(args[0])
            if target == None:
                return 0xc0000008
            subkeys = _direct_subkeys(state, target)
            if args[2] >= len(subkeys):
                return 0x8000001a
            if not args[1]:
                return 0xc000000d
            data = binary.encode(subkeys[args[2]], encoding = "utf16le")
            descriptor = binary.cursor(event.machine.read(args[1], 8))
            descriptor.u16le()
            capacity = descriptor.u16le()
            data_address = descriptor.u32le()
            if not data_address or capacity < len(data):
                return 0x80000005
            event.machine.write(data_address, data)
            if capacity >= len(data) + 2:
                event.machine.write(data_address + len(data), b"\x00\x00")
            event.machine.write(args[1], binary.u16le(len(data)))
            return 0
        if name == "rtlqueryregistryvalues":
            if not args[2]:
                return 0xc000000d
            path = event.machine.read_cstring(args[1], encoding = "utf16le") if args[1] else ""
            top = relative_registry_key(args[0], path)
            if top == None:
                return 0xc0000034
            current = top
            for index in range(1024):
                entry = binary.cursor(event.machine.read(args[2] + index * 28, 28))
                routine = entry.u32le()
                flags = entry.u32le()
                name_address = entry.u32le()
                entry_context = entry.u32le()
                default_type = entry.u32le()
                default_data = entry.u32le()
                default_length = entry.u32le()
                if not routine and not name_address:
                    return 0
                value_name = event.machine.read_cstring(name_address, encoding = "utf16le") if name_address else ""
                if flags & 0x2:  # RTL_QUERY_REGISTRY_TOPKEY
                    current = top
                if flags & 0x1:  # RTL_QUERY_REGISTRY_SUBKEY
                    current = join_key(current, value_name)
                    continue
                identity = _identity(current[0], current[1], value_name if value_name else "(default)")
                value = _lookup_value(state, current, value_name if value_name else "(default)")
                if len(state["queries"]) < 4096:
                    state["queries"].append({
                        "hive": current[0], "key": current[1], "name": value_name if value_name else "(default)",
                        "found": value != None, "api": name, "flags": flags, "routine": routine,
                        "entry_context": entry_context, "default_type": default_type,
                        "default_length": default_length,
                    })
                if value == None:
                    if flags & 0x4 and not default_data:  # RTL_QUERY_REGISTRY_REQUIRED
                        return 0xc0000034
                    if not default_data and not default_length:
                        continue
                    value_type = default_type
                    raw = event.machine.read(default_data, default_length) if default_data and default_length else b""
                else:
                    value_type = value["type"]
                    raw = value["raw"]
                if flags & 0x20:  # RTL_QUERY_REGISTRY_DIRECT
                    if not entry_context:
                        return 0xc000000d
                    if value_type == 4 and len(raw) >= 4:
                        event.machine.write(entry_context, raw[:4])
                    elif value_type in [1, 2]:
                        descriptor = binary.cursor(event.machine.read(entry_context, 8))
                        descriptor.u16le()
                        capacity = descriptor.u16le()
                        destination = descriptor.u32le()
                        if not destination or capacity < len(raw):
                            return 0xc0000023
                        event.machine.write(destination, raw)
                        event.machine.write(entry_context, binary.u16le(max(0, len(raw) - 2)))
                    else:
                        event.machine.write(entry_context, raw)
                elif routine:
                    result = event.machine.invoke(routine, args = [name_address, value_type, default_data if value == None else event.machine.allocate(value = raw, name = "registry value"), len(raw), args[3], entry_context])
                    if result.reason != "return":
                        event.machine.stop(result.reason, detail = result.detail)
                        return result.value
                    if result.value & 0x80000000:
                        return result.value
            return 0xc0000023
        if name == "rtlinitializerxact":
            root = key_for(args[0])
            if root == None or not args[2]:
                return 0xc0000008
            context = event.machine.allocate(size = 64, name = "RTL_RXACT_CONTEXT")
            state["transactions"][context] = {"root": root, "actions": [], "started": False}
            event.machine.write(args[2], binary.u32le(context))
            state["transaction_actions"].append({"api": name, "context": context, "root": root, "commit": bool(args[1])})
            return 0
        if name == "rtlstartrxact":
            transaction = state["transactions"].get(args[0])
            if transaction == None:
                return 0xc0000008
            transaction["started"] = True
            transaction["actions"] = []
            state["transaction_actions"].append({"api": name, "context": args[0]})
            return 0
        if name in ["rtladdactiontorxact", "rtladdattributeactiontorxact"]:
            transaction = state["transactions"].get(args[0])
            if transaction == None or not transaction["started"]:
                return 0xc0000008
            attribute = name == "rtladdattributeactiontorxact"
            data_index = 6 if attribute else 4
            size_index = 7 if attribute else 5
            size = args[size_index]
            action = {
                "api": name,
                "context": args[0],
                "operation": args[1],
                "subkey": _unicode_string(event.machine, args[2]),
                "key_handle": args[3] if attribute else 0,
                "attribute": _unicode_string(event.machine, args[4]) if attribute else "",
                "type": args[5] if attribute else args[3],
                "value": event.machine.read(args[data_index], size) if args[data_index] and size <= (16 << 20) else b"",
                "size": size,
            }
            transaction["actions"].append(action)
            state["transaction_actions"].append(action)
            return 0
        if name == "rtlabortrxact":
            transaction = state["transactions"].get(args[0])
            if transaction == None:
                return 0xc0000008
            transaction["started"] = False
            transaction["actions"] = []
            state["transaction_actions"].append({"api": name, "context": args[0]})
            return 0
        if name in ["rtlapplyrxact", "rtlapplyrxactnoflush"]:
            transaction = state["transactions"].get(args[0])
            if transaction == None or not transaction["started"]:
                return 0xc0000008
            for action in transaction["actions"]:
                target = join_key(transaction["root"], action["subkey"])
                existing = _key_exists(state, target)
                ensure_key(target[0], target[1])
                if not existing:
                    record_created_key(target[0], target[1])
                if action["size"]:
                    registry_type = _TYPES.get(action["type"])
                    if registry_type == None:
                        return 0xc000000d
                    store_value(
                        target[0],
                        target[1],
                        "(default)",
                        registry_type,
                        _decode_value(action["value"], action["type"], True),
                        True,
                    )
            transaction["started"] = False
            state["transaction_actions"].append({"api": name, "context": args[0], "count": len(transaction["actions"])})
            return 0
        if name == "regdisablepredefinedcache":
            return 0
        if name == "regoverridepredefkey":
            if args[0] not in _ROOTS:
                return 87  # ERROR_INVALID_PARAMETER
            if not args[1]:
                state["overrides"].pop(args[0], None)
                return 0
            target = key_for(args[1])
            if target == None:
                return 6  # ERROR_INVALID_HANDLE
            state["overrides"][args[0]] = target
            return 0
        if name == "regopencurrentuser":
            if not args[1]:
                return 87
            root = key_for(0x80000001)
            _write_handle(event.machine, args[1], allocate_handle(root[0], root[1]))
            return 0
        if name.startswith("shregopenuskey") or name.startswith("shregcreateuskey"):
            path = _cstring(event.machine, args[0], wide)
            relative = us_targets(args[2])
            if not relative:
                relative = [] if args[4] else [_ROOTS[0x80000001]]
                relative.append(_ROOTS[0x80000002])
            targets = []
            create = name.startswith("shregcreateuskey")
            for parent in relative:
                target = join_key(parent, path)
                exists = _key_exists(state, target)
                if create and not exists:
                    ensure_key(target[0], target[1])
                    record_created_key(target[0], target[1])
                    exists = True
                if exists:
                    targets.append(target)
            if not targets:
                return 2
            _write_handle(event.machine, args[3], allocate_us_handle(targets))
            return 0
        if name == "shregcloseuskey":
            if args[0] not in state["us_handles"]:
                return 6
            state["us_handles"].pop(args[0])
            return 0
        if name.startswith("shregqueryusvalue"):
            value_name = _cstring(event.machine, args[1], wide) if args[1] else "(default)"
            return query_us(
                event.machine,
                us_targets(args[0], ignore_user = bool(args[5])),
                value_name,
                args[2],
                args[3],
                args[4],
                wide,
                default_address = args[6],
                default_size = args[7],
            )
        if name.startswith("reggetvalue"):
            parent = key_for(args[0])
            flags, type_address, data_address, size_address = args[3:]
            capacity = event.machine.read_u32le(size_address) if size_address else 0
            def failed(status):
                if flags & 0x20000000 and data_address and capacity:
                    if capacity > 16 << 20:
                        event.machine.stop("RegGetValue zero-on-failure buffer exceeds process bound")
                    else:
                        event.machine.write(data_address, b"\x00" * capacity)
                return status
            if flags & ~0x3003ffff or flags & 0x30000 == 0x30000 or data_address and not size_address:
                return failed(87)
            if parent == None:
                return failed(6)
            target = join_key(parent, _cstring(event.machine, args[1], wide)) if args[1] else parent
            value_name = _cstring(event.machine, args[2], wide) if args[2] else "(default)"
            value = _lookup_value(state, target, value_name)
            if len(state["queries"]) < 4096:
                state["queries"].append({"hive": target[0], "key": target[1], "name": value_name, "found": value != None, "flags": flags})
            if value == None:
                return failed(2)
            value_type = value["type"]
            raw = _api_value_raw(value, wide)
            if value_type == 2 and not flags & 0x10000000:
                expanded = expand_environment(_decode_value(value["raw"], 2, True), environment)
                raw = binary.encode(expanded, encoding = "utf16le" if wide else "ascii", nul = True)
                value_type = 1
            if value_type in [1, 2, 7]:
                terminator = b"\x00\x00" if wide else b"\x00"
                if value_type == 7:
                    terminator *= 2
                if raw[-len(terminator):] != terminator:
                    raw = bytes_concat([raw, terminator])
            if type_address:
                event.machine.write_u32le(type_address, value_type)
            restriction = flags & 0xffff
            type_flag = {0: 1, 1: 2, 2: 4, 3: 8, 4: 16, 7: 32, 11: 64}.get(value_type, 0)
            if restriction not in [0, 0xffff] and not restriction & type_flag:
                return failed(1630)
            if value_type == 3 and (restriction == 0x18 and len(raw) != 4 or restriction == 0x48 and len(raw) != 8):
                return failed(1629)
            if size_address:
                event.machine.write_u32le(size_address, len(raw))
            if data_address:
                if capacity < len(raw):
                    return failed(234)
                event.machine.write(data_address, raw)
            return 0
        if name.startswith("shreggetvalue"):
            parent = key_for(args[0])
            target = join_key(parent, _cstring(event.machine, args[1], wide)) if parent != None and args[1] else parent
            value_name = _cstring(event.machine, args[2], wide) if args[2] else "(default)"
            return query(event.machine, target, value_name, args[4], args[5], args[6], wide)
        if name.startswith("shreggetusvalue"):
            subkey = _cstring(event.machine, args[0], wide)
            value_name = _cstring(event.machine, args[1], wide) if args[1] else "(default)"
            targets = []
            if not args[5]:
                targets.append(join_key(_ROOTS[0x80000001], subkey))
            targets.append(join_key(_ROOTS[0x80000002], subkey))
            return query_us(
                event.machine,
                targets,
                value_name,
                args[2],
                args[3],
                args[4],
                wide,
                default_address = args[6],
                default_size = args[7],
            )
        if name.startswith("shgetvalue"):
            parent = key_for(args[0])
            target = join_key(parent, _cstring(event.machine, args[1], wide)) if parent != None and args[1] else parent
            value_name = _cstring(event.machine, args[2], wide) if args[2] else "(default)"
            return query(event.machine, target, value_name, args[3], args[4], args[5], wide)
        if name.startswith("shdeletekey"):
            parent = key_for(args[0])
            if parent == None:
                return 6
            return _delete_tree(state, join_key(parent, _cstring(event.machine, args[1], wide)))
        if name.startswith("shdeleteorphankey"):
            parent = key_for(args[0])
            if parent == None:
                return 6
            target = join_key(parent, _cstring(event.machine, args[1], wide))
            if not _key_exists(state, target):
                return 2
            information = _key_information(state, target)
            if information["subkeys"] == 0 and information["values"] == 0:
                return _delete_tree(state, target)
            return 0
        if name.startswith("shdeletevalue"):
            parent = key_for(args[0])
            if parent == None:
                return 6
            target = join_key(parent, _cstring(event.machine, args[1], wide)) if args[1] else parent
            value_name = _cstring(event.machine, args[2], wide) if args[2] else "(default)"
            return _delete_value(state, target, value_name)
        if name.startswith("shregsetpath"):
            parent = key_for(args[0])
            if parent == None:
                return 6
            target = join_key(parent, _cstring(event.machine, args[1], wide)) if args[1] else parent
            value_name = _cstring(event.machine, args[2], wide) if args[2] else "(default)"
            value = _cstring(event.machine, args[3], wide) if args[3] else ""
            store_value(target[0], target[1], value_name, "REG_EXPAND_SZ", value, True)
            return 0
        if name.startswith("shsetvalue"):
            parent = key_for(args[0])
            if parent == None:
                return 6
            target = join_key(parent, _cstring(event.machine, args[1], wide)) if args[1] else parent
            value_name = _cstring(event.machine, args[2], wide) if args[2] else "(default)"
            registry_type = args[3] & 0xffffffff
            size = args[5] & 0xffffffff
            raw = event.machine.read(args[4], size) if size else b""
            symbolic = _TYPES.get(registry_type)
            if symbolic == None:
                return 87
            store_value(target[0], target[1], value_name, symbolic, _decode_value(raw, registry_type, wide), True)
            return 0
        if name.startswith("regopenkey") or name.startswith("regcreatekey"):
            parent = key_for(args[0])
            if parent == None:
                return 6
            child = _cstring(event.machine, args[1], wide)
            result_index = 2 if name in ["regopenkeyw", "regopenkeya", "regcreatekeyw", "regcreatekeya"] else (4 if name.startswith("regopen") else 7)
            hive, key = join_key(parent, child)
            existing = _key_exists(state, (hive, key))
            if len(state["opens"]) < 4096:
                state["opens"].append({"api": name, "hive": hive, "key": key, "found": existing})
            if name.startswith("regopen") and not existing:
                return 2
            access = args[3] if name.startswith("regopenkeyex") else (args[5] if name.startswith("regcreatekeyex") else None)
            if existing and access != None:
                access = open_access(event, (hive, key), access)
                if access == None: return 5
            if not existing and on_open_key != None and access != None and access & 0xf2000000:
                fail("new registry key requires concrete creation access")
            if name.startswith("regcreate") and not existing:
                extended = name.startswith("regcreatekeyex")
                attributes = args[6] if extended else 0
                creator = event.machine.read_pointer(attributes + (8 if event.machine.pointer_size == 8 else 4)) if attributes else 0
                create_new_key(event, hive, key, dict(api=name, creator_security=creator, class_address=args[3] if extended else 0, options=args[4] & 0xffffffff if extended else 0, access=args[5] & 0xffffffff if extended else None))
            handle = allocate_handle(hive, key, access)
            _write_handle(event.machine, args[result_index], handle)
            if name.startswith("regcreatekeyex") and args[8]:
                event.machine.write(args[8], binary.u32le(2 if existing else 1))
            return 0
        if name in ["regsetvaluew", "regsetvaluea"]:
            parent = key_for(args[0])
            if parent == None:
                return 6
            target = join_key(parent, _cstring(event.machine, args[1], wide)) if args[1] else parent
            # RegSetValue is the legacy REG_SZ-only API. cbData is ignored;
            # unlike RegSetValueEx, its data is a NUL-terminated string.
            # https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regsetvaluea
            if args[2] & 0xffffffff != 1 or not args[3]:
                return 87
            value = _cstring(event.machine, args[3], wide)
            ensure_key(target[0], target[1])
            store_value(
                target[0],
                target[1],
                "(default)",
                "REG_SZ",
                value,
                True,
            )
            return 0
        if name.startswith("regsetvalueex"):
            target = key_for(args[0])
            if target == None:
                return 6
            value_name = _cstring(event.machine, args[1], wide) if args[1] else "(default)"
            # DWORD arguments occupy only the low half of a Win64 argument
            # slot. Native callers may leave unrelated bytes in the high half
            # of stack-passed cbData; pointers and handles remain full-width.
            registry_type = args[3] & 0xffffffff
            size = args[5] & 0xffffffff
            raw = event.machine.read(args[4], size) if size else b""
            value = _decode_value(raw, registry_type, wide)
            identity = _identity(target[0], target[1], value_name)
            state["deleted_values"].pop(identity, None)
            state["values"][identity] = {
                "type": registry_type,
                "raw": _encoded_value(_TYPES.get(registry_type, registry_type), value),
            }
            state["patches"].append({
                "hive": target[0], "key": target[1], "name": value_name,
                "type": _TYPES.get(registry_type, registry_type), "value": value,
            })
            return 0
        if name.startswith("regsetkeyvalue"):
            parent = key_for(args[0])
            if parent == None:
                return 6
            target = join_key(parent, _cstring(event.machine, args[1], wide)) if args[1] else parent
            if not _key_exists(state, target):
                return 2
            value_name = _cstring(event.machine, args[2], wide) if args[2] else "(default)"
            registry_type = args[3] & 0xffffffff
            size = args[5] & 0xffffffff
            raw = event.machine.read(args[4], size) if size else b""
            value = _decode_value(raw, registry_type, wide)
            identity = _identity(target[0], target[1], value_name)
            state["deleted_values"].pop(identity, None)
            state["values"][identity] = {
                "type": registry_type,
                "raw": _encoded_value(_TYPES.get(registry_type, registry_type), value),
            }
            state["patches"].append({
                "hive": target[0], "key": target[1], "name": value_name,
                "type": _TYPES.get(registry_type, registry_type), "value": value,
            })
            return 0
        if name == "regclosekey":
            handle = _predefined_handle(args[0])
            if state["handles"].get(handle) == None:
                return 6
            if handle not in _ROOTS:
                state["handles"][handle] = None
                state["handle_access"].pop(handle, None)
                state["deleted_handles"].pop(handle, None)
            return 0
        if name in ["regflushkey", "ntflushkey"]:
            target = key_for(args[0])
            if target == None:
                return 0xc0000008 if name == "ntflushkey" else 6
            if len(state["flushes"]) < 4096:
                state["flushes"].append({"hive": target[0], "key": target[1]})
            return 0
        if name.startswith("regdeletetree"):
            parent = key_for(args[0])
            if parent == None:
                return 6
            subkey = _cstring(event.machine, args[1], wide) if args[1] else ""
            if subkey:
                return _delete_tree(state, join_key(parent, subkey))
            for child in _direct_subkeys(state, parent):
                _delete_tree(state, join_key(parent, child))
            for value in _direct_values(state, parent):
                _delete_value(state, parent, value["name"])
            return 0
        if name in ["regdeletekeya", "regdeletekeyw", "regdeletekeyexa", "regdeletekeyexw"]:
            if name.startswith("regdeletekeyex"):
                desired, reserved = args[2] & 0xffffffff, args[3] & 0xffffffff
                if reserved or desired & 0x300 == 0x300:
                    return 87  # ERROR_INVALID_PARAMETER
                native_view = 0x100 if event.machine.pointer_size == 8 else 0x200
                if desired not in [0, native_view]:
                    fail("RegDeleteKeyEx: alternate registry views/access policies are not modeled")
            parent = key_for(args[0])
            if parent == None:
                return 6
            if not args[1]:
                return 87
            subkey = _cstring(event.machine, args[1], wide)
            # Native RegDeleteKeyEx reopens even an empty relative name with
            # DELETE, then deletes that key object. A read-only hKey is not
            # itself the DELETE authorization. Keep this within the existing
            # registry security model (not full NT ACL authorization), reject
            # hive-root/child-bearing deletion, and retain stale references.
            return delete_leaf(join_key(parent, subkey) if subkey else parent)
        if name.startswith("regdeletevalue"):
            target = key_for(args[0])
            if target == None:
                return 6
            value_name = _cstring(event.machine, args[1], wide) if args[1] else "(default)"
            return _delete_value(state, target, value_name)
        if name.startswith("regenumkey"):
            target = key_for(args[0])
            if target == None:
                return 6
            subkeys = _direct_subkeys(state, target)
            if args[1] >= len(subkeys):
                return 259  # ERROR_NO_MORE_ITEMS
            value = subkeys[args[1]]
            if name in ["regenumkeya", "regenumkeyw"]:
                capacity = args[3]
                if not args[2] or capacity <= len(value):
                    return 234  # ERROR_MORE_DATA
                event.machine.write(args[2], binary.encode(
                    value,
                    encoding = "utf16le" if wide else "ascii",
                    nul = True,
                ))
                return 0
            if not args[3]:
                return 87
            capacity = binary.read_u32le(event.machine.read(args[3], 4))
            event.machine.write(args[3], binary.u32le(len(value)))
            if not args[2] or capacity <= len(value):
                return 234
            event.machine.write(args[2], binary.encode(
                value,
                encoding = "utf16le" if wide else "ascii",
                nul = True,
            ))
            if args[5] and args[6]:
                class_capacity = binary.read_u32le(event.machine.read(args[6], 4))
                event.machine.write(args[6], binary.u32le(0))
                if class_capacity:
                    event.machine.write(args[5], b"\x00\x00" if wide else b"\x00")
            if args[7]:
                event.machine.write(args[7], b"\x00" * 8)
            return 0
        if name.startswith("regenumvalue"):
            target = key_for(args[0])
            if target == None:
                return 6
            values = _direct_values(state, target)
            if args[1] >= len(values):
                return 259
            item = values[args[1]]
            value_name = item["name"]
            if not args[3]:
                return 87
            name_capacity = binary.read_u32le(event.machine.read(args[3], 4))
            event.machine.write(args[3], binary.u32le(len(value_name)))
            if args[2]:
                if name_capacity <= len(value_name):
                    return 234
                event.machine.write(args[2], binary.encode(
                    value_name,
                    encoding = "utf16le" if wide else "ascii",
                    nul = True,
                ))
            if args[5]:
                event.machine.write(args[5], binary.u32le(item["value"]["type"]))
            raw = _api_value_raw(item["value"], wide)
            data_capacity = binary.read_u32le(event.machine.read(args[7], 4)) if args[7] else 0
            if args[7]:
                event.machine.write(args[7], binary.u32le(len(raw)))
            if args[6]:
                if not args[7] or data_capacity < len(raw):
                    return 234
                event.machine.write(args[6], raw)
            return 0
        if name.startswith("regqueryvalueex"):
            target = key_for(args[0])
            value_name = _cstring(event.machine, args[1], wide) if args[1] else "(default)"
            return query(event.machine, target, value_name, args[3], args[4], args[5], wide)
        if name.startswith("regqueryvalue"):
            parent = key_for(args[0])
            target = join_key(parent, _cstring(event.machine, args[1], wide)) if parent != None and args[1] else parent
            return query(event.machine, target, "(default)", 0, args[2], args[3], wide)
        if name.startswith("regqueryinfokey"):
            target = key_for(args[0])
            if target == None:
                return 6  # ERROR_INVALID_HANDLE
            information = _key_information(state, target)
            if args[2]:
                event.machine.write(args[2], binary.u32le(0))
            if args[1]:
                event.machine.write(args[1], b"\x00\x00" if wide else b"\x00")
            for address, value in [
                (args[4], information["subkeys"]),
                (args[5], information["max_subkey_length"]),
                (args[6], 0),
                (args[7], information["values"]),
                (args[8], information["max_value_name_length"]),
                (args[9], information["max_value_length"]),
                (args[10], 0),
            ]:
                if address:
                    event.machine.write(address, binary.u32le(value))
            if args[11]:
                event.machine.write(args[11], b"\x00" * 8)
            return 0
        if name == "regnotifychangekeyvalue":
            target = key_for(args[0])
            if target == None:
                return 6  # ERROR_INVALID_HANDLE
            if args[4] and not args[3]:
                return 87  # ERROR_INVALID_PARAMETER
            if len(state["notifications"]) < 4096:
                state["notifications"].append({
                    "hive": target[0], "key": target[1], "subtree": bool(args[1]),
                    "filter": args[2], "event": args[3], "asynchronous": bool(args[4]),
                })
            return 0
        return 120

    def install(machine):
        for module in ["advapi32.dll", "advapi32_vista.dll", "kernel32.dll", "kernelbase.dll", "api-ms-win-core-registry-l1-1-0.dll"]:
            machine.provide_exports(callback, module = module, signatures = _CALLS)
        for imported in machine.imports_named(_CALLS):
            name = imported.name.lower()
            if name in _CALLS and _registry_provider_module(imported.module):
                machine.hook(callback, address = imported.address, argc = _CALLS[name])
        machine.provide_exports(callback, module = "ntdll.dll", signatures = _NATIVE_CALLS)
        for ordinal, binding in _SHLWAPI_REGISTRY_WRAPPERS.items():
            function, argc = binding
            def wrapped(event, function = function):
                return callback(event, function)
            machine.provide_export(wrapped, module = "shlwapi.dll", ordinal = ordinal, argc = argc)
        for name, binding in _SHLWAPI_NAMED_REGISTRY_WRAPPERS.items():
            function, argc = binding
            def wrapped(event, function = function):
                return callback(event, function)
            machine.provide_export(wrapped, module = "shlwapi.dll", name = name, argc = argc)
        for imported in machine.imports:
            if imported.module.lower() != "api-ms-win-core-registryuserspecific-l1-1-0.dll":
                continue
            binding = _SHLWAPI_NAMED_REGISTRY_WRAPPERS.get(imported.name.lower())
            if binding == None:
                continue
            function, argc = binding
            def wrapped(event, function = function):
                return callback(event, function)
            machine.hook(wrapped, address = imported.address, argc = argc)

    def patches():
        return list(state["patches"])

    def effects(patch_start = 0, key_deletion_start = 0):
        """Capture surviving writes separately from chronological API patches.

        A key may be deleted/recreated more than once. Replaying all sets
        after excluding deleted keys would resurrect writes to dead objects.
        Read only the final owned values for touched names; retain actual key
        deletions independently, including empty keys. Source data is not
        exported unless native code changed it. Capture before hive teardown.
        Optional history offsets isolate a mounted-hive epoch from namespace
        cleanup in an earlier epoch. Capture offsets before native mutation;
        they refer to the current histories and become invalid after reset.
        """
        if type(patch_start) != "int" or type(key_deletion_start) != "int" or patch_start < 0 or patch_start > len(state["patches"]) or key_deletion_start < 0 or key_deletion_start > len(state["key_deletions"]):
            fail("registry effect history offset is out of bounds")
        touched = {}
        for patch in state["patches"][patch_start:]:
            touched[_identity(patch["hive"], patch["key"], patch["name"])] = patch
        values = []
        removals = []
        for identity in sorted(touched.keys()):
            patch = touched[identity]
            current = state["values"].get(identity)
            item = {"hive": patch["hive"], "key": output_key(patch["key"]), "name": patch["name"]}
            if current != None:
                # Numeric type + raw data is lossless and accepted by the hive
                # writer. Do not round-trip strings through decoded API text.
                item.update(type = current["type"], value = current["raw"])
                values.append(item)
            elif patch.get("delete", False):
                removals.append(item)
        return {"keys": reported_keys(), "key_deletions": key_deletions()[key_deletion_start:], "values": values, "value_deletions": removals}

    def key_deletions():
        return [{"hive": item["hive"], "key": output_key(item["key"])} for item in state["key_deletions"]]

    def queries():
        return list(state["queries"])

    def opens():
        return list(state["opens"])

    def transactions():
        return list(state["transaction_actions"])

    def set_value(hive, key, name, type, value):
        store_value(hive, key, name, type, value, True)

    def get_value(hive, key, name, default = None):
        current = _lookup_value(state, (hive, key), name)
        if current == None:
            return default
        return _decode_value(current["raw"], current["type"], True)

    def set_security(handle, descriptor):
        target = key_for(handle)
        if target == None:
            return 6  # ERROR_INVALID_HANDLE
        return set_key_security(target[0], target[1], descriptor)

    def set_key_security(hive, key, descriptor):
        ensure_key(hive, key)
        identity = _key_identity(hive, key)
        state["security"][identity] = {
            "hive": hive,
            "key": output_key(key),
            "security": descriptor,
        }
        return 0

    def reported_keys():
        identities = {}
        for identity in state["created_keys"]:
            identities[identity] = True
        for identity in state["security"]:
            identities[identity] = True
        output = []
        for identity in sorted(identities.keys()):
            if identity not in state["keys"]:
                continue
            if identity in state["created_keys"]:
                item = dict(state["created_keys"][identity])
            else:
                item = {
                    "hive": state["security"][identity]["hive"],
                    "key": state["security"][identity]["key"],
                }
            if identity in state["security"]:
                item["security"] = state["security"][identity]["security"]
            output.append(item)
        return output

    def delete_value(hive, key, name):
        return _delete_value(state, (hive, key), name)

    def delete_tree(hive, key):
        return _delete_tree(state, (hive, key))

    def reset():
        state["handles"] = dict(_ROOTS)
        state["handle_access"] = {}
        state["deleted_handles"] = {}
        state["overrides"] = {}
        state["next_handle"] = 0x10000
        state["patches"] = []
        state["keys"] = {}
        state["created_keys"] = {}
        state["values"] = {}
        state["source_cache"] = {}
        state["source_cache_serial"] = 0
        state["subkeys_cache"] = {}
        state["key_names_revision"] = 0
        state["deleted_keys"] = {}
        state["key_deletions"] = []
        state["deleted_values"] = {}
        state["queries"] = []
        state["opens"] = []
        state["notifications"] = []
        state["security"] = {}
        state["transactions"] = {}
        state["transaction_actions"] = []
        state["us_handles"] = {}
        for root in _ROOTS.values():
            ensure_key(root[0], root[1])
        for hive, key in _BASELINE_KEYS:
            ensure_key(hive, key)
        for mount in state["mounts"]: ensure_key(mount["hive"],mount["key"])
        load_keys(keys)
        load_values(values)

    def transaction_data():
        return {field:_clone_registry_overlay(state[field]) for field in _TRANSACTION_FIELDS}

    def fork(next_handle):
        child=registry_plugin(hives=state["sources"],user_sid=user_sid,output_key_case=output_key_case,environment=environment,on_create_key=on_create_key,effective_token_privileges=effective_token_privileges,mounts=state["mounts"],on_open_key=on_open_key)
        child.state.update(transaction_data())
        for field in ["handles","handle_access","deleted_handles","overrides","source_cache"]:
            child.state[field]=_clone_registry_overlay(state[field])
        child.state["next_handle"]=next_handle
        return child

    def commit_fork(child, baseline):
        # The supported subset has no concurrent writer. Never overwrite an
        # intervening parent edit or pretend it has been conflict-checked.
        if transaction_data()!=baseline:
            fail("concurrent registry writes during a native transaction are not modeled")
        replacement=child._transaction_data()
        state.update(replacement)
        state["source_cache"]=_clone_registry_overlay(child.state["source_cache"])
        for handle in state["handles"]:
            if handle in child.state["deleted_handles"]: state["deleted_handles"][handle]=True
        _invalidate_key_names(state)

    return emulator.plugin(
        install,
        name = "windows.registry",
        state = state,
        attrs = {"_duplicate_handle": duplicate_handle, "_close_handle": close_handle, "_dispatch": callback, "_fork": fork, "_transaction_data": transaction_data, "_commit_fork": commit_fork, "patches": patches, "effects": effects, "key_deletions": key_deletions, "queries": queries, "opens": opens, "transactions": transactions, "keys": reported_keys, "reset": reset, "load_values": load_values, "load_keys": load_keys, "set_value": set_value, "get_value": get_value, "delete_value": delete_value, "delete_tree": delete_tree, "set_security": set_security, "set_key_security": set_key_security},
    )


def registry_handles_plugin(registry, kernel):
    """Connect owned registry keys to same-process kernel handle operations."""
    def install(machine):
        kernel.state.setdefault("handle_duplicators", []).append(registry._duplicate_handle)
        kernel.state.setdefault("handle_closers", []).append(registry._close_handle)
    return emulator.plugin(install, name="windows.registry-handles")
