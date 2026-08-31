"""Registry API plugin for deterministic Windows self-registration emulation."""

_ROOTS = {
    0x80000000: ("SOFTWARE", "/Classes"),
    0x80000001: ("DEFAULT", "/"),
    0x80000002: ("SOFTWARE", "/"),
    0x80000003: ("DEFAULT", "/@users"),
}

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
    "regclosekey": 1,
    "regflushkey": 1,
    "regdeletekeyw": 2,
    "regdeletekeya": 2,
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
    "ntenumeratekey": 6,
    "ntopenkey": 3,
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
    return normalized in ["advapi32.dll", "kernel32.dll"] or normalized.startswith("api-ms-win-core-registry-") or normalized.startswith("ext-ms-win-advapi32-registry-")

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
    descriptor = binary.cursor(machine.read(address, 8))
    length = descriptor.u16le()
    descriptor.u16le()
    data = descriptor.u32le()
    if not data or not length:
        return ""
    return binary.text(machine.read(data, length), encoding = "utf16le")

def _native_absolute_key(path):
    normalized = path.replace("/", "\\").strip("\\")
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

def _source_entry(state, target):
    hive, key = target
    identity = _key_identity(hive, key)
    sources = state.get("sources", {})
    if hive.upper() not in sources:
        return None
    cache = state.get("source_cache")
    if cache == None:
        cache = {}
        state["source_cache"] = cache
    cached = cache.get(identity)
    if cached != None:
        return cached if cached["found"] else None
    source = sources.get(hive.upper())
    node = source.find([_decode_key_part(part) for part in key.strip("/").split("/") if part]) if source != None else None
    if node == None:
        cache[identity] = {"found": False}
        return None
    entry = {
        "found": True,
        "subkeys": [child.name for child in node.children],
        "values": {
            name.lower(): {"name": name, "type": record.type, "raw": record.raw}
            for name, record in node.value_records.items()
        },
    }
    cache[identity] = entry
    return entry

def _key_deleted(state, identity):
    for deleted in state.get("deleted_keys", {}):
        if identity == deleted or identity.startswith(deleted.rstrip("/") + "/"):
            return True
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

def _direct_subkeys(state, target):
    hive, key = target
    base = _key_identity(hive, key)
    child_prefix = base.rstrip("/") + "/"
    output = {}
    source = _source_entry(state, target)
    if source != None:
        for name in source["subkeys"]:
            child = _key_identity(hive, _join(key, _encode_key_part(name)))
            if not _key_deleted(state, child):
                output[name.lower()] = name
    for identity in state["keys"]:
        if not identity.startswith(child_prefix):
            continue
        relative = identity[len(child_prefix):]
        if relative:
            name = _decode_key_part(relative.split("/")[0])
            output[name.lower()] = name
    return [output[name] for name in sorted(output.keys())]

def _direct_values(state, target):
    hive, key = target
    value_prefix = _key_identity(hive, key) + "\x00"
    output = {}
    source = _source_entry(state, target)
    if source != None:
        for name, value in source["values"].items():
            identity = _identity(hive, key, name)
            if identity not in state.get("deleted_values", {}):
                output[name] = {"name": "" if name == "(default)" else value["name"], "value": {"type": value["type"], "raw": value["raw"]}}
    for identity, value in state["values"].items():
        if not identity.startswith(value_prefix):
            continue
        name = identity[len(value_prefix):]
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

def _delete_tree(state, target):
    """Deletes a known registry key tree and records its removed values."""
    hive, key = target
    base = _key_identity(hive, key).rstrip("/")
    value_exact = base + "\x00"
    descendant = base + "/"
    retained = {}
    deleted = _key_exists(state, target)
    for identity, value in state["values"].items():
        if identity.startswith(value_exact) or identity.startswith(descendant):
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
        else:
            retained[identity] = value
    state["values"] = retained
    state["keys"] = {
        identity: True
        for identity in state["keys"]
        if identity != base and not identity.startswith(descendant)
    }
    state.setdefault("deleted_keys", {})[base] = True
    if "created_keys" in state:
        state["created_keys"] = {
            identity: item
            for identity, item in state["created_keys"].items()
            if identity != base and not identity.startswith(descendant)
        }
    if "security" in state:
        state["security"] = {
            identity: item
            for identity, item in state["security"].items()
            if identity != base and not identity.startswith(descendant)
        }
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

def registry_plugin(values = [], keys = [], hives = {}, user_sid = "", output_key_case = "preserve", prepared_state = None):
    """Returns a registry plugin initialized from hive-style dictionaries.

    Initial values are queryable but are not reported as writes. Each value uses
    the same `hive`, `key`, `name`, `type`, and `value` fields as a hive patch.
    Initial keys use `hive` and `key`; they make empty setup-created namespaces
    observable without being reported as writes. `hives` may map hive names to
    parsed `windows.hive` objects; these are consulted lazily and overridden by
    explicit keys, values, and subsequent writes.
    """
    if output_key_case not in ["preserve", "folded"]:
        fail("registry output_key_case must be preserve or folded")
    state = {
        "handles": dict(_ROOTS),
        "overrides": {},
        "next_handle": 0x10000,
        "patches": [],
        "keys": dict(prepared_state.get("keys", {})) if prepared_state != None else {},
        "created_keys": {},
        "values": dict(prepared_state.get("values", {})) if prepared_state != None else {},
        "sources": {name.upper(): source for name, source in hives.items()},
        "source_cache": {},
        "deleted_keys": {},
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

    def store_value(hive, key, name, registry_type, value, record):
        name = _value_name(name)
        numeric_type = None
        for numeric, symbolic in _TYPES.items():
            if symbolic == registry_type:
                numeric_type = numeric
                break
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
            identity = _identity(value["hive"], key, name)
            current = _lookup_value(state, (value["hive"], key), name)
            registry_type = _TYPES.get(value["type"], value["type"])
            if value.get("delete", False):
                state["values"].pop(identity, None)
                state["deleted_values"][identity] = True
                continue
            if value.get("append", False) and current != None:
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
            if value.get("if_absent", False) and current != None:
                continue
            if value.get("overwrite_only", False) and current == None:
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
    load_keys(keys)
    load_values(values)

    def allocate_handle(hive, key):
        handle = state["next_handle"]
        state["next_handle"] = handle + 1
        state["handles"][handle] = (hive, key)
        return handle

    def allocate_us_handle(targets):
        handle = state["next_handle"]
        state["next_handle"] = handle + 1
        state["us_handles"][handle] = targets
        return handle

    def key_for(handle):
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
        attributes = binary.cursor(machine.read(object_attributes, 24))
        if attributes.u32le() < 24:
            return None
        root = attributes.u32le()
        name = _unicode_string(machine, attributes.u32le())
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
        args = event.args
        wide = name.endswith("w")
        if name in ["ntopenkey", "rtlpntopenkey"]:
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
            event.machine.write(args[0], binary.u32le(allocate_handle(target[0], target[1])))
            return 0
        if name == "rtlpntcreatekey":
            if not args[0]:
                return 0xc000000d
            target = native_object_key(event.machine, args[2])
            if target == None:
                return 0xc0000034
            existing = _key_exists(state, target)
            ensure_key(target[0], target[1])
            if not existing:
                record_created_key(target[0], target[1])
            event.machine.write(args[0], binary.u32le(allocate_handle(target[0], target[1])))
            if args[5]:
                event.machine.write(args[5], binary.u32le(2 if existing else 1))
            return 0
        if name == "ntenumeratekey":
            target = key_for(args[0])
            if target == None:
                return 0xc0000008  # STATUS_INVALID_HANDLE
            subkeys = _direct_subkeys(state, target)
            if args[1] >= len(subkeys):
                return 0x8000001a  # STATUS_NO_MORE_ENTRIES
            encoded = binary.encode(subkeys[args[1]], encoding = "utf16le")
            # KEY_BASIC_INFORMATION: last-write time, title index, then name.
            result = binary.builder(capacity = 16 + len(encoded))
            result.u64le(0)
            result.u32le(0)
            result.u32le(len(encoded))
            result.append(encoded)
            data = result.bytes()
            if args[5]:
                event.machine.write(args[5], binary.u32le(len(data)))
            if args[4] < len(data):
                return 0xc0000023  # STATUS_BUFFER_TOO_SMALL
            event.machine.write(args[3], data)
            return 0
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
            event.machine.write(args[1], binary.u32le(allocate_handle(root[0], root[1])))
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
            event.machine.write(args[3], binary.u32le(allocate_us_handle(targets)))
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
            registry_type = args[3]
            raw = event.machine.read(args[4], args[5]) if args[5] else b""
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
            if name.startswith("regcreate"):
                ensure_key(hive, key)
                if not existing:
                    record_created_key(hive, key)
            handle = allocate_handle(hive, key)
            event.machine.write(args[result_index], binary.u32le(handle))
            if name.startswith("regcreatekeyex") and args[8]:
                event.machine.write(args[8], binary.u32le(2 if existing else 1))
            return 0
        if name in ["regsetvaluew", "regsetvaluea"]:
            parent = key_for(args[0])
            if parent == None:
                return 6
            target = join_key(parent, _cstring(event.machine, args[1], wide)) if args[1] else parent
            registry_type = args[2]
            symbolic = _TYPES.get(registry_type)
            if symbolic == None:
                return 87
            raw = event.machine.read(args[3], args[4]) if args[3] and args[4] else b""
            ensure_key(target[0], target[1])
            store_value(
                target[0],
                target[1],
                "(default)",
                symbolic,
                _decode_value(raw, registry_type, wide),
                True,
            )
            return 0
        if name.startswith("regsetvalueex"):
            target = key_for(args[0])
            if target == None:
                return 6
            value_name = _cstring(event.machine, args[1], wide) if args[1] else "(default)"
            registry_type = args[3]
            raw = event.machine.read(args[4], args[5]) if args[5] else b""
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
            if args[0] not in _ROOTS:
                state["handles"][args[0]] = None
            return 0
        if name == "regflushkey":
            target = key_for(args[0])
            if target == None:
                return 6  # ERROR_INVALID_HANDLE
            if len(state["flushes"]) < 4096:
                state["flushes"].append({"hive": target[0], "key": target[1]})
            return 0
        if name.startswith("regdeletekey"):
            parent = key_for(args[0])
            if parent == None:
                return 6
            return _delete_tree(state, join_key(parent, _cstring(event.machine, args[1], wide)))
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
        for module in ["advapi32.dll", "kernel32.dll"]:
            for name, argc in _CALLS.items():
                machine.provide_export(callback, module = module, name = name, argc = argc)
        for imported in machine.imports:
            name = imported.name.lower()
            if _registry_provider_module(imported.module) and name in _CALLS:
                machine.hook(callback, address = imported.address, argc = _CALLS[name])
        for name, argc in _NATIVE_CALLS.items():
            machine.provide_export(callback, module = "ntdll.dll", name = name, argc = argc)
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

    def patches():
        return list(state["patches"])

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
        state["overrides"] = {}
        state["next_handle"] = 0x10000
        state["patches"] = []
        state["keys"] = {}
        state["created_keys"] = {}
        state["values"] = {}
        state["source_cache"] = {}
        state["deleted_keys"] = {}
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
        load_keys(keys)
        load_values(values)

    return emulator.plugin(
        install,
        name = "windows.registry",
        state = state,
        attrs = {"patches": patches, "queries": queries, "opens": opens, "transactions": transactions, "keys": reported_keys, "reset": reset, "load_values": load_values, "load_keys": load_keys, "set_value": set_value, "get_value": get_value, "delete_value": delete_value, "delete_tree": delete_tree, "set_security": set_security, "set_key_security": set_key_security},
    )
