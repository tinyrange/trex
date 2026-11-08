"""Tests private standard-library algorithms without exposing production API."""

load("//tests:testing.star", "case", "equal", "not_equal", "raises", "suite", "true")

def test_gdb_integer_codecs():
    module = testing.module("@stdlib//debug:gdb.star")
    equal(module["_uint"](b"\x78\x56\x34\x12"), 0x12345678)
    equal(module["_uint"](b"\xff\xff", signed = True), -1)

def test_resource_patch_normalization():
    module = testing.module("@stdlib//windows/selfreg:policy.star")
    patches = module["_expand_patches"]([{
        "key": "/Classes/Example",
        "name": "(default)",
        "type": "REG_SZ",
        "value": "%MODULE%",
    }], {"MODULE": "example.dll"}, default_hive = "SOFTWARE")
    equal(patches, [{
        "hive": "SOFTWARE",
        "key": "/Classes/Example",
        "name": "(default)",
        "type": "REG_SZ",
        "value": "example.dll",
    }])

def test_registration_execution_preserves_static_server_path():
    module = testing.module("@stdlib//windows/selfreg:policy.star")
    static = [{
        "hive": "SOFTWARE",
        "key": "/Classes/CLSID/{A}/InprocServer32",
        "name": "(default)",
        "type": "REG_SZ",
        "value": "C:\\WINDOWS\\system32\\example.dll",
        "if_absent": True,
    }]
    runtime = [
        {
            "hive": "SOFTWARE",
            "key": "/Classes/CLSID/{a}/InprocServer32",
            "name": "(default)",
            "type": "REG_SZ",
            "value": "",
        },
        {
            "hive": "SOFTWARE",
            "key": "/Classes/Example.Component",
            "name": "(default)",
            "type": "REG_SZ",
            "value": "Example",
        },
    ]
    equal(module["_merge_execution_patches"](static, runtime), static + runtime[1:])

def test_partial_class_registration_accepts_only_completed_hkcr_writes():
    module = testing.module("@stdlib//windows/selfreg:policy.star")
    static = [{
        "hive": "SOFTWARE",
        "key": "/Classes/CLSID/{A}/InprocServer32",
        "name": "(default)",
        "type": "REG_SZ",
        "value": "example.dll",
    }]
    completed = {
        "hive": "SOFTWARE",
        "key": "/Classes/Example.Component/CLSID",
        "name": "(default)",
        "type": "REG_SZ",
        "value": "{A}",
    }
    runtime = [
        dict(completed, delete = True),
        completed,
        {"hive": "SYSTEM", "key": "/Services/Example", "name": "Start", "type": "REG_DWORD", "value": 2},
    ]
    equal(module["_partial_class_registration_patches"](static, runtime, 0x80040201), [completed])
    equal(module["_partial_class_registration_patches"](static, runtime, 0x80004005), [])
    equal(module["_partial_class_registration_patches"]([], runtime, 0x80040201), [])

def test_registration_result_conventions():
    module = testing.module("@stdlib//windows/selfreg:policy.star")
    succeeded = module["_registration_succeeded"]
    true(succeeded(0, True))
    equal(succeeded(10, True), False)
    true(succeeded(10, False))
    equal(succeeded(0x80004005, False), False)
    execution_succeeded = module["_execution_succeeded"]
    true(execution_succeeded("process-exit", 0, True))
    true(execution_succeeded("return", 0, True))
    equal(execution_succeeded("process-exit", 1, True), False)
    equal(execution_succeeded("stop", 0, True), False)
    true(execution_succeeded("return", 0, False))
    equal(execution_succeeded("process-exit", 0, False), False)

def test_incomplete_structured_class_registration_is_detected():
    missing = testing.module("@stdlib//windows/selfreg:policy.star")["_unregistered_classes"]
    patches = [{
        "hive": "SOFTWARE",
        "key": "/Classes/CLSID/{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}/InprocServer32",
        "name": "(default)",
        "type": "REG_SZ",
        "value": "C:\\WINDOWS\\system32\\example.dll",
    }]
    classes = [
        "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
        "{11111111-2222-3333-4444-555555555555}",
    ]
    equal(missing(patches, classes), [classes[1]])
    equal(missing(patches + [{
        "hive": "SOFTWARE",
        "key": "/Classes/CLSID/{11111111-2222-3333-4444-555555555555}/InprocServer32",
        "name": "(default)",
        "type": "REG_SZ",
        "value": "C:\\WINDOWS\\system32\\second.dll",
    }], classes), [])

def test_recursive_registry_deletion():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    identity = module["_identity"]
    key_identity = module["_key_identity"]
    state = {
        "keys": {
            key_identity("DEFAULT", "/"): True,
            key_identity("DEFAULT", "/Desktop"): True,
            key_identity("DEFAULT", "/Desktop/Components"): True,
            key_identity("DEFAULT", "/Desktop/Components/0"): True,
            key_identity("DEFAULT", "/Desktop/Scheme"): True,
        },
        "values": {
            identity("DEFAULT", "/Desktop/Components", "Settings"): {"type": 4, "raw": binary.u32le(1)},
            identity("DEFAULT", "/Desktop/Components/0", "Source"): {"type": 1, "raw": binary.encode("about:home", encoding = "utf16le", nul = True)},
            identity("DEFAULT", "/Desktop/Scheme", "Display"): {"type": 1, "raw": binary.encode("", encoding = "utf16le", nul = True)},
        },
        "patches": [],
    }
    equal(module["_delete_tree"](state, ("DEFAULT", "/Desktop/Components")), 0)
    equal((len(state["values"]), len(state["patches"])), (1, 2))
    equal(module["_delete_tree"](state, ("DEFAULT", "/Desktop/Missing")), 2)

def test_registry_value_deletion():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    identity = module["_identity"]("DEFAULT", "/Desktop", "Wallpaper")
    state = {
        "values": {identity: {"type": 1, "raw": binary.encode("clouds.bmp", encoding = "utf16le", nul = True)}},
        "patches": [],
    }
    equal(module["_delete_value"](state, ("DEFAULT", "/Desktop"), "Wallpaper"), 0)
    true(identity not in state["values"])
    true(len(state["patches"]) == 1 and state["patches"][0]["delete"])
    equal(module["_delete_value"](state, ("DEFAULT", "/Desktop"), "Wallpaper"), 2)

def test_registry_multi_string_decode():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    decode = module["_decode_value"]
    equal(decode(binary.encode("one\x00two\x00\x00", encoding = "utf16le"), 7, True), ["one", "two"])
    equal(decode(b"one\x00two\x00\x00", 7, False), ["one", "two"])
    canonical = {"type": 1, "raw": binary.encode("C:\\WINDOWS", encoding = "utf16le", nul = True)}
    equal(module["_api_value_raw"](canonical, False), b"C:\\WINDOWS\x00")
    equal(module["_api_value_raw"](canonical, True), canonical["raw"])

def test_registry_initial_assignment_modes():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    registry = module["registry_plugin"]()
    base = {"hive": "SOFTWARE", "key": "/Example", "name": "Value", "type": "REG_MULTI_SZ"}
    registry.load_values([dict(base, value = ["first"])])
    registry.load_values([dict(base, value = ["ignored"], if_absent = True)])
    equal(registry.get_value("SOFTWARE", "/Example", "Value"), ["first"])
    registry.load_values([dict(base, value = ["FIRST", "second"], append = True)])
    equal(registry.get_value("SOFTWARE", "/Example", "Value"), ["first", "second"])
    registry.load_values([dict(base, value = ["replaced"], overwrite_only = True)])
    equal(registry.get_value("SOFTWARE", "/Example", "Value"), ["replaced"])
    registry.load_values([dict(base, delete = True)])
    registry.load_values([dict(base, value = ["ignored"], overwrite_only = True)])
    equal(registry.get_value("SOFTWARE", "/Example", "Value"), None)
    registry.load_values([dict(base, value = ["new"])])
    equal(registry.get_value("SOFTWARE", "/Example", "Value"), ["new"])
    equal(registry.patches(), [])

def test_registry_qword_round_trip():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    value = 0xFEDCBA9876543210
    raw = binary.u64le(value)
    equal(raw, b"\x10\x32\x54\x76\x98\xba\xdc\xfe")
    equal(module["_decode_value"](raw, 11, True), value)
    registry = module["registry_plugin"](values = [{
        "hive": "SOFTWARE",
        "key": "/Example",
        "name": "Large",
        "type": "REG_QWORD",
        "value": value,
    }])
    equal(registry.get_value("SOFTWARE", "/Example", "Large"), value)

def test_registry_key_information():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    registry = module["registry_plugin"](
        values = [
            {"hive": "SOFTWARE", "key": "/Classes/CLSID", "name": "(default)", "type": "REG_SZ", "value": "classes"},
            {"hive": "SOFTWARE", "key": "/Classes/CLSID", "name": "LongValue", "type": "REG_BINARY", "value": b"123456"},
        ],
        keys = [
            {"hive": "SOFTWARE", "key": "/Classes/CLSID/{A}"},
            {"hive": "SOFTWARE", "key": "/Classes/CLSID/{A}/Nested"},
            {"hive": "SOFTWARE", "key": "/Classes/CLSID/{LONGER}"},
        ],
    )
    equal(module["_CALLS"]["regqueryinfokeyw"], 12)
    equal(module["_CALLS"]["regenumvaluew"], 8)
    equal(module["_direct_subkeys"](registry.state, ("SOFTWARE", "/Classes/CLSID")), ["{a}", "{longer}"])
    equal([item["name"] for item in module["_direct_values"](registry.state, ("SOFTWARE", "/Classes/CLSID"))], ["", "longvalue"])
    equal(module["_key_information"](registry.state, ("SOFTWARE", "/Classes/CLSID")), {
        "subkeys": 2,
        "max_subkey_length": 8,
        "values": 2,
        "max_value_name_length": 9,
        "max_value_length": 16,
    })

def test_registry_native_enumerate_full_value_information():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        registry = module["registry_plugin"](values = [{"hive": "SOFTWARE", "key": "/NativeProbe", "name": "Abc", "type": "REG_BINARY", "value": b"123456"}])
        machine.use(registry)
        key = machine.allocate(value = binary.encode("NativeProbe", encoding = "utf16le", nul = True))
        opened = machine.allocate(size = machine.pointer_size)
        equal(machine.call(machine.resolve_export("advapi32.dll", name = "RegOpenKeyExW"), args = [0x80000002, key, 0, 0x20019, opened]).value, 0)
        handle = machine.read_pointer(opened)
        output = machine.allocate(size = 48)
        needed = machine.allocate(value = b"Z" * 8)
        enumerate = machine.resolve_export("ntdll.dll", name = "NtEnumerateValueKey")
        high = 0x600000000000 if architecture == "amd64" else 0
        for capacity, status in [(0, 0xc0000023), (19, 0xc0000023), (20, 0x80000005), (33, 0x80000005), (34, 0), (48, 0)]:
            machine.write(output, b"Z" * 48)
            result = machine.call(enumerate, args = [handle, high, high | 1, output, high | capacity, needed])
            equal(result.reason, "return")
            equal(result.value, status)
            equal(machine.read_u32le(needed), 34)
            equal(machine.read(needed + 4, 4), b"ZZZZ")
            if capacity >= 20:
                equal([machine.read_u32le(output + offset) for offset in range(0, 20, 4)], [0, 3, 28, 6, 6])
            if capacity >= 34:
                equal(machine.read(output + 20, 6), binary.encode("abc", encoding = "utf16le"))
                equal(machine.read(output + 28, 6), b"123456")
            written = min(capacity, 34) if capacity >= 20 else 0
            equal(machine.read(output + written, 48 - written), b"Z" * (48 - written))
        for capacity, expected in [(0, 0xc0000023), (11, 0xc0000023), (12, 0x80000005), (18, 0)]:
            machine.write(output, b"Z" * 48)
            result = machine.call(enumerate, args = [handle, 0, 0, output, capacity, needed])
            equal(result.reason, "return")
            equal(result.value, expected)
            equal(machine.read_u32le(needed), 18)
            if capacity >= 12:
                equal([machine.read_u32le(output + offset) for offset in range(0, 12, 4)], [0, 3, 6])
            if capacity >= 18:
                equal(machine.read(output + 12, 6), binary.encode("abc", encoding = "utf16le"))
            written = min(capacity, 18) if capacity >= 12 else 0
            equal(machine.read(output + written, 48 - written), b"Z" * (48 - written))
        equal(machine.call(enumerate, args = [handle, 1, 1, output, 48, needed]).value, 0x8000001a)
        equal(machine.call(enumerate, args = [0x12345, 0, 1, output, 48, needed]).value, 0xc0000008)

def test_registry_key_name_cache_tracks_mutation_and_source_reload():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    def source(child):
        return windows.hive(windows.hive_from_patches("SOFTWARE", [{"key": "/Root/" + child, "name": "Value", "type": "REG_DWORD", "value": 1}]))
    registry = module["registry_plugin"](hives = {"SOFTWARE": source("Old")})
    target = ("SOFTWARE", "/Root")
    names = module["_direct_subkeys"](registry.state, target)
    equal(names, ["Old"])
    names.append("caller mutation")
    equal(module["_direct_subkeys"](registry.state, target), ["Old"])
    registry.set_value("SOFTWARE", "/Root/New", "Value", "REG_DWORD", 2)
    equal(module["_direct_subkeys"](registry.state, target), ["new", "Old"])
    equal(registry.delete_tree("SOFTWARE", "/Root/New"), 0)
    equal(module["_direct_subkeys"](registry.state, target), ["Old"])
    registry.state["sources"]["SOFTWARE"] = source("Replacement")
    registry.state["source_cache"].clear()
    equal(module["_direct_subkeys"](registry.state, target), ["Replacement"])
    registry.load_keys([{"hive": "SOFTWARE", "key": "/Root/New"}])
    equal(module["_direct_subkeys"](registry.state, target), ["new", "Replacement"])
    registry.reset()
    equal(module["_direct_subkeys"](registry.state, target), ["Replacement"])

def test_registry_deleted_ancestor_boundaries():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    identity = module["_key_identity"]
    deleted = module["_key_deleted"]
    state = {"deleted_keys": {identity("SOFTWARE", "/Branch"): True, identity("SOFTWARE", "/A%2fB"): True}}
    for hive, key, expected in [
        ("SOFTWARE", "/Branch", True),
        ("SOFTWARE", "/Branch/Child/Grandchild", True),
        ("SOFTWARE", "/Branchish/Child", False),
        ("SYSTEM", "/Branch/Child", False),
        ("SOFTWARE", "/", False),
        ("SOFTWARE", "/A%2fB/Child", True),
        ("SOFTWARE", "/A/B/Child", False),
        ("SOFTWARE", "/A%2fBC/Child", False),
    ]:
        equal(deleted(state, identity(hive, key)), expected)
    state["deleted_keys"][identity("SOFTWARE", "/").rstrip("/")] = True
    true(deleted(state, identity("SOFTWARE", "/")))
    true(deleted(state, identity("SOFTWARE", "/Unrelated/Child")))
    true(not deleted(state, identity("SYSTEM", "/Unrelated/Child")))

def test_registry_cached_information_after_many_source_deletions():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    source = windows.hive(windows.hive_from_patches("SOFTWARE", [
        {"key": "/Hot/Child" + str(1000 + i), "name": "Value", "type": "REG_DWORD", "value": i}
        for i in range(512)
    ]))
    for architecture in ["x86", "amd64"]:
        registry = module["registry_plugin"](hives = {"SOFTWARE": source})
        for i in range(0, 512, 2):
            equal(registry.delete_tree("SOFTWARE", "/Hot/Child" + str(1000 + i)), 0)
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(registry)
        path = machine.allocate(value = binary.encode("Hot", encoding = "utf16le", nul = True))
        opened = machine.allocate(size = machine.pointer_size)
        equal(machine.call(machine.resolve_export("kernelbase.dll", name = "RegOpenKeyExW"), args = [0x80000002, path, 0, 0x20019, opened]).value, 0)
        output = machine.allocate(value = b"Z" * 48)
        needed = machine.allocate(value = b"Z" * 8)
        result = machine.call(machine.resolve_export("ntdll.dll", name = "NtQueryKey"), args = [machine.read_pointer(opened), 4, output, 40, needed])
        equal((result.reason, result.value), ("return", 0))
        equal(machine.read_u32le(needed), 40)
        equal(machine.read(needed + 4, 4), b"ZZZZ")
        equal([machine.read_u32le(output + offset) for offset in range(8, 36, 4)], [0, 256, 18, 0, 0, 0, 6])
        equal(machine.read(output + 36, 12), b"Z" * 12)
        equal(registry.get_value("SOFTWARE", "/Hot/Child1000", "Value"), None)
        equal(registry.get_value("SOFTWARE", "/Hot/Child1001", "Value"), 1)

def test_registry_native_cached_key_information():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        registry = module["registry_plugin"](keys = [{"hive": "SOFTWARE", "key": "/NativeProbe/Child"}], values = [{"hive": "SOFTWARE", "key": "/NativeProbe", "name": "Current", "type": "REG_BINARY", "value": b"123456"}])
        machine.use(registry)
        key = machine.allocate(value = binary.encode("NativeProbe", encoding = "utf16le", nul = True))
        opened = machine.allocate(size = machine.pointer_size)
        equal(machine.call(machine.resolve_export("advapi32.dll", name = "RegOpenKeyExW"), args = [0x80000002, key, 0, 0x20019, opened]).value, 0)
        handle = machine.read_pointer(opened)
        output = machine.allocate(size = 48)
        needed = machine.allocate(value = b"Z" * 8)
        query = machine.resolve_export("ntdll.dll", name = "NtQueryKey")
        high = 0x600000000000 if architecture == "amd64" else 0
        for size, expected in [(0, 0xc0000023), (39, 0xc0000023), (40, 0), (48, 0)]:
            machine.write(output, b"Z" * 48)
            result = machine.call(query, args = [handle, high | 4, output, high | size, needed])
            equal(result.reason, "return")
            equal(result.value, expected)
            equal(machine.read_u32le(needed), 40)
            equal(machine.read(needed + 4, 4), b"ZZZZ")
            if expected:
                equal(machine.read(output, 48), b"Z" * 48)
            else:
                equal(machine.read_u64le(output), 0)
                equal([machine.read_u32le(output + offset) for offset in range(8, 36, 4)], [0, 1, 10, 1, 14, 6, 22])
                equal(machine.read(output + 36, 12), b"Z" * 12)
        equal(machine.call(query, args = [0x12345, 4, output, 48, needed]).value, 0xc0000008)
        result = machine.call(query, args = [handle, 3, output, 48, needed])
        equal(result.reason, "plugin")
        true("only KeyFullInformation and KeyCachedInformation" in result.detail)

def test_registry_native_set_value_effects():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        registry = module["registry_plugin"](keys = [{"hive": "SOFTWARE", "key": "/NativeProbe"}])
        machine.use(registry)
        key = machine.allocate(value = binary.encode("NativeProbe", encoding = "utf16le", nul = True))
        opened = machine.allocate(size = machine.pointer_size)
        equal(machine.call(machine.resolve_export("advapi32.dll", name = "RegOpenKeyExW"), args = [0x80000002, key, 0, 0x2001f, opened]).value, 0)
        handle = machine.read_pointer(opened)
        layout = abi["counted_string_layout"](machine.pointer_size)
        name = machine.allocate(size = layout["Size"])
        text = binary.encode("Version", encoding = "utf16le")
        machine.write_u16le(name, len(text))
        machine.write_u16le(name + 2, len(text))
        machine.write_pointer(name + layout["Buffer"], machine.allocate(value = text))
        set = machine.resolve_export("ntdll.dll", name = "NtSetValueKey")
        query = machine.resolve_export("ntdll.dll", name = "NtQueryValueKey")
        output = machine.allocate(size = 64)
        needed = machine.allocate(size = 4)
        high = 0x600000000000 if architecture == "amd64" else 0
        for kind, raw in [(3, b"\x00a\xffz"), (4, b"\x78\x56\x34\x12"), (1, b"A\x00\x00\x00"), (3, b"")]:
            source = machine.allocate(value = raw) if raw else 0
            result = machine.call(set, args = [handle, name, 0, high | kind, source, high | len(raw)])
            equal(result.reason, "return")
            equal(result.value, 0)
            equal(registry.patches()[-1]["name"], "Version")
            result = machine.call(query, args = [handle, name, 2, output, 64, needed])
            equal(result.value, 0)
            equal(machine.read_u32le(output + 4), kind)
            equal(machine.read_u32le(output + 8), len(raw))
            equal(machine.read(output + 12, len(raw)), raw)
        delete = machine.resolve_export("ntdll.dll", name = "NtDeleteValueKey")
        equal(machine.call(delete, args = [handle, name]).value, 0)
        true(registry.patches()[-1]["delete"])
        equal(machine.call(query, args = [handle, name, 2, output, 64, needed]).value, 0xc0000034)
        count = len(registry.patches())
        equal(machine.call(delete, args = [handle, name]).value, 0xc0000034)
        equal(machine.call(delete, args = [0x12345, name]).value, 0xc0000008)
        equal(len(registry.patches()), count)
        equal(machine.call(set, args = [0x12345, name, 0, 3, 0, 0]).value, 0xc0000008)
        equal(machine.call(set, args = [handle, name, 0, 3, 0, 1]).value, 0xc0000005)
        result = machine.call(set, args = [handle, name, 0, 1, machine.allocate(value = b"A\x00"), 2])
        equal(result.reason, "plugin")
        true("raw registry patches" in result.detail)
        equal(len(registry.patches()), count)

def test_registry_native_partial_value_query():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        registry = module["registry_plugin"](values = [{"hive": "SOFTWARE", "key": "/NativeProbe", "name": "Current", "type": "REG_DWORD", "value": 1}])
        machine.use(registry)
        key = machine.allocate(value = binary.encode("NativeProbe", encoding = "utf16le", nul = True))
        opened = machine.allocate(size = machine.pointer_size)
        equal(machine.call(machine.resolve_export("advapi32.dll", name = "RegOpenKeyExW"), args = [0x80000002, key, 0, 0x20019, opened]).value, 0)
        handle = machine.read_pointer(opened)
        layout = abi["counted_string_layout"](machine.pointer_size)
        name = machine.allocate(size = layout["Size"])
        text = binary.encode("cUrReNt", encoding = "utf16le")
        source = machine.allocate(value = text)
        machine.write_u16le(name, len(text))
        machine.write_u16le(name + 2, len(text))
        machine.write_pointer(name + layout["Buffer"], source)
        output = machine.allocate(size = 20)
        length = machine.allocate(size = 8)
        query = machine.resolve_export("ntdll.dll", name = "NtQueryValueKey")
        data = binary.builder()
        for value in [0, 4, 4, 1]: data.u32le(value)
        payload = data.bytes()
        for capacity, status, written in [(0, 0xc0000023, 0), (11, 0xc0000023, 0), (12, 0x80000005, 12), (14, 0x80000005, 14), (16, 0, 16), (20, 0, 16)]:
            machine.write(output, b"Z" * 20)
            machine.write(length, b"Z" * 8)
            size = capacity | (0x7fff00000000 if architecture == "amd64" else 0)
            result = machine.call(query, args = [handle, name, 2, output, size, length])
            equal(result.reason, "return")
            equal(result.value, status)
            equal(machine.read_u32le(length), 16)
            equal(machine.read(length + 4, 4), b"ZZZZ")
            equal(machine.read(output, written), payload[:written])
            equal(machine.read(output + written, 20 - written), b"Z" * (20 - written))
        machine.write_u16le(name, 0)  # Missing unnamed value, not named Current.
        machine.write(output, b"Z" * 20)
        equal(machine.call(query, args = [handle, name, 2, output, 20, length]).value, 0xc0000034)
        equal(machine.read(output, 20), b"Z" * 20)
        equal(machine.call(query, args = [0x12345, name, 2, output, 20, length]).value, 0xc0000008)
        result = machine.call(query, args = [handle, name, 1, output, 20, length])
        equal(result.reason, "plugin")
        true("information class 1" in result.detail)

def test_registry_native_enumerate_long_key_buffer():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        name = "longkey" * 16
        encoded = binary.encode(name, encoding = "utf16le")
        required = 16 + len(encoded)
        registry = module["registry_plugin"](keys = [{"hive": "SOFTWARE", "key": "/" + name}])
        machine.use(registry)
        # Predefined HKLM has other baseline children; locate our exact index.
        subkeys = module["_direct_subkeys"](registry.state, ("SOFTWARE", "/"))
        index = subkeys.index(name)
        target = machine.resolve_export("ntdll.dll", name = "NtEnumerateKey")
        output = machine.allocate(value = b"Z" * (required + 8))
        needed = machine.allocate(value = b"Y" * 8)
        upper = 0xfeed00000000 if architecture == "amd64" else 0
        for capacity, status in [(0, 0xc0000023), (15, 0xc0000023), (16, 0x80000005), (96, 0x80000005), (required, 0)]:
            machine.write(output, b"Z" * (required + 8))
            result = machine.call(target, args = [0x80000002, upper | index, upper, output, upper | capacity, needed])
            equal(result.reason, "return")
            equal(result.value, status)
            equal(machine.read_u32le(needed), required)
            equal(machine.read(needed + 4, 4), b"YYYY")
            if capacity < 16:
                equal(machine.read(output, required + 8), b"Z" * (required + 8))
            else:
                equal(machine.read_u32le(output + 12), len(encoded))
                equal(machine.read(output + 16, capacity - 16), encoded[:capacity - 16])
                equal(machine.read(output + capacity, required + 8 - capacity), b"Z" * (required + 8 - capacity))
        equal(registry.patches(), [])

def test_registry_native_delete_key_lifetime():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    for architecture in ["x86", "amd64"]:
        source = windows.hive(windows.hive_from_patches("SOFTWARE", [
            {"key": "/DeleteProbe/Leaf", "name": "", "type": "REG_SZ", "value": "old.inf"},
            {"key": "/DeleteProbe/Leaf", "name": "Other", "type": "REG_DWORD", "value": 7},
        ]))
        registry = module["registry_plugin"](hives = {"SOFTWARE": source})
        equal(registry.effects(), dict(keys=[], key_deletions=[], values=[], value_deletions=[]))
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(registry)
        if architecture == "amd64":
            registry.state["next_handle"] = 0x100010000
        layout = abi["object_attributes_layout"](machine.pointer_size)
        string = abi["counted_string_layout"](machine.pointer_size)
        descriptor = machine.allocate(size = string["Size"])
        obj = machine.allocate(size = layout["Size"])
        output = machine.allocate(value = b"Z" * (machine.pointer_size + 8))
        disposition = machine.allocate(value = b"Y" * 8)
        machine.write_u32le(obj, layout["Size"])
        machine.write_pointer(obj + layout["ObjectName"], descriptor)
        def name(value, parent = 0):
            raw = binary.encode(value, encoding = "utf16le")
            machine.write_u16le(descriptor, len(raw))
            machine.write_u16le(descriptor + 2, len(raw))
            machine.write_pointer(descriptor + string["Buffer"], machine.allocate(value = raw))
            machine.write_pointer(obj + layout["RootDirectory"], parent)
        def call(api, args):
            result = machine.call(machine.resolve_export("ntdll.dll", name = api), args = args)
            equal(result.reason, "return", result.detail)
            return result.value
        name(r"\Registry\Machine\SOFTWARE\DeleteProbe")
        equal(call("NtOpenKey", [output, 0x10000, obj]), 0)
        parent = machine.read_pointer(output)
        # Leaf deletion must not accidentally turn into recursive deletion.
        equal(call("NtDeleteKey", [parent]), 0xc0000121)
        equal(registry.patches(), [])
        name("Leaf", parent)
        handles = []
        for access in [0x20019, 0x10000, 0x10000]:
            upper = 0xface00000000 if architecture == "amd64" else 0
            equal(call("NtOpenKey", [output, upper | access, obj]), 0)
            handles.append(machine.read_pointer(output))
            equal(machine.read(output + machine.pointer_size, 8), b"Z" * 8)
        reader, deleter, second = handles
        equal(call("NtDeleteKey", [0]), 0xc0000008)
        equal(call("NtDeleteKey", [0x80000002]), 0xc0000008)
        equal(call("NtDeleteKey", [reader]), 0xc0000022)
        equal(registry.patches(), [])
        equal(call("NtDeleteKey", [deleter]), 0)
        equal(call("NtDeleteKey", [second]), 0)
        equal([p["key"].lower() for p in registry.key_deletions()], ["/deleteprobe/leaf"])
        equal(len(registry.patches()), 2)
        true(all([p.get("delete", False) for p in registry.patches()]))
        equal(registry.get_value("SOFTWARE", "/DeleteProbe/Leaf", ""), None)
        equal(module["_direct_subkeys"](registry.state, ("SOFTWARE", "/DeleteProbe")), [])
        equal(sorted(registry.state["deleted_handles"]), sorted(handles))
        # No automatic close: every original key reference is still owned.
        true(all([registry.state["handles"][h] != None for h in handles]))
        machine.write(output, b"Z" * (machine.pointer_size + 8))
        equal(call("NtOpenKey", [output, 0x20019, obj]), 0xc0000034)
        equal(machine.read(output, machine.pointer_size + 8), b"Z" * (machine.pointer_size + 8))
        for api, args in [
            ("NtQueryKey", [reader, 4, output, 40, disposition]),
            ("NtQueryValueKey", [reader, descriptor, 2, output, 40, disposition]),
            ("NtEnumerateKey", [reader, 0, 0, output, 40, disposition]),
            ("NtEnumerateValueKey", [reader, 0, 0, output, 40, disposition]),
            ("NtSetValueKey", [reader, descriptor, 0, 4, disposition, 4]),
            ("NtDeleteValueKey", [reader, descriptor]),
        ]:
            equal(call(api, args), 0xc000017c)
        equal(machine.read(output, machine.pointer_size + 8), b"Z" * (machine.pointer_size + 8))
        equal(machine.read(disposition, 8), b"Y" * 8)
        name("Child", reader)
        equal(call("NtOpenKey", [output, 0x20019, obj]), 0xc000017c)
        equal(call("NtCreateKey", [output, 0x10000, obj, 0, 0, 0, disposition]), 0xc000017c)
        # Creating by the live parent's name creates a distinct empty object;
        # old references must not alias it and lazy source data must stay gone.
        name("Leaf", parent)
        equal(call("NtCreateKey", [output, 0x10000, obj, 0, 0, 0, disposition]), 0)
        fresh = machine.read_pointer(output)
        equal(machine.read_u32le(disposition), 1)
        equal(machine.read(disposition + 4, 4), b"YYYY")
        equal(module["_direct_values"](registry.state, ("SOFTWARE", "/DeleteProbe/Leaf")), [])
        registry.set_value("SOFTWARE", "/DeleteProbe/Leaf", "New", "REG_DWORD", 9)
        equal(call("NtDeleteKey", [deleter]), 0)
        equal(registry.get_value("SOFTWARE", "/DeleteProbe/Leaf", "New"), 9)
        captured = registry.effects()
        equal(captured["values"], [dict(hive="SOFTWARE", key="/DeleteProbe/Leaf", name="New", type=4, value=binary.u32le(9))])
        equal([p["name"].lower() for p in captured["value_deletions"]], ["(default)", "other"])
        # Recreated names lose their live tombstone, not the source-removal
        # event required by offline effect consumers. Stale handles add none.
        equal([p["key"].lower() for p in registry.key_deletions()], ["/deleteprobe/leaf"])
        query = machine.resolve_export("advapi32.dll", name = "RegQueryValueExW")
        equal(machine.call(query, args = [reader, 0, 0, 0, 0, 0]).value, 1018)
        close = machine.resolve_export("advapi32.dll", name = "RegCloseKey")
        for handle in handles:
            equal(machine.call(close, args = [handle]).value, 0)
            equal(call("NtDeleteKey", [handle]), 0xc0000008)
        equal(registry.state["deleted_handles"], {})
        offsets = (len(registry.patches()), len(registry.key_deletions()))
        equal(call("NtDeleteKey", [fresh]), 0)
        scoped = registry.effects(patch_start=offsets[0], key_deletion_start=offsets[1])
        equal(scoped["values"], [])
        equal([p["name"] for p in scoped["value_deletions"]], ["new"])
        equal(len(scoped["key_deletions"]), 1)
        raises(registry.effects, kwargs={"patch_start":len(registry.patches())+1}, message="offset is out of bounds")
        equal([p["key"].lower() for p in registry.key_deletions()], ["/deleteprobe/leaf", "/deleteprobe/leaf"])
        equal(registry.get_value("SOFTWARE", "/DeleteProbe/Leaf", "New"), None)
        equal(registry.effects()["values"], [])
        # Reports own their outer records; later deletion must not change a
        # captured value or make the historical New=9 write survive today.
        equal(captured["values"][0]["value"], binary.u32le(9))
        # An empty source namespace produces no value patches at all; its
        # actual deletion still has to reach the image-effect consumer.
        registry.load_keys([{"hive": "SOFTWARE", "key": "/ExportEmpty"}])
        patch_count = len(registry.patches())
        name(r"\Registry\Machine\SOFTWARE\ExportEmpty")
        equal(call("NtOpenKey", [output, 0x10000, obj]), 0)
        empty_handle = machine.read_pointer(output)
        equal(call("NtDeleteKey", [empty_handle]), 0)
        equal(len(registry.patches()), patch_count)
        equal(registry.key_deletions()[-1]["key"].lower(), "/exportempty")
        equal(machine.call(close, args=[empty_handle]).value, 0)
        registry.reset()
        equal(registry.key_deletions(), [])
        equal(registry.state["deleted_handles"], {})
        equal(registry.state["handle_access"], {})
        equal(registry.get_value("SOFTWARE", "/DeleteProbe/Leaf", ""), "old.inf")

def test_registry_creation_security_provider():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    descriptor = windows.compile_sddl("O:SYG:SYD:P(A;;KA;;;SY)")
    for architecture in ["x86", "amd64"]:
        for native in [False, True]:
            for complete in [False, True]:
                requests = []
                def provider(machine, request):
                    requests.append(dict(request))
                    return {key:descriptor for key in request["missing_keys"]} if complete else {}
                registry = module["registry_plugin"](on_create_key=provider)
                machine = emulator.machine(code=b"\xc3", architecture=architecture)
                machine.use(registry)
                output = machine.allocate(value=b"Z" * (machine.pointer_size+8))
                disposition = machine.allocate(value=b"Y" * 8)
                if native:
                    layout = abi["object_attributes_layout"](machine.pointer_size)
                    string = abi["counted_string_layout"](machine.pointer_size)
                    raw = binary.encode(chr(92)+"Registry"+chr(92)+"Machine"+chr(92)+"SOFTWARE"+chr(92)+"Created"+chr(92)+"Child", encoding="utf16le")
                    name = machine.allocate(size=string["Size"])
                    machine.write_u16le(name,len(raw))
                    machine.write_u16le(name+2,len(raw))
                    machine.write_pointer(name+string["Buffer"],machine.allocate(value=raw))
                    obj = machine.allocate(size=layout["Size"])
                    machine.write_u32le(obj,layout["Size"])
                    machine.write_pointer(obj+layout["ObjectName"],name)
                    address = machine.resolve_export("ntdll.dll",name="NtCreateKey")
                    result = machine.call(address,args=[output,0xf003f,obj,0,0,0,disposition])
                else:
                    key = machine.allocate(value=binary.encode("SOFTWARE"+chr(92)+"Created"+chr(92)+"Child",encoding="utf16le",nul=True))
                    address = machine.resolve_export("advapi32.dll",name="RegCreateKeyExW")
                    result = machine.call(address,args=[0x80000002,key,0,0,0,0xf003f,0,output,disposition])
                equal(len(requests),1)
                equal(requests[0]["missing_keys"],["/Created","/Created/Child"])
                equal(requests[0]["creator_security"],0)
                if not complete:
                    equal(result.reason,"plugin")
                    equal(registry.effects(),dict(keys=[],key_deletions=[],values=[],value_deletions=[]))
                    equal(machine.read(output,machine.pointer_size+8),b"Z"*(machine.pointer_size+8))
                    equal(machine.read(disposition,8),b"Y"*8)
                    continue
                equal(result.reason,"return",result.detail)
                equal(result.value,0)
                equal(machine.read_u32le(disposition),1)
                equal(machine.read(disposition+4,4),b"YYYY")
                equal(machine.read(output+machine.pointer_size,8),b"Z"*8)
                equal([(key["key"],key["security"]) for key in registry.effects()["keys"]],[("/Created",descriptor),("/Created/Child",descriptor)])
                close = machine.resolve_export("advapi32.dll",name="RegCloseKey")
                equal(machine.call(close,args=[machine.read_pointer(output)]).value,0)

def test_registry_win32_delete_key_ex_lifetime():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    for architecture in ["x86", "amd64"]:
        for suffix, encoding in [("W", "utf16le"), ("A", "ascii")]:
            source = windows.hive(windows.hive_from_patches("SOFTWARE", [
                {"key": "/DeleteApi/Leaf", "name": "Old", "type": "REG_DWORD", "value": 17},
                {"key": "/DeleteApi/Parent/Child", "name": "Keep", "type": "REG_DWORD", "value": 23},
            ]))
            registry = module["registry_plugin"](hives = {"SOFTWARE": source})
            machine = emulator.machine(code = b"\xc3", architecture = architecture)
            machine.use(registry)
            if architecture == "amd64":
                registry.state["next_handle"] = 0x100010000
            def text(value):
                return machine.allocate(value = binary.encode(value, encoding = encoding, nul = True))
            def call(api, args):
                result = machine.call(machine.resolve_export("api-ms-win-core-registry-l1-1-0.dll", name = api), args = args)
                equal(result.reason, "return", result.detail)
                return result.value
            output = machine.allocate(value = b"Z" * (machine.pointer_size + 8))
            equal(call("RegOpenKeyEx" + suffix, [0x80000002, text("SOFTWARE" + chr(92) + "DeleteApi"), 0, 0x20019, output]), 0)
            parent = machine.read_pointer(output)
            # hKey need not have DELETE access: the target is opened separately.
            equal(call("RegOpenKeyEx" + suffix, [parent, text("Leaf"), 0, 0x20019, output]), 0)
            reader = machine.read_pointer(output)
            equal(machine.read(output + machine.pointer_size, 8), b"Z" * 8)
            flush = machine.resolve_export("ntdll.dll", name="NtFlushKey")
            equal(machine.call(flush,args=[reader]).value,0)
            equal(len(registry.state["flushes"]),1)
            equal(machine.call(flush,args=[123]).value,0xc0000008)
            equal(len(registry.state["flushes"]),1)
            deleted = machine.resolve_export("advapi32.dll", name = "RegDeleteKeyEx" + suffix)
            leaf = text("Leaf")
            high = 0xfeed00000000 if architecture == "amd64" else 0
            native_view = 0x100 if architecture == "amd64" else 0x200
            for key, desired, reserved, expected in [(parent, 0, 1, 87), (parent, 0x300, 0, 87), (0, 0, 0, 6)]:
                result = machine.call(deleted, args = [key, leaf, high | desired, high | reserved])
                equal(result.reason, "return", result.detail)
                equal(result.value, expected)
                equal(registry.patches(), [])
            equal(call("RegDeleteKeyEx" + suffix, [parent, 0, 0, 0]), 87)
            alternate = 0x200 if architecture == "amd64" else 0x100
            result = machine.call(deleted, args = [parent, leaf, alternate, 0])
            true(result.reason != "return")
            true("alternate registry views" in result.detail)
            equal(registry.patches(), [])
            for api in ["RegDeleteKeyEx" + suffix, "RegDeleteKey" + suffix]:
                args = [parent, text("Parent")]
                if "Ex" in api:
                    args += [0, 0]
                equal(call(api, args), 5)
                equal(registry.get_value("SOFTWARE", "/DeleteApi/Parent/Child", "Keep"), 23)
                equal(registry.patches(), [])
            equal(call("RegDeleteKeyEx" + suffix, [parent, leaf, high | native_view, high]), 0)
            equal(len(registry.patches()), 1)
            true(registry.patches()[0]["delete"])
            equal(registry.get_value("SOFTWARE", "/DeleteApi/Leaf", "Old"), None)
            true(reader in registry.state["deleted_handles"])
            true(registry.state["handles"][reader] != None)
            equal(machine.call(flush,args=[reader]).value,0xc000017c)
            equal(len(registry.state["flushes"]),1)
            equal(call("RegQueryValueEx" + suffix, [reader, 0, 0, 0, 0, 0]), 1018)
            equal(call("RegDeleteKeyEx" + suffix, [parent, leaf, 0, 0]), 2)
            machine.write(output, b"Z" * (machine.pointer_size + 8))
            equal(call("RegOpenKeyEx" + suffix, [parent, leaf, 0, 0x20019, output]), 2)
            equal(machine.read(output, machine.pointer_size + 8), b"Z" * (machine.pointer_size + 8))
            equal(call("RegCreateKeyEx" + suffix, [parent, leaf, 0, 0, 0, 0x20019, 0, output, 0]), 0)
            fresh = machine.read_pointer(output)
            equal(registry.get_value("SOFTWARE", "/DeleteApi/Leaf", "Old"), None)
            registry.set_value("SOFTWARE", "/DeleteApi/Leaf", "New", "REG_DWORD", 31)
            equal(call("RegDeleteKeyEx" + suffix, [reader, text("Child"), 0, 0]), 1018)
            equal(registry.get_value("SOFTWARE", "/DeleteApi/Leaf", "New"), 31)
            equal(call("RegCloseKey", [reader]), 0)
            # Empty (but non-NULL) names reopen/delete the hKey itself.
            # This must retain the same stale-object lifetime and must not
            # require DELETE on the original read-only handle.
            equal(call("RegDeleteKeyEx" + suffix, [fresh, text(""), high | native_view, high]), 0)
            equal(call("RegQueryValueEx" + suffix, [fresh, 0, 0, 0, 0, 0]), 1018)
            equal(call("RegCreateKeyEx" + suffix, [parent, leaf, 0, 0, 0, 0x20019, 0, output, 0]), 0)
            second = machine.read_pointer(output)
            equal(call("RegDeleteKey" + suffix, [second, text("")]), 0)
            equal(call("RegQueryValueEx" + suffix, [second, 0, 0, 0, 0, 0]), 1018)
            equal(call("RegDeleteKey" + suffix, [parent, text("")]), 5)
            equal(call("RegDeleteKeyEx" + suffix, [0x80000002, text(""), 0, 0]), 5)
            equal(call("RegCloseKey", [second]), 0)
            equal(call("RegCloseKey", [fresh]), 0)
            equal(call("RegCloseKey", [parent]), 0)

def test_registry_native_object_pointer_width():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        registry = module["registry_plugin"](keys = [{"hive": "SYSTEM", "key": "/NativeProbe/Child"}])
        machine.use(registry)
        string = abi["counted_string_layout"](machine.pointer_size)
        attributes = abi["object_attributes_layout"](machine.pointer_size)
        descriptor = machine.allocate(size = string["Size"])
        obj = machine.allocate(size = attributes["Size"])
        output = machine.allocate(size = machine.pointer_size + 4)
        machine.write_u32le(obj, attributes["Size"])
        machine.write_pointer(obj + attributes["ObjectName"], descriptor)
        parent = 0
        # Counted names deliberately have no NUL terminator. AMD64 allocations
        # are above 4 GiB, exposing either descriptor or object truncation.
        for name, api in [("\\Registry\\Machine\\SYSTEM\\NativeProbe", "NtOpenKey"), ("Child", "NtOpenKeyEx")]:
            text = binary.encode(name, encoding = "utf16le")
            source = machine.allocate(value = text)
            machine.write_u16le(descriptor, len(text))
            machine.write_u16le(descriptor + 2, len(text))
            machine.write_pointer(descriptor + string["Buffer"], source)
            machine.write_pointer(obj + attributes["RootDirectory"], parent)
            machine.write(output, b"Z" * (machine.pointer_size + 4))
            args = [output, 0x20019, obj] + ([0] if api == "NtOpenKeyEx" else [])
            result = machine.call(machine.resolve_export("ntdll.dll", name = api), args = args)
            equal(result.reason, "return")
            equal(result.value, 0)
            equal(machine.read(output + machine.pointer_size, 4), b"ZZZZ")
            parent = machine.read_pointer(output)
        equal(registry.opens()[-1]["hive"], "SYSTEM")
        equal(registry.opens()[-1]["key"].lower(), "/nativeprobe/child")
        # Native driver-store code reopens an existing control set with an
        # empty relative name. The seventh argument, not the sixth, receives
        # the disposition; DWORD options may have stale Win64 upper bits.
        machine.write_pointer(obj + attributes["RootDirectory"], parent)
        machine.write_u16le(descriptor, 0)
        disposition = machine.allocate(size = 8, value = b"ZZZZZZZZ")
        options = 0x600000000000 if architecture == "amd64" else 0
        created = machine.call(machine.resolve_export("ntdll.dll", name = "NtCreateKey"), args = [output, 0x2001f, obj, 0, 0, options, disposition])
        equal(created.reason, "return")
        equal(created.value, 0)
        equal(machine.read_u32le(disposition), 2)
        equal(machine.read(disposition + 4, 4), b"ZZZZ")
        equal(registry.keys(), [])
        # OPEN_LINK must also open an ordinary key itself. Upper slot bits
        # are not options. The handle must retain this exact root-relative key.
        machine.write(output, b"Z" * (machine.pointer_size + 4))
        result = machine.call(machine.resolve_export("ntdll.dll", name = "NtOpenKeyEx"), args = [output, 0x20019, obj, options | 8])
        equal(result.reason, "return")
        equal(result.value, 0)
        equal(registry.state["handles"][machine.read_pointer(output)], registry.state["handles"][parent])
        equal(machine.read(output + machine.pointer_size, 4), b"ZZZZ")
        before = dict(registry.state["handles"])
        machine.write(output, b"Z" * (machine.pointer_size + 4))
        result = machine.call(machine.resolve_export("ntdll.dll", name = "NtOpenKeyEx"), args = [output, 0x20019, obj, 16])
        equal(result.reason, "plugin")
        true("unsupported open options" in result.detail)
        equal(registry.state["handles"], before)
        equal(machine.read(output, machine.pointer_size + 4), b"Z" * (machine.pointer_size + 4))

def test_registry_plugin_publishes_late_bound_exports():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["registry_plugin"]()])
    true(machine.resolve_export("advapi32.dll", name = "RegEnumValueW") != 0)
    true(machine.resolve_export("kernel32.dll", name = "RegOpenKeyExW") != 0)
    query = machine.resolve_export("api-ms-win-core-registry-l1-1-0.dll", name = "RegQueryValueExW")
    true(query != 0)
    equal(machine.call(query, args = [0x80000001, 0, 0, 0, 0, 0]).value, 2)
    true(machine.resolve_export("ntdll.dll", name = "NtEnumerateKey") != 0)
    true(machine.resolve_export("shlwapi.dll", name = "SHRegGetValueW") != 0)
    true(machine.resolve_export("shlwapi.dll", ordinal = 128) != 0)

def test_registry_set_key_value_uses_existing_subkey_and_win64_dwords():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    machine = emulator.machine(code = b"\xc3", architecture = "amd64")
    registry = module["registry_plugin"](keys = [{"hive": "DEFAULT", "key": "/Software/Example"}])
    machine.use([registry])
    subkey = machine.allocate(value = binary.encode(r"Software\Example", encoding = "utf16le", nul = True))
    missing = machine.allocate(value = binary.encode(r"Software\Missing", encoding = "utf16le", nul = True))
    name = machine.allocate(value = binary.encode("Enabled", encoding = "utf16le", nul = True))
    data = machine.allocate(value = binary.u32le(1))
    target = machine.resolve_export("advapi32.dll", name = "RegSetKeyValueW")
    equal(machine.call(target, args = [0x80000001, subkey, name, 0x1234567800000004, data, 0xabcdef0000000004]).value, 0)
    equal(registry.get_value("DEFAULT", "/Software/Example", "Enabled"), 1)
    equal(machine.call(target, args = [0x80000001, missing, name, 4, data, 4]).value, 2)
    shell_name = machine.allocate(value = binary.encode("ShellEnabled", encoding = "utf16le", nul = True))
    shell_set = machine.resolve_export("shlwapi.dll", name = "SHSetValueW")
    equal(machine.call(shell_set, args = [0x80000001, subkey, shell_name, 0x1234567800000004, data, 0x7fff00000004]).value, 0)
    equal(registry.get_value("DEFAULT", "/Software/Example", "ShellEnabled"), 1)
    equal(len(registry.patches()), 2)

def test_registry_provider_recognizes_api_set_contracts():
    provider = testing.module("@stdlib//windows/selfreg:registry.star")["_registry_provider_module"]
    true(provider("advapi32.dll"))
    true(provider("API-MS-WIN-CORE-REGISTRY-L1-1-0.DLL"))
    true(provider("ext-ms-win-advapi32-registry-l1-1-0.dll"))
    true(not provider("api-ms-win-core-sysinfo-l1-1-0.dll"))
    true(not provider("vendor.dll"))

def test_registry_plugin_reads_source_hives_lazily():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    source = windows.hive(windows.hive_from_patches("SOFTWARE", [
        {"key": "/Source", "name": "Path", "type": "REG_EXPAND_SZ", "value": "%SystemRoot%\\Source"},
        {"key": "/Source/Child", "name": "Count", "type": "REG_DWORD", "value": 7},
    ]))
    record = source.find("/Source").value_records["Path"]
    equal(record.type, 2)
    equal(record.raw, binary.encode("%SystemRoot%\\Source", encoding = "utf16le", nul = True))
    registry = module["registry_plugin"](hives = {"SOFTWARE": source})
    equal(registry.get_value("SOFTWARE", "/Source", "Path"), "%SystemRoot%\\Source")
    equal(module["_direct_subkeys"](registry.state, ("SOFTWARE", "/Source")), ["Child"])
    registry.set_value("SOFTWARE", "/Source", "Path", "REG_SZ", "overridden")
    equal(registry.get_value("SOFTWARE", "/Source", "Path"), "overridden")
    registry.set_value("SOFTWARE", "/Source", "", "REG_SZ", "default")
    equal(registry.get_value("SOFTWARE", "/Source", "(default)"), "default")
    equal(registry.patches()[-1]["name"], "(default)")
    equal(registry.delete_value("SOFTWARE", "/Source/Child", "Count"), 0)
    equal(registry.get_value("SOFTWARE", "/Source/Child", "Count"), None)

def test_registry_structured_key_parts_preserve_literal_slashes():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    parts = ["Plugins", "Objects", "vendor:format/algorithm/sample/4.0"]
    registry = module["registry_plugin"](values = [{
        "hive": "SOFTWARE",
        "key": "/Plugins/Objects/vendor:format/algorithm/sample/4.0",
        "key_parts": parts,
        "name": "ModuleId",
        "type": "REG_SZ",
        "value": "module",
    }])
    encoded = module["_key_from_parts"](parts)
    equal(module["_display_key"](encoded), "/Plugins/Objects/vendor:format/algorithm/sample/4.0")
    equal(module["_direct_subkeys"](registry.state, ("SOFTWARE", "/Plugins/Objects")), ["vendor:format/algorithm/sample/4.0"])
    equal(module["_join_key"](("SOFTWARE", "/Plugins/Objects"), "vendor:format/algorithm/sample/4.0"), ("SOFTWARE", encoded))
    equal(registry.get_value("SOFTWARE", encoded, "ModuleId"), "module")


def test_registry_native_absolute_names_keep_literal_slashes():
    module=testing.module("@stdlib//windows/selfreg:registry.star")
    abi=testing.module("@stdlib//windows/emulation:abi.star")
    for architecture in ["x86","amd64"]:
        machine=emulator.machine(code=b"\xc3",architecture=architecture)
        paths=[(["Root","Hash/Leaf="],11),(["Root","Hash","Leaf="],22),(["Mount/Offline","Hash/Leaf="],33),(["Mount","Offline","Hash","Leaf="],44)]
        source=windows.hive_from_patches("SOFTWARE",[dict(key_parts=parts,name="Marker",type="REG_DWORD",value=value) for parts,value in paths])
        registry=module["registry_plugin"](hives={"SOFTWARE":windows.hive(source)})
        machine.use(registry)
        width=machine.pointer_size
        string=abi["counted_string_layout"](width)
        attributes=abi["object_attributes_layout"](width)
        descriptor=machine.allocate(size=string["Size"])
        obj=machine.allocate(size=attributes["Size"])
        machine.write_u32le(obj,attributes["Size"])
        machine.write_pointer(obj+attributes["ObjectName"],descriptor)
        output=machine.allocate(size=width+4)
        name=machine.allocate(value=binary.encode("Marker",encoding="utf16le",nul=True))
        size=machine.allocate(value=binary.u32le(4))
        data=machine.allocate(size=4)
        native_open=machine.resolve_export("ntdll.dll",name="NtOpenKey")
        query=machine.resolve_export("advapi32.dll",name="RegQueryValueExW")
        slash=chr(92)
        for relative,expected in [("SOFTWARE"+slash+"Root"+slash+"Hash/Leaf=",11),("SOFTWARE"+slash+"Root"+slash+"Hash"+slash+"Leaf=",22),("Mount/Offline"+slash+"Hash/Leaf=",33),("Mount"+slash+"Offline"+slash+"Hash"+slash+"Leaf=",44)]:
            text=binary.encode(slash+"Registry"+slash+"Machine"+slash+relative,encoding="utf16le")
            pointer=machine.allocate(value=text)
            machine.write_u16le(descriptor,len(text))
            machine.write_u16le(descriptor+2,len(text))
            machine.write_pointer(descriptor+string["Buffer"],pointer)
            machine.write(output,b"Z"*(width+4))
            result=machine.call(native_open,args=[output,0x20019,obj])
            equal(result.reason,"return",result.detail)
            equal(result.value,0)
            equal(machine.read(output+width,4),b"ZZZZ")
            handle=machine.read_pointer(output)
            machine.write_u32le(size,4)
            equal(machine.call(query,args=[handle,name,0,0,data,size]).value,0)
            equal(machine.read_u32le(data),expected)
        # Unix-looking display paths are not native object-manager paths.
        text=binary.encode("/Registry/Machine/SOFTWARE/Root/Hash/Leaf=",encoding="utf16le")
        pointer=machine.allocate(value=text)
        machine.write_u16le(descriptor,len(text))
        machine.write_u16le(descriptor+2,len(text))
        machine.write_pointer(descriptor+string["Buffer"],pointer)
        machine.write(output,b"Z"*(width+4))
        equal(machine.call(native_open,args=[output,0x20019,obj]).value,0xc0000034)
        equal(machine.read(output,width+4),b"Z"*(width+4))


def test_registry_initial_keys_are_baseline_state():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    registry = module["registry_plugin"](keys = [{
        "hive": "SOFTWARE",
        "key": "/Microsoft/Setup/Empty",
    }])
    equal(registry.keys(), [])
    equal(registry.state["flushes"], [])
    machine = emulator.x86(code = b"\xc3")
    machine.use([registry])
    appid = machine.allocate(value = binary.encode("AppID", encoding = "utf16le", nul = True))
    output = machine.allocate(size = 4)
    opened = machine.call(machine.resolve_export("advapi32.dll", name = "RegOpenKeyExW"), args = [0x80000000, appid, 0, 0x20019, output])
    equal(opened.value, 0)
    true(machine.read_u32le(output) != 0)
    equal(registry.keys(), [])

def test_registry_predefined_root_override_redirects_operations():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    registry = module["registry_plugin"]()
    machine = emulator.x86(code = b"\xc3")
    machine.use([registry])
    redirected = machine.allocate(value = binary.encode("Redirected", encoding = "utf16le", nul = True))
    redirected_handle = machine.allocate(size = 4)
    create = machine.resolve_export("advapi32.dll", name = "RegCreateKeyW")
    equal(machine.call(create, args = [0x80000002, redirected, redirected_handle]).value, 0)
    override = machine.resolve_export("advapi32.dll", name = "RegOverridePredefKey")
    equal(machine.call(override, args = [0x80000000, machine.read_u32le(redirected_handle)]).value, 0)
    child = machine.allocate(value = binary.encode("Sample", encoding = "utf16le", nul = True))
    child_handle = machine.allocate(size = 4)
    equal(machine.call(create, args = [0x80000000, child, child_handle]).value, 0)
    true({"hive": "SOFTWARE", "key": "/Redirected/Sample"} in registry.keys())
    equal(machine.call(override, args = [0x80000000, 0]).value, 0)

def test_registry_can_emit_folded_key_spelling():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    registry = module["registry_plugin"](output_key_case = "folded")
    registry.set_value("SYSTEM", "/Mixed/ABC-1", "", "REG_BINARY", b"value")
    equal(registry.patches()[0]["key"], "/mixed/abc-1")

def test_registry_initial_values_preserve_patch_semantics():
    registry = testing.module("@stdlib//windows/selfreg:registry.star")["registry_plugin"](values = [
        {
            "hive": "SOFTWARE",
            "key": "/Microsoft/Windows NT/CurrentVersion/Svchost",
            "name": "netsvcs",
            "type": "REG_MULTI_SZ",
            "value": ["EventSystem", "Netman", "winmgmt"],
        },
        {
            "hive": "SOFTWARE",
            "key": "/Microsoft/Windows NT/CurrentVersion/Svchost",
            "name": "netsvcs",
            "type": "REG_MULTI_SZ",
            "value": ["WinMgmt", "wuauserv"],
            "append": True,
        },
        {
            "hive": "SOFTWARE",
            "key": "/Example",
            "name": "Existing",
            "type": "REG_SZ",
            "value": "first",
        },
        {
            "hive": "SOFTWARE",
            "key": "/Example",
            "name": "Existing",
            "type": "REG_SZ",
            "value": "ignored",
            "if_absent": True,
        },
        {
            "hive": "SOFTWARE",
            "key": "/Example",
            "name": "Missing",
            "type": "REG_SZ",
            "value": "ignored",
            "overwrite_only": True,
        },
        {
            "hive": "SOFTWARE",
            "key": "/Example",
            "name": "Existing",
            "type": "REG_SZ",
            "value": "",
            "delete": True,
        },
    ])
    equal(
        registry.get_value("SOFTWARE", "/Microsoft/Windows NT/CurrentVersion/Svchost", "netsvcs"),
        ["EventSystem", "Netman", "winmgmt", "wuauserv"],
    )
    equal(registry.get_value("SOFTWARE", "/Example", "Existing"), None)
    equal(registry.get_value("SOFTWARE", "/Example", "Missing"), None)
    equal(registry.patches(), [])

def test_registry_system_root_routing():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    join_key = module["_join_key"]
    equal(join_key(("SOFTWARE", "/"), "SYSTEM\\CurrentControlSet\\Services\\Example"), ("SYSTEM", "/ControlSet001/Services/Example"))
    equal(join_key(("SOFTWARE", "/"), "SOFTWARE\\Classes\\Example"), ("SOFTWARE", "/Classes/Example"))
    equal(module["registry_plugin"]().opens(), [])
    equal(module["_CALLS"]["regnotifychangekeyvalue"], 5)
    equal(module["_CALLS"]["regflushkey"], 1)
    equal(module["_CALLS"]["regsetvaluea"], 5)
    equal(module["_CALLS"]["regsetvaluew"], 5)

def test_automation_type_library_resource_paths():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    libraries = {
        "c:\\windows\\system32\\vbscript.dll": "module",
        "c:\\windows\\system32\\standalone.tlb": "library",
    }
    resolve = module["_resolve_type_library_path"]
    equal(resolve("C:/WINDOWS/system32/vbscript.dll/2", libraries), "c:\\windows\\system32\\vbscript.dll")
    equal(resolve("C:\\WINDOWS\\system32\\standalone.tlb", libraries), "c:\\windows\\system32\\standalone.tlb")
    equal(resolve("C:\\WINDOWS\\system32\\vbscript.dll\\TYPELIB", libraries), None)
    equal(resolve("C:\\WINDOWS\\system32\\missing.dll\\2", libraries), None)

def test_advanced_inf_command_and_registry_adapters():
    module = testing.module("@stdlib//windows:installer.star")
    select_root = module["_advanced_inf_platform_root"]
    controller_roots = ["NEC_WIN98_INSTALL", "WIN98_INSTALL", "NEC_WIN95_INSTALL", "WIN95_INSTALL", "WINNT50_INSTALL"]
    equal(select_root(controller_roots, {"platform_id": 1, "major": 4, "minor": 10}), "WIN98_INSTALL")
    equal(select_root(controller_roots, {"platform_id": 1, "major": 4, "minor": 0}), "WIN95_INSTALL")
    equal(select_root(controller_roots, {"platform_id": 2, "major": 5, "minor": 0}), "WINNT50_INSTALL")
    equal(select_root(["ProductInstall"], {"platform_id": 1, "major": 4, "minor": 10}), "ProductInstall")
    raises(
        select_root,
        args = [["FirstInstall", "SecondInstall"], {"platform_id": 1, "major": 4, "minor": 10}],
        message = "no unique install root",
    )
    equal(module["_advanced_inf_unquote"]("'%24%\\Program Files'"), r"%24%\Program Files")
    equal(module["_advanced_inf_unquote"]('"quoted"'), "quoted")
    equal(module["_advanced_inf_unquote"]("developer's tools"), "developer's tools")
    equal(module["_advanced_inf_unquote"]("'unbalanced"), "'unbalanced")
    equal(module["_advanced_inf_csv"]('"Microsoft Chat", "C:\\Program Files\\Microsoft Chat\\CChat.exe"'), [
        "Microsoft Chat",
        r"C:\Program Files\Microsoft Chat\CChat.exe",
    ])
    per_user = module["_advanced_inf_per_user_modifications"]({
        "DisplayName": ["Microsoft Chat 2.5"],
        "ComponentID": ["comicchat"],
        "GUID": ["{44BBA844-CC51-11CF-AAFA-00AA00B6015C}"],
        "Version": ["4", "71", "2302", "0"],
        "Locale": ["EN"],
        "IsInstalled": ["1"],
        "StubPath": ["rundll32.exe advpack.dll", "LaunchINFSection %17%\\CChat25.inf", "PerUserAdd"],
    }, {"17": r"C:\WINDOWS\INF"}, {})
    equal(len(per_user), 6)
    per_user_values = {item["name"]: item["value"] for item in per_user}
    equal(per_user_values["(default)"], "Microsoft Chat 2.5")
    equal(per_user_values["Version"], "4,71,2302,0")
    equal(per_user_values["StubPath"], r"rundll32.exe advpack.dll,LaunchINFSection C:\WINDOWS\INF\CChat25.inf,PerUserAdd")
    equal(per_user_values["IsInstalled"], 1)
    links = windows.inf(r'''[Links]
setup.ini,progman.groups,,"group=Accessories"
setup.ini,group,,"""Old Link"""
setup.ini,group,,"""New Link"", ""C:\Program Files\Thing\thing.exe""
''')
    link_modifications = module["_advanced_inf_update_inis"](
        links,
        ["Links"],
        {},
        {},
        {},
        r"C:\WINDOWS",
    )
    equal([(item["operation"], item["path"]) for item in link_modifications], [
        ("delete_file", r"C:\WINDOWS\Start Menu\Programs\Accessories\Old Link.lnk"),
        ("write_file", r"C:\WINDOWS\Start Menu\Programs\Accessories\New Link.lnk"),
    ])

def test_acme_setup_table_adapters():
    module = testing.module("@stdlib//windows:installer.star")
    equal(module["_acme_csv"]('"""Install"", ""WORDVIEW.EXE"""'), ["Install", "WORDVIEW.EXE"])
    equal(module["_acme_csv"]('"Shared Files,MSO97V_DLL,MSO97V.DLL,,41"'), [
        "Shared Files", "MSO97V_DLL", "MSO97V.DLL", "", "41",
    ])
    equal(module["_acme_csv"]('"""HKEY_LOCAL_MACHINE"", ""Software\\Example"", ""Name"", ""Value"", """""'), [
        "HKEY_LOCAL_MACHINE", r"Software\Example", "Name", "Value", "",
    ])
    parsed = module["_acme_stf"](binary.view(binary.encode(
        "App Name\tExample\r\n" +
        "Batch Mode Root Object ID\t32 : 1\r\n" +
        "ObjID\tInstall During Batch Mode\tTitle\tDescr\tType\tData\tBMP Id\tVital\tShared\tDir Chang\tDest Dir\r\n" +
        "32\tyes\tBatch\t\tGroup\t40\t\t\t\t\t%D\\setup\r\n",
        encoding = "ascii",
    )))
    equal(parsed["header"]["Batch Mode Root Object ID"], "32 : 1")
    equal(parsed["objects"]["32"], {
        "id": "32",
        "batch": True,
        "title": "Batch",
        "type": "Group",
        "data": "40",
        "destination": r"%D\setup",
    })
    equal(module["_acme_expand"](
        r"%D\%41\%F41 %%1",
        r"C:\Program Files\Example",
        r"C:\WINDOWS",
        {"41": r"C:\Program Files\Example"},
        {"41": "example.exe"},
        current = r"C:\Program Files\Example\setup",
    ), r"C:\Program Files\Example\setup\C:\Program Files\Example\example.exe %1")
    equal(module["_acme_expand"](
        r"%p\Example",
        "",
        r"C:\WINDOWS",
        {},
        {},
    ), r"C:\WINDOWS\Program Files\Example")
    equal(module["_acme_registry_modification"]("CLASSES", r"Example\shell\open", "", "example.exe"), {
        "operation": "registry_set_value",
        "root": "HKEY_LOCAL_MACHINE",
        "key": r"Software\Classes\Example\shell\open",
        "name": "(default)",
        "type": "REG_SZ",
        "value": "example.exe",
    })
    equal(module["_acme_registry_modification"](
        "HKEY_LOCAL_MACHINE",
        r"Software\Microsoft\Windows\CurrentVersion\SharedDLLs",
        r"C:\WINDOWS\SYSTEM\MSO97V.DLL",
        1,
        registry_type = "REG_DWORD",
    )["type"], "REG_DWORD")
    shared = windows.inf(r'''[Shared Files]
"MSO7ENUV_DLL"=1,msv7enu.dll,,,,,,,,,,,,Microsoft Shared
''')
    # InstallShared's STF component name is only a detection symbol. The INF
    # row supplies the payload and installed filename.
    equal(module["_acme_inf_entries"](shared, "Shared Files", symbol = "MSO7ENUV_DLL")[0][1], "msv7enu.dll")
    section = windows.inf(r'''[Commands]
one="%17%\helper.exe",/RegServer
''').section("Commands")
    equal(module["_advanced_inf_command"](section, {"17": r"C:\WINDOWS\INF"}, {}), [r"C:\WINDOWS\INF\helper.exe,/RegServer"])
    image_builder = binary.builder(capacity = 68)
    image_builder.append(b"MZ")
    image_builder.reserve(58)
    image_builder.u32le(64)
    image_builder.append(b"PE\x00\x00")
    image = image_builder.bytes()
    files = {r"C:\WINDOWS\INF\helper.exe": image}
    target = module["_advanced_inf_command_target"](r'"C:\WINDOWS\INF\helper.exe" /RegServer', files)
    equal(target[0], r"C:\WINDOWS\INF\helper.exe")
    equal(target[1], image)
    equal(module["_advanced_inf_command_target"]("rundll32.exe setup.dll,Install", files), None)
    modification = {
        "operation": "registry_set_value",
        "root": "HKEY_LOCAL_MACHINE",
        "key": r"SOFTWARE\Example",
        "name": "Value",
        "type": "REG_SZ",
        "value": "data",
    }
    patch = module["_advanced_inf_registry_patch"](modification)
    equal(patch, {"hive": "SOFTWARE", "key": "/Example", "name": "Value", "type": "REG_SZ", "value": "data"})
    equal(module["_advanced_inf_registry_modification"](patch, {}, {}), modification)

def test_registered_type_library_resolution():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    resolve = module["_registered_type_library"]
    registrations = [{
        "path": r"c:\windows\system32\example.dll",
        "library": {
            "guid": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            "major": 1,
            "minor": 0,
            "lcid": 0x409,
        },
    }]
    equal(resolve("{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}", 1, 0, 0x409, registrations), registrations[0])
    equal(resolve("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", 1, 0, 0, registrations), registrations[0])
    equal(resolve("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", 2, 0, 0, registrations), None)

def test_setupapi_inf_lines():
    module = testing.module("@stdlib//windows/selfreg:setupapi.star")
    inf = windows.inf(r"""
[Version]
Build=2001,12,4720,3959
Repeated=first
Repeated=second,part
[Files]
one.dll
two.dll
""")
    build = module["_find_line"](inf, "version", "build")
    equal(module["_line_text"](build), "2001,12,4720,3959")
    repeated = module["_find_line"](inf, "Version", "Repeated")
    equal(module["_line_text"](repeated), "first")
    repeated = module["_find_line"](inf, "Version", "Repeated", after = repeated["index"])
    equal(module["_line_text"](repeated), "second,part")
    files = module["_section_lines"](inf, "Files")
    equal([(line["key"], module["_line_text"]({"lines": files, "index": index})) for index, line in enumerate(files)], [("", "one.dll"), ("", "two.dll")])
    equal(module["_SIGNATURES"]["setupfindfirstlinew"], 4)
    equal(module["_SIGNATURES"]["setupopeninffilew"], 4)
    equal(module["_SIGNATURES"]["setupgetstringfieldw"], 5)
    equal(module["_SIGNATURES"]["setupqueuecopyw"], 9)
    equal(module["_SIGNATURES"]["setupopenlog"], 1)

def test_kernel_synchronization_signatures():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    signatures = module["_KERNEL_SIGNATURES"]
    equal(signatures["createmutexa"], 3)
    equal(signatures["createmutexw"], 3)
    equal(signatures["exitprocess"], 1)
    equal(signatures["waitforsingleobject"], 2)
    equal(signatures["createfilemappingw"], 6)
    equal(signatures["setfilepointerex"], 5)
    equal(signatures["getfilesizeex"], 2)
    equal(signatures["getfileattributesexw"], 3)
    equal(signatures["gettemppathw"], 2)
    equal(signatures["gettemppath2w"], 2)
    equal(signatures["gettempfilenamew"], 4)
    equal(signatures["getstringtypeexw"], 5)
    equal(signatures["setprocessshutdownparameters"], 2)
    equal(signatures["seterrormode"], 1)
    equal(signatures["findfirstchangenotificationw"], 3)
    equal(signatures["setconsolectrlhandler"], 2)
    equal(signatures["searchpathw"], 6)
    equal(signatures["getmodulehandleexw"], 3)
    equal(signatures["globalmemorystatus"], 1)
    equal(signatures["globalmemorystatusex"], 1)
    equal(signatures["getsystempowerstatus"], 1)
    equal(signatures["getproductinfo"], 5)
    equal(signatures["getnativesysteminfo"], 1)
    equal(module["_MULTIMEDIA_SIGNATURES"]["timegettime"], 0)
    equal(module["_MULTIMEDIA_SIGNATURES"]["timebeginperiod"], 1)
    equal(signatures["rtlcapturestackbacktrace"], 4)
    equal(signatures["getthreadpreferreduilanguages"], 4)
    equal(signatures["createprocessw"], 10)
    equal(signatures["isdebuggerpresent"], 0)
    equal(signatures["isprocessorfeaturepresent"], 1)
    equal(signatures["ntqueryinformationprocess"], 5)
    equal(signatures["zwqueryinformationprocess"], 5)
    equal(signatures["ntquerysysteminformation"], 4)
    equal(signatures["zwquerysysteminformation"], 4)
    equal(signatures["etweventregister"], 4)
    equal(signatures["etweventunregister"], 2)
    equal(signatures["etweventenabled"], 3)
    equal(signatures["etweventwrite"], 5)
    equal(signatures["getcomputernameexa"], 3)
    equal(signatures["getcomputernameexw"], 3)
    equal(signatures["filetimetosystemtime"], 2)
    equal(signatures["systemtimetofiletime"], 2)
    equal(signatures["virtualalloc"], 4)
    equal(signatures["virtualfree"], 3)
    equal(signatures["virtualprotect"], 4)
    equal(signatures["virtualquery"], 3)
    equal(signatures["initializeconditionvariable"], 1)
    equal(signatures["initializecriticalsectionex"], 3)
    equal(signatures["wakeconditionvariable"], 1)
    equal(signatures["wakeallconditionvariable"], 1)
    equal(signatures["versetconditionmask"], 4)
    equal(signatures["verifyversioninfow"], 4)
    condition_mask = module["_version_condition_mask"](0, 0x22, 3)
    equal(condition_mask, (3 << 3) | (3 << 15))
    true(module["_version_condition_satisfied"](5, 3, 3))
    true(not module["_version_condition_satisfied"](2, 3, 3))
    true(module["_version_condition_satisfied"](0x12, 0x10, 6))
    equal(signatures["createtimerqueuetimer"], 7)
    equal(signatures["openthread"], 3)
    equal(signatures["getthreadpriority"], 1)
    equal(signatures["setthreadpriority"], 2)
    equal(signatures["duplicatehandle"], 7)
    equal(signatures["changetimerqueuetimer"], 4)
    equal(signatures["deletetimerqueueex"], 2)
    equal(signatures["createthread"], 6)
    equal(signatures["queueuserworkitem"], 3)
    equal(signatures["registerwaitforsingleobject"], 6)
    equal(signatures["unregisterwaitex"], 2)
    equal(signatures["getexitcodethread"], 2)
    equal(module["_filetime_ticks"](1601, 1, 1, 0, 0, 0, 0), 0)
    equal(module["_filetime_ticks"](1970, 1, 1, 0, 0, 0, 0), 116444736000000000)
    equal(module["_filetime_ticks"](2000, 1, 1, 0, 0, 0, 0), 125911584000000000)
    equal(module["_filetime_ticks"](2001, 2, 29, 0, 0, 0, 0), None)
    equal(module["_filetime_fields"](0), [1601, 1, 1, 1, 0, 0, 0, 0])
    equal(module["_filetime_fields"](125911584001230000), [2000, 1, 6, 1, 0, 0, 0, 123])
    equal(signatures["mapviewoffile"], 5)
    equal(signatures["interlockedexchangeadd"], 2)
    equal(signatures["openfilemappinga"], 3)
    equal(signatures["openfilemappingw"], 3)
    equal(signatures["readfile"], 5)
    equal(signatures["writefile"], 5)
    equal(signatures["ntwritefile"], 9)
    equal(module["_radix_text"](0, 10), "0")
    equal(module["_radix_text"](0x123456789abcdef0, 16), "123456789abcdef0")
    equal(module["_radix_text"](35, 36), "z")
    equal(module["_radix_text"](1, 1), "")
    equal(module["_number_text"](0xffffffffffffffff, "d", bits = 64), "-1")
    equal(module["_number_text"](0xffffffffffffffff, "u", bits = 64), "18446744073709551615")
    equal(module["_scan_integer"]("1", "%I64u"), {"value": 1, "bits": 64})
    equal(module["_scan_integer"]("-42tail", "%d"), {"value": 0xffffffd6, "bits": 32})
    equal(module["_scan_integer"]("0x2a", "%i"), {"value": 42, "bits": 32})
    equal(module["_scan_integer"]("077", "%i"), {"value": 63, "bits": 32})
    equal(module["_scan_integer"]("12345", "%3hu"), {"value": 123, "bits": 16})
    equal(module["_scan_integer"]("word", "%u"), None)
    equal(module["_scan_float"]("1", "%f"), {"value": 1.0, "bits": 32, "floating": True})
    equal(module["_scan_float"]("-1.25e2tail", "%f"), {"value": -125.0, "bits": 32, "floating": True})
    equal(module["_scan_float"]("1234", "%3f"), {"value": 123.0, "bits": 32, "floating": True})
    equal(module["_scan_float"]("1e+tail", "%lf"), {"value": 1.0, "bits": 64, "floating": True})
    equal(module["_scan_float"]("word", "%f"), None)
    equal(module["_scan_float"]("1", "%a"), None)
    equal(module["_parse_c_integer"]("  -42tail", 10), {"value": -42, "consumed": 5})
    equal(module["_parse_c_integer"]("0x2a rest", 0), {"value": 42, "consumed": 4})
    equal(module["_parse_c_integer"]("077 rest", 0), {"value": 63, "consumed": 3})
    equal(module["_parse_c_integer"]("s\\%s:%s", 10), {"value": 0, "consumed": 0})
    paths = {
        "c:\\readable": {},
        "c:\\readonly": {"writable": False},
    }
    true(module["_virtual_path_access"](paths, "C:/READABLE", 0))
    true(module["_virtual_path_access"](paths, "C:/READABLE", 6))
    equal(module["_virtual_path_access"](paths, "C:/READONLY", 2), False)
    equal(module["_virtual_path_access"](paths, "C:/MISSING", 0), False)
    equal(module["_virtual_path_access"](paths, "C:/READABLE", 1), False)
    equal(module["_command_line_arguments"]('"C:\\Program Files\\tool.exe" /RegServer'), ["C:\\Program Files\\tool.exe", "/RegServer"])
    equal(module["_command_line_arguments"]('tool.exe "a b" c\\\\\\"d'), ["tool.exe", "a b", 'c\\"d'])
    equal(module["msvcrt_plugin"]().name, "windows.msvcrt")
    machine = emulator.x86(code = b"\xc3")
    argc, argv, environment = module["_crt_main_arguments"](
        machine,
        '"C:\\Program Files\\tool.exe" /RegServer',
        True,
    )
    equal(argc, 2)
    argv_data = binary.cursor(machine.read(argv, 12))
    first = argv_data.u32le()
    second = argv_data.u32le()
    equal(argv_data.u32le(), 0)
    equal(machine.read_cstring(first, encoding = "utf16le"), "C:\\Program Files\\tool.exe")
    equal(machine.read_cstring(second, encoding = "utf16le"), "/RegServer")
    equal(machine.read(environment, 4), b"\x00\x00\x00\x00")
    command_lines = module["_crt_command_line_imports"](machine, "tool.exe /RegServer")
    narrow = binary.cursor(command_lines["_acmdln"]).u32le()
    wide = binary.cursor(command_lines["_wcmdln"]).u32le()
    equal(machine.read_cstring(narrow, encoding = "ascii"), "tool.exe /RegServer")
    equal(machine.read_cstring(wide, encoding = "utf16le"), "tool.exe /RegServer")
    equal(module["_module_windows_directory"]("C:\\WINDOWS\\system32\\wbem\\wbemupgd.dll"), "C:\\WINDOWS")
    equal(module["_module_windows_directory"]("C:\\WINDOWS\\system32\\shell32.dll"), "C:\\WINDOWS")
    equal(module["_module_windows_directory"]("C:\\WINDOWS\\system\\ie4uinit.exe"), "C:\\WINDOWS")
    equal(module["_OLE_SIGNATURES"]["stringfromclsid"], 2)
    equal(module["_system_power_status"](), b"\x01\x80\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff")
    equal(module["_dos_short_path"](r"C:\WINDOWS\SYSTEM\logagent.exe"), r"C:\WINDOWS\SYSTEM\logagent.exe")
    equal(module["_dos_short_path"](r"C:\Program Files\Long Name.dll"), r"C:\PROGRA~1\LONGNA~1.DLL")

def test_crt_eh_prolog_frame():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3", fs_base = 0x7ffde000)
    machine.use([module["msvcrt_plugin"]()])
    top = machine.stack.high
    result = machine.call(
        machine.resolve_export("msvcrt.dll", name = "_EH_prolog"),
        registers = {"eax": 0x12345678, "ebp": 0x87654321},
    )
    equal(result.reason, "return", result.detail)
    equal(machine.get_register("ebp"), top - 4)
    equal(machine.get_register("esp"), top - 16)
    equal(machine.read_u32le(machine.segment_base("fs")), top - 16)
    equal(machine.read_u32le(top - 12), 0x12345678)
    equal(machine.read_u32le(top - 8), 0xffffffff)
    equal(machine.read_u32le(top - 4), 0x87654321)

def test_kernel_overlapped_file_io_uses_explicit_offsets():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    kernel = module["kernel32_plugin"](files = {"C:\\sample.bin": b"0123456789"})
    machine.use([kernel])
    path = machine.allocate(value = binary.encode("C:\\sample.bin", encoding = "utf16le", nul = True))
    handle = machine.call(
        machine.resolve_export("kernel32.dll", name = "CreateFileW"),
        args = [path, 0xc0000000, 0, 0, 3, 0x40000000, 0],
    ).value
    event = machine.call(
        machine.resolve_export("kernel32.dll", name = "CreateEventW"),
        args = [0, 1, 0, 0],
    ).value
    output = machine.allocate(8)
    transferred = machine.allocate(4)
    overlapped = machine.allocate(20)
    machine.write_u32le(overlapped + 8, 3)
    machine.write_u32le(overlapped + 16, event)
    result = machine.call(
        machine.resolve_export("kernel32.dll", name = "ReadFile"),
        args = [handle, output, 4, transferred, overlapped],
    )
    equal(result.value, 1)
    equal(machine.read(output, 4), b"3456")
    equal(machine.read_u32le(transferred), 4)
    equal(machine.read_u32le(overlapped), 0)
    equal(machine.read_u32le(overlapped + 4), 4)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "WaitForSingleObject"), args = [event, 0]).value, 0)

    # An overlapped operation does not advance the handle's synchronous cursor.
    equal(machine.call(
        machine.resolve_export("kernel32.dll", name = "ReadFile"),
        args = [handle, output, 4, transferred, 0],
    ).value, 1)
    equal(machine.read(output, 4), b"0123")

    machine.write(output, b"XY")
    machine.write_u32le(overlapped + 8, 6)
    equal(machine.call(
        machine.resolve_export("kernel32.dll", name = "WriteFile"),
        args = [handle, output, 2, transferred, overlapped],
    ).value, 1)
    equal(kernel.state["file_data"]("c:\\sample.bin"), b"012345XY89")

def test_kernel_file_mappings_observe_file_writes():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    kernel = module["kernel32_plugin"](files = {"C:\\sample.bin": b"0123456789"})
    machine.use([kernel])
    path = machine.allocate(value = binary.encode("C:\\sample.bin", encoding = "utf16le", nul = True))
    handle = machine.call(
        machine.resolve_export("kernel32.dll", name = "CreateFileW"),
        args = [path, 0xc0000000, 0, 0, 3, 0, 0],
    ).value
    read_buffer = machine.allocate(2)
    explicit = machine.allocate(20)
    machine.write_u32le(explicit + 8, 2)
    equal(machine.call(
        machine.resolve_export("kernel32.dll", name = "ReadFile"),
        args = [handle, read_buffer, 2, 0, explicit],
    ).value, 1)
    equal(machine.read(read_buffer, 2), b"23")
    equal(machine.call(
        machine.resolve_export("kernel32.dll", name = "ReadFile"),
        args = [handle, read_buffer, 2, 0, 0],
    ).value, 1)
    equal(machine.read(read_buffer, 2), b"45")
    mapping = machine.call(
        machine.resolve_export("kernel32.dll", name = "CreateFileMappingW"),
        args = [handle, 0, 4, 0, 0, 0],
    ).value
    view = machine.call(
        machine.resolve_export("kernel32.dll", name = "MapViewOfFile"),
        args = [mapping, 4, 0, 0, 0],
    ).value
    equal(machine.read(view, 10), b"0123456789")

    value = machine.allocate(value = b"XY")
    position = machine.allocate(8)
    machine.write_u64le(position, 3)
    equal(machine.call(
        machine.resolve_export("kernel32.dll", name = "SetFilePointerEx"),
        args = [handle, 3, 0, position, 0],
    ).value, 1)
    equal(machine.call(
        machine.resolve_export("kernel32.dll", name = "WriteFile"),
        args = [handle, value, 2, 0, 0],
    ).value, 1)
    equal(machine.read(view, 10), b"012XY56789")

def test_kernel_legacy_profile_and_file_metadata():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["kernel32_plugin"](r"C:\WINDOWS\SYSTEM\tool.exe", files = {
        r"C:\sample.bin": b"x",
        r"C:\WINDOWS\WIN.INI": b"[windows]\r\nrun=wmplayer.exe\r\n",
    })])
    section = machine.allocate(value = b"windows\x00")
    key = machine.allocate(value = b"run\x00")
    output = machine.allocate(size = 32)
    read = machine.call(machine.resolve_export("kernel32.dll", name = "GetProfileStringA"), args = [section, key, 0, output, 32])
    equal((read.value, machine.read_cstring(output)), (12, "wmplayer.exe"))
    path = machine.allocate(value = b"C:\\sample.bin\x00")
    handle = machine.call(machine.resolve_export("kernel32.dll", name = "CreateFileA"), args = [path, 0, 0, 0, 3, 0, 0]).value
    creation = machine.allocate(size = 8)
    access = machine.allocate(size = 8)
    written = machine.allocate(size = 8)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "GetFileTime"), args = [handle, creation, access, written]).value, 1)
    expected = module["_filetime_ticks"](2000, 1, 1, 0, 0, 0, 0)
    equal((machine.read_u64le(creation), machine.read_u64le(access), machine.read_u64le(written)), (expected, expected, expected))
    short = machine.allocate(size = 260)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "GetShortPathNameA"), args = [path, short, 260]).value, len(r"C:\sample.bin"))
    equal(machine.read_cstring(short), r"C:\sample.bin")
    atom_name = machine.allocate(value = b"trex\x00")
    equal(
        machine.call(machine.resolve_export("kernel32.dll", name = "AddAtomA"), args = [atom_name]).value,
        machine.call(machine.resolve_export("kernel32.dll", name = "GlobalAddAtomA"), args = [atom_name]).value,
    )

def test_crt_bounded_string_comparison():
    compare = testing.module("@stdlib//windows/selfreg:win32.star")["_crt_compare_strings"]
    machine = emulator.x86(code = b"\xc3")
    left = machine.allocate(value = b"A\x00B\x00", name = "unterminated left")
    right = machine.allocate(value = b"a\x00C\x00", name = "unterminated right")
    equal(compare(machine, left, right, True, count = 0, ignore_case = True), 0)
    equal(compare(machine, left, right, True, count = 1, ignore_case = True), 0)
    equal(compare(machine, left, right, True, count = 2, ignore_case = True), -1)
    equal(compare(machine, 0, 0, False, count = 0), 0)

def test_crt_bounded_memory_comparison():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["msvcrt_plugin"]()])
    left = machine.allocate(value = b"aBcZ", name = "memcmp left")
    right = machine.allocate(value = b"AbCY", name = "memcmp right")
    memcmp = machine.resolve_export("msvcrt.dll", name = "memcmp")
    memicmp = machine.resolve_export("msvcrt.dll", name = "_memicmp")
    equal(module["_crt_compare_memory"](machine, left, right, 3), 32)
    equal(machine.call(memcmp, args = [left, left, 4]).value, 0)
    equal(machine.call(memcmp, args = [left, right, 3]).value, 32)
    equal(machine.call(memicmp, args = [left, right, 3]).value, 0)
    equal(machine.call(memicmp, args = [left, right, 4]).value, 1)
    memchr = machine.resolve_export("msvcrt.dll", name = "memchr")
    equal(machine.call(memchr, args = [left, ord("B"), 4]).value, left + 1)
    equal(machine.call(memchr, args = [left, ord("Q"), 4]).value, 0)

def test_crt_wide_case_conversion():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["msvcrt_plugin"]()])
    value = machine.allocate(value = binary.encode("MiXeD", encoding = "utf16le", nul = True))
    lower = machine.resolve_export("msvcrt.dll", name = "_wcslwr")
    upper = machine.resolve_export("msvcrt.dll", name = "_wcsupr")
    equal(machine.call(lower, args = [value]).value, value)
    equal(machine.read_cstring(value, encoding = "utf16le"), "mixed")
    equal(machine.call(upper, args = [value]).value, value)
    equal(machine.read_cstring(value, encoding = "utf16le"), "MIXED")

def test_crt_ui64_wide_formatting():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["msvcrt_plugin"]()])
    output = machine.allocate(66, name = "_ui64tow output")
    ui64tow = machine.resolve_export("msvcrt.dll", name = "_ui64tow")
    equal(machine.call(ui64tow, args = [0x89abcdef, 0x01234567, output, 16]).value, output)
    equal(machine.read_cstring(output, encoding = "utf16le"), "123456789abcdef")

def test_crt_wide_floating_conversion():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["msvcrt_plugin"]()])
    source = machine.allocate(value = binary.encode(" -1.25e2suffix", encoding = "utf16le", nul = True))
    wtof = machine.resolve_export("msvcrt.dll", name = "_wtof")
    equal(machine.call(wtof, args = [source]).reason, "return")

    output = machine.allocate(8, name = "_wtof result")
    store = machine.allocate(value = b"\xdd\x1d\x00\x00\x00\x00\xc3", executable = True, name = "store ST(0)")
    machine.write_u32le(store + 2, output)
    equal(machine.call(store).reason, "return")
    equal(machine.read_f64le(output), -125.0)

def test_crt_scanf_floating_point():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["msvcrt_plugin"]()])
    source = machine.allocate(value = binary.encode("99.25tail", encoding = "utf16le", nul = True))
    float_format = machine.allocate(value = binary.encode("%f", encoding = "utf16le", nul = True))
    double_format = machine.allocate(value = binary.encode("%lf", encoding = "utf16le", nul = True))
    output = machine.allocate(8)
    swscanf = machine.resolve_export("msvcrt.dll", name = "swscanf")
    scan_args = [source, float_format, output] + [0] * 13
    equal(machine.call(swscanf, args = scan_args).value, 1)
    equal(machine.read_f32le(output), 99.25)
    equal(machine.call(swscanf, args = [source, double_format, output] + [0] * 13).value, 1)
    equal(machine.read_f64le(output), 99.25)
    secure = machine.resolve_export("msvcrt.dll", name = "swscanf_s")
    equal(machine.call(secure, args = [source, double_format, output] + [0] * 13).value, 1)
    equal(machine.read_f64le(output), 99.25)

def test_crt_errno_is_stable_and_writable():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["msvcrt_plugin"]()])
    errno = machine.resolve_export("msvcrt.dll", name = "_errno")
    first = machine.call(errno).value
    machine.write_u32le(first, 22)
    equal(machine.call(errno).value, first)
    equal(machine.read_u32le(first), 22)

def test_crt_imported_mode_data_matches_accessors():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"](command_line = '"C:\\Program Files\\tool.exe" /UserConfig')
        machine.use([kernel, module["msvcrt_plugin"](kernel = kernel)])
        for data_name, accessor_name in [("_fmode", "__p__fmode"), ("_commode", "__p__commode")]:
            data = machine.resolve_export("msvcrt.dll", name = data_name)
            accessor = machine.resolve_export("msvcrt.dll", name = accessor_name)
            true(data != 0)
            equal(machine.call(accessor).value, data)
            machine.write_u32le(data, 0x12345678)
            equal(machine.read_u32le(machine.call(accessor).value), 0x12345678)
        argc_output = machine.allocate(size = 4)
        argv_output = machine.allocate(size = machine.pointer_size)
        environment_output = machine.allocate(size = machine.pointer_size)
        startup = machine.allocate(size = machine.pointer_size * 2)
        get_arguments = machine.resolve_export("msvcrt.dll", name = "__wgetmainargs")
        equal(machine.call(get_arguments, args = [argc_output, argv_output, environment_output, 0, startup]).value, 0)
        equal(machine.read_u32le(argc_output), 2)
        argv = machine.read_pointer(argv_output)
        equal(machine.read_cstring(machine.read_pointer(argv), encoding = "utf16le"), "C:\\Program Files\\tool.exe")
        equal(machine.read_cstring(machine.read_pointer(argv + machine.pointer_size), encoding = "utf16le"), "/UserConfig")
        equal(machine.read_pointer(argv + machine.pointer_size * 2), 0)
        equal(machine.read_pointer(machine.read_pointer(environment_output)), 0)





def test_security_native_descriptor_control_preserves_native_write_order():
    module=testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86","amd64"]:
        machine=emulator.machine(code=b"\xc3",architecture=architecture)
        machine.use(module["security_plugin"]())
        read_control=machine.resolve_export("ntdll.dll",name="RtlGetControlSecurityDescriptor")
        source=machine.allocate(value=b"\x01\x00\x14\x90")
        control=machine.allocate(value=b"CONTROL!")
        revision=machine.allocate(value=b"REVISION")
        result=machine.call(read_control,args=[source,control,revision])
        equal(result.reason,"return",result.detail)
        equal(result.value,0)
        equal(machine.read_u16le(control),0x9014)
        equal(machine.read(control+2,6),b"NTROL!")
        equal(machine.read_u32le(revision),1)
        equal(machine.read(revision+4,4),b"SION")
        for invalid in [0,2,255]:
            machine.write_u8(source,invalid)
            machine.write(control,b"CONTROL!")
            result=machine.call(read_control,args=[source,control,revision])
            equal(result.value,0xc0000058)
            equal(machine.read(control,8),b"CONTROL!")
            equal(machine.read_u32le(revision),invalid)
            equal(machine.read(revision+4,4),b"SION")


def test_security_native_duplicate_and_adjust_preserve_token_ownership():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86","amd64"]:
        machine=emulator.machine(code=b"\xc3",architecture=architecture)
        kernel=module["kernel32_plugin"]()
        security=module["security_plugin"](kernel=kernel,token_privileges={17:0,18:1})
        machine.use([kernel,security])
        open_process=machine.resolve_export("ntdll.dll",name="NtOpenProcessToken")
        duplicate=machine.resolve_export("ntdll.dll",name="NtDuplicateToken")
        adjust=machine.resolve_export("ntdll.dll",name="NtAdjustPrivilegesToken")
        width=machine.pointer_size
        output=machine.allocate(value=b"GUARD123TAIL")
        process=0xffffffffffffffff if width==8 else 0xffffffff
        equal(machine.call(open_process,args=[process,0x2a,output]).value,0)
        primary=machine.read_pointer(output)
        attributes=machine.allocate(size=48 if width==8 else 24)
        machine.write_u32le(attributes,48 if width==8 else 24)
        qos=machine.allocate(size=12)
        machine.write_u32le(qos,12)
        machine.write_u32le(qos+4,2)
        machine.write_u8(qos+8,1)
        machine.write_pointer(attributes+(40 if width==8 else 20),qos)
        machine.write(output,b"GUARD123TAIL")
        machine.write_u32le(qos+4,4)
        equal(machine.call(duplicate,args=[primary,0x2c,attributes,0,2,output]).value,0xc00000a5)
        equal(machine.read(output,12),b"GUARD123TAIL")
        machine.write_u32le(qos+4,2)
        equal(machine.call(duplicate,args=[primary,0x2c,attributes,0,2,output]).value,0)
        copied=machine.read_pointer(output)
        equal(machine.read(output+width,12-width),b"GUARD123TAIL"[width:])
        token=kernel.state["handles"][copied]["value"]
        equal(token["type"],2)
        equal(token["impersonation_level"],2)
        equal(token["privileges"],{17:0,18:1})
        attach=machine.resolve_export("ntdll.dll",name="NtSetInformationThread")
        open_thread=machine.resolve_export("ntdll.dll",name="NtOpenThreadToken")
        thread=0xfffffffffffffffe if width==8 else 0xfffffffe
        slot=machine.allocate(size=width)
        machine.write_pointer(slot,copied)
        equal(machine.call(attach,args=[thread,5,slot,width-1]).value,0xc0000004)
        machine.write_pointer(slot,primary)
        equal(machine.call(attach,args=[thread,5,slot,width]).value,0xc00000a8)
        machine.write_pointer(slot,copied)
        equal(machine.call(attach,args=[thread,5,slot,width]).value,0)
        equal(machine.call(open_thread,args=[thread,8,1,output]).value,0)
        thread_handle=machine.read_pointer(output)
        equal(kernel.state["handles"][thread_handle]["value"]["type"],2)
        equal(machine.call(open_thread,args=[thread,2,1,output]).value,0)
        duplicate_source=machine.read_pointer(output)
        machine.write_u32le(qos+4,3)
        machine.write(output,b"GUARD123TAIL")
        equal(machine.call(duplicate,args=[duplicate_source,0x2c,attributes,0,2,output]).value,0xc00000a5)
        equal(machine.read(output,12),b"GUARD123TAIL")
        machine.write_u32le(qos+4,2)
        request=machine.allocate(size=16)
        machine.write_u32le(request,1)
        machine.write_u64le(request+4,17)
        machine.write_u32le(request+12,2)
        previous=machine.allocate(value=b"UNCHANGED_PREVIOUS__")
        length=machine.allocate(size=4)
        kernel.state["last_error"]=1234
        equal(machine.call(adjust,args=[copied,0,request,4,previous,length]).value,0xc0000023)
        equal(machine.read_u32le(length),16)
        equal(machine.read(previous,20),b"UNCHANGED_PREVIOUS__")
        equal(token["privileges"],{17:0,18:1})
        equal(kernel.state["last_error"],1234)
        equal(machine.call(adjust,args=[copied,0,request,20,previous,length]).value,0)
        equal(machine.read_u32le(previous),1)
        equal(machine.read_u64le(previous+4),17)
        equal(machine.read_u32le(previous+12),0)
        equal(token["privileges"],{17:2,18:1})
        equal(security.state["process_token"]["privileges"],{17:0,18:1})
        equal(kernel.state["last_error"],1234)
        machine.write_u64le(request+4,999)
        equal(machine.call(adjust,args=[copied,0,request,0,0,0]).value,0x106)
        equal(token["privileges"],{17:2,18:1})
        equal(kernel.state["last_error"],1234)
        equal(machine.call(adjust,args=[copied,1,0,0,0,0]).value,0)
        equal(token["privileges"],{17:0,18:1})
        equal(machine.call(adjust,args=[123,0,request,0,0,0]).value,0xc0000008)
        machine.write_pointer(slot,0)
        equal(machine.call(attach,args=[thread,5,slot,width]).value,0)
        equal(machine.call(open_thread,args=[thread,8,1,output]).value,0xc000007c)
        equal(kernel.state["handles"][thread_handle]["value"]["privileges"],{17:0,18:1})


def test_security_impersonate_self_clones_only_owned_primary_token():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86","amd64"]:
        machine = emulator.machine(code=b"\xc3",architecture=architecture)
        kernel = module["kernel32_plugin"]()
        security = module["security_plugin"](kernel=kernel,token_privileges={17:0,18:1})
        machine.use([kernel,security])
        impersonate = machine.resolve_export("api-ms-win-security-base-l1-1-0.dll",name="ImpersonateSelf")
        open_thread = machine.resolve_export("advapi32.dll",name="OpenThreadToken")
        revert = machine.resolve_export("advapi32.dll",name="RevertToSelf")
        native_open = machine.resolve_export("ntdll.dll",name="NtOpenThreadToken")
        output = machine.allocate(value=b"GUARD123"+b"TAIL")
        pseudo = 0xfffffffffffffffe if architecture=="amd64" else 0xfffffffe
        equal(machine.call(open_thread,args=[pseudo,0x28,1,output]).value,0)
        equal(kernel.state["last_error"],1008)
        equal(machine.read(output,12),b"GUARD123TAIL")
        equal(machine.call(native_open,args=[pseudo,8,1,output]).value,0xc000007c)
        equal(machine.call(native_open,args=[123,8,1,output]).value,0xc0000008)
        equal(machine.call(native_open,args=[pseudo,8,1,0]).value,0xc000000d)
        equal(machine.read(output,12),b"GUARD123TAIL")
        equal(machine.call(impersonate,args=[2]).value,1)
        equal(machine.call(native_open,args=[pseudo,0x28,1,output]).value,0)
        handle = machine.read_pointer(output)
        entry = kernel.state["handles"][handle]
        token = entry["value"]
        equal(token["type"],2)
        equal(token["impersonation_level"],2)
        equal(token["privileges"],{17:0,18:1})
        token["privileges"][17]=2
        equal(security.state["process_token"]["privileges"],{17:0,18:1})
        # Invalid level does not overwrite an existing impersonation context.
        equal(machine.call(impersonate,args=[0xffffffff]).value,0)
        equal(kernel.state["last_error"],1346)
        equal(security.state["thread_tokens"][8]["privileges"],{17:2,18:1})
        kernel.state["current_thread"]={"id":12}
        equal(machine.call(open_thread,args=[pseudo,8,1,output]).value,0)
        equal(kernel.state["last_error"],1008)
        kernel.state["current_thread"]=None
        equal(machine.call(revert).value,1)
        equal(machine.call(open_thread,args=[pseudo,8,1,output]).value,0)
        # An already opened token handle still owns the detached object.
        equal(entry["value"]["privileges"],{17:2,18:1})
        equal(machine.call(native_open,args=[pseudo,8,1,output]).value,0xc000007c)
        equal(machine.call(impersonate,args=[1]).value,1)
        equal(security.state["thread_tokens"][8]["privileges"],{17:0,18:1})
        equal(security.state["thread_tokens"][8]["impersonation_level"],1)
        equal(machine.call(revert).value,1)


def test_crt_private_memory_contract_preserves_abi_and_overlap():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code=b"\xc3", architecture=architecture)
        machine.use(module["msvcrt_plugin"]())
        source = machine.allocate(value=b"0123456789")
        destination = machine.allocate(value=b"guard..........tail")
        copy = machine.resolve_export("api-ms-win-crt-private-l1-1-0.dll", name="memcpy")
        move = machine.resolve_export("api-ms-win-crt-private-l1-1-0.dll", name="memmove")
        compare = machine.resolve_export("api-ms-win-crt-private-l1-1-0.dll", name="memcmp")
        result = machine.call(copy, args=[destination+5, source, 10])
        equal(result.reason,"return",result.detail)
        equal(result.value,destination+5)
        equal(machine.read(destination,19),b"guard0123456789tail")
        equal(machine.call(compare,args=[destination+5,source,10]).value,0)
        equal(machine.call(move,args=[destination+7,destination+5,8]).value,destination+7)
        equal(machine.read(destination,19),b"guard0101234567tail")
        equal(machine.call(move,args=[destination+5,destination+7,8]).value,destination+5)
        equal(machine.read(destination,19),b"guard0123456767tail")
        # Zero length must not dereference null source/destination, and no
        # integer-width truncation may change the returned destination.
        equal(machine.call(copy,args=[0,0,0]).value,0)
        equal(machine.call(compare,args=[0,0,0]).value,0)


def test_crt_unsigned_char_locale_initialization():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        for initialize_first in [False, True]:
            machine = emulator.machine(code = b"\xc3", architecture = architecture)
            machine.use([module["msvcrt_plugin"]()])
            localeconv = machine.resolve_export("api-ms-win-crt-locale-l1-1-0.dll", name = "localeconv")
            initialize = machine.resolve_export("api-ms-win-crt-locale-l1-1-0.dll", name = "__initialize_lconv_for_unsigned_char")
            if initialize_first:
                equal(machine.call(initialize).value, 0)
            address = machine.call(localeconv).value
            width = machine.pointer_size
            equal(machine.read(address + width * 10, 8), (b"\xff" if initialize_first else b"\x7f") * 8)
            equal(machine.call(initialize).value, 0)
            equal(machine.call(localeconv).value, address)
            equal(machine.read(address + width * 10, 8), b"\xff" * 8)
            equal(machine.read_cstring(machine.read_pointer(address), encoding = "ascii"), ".")
            equal(machine.read_cstring(machine.read_pointer(address + width), encoding = "ascii"), "")
            wide = address + width * 10 + 8
            equal(machine.read_cstring(machine.read_pointer(wide), encoding = "utf16le"), ".")
            equal(machine.read_cstring(machine.read_pointer(wide + 7 * width), encoding = "utf16le"), "")



def test_query_actctx_basic_bounds():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"]()
        machine.use([kernel])
        query = machine.resolve_export("kernel32.dll", name = "QueryActCtxW")
        width = machine.pointer_size
        required = machine.allocate(value = b"\xff" * width)
        output = machine.allocate(value = b"\x55" * (width * 2 + 4))
        equal(machine.call(query, args = [0, 0, 0, 1, output, width * 2 - 1, required]).value, 0)
        equal(kernel.state["last_error"], 122)
        equal(machine.read_pointer(required), width * 2)
        equal(machine.read(output, width * 2 + 4), b"\x55" * (width * 2 + 4))
        equal(machine.call(query, args = [0, 0, 0, 1, output, width * 2, required]).value, 1)
        equal(machine.read(output, width * 2), b"\x00" * (width * 2))
        equal(machine.read(output + width * 2, 4), b"\x55" * 4)
        equal(machine.call(query, args = [12, 0, 0, 1, output, width * 2, required]).value, 0)
        equal(kernel.state["last_error"], 87)
        equal(machine.call(query, args = [0, 0x12345, 0, 1, output, width * 2, required]).value, 0)
        equal(kernel.state["last_error"], 6)
        equal(machine.call(query, args = [8, 0, 0, 1, output, width * 2, required]).value, 1)
        equal(machine.read_pointer(output), 0)

def test_fixed_timezone_and_secure_wide_crt():
    def system_time(fields):
        builder = binary.builder()
        for field in fields:
            builder.u16le(field)
        return builder.bytes()

    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"]()
        machine.use([kernel, module["msvcrt_plugin"](kernel = kernel)])
        convert = machine.resolve_export("kernel32.dll", name = "SystemTimeToTzSpecificLocalTime")
        # UTC March 1 minus one hour crosses the leap-day boundary.
        utc = machine.allocate(value = system_time([2024, 3, 5, 1, 0, 30, 45, 123]))
        local = machine.allocate(value = b"\xaa" * 16)
        zone = machine.allocate(size = 172, value = binary.u32le(60))
        equal(machine.call(convert, args = [zone, utc, local]).value, 1)
        equal(machine.read(local, 16), system_time([2024, 2, 4, 29, 23, 30, 45, 123]))
        equal(machine.call(convert, args = [0, utc, local]).value, 1)
        equal(machine.read(local, 16), machine.read(utc, 16))
        machine.write_u32le(zone, 0xffffffc4)
        equal(machine.call(convert, args = [zone, utc, local]).value, 1)
        equal(machine.read_u16le(local + 8), 1)
        machine.write_u16le(utc + 2, 13)
        before = machine.read(local, 16)
        equal(machine.call(convert, args = [zone, utc, local]).value, 0)
        equal(machine.read(local, 16), before)
        equal(kernel.state["last_error"], 87)
        lower = machine.resolve_export("api-ms-win-crt-string-l1-1-0.dll", name = "_wcslwr_s")
        text = machine.allocate(value = binary.encode("AZÉ!", encoding = "utf16le", nul = True))
        equal(machine.call(lower, args = [text, 5]).value, 0)
        equal(machine.read_cstring(text, encoding = "utf16le"), "azÉ!")
        errno = machine.call(machine.resolve_export("msvcrt.dll", name = "_errno")).value
        machine.write(text, binary.encode("ABCD", encoding = "utf16le"))
        equal(machine.call(lower, args = [text, 4]).value, 22)
        equal(machine.read_u16le(text), 0)
        equal(machine.read_u32le(errno), 22)
        equal(machine.read_u16le(text + 2), 66)
        format = machine.allocate(value = binary.encode("%s:%d", encoding = "utf16le", nul = True))
        word = machine.allocate(value = binary.encode("AZ", encoding = "utf16le", nul = True))
        values = machine.allocate(size = machine.pointer_size * 2)
        machine.write_pointer(values, word)
        machine.write_pointer(values + machine.pointer_size, 7)
        output = machine.allocate(value = b"\x55" * 16)
        formatting = machine.resolve_export("api-ms-win-crt-stdio-l1-1-0.dll", name = "__stdio_common_vswprintf_s")
        prefix = [4, 0] if architecture == "x86" else [4]
        equal(machine.call(formatting, args = prefix + [output, 5, format, 0, values]).value, 4)
        equal(machine.read_cstring(output, encoding = "utf16le"), "AZ:7")
        equal(machine.read(output + 10, 6), b"\x55" * 6)
        equal(machine.call(formatting, args = prefix + [output, 4, format, 0, values]).value & 0xffffffff, 0xffffffff)
        equal(machine.read_u16le(output), 0)
        equal(machine.read_u32le(errno), 34)

def test_crt_api_set_contracts():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.machine(code = b"\x31\xc0\xc3", architecture = "amd64")
    crt = module["msvcrt_plugin"]()
    machine.use([crt])
    initialize = machine.resolve_export("api-ms-win-crt-private-l1-1-0.dll", name = "_o__initialize_onexit_table")
    equal(machine.call(initialize, args = [0]).value & 0xffffffff, 0xffffffff)
    table = machine.allocate(size = 24)
    equal(machine.call(initialize, args = [table]).value, 0)
    encoded_null = machine.read_u64le(table)
    true(encoded_null != 0)
    equal(machine.read_u64le(table + 8), encoded_null)
    equal(machine.read_u64le(table + 16), encoded_null)
    machine.write_u64le(table, 0x11111111)
    machine.write_u64le(table + 8, 0x22222222)
    machine.write_u64le(table + 16, 0x33333333)
    equal(machine.call(initialize, args = [table]).value, 0)
    equal(machine.read_u64le(table), 0x11111111)
    equal(machine.read_u64le(table + 8), 0x22222222)
    equal(machine.read_u64le(table + 16), 0x33333333)
    initializers = machine.allocate(size = 16)
    machine.write_pointer(initializers, machine.entry)
    initterm_e = machine.resolve_export("api-ms-win-crt-runtime-l1-1-0.dll", name = "_initterm_e")
    initterm = machine.resolve_export("api-ms-win-crt-runtime-l1-1-0.dll", name = "_initterm")
    equal(machine.call(initterm_e, args = [initializers, initializers + 8]).value, 0)
    equal(machine.call(initterm, args = [initializers, initializers + 8]).value, 0)
    register = machine.resolve_export("api-ms-win-crt-private-l1-1-0.dll", name = "_o__register_onexit_function")
    execute = machine.resolve_export("api-ms-win-crt-private-l1-1-0.dll", name = "_o__execute_onexit_table")
    equal(machine.call(register, args = [table, machine.entry]).value, 0)
    equal(machine.call(register, args = [table, machine.entry + 2]).value, 0)
    true(machine.read_u64le(table) < machine.read_u64le(table + 8))
    equal(machine.call(execute, args = [table]).value, 0)
    onexit = [action for action in crt.state["actions"] if action["api"] == "_o__execute_onexit_table"]
    equal([action["callback"] for action in onexit], [machine.entry + 2, machine.entry])
    equal(machine.read_u64le(table), machine.read_u64le(table + 8))
    equal(machine.read_u64le(table + 8), machine.read_u64le(table + 16))
    for name in ["wcscmp", "wcsncmp", "strcmp", "strncmp", "memset"]:
        true(machine.resolve_export("api-ms-win-crt-string-l1-1-0.dll", name = name) != 0)
    buffer = machine.allocate(size = 4)
    memset = machine.resolve_export("api-ms-win-crt-string-l1-1-0.dll", name = "memset")
    equal(machine.call(memset, args = [buffer, 0x5a, 4]).value, buffer)
    equal(machine.read(buffer, 4), b"ZZZZ")

def test_event_log_exports_support_late_loaded_modules():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code=b"\xc3", architecture=architecture)
        provider = module["event_log_plugin"]()
        machine.use([provider])
        output = machine.allocate(value=b"\xaa"*16)
        classic = "api-ms-win-eventing-classicprovider-l1-1-0.dll"
        modern = "api-ms-win-eventing-provider-l1-1-0.dll"
        register = machine.resolve_export(classic, name="RegisterTraceGuidsW")
        unregister = machine.resolve_export("advapi32.dll", name="UnregisterTraceGuids")
        result = machine.call(register, args=[0,0,0,0,0,0,0,output])
        equal(result.reason,"return",result.detail)
        equal(result.value,0)
        handle = machine.read_u64le(output)
        true(handle != 0)
        equal(machine.read(output+8,8),b"\xaa"*8)
        args = [handle] if architecture=="amd64" else [handle & 0xffffffff,handle>>32]
        equal(machine.call(unregister,args=args).value,0)
        equal(machine.call(machine.resolve_export(classic,name="UnregisterTraceGuids"),args=args).value,6)
        guid = machine.allocate(value=b"\x00"*16)
        result = machine.call(machine.resolve_export(modern,name="EventRegister"),args=[guid,0,0,output])
        equal(result.reason,"return",result.detail)
        equal(result.value,0)
        handle = machine.read_u64le(output)
        args = [handle] if architecture=="amd64" else [handle & 0xffffffff,handle>>32]
        equal(machine.call(machine.resolve_export(modern,name="EventSetInformation"),args=args+[0,0,0]).value,0)
        equal(machine.call(machine.resolve_export("ntdll.dll",name="EtwEventUnregister"),args=args).value,0)
        equal(machine.call(machine.resolve_export(modern,name="EventSetInformation"),args=args+[0,0,0]).value,6)
        equal(provider.state["trace_providers"],{})

def test_security_native_allow_ace_ex_contract():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    sid_value = testing.module("@stdlib//windows:security.star")["sid"]
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"]()
        machine.use([kernel, module["security_plugin"](kernel = kernel)])
        kernel.state["last_error"] = 31337
        high = 0xface00000000 if architecture == "amd64" else 0
        api = machine.resolve_export("ntdll.dll", name = "RtlAddAccessAllowedAceEx")
        sid = machine.allocate(value = sid_value(5, [18]))
        def check(revision = 2, flags = 2, capacity = 68, count = 0, sid_revision = 1, sid_count = 1, acl_revision = 2, expected = 0):
            acl = machine.allocate(value = binary.concat([bytes([acl_revision, 0]), binary.u16le(capacity), binary.u16le(count), b"ZZ", b"Q" * 80]))
            principal = machine.allocate(value = binary.concat([bytes([sid_revision, sid_count]), b"\x00" * 5, b"\x05", binary.u32le(18), b"\x00" * 60]))
            before = machine.read(acl, 88)
            result = machine.call(api, args = [acl, high | revision, high | flags, high | 0xf003f, principal])
            equal(result.reason, "return", result.detail)
            equal(result.value, expected)
            equal(kernel.state["last_error"], 31337)
            if expected:
                equal(machine.read(acl, 88), before)
            else:
                equal(machine.read_u8(acl), max(acl_revision, revision))
                equal(machine.read_u16le(acl + 4), 1)
                equal(machine.read(acl + 6, 2), b"ZZ")
                equal(machine.read(acl + capacity, 8), b"Q" * 8)
                equal(machine.read_u8(acl + 8), 0)
                equal(machine.read_u8(acl + 9), flags)
                equal(machine.read_u32le(acl + 12), 0xf003f)
                equal(machine.read(acl + 16, 8 + sid_count * 4), machine.read(principal, 8 + sid_count * 4))
            return acl
        for revision in [0, 1, 2, 3, 4]:
            check(revision = revision)
        for flags in [0, 0x1f, 0x20, 0x3f]:
            check(flags = flags)
        for flags in [0x40, 0x80, 0x100, 0xff]:
            check(flags = flags, expected = 0xc000000d)
        check(revision = 5, expected = 0xc0000059)
        check(acl_revision = 5, expected = 0xc0000059)
        check(acl_revision = 1, expected = 0xc0000077)
        check(acl_revision = 3)
        check(acl_revision = 4)
        check(sid_revision = 2, expected = 0xc0000078)
        check(sid_count = 16, expected = 0xc0000078)
        check(sid_count = 0)
        check(capacity = 7, expected = 0xc0000077)
        check(capacity = 24, expected = 0xc0000099)
        check(capacity = 27, expected = 0xc0000099)
        check(capacity = 29)
        check(count = 100, expected = 0xc0000077)
        # A second append preserves the first ACE and all unused/guard bytes.
        acl = check()
        original = machine.read(acl + 8, 20)
        second = machine.allocate(value = sid_value(5, [32, 544]))
        result = machine.call(api, args = [acl, 4, 3, 0x20019, second])
        equal(result.reason, "return", result.detail)
        equal(result.value, 0)
        equal(machine.read(acl + 8, 20), original)
        parsed = windows.acl_entries(machine.read(acl, 68))
        equal(parsed["revision"], 4)
        equal(len(parsed["entries"]), 2)
        equal(parsed["entries"][0]["sid"], sid_value(5, [18]))
        equal(parsed["entries"][1]["sid"], sid_value(5, [32, 544]))
        equal(parsed["entries"][1]["flags"], 3)
        equal(parsed["entries"][1]["mask"], 0x20019)
        equal(machine.read(acl + 68, 8), b"Q" * 8)
        # Malformed existing ACE extents fail before any append.
        machine.write_u16le(acl + 10, 2)
        corrupt = machine.read(acl, 88)
        result = machine.call(api, args = [acl, 2, 0, 1, sid])
        equal(result.reason, "return", result.detail)
        equal(result.value, 0xc0000077)
        equal(machine.read(acl, 88), corrupt)
        equal(kernel.state["last_error"], 31337)

def test_security_native_descriptor_validation():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    principal = testing.module("@stdlib//windows:security.star")["sid"](5, [18])
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"]()
        machine.use([kernel, module["security_plugin"](kernel = kernel)])
        kernel.state["last_error"] = 31337
        for relative in [False, True]:
            layout = abi["security_descriptor_layout"](machine.pointer_size, relative = relative)
            for mutation, expected in [("", 1), ("revision", 0), ("sid", 0), ("count", 0), ("acl", 0), ("ace", 0), ("acl_revision3", 1), ("null_acl", 1), ("absent_acl", 1)]:
                sd = machine.allocate(size = 136)
                sid, acl = sd + 48, sd + 64
                machine.write(sd, b"\x01\x00")
                machine.write_u16le(sd + 2, 0x8004 if relative else 4)
                machine.write(sid, principal)
                machine.write(acl, binary.concat([b"\x02\x00", binary.u16le(28), binary.u16le(1), b"\x00\x00", b"\x00\x02", binary.u16le(20), binary.u32le(0xf003f), principal]).bytes())
                for field, pointer in [("Owner", sid), ("Group", sid), ("Dacl", acl)]:
                    if relative:
                        machine.write_u32le(sd + layout[field], pointer - sd)
                    else:
                        machine.write_pointer(sd + layout[field], pointer)
                if mutation == "revision":
                    machine.write(sd, b"\x02")
                elif mutation == "sid":
                    machine.write(sid, b"\x02")
                elif mutation == "count":
                    machine.write(sid + 1, b"\x10")
                elif mutation == "acl":
                    machine.write_u16le(acl + 2, 7)
                elif mutation == "ace":
                    machine.write_u16le(acl + 10, 2)
                elif mutation == "acl_revision3":
                    machine.write(acl, b"\x03")
                elif mutation == "null_acl":
                    machine.write_pointer(sd + layout["Dacl"], 0)
                elif mutation == "absent_acl":
                    machine.write_u16le(sd + 2, 0x8000 if relative else 0)
                    machine.write_u16le(acl + 2, 7)
                machine.write(sd + 128, b"GUARDEND")
                before = machine.read(sd, 136)
                for library, api in [("ntdll.dll", "RtlValidSecurityDescriptor"), ("advapi32.dll", "IsValidSecurityDescriptor")]:
                    result = machine.call(machine.resolve_export(library, name = api), args = [sd])
                    equal(result.reason, "return", result.detail)
                    equal(result.value, expected, architecture + " " + str(relative) + " " + mutation)
                    equal(machine.read(sd, 136), before)
                    equal(kernel.state["last_error"], 31337)

def test_security_native_absolute_to_self_relative():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    principal = testing.module("@stdlib//windows:security.star")["sid"](5, [18])
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"]()
        machine.use([kernel, module["security_plugin"](kernel = kernel)])
        kernel.state["last_error"] = 31337
        sd = machine.allocate(size = 128)
        machine.write(sd, b"\x01\x00")
        machine.write_u16le(sd + 2, 4)
        sid, acl = sd + 48, sd + 64
        machine.write(sid, principal)
        acl_bytes = binary.concat([b"\x02\x00", binary.u16le(28), binary.u16le(1), b"\x00\x00", b"\x00\x02", binary.u16le(20), binary.u32le(0xf003f), principal]).bytes()
        machine.write(acl, acl_bytes)
        layout = abi["security_descriptor_layout"](machine.pointer_size)
        for field, pointer in [("Owner", sid), ("Group", sid), ("Dacl", acl)]:
            machine.write_pointer(sd + layout[field], pointer)
        source = machine.read(sd, 128)
        output = machine.allocate(value = b"Z" * 148)
        length = machine.allocate(value = binary.concat([binary.u32le(0), b"GUARDEND"]))
        for api_name in ["RtlAbsoluteToSelfRelativeSD", "RtlMakeSelfRelativeSD"]:
            api = machine.resolve_export("ntdll.dll", name = api_name)
            for capacity, destination, expected in [(0, 0, 0xc0000023), (71, output, 0xc0000023), (72, output, 0), (140, output, 0), (140, 0, 0xc000000d)]:
                machine.write(output, b"Z" * 148)
                machine.write_u32le(length, capacity)
                result = machine.call(api, args = [sd, destination, length])
                equal(result.reason, "return", result.detail)
                equal(result.value, expected)
                equal(machine.read_u32le(length), 72 if expected == 0xc0000023 else capacity)
                equal(machine.read(length + 4, 8), b"GUARDEND")
                equal(machine.read(sd, 128), source)
                equal(kernel.state["last_error"], 31337)
                if expected:
                    equal(machine.read(output, 148), b"Z" * 148)
                else:
                    equal(machine.read_u16le(output + 2), 0x8004)
                    equal([machine.read_u32le(output + offset) for offset in [4, 8, 12, 16]], [48, 60, 0, 20])
                    equal(machine.read(output + 20, 28), acl_bytes)
                    equal(machine.read(output + 48, 12), principal)
                    equal(machine.read(output + 60, 12), principal)
                    equal(machine.read(output + 72, 76), b"Z" * 76)
                    serialized = machine.read(output, 72)
                    parts = windows.security_descriptor_parts(serialized)
                    equal(parts["owner"], principal)
                    equal(parts["group"], principal)
                    equal(parts["dacl"], acl_bytes)
        # Make accepts a self-relative input; Absolute rejects it. Both use
        # the same canonical native layout and preserve destination guards.
        relative=machine.allocate(value=serialized)
        api=machine.resolve_export("ntdll.dll",name="RtlMakeSelfRelativeSD")
        for capacity,expected in [(71,0xc0000023),(140,0)]:
            machine.write(output,b"Z"*148)
            machine.write_u32le(length,capacity)
            result=machine.call(api,args=[relative,output,length])
            equal(result.reason,"return",result.detail)
            equal(result.value,expected)
            equal(machine.read_u32le(length),72 if expected else 140)
            equal(machine.read(output,148),b"Z"*148 if expected else binary.concat([serialized,b"Z"*76]).bytes())
            equal(machine.read(relative,72),serialized)
        machine.write(output,b"Z"*148)
        api=machine.resolve_export("ntdll.dll",name="RtlAbsoluteToSelfRelativeSD")
        machine.write_u16le(sd + 2, 0x8004)
        machine.write_u32le(length, 140)
        result = machine.call(api, args = [sd, output, length])
        equal(result.reason, "return", result.detail)
        equal(result.value, 0xc00000e7)
        equal(machine.read_u32le(length), 140)
        equal(machine.read(output, 148), b"Z" * 148)

def test_security_reports_required_sid_length():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["security_plugin"]()])
    target = machine.resolve_export("advapi32.dll", name = "GetSidLengthRequired")
    equal(machine.call(target, args = [0]).value, 8)
    equal(machine.call(target, args = [5]).value, 28)
    authority = machine.allocate(value = b"\x00\x00\x00\x00\x00\x05")
    output = machine.allocate(size = 12)
    initialize = machine.resolve_export("advapi32.dll", name = "InitializeSid")
    equal(machine.call(initialize, args = [output, authority, 1]).value, 1)
    equal(machine.read(output, 8), b"\x01\x01\x00\x00\x00\x00\x00\x05")
    service = machine.allocate(value = binary.encode("SampleService", encoding = "utf16le", nul = True))
    set_named = machine.resolve_export("advapi32.dll", name = "SetNamedSecurityInfoW")
    equal(machine.call(set_named, args = [service, 5, 4, 0, 0, 0, 0]).value, 0)

def test_kernel_budget_threads_remain_runnable():
    state_for = testing.module("@stdlib//windows/selfreg:win32.star")["_execution_thread_state"]
    equal(state_for("return"), "terminated")
    equal(state_for("wait"), "waiting")
    equal(state_for("budget"), "runnable")
    equal(state_for("memory"), "stopped")

def test_kernel_provider_recognizes_api_set_contracts():
    provider = testing.module("@stdlib//windows/selfreg:win32.star")["_kernel_provider_module"]
    true(provider("kernel32.dll"))
    true(provider("NTDLL.DLL"))
    true(provider("api-ms-win-core-sysinfo-l1-1-0.dll"))
    true(provider("C:\\Windows\\System32\\ext-ms-win-kernel32-package-current-l1-1-0.dll"))
    true(not provider("api-ms-win-crt-runtime-l1-1-0.dll"))
    true(not provider("vendor.dll"))

def test_shlwapi_provider_recognizes_api_set_contracts():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    provider = module["_shlwapi_provider_module"]
    true(provider("SHLWAPI.dll"))
    true(provider("api-ms-win-core-shlwapi-legacy-l1-1-0.dll"))
    true(provider("api-ms-win-core-shlwapi-obsolete-l1-1-0.dll"))
    true(not provider("api-ms-win-core-file-l1-1-0.dll"))
    machine = emulator.machine(code = b"\xc3", architecture = "amd64")
    machine.use(module["shell_plugin"](r"C:\Windows\System32\sample.dll"))
    local = machine.allocate(value = binary.encode(r"C:\Users\Administrator", encoding = "utf16le", nul = True))
    network = machine.allocate(value = binary.encode(r"\\server\share", encoding = "utf16le", nul = True))
    path_is_network = machine.resolve_export("shlwapi.dll", name = "PathIsNetworkPathW")
    equal(machine.call(path_is_network, args = [local]).value, 0)
    equal(machine.call(path_is_network, args = [network]).value, 1)

def test_compare_string_amd64_int_lengths():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.machine(code = b"\xc3", architecture = "amd64")
    machine.use([module["kernel32_plugin"]()])
    for suffix, encoding in [("A", "ascii"), ("W", "utf16le")]:
        compare = machine.resolve_export("kernel32.dll", name = "CompareString" + suffix)
        left = machine.allocate(value = binary.encode("HKCU\x00", encoding = encoding))
        right = machine.allocate(value = binary.encode("hkcu\x00", encoding = encoding))
        # AMD64 stack slots carry eight bytes, but cchCount is an INT.
        # Exercise both stale and sign-extended upper halves of -1 and
        # ordinary explicit lengths; neither upper half is string data.
        for count in [0xffffffff, 0x7fffffffffff, 0xffffffffffffffff, 0x1234567800000004]:
            result = machine.call(compare, args = [0x7f, 1, left, count, right, count])
            equal(result.reason, "return")
            equal(result.value, 2)
        equal(machine.call(compare, args = [0x7f, 0, left, 4, right, 4]).value, 1)
def test_kernel_integer_to_char_native_boundaries():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(module["kernel32_plugin"]())
        format = machine.resolve_export("ntdll.dll", name = "RtlIntegerToChar")
        output = machine.allocate(size = 40)
        high = 0x7fff00000000 if architecture == "amd64" else 0
        for value, base, capacity, status, data in [
            (255, 16, 2, 0, b"FF"),
            (255, 16, 3, 0, b"FF\x00"),
            (0x1234, 16, 2, 0x80000005, b""),
            (255, 3, 16, 0xc000000d, b""),
            (1, 0, 5, 0, b"1\x00"),
            (0xffffffff, 10, 10, 0, b"4294967295"),
            (0xffffffff, 2, 32, 0, b"11111111111111111111111111111111"),
        ]:
            machine.write(output, b"Z" * 40)
            result = machine.call(format, args = [high | value, high | base, high | capacity, output])
            equal(result.reason, "return")
            equal(result.value, status)
            equal(machine.read(output, len(data)), data)
            equal(machine.read(output + len(data), 40 - len(data)), b"Z" * (40 - len(data)))

def test_kernel_explicit_file_write_bound():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86","amd64"]:
        machine = emulator.machine(code=b"\xc3",architecture=architecture)
        kernel = module["kernel32_plugin"](files={"C:/bound.bin":b""},maximum_file_size=32)
        machine.use([kernel])
        path = machine.allocate(value=binary.encode("C:/bound.bin",encoding="utf16le",nul=True))
        handle = machine.call(machine.resolve_export("kernel32.dll",name="CreateFileW"),args=[path,0x40000000,7,0,3,0,0]).value
        buffer = machine.allocate(value=b"X"*33)
        count = machine.allocate(value=b"ZZZZ")
        write = machine.resolve_export("kernel32.dll",name="WriteFile")
        equal(machine.call(write,args=[handle,buffer,33,count,0]).value,0)
        equal(kernel.state["file_data"](r"c:\bound.bin"),b"")
        equal(machine.read(count,4),b"ZZZZ")
        equal(machine.call(write,args=[handle,buffer,7,count,0]).value,1)
        equal(machine.call(write,args=[handle,buffer,25,count,0]).value,1)
        equal(kernel.state["file_data"](r"c:\bound.bin"),b"X"*32)
        equal(machine.call(write,args=[handle,buffer,1,count,0]).value,0)
        equal(kernel.state["last_error"],112)
        equal(kernel.state["file_data"](r"c:\bound.bin"),b"X"*32)
    for limit in [0,513<<20]:
        raises(module["kernel32_plugin"],kwargs={"maximum_file_size":limit},message="virtual file write bound")

def test_cabinet_callback_stream_and_native_notifications():
    win32 = testing.module("@stdlib//windows/selfreg:win32.star")
    cabinet = testing.module("@stdlib//windows/selfreg:cabinet.star")
    payload = b"native callback cabinet payload"
    name = b"sample.bin\x00"
    data_offset = 44+16+len(name)
    fixture = binary.builder()
    fixture.append(b"MSCF")
    fixture.u32le(0)
    fixture.u32le(data_offset+8+len(payload))
    fixture.u32le(0)
    fixture.u32le(44)
    fixture.u32le(0)
    fixture.append(b"\x03\x01")
    for value in [1,1,0,0x1234,7]: fixture.u16le(value)
    fixture.u32le(data_offset)
    fixture.u16le(1)
    fixture.u16le(0)
    fixture.u32le(len(payload))
    fixture.u32le(0)
    for value in [0,0x5d41,0x7283,0x21]: fixture.u16le(value)
    fixture.append(name)
    fixture.u32le(0)
    fixture.u16le(len(payload))
    fixture.u16le(len(payload))
    fixture.append(payload)
    contents = fixture.bytes()
    for architecture in ["x86","amd64"]:
        for mode in ["copy","truncated","abort"]:
            machine = emulator.machine(code=b"\xc3",architecture=architecture)
            kernel = win32["kernel32_plugin"]()
            plugin = cabinet["cabinet_plugin"](kernel)
            machine.use([kernel,plugin])
            state = dict(position=0,closed=0,output=b"",notices=[])
            handle = 0x10000001234 if architecture=="amd64" else 0x1234
            user = machine.allocate(size=8)
            maximum = (1 << (machine.pointer_size*8))-1
            source = contents[:-3] if mode=="truncated" else contents
            def open_input(event):
                equal(event.machine.read_cstring(event.args[0]),"memory:CaseSensitive")
                equal(event.args[1],0x8000)
                return handle
            def read_input(event):
                equal(event.args[0],handle)
                start = state["position"]
                chunk = source[start:start+min(7,event.args[2])]
                event.machine.write(event.args[1],chunk)
                state["position"] += len(chunk)
                return len(chunk)
            def close_input(event):
                equal(event.args[0],handle)
                state["closed"] += 1
                return 0
            def write_output(event):
                equal(event.args[0],handle+1)
                state["output"] = binary.concat([state["output"],event.machine.read(event.args[1],event.args[2])]).bytes()
                return event.args[2]
            def notify(event):
                m = event.machine
                kind,address = event.args
                p = 8 if m.pointer_size==8 else 4
                equal(m.read_u32le(address),len(payload))
                equal(m.read_cstring(m.read_pointer(address+p)),"sample.bin")
                equal(m.read_pointer(address+p*4),user)
                tail = address+p*6
                equal([m.read_u16le(tail+i*2) for i in range(6)],[0x5d41,0x7283,0x21,0x1234,7,0])
                state["notices"].append(kind)
                if kind==2: return maximum if mode=="abort" else handle+1
                equal(kind,3)
                equal(m.read_pointer(address+p*5),handle+1)
                return 1
            callbacks = {}
            for label,callback,argc in [("open",open_input,3),("read",read_input,3),("close",close_input,1),("write",write_output,3),("notify",notify,2)]:
                callbacks[label] = machine.provide_export(callback,module="test-fdi.dll",name=label,argc=argc,convention="cdecl")
            error = machine.allocate(size=12)
            context = machine.call(machine.resolve_export("cabinet.dll",name="FDICreate"),args=[0,0,callbacks["open"],callbacks["read"],callbacks["write"],callbacks["close"],0,0xffffffff,error]).value
            path = machine.allocate(value=b"memory:\x00")
            name_address = machine.allocate(value=b"CaseSensitive\x00")
            result = machine.call(machine.resolve_export("cabinet.dll",name="FDICopy"),args=[context,name_address,path,0,callbacks["notify"],0,user])
            equal(result.reason,"return",result.detail)
            equal(result.value,1 if mode=="copy" else 0)
            equal(state["closed"],1)
            equal(state["output"],payload if mode=="copy" else b"")
            equal(state["notices"],[2,3] if mode=="copy" else [2] if mode=="abort" else [])
            equal(machine.read_u32le(error+8),0 if mode=="copy" else 1)
            equal(machine.read_u32le(error),0 if mode=="copy" else 11 if mode=="abort" else 4)
            equal(machine.call(machine.resolve_export("cabinet.dll",name="FDIDestroy"),args=[context]).value,1)

def test_cabinet_non_cabinet_copy_reports_fdi_error():
    win32 = testing.module("@stdlib//windows/selfreg:win32.star")
    cabinet = testing.module("@stdlib//windows/selfreg:cabinet.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = win32["kernel32_plugin"](files = {"C:/Input/driver.sys": b"MZ\x90\x00not-a-cabinet"})
        plugin = cabinet["cabinet_plugin"](kernel)
        machine.use([kernel, plugin])
        def unexpected(event): fail("a non-cabinet must not produce file notifications")
        machine.provide_export(unexpected, module = "test-cabinet.dll", name = "Notify", argc = 2, convention = "cdecl")
        notify = machine.resolve_export("test-cabinet.dll", name = "Notify")
        original_paths = sorted(kernel.state["paths"])
        error = machine.allocate(value = b"Z" * 16)
        create = machine.resolve_export("cabinet.dll", name = "FDICreate")
        context = machine.call(create, args = [0, 0, 0, 0, 0, 0, 0, 0xffffffff, error]).value
        name = machine.allocate(value = b"driver.sys\x00")
        directory = machine.allocate(value = binary.encode("C:/Input/", encoding = "ascii", nul = True))
        result = machine.call(machine.resolve_export("cabinet.dll", name = "FDICopy"), args = [context, name, directory, 0, notify, 0, 0])
        equal(result.reason, "return")
        equal(result.value, 0)
        equal(machine.read_u32le(error), 2)  # FDIERROR_NOT_A_CABINET
        equal(machine.read_u32le(error + 4), 0)
        equal(machine.read_u32le(error + 8), 1)
        equal(machine.read(error + 12, 4), b"ZZZZ")
        equal(plugin.state["actions"][-1]["operation"], 2)
        equal(sorted(kernel.state["paths"]), original_paths)

def test_kernel_exclusive_srw_native_alias_contention():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(module["kernel32_plugin"]())
        lock = machine.allocate(size = machine.pointer_size)
        initialize = machine.resolve_export("ntdll.dll", name = "RtlInitializeSRWLock")
        acquire = machine.resolve_export("ntdll.dll", name = "RtlAcquireSRWLockExclusive")
        release = machine.resolve_export("ntdll.dll", name = "RtlReleaseSRWLockExclusive")
        attempt = machine.resolve_export("kernel32.dll", name = "TryAcquireSRWLockExclusive")
        equal(machine.call(initialize, args = [lock]).reason, "return")
        equal(machine.call(acquire, args = [lock]).reason, "return")
        equal(machine.call(attempt, args = [lock]).value, 0)
        contender = machine.spawn(acquire, args = [lock])
        equal(contender.run().reason, "wait")
        equal(machine.call(release, args = [lock]).reason, "return")
        equal(contender.run().reason, "return")
        equal(machine.call(attempt, args = [lock]).value, 0)
        invalid = machine.call(release, args = [lock])
        equal(invalid.reason, "plugin")
        true("exclusive ownership" in invalid.detail)
        contender.close()

def test_profile_string_native_dword_capacity():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"]()
        machine.use(kernel)
        high = 0x600000000000 if architecture == "amd64" else 0
        for suffix, encoding, unit in [("A", "ascii", 1), ("W", "utf16le", 2)]:
            section = machine.allocate(value = binary.encode("Version", encoding = encoding, nul = True))
            key = machine.allocate(value = binary.encode("ProductType", encoding = encoding, nul = True))
            default = machine.allocate(value = binary.encode("abcdef", encoding = encoding, nul = True))
            file = machine.allocate(value = binary.encode("C:/absent.ini", encoding = encoding, nul = True))
            output = machine.allocate(size = 32)
            for base in ["GetPrivateProfileString", "GetProfileString"]:
                get = machine.resolve_export("kernel32.dll", name = base + suffix)
                for capacity in [0, 1, 4, 8]:
                    machine.write(output, b"Z" * 32)
                    args = [section, key, default, output, high | capacity]
                    if base == "GetPrivateProfileString": args.append(file)
                    result = machine.call(get, args = args)
                    equal(result.reason, "return")
                    count = min(6, capacity - 1) if capacity else 0
                    equal(result.value, count)
                    expected = binary.encode("abcdef"[:count], encoding = encoding, nul = True) if capacity else b""
                    equal(machine.read(output, len(expected)), expected)
                    equal(machine.read(output + len(expected), 32 - len(expected)), b"Z" * (32 - len(expected)))

def test_crt_toupper_ascii_int_width():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(module["msvcrt_plugin"]())
        upper = machine.resolve_export("msvcrt.dll", name = "toupper")
        high = 0x600000000000 if architecture == "amd64" else 0
        for value in range(128):
            expected = value - 32 if value >= 97 and value <= 122 else value
            result = machine.call(upper, args = [high | value])
            equal(result.reason, "return")
            equal(result.value, expected)
        equal(machine.call(upper, args = [high | 0xffffffff]).value, 0xffffffff)
        result = machine.call(upper, args = [0xe9])
        equal(result.reason, "plugin")
        true("native CRT locale tables" in result.detail)

def test_catalog_hash_native_sizing_and_file_handle():
    win32 = testing.module("@stdlib//windows/selfreg:win32.star")
    crypto_module = testing.module("@stdlib//windows/selfreg:crypto.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = win32["kernel32_plugin"](files = {"C:/Input/member.inf": b"catalog member"})
        plugin = crypto_module["cryptoapi_plugin"](kernel = kernel)
        machine.use([kernel, plugin])
        calculate = machine.resolve_export("wintrust.dll", name = "CryptCATAdminCalcHashFromFileHandle")
        path = machine.allocate(value = binary.encode("C:/Input/member.inf", encoding = "utf16le", nul = True))
        opened = machine.call(machine.resolve_export("kernel32.dll", name = "CreateFileW"), args = [path, 0x80000000, 1, 0, 3, 0, 0]).value
        size = machine.allocate(value = b"Z" * 8)
        output = machine.allocate(value = b"Z" * 32)
        high = 0x600000000000 if architecture == "amd64" else 0
        for capacity, destination, expected in [(0, 0, 1), (19, output, 0), (20, 0, 1), (32, 0, 1)]:
            machine.write_u32le(size, capacity)
            result = machine.call(calculate, args = [opened, size, destination, high])
            equal(result.reason, "return")
            equal(result.value, expected)
            equal(machine.read_u32le(size), 20)
            equal(machine.read(size + 4, 4), b"ZZZZ")
            equal(machine.read(output, 32), b"Z" * 32)
        machine.write_u32le(size, 32)
        result = machine.call(calculate, args = [opened, size, output, high])
        equal(result.reason, "return")
        equal(result.value, 1)
        equal(machine.read(output, 20), crypto.hash("sha1", b"catalog member"))
        equal(machine.read(output + 20, 12), b"Z" * 12)
        equal(plugin.state["actions"][-1]["operation"], "catalog-hash")
        machine.call(machine.resolve_export("kernel32.dll", name = "CloseHandle"), args = [opened])
        result = machine.call(calculate, args = [opened, size, output, 0])
        equal(result.value, 0)
        equal(kernel.state["last_error"], 6)
        result = machine.call(calculate, args = [opened, size, output, 1])
        equal(result.value, 0)
        equal(kernel.state["last_error"], 87)

def test_kernel_delete_on_close_open_object_lifetime():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86","amd64"]:
        for wide in [False,True]:
            machine = emulator.machine(code=b"\xc3",architecture=architecture)
            kernel = module["kernel32_plugin"](files={"D:/temp/name":b"original"},volumes={"D:":dict(filesystem="NTFS",serial=4)})
            machine.use(kernel)
            if architecture=="amd64":
                kernel.state["next_handle"]=0x100040000
            invalid=(1<<(machine.pointer_size*8))-1
            def text(value):
                return machine.allocate(value=binary.encode(value,encoding="utf16le" if wide else "ascii",nul=True))
            def call(api,args):
                result=machine.call(machine.resolve_export("kernel32.dll",name=api),args=args)
                equal(result.reason,"return",result.detail)
                return result.value
            create="CreateFileW" if wide else "CreateFileA"
            path=text("D:/temp/name")
            name=r"d:\temp\name"
            blocker=call(create,[path,0x80000000,3,0,3,0,0])
            equal(call(create,[path,0x80000000,7,0,2,0x04000000,0]),invalid)
            equal(kernel.state["last_error"],32)
            equal(kernel.state["file_data"](name),b"original")
            equal(call("CloseHandle",[blocker]),1)
            kernel.state["paths"][name]["attributes"]=1
            equal(call(create,[path,0x80000000,7,0,2,0x04000000,0]),invalid)
            equal(kernel.state["last_error"],5)
            equal(kernel.state["file_data"](name),b"original")
            kernel.state["paths"][name]["attributes"]=0x80
            owner=call(create,[path,0x80000000,7,0,3,0x04000000,0])
            other=call(create,[path,0x80000000,7,0,3,0,0])
            true(owner!=invalid and other!=invalid)
            output=machine.allocate(value=b"Z"*(machine.pointer_size+8))
            equal(call("DuplicateHandle",[invalid,owner,invalid,output,0,0,2]),1)
            duplicate=machine.read_pointer(output)
            true(duplicate!=owner)
            if architecture=="amd64":
                true(duplicate>0xffffffff)
            equal(machine.read(output+machine.pointer_size,8),b"Z"*8)
            equal(call("CloseHandle",[owner]),1)
            equal(kernel.state["pending_file_deletes"],{})
            equal(call("CloseHandle",[duplicate]),1)
            true(name in kernel.state["paths"])
            true(name in kernel.state["pending_file_deletes"])
            equal(call(create,[path,0x80000000,7,0,3,0,0]),invalid)
            buffer=machine.allocate(size=8)
            count=machine.allocate(size=4)
            equal(call("ReadFile",[other,buffer,8,count,0]),1)
            equal(machine.read(buffer,8),b"original")
            equal(call("CloseHandle",[other]),1)
            true(name not in kernel.state["paths"])
            equal(kernel.state["pending_file_deletes"],{})
            # A later create has independent identity and no stale deletion.
            fresh=call(create,[path,0x40000000,7,0,1,0,0])
            true(fresh!=invalid)
            equal(call("CloseHandle",[fresh]),1)
            true(name in kernel.state["paths"])
            renamed = text("D:/temp/renamed")
            owner = call(create,[path,0x80000000,7,0,3,0x04000000,0])
            move = "MoveFileW" if wide else "MoveFileA"
            equal(call(move,[path,renamed]),1)
            fresh = call(create,[path,0x40000000,7,0,1,0,0])
            true(fresh!=invalid)
            equal(call("CloseHandle",[owner]),1)
            true(name in kernel.state["paths"])
            true(r"d:\temp\renamed" not in kernel.state["paths"])
            equal(call("CloseHandle",[fresh]),1)

def test_kernel_hard_link_identity_and_lifetime():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"](files = {"D:/store/a.inf": b"abcdefgh"}, directories = ["D:/inf", "E:/inf"], volumes = {"D:": {"filesystem": "NTFS", "serial": 42}, "E:": {"filesystem": "NTFS", "serial": 43}})
        machine.use(kernel)
        invalid = (1 << (machine.pointer_size * 8)) - 1
        def text(s):
            return machine.allocate(value = binary.encode(s, encoding = "utf16le", nul = True))
        def call(api, args):
            result = machine.call(machine.resolve_export("kernel32.dll", name = api), args = args)
            equal(result.reason, "return", result.detail)
            return result.value
        source, alias = text("D:/store/a.inf"), text("D:/inf/b.inf")
        source_key, alias_key = r"d:\store\a.inf", r"d:\inf\b.inf"
        kernel.state["paths"][source_key]["security"] = b"source-owned-descriptor"
        for dest, src, reserved, error in [(text("E:/inf/c.inf"), source, 0, 17), (text("D:/missing/c.inf"), source, 0, 3), (alias, text("D:/store/missing.inf"), 0, 2), (alias, text("D:/store"), 0, 5), (alias, source, 1, 87)]:
            equal(call("CreateHardLinkW", [dest, src, reserved]), 0)
            equal(kernel.state["last_error"], error)
            true(alias_key not in kernel.state["paths"])
        equal(call("CreateHardLinkW", [alias, source, 0]), 1)
        equal(call("CreateHardLinkW", [alias, source, 0]), 0)
        equal(kernel.state["last_error"], 183)
        # Linking a lazy input does not read or duplicate its payload.
        true("data" not in kernel.state["paths"][source_key])
        equal(kernel.state["paths"][alias_key]["security"], b"source-owned-descriptor")
        a = call("CreateFileW", [source, 0xc0000000, 7, 0, 3, 0, 0])
        b = call("CreateFileW", [alias, 0xc0000000, 7, 0, 3, 0, 0])
        true(a != invalid and b != invalid)
        info = machine.allocate(value = b"Z" * 56)
        equal(call("GetFileInformationByHandle", [a, info]), 1)
        equal(machine.read_u32le(info + 28), 42)
        equal(machine.read_u32le(info + 40), 2)
        identity = machine.read(info + 44, 8)
        true(identity != b"\x00" * 8)
        equal(call("GetFileInformationByHandle", [b, info]), 1)
        equal(machine.read(info + 44, 8), identity)
        equal(machine.read(info + 52, 4), b"ZZZZ")
        data = machine.allocate(value = b"XY")
        count = machine.allocate(value = b"Y" * 8)
        equal(call("SetFilePointer", [b, 2, 0, 0]), 2)
        equal(call("WriteFile", [b, data, 2, count, 0]), 1)
        equal(kernel.state["file_data"](source_key), b"abXYefgh")
        stamp = machine.allocate(value = binary.u64le(123456))
        equal(call("SetFileTime", [b, 0, 0, stamp]), 1)
        equal(call("GetFileInformationByHandle", [a, info]), 1)
        equal(machine.read_u64le(info + 20), 123456)
        # CREATE_ALWAYS truncates the shared file instead of replacing one alias.
        truncate = call("CreateFileW", [alias, 0x40000000, 7, 0, 2, 0, 0])
        true(truncate != invalid)
        equal(call("GetFileSize", [a, 0]), 0)
        equal(call("WriteFile", [truncate, data, 2, count, 0]), 1)
        equal(call("CloseHandle", [truncate]), 1)
        # A pending unlink keeps its live references and blocks reopening.
        equal(call("DeleteFileW", [alias]), 1)
        true(alias_key in kernel.state["paths"])
        equal(call("CreateFileW", [alias, 0, 7, 0, 3, 0, 0]), invalid)
        equal(kernel.state["last_error"], 5)
        equal(call("CloseHandle", [b]), 1)
        true(alias_key in kernel.state["paths"])
        equal(call("CloseHandle", [a]), 1)
        true(alias_key not in kernel.state["paths"])
        equal(kernel.state["file_data"](source_key), b"XY")
        # A new occupant of the deleted name has its own identity and bytes.
        fresh = call("CreateFileW", [alias, 0xc0000000, 7, 0, 1, 0, 0])
        equal(call("GetFileInformationByHandle", [fresh, info]), 1)
        true(machine.read(info + 44, 8) != identity)
        equal(call("CloseHandle", [fresh]), 1)
        equal(call("DeleteFileW", [alias]), 1)
        equal(call("CreateHardLinkW", [alias, source, 0]), 1)
        exclusive = call("CreateFileW", [source, 0x80000000, 0, 0, 3, 0, 0])
        equal(call("CreateFileW", [alias, 0x80000000, 7, 0, 3, 0, 0]), invalid)
        equal(kernel.state["last_error"], 32)
        equal(call("DeleteFileW", [alias]), 0)
        equal(kernel.state["last_error"], 32)
        equal(call("CloseHandle", [exclusive]), 1)
        # Cloning preserves aliases but owns a separate mutable object.
        cloned = module["kernel32_plugin"](prepared_file_entries = kernel.state["paths"])
        true(cloned.state["write_file_data"](alias_key, 0, b"QR"))
        equal(cloned.state["file_data"](source_key), b"QR")
        equal(kernel.state["file_data"](source_key), b"XY")
        # Overwriting a destination updates every alias; copying onto one's
        # own alias fails without truncating either name.
        copied = text("D:/store/copied.inf")
        equal(call("CopyFileW", [source, alias, 0]), 0)
        equal(kernel.state["last_error"], 32)
        equal(call("CopyFileW", [source, copied, 0]), 1)
        copy_handle = call("CreateFileW", [copied, 0x40000000, 7, 0, 3, 0, 0])
        machine.write(data, b"IJ")
        equal(call("WriteFile", [copy_handle, data, 2, count, 0]), 1)
        equal(call("CloseHandle", [copy_handle]), 1)
        equal(call("CopyFileExW", [copied, alias, 0, 0, 0, 0]), 1)
        equal(kernel.state["file_data"](source_key), b"IJ")
        equal(kernel.state["file_data"](alias_key), b"IJ")

def test_kernel_hard_link_mappings_and_clone():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"](files = {"D:/a": b"abcdefgh"}, volumes = {"D:": {"filesystem": "NTFS"}})
        machine.use(kernel)
        def text(s):
            return machine.allocate(value = binary.encode(s, encoding = "utf16le", nul = True))
        def call(m, api, args):
            result = m.call(m.resolve_export("kernel32.dll", name = api), args = args)
            equal(result.reason, "return", result.detail)
            return result.value
        a, b, renamed = text("D:/a"), text("D:/b"), text("D:/renamed")
        equal(call(machine, "CreateHardLinkW", [b, a, 0]), 1)
        opened = call(machine, "CreateFileW", [a, 0xc0000000, 7, 0, 3, 0, 0])
        other = call(machine, "CreateFileW", [b, 0xc0000000, 7, 0, 3, 0, 0])
        mapping = call(machine, "CreateFileMappingW", [opened, 0, 4, 0, 0, 0])
        view = call(machine, "MapViewOfFile", [mapping, 2, 0, 0, 8])
        data = machine.allocate(value = b"XY")
        count = machine.allocate(size = 4)
        equal(call(machine, "WriteFile", [other, data, 2, count, 0]), 1)
        equal(machine.read(view, 8), b"XYcdefgh")
        machine.write(view + 2, b"UV")
        equal(call(machine, "FlushViewOfFile", [view, 8]), 1)
        equal(kernel.state["file_data"](r"d:\a"), b"XYUVefgh")
        # machine.snapshot() forks CPU/memory, NOT semantic plugin state.
        # Independent API variants require a fresh kernel namespace clone.
        cloned_machine = emulator.machine(code = b"\xc3", architecture = architecture)
        cloned_kernel = module["kernel32_plugin"](prepared_file_entries = kernel.state["paths"])
        cloned_machine.use(cloned_kernel)
        cloned_name = cloned_machine.allocate(value = binary.encode("D:/b", encoding = "utf16le", nul = True))
        cloned_data = cloned_machine.allocate(value = b"QQ")
        cloned_count = cloned_machine.allocate(size = 4)
        cloned_file = call(cloned_machine, "CreateFileW", [cloned_name, 0x40000000, 7, 0, 3, 0, 0])
        equal(call(cloned_machine, "WriteFile", [cloned_file, cloned_data, 2, cloned_count, 0]), 1)
        equal(cloned_kernel.state["file_data"](r"d:\a"), b"QQUVefgh")
        equal(machine.read(view, 8), b"XYUVefgh")
        equal(kernel.state["file_data"](r"d:\b"), b"XYUVefgh")
        equal(call(machine, "MoveFileW", [a, renamed]), 1)
        fresh = call(machine, "CreateFileW", [a, 0xc0000000, 7, 0, 1, 0, 0])
        equal(call(machine, "WriteFile", [fresh, data, 2, count, 0]), 1)
        machine.write(view + 4, b"ZZ")
        equal(call(machine, "FlushViewOfFile", [view, 8]), 1)
        equal(kernel.state["file_data"](r"d:\renamed"), b"XYUVZZgh")
        equal(kernel.state["file_data"](r"d:\b"), b"XYUVZZgh")
        equal(kernel.state["file_data"](r"d:\a"), b"XY")
        equal(call(machine, "DeleteFileW", [b]), 1)
        equal(call(machine, "CloseHandle", [opened]), 1)
        equal(call(machine, "CloseHandle", [other]), 1)
        equal(call(machine, "CloseHandle", [mapping]), 1)
        true(r"d:\b" in kernel.state["paths"])
        equal(call(machine, "UnmapViewOfFile", [view]), 1)
        true(r"d:\b" not in kernel.state["paths"])
        equal(kernel.state["file_data"](r"d:\renamed"), b"XYUVZZgh")
        equal(call(machine, "CloseHandle", [fresh]), 1)

def test_kernel_copy_file_ex_effects_and_failure_atomicity():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"](files = {"C:/Input/source.sys": b"MZactual-driver", "C:/Output/existing.sys": b"original"}, directories = ["C:/Output"])
        machine.use(kernel)
        copy = machine.resolve_export("kernel32.dll", name = "CopyFileExW")
        source = machine.allocate(value = binary.encode("C:/Input/source.sys", encoding = "utf16le", nul = True))
        output = machine.allocate(value = binary.encode("C:/Output/new.sys", encoding = "utf16le", nul = True))
        existing = machine.allocate(value = binary.encode("C:/Output/existing.sys", encoding = "utf16le", nul = True))
        absent = machine.allocate(value = binary.encode("C:/Missing/new.sys", encoding = "utf16le", nul = True))
        key = "c:" + chr(92) + "input" + chr(92) + "source.sys"
        destination = "c:" + chr(92) + "output" + chr(92) + "new.sys"
        original = "c:" + chr(92) + "output" + chr(92) + "existing.sys"
        metadata = {"attributes": 0x21, "creation_time": 101, "access_time": 102, "write_time": 103, "security": b"owned-descriptor"}
        kernel.state["paths"][key].update(metadata)
        high = 0x600000000000 if architecture == "amd64" else 0
        result = machine.call(copy, args = [source, output, 0, 0, 0, high])
        equal(kernel.state["last_error"], 0)
        equal(result.reason, "return")
        equal(result.value, 1, architecture + " copy failed: " + str(result.detail) + " queries=" + str(kernel.state["file_queries"]))
        entry = kernel.state["paths"][destination]
        equal(entry["data"], b"MZactual-driver")
        equal(entry["size"], len(b"MZactual-driver"))
        true(entry["dirty"])
        for field, value in metadata.items():
            equal(entry[field], value)
        for target, flags, expected in [(existing, 1, 80), (absent, 0, 3), (output, 0, 5)]:
            result = machine.call(copy, args = [source, target, 0, 0, 0, high | flags])
            equal(result.reason, "return")
            equal(result.value, 0)
            equal(kernel.state["last_error"], expected)
            equal(kernel.state["file_data"](original), b"original")
        cancel = machine.allocate(size = 4)
        machine.write_u32le(cancel, 1)
        result = machine.call(copy, args = [source, existing, 0, 0, cancel, 0])
        equal(result.value, 0)
        equal(kernel.state["last_error"], 1235)
        result = machine.call(copy, args = [source, existing, 123, 0, 0, 0])
        equal(result.reason, "plugin")
        true("progress callbacks are not modeled" in result.detail)
        equal(kernel.state["file_data"](original), b"original")

def test_kernel_dos_device_name_native_boundaries():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(module["kernel32_plugin"]())
        classify = machine.resolve_export("ntdll.dll", name = "RtlIsDosDeviceName_U")
        equal(machine.call(classify, args = [0]).value, 0)
        for path, expected in [
            ("", 0), ("SET1.tmp", 0), ("D:/dir/SET1.tmp", 0),
            ("CON", 6), ("nul", 6), ("AUX", 6), ("PRN", 6),
            ("COM1", 8), ("COM9", 8), ("COM0", 0), ("COM10", 0),
            ("LPT1", 8), ("LPT9", 8), ("LPT0", 0),
            ("CONIN$", 12), ("CONOUT$", 14), ("CLOCK$", 0),
            ("NUL   ", 6), ("NUL...", 6), ("NUL:", 6),
            ("C:/foo/NUL", 0xe0006), ("foo/NUL/bar", 0),
            ("//server/share/NUL", 0), ("//./CON", 0), ("//?/C:/NUL", 0),
        ]:
            for spelling in [path, path.replace("/", chr(92))]:
                source = machine.allocate(value = binary.encode(spelling, encoding = "utf16le", nul = True))
                result = machine.call(classify, args = [source])
                equal(result.reason, "return")
                equal(result.value, expected)
        source = machine.allocate(value = binary.encode("NUL.txt", encoding = "utf16le", nul = True))
        result = machine.call(classify, args = [source])
        equal(result.reason, "plugin")
        true("native DOS-device process policy" in result.detail)

def test_kernel_ansi_char_native_pointer_advance():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(module["kernel32_plugin"]())
        convert = machine.resolve_export("ntdll.dll", name = "RtlAnsiCharToUnicodeChar")
        source = machine.allocate(value = b"ZZ")
        slot = machine.allocate(value = b"Z" * (machine.pointer_size + 8))
        # Native original-media NTDLL: ASCII identity, one-byte consumption,
        # including NUL; only the native-width caller pointer is changed.
        for value in range(128):
            machine.write(source, bytes([value, 90]))
            machine.write_pointer(slot, source)
            result = machine.call(convert, args = [slot])
            equal(result.reason, "return")
            equal(result.value, value)
            equal(machine.read_pointer(slot), source + 1)
            equal(machine.read(source, 2), bytes([value, 90]))
            equal(machine.read(slot + machine.pointer_size, 8), b"Z" * 8)
        machine.write(source, b"\x80Z")
        machine.write_pointer(slot, source)
        result = machine.call(convert, args = [slot])
        equal(result.reason, "plugin")
        true("native NLS code-page table" in result.detail)
        equal(machine.read_pointer(slot), source)

def test_kernel_upcase_unicode_char_parameter_width():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(module["kernel32_plugin"]())
        upcase = machine.resolve_export("ntdll.dll", name = "RtlUpcaseUnicodeChar")
        high = 0x7fff12340000 if architecture == "amd64" else 0x12340000
        for unit, expected in [(0, 0), (ord("a"), ord("A")), (ord("z"), ord("Z")), (ord("D"), ord("D")), (ord("/"), ord("/"))]:
            result = machine.call(upcase, args = [high | unit])
            equal(result.reason, "return")
            equal(result.value, expected)
        result = machine.call(upcase, args = [0xe9])
        equal(result.reason, "plugin")
        true("native NLS upcase table" in result.detail)

def test_kernel_find_failure_handle_native_width():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"](directories = ["C:/Input"])
        machine.use(kernel)
        invalid = (1 << (machine.pointer_size * 8)) - 1
        output = machine.allocate(value = b"Z" * 592)
        for suffix, encoding in [("A", "ascii"), ("W", "utf16le")]:
            find = machine.resolve_export("kernel32.dll", name = "FindFirstFile" + suffix)
            for path, error in [("C:/Input/missing.inf", 2), ("C:/Absent/missing.inf", 3)]:
                source = machine.allocate(value = binary.encode(path, encoding = encoding, nul = True))
                result = machine.call(find, args = [source, output])
                equal(result.reason, "return")
                equal(result.value, invalid)
                equal(kernel.state["last_error"], error)
                equal(machine.read(output, 592), b"Z" * 592)
                # GetFileAttributes returns DWORD, not HANDLE.
                attributes = machine.resolve_export("kernel32.dll", name = "GetFileAttributes" + suffix)
                equal(machine.call(attributes, args = [source]).value, 0xffffffff)
            equal(machine.call(find, args = [0, output]).value, invalid)
            equal(kernel.state["last_error"], 87)

def test_kernel_child_process_exit_code_and_handle_lifetime():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    def child(machine, request):
        equal(request["command_line"], "bounded-child")
        return {"process_id": 16, "thread_id": 20, "exit_code": 0x80070005}
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"](on_process_create = child)
        machine.use(kernel)
        width = machine.pointer_size
        command = machine.allocate(value = binary.encode("bounded-child", encoding = "utf16le", nul = True))
        info_size = 2 * width + 8
        info = machine.allocate(value = b"Z" * (info_size + 4))
        output = machine.allocate(value = b"Z" * 8)
        create = machine.resolve_export("kernel32.dll", name = "CreateProcessW")
        query = machine.resolve_export("kernel32.dll", name = "GetExitCodeProcess")
        wait = machine.resolve_export("kernel32.dll", name = "WaitForSingleObject")
        close = machine.resolve_export("kernel32.dll", name = "CloseHandle")
        error = machine.resolve_export("kernel32.dll", name = "GetLastError")
        result = machine.call(create, args = [0, command, 0, 0, 0, 0, 0, 0, 0, info])
        equal(result.reason, "return", result.detail)
        equal(result.value, 1)
        equal(machine.read(info + info_size, 4), b"ZZZZ")
        process = machine.read_pointer(info)
        thread = machine.read_pointer(info + width)
        equal(machine.call(wait, args = [process, 0]).value, 0)
        equal(machine.call(query, args = [process, output]).value, 1)
        equal(machine.read_u32le(output), 0x80070005)
        equal(machine.read(output + 4, 4), b"ZZZZ")
        # A running process is not a completed zero-exit child.
        current = (1 << (8 * width)) - 1
        equal(machine.call(query, args = [current, output]).value, 1)
        equal(machine.read_u32le(output), 259)
        equal(machine.call(query, args = [process, 0]).value, 0)
        equal(machine.call(error).value, 87)
        invalid = [thread, 0, process + (1 << 32)] if width == 8 else [thread, 0]
        for handle in invalid:
            machine.write(output, b"Z" * 8)
            equal(machine.call(query, args = [handle, output]).value, 0)
            equal(machine.call(error).value, 6)
            equal(machine.read(output, 8), b"Z" * 8)
        duplicate = machine.allocate(size = width)
        equal(machine.call(machine.resolve_export("kernel32.dll", name = "DuplicateHandle"), args = [current, process, current, duplicate, 0, 0, 2]).value, 1)
        retained = machine.read_pointer(duplicate)
        equal(machine.call(close, args = [process]).value, 1)
        equal(machine.call(query, args = [process, output]).value, 0)
        equal(machine.call(error).value, 6)
        equal(machine.call(query, args = [retained, output]).value, 1)
        equal(machine.read_u32le(output), 0x80070005)
        equal(machine.call(close, args = [retained]).value, 1)
        equal(machine.call(close, args = [thread]).value, 1)

def test_kernel_redirection_trust_policy():
    factory = testing.module("@stdlib//windows/selfreg:win32.star")["kernel32_plugin"]
    for invalid in [-1, 4, True, "0"]:
        raises(factory, kwargs = {"redirection_trust_policy": invalid}, message = "explicit RedirectionGuard")
    for entry in [{"directory": True, "attributes": 0x400}, {"directory": True, "reparse_data": b"x"}]:
        raises(factory, kwargs = {"redirection_trust_policy": 0, "prepared_file_entries": {"c:\\junction": entry}}, message = "junction-free")
    for architecture in ["x86", "amd64"]:
        for initial in [0, 1, 2, 3]:
            machine = emulator.machine(code = b"\xc3", architecture = architecture)
            kernel = factory(redirection_trust_policy = initial)
            machine.use(kernel)
            query = machine.resolve_export("kernel32.dll", name = "GetProcessMitigationPolicy")
            change = machine.resolve_export("kernel32.dll", name = "SetProcessMitigationPolicy")
            error = machine.resolve_export("kernel32.dll", name = "GetLastError")
            current = (1 << (8 * machine.pointer_size)) - 1
            output = machine.allocate(value = b"Z" * 8)
            result = machine.call(query, args = [current, 16, output, 4])
            equal(result.reason, "return", result.detail)
            equal(result.value, 1)
            equal(machine.read_u32le(output), initial)
            equal(machine.read(output + 4, 4), b"ZZZZ")
            # Execute the same read/enable/write/read transition as the native
            # SecurityHealth helper; audit mode must survive enabling enforcement.
            machine.write_u32le(output, initial | 1)
            equal(machine.call(change, args = [16, output, 4]).value, 1)
            machine.write(output, b"Z" * 8)
            equal(machine.call(query, args = [current, 16, output, 4]).value, 1)
            equal(machine.read_u32le(output), initial | 1)
            equal(machine.read(output + 4, 4), b"ZZZZ")
            for length in [0, 3, 8] + ([0x100000004] if machine.pointer_size == 8 else []):
                machine.write(output, b"Z" * 8)
                equal(machine.call(query, args = [current, 16, output, length]).value, 0)
                equal(machine.call(error).value, 87)
                equal(machine.read(output, 8), b"Z" * 8)
                equal(machine.call(change, args = [16, output, length]).value, 0)
                equal(kernel.state["redirection_trust_policy"], initial | 1)
            equal(machine.call(query, args = [current, 16, 0, 4]).value, 0)
            equal(machine.call(change, args = [16, 0, 4]).value, 0)
            machine.write_u32le(output, 4)
            equal(machine.call(change, args = [16, output, 4]).value, 0)
            equal(machine.call(error).value, 87)
            equal(kernel.state["redirection_trust_policy"], initial | 1)
            wrong = [0, current - 1] + ([0xffffffff] if machine.pointer_size == 8 else [])
            for handle in wrong:
                machine.write(output, b"Z" * 8)
                equal(machine.call(query, args = [handle, 16, output, 4]).value, 0)
                equal(machine.call(error).value, 6)
                equal(machine.read(output, 8), b"Z" * 8)
            unsupported = machine.call(query, args = [current, 7, output, 4])
            true(unsupported.reason != "return")
            true("not modeled" in unsupported.detail)
        # Unspecified initial policy is an explicit missing fact, never success.
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(factory())
        output = machine.allocate(value = b"Z" * 8)
        query = machine.resolve_export("kernel32.dll", name = "GetProcessMitigationPolicy")
        current = (1 << (8 * machine.pointer_size)) - 1
        result = machine.call(query, args = [current, 16, output, 4])
        true(result.reason != "return")
        true("explicit initial policy" in result.detail)
        equal(machine.read(output, 8), b"Z" * 8)

def test_kernel_mutex_handle_independence():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"]()
        machine.use(kernel)
        close = machine.resolve_export("kernel32.dll", name = "CloseHandle")
        wait = machine.resolve_export("kernel32.dll", name = "WaitForSingleObject")
        for name, extended in [("CreateMutexW", False), ("CreateMutexExW", True)]:
            create = machine.resolve_export("kernel32.dll", name = name)
            args = [0, 0, 0, 0x1f0001] if extended else [0, 0, 0]
            first = machine.call(create, args = args).value
            second = machine.call(create, args = args).value
            true(first != second)
            equal(machine.call(close, args = [first]).value, 1)
            equal(machine.call(wait, args = [second, 0]).value, 0)
            equal(machine.call(close, args = [second]).value, 1)
        name = machine.allocate(value = binary.encode("NativeMutex", encoding = "utf16le", nul = True))
        create = machine.resolve_export("kernel32.dll", name = "CreateMutexW")
        first = machine.call(create, args = [0, 0, name]).value
        second = machine.call(create, args = [0, 1, name]).value
        true(first != second)
        equal(kernel.state["last_error"], 183)
        opened = machine.call(machine.resolve_export("kernel32.dll", name = "OpenMutexW"), args = [0x1f0001, 0, name]).value
        true(opened != first and opened != second)
        equal(machine.call(close, args = [first]).value, 1)
        equal(machine.call(close, args = [second]).value, 1)
        equal(machine.call(wait, args = [opened, 0]).value, 0)
        equal(machine.call(close, args = [opened]).value, 1)
        equal(machine.call(machine.resolve_export("kernel32.dll", name = "OpenMutexW"), args = [0x1f0001, 0, name]).value, 0)
        equal(kernel.state["last_error"], 2)

def test_kernel_guid_from_counted_string_native_effects():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(module["kernel32_plugin"]())
        layout = abi["counted_string_layout"](machine.pointer_size)
        descriptor = machine.allocate(size = layout["Size"])
        output = machine.allocate(size = 20)
        parse = machine.resolve_export("ntdll.dll", name = "RtlGUIDFromString")
        prefix = binary.builder()
        prefix.u32le(0x4d36e97d)
        prefix.u16le(0xe325)
        prefix.u16le(0x11ce)
        for text, status, fields in [
            ("{4d36e97d-e325-11ce-bfc1-08002be10318}", 0, 8),
            ("4d36e97d-e325-11ce-bfc1-08002be10318", 0xc000000d, 0),
            ("{4d36e97d-e325-11ce-bfc1-08002be10318}extra", 0xc000000d, 8),
            ("{4d36e97d-e325-zzzz-bfc1-08002be10318}", 0xc000000d, 6),
            ("{4d36e97d-e325-11ce-bfc1-08002be1031z}", 0xc000000d, 8),
        ]:
            data = binary.encode(text, encoding = "utf16le")
            source = machine.allocate(value = data)  # No terminator.
            machine.write_u16le(descriptor, len(data))
            machine.write_u16le(descriptor + 2, len(data))
            machine.write_pointer(descriptor + layout["Buffer"], source)
            machine.write(output, b"Z" * 20)
            result = machine.call(parse, args = [descriptor, output])
            equal(result.reason, "return")
            equal(result.value, status)
            equal(machine.read(output, fields), prefix.bytes()[:fields])
            if status == 0:
                equal(machine.read(output + 8, 8), b"\xbf\xc1\x08\x00\x2b\xe1\x03\x18")
                equal(machine.read(output + 16, 4), b"ZZZZ")
            else:
                equal(machine.read(output + fields, 20 - fields), b"Z" * (20 - fields))

def test_crt_integer_end_pointer_native_width():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(module["msvcrt_plugin"]())
        output = machine.allocate(size = machine.pointer_size + 4)
        for name, encoding, width in [("strtoul", "ascii", 1), ("wcstol", "utf16le", 2), ("wcstoul", "utf16le", 2)]:
            parse = machine.resolve_export("msvcrt.dll", name = name)
            for text, radix, value, consumed in [("  3426tail", 10, 3426, 6), ("0x10z", 0, 16, 4), ("abc", 10, 0, 0)]:
                source = machine.allocate(value = binary.encode(text, encoding = encoding, nul = True))
                machine.write(output, b"Z" * (machine.pointer_size + 4))
                result = machine.call(parse, args = [source, output, radix])
                equal(result.reason, "return")
                equal(result.value, value)
                equal(machine.read_pointer(output), source + consumed * width)
                equal(machine.read(output + machine.pointer_size, 4), b"ZZZZ")

def test_kernel_file_mapping_native_dword_widths():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        data = binary.builder()
        data.reserve(65536)
        data.append(b"AB")
        kernel = module["kernel32_plugin"](files = {"C:/Input/data.bin": data.bytes()})
        machine.use(kernel)
        path = machine.allocate(value = binary.encode("C:/Input/data.bin", encoding = "utf16le", nul = True))
        file = machine.call(machine.resolve_export("kernel32.dll", name = "CreateFileW"), args = [path, 0x80000000, 1, 0, 3, 0, 0]).value
        high = 0x7fff00000000 if architecture == "amd64" else 0
        create = machine.resolve_export("kernel32.dll", name = "CreateFileMappingW")
        result = machine.call(create, args = [file, 0, high | 2, high, high | 65538, 0])
        equal(result.reason, "return")
        true(result.value != 0)
        mapping = result.value
        equal(kernel.state["file_queries"][-1]["size"], 65538)
        equal(kernel.state["file_queries"][-1]["protect"], 2)
        view = machine.resolve_export("kernel32.dll", name = "MapViewOfFile")
        result = machine.call(view, args = [mapping, 4, high, high | 65536, 2])
        equal(result.reason, "return")
        true(result.value != 0)
        equal(machine.read(result.value, 2), b"AB")
        equal(kernel.state["file_queries"][-1]["offset"], 65536)
        equal(machine.call(machine.resolve_export("kernel32.dll", name = "UnmapViewOfFile"), args = [result.value]).value, 1)
        if architecture == "amd64":
            # NumberOfBytesToMap is SIZE_T, unlike the DWORD offset fields.
            equal(machine.call(view, args = [mapping, 4, 0, 65536, 0x100000002]).value, 0)
            equal(kernel.state["last_error"], 87)
        invalid = 0xffffffffffffffff if architecture == "amd64" else 0xffffffff
        page = machine.call(create, args = [invalid, 0, 4, 0, 8, 0])
        equal(page.reason, "return")
        true(page.value != 0)
        address = machine.call(view, args = [page.value, 4, 0, 0, 8]).value
        true(address != 0)
        equal(machine.read(address, 8), b"\x00" * 8)

def test_kernel_compare_string_ordinal_units():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"]()
        machine.use(kernel)
        compare = machine.resolve_export("kernel32.dll", name = "CompareStringOrdinal")
        for left, right, count, insensitive, expected in [
            (b"a\x00b\x00", b"A\x00B\x00", 2, 1, 2),
            (b"a\x00b\x00", b"A\x00B\x00", 2, 0, 3),
            (b"\x00\x01", b"\xff\x00", 1, 0, 3),
            (b"\x00\xd8", b"\x00\xe0", 1, 0, 1),
            (b"a\x00\x00\x00b\x00", b"a\x00\x00\x00c\x00", 3, 0, 1),
            (b"a\x00\x00\x00b\x00", b"a\x00\x00\x00c\x00", 0xffffffff, 0, 2),
        ]:
            a = machine.allocate(value = left)
            b = machine.allocate(value = right)
            size = count | (0x7fff00000000 if architecture == "amd64" else 0)
            result = machine.call(compare, args = [a, size, b, size, insensitive])
            equal(result.reason, "return")
            equal(result.value, expected)
        empty = machine.allocate(size = 2)
        equal(machine.call(compare, args = [empty, 0, empty, 0, 0]).value, 2)
        equal(machine.call(compare, args = [empty, 0, empty, 1, 0]).value, 1)
        equal(machine.call(compare, args = [empty, 0xfffffffe, empty, 0, 0]).value, 0)
        equal(kernel.state["last_error"], 87)

def test_kernel_duplicate_unicode_string_native_contract():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"]()
        machine.use(kernel)
        layout = abi["counted_string_layout"](machine.pointer_size)
        duplicate = machine.resolve_export("ntdll.dll", name = "RtlDuplicateUnicodeString")
        free = machine.resolve_export("ntdll.dll", name = "RtlFreeUnicodeString")
        source = machine.allocate(value = b"A\x00\x00\xd8Z\x00")
        descriptor = machine.allocate(size = layout["Size"])
        output = machine.allocate(value = b"Z" * (layout["Size"] + 8))
        high = 0x600000000000 if architecture == "amd64" else 0
        machine.write_u16le(descriptor, 4)
        machine.write_u16le(descriptor + 2, 6)
        machine.write_pointer(descriptor + layout["Buffer"], source)
        for flags in [0, 1, 3]:
            machine.write(output, b"Z" * (layout["Size"] + 8))
            result = machine.call(duplicate, args = [high | flags, descriptor, output])
            equal(result.reason, "return")
            equal(result.value, 0)
            address = machine.read_pointer(output + layout["Buffer"])
            true(address != source)
            equal(machine.read_u16le(output), 4)
            equal(machine.read_u16le(output + 2), 4 if flags == 0 else 6)
            equal(machine.read(address, 4), b"A\x00\x00\xd8")
            if flags:
                equal(machine.read(address + 4, 2), b"\x00\x00")
            equal(machine.read(output + layout["Size"], 8), b"Z" * 8)
            true(address in kernel.state["local_allocations"])
            machine.call(free, args = [output])
            true(address not in kernel.state["local_allocations"])
        for flags, length, maximum, status in [(2, 4, 6, 0xc000000d), (4, 4, 6, 0xc000000d), (1, 3, 6, 0xc000000d), (1, 4, 3, 0xc000000d), (1, 65534, 65534, 0xc0000106)]:
            machine.write_u16le(descriptor, length)
            machine.write_u16le(descriptor + 2, maximum)
            machine.write(output, b"Z" * layout["Size"])
            equal(machine.call(duplicate, args = [flags, descriptor, output]).value, status)
            equal(machine.read(output, layout["Size"]), b"Z" * layout["Size"])
        for flags in [0, 1, 3]:
            equal(machine.call(duplicate, args = [flags, 0, output]).value, 0)
            equal(machine.read_u16le(output), 0)
            equal(machine.read_u16le(output + 2), 2 if flags == 3 else 0)
            address = machine.read_pointer(output + layout["Buffer"])
            if flags == 3:
                true(address != 0)
                equal(machine.read(address, 2), b"\x00\x00")
            else:
                equal(address, 0)
            machine.call(free, args = [output])

def test_kernel_prefix_counted_unicode_strings():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(module["kernel32_plugin"]())
        layout = abi["counted_string_layout"](machine.pointer_size)
        left = machine.allocate(size = layout["Size"])
        right = machine.allocate(size = layout["Size"])
        compare = machine.resolve_export("ntdll.dll", name = "RtlPrefixUnicodeString")
        high = 0x600000000000 if architecture == "amd64" else 0x100
        for a, b, insensitive, expected in [
            (b"S\x00Y\x00S\x00", b"s\x00y\x00s\x00X\x00", high | 1, 1),
            (b"S\x00Y\x00S\x00", b"s\x00y\x00s\x00X\x00", high, 0),
            (b"A\x00\x00\x00B\x00", b"a\x00\x00\x00c\x00X\x00", 1, 0),
            (b"\x00\xd8", b"\x00\xd8X\x00", 1, 1),
            (b"ABCDEF", b"ABCD", 0, 0),
        ]:
            for descriptor, data in [(left, a), (right, b)]:
                machine.write_u16le(descriptor, len(data))
                machine.write_pointer(descriptor + layout["Buffer"], machine.allocate(value = data))
            result = machine.call(compare, args = [left, right, insensitive])
            equal(result.reason, "return")
            equal(result.value, expected)
        machine.write_u16le(left, 0)
        machine.write_pointer(left + layout["Buffer"], 1)
        machine.write_pointer(right + layout["Buffer"], 1)
        equal(machine.call(compare, args = [left, right, 1]).value, 1)
        for descriptor, data in [(left, b"\xe9\x00"), (right, b"\xc9\x00")]:
            machine.write_u16le(descriptor, 2)
            machine.write_pointer(descriptor + layout["Buffer"], machine.allocate(value = data))
        result = machine.call(compare, args = [left, right, 1])
        equal(result.reason, "plugin")
        true("NLS" in result.detail)

def test_kernel_equal_counted_unicode_strings():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(module["kernel32_plugin"]())
        layout = abi["counted_string_layout"](machine.pointer_size)
        left = machine.allocate(size = layout["Size"])
        right = machine.allocate(size = layout["Size"])
        compare = machine.resolve_export("ntdll.dll", name = "RtlEqualUnicodeString")
        for a, b, insensitive, expected in [
            (b"S\x00Y\x00S\x00", b"s\x00y\x00s\x00", 1, 1),
            (b"S\x00Y\x00S\x00", b"s\x00y\x00s\x00", 0x7fff00000000 if architecture == "amd64" else 0x100, 0),
            (b"A\x00\x00\x00B\x00", b"a\x00\x00\x00c\x00", 1, 0),
            (b"\x00\xd8", b"\x00\xd8", 1, 1),
            (b"A", b"A", 0, 1),
        ]:
            for descriptor, data in [(left, a), (right, b)]:
                source = machine.allocate(value = data)
                machine.write_u16le(descriptor, len(data))
                machine.write_u16le(descriptor + 2, len(data))
                machine.write_pointer(descriptor + layout["Buffer"], source)
            result = machine.call(compare, args = [left, right, insensitive])
            equal(result.reason, "return")
            equal(result.value, expected)
        # Length mismatch and two empty strings do not dereference buffers.
        machine.write_pointer(left + layout["Buffer"], 1)
        machine.write_pointer(right + layout["Buffer"], 1)
        machine.write_u16le(left, 2)
        machine.write_u16le(right, 0)
        equal(machine.call(compare, args = [left, right, 1]).value, 0)
        machine.write_u16le(left, 0)
        equal(machine.call(compare, args = [left, right, 1]).value, 1)
        # Do not substitute host Unicode casing for Windows' NLS table.
        for descriptor, data in [(left, b"\xe9\x00"), (right, b"\xc9\x00")]:
            machine.write_u16le(descriptor, 2)
            machine.write_pointer(descriptor + layout["Buffer"], machine.allocate(value = data))
        result = machine.call(compare, args = [left, right, 1])
        equal(result.reason, "plugin")
        true("native NLS upcase table" in result.detail)

def test_kernel_create_unicode_string_owned_buffer():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture, memory_limit = 4 << 20)
        kernel = module["kernel32_plugin"]()
        machine.use(kernel)
        layout = abi["counted_string_layout"](machine.pointer_size)
        output = machine.allocate(value = b"Z" * (layout["Size"] + 4))
        create = machine.resolve_export("ntdll.dll", name = "RtlCreateUnicodeString")
        free = machine.resolve_export("ntdll.dll", name = "RtlFreeUnicodeString")
        for data in [b"\x00\x00", b"A\x00\x00\xd8\x00\x00", binary.encode("A" * 32766, encoding = "utf16le", nul = True)]:
            machine.write(output, b"Z" * (layout["Size"] + 4))
            source = machine.allocate(value = data)
            result = machine.call(create, args = [output, source])
            equal(result.reason, "return")
            equal(result.value, 1)
            owned = machine.read_pointer(output + layout["Buffer"])
            equal(owned != source, True)
            equal(machine.read_u16le(output), len(data) - 2)
            equal(machine.read_u16le(output + 2), len(data))
            equal(machine.read(owned, len(data)), data)
            machine.write_u16le(source, 0x42)
            equal(machine.read(owned, len(data)), data)
            equal(kernel.state["local_allocations"][owned], len(data))
            equal(machine.call(free, args = [output]).reason, "return")
            equal(owned in kernel.state["local_allocations"], False)
            equal(machine.read_u16le(output), 0)
            equal(machine.read_u16le(output + 2), 0)
            equal(machine.read_pointer(output + layout["Buffer"]), 0)
            equal(machine.read(output + layout["Size"], 4), b"ZZZZ")
        # The native oversized-source branch leaves the descriptor unchanged.
        machine.write(output, b"Z" * (layout["Size"] + 4))
        source = machine.allocate(value = binary.encode("A" * 32767, encoding = "utf16le", nul = True))
        equal(machine.call(create, args = [output, source]).value, 0)
        equal(machine.read(output, layout["Size"] + 4), b"Z" * (layout["Size"] + 4))

def test_kernel_multiple_wait_native_width():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"]()
        machine.use(kernel)
        # High bits and array stride both matter on AMD64.
        kernel.state["next_handle"] = 0x100040000 if architecture == "amd64" else 0x40000
        event = machine.call(machine.resolve_export("kernel32.dll", name = "CreateEventW"), args = [0, 1, 0, 0]).value
        semaphore = machine.call(machine.resolve_export("kernel32.dll", name = "CreateSemaphoreW"), args = [0, 1, 1, 0]).value
        handles = machine.allocate(size = 2 * machine.pointer_size)
        machine.write_pointer(handles, event)
        machine.write_pointer(handles + machine.pointer_size, semaphore)
        for name in ["WaitForMultipleObjects", "WaitForMultipleObjectsEx"]:
            wait = machine.resolve_export("kernel32.dll", name = name)
            args = [2, handles, 1, 0] + ([0] if name.endswith("Ex") else [])
            # Wait-all timeout must not consume the ready semaphore.
            result = machine.call(wait, args = args)
            equal(result.reason, "return")
            equal(result.value, 0x102)
            args[2] = 0
            equal(machine.call(wait, args = args).value, 1)
            equal(machine.call(wait, args = args).value, 0x102)
            machine.call(machine.resolve_export("kernel32.dll", name = "ReleaseSemaphore"), args = [semaphore, 1, 0])
        # Suspended waits must retain the same full-width handle array.
        machine.call(machine.resolve_export("kernel32.dll", name = "WaitForMultipleObjects"), args = [2, handles, 0, 0])
        current = {}
        kernel.state["current_thread"] = current
        result = machine.call(machine.resolve_export("kernel32.dll", name = "WaitForMultipleObjectsEx"), args = [2, handles, 0, 10, 0])
        equal(result.reason, "wait")
        equal(current["wait"]["handles"], [event, semaphore])
        kernel.state["current_thread"] = None
        for count in [0, 65]:
            equal(machine.call(machine.resolve_export("kernel32.dll", name = "WaitForMultipleObjects"), args = [count, 0, 0, 0]).value, 0xffffffff)
            equal(kernel.state["last_error"], 87)

def test_kernel_ldr_load_dll_native_pointer_width():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"](virtual_modules = ["msvcrt.dll"])
        machine.use(kernel)
        layout = abi["counted_string_layout"](machine.pointer_size)
        descriptor = machine.allocate(size = layout["Size"])
        text = binary.encode("MSVCRT.dll", encoding = "utf16le")
        source = machine.allocate(value = text)
        machine.write_u16le(descriptor, len(text))
        machine.write_u16le(descriptor + 2, len(text))
        machine.write_pointer(descriptor + layout["Buffer"], source)
        output = machine.allocate(value = b"Z" * (machine.pointer_size + 4))
        result = machine.call(machine.resolve_export("ntdll.dll", name = "LdrLoadDll"), args = [0, 0, descriptor, output])
        equal(result.reason, "return")
        equal(result.value, 0)
        equal(machine.read_pointer(output), kernel.state["modules"]["msvcrt.dll"])
        equal(machine.read(output + machine.pointer_size, 4), b"ZZZZ")
        equal(kernel.state["module_queries"][-1]["module"], "msvcrt.dll")

def test_kernel_system_windows_directory_capacity():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(module["kernel32_plugin"](environment = {"SystemRoot": "D:/OS"}))
        for api, directory in [("GetSystemWindowsDirectory", r"D:\OS"), ("GetSystemDirectory", r"D:\OS\system32")]:
            for suffix, encoding, width in [("A", "ascii", 1), ("W", "utf16le", 2)]:
                export = machine.resolve_export("kernel32.dll", name = api + suffix)
                expected = binary.encode(directory, encoding = encoding, nul = True)
                required = len(expected) // width
                equal(machine.call(export, args = [0, 0]).value, required)
                output = machine.allocate(size = len(expected) + 4)
                machine.write(output, b"Z" * (len(expected) + 4))
                equal(machine.call(export, args = [output, required - 1]).value, required)
                equal(machine.read(output, len(expected) + 4), b"Z" * (len(expected) + 4))
                result = machine.call(export, args = [output, required])
                equal(result.reason, "return")
                equal(result.value, required - 1)
                equal(machine.read(output, len(expected)), expected)
                equal(machine.read(output + len(expected), 4), b"ZZZZ")

def test_kernel_unicode_string_ex_native_boundaries():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use(module["kernel32_plugin"]())
        initialize = machine.resolve_export("ntdll.dll", name = "RtlInitUnicodeStringEx")
        size = 16 if architecture == "amd64" else 8
        pointer_offset = 8 if architecture == "amd64" else 4
        descriptor = machine.allocate(size = size + 4)
        # Native NTDLL clears lengths/padding on overflow but keeps Buffer.
        # No terminator is needed once the source exceeds the length limit.
        for data, status, length in [
            (None, 0, 0),
            (b"\x00\x00", 0, 0),
            (b"\x00\xd8A\x00\x00\x00", 0, 4),
            (binary.encode("A" * 32766, encoding = "utf16le", nul = True), 0, 65532),
            (b"A\x00" * 32767, 0xc0000106, 0),
        ]:
            source = machine.allocate(value = data) if data != None else 0
            machine.write(descriptor, b"Z" * (size + 4))
            result = machine.call(initialize, args = [descriptor, source])
            equal(result.reason, "return")
            equal(result.value, status)
            equal(machine.read_u16le(descriptor), length)
            equal(machine.read_u16le(descriptor + 2), length + 2 if source and status == 0 else 0)
            equal(machine.read_pointer(descriptor + pointer_offset), source)
            if architecture == "amd64":
                equal(machine.read_u32le(descriptor + 4), 0)
            equal(machine.read(descriptor + size, 4), b"ZZZZ")

def test_device_family_info_optional_outputs():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use([module["kernel32_plugin"](version = {"major": 10, "minor": 0, "build": 26100, "revision": 9278, "suite_mask": 0x100})])
        equal(machine.call(machine.resolve_export("ntdll.dll", name = "RtlGetSuiteMask")).value, 0x100)
        version = machine.allocate(size = 284)
        machine.write_u32le(version, 284)
        equal(machine.call(machine.resolve_export("ntdll.dll", name = "RtlGetVersion"), args = [version]).value, 0)
        equal(machine.read_u32le(version + 4), 10)
        equal(machine.read_u32le(version + 8), 0)
        equal(machine.read_u32le(version + 12), 26100)
        equal(machine.read_u16le(version + 280), 0x100)
        query = machine.resolve_export("ntdll.dll", name = "RtlGetDeviceFamilyInfoEnum")
        output = machine.allocate(size = 16)
        result = machine.call(query, args = [output, output + 8, output + 12])
        equal(result.reason, "return")
        equal(machine.read_u64le(output), (10 << 48) | (26100 << 16) | 9278)
        equal(machine.read_u32le(output + 8), 3)
        equal(machine.read_u32le(output + 12), 0)
        equal(machine.call(query, args = [0, 0, 0]).reason, "return")
        equal(machine.call(query, args = [0, output, 0]).reason, "return")
        equal(machine.read_u32le(output), 3)

def test_crt_bsearch_calls_target_comparator():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    # Native comparators returning signed INTs in each calling convention.
    for architecture, code in [("x86", b"\x8b\x44\x24\x04\x8b\x00\x8b\x54\x24\x08\x2b\x02\xc3"), ("amd64", b"\x8b\x01\x2b\x02\xc3")]:
        machine = emulator.machine(code = code, architecture = architecture)
        machine.use([module["msvcrt_plugin"]()])
        search = machine.resolve_export("msvcrt.dll", name = "bsearch")
        values = [2, 4, 8, 16, 32]
        data = binary.builder()
        for value in values:
            data.u32le(value)
        array = machine.allocate(value = data.bytes())
        key = machine.allocate(size = 4)
        for value in [0, 2, 4, 7, 8, 16, 32, 33]:
            machine.write_u32le(key, value)
            result = machine.call(search, args = [key, array, len(values), 4, machine.entry])
            equal(result.reason, "return", result.detail)
            expected = array + values.index(value) * 4 if value in values else 0
            equal(result.value, expected)
        equal(machine.call(search, args = [0, 0, 0, 0, 0]).value, 0)

def test_crt_wcspbrk_returns_first_matching_unit():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use([module["msvcrt_plugin"]()])
        search = machine.resolve_export("msvcrt.dll", name = "wcspbrk")
        value = machine.allocate(value = binary.encode("alphabet", encoding = "utf16le", nul = True))
        wanted = machine.allocate(value = binary.encode("txp", encoding = "utf16le", nul = True))
        missing = machine.allocate(value = binary.encode("123", encoding = "utf16le", nul = True))
        equal(machine.call(search, args = [value, wanted]).value, value + 4)
        equal(machine.call(search, args = [value, missing]).value, 0)

def test_crt_secure_memory_copy_checks_capacity():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use([module["msvcrt_plugin"]()])
        source = machine.allocate(value = b"source")
        for name in ["memcpy_s", "memmove_s"]:
            copy = machine.resolve_export("msvcrt.dll", name = name)
            destination = machine.allocate(value = b"XXXXXXXX")
            equal(machine.call(copy, args = [destination, 8, source, 6]).value, 0)
            equal(machine.read(destination, 8), b"sourceXX")
            machine.write(destination, b"XXXXXXXX")
            equal(machine.call(copy, args = [destination, 4, source, 6]).value, 22)
            equal(machine.read(destination, 8), b"\x00\x00\x00\x00XXXX")
            equal(machine.call(copy, args = [0, 0, 0, 0]).value, 0)
        concatenate = machine.resolve_export("msvcrt.dll", name = "wcscat_s")
        destination = machine.allocate(size = 16, value = binary.encode("base", encoding = "utf16le", nul = True))
        suffix = machine.allocate(value = binary.encode("/ok", encoding = "utf16le", nul = True))
        equal(machine.call(concatenate, args = [destination, 8, suffix]).value, 0)
        equal(machine.read_cstring(destination, encoding = "utf16le"), "base/ok")
        overflow = machine.allocate(value = binary.encode("xx", encoding = "utf16le", nul = True))
        equal(machine.call(concatenate, args = [destination, 8, overflow]).value, 34)
        equal(machine.read_u16le(destination), 0)

def test_kernel_open_process_tracks_current_process():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    kernel = module["kernel32_plugin"]()
    machine.use([kernel])
    open_process = machine.resolve_export("kernel32.dll", name = "OpenProcess")
    handle = machine.call(open_process, args = [0x1000, 1, 4]).value
    true(handle != 0)
    equal(kernel.state["handles"][handle], {
        "kind": "process_reference",
        "value": {"id": 4, "access": 0x1000, "inherit": True},
    })
    equal(machine.call(open_process, args = [0x1000, 0, 99]).value, 0)
    equal(kernel.state["last_error"], 87)

def test_windows_wall_clock_is_coherent_across_apis_and_shared_data():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    expected = 116444736000000000  # 1970-01-01 as Windows FILETIME ticks.

    machine = emulator.x86(code = b"\xc3")
    machine.use([module["kernel32_plugin"](system_time = 0)])
    output = machine.allocate(size = 16)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "GetSystemTimeAsFileTime"), args = [output]).reason, "return")
    equal(machine.read_u64le(output), expected)
    equal(machine.call(machine.resolve_export("ntdll.dll", name = "NtQuerySystemTime"), args = [output]).value, 0)
    equal(machine.read_u64le(output), expected)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "GetSystemTime"), args = [output]).reason, "return")
    equal([machine.read_u16le(output + index * 2) for index in range(8)], [1970, 1, 4, 1, 0, 0, 0, 0])

    file_time = machine.allocate(size = 8)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "GetSystemTimeAsFileTime"), args = [file_time]).reason, "return")
    local = machine.allocate(size = 8)
    round_trip = machine.allocate(size = 8)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "FileTimeToLocalFileTime"), args = [file_time, local]).value, 1)
    equal(machine.read_u64le(local), expected)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "LocalFileTimeToFileTime"), args = [local, round_trip]).value, 1)
    equal(machine.read_u64le(round_trip), expected)

    shared_machine = emulator.x86(code = b"\xc3")
    shared_machine.use([module["environment_plugin"](system_time = 0)])
    equal(shared_machine.read_u32le(0x7ffe0014), expected & 0xffffffff)
    equal(shared_machine.read_u32le(0x7ffe0018), expected >> 32)
    equal(shared_machine.read_u32le(0x7ffe001c), expected >> 32)

def test_kernel_reports_consistent_default_language():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["kernel32_plugin"]()])
    for name in [
        "GetSystemDefaultLangID",
        "GetUserDefaultLangID",
        "GetSystemDefaultUILanguage",
        "GetUserDefaultUILanguage",
        "GetThreadLocale",
    ]:
        target = machine.resolve_export("kernel32.dll", name = name)
        equal(machine.call(target).value, 0x0409)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "SetThreadLocale"), args = [0x0809]).value, 1)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "GetThreadLocale")).value, 0x0809)

def test_kernel_validates_supported_code_pages():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["kernel32_plugin"]()])
    target = machine.resolve_export("kernel32.dll", name = "IsValidCodePage")
    equal(machine.call(target, args = [1252]).value, 1)
    equal(machine.call(target, args = [65001]).value, 1)
    equal(machine.call(target, args = [0]).value, 0)

def test_kernel_initializes_x86_slist_header():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["kernel32_plugin"]()])
    header = machine.allocate(value = b"\xff" * 8)
    target = machine.resolve_export("kernel32.dll", name = "InitializeSListHead")
    equal(machine.call(target, args = [header]).value, 0)
    equal(machine.read(header, 8), b"\x00" * 8)

def test_kernel_reports_deterministic_current_thread_times():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["kernel32_plugin"](system_time = 0)])
    times = machine.allocate(size = 32)
    target = machine.resolve_export("kernel32.dll", name = "GetThreadTimes")
    result = machine.call(target, args = [0xfffffffe, times, times + 8, times + 16, times + 24])
    equal((result.reason, result.value), ("return", 1))
    equal(machine.read_u64le(times), 116444736000000000)
    equal([machine.read_u64le(times + offset) for offset in [8, 16, 24]], [0, 0, 0])
    shutdown = machine.allocate(size = 8)
    get_shutdown = machine.resolve_export("kernel32.dll", name = "GetProcessShutdownParameters")
    equal(machine.call(get_shutdown, args = [shutdown, shutdown + 4]).value, 1)
    equal((machine.read_u32le(shutdown), machine.read_u32le(shutdown + 4)), (0x280, 0))

def test_kernel_tls_apis_share_the_x86_teb_array():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3", fs_base = 0x7000)
    machine.use([module["kernel32_plugin"]()])
    allocate = machine.resolve_export("kernel32.dll", name = "TlsAlloc")
    get_value = machine.resolve_export("kernel32.dll", name = "TlsGetValue")
    set_value = machine.resolve_export("kernel32.dll", name = "TlsSetValue")
    index = machine.call(allocate).value
    tls_array = machine.read_u32le(0x7000 + 0x2c)
    true(tls_array != 0)
    equal(machine.call(set_value, args = [index, 0x12345678]).value, 1)
    equal(machine.read_u32le(tls_array + index * 4), 0x12345678)
    machine.write_u32le(tls_array + index * 4, 0x87654321)
    equal(machine.call(get_value, args = [index]).value, 0x87654321)

def test_kernel_short_path_preserves_components_without_aliases():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["kernel32_plugin"]()])
    source = machine.allocate(value = binary.encode("C:\\Program Files\\Sample", encoding = "utf16le", nul = True))
    output = machine.allocate(size = 128)
    target = machine.resolve_export("kernel32.dll", name = "GetShortPathNameW")
    equal(machine.call(target, args = [source, 0, 0]).value, 24)
    equal(machine.call(target, args = [source, output, 64]).value, 23)
    equal(machine.read_cstring(output, encoding = "utf16le"), "C:\\Program Files\\Sample")

def test_kernel_current_directory_resolves_relative_file_paths():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    kernel = module["kernel32_plugin"](
        environment = {"CurrentDirectory": "C:\\Initial"},
        files = {"C:\\Target\\sample.bin": b"sample"},
        directories = ["C:\\Initial", "C:\\Target"],
    )
    machine.use([kernel])
    target = machine.allocate(value = binary.encode("C:\\Target", encoding = "utf16le", nul = True))
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "SetCurrentDirectoryW"), args = [target]).value, 1)
    output = machine.allocate(size = 64)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "GetCurrentDirectoryW"), args = [32, output]).value, 9)
    equal(machine.read_cstring(output, encoding = "utf16le"), "C:\\Target")
    relative = machine.allocate(value = binary.encode("sample.bin", encoding = "utf16le", nul = True))
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "GetFileAttributesW"), args = [relative]).value, 0x80)

def test_kernel_init_once_executes_callback_once_and_preserves_context():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use([module["kernel32_plugin"]()])
        calls = []
        context_value = 0x12345678 if architecture == "x86" else 0x123456789abcdef0
        def initialize(event):
            calls.append(event.args[1])
            event.machine.write_pointer(event.args[2], context_value)
            return 1
        callback = machine.provide_export(initialize, module = "sample.dll", name = "Initialize", argc = 3)
        once = machine.allocate(size = machine.pointer_size)
        context = machine.allocate(size = machine.pointer_size)
        target = machine.resolve_export("kernel32.dll", name = "InitOnceExecuteOnce")
        equal(machine.call(target, args = [once, callback, 7, context]).value, 1)
        machine.write_pointer(context, 0)
        equal(machine.call(target, args = [once, callback, 9, context]).value, 1)
        equal((calls, machine.read_pointer(context), machine.read_pointer(once)), ([7], context_value, context_value | 2))
    event_name = machine.allocate(value = binary.encode("Sample", encoding = "utf16le", nul = True))
    create_event = machine.resolve_export("kernel32.dll", name = "CreateEventExW")
    event = machine.call(create_event, args = [0, event_name, 3, 0x1f0003]).value
    true(event != 0)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "WaitForSingleObject"), args = [event, 0]).value, 0)


def test_kernel_init_once_begin_complete_matches_native_states():
    module=testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86","amd64"]:
        machine=emulator.machine(code=b"\xc3",architecture=architecture)
        kernel=module["kernel32_plugin"]()
        machine.use([kernel])
        begin=machine.resolve_export("kernel32.dll",name="InitOnceBeginInitialize")
        complete=machine.resolve_export("kernel32.dll",name="InitOnceComplete")
        once=machine.allocate(size=machine.pointer_size)
        pending=machine.allocate(value=binary.u32le(0xaabbccdd))
        context=machine.allocate(size=machine.pointer_size)
        value=0x12345678 if architecture=="x86" else 0x123456789abcdef0
        machine.write_pointer(context,value)
        kernel.state["last_error"]=123
        equal(machine.call(begin,args=[once,1,pending,context]).value,0)
        equal((kernel.state["last_error"],machine.read_u32le(pending),machine.read_pointer(context)),(31,0xaabbccdd,value))
        for flags in [3,4]:
            equal(machine.call(begin,args=[once,flags,pending,context]).value,0)
            equal((kernel.state["last_error"],machine.read_pointer(once),machine.read_u32le(pending)),(87,0,0xaabbccdd))
        kernel.state["last_error"]=123
        equal(machine.call(begin,args=[once,0,pending,context]).value,1)
        equal((machine.read_pointer(once),machine.read_u32le(pending),machine.read_pointer(context),kernel.state["last_error"]),(1,1,value,123))
        for flags,invalid_context in [(0,3),(4,4),(2,0)]:
            equal(machine.call(complete,args=[once,flags,invalid_context]).value,0)
            equal((machine.read_pointer(once),kernel.state["last_error"]),(1,87))
        equal(machine.call(complete,args=[once,0,value]).value,1)
        equal(machine.read_pointer(once),value|2)
        machine.write_pointer(context,0)
        equal(machine.call(begin,args=[once,1,pending,context]).value,1)
        equal((machine.read_u32le(pending),machine.read_pointer(context)),(0,value))
        equal(machine.call(complete,args=[once,0,0]).value,0)
        equal((machine.read_pointer(once),kernel.state["last_error"]),(value|2,31))
        # Memory, not a stale completed-context cache, controls reinitialization.
        machine.write_pointer(once,0)
        equal(machine.call(begin,args=[once,0,pending,0]).value,1)
        equal(machine.call(complete,args=[once,4,0]).value,1)
        equal(machine.read_pointer(once),0)
        equal(machine.call(begin,args=[once,2,pending,context]).value,1)
        equal(machine.read_pointer(once),3)
        equal(machine.call(begin,args=[once,2,pending,context]).value,1)
        for flags in [0,6]:
            equal(machine.call(complete,args=[once,flags,0]).value,0)
            equal((machine.read_pointer(once),kernel.state["last_error"]),(3,87))
        equal(machine.call(complete,args=[once,2,value]).value,1)
        equal(machine.read_pointer(once),value|2)

def test_kernel_init_once_execute_retry_and_private_context():
    module=testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86","amd64"]:
        machine=emulator.machine(code=b"\xc3",architecture=architecture)
        kernel=module["kernel32_plugin"]()
        machine.use([kernel])
        once=machine.allocate(size=machine.pointer_size)
        calls=[]
        def initialize(event):
            calls.append(event.args[1])
            true(event.args[2]!=0)
            event.machine.write_pointer(event.args[2],0x1234)
            return event.args[1]
        callback=machine.provide_export(initialize,module="sample.dll",name="Once",argc=3)
        execute=machine.resolve_export("kernel32.dll",name="InitOnceExecuteOnce")
        equal(machine.call(execute,args=[once,callback,0,0]).value,0)
        equal((machine.read_pointer(once),kernel.state["last_error"]),(0,31))
        output=machine.allocate(size=machine.pointer_size)
        equal(machine.call(execute,args=[once,callback,0,output]).value,0)
        equal((machine.read_pointer(once),machine.read_pointer(output),kernel.state["last_error"]),(0,0x1234,31))
        equal(machine.call(execute,args=[once,callback,1,0]).value,1)
        equal(machine.read_pointer(once),0x1236)
        equal(machine.call(execute,args=[once,callback,9,0]).value,1)
        equal(calls,[0,0,1])

def test_kernel_resolves_rva_delay_imports():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        target = machine.provide_export(lambda unused: 42, module = "sample.dll", name = "Answer", argc = 0)
        ordinal_target = machine.provide_export(lambda unused: 43, module = "sample.dll", ordinal = 7, argc = 0)
        kernel = module["kernel32_plugin"](virtual_modules = ["sample.dll"])
        machine.use([kernel])

        image = machine.allocate(size = 256, alignment = 256, name = "delay import image")
        descriptor = image + 0x20
        module_slot = image + 0x50
        iat = image + 0x60
        names = image + 0x80
        dll_name = image + 0xa0
        import_name = image + 0xc0
        machine.write_u32le(descriptor, 1)
        machine.write_u32le(descriptor + 4, dll_name - image)
        machine.write_u32le(descriptor + 8, module_slot - image)
        machine.write_u32le(descriptor + 12, iat - image)
        machine.write_u32le(descriptor + 16, names - image)
        machine.write_pointer(names, import_name - image)
        machine.write_pointer(names + machine.pointer_size, (1 << (machine.pointer_size * 8 - 1)) | 7)
        machine.write(dll_name, b"sample.dll\x00")
        machine.write(import_name, b"\x00\x00Answer\x00")

        resolver = machine.resolve_export("kernel32.dll", name = "ResolveDelayLoadedAPI")
        for index, procedure, expected in [(0, "Answer", target), (1, "#7", ordinal_target)]:
            thunk = iat + index * machine.pointer_size
            raw_flags = 1 << 32 if architecture == "amd64" and index == 1 else 0
            result = machine.call(resolver, args = [image, descriptor, 0, 0, thunk, raw_flags])
            equal(result.value, expected, (architecture, procedure, result.reason, result.detail, kernel.state["module_queries"], kernel.state["procedure_queries"]))
            equal(machine.read_pointer(thunk), expected)
            loaded_bases = [loaded.base for loaded in machine.modules if loaded.name == "sample.dll"]
            sample_base = loaded_bases[0] if loaded_bases else kernel.state["modules"]["sample.dll"]
            equal(machine.read_pointer(module_slot), sample_base)
            equal(kernel.state["procedure_queries"][-1], {"module": "sample.dll", "procedure": procedure, "found": True})
            equal(kernel.state["delay_load_queries"][-1]["stop"], "resolved")
            equal(kernel.state["delay_load_queries"][-1]["index"], index)
            equal(kernel.state["delay_load_queries"][-1]["procedure"], procedure)
            equal(kernel.state["delay_load_queries"][-1]["flags"], 0)
            if raw_flags:
                equal(kernel.state["delay_load_queries"][-1]["raw_flags"], raw_flags)
        equal(machine.call(resolver, args = [image, descriptor, 0, 0, iat + 1, 0]).value, 0)
        # A missing delayed export must not turn the thunk's JMP NULL into a
        # successful top-level return, or publish any loader table changes.
        machine.write(import_name, b"\x00\x00Absent\x00")
        before = machine.read(iat, machine.pointer_size * 2)
        result = machine.call(resolver, args = [image, descriptor, 0, 0, iat, 0])
        equal(result.reason, "missing-import")
        true("sample.dll!Absent" in result.detail)
        equal(machine.read(iat, machine.pointer_size * 2), before)
        machine.write(dll_name, b"absent.dll\x00")
        result = machine.call(resolver, args = [image, descriptor, 0, 0, iat, 0])
        equal(result.reason, "missing-import")
        true("absent.dll" in result.detail)
        equal(machine.read(iat, machine.pointer_size * 2), before)

def test_ole_com_contract_aliases_share_state():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use([module["ole32_plugin"]()])
        values = []
        for contract in ["ole32.dll", "api-ms-win-core-com-l1-1-0.dll", "api-ms-win-core-com-l1-1-1.dll"]:
            output = machine.allocate(size = 16)
            result = machine.call(machine.resolve_export(contract, name = "CoCreateGuid"), args = [output])
            equal((result.reason, result.value), ("return", 0))
            value = machine.read(output, 16)
            true(value not in values)
            values.append(value)

def test_advpack_string_table_pointer_width():
    module = testing.module("@stdlib//windows/selfreg:advpack.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        width = machine.pointer_size
        table = machine.allocate(size = 2 * width)
        entries = machine.allocate(size = 4 * width)
        machine.write_u32le(table, 2)
        machine.write_pointer(table + width, entries)
        for index, name, value in [(0, "system", "C:\\Windows\\System32"), (1, "profile", "C:\\Users\\Default")]:
            machine.write_pointer(entries + index * 2 * width, machine.allocate(value = binary.encode(name, nul = True)))
            machine.write_pointer(entries + (index * 2 + 1) * width, machine.allocate(value = binary.encode(value, nul = True)))
        equal(module["_string_table"](machine, table), {"SYSTEM": "C:\\Windows\\System32", "PROFILE": "C:\\Users\\Default"})
        equal(module["_string_table"](machine, 0), {})
        machine.write_u32le(table, 4097)
        equal(module["_string_table"](machine, table), None)
        machine.write_u32le(table, 1)
        machine.write_pointer(table + width, 0)
        equal(module["_string_table"](machine, table), None)

def test_shlwapi_ansi_to_unicode_ordinal():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["shell_plugin"]("C:\\WINDOWS\\SYSTEM\\shell32.dll")])
    source = machine.allocate(value = b"::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\x00")
    destination = machine.allocate(size = 96)
    address = machine.resolve_export("shlwapi.dll", ordinal = 215)
    result = machine.call(address, args = [source, destination, 48])
    equal(result.reason, "return")
    equal(result.value, 40)
    equal(machine.read_cstring(destination, encoding = "utf16le"), "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}")
    compat = machine.call(machine.resolve_export("shlwapi.dll", ordinal = 476), args = [0, 0])
    equal((compat.reason, compat.value), ("return", 0))
    thread_reference = machine.allocate(value = b"\x78\x56\x34\x12")
    released = machine.call(machine.resolve_export("shlwapi.dll", ordinal = 169), args = [thread_reference])
    equal((released.reason, machine.read_u32le(thread_reference)), ("return", 0))
    class_id = machine.allocate(value = b"\x00" * 16)
    pinned = machine.call(machine.resolve_export("shlwapi.dll", ordinal = 236), args = [class_id])
    equal(pinned.reason, "return")
    true(pinned.value != 0)
    root = machine.allocate(size = 8)
    built = machine.call(machine.resolve_export("shlwapi.dll", name = "PathBuildRootA"), args = [root, 2])
    equal((built.reason, built.value, machine.read_cstring(root)), ("return", root, "C:\\"))
    valid_a = machine.resolve_export("shlwapi.dll", ordinal = 455)
    equal(machine.call(valid_a, args = [ord("A"), 0x080]).value, 0x080)
    equal(machine.call(valid_a, args = [ord("."), 0x004]).value, 0x004)
    equal(machine.call(valid_a, args = [ord("/"), 0xffffffff]).value, 0)
    equal(machine.call(valid_a, args = [0x80, 0x100]).value, 0x100)
    valid_w = machine.resolve_export("shlwapi.dll", ordinal = 456)
    equal(machine.call(valid_w, args = [ord("\\"), 0x008]).value, 0x008)
    long_source = machine.allocate(value = b"C:\\Program Files\\Sample\x00")
    long_destination = machine.allocate(size = 260)
    long_path = machine.resolve_export("shlwapi.dll", ordinal = 458)
    equal(machine.call(long_path, args = [long_source, long_destination, 260]).value, 23)
    equal(machine.read_cstring(long_destination), "C:\\Program Files\\Sample")
    equal(machine.call(long_path, args = [long_source, long_destination, 4]).value, 24)
    url = machine.allocate(value = binary.encode("https://example.invalid/a", encoding = "utf16le", nul = True))
    local_path = machine.allocate(value = binary.encode("C:\\WINDOWS\\SYSTEM", encoding = "utf16le", nul = True))
    path_is_url = machine.resolve_export("shlwapi.dll", name = "PathIsURLW")
    equal(machine.call(path_is_url, args = [url]).value, 1)
    equal(machine.call(path_is_url, args = [local_path]).value, 0)
    compare_left = machine.allocate(value = binary.encode("Alpha", encoding = "utf16le", nul = True))
    compare_right = machine.allocate(value = binary.encode("alpha", encoding = "utf16le", nul = True))
    compare = machine.resolve_export("shlwapi.dll", name = "StrCmpW")
    equal(machine.call(compare, args = [compare_left, compare_right]).value, 0xffffffff)
    compare_ignore_case = machine.resolve_export("shlwapi.dll", name = "StrCmpICW")
    equal(machine.call(compare_ignore_case, args = [compare_left, compare_right]).value, 0)
    parsed_source = machine.allocate(value = binary.encode("file:///C:/Windows", encoding = "utf16le", nul = True))
    parsed = machine.allocate(size = 24)
    machine.write_u32le(parsed, 24)
    equal(machine.call(machine.resolve_export("shlwapi.dll", ordinal = 2), args = [parsed_source, parsed]).value, 0)
    equal(machine.read_u32le(parsed + 4), parsed_source)
    equal(machine.read_u32le(parsed + 8), 4)
    equal(machine.read_cstring(machine.read_u32le(parsed + 12), encoding = "utf16le"), "C:/Windows")
    equal(machine.read_u32le(parsed + 16), 10)
    equal(machine.read_u32le(parsed + 20), 9)
    duplicated_output = machine.allocate(size = 4)
    equal(machine.call(machine.resolve_export("shlwapi.dll", name = "SHStrDupW"), args = [compare_left, duplicated_output]).value, 0)
    equal(machine.read_cstring(machine.read_u32le(duplicated_output), encoding = "utf16le"), "Alpha")
    interface_slot = machine.allocate(value = b"\x78\x56\x34\x12")
    replaced = machine.call(machine.resolve_export("shlwapi.dll", ordinal = 199), args = [0x10203040, interface_slot])
    equal((replaced.reason, machine.read_u32le(interface_slot)), ("return", 0x10203040))
    concatenated = machine.allocate(value = b"abc\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    suffix = machine.allocate(value = b"defghi\x00")
    equal(machine.call(machine.resolve_export("shlwapi.dll", name = "StrNCatA"), args = [concatenated, suffix, 7]).value, concatenated)
    equal(machine.read_cstring(concatenated), "abcdef")
    roundtrip_source = machine.allocate(value = binary.encode("My Documents", encoding = "utf16le", nul = True))
    roundtrip_destination = machine.allocate(size = 32)
    roundtrip_address = machine.resolve_export("shlwapi.dll", ordinal = 365)
    true(roundtrip_address != 0)
    roundtrip = machine.call(roundtrip_address, args = [roundtrip_source, roundtrip_destination, 32])
    equal((roundtrip.reason, roundtrip.value, machine.read_cstring(roundtrip_destination)), ("return", 1, "My Documents"))
    left = machine.allocate(value = binary.encode("C:\\Program Files\\Microsoft", encoding = "utf16le", nul = True))
    right = machine.allocate(value = binary.encode("c:\\Program Files\\Mozilla", encoding = "utf16le", nul = True))
    common = machine.allocate(size = 260 * 2)
    common_prefix = machine.resolve_export("shlwapi.dll", name = "PathCommonPrefixW")
    equal(machine.call(common_prefix, args = [left, right, common]).value, 17)
    equal(machine.read_cstring(common, encoding = "utf16le"), "C:\\Program Files\\")

def test_shell32_special_folder_location_round_trip():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.machine(code = b"\xc3", architecture = "amd64")
    machine.use([module["shell32_plugin"]("C:\\WINDOWS\\SYSTEM\\shell32.dll")])
    output = machine.allocate(size = machine.pointer_size)
    located = machine.call(machine.resolve_export("shell32.dll", name = "SHGetSpecialFolderLocation"), args = [0, 0x1a, output])
    equal((located.reason, located.value), ("return", 0))
    pidl = machine.read_pointer(output)
    true(pidl != 0)
    path = machine.allocate(size = 260)
    resolved = machine.call(machine.resolve_export("shell32.dll", name = "SHGetPathFromIDListA"), args = [pidl, path])
    equal((resolved.reason, resolved.value), ("return", 1))
    equal(machine.read_cstring(path), "C:\\WINDOWS\\Application Data")
    notified = machine.call(machine.resolve_export("shell32.dll", name = "SHChangeNotify"), args = [0x08000000, 0, path, 0])
    equal(notified.reason, "return")

def test_oleaut_variant_time_by_value_abi():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["oleaut_plugin"]()])
    encoded = binary.builder(capacity = 8)
    encoded.f64le(36526.5)  # 2000-01-01 12:00:00
    words = binary.cursor(encoded.bytes())
    output = machine.allocate(size = 16)
    converted = machine.call(
        machine.resolve_export("oleaut32.dll", name = "VariantTimeToSystemTime"),
        args = [words.u32le(), words.u32le(), output],
    )
    equal((converted.reason, converted.value), ("return", 1))
    fields = binary.cursor(machine.read(output, 16))
    equal([fields.u16le() for unused in range(8)], [2000, 1, 6, 1, 12, 0, 0, 0])

def test_shell32_known_folder_path_uses_process_environment():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.machine(code = b"\xc3", architecture = "amd64")
    machine.use([module["shell32_plugin"](
        "C:\\Windows\\System32\\shell32.dll",
        environment = {
            "ProgramData": "D:\\SharedData",
            "USERPROFILE": "C:\\Users\\Test",
            "windir": "C:\\Windows",
        },
    )])
    # FOLDERID_ProgramData, encoded using the in-memory GUID byte order.
    identifier = machine.allocate(value = b"\x82\x5d\xab\x62\xc1\xfd\xc3\x4d\xa9\xdd\x07\x0d\x1d\x49\x5d\x97")
    output = machine.allocate(size = machine.pointer_size)
    result = machine.call(machine.resolve_export("shell32.dll", name = "SHGetKnownFolderPath"), args = [identifier, 0, 0, output])
    equal((result.reason, result.value), ("return", 0))
    equal(machine.read_cstring(machine.read_pointer(output), encoding = "utf16le"), "D:\\SharedData")
    legacy_output = machine.allocate(size = 260 * 2)
    legacy_result = machine.call(machine.resolve_export("shell32.dll", name = "SHGetFolderPathW"), args = [0, 0x23, 0, 0, legacy_output])
    equal((legacy_result.reason, legacy_result.value), ("return", 0))
    equal(machine.read_cstring(legacy_output, encoding = "utf16le"), "D:\\SharedData")
    special_output = machine.allocate(size = 260 * 2)
    special = machine.call(machine.resolve_export("shell32.dll", name = "SHGetSpecialFolderPathW"), args = [0, special_output, 0x10, 0])
    equal((special.reason, special.value), ("return", 1))
    equal(machine.read_cstring(special_output, encoding = "utf16le"), "C:\\Users\\Test\\Desktop")
    legacy_machine = emulator.x86(code = b"\xc3")
    legacy_machine.use(module["shell32_plugin"](environment = {
        "ALLUSERSPROFILE": "C:\\Documents and Settings\\All Users",
    }))
    legacy_buffer = legacy_machine.allocate(size = 260 * 2)
    legacy_folder = legacy_machine.call(legacy_machine.resolve_export("shell32.dll", name = "SHGetFolderPathW"), args = [0, 0x23, 0, 0, legacy_buffer])
    equal((legacy_folder.reason, legacy_folder.value), ("return", 0))
    equal(legacy_machine.read_cstring(legacy_buffer, encoding = "utf16le"), "C:\\Documents and Settings\\All Users\\Application Data")

def test_userenv_profile_and_environment_block_contracts():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    environment = {
        "ProgramFiles": "C:\\Program Files (x86)",
        "USERPROFILE": "C:\\Users\\Test",
    }
    machine = emulator.x86(code = b"\xc3")
    machine.use([
        module["shell32_plugin"]("C:\\Windows\\System32\\shell32.dll", environment = environment),
        module["userenv_plugin"](environment = environment),
    ])
    size = machine.allocate(value = binary.u32le(1))
    profile = machine.allocate(size = 260 * 2)
    target = machine.resolve_export("userenv.dll", name = "GetUserProfileDirectoryW")
    equal(machine.call(target, args = [0, profile, size]).value, 0)
    equal(machine.read_u32le(size), len("C:\\Users\\Test") + 1)
    machine.write_u32le(size, 260)
    equal(machine.call(target, args = [0, profile, size]).value, 1)
    equal(machine.read_cstring(profile, encoding = "utf16le"), "C:\\Users\\Test")
    block = machine.allocate(size = 4)
    created = machine.call(machine.resolve_export("userenv.dll", name = "CreateEnvironmentBlock"), args = [block, 0, 0])
    equal(created.value, 1)
    environment_block = machine.read_u32le(block)
    equal(machine.read_cstring(environment_block, encoding = "utf16le"), "ProgramFiles=C:\\Program Files (x86)")
    equal(machine.call(machine.resolve_export("userenv.dll", name = "DestroyEnvironmentBlock"), args = [environment_block]).value, 1)
    program_files = machine.allocate(size = 260 * 2)
    folder = machine.call(machine.resolve_export("shell32.dll", name = "SHGetFolderPathW"), args = [0, 0x26, 0, 0, program_files])
    equal(folder.value, 0)
    equal(machine.read_cstring(program_files, encoding = "utf16le"), "C:\\Program Files (x86)")

def test_shell32_command_line_to_argv_uses_local_allocation():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use([module["kernel32_plugin"](), module["shell32_plugin"]("C:\\Program Files\\Sample\\sample.exe")])
        command_line = machine.allocate(value = binary.encode('sample.exe /regsvc "two words"', encoding = "utf16le", nul = True))
        count = machine.allocate(size = 4)
        result = machine.call(machine.resolve_export("shell32.dll", name = "CommandLineToArgvW"), args = [command_line, count])
        equal(result.reason, "return")
        argv = result.value
        equal(machine.read_u32le(count), 3)
        equal([
            machine.read_cstring(machine.read_pointer(argv + index * machine.pointer_size), encoding = "utf16le")
            for index in range(3)
        ], ["sample.exe", "/regsvc", "two words"])
        equal(machine.read_pointer(argv + 3 * machine.pointer_size), 0)
        equal(machine.call(machine.resolve_export("kernel32.dll", name = "LocalFree"), args = [argv]).value, 0)

def test_winsock_helper_signatures():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    signatures = module["_WS2HELP_SIGNATURES"]
    equal(signatures["wahcreatehandlecontexttable"], 1)
    equal(signatures["wahdestroyhandlecontexttable"], 1)
    equal(signatures["wahopenapchelper"], 1)
    equal(signatures["wahcloseapchelper"], 1)
    equal(signatures["wahopencurrentthread"], 2)
    equal(signatures["wahclosethread"], 1)
    equal(module["_WINSOCK_ORDINAL_SIGNATURES"], {2: 3, 3: 1, 6: 3, 7: 5, 8: 1, 9: 1, 10: 3, 14: 1, 15: 1, 19: 4, 21: 5, 23: 3, 103: 5, 111: 0, 112: 1, 114: 0, 115: 2, 116: 0})
    machine = emulator.x86(code = b"\xc3")
    winsock = module["winsock_plugin"]()
    machine.use([winsock])
    data = machine.allocate(size = 400)
    startup = machine.call(machine.resolve_export("wsock32.dll", ordinal = 115), args = [0x0101, data])
    equal((startup.reason, startup.value, machine.read_u16le(data), machine.read_u16le(data + 2)), ("return", 0, 0x0101, 0x0202))
    equal(machine.call(machine.resolve_export("wsock32.dll", ordinal = 112), args = [10061]).value, 0)
    equal(machine.call(machine.resolve_export("wsock32.dll", ordinal = 111)).value, 10061)
    equal(machine.call(machine.resolve_export("wsock32.dll", ordinal = 116)).value, 0)

def test_wer_process_registrations_are_reversible():
    module = testing.module("@stdlib//windows/selfreg:wer.star")
    machine = emulator.x86(code = b"\xc3")
    plugin = module["wer_plugin"]()
    machine.use([plugin])
    path = machine.allocate(value = binary.encode("C:\\Program Files\\Sample\\sample.dll", encoding = "utf16le", nul = True))
    register = machine.resolve_export("wer.dll", name = "WerRegisterRuntimeExceptionModule")
    unregister = machine.resolve_export("wer.dll", name = "WerUnregisterRuntimeExceptionModule")
    equal(machine.call(register, args = [path, 0x1234]).value, 0)
    equal(plugin.state["runtime_modules"]["c:\\program files\\sample\\sample.dll"]["context"], 0x1234)
    equal(machine.call(unregister, args = [path, 0x1234]).value, 0)
    equal(plugin.state["runtime_modules"], {})
    equal(machine.call(machine.resolve_export("wer.dll", name = "WerSetFlags"), args = [4]).value, 0)
    flags = machine.allocate(size = 4)
    equal(machine.call(machine.resolve_export("wer.dll", name = "WerGetFlags"), args = [0, flags]).value, 0)
    equal(machine.read_u32le(flags), 4)
    event_type = machine.allocate(value = binary.encode("SampleEvent", encoding = "utf16le", nul = True))
    report_output = machine.allocate(size = 4)
    equal(machine.call(machine.resolve_export("wer.dll", name = "WerReportCreate"), args = [event_type, 2, 0, report_output]).value, 0)
    report = machine.read_u32le(report_output)
    parameter_name = machine.allocate(value = binary.encode("Version", encoding = "utf16le", nul = True))
    parameter_value = machine.allocate(value = binary.encode("1.0", encoding = "utf16le", nul = True))
    equal(machine.call(machine.resolve_export("wer.dll", name = "WerReportSetParameter"), args = [report, 0, parameter_name, parameter_value]).value, 0)
    submit_result = machine.allocate(size = 4)
    equal(machine.call(machine.resolve_export("wer.dll", name = "WerReportSubmit"), args = [report, 2, 0, submit_result]).value, 0)
    equal(machine.read_u32le(submit_result), 1)
    equal(plugin.state["reports"][report]["parameters"][0]["value"], "1.0")
    equal(machine.call(machine.resolve_export("wer.dll", name = "WerReportCloseHandle"), args = [report]).value, 0)
    equal(plugin.state["reports"], {})

def test_appmodel_reports_unpacked_desktop_process():
    module = testing.module("@stdlib//windows/selfreg:appmodel.star")
    machine = emulator.x86(code = b"\xc3")
    plugin = module["appmodel_plugin"]()
    machine.use([plugin])
    length = machine.allocate(size = 4)
    machine.write_u32le(length, 260)
    target = machine.resolve_export("api-ms-win-appmodel-runtime-l1-1-2.dll", name = "GetCurrentPackageFullName")
    true(target != 0)
    equal(machine.call(target, args = [length, 0]).value, 15700)
    equal(machine.read_u32le(length), 0)
    equal(plugin.state["queries"][-1]["api"], "getcurrentpackagefullname")
    policy = machine.allocate(size = 4)
    query_policy = machine.resolve_export("api-ms-win-appmodel-runtime-l1-1-2.dll", name = "AppPolicyGetProcessTerminationMethod")
    equal(machine.call(query_policy, args = [0, policy]).value, 0)
    equal(machine.read_u32le(policy), 0)
    machine64 = emulator.machine(code = b"\xc3", architecture = "amd64")
    plugin64 = module["appmodel_plugin"]()
    machine64.use([plugin64])
    package_size = machine64.allocate(value = b"\xff" * 8)
    application_size = machine64.allocate(value = b"\xff" * 8)
    dynamic_id = machine64.allocate(value = b"\xff" * 16)
    package_flags = machine64.allocate(value = b"\xff" * 4)
    package_origin = machine64.allocate(value = b"\xff" * 8)
    claims = machine64.resolve_export("ntdll.dll", name = "RtlQueryPackageClaims")
    true(claims != 0)
    equal(machine64.call(claims, args = [1, 0, package_size, 0, application_size, dynamic_id, package_flags, package_origin]).value, 0)
    equal(machine64.read_pointer(package_size), 0)
    equal(machine64.read_pointer(application_size), 0)
    equal(machine64.read(dynamic_id, 16), b"\x00" * 16)
    equal(machine64.read_u32le(package_flags), 0)
    equal(machine64.read_u64le(package_origin), 0)
    equal(plugin64.state["queries"][-1]["api"], "rtlquerypackageclaims")

def test_rpc_runtime_signatures():
    module = testing.module("@stdlib//windows/emulation:rpc.star")
    signatures = module["_RPC_RUNTIME_SIGNATURES"]
    equal(signatures["rpcmgmtsetserverstacksize"], 1)
    equal(signatures["rpcserveruseprotseqepw"], 4)
    equal(signatures["rpcserverregisterifex"], 6)
    equal(signatures["rpcserverinqcallattributesw"], 2)
    equal(signatures["rpcserverinterfacegroupcreatew"], 8)
    equal(signatures["rpcserverinterfacegroupactivate"], 1)
    equal(signatures["rpcserverinterfacegroupclose"], 1)
    equal(signatures["rpcserverunregisterif"], 3)
    equal(signatures["rpcreverttoselfex"], 1)
    equal(signatures["uuidcreate"], 1)
    equal(signatures["uuidfromstringw"], 2)
    equal(signatures["uuidtostringw"], 2)
    equal(signatures["rpcstringfreew"], 1)
    raw = module["_uuid_bytes"]("00112233-4455-6677-8899-AABBCCDDEEFF")
    equal(hex(raw), "33221100554477668899aabbccddeeff")
    equal(module["_uuid_text"](raw), "00112233-4455-6677-8899-aabbccddeeff")
    equal(module["_uuid_bytes"]("not-a-uuid"), None)
    created = module["_created_uuid"]("example.exe", 0)
    equal(len(created), 16)
    equal(binary.read_u8(created, 7) & 0xf0, 0x40)
    equal(binary.read_u8(created, 8) & 0xc0, 0x80)
    not_equal(created, module["_created_uuid"]("example.exe", 1))
    equal(module["_NDR_PROXY_SIGNATURES"]["ndrdllgetclassobject"], 6)
    equal(module["_NDR_PROXY_SIGNATURES"]["ndrdllregisterproxy"], 3)

    registry = testing.module("@stdlib//windows/selfreg:registry.star")["registry_plugin"]()
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["rpc_plugin"](registry, "fixture.dll")])
    uuid_to_string = machine.resolve_export("rpcrt4.dll", name = "UuidToStringW")
    uuid = machine.allocate(value = raw)
    uuid_output = machine.allocate(size = 4)
    equal(machine.call(uuid_to_string, args = [uuid, uuid_output]).value, 0)
    equal(machine.read_cstring(machine.read_u32le(uuid_output), encoding = "utf16le"), "00112233-4455-6677-8899-aabbccddeeff")
    compose = machine.resolve_export("rpcrt4.dll", name = "RpcStringBindingComposeW")
    not_equal(machine.resolve_export("rpcrt4.dll", name = "NdrClientCall2"), 0)
    protocol = machine.allocate(value = binary.encode("ncalrpc", encoding = "utf16le", nul = True))
    endpoint = machine.allocate(value = binary.encode("TEST", encoding = "utf16le", nul = True))
    output = machine.allocate(size = 4)
    equal(machine.call(compose, args = [0, protocol, 0, endpoint, 0, output]).value, 0)
    equal(machine.read_cstring(machine.read_u32le(output), encoding = "utf16le"), "ncalrpc:[TEST]")
    attributes = machine.allocate(size = 0x50, value = binary.u32le(2))
    inquire = machine.resolve_export("rpcrt4.dll", name = "RpcServerInqCallAttributesW")
    equal(machine.call(inquire, args = [0, attributes]).value, 0)
    equal(machine.read_u32le(attributes + 0x18), 6)
    equal(machine.read_u16le(attributes + 0x40), 1)


def test_rpc_pointer_outputs_and_release():
    module = testing.module("@stdlib//windows/emulation:rpc.star")
    registry_module = testing.module("@stdlib//windows/selfreg:registry.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use([module["rpc_plugin"](registry_module["registry_plugin"](), "fixture.dll")])
        protocol = machine.allocate(value = binary.encode("ncalrpc", encoding = "utf16le", nul = True))
        endpoint = machine.allocate(value = binary.encode("TEST", encoding = "utf16le", nul = True))
        output = machine.allocate(value = b"\xff" * machine.pointer_size)
        binding = machine.allocate(value = b"\xff" * machine.pointer_size)
        compose = machine.resolve_export("rpcrt4.dll", name = "RpcStringBindingComposeW")
        equal(machine.call(compose, args = [0, protocol, 0, endpoint, 0, output]).value, 0)
        string = machine.read_pointer(output)
        equal(machine.read_cstring(string, encoding = "utf16le"), "ncalrpc:[TEST]")
        bind = machine.resolve_export("rpcrt4.dll", name = "RpcBindingFromStringBindingW")
        equal(machine.call(bind, args = [string, binding]).value, 0)
        true(machine.read_pointer(binding) != 0)
        release = machine.resolve_export("rpcrt4.dll", name = "RpcBindingFree")
        equal(machine.call(release, args = [binding]).value, 0)
        equal(machine.read_pointer(binding), 0)
        free = machine.resolve_export("rpcrt4.dll", name = "RpcStringFreeW")
        equal(machine.call(free, args = [output]).value, 0)
        equal(machine.read_pointer(output), 0)
        uuid = machine.allocate(value = module["_uuid_bytes"]("00112233-4455-6677-8899-aabbccddeeff"))
        machine.write(output, b"\xff" * machine.pointer_size)
        convert = machine.resolve_export("rpcrt4.dll", name = "UuidToStringW")
        equal(machine.call(convert, args = [uuid, output]).value, 0)
        equal(machine.read_cstring(machine.read_pointer(output), encoding = "utf16le"), "00112233-4455-6677-8899-aabbccddeeff")
        equal(machine.call(free, args = [output]).value, 0)
        equal(machine.read_pointer(output), 0)

def test_kernel_virtual_file_entries():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    true(module["_wildcard_match"]("*.mof", "cimwin32.mof"))
    true(module["_wildcard_match"]("system.?of", "SYSTEM.MOF"))
    true(module["_wildcard_match"]("*.*", "skus"))
    true(module["_wildcard_match"]("*.*", "payload.dat"))
    true(not module["_wildcard_match"]("*.mfl", "system.mof"))
    equal(module["_normalize_virtual_path"]("C:/WINDOWS//System32\\\\WBEM\\"), "c:\\windows\\system32\\wbem")
    equal(module["_normalize_virtual_path"]("\\\\SERVER\\\\Share\\file"), "\\\\server\\share\\file")
    entries = module["_virtual_file_entries"]({
        "C:/WINDOWS/System32/WBEM/core.mof": b"mof",
    }, 16)
    equal(entries["c:\\windows\\system32\\wbem\\core.mof"]["source"], b"mof")
    equal(entries["c:\\windows\\system32\\wbem\\core.mof"]["size"], 3)
    true("data" not in entries["c:\\windows\\system32\\wbem\\core.mof"])
    true(entries["c:\\windows\\system32\\wbem\\core.mof"]["initial"])
    true(not entries["c:\\windows\\system32\\wbem\\core.mof"]["dirty"])
    true(entries["c:\\windows\\system32\\wbem"]["directory"])
    raises(lambda: testing.module("@stdlib//windows/selfreg:win32.star")["_virtual_file_entries"]({"C:/large": b"123"}, 2), message = "maximum modeled file size")

    machine = emulator.x86(code = b"\xc3")
    machine.use([module["kernel32_plugin"](directories = ["C:\\empty"])])
    find_first = machine.resolve_export("kernel32.dll", name = "FindFirstFileW")
    get_last_error = machine.resolve_export("kernel32.dll", name = "GetLastError")
    find_data = machine.allocate(size = 592)
    empty_pattern = machine.allocate(value = binary.encode("C:\\empty\\*.*", encoding = "utf16le", nul = True))
    missing_pattern = machine.allocate(value = binary.encode("C:\\missing\\*.*", encoding = "utf16le", nul = True))
    equal(machine.call(find_first, args = [empty_pattern, find_data]).value, 0xffffffff)
    equal(machine.call(get_last_error).value, 2)
    equal(machine.call(find_first, args = [missing_pattern, find_data]).value, 0xffffffff)
    equal(machine.call(get_last_error).value, 3)

def test_profile_section_parser():
    parse = testing.module("@stdlib//windows/selfreg:win32.star")["_profile_sections"]
    profile = parse(b"; comment\r\n[First]\r\nOne = 1\r\nFlag\r\n[first]\r\nTwo=second\r\n[Empty]\r\n")
    equal(profile["order"], ["First", "Empty"])
    equal(profile["sections"]["first"]["values"], {"one": "1", "flag": "", "two": "second"})
    equal([item["line"] for item in profile["sections"]["first"]["items"]], ["One=1", "Flag", "Two=second"])

def test_event_log_provider_recognizes_api_set_contracts():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    true(module["_event_log_provider_module"]("advapi32.dll"))
    true(module["_event_log_provider_module"]("api-ms-win-eventlog-legacy-l1-1-0.dll"))
    true(module["_event_log_provider_module"]("api-ms-win-eventing-classicprovider-l1-1-0.dll"))
    true(not module["_event_log_provider_module"]("api-ms-win-core-file-l1-1-0.dll"))
    machine = emulator.x86(code = b"\xc3")
    plugin = module["event_log_plugin"]()
    machine.use([plugin])
    provider = machine.allocate(value = b"\x00" * 16)
    output = machine.allocate(size = 8)
    register = machine.resolve_export("advapi32.dll", name = "EventRegister")
    unregister = machine.resolve_export("advapi32.dll", name = "EventUnregister")
    equal(machine.call(register, args = [provider, 0, 0, output]).value, 0)
    handle = machine.read_u64le(output)
    true(handle in plugin.state["trace_providers"])
    equal(machine.call(unregister, args = [handle & 0xffffffff, handle >> 32]).value, 0)

def test_create_service_default_account():
    module = testing.module("@stdlib//windows/selfreg:service.star")
    default_account = module["_create_service_default_account"]
    equal(default_account(0x10, 0), "LocalSystem")
    equal(default_account(0x20, 0), "LocalSystem")
    equal(default_account(0x01, 0), "")
    equal(default_account(0x20, 0x1234), "")
    true(module["_service_is_active"]([0x20, 4]))
    equal(module["_service_is_active"]([0x20, 1]), False)
    equal(module["_SIGNATURES"]["registerservicectrlhandlerexw"], 3)
    equal(module["_SIGNATURES"]["setservicestatus"], 2)
    equal(module["_SIGNATURES"]["setserviceobjectsecurity"], 3)
    machine = emulator.x86(code = b"\xc3")
    descriptor = testing.module("@stdlib//windows:security.star")["security_descriptor"](
        owner = testing.module("@stdlib//windows:security.star")["sid"](5, [18]),
    )
    descriptor_address = machine.allocate(value = descriptor)
    equal(module["_self_relative_security_descriptor"](machine, descriptor_address), descriptor)
    registry = testing.module("@stdlib//windows/selfreg:registry.star")["registry_plugin"](values = [
        {"hive": "SOFTWARE", "key": "/Classes/CLSID/{11111111-2222-3333-4444-555555555555}", "name": "AppId", "type": "REG_SZ", "value": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"},
        {"hive": "SOFTWARE", "key": "/Classes/AppID/{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", "name": "LocalService", "type": "REG_SZ", "value": "ExampleSvc"},
        {"hive": "SYSTEM", "key": "/ControlSet001/Services/ExampleSvc/Parameters", "name": "ServiceDll", "type": "REG_EXPAND_SZ", "value": "%SystemRoot%\\system32\\example.dll"},
        {"hive": "SYSTEM", "key": "/ControlSet001/Services/ExampleSvc/Parameters", "name": "ServiceMain", "type": "REG_SZ", "value": "ExampleMain"},
    ])
    registry.set_value("SYSTEM", "/ControlSet001/Services/ExistingSvc", "Type", "REG_DWORD", 0x10)
    service = module["service_manager_plugin"](registry)
    machine.use([service])
    true(machine.resolve_export("advapi32.dll", name = "OpenSCManagerW") != 0)
    manager = machine.call(machine.resolve_export("advapi32.dll", name = "OpenSCManagerW"), args = [0, 0, 0]).value
    open_service = machine.resolve_export("advapi32.dll", name = "OpenServiceW")
    existing_name = machine.allocate(value = binary.encode("existingsvc", encoding = "utf16le", nul = True))
    missing_name = machine.allocate(value = binary.encode("MissingSvc", encoding = "utf16le", nul = True))
    equal(machine.call(open_service, args = [0, existing_name, 0]).value, 0)
    equal(machine.call(open_service, args = [manager, missing_name, 0]).value, 0)
    existing_service = machine.call(open_service, args = [manager, existing_name, 0]).value
    true(existing_service != 0)
    status_ex = machine.resolve_export("advapi32.dll", name = "QueryServiceStatusEx")
    status_size = machine.allocate(size = 4)
    status_data = machine.allocate(size = 36)
    equal(machine.call(status_ex, args = [existing_service, 0, 0, 0, status_size]).value, 0)
    equal(machine.read_u32le(status_size), 36)
    equal(service.state["last_error"], 122)
    equal(machine.call(status_ex, args = [existing_service, 1, status_data, 36, status_size]).value, 0)
    equal(service.state["last_error"], 124)
    equal(machine.call(status_ex, args = [existing_service, 0, status_data, 36, status_size]).value, 1)
    equal([machine.read_u32le(status_data+i*4) for i in range(9)], [0x10, 1, 0, 0, 0, 0, 0, 0, 0])
    equal(machine.call(machine.resolve_export("advapi32.dll", name = "DeleteService"), args = [existing_service]).value, 1)
    equal(machine.call(open_service, args = [manager, existing_name, 0]).value, 0)
    service_name = machine.allocate(value = binary.encode("QuerySvc", encoding = "utf16le", nul = True))
    image_path = machine.allocate(value = binary.encode("C:\\query.exe", encoding = "utf16le", nul = True))
    query_service = machine.call(machine.resolve_export("advapi32.dll", name = "CreateServiceW"), args = [manager, service_name, 0, 0, 0x10, 2, 1, image_path, 0, 0, 0, 0, 0]).value
    description_text = machine.allocate(value = binary.encode("Query service", encoding = "utf16le", nul = True))
    description_info = machine.allocate(size = 4)
    machine.write_u32le(description_info, description_text)
    equal(machine.call(machine.resolve_export("advapi32.dll", name = "ChangeServiceConfig2W"), args = [query_service, 1, description_info]).value, 1)
    required = machine.allocate(size = 4)
    query_config = machine.resolve_export("advapi32.dll", name = "QueryServiceConfig2W")
    equal(machine.call(query_config, args = [query_service, 1, 0, 0, required]).value, 0)
    output = machine.allocate(size = machine.read_u32le(required))
    equal(machine.call(query_config, args = [query_service, 1, output, machine.read_u32le(required), required]).value, 1)
    equal(machine.read_cstring(machine.read_u32le(output), encoding = "utf16le"), "Query service")
    equal(service.resolve_class("{11111111-2222-3333-4444-555555555555}", 4), {
        "class": "{11111111-2222-3333-4444-555555555555}",
        "service": "ExampleSvc",
        "module_path": "%SystemRoot%\\system32\\example.dll",
        "module": "example.dll",
        "entry": "ExampleMain",
    })
    equal(service.resolve_class("{11111111-2222-3333-4444-555555555555}", 1), None)

    scheduler_machine = emulator.x86(code = b"\x40\x40\xc3", instruction_limit = 2)
    scheduler_service = module["service_manager_plugin"](registry)
    execution = scheduler_machine.spawn(scheduler_machine.entry)
    first = execution.run()
    equal(first.reason, "budget")
    scheduler_service.state["executions"].append(execution)
    scheduler_service.state["execution_results"].append(first)
    true(scheduler_service.state["pump_execution_slice"](scheduler_machine))
    equal(scheduler_service.state["execution_results"][0].reason, "return")
    equal(scheduler_service.state["execution_results"][0].value, 2)

def test_service_dispatcher_pointer_width():
    service_module = testing.module("@stdlib//windows/selfreg:service.star")
    registry_module = testing.module("@stdlib//windows/selfreg:registry.star")
    for architecture in ["x86", "amd64"]:
        for wide in [False, True]:
            machine = emulator.machine(code = b"\xc3", architecture = architecture)
            service = service_module["service_manager_plugin"](registry_module["registry_plugin"]())
            machine.use(service)
            width = machine.pointer_size
            high = 0x100000000 if width == 8 else 0
            # Native ServiceMain validates argc, then returns argv[0]. Both
            # the table's name and code pointers exceed DWORD on Win64.
            code = b"\x83\xf9\x01\x75\x04\x48\x8b\x02\xc3\x31\xc0\xc3" if width == 8 else b"\x83\x7c\x24\x04\x01\x75\x09\x8b\x44\x24\x08\x8b\x00\xc2\x08\x00\x31\xc0\xc2\x08\x00"
            target = machine.allocate(value = code, address = high + 0x200000, executable = True)
            encoding = "utf16le" if wide else "ascii"
            name = "WideService" if wide else "AnsiService"
            name_pointer = machine.allocate(value = binary.encode(name, encoding = encoding, nul = True), address = high + 0x210000)
            table = machine.allocate(size = 4 * width, address = high + 0x220000)
            machine.write_pointer(table, name_pointer)
            machine.write_pointer(table + width, target)
            dispatch = machine.resolve_export("advapi32.dll", name = "StartServiceCtrlDispatcherW" if wide else "StartServiceCtrlDispatcherA")
            result = machine.call(dispatch, args = [table])
            equal(result.reason, "return", result.detail)
            equal(result.value, 1)
            equal(len(service.state["activations"]), 1)
            activation = service.state["activations"][0]
            equal(activation["service"], name)
            equal(activation["result"], "return", activation["detail"])
            true(activation["value"] != 0)
            equal(machine.read_cstring(activation["value"], encoding = encoding), name)
            equal(machine.read_pointer(table), name_pointer)
            equal(machine.read_pointer(table + width), target)
            # A null entry must not launch another service.
            machine.write_pointer(table + width, 0)
            equal(machine.call(dispatch, args = [table]).value, 0)
            equal(service.state["activations"][-1]["result"], "invalid-table")
            equal(len(service.state["executions"]), 1)

def test_automation_registration_signatures():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    candidates = module["_class_server_names"]
    classes = {
        "owned.dll": ["{AAAAAAAA-0000-0000-0000-000000000000}"],
        "other.dll": ["{BBBBBBBB-0000-0000-0000-000000000000}"],
    }
    equal(candidates(["owned.dll", "other.dll", "unknown.dll"], classes, "{AAAAAAAA-0000-0000-0000-000000000000}"), ["owned.dll"])
    equal(candidates(["owned.dll", "other.dll", "unknown.dll"], classes, "{CCCCCCCC-0000-0000-0000-000000000000}"), ["unknown.dll"])
    equal(candidates(["owned.dll", "C:\\Windows\\System32\\WBEM\\fastprox.dll"], classes, "{CCCCCCCC-0000-0000-0000-000000000000}", registered_server = "%SystemRoot%\\system32\\wbem\\FASTPROX.DLL"), ["C:\\Windows\\System32\\WBEM\\fastprox.dll"])
    equal(candidates(["owned.dll", "unknown.dll"], classes, "{AAAAAAAA-0000-0000-0000-000000000000}", registered_server = "missing.dll"), ["owned.dll"])
    equal(module["_OLE_SIGNATURES"]["cocreateguid"], 1)
    equal(module["_OLE_SIGNATURES"]["cocreatefreethreadedmarshaler"], 2)
    equal(module["_OLE_SIGNATURES"]["codisconnectcontext"], 1)
    equal(module["_OLE_SIGNATURES"]["cogetinterfaceandreleasestream"], 3)
    equal(module["_OLE_SIGNATURES"]["comarshalinterthreadinterfaceinstream"], 3)
    equal(module["_OLE_SIGNATURES"]["coregisterpsclsid"], 2)
    equal(module["_OLE_SIGNATURES"]["cocreateinstanceex"], 6)
    equal(module["_OLE_SIGNATURES"]["coinitializesecurity"], 9)
    equal(module["_OLE_SIGNATURES"]["cogetcallcontext"], 2)
    equal(module["_OLE_SIGNATURES"]["clsidfromstring"], 2)
    equal(module["_OLE_SIGNATURES"]["iidfromstring"], 2)
    equal(module["_OLE_SIGNATURES"]["coregisterclassobject"], 5)
    equal(module["_OLE_SIGNATURES"]["coqueryproxyblanket"], 8)
    equal(module["_OLE_SIGNATURES"]["cosetproxyblanket"], 8)
    equal(module["_OLE_SIGNATURES"]["coimpersonateclient"], 0)
    equal(module["_OLE_SIGNATURES"]["coreverttoself"], 0)
    equal(module["_OLE_SIGNATURES"]["coswitchcallcontext"], 2)
    equal(module["_MSVCRT_LOCALE_COUNTERS"]["___setlc_active_func"], "setlc_active")
    equal(module["_MSVCRT_LOCALE_COUNTERS"]["___unguarded_readlc_active_add_func"], "unguarded_readlc_active")
    equal(module["_MSVCRT_LOCALE_POINTERS"]["___lc_handle_func"], [36, "lc_handle"])
    equal(module["_MSVCRT_LOCALE_VALUES"]["___lc_codepage_func"], 1252)
    equal(module["_MSVCRT_LOCALE_VALUES"]["___lc_collate_cp_func"], 1252)
    equal(module["_MSVCRT_CXX_CONSTRUCTORS"]["??0exception@@qae@abqbd@z"], 1)
    equal(module["_ctype_mask"](0x41), 0x0181)
    equal(module["_ctype_mask"](0x39), 0x0084)
    equal(module["_ctype_mask"](0x20), 0x0048)
    equal(module["_strftime_text"]("%Y-%m-%d %H:%M:%S", [5, 4, 3, 2, 0, 100, 0, 1, 0]), "2000-01-02 03:04:05")
    equal(len(module["_deterministic_guid"](1)), 16)
    not_equal(module["_deterministic_guid"](1), module["_deterministic_guid"](2))
    signatures = module["_OLEAUT_SIGNATURES"]
    equal(signatures[15], 3)
    equal(signatures[23], 2)
    equal(signatures[77], 2)
    equal(signatures[201], 2)
    equal(signatures[411], 3)
    equal(signatures[161], 2)
    equal(signatures[163], 3)
    equal(module["_RESOURCE_SIGNATURES"]["freeresource"], 1)
    equal(module["_KERNEL_SIGNATURES"]["comparestringw"], 6)
    equal(module["_KERNEL_SIGNATURES"]["globallock"], 1)
    equal(module["_KERNEL_SIGNATURES"]["globalsize"], 1)
    equal(module["_KERNEL_SIGNATURES"]["localsize"], 1)
    equal(module["_KERNEL_SIGNATURES"]["globalunlock"], 1)
    equal(module["_KERNEL_SIGNATURES"]["rtlcreateheap"], 6)
    equal(module["_KERNEL_SIGNATURES"]["rtlinitializeresource"], 1)
    registry = testing.module("@stdlib//windows/selfreg:registry.star")
    equal(registry["_CALLS"]["regopencurrentuser"], 2)
    equal(registry["_TYPES"][10], "REG_RESOURCE_REQUIREMENTS_LIST")

def test_com_target_invocation_continues_budget():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(
        code = b"\x90\x90\x90\xb8\x78\x56\x34\x12\xc3",
        instruction_limit = 2,
    )
    budgets = []
    def on_budget(unused_machine):
        budgets.append(True)
    result = module["_invoke_target"](machine, machine.entry, [], on_budget = on_budget)
    equal(result.reason, "return")
    equal(result.value, 0x12345678)
    true(len(budgets) > 0)

def test_kernel_immediate_timer_and_thread_priority():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xb8\x34\x12\x00\x00\xc2\x08\x00")
    kernel = module["kernel32_plugin"]()
    machine.use([kernel])

    open_thread = machine.resolve_export("kernel32.dll", name = "OpenThread")
    get_priority = machine.resolve_export("kernel32.dll", name = "GetThreadPriority")
    set_priority = machine.resolve_export("kernel32.dll", name = "SetThreadPriority")
    thread = machine.call(open_thread, args = [0x20, 0, 8]).value
    not_equal(thread, 0)
    equal(machine.call(get_priority, args = [thread]).value, 0)
    equal(machine.call(set_priority, args = [thread, 2]).value, 1)
    equal(machine.call(get_priority, args = [thread]).value, 2)

    duplicate_output = machine.allocate(size = 4)
    duplicate_handle = machine.resolve_export("kernel32.dll", name = "DuplicateHandle")
    equal(machine.call(duplicate_handle, args = [0xffffffff, 0xfffffffe, 0xffffffff, duplicate_output, 0, 0, 2]).value, 1)
    duplicate = machine.read_u32le(duplicate_output)
    not_equal(duplicate, 0)
    equal(machine.call(get_priority, args = [duplicate]).value, 2)

    output = machine.allocate(size = 4)
    create_timer = machine.resolve_export("kernel32.dll", name = "CreateTimerQueueTimer")
    equal(machine.call(create_timer, args = [output, 0, machine.entry, 0, 0, 0, 8]).value, 1)
    equal(len(kernel.state["timer_callbacks"]), 1)
    equal(kernel.state["timer_callbacks"][0]["reason"], "return")
    equal(kernel.state["timer_callbacks"][0]["value"], 0x1234)

    sliced = emulator.x86(code = b"\x90\xb8\x78\x56\x34\x12\xc2\x08\x00", instruction_limit = 1)
    sliced_kernel = module["kernel32_plugin"](thread_instruction_limit = 1)
    sliced.use([sliced_kernel])
    sliced_output = sliced.allocate(size = 4)
    sliced_timer = sliced.resolve_export("kernel32.dll", name = "CreateTimerQueueTimer")
    equal(sliced.call(sliced_timer, args = [sliced_output, 0, sliced.entry, 0, 0, 0, 8]).value, 1)
    equal(sliced_kernel.state["timer_callbacks"][0]["reason"], "budget")
    true(sliced_kernel.state["pump_threads"](sliced))
    equal(sliced_kernel.state["timer_callbacks"][0]["reason"], "return")
    equal(sliced_kernel.state["timer_callbacks"][0]["value"], 0x12345678)

    worker = emulator.x86(code = b"\xb8\x21\x43\x00\x00\xc2\x04\x00")
    worker_kernel = module["kernel32_plugin"]()
    worker.use([worker_kernel])
    queue = worker.resolve_export("kernel32.dll", name = "QueueUserWorkItem")
    equal(worker.call(queue, args = [worker.entry, 0x1234, 0]).value, 1)
    equal(len(worker_kernel.state["threads"]), 1)
    equal(worker_kernel.state["threads"][0]["parameter"], 0x1234)
    equal(worker_kernel.state["threads"][0].get("result"), None)
    true(worker_kernel.state["pump_thread_slice"](worker))
    equal(worker_kernel.state["threads"][0]["result"].value, 0x4321)

def test_kernel_threadpool_timer_lifecycle():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.machine(code = b"\xc3", architecture = "amd64")
    kernel = module["kernel32_plugin"]()
    machine.use([kernel])

    create = machine.resolve_export("kernel32.dll", name = "CreateThreadpoolTimer")
    set_timer = machine.resolve_export("kernel32.dll", name = "SetThreadpoolTimer")
    wait = machine.resolve_export("kernel32.dll", name = "WaitForThreadpoolTimerCallbacks")
    close = machine.resolve_export("kernel32.dll", name = "CloseThreadpoolTimer")
    handle = machine.call(create, args = [machine.entry, 0x1234, 0]).value
    not_equal(handle, 0)

    due = machine.allocate(size = 8)
    machine.write_u64le(due, 0xffffffff4d2fa200)
    equal(machine.call(set_timer, args = [handle, due, 0, 75000]).reason, "return")
    timer = kernel.state["handles"][handle]["value"]
    equal(timer["callback"], machine.entry)
    equal(timer["context"], 0x1234)
    equal(timer["due_time"], 0xffffffff4d2fa200)
    equal(timer["period"], 0)
    equal(timer["window"], 75000)
    true(timer["pending"])
    equal(len(kernel.state["timer_callbacks"]), 0)

    equal(machine.call(wait, args = [handle, 1]).reason, "return")
    equal(timer["pending"], False)
    equal(machine.call(close, args = [handle]).reason, "return")
    equal(kernel.state["handles"].get(handle), None)

def test_kernel_amd64_thread_and_module_handle_width():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.machine(code = b"\x48\x89\xc8\xc3", architecture = "amd64")
    kernel = module["kernel32_plugin"]()
    machine.use([kernel])

    kernel.state["modules"]["high.dll"] = 0x140000000
    module_name = machine.allocate(value = binary.encode("high.dll", encoding = "utf16le", nul = True))
    output = machine.allocate(size = machine.pointer_size)
    get_module = machine.resolve_export("kernel32.dll", name = "GetModuleHandleExW")
    equal(machine.call(get_module, args = [2, module_name, output]).value, 1)
    equal(machine.read_pointer(output), 0x140000000)

    message = machine.allocate(value = binary.encode("sample", encoding = "utf16le", nul = True))
    message_output = machine.allocate(size = machine.pointer_size)
    formatted = machine.call(machine.resolve_export("kernel32.dll", name = "FormatMessageW"), args = [0x500, message, 0, 0, message_output, 0, 0])
    equal(formatted.value, 6)
    equal(machine.read_cstring(machine.read_pointer(message_output), encoding = "utf16le"), "sample")

    root = machine.allocate(value = binary.encode(r"C:\Windows", encoding = "utf16le", nul = True))
    free_bytes = machine.allocate(size = 8)
    total_bytes = machine.allocate(size = 8)
    total_free = machine.allocate(size = 8)
    disk_space = machine.resolve_export("kernel32.dll", name = "GetDiskFreeSpaceExW")
    equal(machine.call(disk_space, args = [root, free_bytes, total_bytes, total_free]).value, 1)
    equal(machine.read_u64le(free_bytes), (96 << 10) * 8 * 512)
    equal(machine.read_u64le(total_bytes), (120 << 10) * 8 * 512)
    equal(machine.read_u64le(total_free), machine.read_u64le(free_bytes))

    queue = machine.resolve_export("kernel32.dll", name = "QueueUserWorkItem")
    equal(machine.call(queue, args = [machine.entry, 0x123456789abcdef0, 0]).value, 1)
    equal(len(kernel.state["threads"]), 1)
    true(kernel.state["pump_thread_slice"](machine))
    result = kernel.state["threads"][0]["result"]
    equal(result.reason, "return")
    equal(result.value, 0x123456789abcdef0)

def test_kernel_create_process_information_pointer_width():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture, pointer_size in [("x86", 4), ("amd64", 8)]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        requests = []
        def create_process(unused_machine, request):
            requests.append(request)
            return {"process_id": 0x11223344, "thread_id": 0x55667788, "exit_code": 7}
        kernel = module["kernel32_plugin"](on_process_create = create_process)
        machine.use([kernel])

        application = machine.allocate(value = binary.encode(r"C:\Windows\sample.exe", encoding = "utf16le", nul = True))
        command = machine.allocate(value = binary.encode(r"C:\Windows\sample.exe /test", encoding = "utf16le", nul = True))
        information_size = pointer_size * 2 + 8
        information = machine.allocate(value = b"\xaa" * (information_size + 4))
        create = machine.resolve_export("kernel32.dll", name = "CreateProcessW")
        equal(machine.call(create, args = [application, command, 0, 0, 0, 0, 0, 0, 0, information]).value, 1)
        process_handle = machine.read_pointer(information)
        thread_handle = machine.read_pointer(information + pointer_size)
        not_equal(process_handle, 0)
        not_equal(thread_handle, 0)
        equal(machine.read_u32le(information + pointer_size * 2), 0x11223344)
        equal(machine.read_u32le(information + pointer_size * 2 + 4), 0x55667788)
        equal(machine.read(information + information_size, 4), b"\xaa" * 4)
        wait = machine.resolve_export("kernel32.dll", name = "WaitForSingleObject")
        equal(machine.call(wait, args = [process_handle, 0xffffffff]).value, 0)
        equal(machine.call(wait, args = [thread_handle, 0xffffffff]).value, 0)
        equal([(request["application"], request["command_line"]) for request in requests], [
            (r"C:\Windows\sample.exe", r"C:\Windows\sample.exe /test"),
        ])

def test_kernel_named_semaphore_open():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.machine(code = b"\xc3", architecture = "amd64")
    kernel = module["kernel32_plugin"]()
    machine.use([kernel])
    present = machine.allocate(value = binary.encode("Local\\present", encoding = "utf16le", nul = True))
    absent = machine.allocate(value = binary.encode("Local\\absent", encoding = "utf16le", nul = True))
    created = machine.call(machine.resolve_export("kernel32.dll", name = "CreateSemaphoreExW"), args = [0, 0, 1, present, 0, 0x1f0003]).value
    not_equal(created, 0)
    open_semaphore = machine.resolve_export("kernel32.dll", name = "OpenSemaphoreW")
    equal(machine.call(open_semaphore, args = [0x1f0003, 0, present]).value, created)
    equal(machine.call(open_semaphore, args = [0x1f0003, 0, absent]).value, 0)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "GetLastError")).value, 2)

def test_shell32_create_directory_ex_records_recursive_memory_directories():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.machine(code = b"\xc3", architecture = "amd64")
    kernel = module["kernel32_plugin"](directories = [r"C:\Users\Administrator"])
    shell = module["shell32_plugin"](kernel = kernel)
    machine.use([kernel, shell])
    path = machine.allocate(value = binary.encode(r"C:\Users\Administrator\Application Data\Microsoft\Internet Explorer", encoding = "utf16le", nul = True))
    create = machine.resolve_export("shell32.dll", name = "SHCreateDirectoryExW")
    equal(machine.call(create, args = [0, path, 0]).value, 0)
    true(kernel.state["paths"][r"c:\users\administrator\application data"]["directory"])
    true(kernel.state["paths"][r"c:\users\administrator\application data\microsoft"]["directory"])
    true(kernel.state["paths"][r"c:\users\administrator\application data\microsoft\internet explorer"]["directory"])
    equal(machine.call(create, args = [0, path, 0]).value, 183)

def test_kernel_critical_section_blocks_other_execution_and_is_recursive():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["kernel32_plugin"]()])
    critical_section = machine.allocate(size = 24)
    initialize = machine.resolve_export("kernel32.dll", name = "InitializeCriticalSection")
    enter = machine.resolve_export("kernel32.dll", name = "EnterCriticalSection")
    leave = machine.resolve_export("kernel32.dll", name = "LeaveCriticalSection")

    equal(machine.call(initialize, args = [critical_section]).reason, "return")
    equal(machine.call(enter, args = [critical_section]).reason, "return")
    equal(machine.call(enter, args = [critical_section]).reason, "return")

    contender = machine.spawn(enter, args = [critical_section])
    equal(contender.run().reason, "wait")
    equal(machine.call(leave, args = [critical_section]).reason, "return")
    equal(contender.run().reason, "wait")
    equal(machine.call(leave, args = [critical_section]).reason, "return")
    equal(contender.run().reason, "return")

    srw = machine.allocate(size = 4)
    initialize_srw = machine.resolve_export("kernel32.dll", name = "InitializeSRWLock")
    acquire_srw = machine.resolve_export("kernel32.dll", name = "TryAcquireSRWLockExclusive")
    release_srw = machine.resolve_export("kernel32.dll", name = "ReleaseSRWLockExclusive")
    machine.write_u32le(srw, 0xffffffff)
    equal(machine.call(initialize_srw, args = [srw]).reason, "return")
    equal(machine.read_u32le(srw), 0)
    equal(machine.call(acquire_srw, args = [srw]).value, 1)
    machine.call(release_srw, args = [srw])
    equal(machine.call(acquire_srw, args = [srw]).value, 1)
    machine.call(release_srw, args = [srw])

def test_virtual_protect_restores_image_execution():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xb8\x34\x12\x00\x00\xc3")
    machine.use([module["kernel32_plugin"]()])
    output = machine.allocate(size = 4)
    virtual_protect = machine.resolve_export("kernel32.dll", name = "VirtualProtect")

    equal(machine.call(virtual_protect, args = [machine.entry, 6, 0x40, output]).value, 1)
    equal(machine.read_u32le(output), 0x20)
    equal(machine.call(virtual_protect, args = [machine.entry, 6, 0x20, output]).value, 1)
    equal(machine.read_u32le(output), 0x40)
    equal(machine.call(machine.entry).value, 0x1234)

def test_virtual_alloc_commits_reserved_subrange():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["kernel32_plugin"]()])
    virtual_alloc = machine.resolve_export("kernel32.dll", name = "VirtualAlloc")
    reserved = machine.call(virtual_alloc, args = [0, 0x1000, 0x2000, 0x01]).value
    true(reserved != 0)
    committed = machine.call(virtual_alloc, args = [reserved, 0x1000, 0x1000, 0x04]).value
    equal(committed, reserved)
    machine.write(committed + 6, b"acme")
    equal(machine.read(committed + 6, 4), b"acme")

def test_kernel_tls_api_shares_teb_slots():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3", fs_base = 0x7ffde000)
    slots = machine.allocate(size = 64 * 4)
    machine.write_u32le(machine.segment_base("fs") + 0x2c, slots)
    machine.use([module["kernel32_plugin"](tls_slots = slots)])
    tls_alloc = machine.resolve_export("kernel32.dll", name = "TlsAlloc")
    tls_get = machine.resolve_export("kernel32.dll", name = "TlsGetValue")
    tls_set = machine.resolve_export("kernel32.dll", name = "TlsSetValue")
    index = machine.call(tls_alloc).value
    equal(machine.call(tls_set, args = [index, 0x12345678]).value, 1)
    equal(machine.read_u32le(machine.read_u32le(machine.segment_base("fs") + 0x2c) + index * 4), 0x12345678)
    machine.write_u32le(slots + index * 4, 0x87654321)
    equal(machine.call(tls_get, args = [index]).value, 0x87654321)

def test_virtual_alloc_reserves_released_fixed_address():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["kernel32_plugin"]()])
    virtual_alloc = machine.resolve_export("kernel32.dll", name = "VirtualAlloc")
    virtual_free = machine.resolve_export("kernel32.dll", name = "VirtualFree")

    original = machine.call(virtual_alloc, args = [0, 0x30000, 0x3000, 0x04]).value
    not_equal(original, 0)
    equal(machine.call(virtual_free, args = [original, 0, 0x8000]).value, 1)
    fixed = original + 0x10000
    equal(machine.call(virtual_alloc, args = [fixed, 0x1000, 0x2000, 0x01]).value, fixed)
    equal(machine.call(virtual_alloc, args = [fixed, 0x1000, 0x1000, 0x04]).value, fixed)
    machine.write_u32le(fixed, 0x12345678)
    equal(machine.read_u32le(fixed), 0x12345678)
    equal(machine.call(virtual_alloc, args = [fixed + 0x10000, 0x1000, 0x1000, 0x04]).value, 0)
    # A subsequent automatic allocation can still consume the leading part
    # of the released range without colliding with the fixed reservation.
    equal(machine.call(virtual_alloc, args = [0, 0x10000, 0x3000, 0x04]).value, original)

def test_kernel_non_debugged_process_introspection():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3", fs_base = 0x7ffde000)
    observed_system_queries = []
    def observe_system_query(current, query):
        observed_system_queries.append({
            "class": query["class"],
            "request": current.read(query["address"], query["length"]),
        })
        return "observed"
    kernel = module["kernel32_plugin"](
        virtual_modules = ["kernel32.dll", "ntdll.dll"],
        on_system_query = observe_system_query,
    )
    machine.use([module["environment_plugin"](), kernel])

    is_debugger_present = machine.resolve_export("kernel32.dll", name = "IsDebuggerPresent")
    equal(machine.call(is_debugger_present).value, 0)

    query_process = machine.resolve_export("ntdll.dll", name = "NtQueryInformationProcess")
    process_output = machine.allocate(size = 24)
    return_length = machine.allocate(size = 4)
    equal(machine.call(query_process, args = [0xffffffff, 0, process_output, 24, return_length]).value, 0)
    equal(machine.read_u32le(return_length), 24)
    equal(machine.read_u32le(process_output + 4), machine.read_u32le(machine.segment_base("fs") + 0x30))
    equal(machine.read_u32le(process_output + 16), 4)

    debug_value = machine.allocate(size = 4)
    equal(machine.call(query_process, args = [0xffffffff, 7, debug_value, 4, return_length]).value, 0)
    equal(machine.read_u32le(debug_value), 0)
    equal(machine.call(query_process, args = [0xffffffff, 31, debug_value, 4, return_length]).value, 0)
    equal(machine.read_u32le(debug_value), 1)
    equal(machine.call(query_process, args = [0xffffffff, 30, debug_value, 4, return_length]).value, 0xc0000353)
    equal(machine.read_u32le(debug_value), 0)
    equal(machine.call(query_process, args = [0xffffffff, 7, debug_value, 3, return_length]).value, 0xc0000004)
    equal(machine.read_u32le(return_length), 4)

    query_system = machine.resolve_export("ntdll.dll", name = "ZwQuerySystemInformation")
    debugger_state = machine.allocate(value = b"\xaa\xbb")
    equal(machine.call(query_system, args = [35, debugger_state, 2, return_length]).value, 0)
    equal(machine.read(debugger_state, 2), b"\x00\x01")
    equal(machine.read_u32le(return_length), 2)
    equal(observed_system_queries, [{"class": 35, "request": b"\xaa\xbb"}])
    equal(kernel.state["system_queries"][0]["observation"], "observed")

    register = machine.resolve_export("ntdll.dll", name = "EtwEventRegister")
    registration = machine.allocate(size = 8)
    equal(machine.call(register, args = [0, 0, 0, registration]).value, 0)
    registration_handle = machine.read_u64le(registration)
    not_equal(registration_handle, 0)
    enabled = machine.resolve_export("ntdll.dll", name = "EtwEventEnabled")
    equal(machine.call(enabled, args = [registration_handle & 0xffffffff, registration_handle >> 32, 0]).value, 0)
    unregister = machine.resolve_export("ntdll.dll", name = "EtwEventUnregister")
    equal(machine.call(unregister, args = [registration_handle & 0xffffffff, registration_handle >> 32]).value, 0)

    get_module = machine.resolve_export("kernel32.dll", name = "GetModuleHandleA")
    get_procedure = machine.resolve_export("kernel32.dll", name = "GetProcAddress")
    ntdll_name = machine.allocate(value = binary.encode("ntdll.dll", nul = True))
    query_name = machine.allocate(value = binary.encode("ZwQueryInformationProcess", nul = True))
    ntdll = machine.call(get_module, args = [ntdll_name]).value
    not_equal(ntdll, 0)
    dynamic_query = machine.call(get_procedure, args = [ntdll, query_name]).value
    not_equal(dynamic_query, 0)
    equal(machine.call(dynamic_query, args = [0xffffffff, 7, debug_value, 4, return_length]).value, 0)
    equal(machine.read_u32le(debug_value), 0)
    true(len(kernel.state["process_queries"]) >= 5)
    equal(len(kernel.state["system_queries"]), 1)

def test_kernel_system_query_provider_preserves_target_status_contract():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    provided = []
    def provide_system_query(current, query):
        provided.append({"class": query["class"], "request": current.read(query["address"], query["length"])})
        if query["class"] != 134:
            return None
        return {
            "required_length": 20,
            "short_status": 0xc0000023,
            "status": 0xc000003e,
        }
    kernel = module["kernel32_plugin"](
        virtual_modules = ["ntdll.dll"],
        system_query_provider = provide_system_query,
    )
    machine.use([kernel])

    query = machine.resolve_export("ntdll.dll", name = "NtQuerySystemInformation")
    original = b"0123456789abcdefghij"
    output = machine.allocate(value = original)
    returned = machine.allocate(size = 4)
    equal(machine.call(query, args = [134, output, 19, returned]).value, 0xc0000023)
    equal(machine.read_u32le(returned), 20)
    equal(machine.read(output, 20), original)
    equal(machine.call(query, args = [134, output, 20, returned]).value, 0xc000003e)
    equal(machine.read_u32le(returned), 20)
    equal(machine.read(output, 20), original)
    equal(machine.call(query, args = [133, output, 20, returned]).value, 0xc0000003)
    equal([item["class"] for item in provided], [134, 134, 133])
    equal(kernel.state["system_queries"][0]["response"], {"data_size": 0, "required_length": 20, "status": 0xc0000023})
    equal(kernel.state["system_queries"][1]["response"], {"data_size": 0, "required_length": 20, "status": 0xc000003e})
    equal(kernel.state["system_queries"][2]["response"], None)

def test_kernel_thread_page_priority_and_process_termination():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    kernel = module["kernel32_plugin"]()
    machine.use([kernel])

    query = machine.resolve_export("ntdll.dll", name = "NtQueryInformationThread")
    update = machine.resolve_export("ntdll.dll", name = "NtSetInformationThread")
    output = machine.allocate(size = 4)
    returned = machine.allocate(size = 4)
    equal(machine.call(query, args = [0xfffffffe, 24, output, 4, returned]).value, 0)
    equal(machine.read_u32le(output), 5)
    equal(machine.read_u32le(returned), 4)
    machine.write_u32le(output, 3)
    equal(machine.call(update, args = [0xfffffffe, 24, output, 4]).value, 0)
    equal(machine.call(query, args = [0xfffffffe, 24, output, 4, returned]).value, 0)
    equal(machine.read_u32le(output), 3)
    equal(machine.call(query, args = [0xfffffffe, 24, output, 3, returned]).value, 0xc0000004)

    equal(machine.call(query, args = [0xfffffffe, 22, output, 4, returned]).value, 0)
    equal(machine.read_u32le(output), 2)
    machine.write_u32le(output, 0)
    equal(machine.call(update, args = [0xfffffffe, 22, output, 4]).value, 0)
    equal(machine.call(query, args = [0xfffffffe, 22, output, 4, returned]).value, 0)
    equal(machine.read_u32le(output), 0)
    machine.write_u32le(output, 4)
    equal(machine.call(update, args = [0xfffffffe, 22, output, 4]).value, 0xc000000d)

    convert_status = machine.resolve_export("ntdll.dll", name = "RtlNtStatusToDosError")
    equal(machine.call(convert_status, args = [0xc0000022]).value, 5)
    equal(machine.call(convert_status, args = [0xdeadbeef]).value, 317)

    terminate = machine.resolve_export("kernel32.dll", name = "TerminateProcess")
    result = machine.call(terminate, args = [0xffffffff, 7])
    equal(result.reason, "process-exit")
    equal(kernel.state["process_exit_code"], 7)

def test_rtl_relative_nt_path_status_and_buffer_ownership():
    win32 = testing.module("@stdlib//windows/selfreg:win32.star")
    for arch in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = arch)
        kernel = win32["kernel32_plugin"]()
        machine.use(kernel)
        kernel.state["current_directory"] = "C:" + chr(92) + "Caller"
        convert = machine.resolve_export("ntdll.dll", name = "RtlDosPathNameToRelativeNtPathName_U_WithStatus")
        legacy = machine.resolve_export("ntdll.dll", name = "RtlDosPathNameToRelativeNtPathName_U")
        size = 16 if arch == "amd64" else 8
        relative_size = size + 2 * machine.pointer_size
        storage = machine.allocate(value = b"Q" * (size + 16))
        output = storage + 8
        rel_storage = machine.allocate(value = b"R" * (relative_size + 16))
        relative = rel_storage + 8
        part_storage = machine.allocate(value = b"P" * (machine.pointer_size + 16))
        part = part_storage + 8
        # Independent actual NTDLL d8b90 captures: rejected buffers untouched.
        for text, expected in [(None, 0xc0000033), ("", 0xc0000033), ("D:" + chr(92) + "a" * 32767, 0xc0000106)]:
            path = machine.allocate(value = binary.encode(text, encoding = "utf16le", nul = True)) if text != None else 0
            result = machine.call(convert, args = [path, output, part, relative])
            equal(result.reason, "return", result.detail)
            equal(result.value, expected)
            equal(machine.read(storage, size + 16), b"Q" * (size + 16))
            equal(machine.read(rel_storage, relative_size + 16), b"R" * (relative_size + 16))
            equal(kernel.state["local_allocations"], {})
        text = "D:" + chr(92) + "Native" + chr(92) + chr(0x1f600) + ".DLL"
        path = machine.allocate(value = binary.encode(text, encoding = "utf16le", nul = True))
        encoded = binary.encode(chr(92) + "??" + chr(92) + text, encoding = "utf16le", nul = True)
        result = machine.call(convert, args = [path, output, part, relative])
        equal(result.reason, "return", result.detail)
        equal(result.value, 0)  # NT_SUCCESS, not the Boolean wrapper's 1.
        buffer = machine.read_pointer(output + (8 if arch == "amd64" else 4))
        equal(machine.read_u16le(output), len(encoded) - 2)
        equal(machine.read_u16le(output + 2), len(encoded))
        equal(machine.read(buffer, len(encoded)), encoded)
        equal(machine.read_cstring(machine.read_pointer(part), encoding = "utf16le"), chr(0x1f600) + ".DLL")
        equal(machine.read_pointer(part) - buffer, len(binary.encode(chr(92) + "??" + chr(92) + "D:" + chr(92) + "Native" + chr(92), encoding = "utf16le")))
        equal(machine.read(relative, relative_size), b"\x00" * relative_size)
        equal(machine.read(storage, 8), b"Q" * 8)
        equal(machine.read(output + size, 8), b"Q" * 8)
        equal(machine.read(rel_storage, 8), b"R" * 8)
        equal(machine.read(relative + relative_size, 8), b"R" * 8)
        equal(machine.read(part_storage, 8), b"P" * 8)
        equal(machine.read(part + machine.pointer_size, 8), b"P" * 8)
        machine.call(machine.resolve_export("ntdll.dll", name = "RtlReleaseRelativeName"), args = [relative])
        machine.call(machine.resolve_export("ntdll.dll", name = "RtlFreeUnicodeString"), args = [output])
        equal(kernel.state["local_allocations"], {})
        # Legacy Boolean ABI is unchanged and shares the owned allocation/free.
        equal(machine.call(legacy, args = [path, output, 0, 0]).value, 1)
        machine.call(machine.resolve_export("ntdll.dll", name = "RtlFreeUnicodeString"), args = [output])
        for unsupported in ["relative.dll", "C:" + chr(92) + "Caller" + chr(92) + "same.dll"]:
            path = machine.allocate(value = binary.encode(unsupported, encoding = "utf16le", nul = True))
            equal(machine.call(convert, args = [path, output, part, relative]).reason, "plugin")
            equal(kernel.state["local_allocations"], {})

def test_cryptoapi_delay_contract_shares_owned_contexts():
    crypto_module = testing.module("@stdlib//windows/selfreg:crypto.star")
    win32 = testing.module("@stdlib//windows/selfreg:win32.star")
    contract = "api-ms-win-security-cryptoapi-l1-1-0.dll"
    for arch in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = arch)
        kernel = win32["kernel32_plugin"](virtual_modules = [contract])
        provider = crypto_module["cryptoapi_plugin"](kernel = kernel)
        machine.use([kernel, provider])
        name = machine.allocate(value = binary.encode(contract, nul = True))
        loaded = machine.call(machine.resolve_export("kernel32.dll", name = "LoadLibraryExA"), args = [name, 0, 0])
        equal(loaded.reason, "return", loaded.detail)
        not_equal(loaded.value, 0)
        resolve = machine.resolve_export("kernel32.dll", name = "GetProcAddress")
        acquire_name = machine.allocate(value = binary.encode("CryptAcquireContextW", nul = True))
        release_name = machine.allocate(value = binary.encode("CryptReleaseContext", nul = True))
        acquire = machine.call(resolve, args = [loaded.value, acquire_name]).value
        release = machine.call(resolve, args = [loaded.value, release_name]).value
        not_equal(acquire, 0)
        not_equal(release, 0)
        output = machine.allocate(value = b"Q" * 16)
        equal(machine.call(acquire, args = [output, 0, 0, 1, 0xf0000000]).value, 1)
        handle = machine.read_pointer(output)
        true(handle in provider.state["providers"])
        equal(machine.read(output + machine.pointer_size, 16 - machine.pointer_size), b"Q" * (16 - machine.pointer_size))
        # A context acquired via the delay contract is owned by the same
        # provider and may be released through Advapi32 (and vice versa).
        equal(machine.call(machine.resolve_export("advapi32.dll", name = "CryptReleaseContext"), args = [handle, 0]).value, 1)
        equal(machine.call(release, args = [handle, 0]).value, 0)
        equal(machine.call(machine.resolve_export("advapi32.dll", name = "CryptAcquireContextW"), args = [output, 0, 0, 1, 0xf0000000]).value, 1)
        handle = machine.read_pointer(output)
        equal(machine.call(release, args = [handle, 0]).value, 1)
        equal(provider.state["providers"], {})
        unknown = machine.allocate(value = binary.encode("NotACryptoExport", nul = True))
        equal(machine.call(resolve, args = [loaded.value, unknown]).value, 0)

def test_cryptoapi_verification_context_lifecycle():
    module = testing.module("@stdlib//windows/selfreg:crypto.star")
    true(module["_cryptoapi_provider_module"]("advapi32.dll"))
    true(module["_cryptoapi_provider_module"]("api-ms-win-security-cryptoapi-l1-1-0.dll"))
    true(module["_cryptoapi_provider_module"]("EXT-MS-WIN-SECURITY-CRYPTOAPI-L1-1-0.DLL"))
    true(not module["_cryptoapi_provider_module"]("api-ms-win-core-registry-l1-1-0.dll"))
    machine = emulator.x86(code = b"\xc3")
    provider = module["cryptoapi_plugin"]()
    machine.use([provider])

    output = machine.allocate(size = 4)
    acquire = machine.resolve_export("advapi32.dll", name = "CryptAcquireContextW")
    release = machine.resolve_export("advapi32.dll", name = "CryptReleaseContext")
    random = machine.resolve_export("advapi32.dll", name = "CryptGenRandom")
    rtl_random = machine.resolve_export("advapi32.dll", name = "SystemFunction036")
    create_hash = machine.resolve_export("advapi32.dll", name = "CryptCreateHash")
    hash_data = machine.resolve_export("advapi32.dll", name = "CryptHashData")
    get_hash = machine.resolve_export("advapi32.dll", name = "CryptGetHashParam")
    destroy_hash = machine.resolve_export("advapi32.dll", name = "CryptDestroyHash")
    import_key = machine.resolve_export("advapi32.dll", name = "CryptImportKey")
    destroy_key = machine.resolve_export("advapi32.dll", name = "CryptDestroyKey")
    name = machine.allocate(value = binary.encode("Microsoft Base Cryptographic Provider v1.0", encoding = "utf16le", nul = True))
    equal(machine.call(acquire, args = [output, 0, name, 1, 0xf0000000]).value, 1)
    handle = machine.read_u32le(output)
    not_equal(handle, 0)
    random_output = machine.allocate(size = 40)
    equal(machine.call(random, args = [handle, 40, random_output]).value, 1)
    not_equal(machine.read(random_output, 40), b"\x00" * 40)
    rtl_random_output = machine.allocate(size = 64)
    equal(machine.call(rtl_random, args = [rtl_random_output, 32]).value, 1)
    first_random = machine.read(rtl_random_output, 32)
    not_equal(first_random, b"\x00" * 32)
    equal(machine.call(rtl_random, args = [rtl_random_output + 32, 32]).value, 1)
    not_equal(machine.read(rtl_random_output + 32, 32), first_random)
    equal(machine.call(rtl_random, args = [0, 0]).value, 1)
    equal(machine.call(rtl_random, args = [0, 1]).value, 0)
    equal(machine.call(create_hash, args = [handle, 0x800c, 0, 0, output]).value, 1)
    hash_handle = machine.read_u32le(output)
    first = machine.allocate(value = b"ab")
    second = machine.allocate(value = b"c")
    equal(machine.call(hash_data, args = [hash_handle, first, 2, 0]).value, 1)
    equal(machine.call(hash_data, args = [hash_handle, second, 1, 0]).value, 1)
    digest = machine.allocate(32)
    digest_size = machine.allocate(value = binary.u32le(32))
    equal(machine.call(get_hash, args = [hash_handle, 2, digest, digest_size, 0]).value, 1)
    equal(machine.read(digest, 32), crypto.hash("sha256", b"abc"))
    equal(machine.call(destroy_hash, args = [hash_handle]).value, 1)
    equal(machine.call(destroy_hash, args = [hash_handle]).value, 0)

    public_key = binary.builder()
    public_key.u8(0x06)
    public_key.u8(0x02)
    public_key.u16le(0)
    public_key.u32le(0xa400)
    public_key.u32le(0x31415352)
    public_key.u32le(512)
    public_key.u32le(65537)
    public_key.append(b"\x01" * 64)
    key_blob = machine.allocate(value = public_key.bytes())
    equal(machine.call(import_key, args = [handle, key_blob, public_key.size, 0, 0x40, output]).value, 1)
    key_handle = machine.read_u32le(output)
    not_equal(key_handle, 0)
    equal(machine.call(destroy_key, args = [key_handle]).value, 1)
    equal(machine.call(import_key, args = [handle, key_blob, public_key.size, 0, 0x80000000, output]).value, 0)

    equal(machine.call(release, args = [handle, 0]).value, 1)
    equal(machine.call(release, args = [handle, 0]).value, 0)

    prefix = binary.decode("3031300d060960864801650304020105000420", encoding = "hex")
    encoded = binary.view(binary.concat([b"\x00\x01", b"\xff" * 8, b"\x00", prefix, crypto.hash("sha256", b"abc")]))
    true(module["_pkcs1_digest_matches"](encoded, crypto.hash("sha256", b"abc"), prefix))
    true(not module["_pkcs1_digest_matches"](binary.concat([encoded[:-1], b"\x00"]), crypto.hash("sha256", b"abc"), prefix))

def test_security_adjusts_only_owned_privileges():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"]()
        security = module["security_plugin"](kernel = kernel, token_privileges = {17: 0, 18: 1})
        machine.use([kernel, security])
        output = machine.allocate(size = machine.pointer_size)
        process = machine.resolve_export("advapi32.dll", name = "OpenProcessToken")
        equal(machine.call(process, args = [0xffffffff, 0x2a, output]).value, 1)
        primary = machine.read_pointer(output)
        duplicate = machine.resolve_export("advapi32.dll", name = "DuplicateTokenEx")
        equal(machine.call(duplicate, args = [primary, 0x2a, 0, 2, 2, output]).value, 1)
        token = machine.read_pointer(output)
        adjust = machine.resolve_export("api-ms-win-security-base-l1-1-0.dll", name = "AdjustTokenPrivileges")
        request = binary.builder()
        request.u32le(2)
        for luid in [17, 999]:
            request.u64le(luid)
            request.u32le(2)
        changes = machine.allocate(value = request.bytes())
        previous = machine.allocate(value = b"Z" * 24)
        required = machine.allocate(size = 4)
        # Failed previous-state sizing must not mutate the token.
        equal(machine.call(adjust, args = [token, 0, changes, 15, previous, required]).value, 0)
        equal(kernel.state["last_error"], 122)
        equal(machine.read_u32le(required), 16)
        equal(machine.read(previous, 24), b"Z" * 24)
        equal(security.state["tokens"][token]["value"]["privileges"][17], 0)
        capacity = 0x7fff00000010 if architecture == "amd64" else 16
        equal(machine.call(adjust, args = [token, 0, changes, capacity, previous, required]).value, 1)
        equal(kernel.state["last_error"], 1300)  # TRUE, but not all assigned.
        equal(machine.read_u32le(previous), 1)
        equal(machine.read_u64le(previous + 4), 17)
        equal(machine.read_u32le(previous + 12), 0)
        equal(machine.read(previous + 16, 8), b"Z" * 8)
        privileges = security.state["tokens"][token]["value"]["privileges"]
        equal(privileges, {17: 2, 18: 1})
        equal(security.state["process_token"]["privileges"], {17: 0, 18: 1})
        # Restore exactly the returned previous state.
        equal(machine.call(adjust, args = [token, 0, previous, 0, 0, 0]).value, 1)
        equal(kernel.state["last_error"], 0)
        equal(privileges[17], 0)
        query = machine.resolve_export("advapi32.dll", name = "GetTokenInformation")
        equal(machine.call(query, args = [token, 3, previous, 24, required]).value, 0)
        equal(kernel.state["last_error"], 122)
        equal(machine.read_u32le(required), 28)
        data = machine.allocate(size = 28)
        equal(machine.call(query, args = [token, 3, data, 28, required]).value, 1)
        equal(machine.read_u32le(data), 2)
        equal(machine.read_u64le(data + 4), 17)
        equal(machine.read_u64le(data + 16), 18)
        # Removed privileges cannot be re-added by adjustment.
        machine.write_u32le(changes, 1)
        machine.write_u32le(changes + 12, 4)
        equal(machine.call(adjust, args = [token, 0, changes, 0, 0, 0]).value, 1)
        equal(17 in privileges, False)
        machine.write_u32le(changes + 12, 2)
        equal(machine.call(adjust, args = [token, 0, changes, 0, 0, 0]).value, 1)
        equal(kernel.state["last_error"], 1300)
        equal(17 in privileges, False)

def test_security_token_object_lifetime():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"]()
        security = module["security_plugin"](kernel = kernel)
        machine.use([kernel, security])
        kernel.state["next_handle"] = 0x100040000 if architecture == "amd64" else 0x40000
        output = machine.allocate(size = machine.pointer_size + 4)
        process = machine.resolve_export("advapi32.dll", name = "OpenProcessToken")
        thread = machine.resolve_export("advapi32.dll", name = "OpenThreadToken")
        duplicate = machine.resolve_export("advapi32.dll", name = "DuplicateTokenEx")
        assign = machine.resolve_export("advapi32.dll", name = "SetThreadToken")
        query = machine.resolve_export("advapi32.dll", name = "GetKernelObjectSecurity")
        set_security = machine.resolve_export("advapi32.dll", name = "SetKernelObjectSecurity")
        current_process = 0xffffffffffffffff if architecture == "amd64" else 0xffffffff
        current_thread = 0xfffffffffffffffe if architecture == "amd64" else 0xfffffffe
        machine.write(output, b"Z" * (machine.pointer_size + 4))
        equal(machine.call(thread, args = [current_thread, 0x20008, 1, output]).value, 0)
        equal(kernel.state["last_error"], 1008)
        equal(machine.read(output, machine.pointer_size + 4), b"Z" * (machine.pointer_size + 4))
        equal(machine.call(process, args = [current_process, 0x6000e, output]).value, 1)
        primary = machine.read_pointer(output)
        equal(machine.read(output + machine.pointer_size, 4), b"ZZZZ")
        required = machine.allocate(size = 4)
        equal(machine.call(query, args = [primary, 4, 0, 0, required]).value, 0)
        equal(kernel.state["last_error"], 122)
        size = machine.read_u32le(required)
        descriptor = machine.allocate(size = size)
        equal(machine.call(query, args = [primary, 4, descriptor, size, required]).value, 1)
        original = machine.read(descriptor, size)
        dacl = machine.read_u32le(descriptor + 16)
        true(dacl >= 20)  # No NULL/permissive DACL substitution.
        equal(machine.read_u16le(descriptor + dacl + 4), 2)
        equal(machine.call(assign, args = [0, primary]).value, 0)
        equal(kernel.state["last_error"], 1349)
        attributes = machine.allocate(size = 24 if architecture == "amd64" else 12)
        machine.write_u32le(attributes, 24 if architecture == "amd64" else 12)
        source_descriptor = machine.allocate(value = original)
        machine.write_pointer(attributes + machine.pointer_size, source_descriptor)
        equal(machine.call(duplicate, args = [primary, 0x6000e, attributes, 2, 2, output]).value, 1)
        copied = machine.read_pointer(output)
        machine.free(source_descriptor)  # Duplicate owns its descriptor bytes.
        true(copied != primary)
        tighter = module["_sddl_descriptor"]("O:SYG:SYD:(A;;GA;;;SY)")
        protected = machine.allocate(value = tighter)
        equal(machine.call(set_security, args = [copied, 4, protected]).value, 1)
        equal(machine.call(query, args = [primary, 4, descriptor, size, required]).value, 1)
        equal(machine.read(descriptor, size), original)  # Independent duplicate.
        equal(machine.call(assign, args = [0, copied]).value, 1)
        close = machine.resolve_export("kernel32.dll", name = "CloseHandle")
        equal(machine.call(close, args = [copied]).value, 1)
        equal(machine.call(thread, args = [current_thread, 0x20008, 1, output]).value, 1)
        reopened = machine.read_pointer(output)
        true(reopened != copied)
        equal(machine.call(query, args = [reopened, 4, descriptor, size, required]).value, 1)
        equal(machine.read(descriptor, len(tighter)), tighter)
        # A different emulated thread has no inherited impersonation token.
        kernel.state["current_thread"] = {"id": 16}
        equal(machine.call(thread, args = [current_thread, 8, 1, output]).value, 0)
        equal(kernel.state["last_error"], 1008)
        kernel.state["current_thread"] = None
        equal(machine.call(machine.resolve_export("advapi32.dll", name = "RevertToSelf")).value, 1)
        equal(machine.call(thread, args = [current_thread, 8, 1, output]).value, 0)
        equal(kernel.state["last_error"], 1008)
        equal(machine.call(process, args = [current_process, 0x20008, output]).value, 1)
        read_only = machine.read_pointer(output)
        equal(machine.call(set_security, args = [read_only, 4, protected]).value, 0)
        equal(kernel.state["last_error"], 5)
        equal(machine.call(process, args = [current_process, 8, output]).value, 1)
        query_only = machine.read_pointer(output)
        equal(machine.call(query, args = [query_only, 4, descriptor, size, required]).value, 0)
        equal(kernel.state["last_error"], 5)
        equal(machine.call(close, args = [primary]).value, 1)
        equal(machine.call(duplicate, args = [primary, 0x6000e, 0, 2, 2, output]).value, 0)
        equal(kernel.state["last_error"], 6)
        equal(machine.call(query, args = [0xdeadbeef, 4, descriptor, size, required]).value, 0)
        equal(kernel.state["last_error"], 6)

def test_nt_open_process_owned_query_handle():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture, width in [("x86", 4), ("amd64", 8)]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        kernel = module["kernel32_plugin"]()
        machine.use([kernel, module["security_plugin"](kernel = kernel)])
        kernel.state["last_error"] = 0x1234
        kernel.state["next_handle"] = 0x100040000 if width == 8 else 0x40000
        target = machine.resolve_export("ntdll.dll", name = "NtOpenProcess")
        output = machine.allocate(value = b"\xa5" * (width + 8))
        attributes = machine.allocate(value = b"\x00" * (48 if width == 8 else 24))
        machine.write_u32le(attributes, 48 if width == 8 else 24)
        client = machine.allocate(value = b"\x00" * (width * 2))
        machine.write_pointer(client, 4)
        result = machine.call(target, args = [output, 0xfeed00001000 if width == 8 else 0x1000, attributes, client])
        equal(result.reason, "return")
        equal(result.value, 0)
        handle = machine.read_pointer(output)
        equal(handle, 0x100040000 if width == 8 else 0x40000)
        equal(machine.read(output + width, 8), b"\xa5" * 8)
        equal(kernel.state["handles"][handle], {"kind": "process_reference", "value": {"id": 4, "access": 0x1000, "inherit": False}})
        equal(kernel.state["last_error"], 0x1234)
        close = machine.resolve_export("ntdll.dll", name = "NtClose")
        equal(machine.call(close, args = [handle]).value, 0)
        true(handle not in kernel.state["handles"])
        # Rejection must neither publish a handle nor overwrite its output.
        machine.write(output, b"\xa5" * (width + 8))
        before = dict(kernel.state["handles"])
        machine.write_pointer(client, 99)
        equal(machine.call(target, args = [output, 0x1000, attributes, client]).value, 0xc000000b)
        equal(machine.read(output, width + 8), b"\xa5" * (width + 8))
        equal(kernel.state["handles"], before)
        machine.write_pointer(client, 4)
        machine.write_u32le(attributes, 0)
        equal(machine.call(target, args = [output, 0x1000, attributes, client]).value, 0xc000000d)
        equal(machine.read(output, width + 8), b"\xa5" * (width + 8))
        machine.write_u32le(attributes, 48 if width == 8 else 24)
        result = machine.call(target, args = [output, 0x1fffff, attributes, client])
        equal(result.reason, "plugin")
        true("outside limited current-process queries" in result.detail)
        equal(kernel.state["handles"], before)
        equal(machine.read(output, width + 8), b"\xa5" * (width + 8))

def test_security_access_mapping():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    true(module["_security_provider_module"]("advapi32.dll"))
    true(module["_security_provider_module"]("api-ms-win-security-sddl-l1-1-0.dll"))
    true(module["_security_provider_module"]("api-ms-win-core-processthreads-l1-1-0.dll"))
    true(module["_security_provider_module"]("EXT-MS-WIN-SECURITY-BASE-L1-1-0.DLL"))
    true(not module["_security_provider_module"]("api-ms-win-core-file-l1-1-0.dll"))
    mapping = [0x0001, 0x0002, 0x0004, 0x0008]
    equal(module["_map_generic_access"](0x80000010, mapping), 0x0011)
    equal(module["_map_generic_access"](0xf0000000, mapping), 0x000f)
    equal(module["_map_generic_access"](0x02000000, mapping), 0x02000000)
    kernel = module["kernel32_plugin"]()
    security = module["security_plugin"](kernel = kernel)
    equal(security.name, "windows.security")
    machine = emulator.machine(code = b"\xc3", architecture = "amd64")
    machine.use([kernel, security])
    output = machine.allocate(size = 8)
    open_thread_token = machine.resolve_export("api-ms-win-core-processthreads-l1-1-0.dll", name = "OpenThreadToken")
    equal(machine.call(open_thread_token, args = [0xfffffffffffffffe, 8, 1, output]).value, 0)
    equal(kernel.state["last_error"], 1008)
    open_process_token = machine.resolve_export("advapi32.dll", name = "OpenProcessToken")
    equal(machine.call(open_process_token, args = [0xffffffffffffffff, 10, output]).value, 1)
    process_token = machine.read_pointer(output)
    revert = machine.resolve_export("api-ms-win-security-base-l1-1-0.dll", name = "RevertToSelf")
    equal(machine.call(revert).value, 1)
    required = machine.allocate(size = 4)
    token_information = machine.resolve_export("api-ms-win-security-base-l1-1-0.dll", name = "GetTokenInformation")
    equal(machine.call(token_information, args = [process_token, 1, 0, 0, required]).value, 0)
    information_size = machine.read_u32le(required)
    true(information_size > 16)
    information = machine.allocate(size = information_size)
    equal(machine.call(token_information, args = [process_token, 1, information, information_size, required]).value, 1)
    equal(machine.read_pointer(information), information + 16)
    is_appcontainer = machine.allocate(size = 4)
    equal(machine.call(token_information, args = [process_token, 29, is_appcontainer, 4, required]).value, 1)
    equal(machine.read_u32le(required), 4)
    equal(machine.read_u32le(is_appcontainer), 0)
    session_id = machine.allocate(size = 4)
    equal(machine.call(token_information, args = [process_token, 12, session_id, 4, required]).value, 1)
    equal(machine.read_u32le(required), 4)
    equal(machine.read_u32le(session_id), 0)
    integrity = machine.allocate(size = 64)
    equal(machine.call(token_information, args = [process_token, 25, integrity, 64, required]).value, 1)
    integrity_sid = machine.read_pointer(integrity)
    equal(machine.read_u32le(integrity + 8), 0x60)
    equal(machine.read(integrity_sid, 8), b"\x01\x01\x00\x00\x00\x00\x00\x10")
    equal(machine.read_u32le(integrity_sid + 8), 12288)
    duplicated = machine.allocate(size = 8)
    duplicate_token = machine.resolve_export("api-ms-win-security-base-l1-1-0.dll", name = "DuplicateTokenEx")
    equal(machine.call(duplicate_token, args = [process_token, 0x2000c, 0, 1, 2, duplicated]).value, 1)
    true(machine.read_pointer(duplicated) != process_token)
    object_required = machine.allocate(size = 4)
    get_object_security = machine.resolve_export("api-ms-win-security-base-l1-1-0.dll", name = "GetKernelObjectSecurity")
    equal(machine.call(get_object_security, args = [0xffffffff, 4, 0, 0, object_required]).value, 0)
    equal(kernel.state["last_error"], 122)
    descriptor_size = machine.read_u32le(object_required)
    true(descriptor_size >= 20)
    descriptor = machine.allocate(size = descriptor_size)
    equal(machine.call(get_object_security, args = [0xffffffff, 4, descriptor, descriptor_size, object_required]).value, 1)
    set_object_security = machine.resolve_export("api-ms-win-security-base-l1-1-0.dll", name = "SetKernelObjectSecurity")
    equal(machine.call(set_object_security, args = [0xffffffff, 4, descriptor]).value, 1)
    absolute = machine.allocate(size = 56)
    machine.write_u8(absolute, 1)
    machine.write_u16le(absolute + 2, 4)
    machine.write_pointer(absolute + 32, absolute + 40)
    machine.write_u8(absolute + 40, 2)
    machine.write_u16le(absolute + 42, 16)
    machine.write_u16le(absolute + 44, 1)
    machine.write_u8(absolute + 48, 0)
    machine.write_u16le(absolute + 50, 8)
    machine.write_u32le(absolute + 52, 0x1234)
    equal(machine.call(set_object_security, args = [0xffffffff, 4, absolute]).value, 1)
    machine.free(absolute)
    equal(machine.call(get_object_security, args = [0xffffffff, 4, 0, 0, object_required]).value, 0)
    persisted_size = machine.read_u32le(object_required)
    persisted = machine.allocate(size = persisted_size)
    equal(machine.call(get_object_security, args = [0xffffffff, 4, persisted, persisted_size, object_required]).value, 1)
    persisted_dacl = machine.allocate(size = 8)
    dacl_present = machine.allocate(size = 4)
    dacl_defaulted = machine.allocate(size = 4)
    get_descriptor_dacl = machine.resolve_export("api-ms-win-security-base-l1-1-0.dll", name = "GetSecurityDescriptorDacl")
    equal(machine.call(get_descriptor_dacl, args = [persisted, dacl_present, persisted_dacl, dacl_defaulted]).value, 1)
    equal(machine.read_u32le(dacl_present), 1)
    equal(machine.read_pointer(persisted_dacl), persisted + 20)
    equal(machine.read_u16le(persisted + 22), 16)
    equal(machine.read_u32le(persisted + 32), 0x1234)
    acl = binary.builder(capacity = 16)
    acl.u8(2)
    acl.u8(0)
    acl.u16le(16)
    acl.u16le(1)
    acl.u16le(0)
    acl.u8(0)
    acl.u8(0)
    acl.u16le(8)
    acl.u32le(0x1234)
    acl_address = machine.allocate(value = acl.bytes())
    ace_output = machine.allocate(size = 8)
    get_ace = machine.resolve_export("api-ms-win-security-base-l1-1-0.dll", name = "GetAce")
    equal(machine.call(get_ace, args = [acl_address, 0, ace_output]).value, 1)
    equal(machine.read_pointer(ace_output), acl_address + 8)
    rtl_get_ace = machine.resolve_export("ntdll.dll", name = "RtlGetAce")
    equal(machine.call(rtl_get_ace, args = [acl_address, 0, ace_output]).value, 0)
    equal(machine.read_pointer(ace_output), acl_address + 8)
    for name in [
        "AccessCheck",
        "AddAccessAllowedAce",
        "CopySid",
        "DuplicateTokenEx",
        "EqualSid",
        "GetAce",
        "GetAclInformation",
        "GetLengthSid",
        "GetKernelObjectSecurity",
        "GetSecurityDescriptorControl",
        "GetSecurityDescriptorDacl",
        "GetSidSubAuthority",
        "GetSidSubAuthorityCount",
        "GetTokenInformation",
        "ImpersonateLoggedOnUser",
        "InitializeAcl",
        "InitializeSecurityDescriptor",
        "IsValidSid",
        "RevertToSelf",
        "SetSecurityDescriptorDacl",
        "SetKernelObjectSecurity",
    ]:
        true(machine.resolve_export("api-ms-win-security-base-l1-1-0.dll", name = name) != 0)

def test_sddl_security_descriptor():
    security = testing.module("@stdlib//windows:security.star")
    object_sd = security["sddl_security_descriptor"]("D:(OA;CI;RP;bf967aba-0de6-11d0-a285-00aa003049e2;;AU)")
    object_acl = binary.read_u32le(object_sd, 16)
    equal(binary.read_u8(object_sd, object_acl), 4)
    equal(hex(object_sd[object_acl + 8:]), "050228001000000001000000ba7a96bfe60dd011a28500aa003049e201010000000000050b000000")
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    equal(module["_MAKE_ABSOLUTE_SD_ARGUMENTS"], 11)
    equal(module["_WELL_KNOWN_SIDS"][22], [5, [18]])
    equal(module["_WELL_KNOWN_SIDS"][26], [5, [32, 544]])
    equal(module["_WELL_KNOWN_DOMAIN_RIDS"][35], 512)
    equal(hex(module["_sid_bytes"](5, [32, 544])), "01020000000000052000000020020000")
    descriptor = module["_sddl_descriptor"]("O:BAG:SYD:P(A;CIOI;GA;;;BA)(A;CIOI;GRGWSD;;;NS)")
    cursor = binary.cursor(descriptor)
    equal(cursor.u8(), 1)
    spaced = module["_sddl_descriptor"](
        "D:(A;;0x10000001;;;BA) (A;;0x10000001;;;LA)\t(A;;0x10000001;;;S-1-5-19)",
        aliases = {"LA": "S-1-5-21-1-2-3-500"},
    )
    equal(binary.cursor(spaced).u8(), 1)
    file_access = module["_sddl_descriptor"]("D:(A;;FA;;;SY)")
    file_cursor = binary.cursor(file_access)
    file_cursor.seek(16)
    file_dacl = file_cursor.u32le()
    file_cursor.seek(file_dacl + 12)
    equal(file_cursor.u32le(), 0x001f01ff)
    restricted = module["_sddl_descriptor"]("D:(A;;GA;;;RC)(A;;GA;;;OW)(A;;GA;;;AC)")
    restricted_cursor = binary.cursor(restricted)
    restricted_cursor.seek(16)
    restricted_dacl = restricted_cursor.u32le()
    equal(
        hex(restricted[restricted_dacl + 16:]),
        "01010000000000050c000000" +
        "0000140000000010010100000000000304000000" +
        "0000180000000010010200000000000f0200000001000000",
    )

    equal(cursor.u8(), 0)
    control = cursor.u16le()
    equal(control & 0x9004, 0x9004)
    owner = cursor.u32le()
    group = cursor.u32le()
    equal(cursor.u32le(), 0)
    dacl = cursor.u32le()
    true(owner >= 20 and group > owner and dacl > group)
    acl = binary.cursor(descriptor)
    acl.seek(dacl)
    equal(acl.u8(), 2)
    acl.u8()
    equal(acl.u16le(), len(descriptor) - dacl)
    equal(acl.u16le(), 2)
    acl.u16le()
    equal(acl.u8(), 0)
    equal(acl.u8(), 3)
    first_size = acl.u16le()
    equal(acl.u32le(), 0x10000000)
    acl.seek(dacl + 8 + first_size)
    equal(acl.u8(), 0)
    equal(acl.u8(), 3)
    acl.u16le()
    equal(acl.u32le(), 0xc0010000)

def test_mandatory_label_ace():
    module = testing.module("@stdlib//windows:security.star")
    low_integrity = module["sid"](16, [4096])
    equal(
        hex(module["mandatory_label_ace"](low_integrity, 1, flags = 0x03)),
        "1103140001000000010100000000001000100000",
    )

def test_win32_dynamic_format_width():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    wide = machine.allocate(value = binary.encode("wide", encoding = "utf16le", nul = True))
    narrow = machine.allocate(value = b"abcdef\x00")
    equal(module["_format_win32"](machine, "%-*ls:%.*s", [8, wide, 3, narrow], False), "wide    :abc")
    equal(module["_format_win32"](machine, "%*s", [0xfffffffa, narrow], False), "abcdef")

def test_user32_wsprintf_reads_all_variadic_arguments():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    image_data = windows.pe32_executable(section = b"\xc3", labels = {"entry": 0}, fixups = [])
    image_builder = binary.builder(capacity = len(image_data))
    image_builder.append(image_data)
    machine.use(module["user32_plugin"](image_builder.file()))
    output = machine.allocate(size = 64)
    format = machine.allocate(value = b"{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}\x00")
    result = machine.call(machine.resolve_export("user32.dll", name = "wsprintfA"), args = [output, format] + list(range(16)))
    equal(result.reason, "return", result.detail)
    equal(result.value, 38)
    equal(machine.read_cstring(output), "{00010203-0405-0607-0809-0A0B0C0D0E0F}")

def test_binary_floating_point_codecs():
    encoded = binary.builder(capacity = 24)
    encoded.f32be(1.5)
    encoded.f32le(-2.25)
    encoded.f64le(36526.0)
    equal(hex(encoded.bytes()), "3fc00000000010c000000000c0d5e140")
    cursor = binary.cursor(encoded.bytes())
    equal(cursor.f32be(), 1.5)
    equal(cursor.f32le(), -2.25)
    equal(cursor.f64le(), 36526.0)

def test_binary_xml_round_trip():
    document = binary.xml(b'<?xml version="1.0"?><p:Root xmlns:p="urn:test">left<p:Item id="1">one</p:Item><p:Item id="2">two</p:Item>right</p:Root>')
    root = document.root
    equal(root.qualified_name, "p:Root")
    equal(root.namespace, "urn:test")
    equal(root.direct_text, "leftright")
    items = root.children_named("Item", namespace = "urn:test")
    equal(len(items), 2)
    equal(items[1].attribute("id"), "2")
    updated = root.with_children([items[1].with_text("three & four")])
    output = document.with_root(updated).bytes()
    equal(output, b'<?xml version="1.0"?><p:Root xmlns:p="urn:test">left<p:Item id="2">three &amp; four</p:Item>right</p:Root>')
    equal(binary.xml(output).root.children[0].text, "three & four")
    equal(binary.base64(b"binary\x00data"), "YmluYXJ5AGRhdGE=")


def test_com_guid_string_uses_pointer_sized_output():
    module=testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86","amd64"]:
        machine=emulator.machine(code=b"\xc3",architecture=architecture)
        machine.use(module["ole32_plugin"]())
        guid=machine.allocate(value=binary.decode("33221100554477668899aabbccddeeff","hex"))
        out=machine.allocate(size=machine.pointer_size+4)
        for name in ["StringFromCLSID","StringFromIID"]:
            machine.write(out,b"Z"*(machine.pointer_size+4))
            result=machine.call(machine.resolve_export("ole32.dll",name=name),args=[guid,out])
            equal(result.reason,"return")
            equal(result.value,0)
            address=machine.read_pointer(out)
            equal(machine.read_cstring(address,encoding="utf16le").lower(),"{00112233-4455-6677-8899-aabbccddeeff}")
            equal(machine.read(out+machine.pointer_size,4),b"ZZZZ")

def test_win32_tracked_reallocate():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    allocations = {}
    original = module["_tracked_allocate"](machine, allocations, 4, "original")
    machine.write(original, b"data")
    replacement = module["_tracked_reallocate"](machine, allocations, original, 8, "replacement")
    equal(machine.read(replacement, 8), b"data\x00\x00\x00\x00")
    true(original not in allocations)
    equal(allocations[replacement], 8)

    # Native UCRT scans UTF-16 with PCMPEQW before testing its terminator.
    # The final vector may extend beyond malloc's logical size, but remains
    # inside its heap page. Realloc must still copy only the logical bytes.
    native = emulator.machine(code = b"\x66\x0f\xef\xc0\x66\x0f\x75\x01\x66\x0f\xd7\xc0\xc3", architecture = "amd64")
    tracked = {}
    text = module["_tracked_allocate"](native, tracked, 40, "CRT string")
    native.write(text, binary.encode("A" * 19, encoding = "utf16le", nul = True))
    scan = native.call(native.entry, args = [text + 32])
    equal(scan.reason, "return")
    equal(scan.value, 0xffc0)
    native.write(text + 40, b"padding!")
    grown = module["_tracked_reallocate"](native, tracked, text, 64, "grown CRT string")
    equal(tracked[grown], 64)
    equal(native.read(grown + 40, 8), b"\x00" * 8)


def test_binary_hex():
    equal(binary.hex(b"\x00\xab\xff"), "00abff")
    raises(binary.hex, args = [b"\x00\xab"], kwargs = {"maximum": 3}, message = "exceeds limit")

def test_installshield5_conventional_component_locations():
    module = testing.module("@stdlib//windows:installer.star")

    equal(module["_installed_artifact_module"]([
        {"source": "/ActiveX/pdf.ocx", "destination": r"C:\Program Files\Reader\ActiveX\pdf.ocx", "resolved": True},
    ], "/activex/PDF.OCX", "pdf.ocx"), r"C:\Program Files\Reader\ActiveX\pdf.ocx")
    equal(module["_installed_artifact_module"]([], "/ActiveX/pdf.ocx", "pdf.ocx"), "pdf.ocx")

    locations = module["_installshield5_component_locations"]([
        {"name": "Program Files"},
        {"name": "Help Files"},
        {"name": "Example Files"},
        {"name": "MFC Dlls"},
        {"name": "OCX Files"},
        {"name": "Windows System"},
        {"name": "ShellExtDlls"},
        {"name": "Application Data"},
        {"name": "English/Eval"},
        {"name": "English/Eval/Core"},
    ], r"C:\Program Files\FTP Voyager", r"C:\WINDOWS\SYSTEM")
    equal(locations, {
        "Program Files": r"C:\Program Files\FTP Voyager",
        "Help Files": r"C:\Program Files\FTP Voyager",
        "Example Files": r"C:\Program Files\FTP Voyager",
        "MFC Dlls": r"C:\WINDOWS\SYSTEM",
        "OCX Files": r"C:\WINDOWS\SYSTEM",
        "Windows System": r"C:\WINDOWS\SYSTEM",
        "ShellExtDlls": r"C:\WINDOWS\SYSTEM",
        "Application Data": r"C:\Program Files\FTP Voyager",
        "English/Eval": r"C:\Program Files\FTP Voyager",
        "English/Eval/Core": r"C:\Program Files\FTP Voyager",
    })

    locations = module["_installshield5_component_locations"]([
        {"name": "Program Files"},
        {"name": "Program Files/Plug-ins"},
        {"name": "Help Files"},
        {"name": "System Files"},
    ], r"C:\Program Files\Example", r"C:\WINDOWS\SYSTEM", entries = [
        {"name": "app.exe", "size": 10, "directory": "", "components": ["Program Files"]},
        {"name": "form.api", "size": 11, "directory": r"Forms\Scripts", "components": ["Program Files/Plug-ins"]},
        {"name": "manual.pdf", "size": 12, "directory": "ENU", "components": ["Help Files"]},
        {"name": "runtime.dll", "size": 13, "directory": "", "components": ["System Files"]},
    ], media_files = [
        {"path": "/Reader/app.exe", "size": 10},
        {"path": "/Reader/plug_ins/Forms/Scripts/form.api", "size": 11},
        {"path": "/Help/ENU/manual.pdf", "size": 12},
        {"path": "/Reader/runtime.dll", "size": 13},
    ])
    equal(locations, {
        "Program Files": r"C:\Program Files\Example\Reader",
        "Program Files/Plug-ins": r"C:\Program Files\Example\Reader\plug_ins",
        "Help Files": r"C:\Program Files\Example\Help",
        "System Files": r"C:\WINDOWS\SYSTEM",
    })

    action = module["_expanded_custom_action"]({
        "dll": "example.dll",
        "arguments": [0, None, r"Name|2001.01.01|<TARGETDIR>"],
    }, {"<TARGETDIR>": r"C:\Program Files\Example"})
    equal(action["arguments"], [0, None, r"Name|2001.01.01|C:\Program Files\Example"])
    equal(module["_calendar_timestamp"]("1970.01.01"), 12 * 3600)
    equal(module["_calendar_timestamp"]("2000.03.01"), 951912000)
    equal(module["_calendar_timestamp"]("2001.07.05"), 994334400)
    raises(module["_calendar_timestamp"], args = ["2001.02.29"], message = "invalid day")

    equal(module["_installshield5_uninstall_locations"]([
        {"name": "AcroRd32.exe", "components": ["Program Files"]},
        {"name": "Uninst.dll", "components": ["Uninstall DLL"]},
    ], {
        "Program Files": r"C:\Program Files\Example\Reader",
        "Uninstall DLL": r"C:\Program Files\Example",
    }, r"C:\WINDOWS"), {
        "<UNINST>": r"C:\WINDOWS\IsUninst.exe",
        "<UninstPath>": r"C:\Program Files\Example",
    })

    registry = module["_additional_registry_modification"]({
        "root": "HKEY_CURRENT_USER",
        "key": r"Software\Example\<TARGETDIR>",
        "name": "DataDir",
        "value": r"<APPDATA>\Example",
    }, {
        "<TARGETDIR>": "Product",
        "<APPDATA>": r"C:\WINDOWS\Application Data",
    })
    equal(registry, {
        "operation": "registry_set_value",
        "root": "HKEY_CURRENT_USER",
        "key": r"Software\Example\Product",
        "name": "DataDir",
        "type": "REG_SZ",
        "value": r"C:\WINDOWS\Application Data\Example",
    })
    raises(module["_additional_registry_modification"], args = [{
        "root": "HKEY_CLASSES_ROOT",
        "key": "Example",
    }, {}], message = "unsupported additional registry root")

    files = module["_additional_file_entries"]([
        "/Group/b.txt",
        "/Other/c.txt",
        "/Group/a.txt",
    ], {
        "source_prefix": "/Group/",
        "destination_prefix": "<TARGETDIR>\\Data\\",
    }, {"<TARGETDIR>": r"C:\Program Files\Example"})
    equal(files, [
        {"source": "/Group/a.txt", "destination": r"C:\Program Files\Example\Data\a.txt", "resolved": True, "container": False},
        {"source": "/Group/b.txt", "destination": r"C:\Program Files\Example\Data\b.txt", "resolved": True, "container": False},
    ])
    raises(module["_additional_file_entries"], args = [[], {
        "source_prefix": "/Missing/",
        "destination_prefix": "C:\\Missing\\",
    }, {}], message = "matched no package files")

def test_registration_ui_object_handles():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    image_data = windows.pe32_executable(section = b"\xc3", labels = {"entry": 0}, fixups = [])
    image_builder = binary.builder(capacity = len(image_data))
    image_builder.append(image_data)
    image = image_builder.file()
    machine.use([module["gdi32_plugin"](), module["user32_plugin"](image)])
    brush = machine.call(machine.resolve_export("gdi32.dll", name = "CreateSolidBrush"), args = [0x123456])
    equal(brush.value, 0xdb123456)
    logical_palette = machine.allocate(value = b"\x00\x03\x02\x00\x01\x02\x03\x00\x04\x05\x06\x00")
    palette = machine.call(machine.resolve_export("gdi32.dll", name = "CreatePalette"), args = [logical_palette])
    equal(palette.value, 0xda000001)
    equal(machine.call(machine.resolve_export("gdi32.dll", name = "DeleteObject"), args = [palette.value]).value, 1)
    bitmap = machine.call(machine.resolve_export("gdi32.dll", name = "CreateDIBitmap"), args = [0, 0, 0, 0, 0, 0])
    equal(bitmap.value, 0xda100001)
    equal(machine.call(machine.resolve_export("user32.dll", name = "GetActiveWindow")).value, 0)
    equal(machine.call(machine.resolve_export("user32.dll", name = "GetForegroundWindow")).value, 0)
    modeless = machine.call(machine.resolve_export("user32.dll", name = "CreateDialogParamA"), args = [0, 1, 0, 0, 0])
    true(modeless.value != 0)
    equal(machine.call(machine.resolve_export("user32.dll", name = "IsWindow"), args = [modeless.value]).value, 1)
    equal(machine.call(machine.resolve_export("user32.dll", name = "GetActiveWindow")).value, modeless.value)
    equal(machine.call(machine.resolve_export("user32.dll", name = "GetForegroundWindow")).value, modeless.value)
    indirect = machine.call(machine.resolve_export("user32.dll", name = "CreateDialogIndirectParamA"), args = [0, 0x1234, modeless.value, 0, 0])
    true(indirect.value != 0)
    equal(machine.call(machine.resolve_export("user32.dll", name = "GetParent"), args = [indirect.value]).value, modeless.value)
    menu = machine.call(machine.resolve_export("user32.dll", name = "LoadMenuA"), args = [0x400000, 101]).value
    true(menu != 0)
    equal(machine.call(machine.resolve_export("user32.dll", name = "SetMenu"), args = [modeless.value, menu]).value, 1)
    equal(machine.call(machine.resolve_export("user32.dll", name = "GetMenu"), args = [modeless.value]).value, menu)
    equal(machine.call(machine.resolve_export("user32.dll", name = "DrawMenuBar"), args = [modeless.value]).value, 1)
    equal(machine.call(machine.resolve_export("user32.dll", name = "DestroyMenu"), args = [menu]).value, 1)
    accelerators = machine.call(machine.resolve_export("user32.dll", name = "LoadAcceleratorsA"), args = [0x400000, 102]).value
    true(accelerators != 0)
    equal(machine.call(machine.resolve_export("user32.dll", name = "TranslateAcceleratorA"), args = [modeless.value, accelerators, 0]).value, 0)

    delivered = []
    hook_handle = [0]
    def cbt_hook(event):
        equal(event.args[0], 3)
        true(event.args[1] != 0, "CBT hook did not receive the prospective HWND")
        true(event.machine.read_u32le(event.args[2]) != 0, "CBT_CREATEWND did not reference CREATESTRUCT")
        delivered.append("cbt")
        return 0
    hook_procedure = machine.provide_export(cbt_hook, module = "test.window", name = "CbtHook", argc = 3)
    hook_handle[0] = machine.call(machine.resolve_export("user32.dll", name = "SetWindowsHookExA"), args = [5, hook_procedure, 0, 1]).value
    true(hook_handle[0] != 0, "SetWindowsHookEx did not return a hook")
    def window_procedure(event):
        delivered.append(event.args[1])
        return 1
    procedure = machine.provide_export(window_procedure, module = "test.window", name = "WindowProcedure", argc = 4)
    class_name = machine.allocate(value = b"TinyRangeWindow\x00")
    window_class = machine.allocate(size = 40)
    equal(machine.call(machine.resolve_export("user32.dll", name = "GetClassInfoA"), args = [0, class_name, window_class]).value, 0)
    machine.write_u32le(window_class + 4, procedure)
    machine.write_u32le(window_class + 36, class_name)
    atom = machine.call(machine.resolve_export("user32.dll", name = "RegisterClassA"), args = [window_class]).value
    class_info = machine.allocate(size = 40)
    equal(machine.call(machine.resolve_export("user32.dll", name = "GetClassInfoA"), args = [0, class_name, class_info]).value, 1)
    equal(machine.read_u32le(class_info + 4), procedure)
    created_result = machine.call(machine.resolve_export("user32.dll", name = "CreateWindowExA"), args = [0, atom, 0, 0, 0, 0, 100, 100, 0, 0, 0x400000, 0])
    equal(created_result.reason, "return", created_result.detail)
    created = created_result.value
    equal(delivered, ["cbt", 0x81, 0x01])
    true(created != 0, "CreateWindowEx rejected a zero-returning CBT hook")
    equal(machine.call(machine.resolve_export("user32.dll", name = "UnhookWindowsHookEx"), args = [hook_handle[0]]).value, 1)

def test_registration_bitmap_ownership():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    gdi = module["gdi32_plugin"]()
    machine.use([gdi])
    data = machine.allocate(value = b"\xaa\x55\x12\x34")
    bitmap = machine.call(machine.resolve_export("gdi32.dll", name = "CreateBitmap"), args = [9, 2, 1, 1, data]).value
    equal(gdi.state["bitmaps"][bitmap]["stride"], 2)
    brush = machine.call(machine.resolve_export("gdi32.dll", name = "CreatePatternBrush"), args = [bitmap]).value
    machine.write(data, b"\x00" * 4)
    machine.call(machine.resolve_export("gdi32.dll", name = "DeleteObject"), args = [bitmap])
    equal(gdi.state["brushes"][brush]["data"], b"\xaa\x55\x12\x34")
    equal(machine.call(machine.resolve_export("gdi32.dll", name = "CreatePatternBrush"), args = [bitmap]).value, 0)
    equal(machine.call(machine.resolve_export("gdi32.dll", name = "CreateBitmap"), args = [0xffffffff, 1, 1, 1, 0]).value, 0)
    machine.call(machine.resolve_export("gdi32.dll", name = "DeleteObject"), args = [brush])
    true(brush not in gdi.state["brushes"])

def test_registration_compatible_dc_and_typelib_attributes():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    gdi = module["gdi32_plugin"]()
    guid = "{6B7E6392-850A-101B-AFC0-4210102A8DA7}"
    library = {"guid": guid, "lcid": 0, "syskind": 1, "major": 1, "minor": 2, "flags": 8, "types": []}
    automation = module["oleaut_plugin"](registered_type_libraries = [{"path": r"C:\test.ocx", "library": library}])
    machine.use([gdi, automation])
    def call(name, args):
        result = machine.call(machine.resolve_export("gdi32.dll", name = name), args = args)
        equal(result.reason, "return")
        return result.value
    dc = call("CreateCompatibleDC", [0])
    mono = call("CreateCompatibleBitmap", [dc, 9, 2])
    equal(gdi.state["bitmaps"][mono]["depth"], 1)
    color = call("CreateCompatibleBitmap", [0xda00, 9, 2])
    equal(gdi.state["bitmaps"][color]["depth"], 32)
    old = call("SelectObject", [dc, color])
    equal(old, 0xd915)
    compatible = call("CreateCompatibleBitmap", [dc, 2, 2])
    equal(gdi.state["bitmaps"][compatible]["depth"], 32)
    equal(call("SelectObject", [dc, old]), color)
    pen = call("CreatePen", [0, 1, 0x123456])
    equal(gdi.state["pens"][pen]["color"], 0x123456)
    equal(call("DeleteObject", [pen]), 1)
    true(pen not in gdi.state["pens"])
    equal(call("DeleteDC", [dc]), 1)
    equal(call("DeleteDC", [dc]), 0)
    equal(call("CreateCompatibleBitmap", [dc, 1, 1]), 0)
    equal(call("CreateCompatibleDC", [123]), 0)
    identifier = machine.allocate(value = testing.module("@stdlib//windows/selfreg:facts.star")["guid_bytes"](guid))
    output = machine.allocate(size = 4)
    result = machine.call(machine.resolve_export("oleaut32.dll", name = "LoadRegTypeLib"), args = [identifier, 1, 2, 0, output])
    equal((result.reason, result.value), ("return", 0))
    obj = machine.read_u32le(output)
    vtable = machine.read_u32le(obj)
    result = machine.call(machine.read_u32le(vtable + 7 * 4), args = [obj, output])
    equal((result.reason, result.value), ("return", 0))
    attr = machine.read_u32le(output)
    equal(machine.read(attr, 16), testing.module("@stdlib//windows/selfreg:facts.star")["guid_bytes"](guid).bytes())
    equal(machine.read(attr + 16, 16), b"\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x02\x00\x08\x00\x00\x00")




def test_kernel_final_path_owned_handle():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code=b"\xc3", architecture=architecture)
        kernel = module["kernel32_plugin"](files={r"C:\test\sample.txt": b"data"})
        machine.use([kernel])
        source = machine.allocate(value=binary.encode(r"C:\test\sample.txt", encoding="utf16le", nul=True))
        handle = machine.call(machine.resolve_export("kernel32.dll", name="CreateFileW"), args=[source,0,7,0,3,0,0]).value
        target = machine.resolve_export("kernelbase.dll", name="GetFinalPathNameByHandleW")
        expected = binary.encode(r"\\?\c:\test\sample.txt", encoding="utf16le", nul=True)
        required = len(expected)//2
        equal(machine.call(target,args=[handle,0,0,0]).value,required)
        output = machine.allocate(value=b"\xaa"*(len(expected)+4))
        equal(machine.call(target,args=[handle,output,required-1,0]).value,required)
        equal(machine.read(output,len(expected)+4),b"\xaa"*(len(expected)+4))
        equal(machine.call(target,args=[handle,output,required,0]).value,required-1)
        equal(machine.read(output,len(expected)),expected)
        equal(machine.read(output+len(expected),4),b"\xaa"*4)
        machine.call(machine.resolve_export("kernel32.dll",name="CloseHandle"),args=[handle])
        equal(machine.call(target,args=[handle,output,required,0]).value,0)
        equal(kernel.state["last_error"],6)

def test_version_resource_mixed_providers():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    # Leaf lengths exclude sibling alignment padding. Both an intermediate
    # and a final unaligned leaf must remain queryable, without allowing a
    # declared value to extend beyond its node.
    leaf = binary.builder()
    for value in [18, 3, 1]:
        leaf.u16le(value)
    leaf.append(binary.encode("K", encoding = "utf16le", nul = True))
    leaf.u16le(0)
    leaf.append(binary.encode("ab", encoding = "utf16le", nul = True))
    last = binary.builder()
    for value in [18, 3, 1]:
        last.u16le(value)
    last.append(binary.encode("Z", encoding = "utf16le", nul = True))
    last.u16le(0)
    last.append(binary.encode("cd", encoding = "utf16le", nul = True))
    root = binary.builder()
    for value in [78, 0, 0]:
        root.u16le(value)
    root.append(binary.encode("VS_VERSION_INFO", encoding = "utf16le", nul = True))
    root.u16le(0)
    root.append(leaf.bytes())
    root.u16le(0)
    root.append(last.bytes())
    data = root.bytes()
    for key, expected in [("K", "ab"), ("Z", "cd")]:
        node = module["_version_query"](data, key)
        true(node != None)
        equal(binary.text(data[node["value_offset"]:node["value_offset"] + 4], encoding = "utf16le"), expected)
    equal(module["_version_node"](leaf.bytes()[:-1], 0), None)
    block = binary.builder()
    block.u16le(92)
    block.u16le(52)
    block.u16le(0)
    block.append(binary.encode("VS_VERSION_INFO", encoding = "utf16le", nul = True))
    block.u16le(0)
    for value in [0xfeef04bd, 0x10000, 0x000a0000, 0x66000001, 0, 0, 0x3f, 0, 0x40004, 2, 0, 0, 0]:
        block.u32le(value)
    image = windows.pe(binary.view(windows.pe32_executable(section = b"\xc3", labels = {"entry": 0}, fixups = []))).with_resources([
        {"type": "#16", "name": "#1", "lang": "#1033", "data": block.bytes()},
    ])
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code = b"\xc3", architecture = architecture)
        machine.use([module["version_plugin"](image, module_path = "sample.dll")])
        path = machine.allocate(value = binary.encode("sample.dll", encoding = "utf16le", nul = True))
        query = machine.allocate(value = binary.encode("\\", encoding = "utf16le", nul = True))
        data = machine.allocate(size = 92)
        output = machine.allocate(value = b"\xaa" * 16)
        length = machine.allocate(size = 4)
        def call(provider, name, args):
            result = machine.call(machine.resolve_export(provider, name = name), args = args)
            equal(result.reason, "return", result.detail)
            return result.value
        equal(call("version.dll", "GetFileVersionInfoSizeW", [path, 0]), 92)
        equal(call("kernelbase.dll", "GetFileVersionInfoW", [path, 0, 92, data]), 1)
        equal(call("api-ms-win-core-version-l1-1-0.dll", "VerQueryValueW", [data, query, output, length]), 1)
        pointer_size = 8 if architecture == "amd64" else 4
        address = machine.read_u64le(output) if architecture == "amd64" else machine.read_u32le(output)
        equal(address, data + 40)
        equal(machine.read_u32le(address), 0xfeef04bd)
        equal(machine.read_u32le(length), 52)
        equal(machine.read(output + pointer_size, 16 - pointer_size), b"\xaa" * (16 - pointer_size))

def test_registration_named_resource_case():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    image = windows.pe(binary.view(windows.pe32_executable(section = b"\xc3", labels = {"entry": 0}, fixups = []))).with_resources([
        {"type": "#10", "name": "SECURITYHEALTHCORE.DLL", "lang": "#0", "data": b"checked resource bytes"},
    ])
    machine = emulator.x86(image = image)
    machine.use([module["resource_plugin"](image)])
    name = machine.allocate(value = binary.encode("SecurityHealthCore.dll", encoding = "utf16le", nul = True))
    resource = machine.call(machine.resolve_export("kernel32.dll", name = "FindResourceW"), args = [0, name, 10])
    equal(resource.reason, "return")
    true(resource.value != 0)
    size = machine.call(machine.resolve_export("kernel32.dll", name = "SizeofResource"), args = [0, resource.value]).value
    loaded = machine.call(machine.resolve_export("kernel32.dll", name = "LoadResource"), args = [0, resource.value]).value
    address = machine.call(machine.resolve_export("kernel32.dll", name = "LockResource"), args = [loaded]).value
    equal(machine.read(address, size), b"checked resource bytes")
    missing = machine.allocate(value = binary.encode("Absent.dll", encoding = "utf16le", nul = True))
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "FindResourceW"), args = [0, missing, 10]).value, 0)

def test_registration_load_bitmap_resource():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    bitmap = binary.builder()
    for value in [40, 2, 2]:
        bitmap.u32le(value)
    bitmap.u16le(1)
    bitmap.u16le(24)
    for value in [0, 16, 0, 0, 0, 0]:
        bitmap.u32le(value)
    bitmap.append(b"\xaa" * 16)
    image = windows.pe(binary.view(windows.pe32_executable(section = b"\xc3", labels = {"entry": 0}, fixups = []))).with_resources([
        {"type": "#2", "name": "#2004", "lang": "#0", "data": bitmap.bytes()},
    ])
    machine = emulator.x86(image = image)
    gdi = module["gdi32_plugin"]()
    machine.use([module["resource_plugin"](image), gdi, module["user32_plugin"](image)])
    handle = machine.call(machine.resolve_export("user32.dll", name = "LoadBitmapA"), args = [0, 2004])
    equal(handle.reason, "return")
    true(handle.value in gdi.state["bitmaps"])
    record = gdi.state["bitmaps"][handle.value]
    equal(machine.read(record["bits"], 16), b"\xaa" * 16)
    equal(machine.call(machine.resolve_export("user32.dll", name = "LoadBitmapA"), args = [0, 2005]).value, 0)
    equal(machine.call(machine.resolve_export("gdi32.dll", name = "DeleteObject"), args = [handle.value]).value, 1)
    true(handle.value not in gdi.state["bitmaps"])

def test_registration_activation_context_lifetime():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    kernel = module["kernel32_plugin"](files = {r"C:\test.manifest": b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity name="test" version="1.0.0.0" type="win32"/></assembly>'})
    machine.use([kernel])
    context = machine.allocate(size = 32)
    source = machine.allocate(value = binary.encode(r"C:\test.manifest", encoding = "utf16le", nul = True))
    machine.write_u32le(context, 32)
    machine.write_u32le(context + 8, source)
    handle = machine.call(machine.resolve_export("kernel32.dll", name = "CreateActCtxW"), args = [context]).value
    true(handle != 0xffffffff)
    cookie = machine.allocate(size = 4)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "ActivateActCtx"), args = [handle, cookie]).value, 1)
    equal(kernel.state["current_actctx"], handle)
    current = machine.allocate(size = 4)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "GetCurrentActCtx"), args = [current]).value, 1)
    equal(machine.read_u32le(current), handle)
    machine.call(machine.resolve_export("kernel32.dll", name = "ReleaseActCtx"), args = [machine.read_u32le(current)])
    machine.call(machine.resolve_export("kernel32.dll", name = "ReleaseActCtx"), args = [handle])
    true(handle in kernel.state["handles"])
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "DeactivateActCtx"), args = [0, machine.read_u32le(cookie)]).value, 1)
    true(handle not in kernel.state["handles"])
    equal(kernel.state["current_actctx"], 0)
    machine.write_u32le(context, 0)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "CreateActCtxW"), args = [context]).value, 0xffffffff)
    equal(kernel.state["last_error"], 87)

def test_registration_registry_delete_tree():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    registry = module["registry_plugin"](values = [
        {"hive": "SOFTWARE", "key": "/Classes/Test", "name": "value", "type": "REG_SZ", "value": "parent"},
        {"hive": "SOFTWARE", "key": "/Classes/Test/Child", "name": "value", "type": "REG_SZ", "value": "child"},
    ])
    machine = emulator.x86(code = b"\xc3")
    machine.use([registry])
    output = machine.allocate(size = 4)
    name = machine.allocate(value = binary.encode("Test", encoding = "utf16le", nul = True))
    equal(machine.call(machine.resolve_export("advapi32.dll", name = "RegOpenKeyW"), args = [0x80000000, name, output]).value, 0)
    handle = machine.read_u32le(output)
    equal(machine.call(machine.resolve_export("advapi32_vista.dll", name = "RegDeleteTreeW"), args = [handle, 0]).value, 0)
    true(module["_key_exists"](registry.state, ("SOFTWARE", "/Classes/Test")))
    equal(module["_direct_subkeys"](registry.state, ("SOFTWARE", "/Classes/Test")), [])
    equal(module["_direct_values"](registry.state, ("SOFTWARE", "/Classes/Test")), [])
    equal(machine.call(machine.resolve_export("advapi32.dll", name = "RegDeleteTreeW"), args = [0x80000000, name]).value, 0)
    true(not module["_key_exists"](registry.state, ("SOFTWARE", "/Classes/Test")))

def test_registration_reggetvalue_contract():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    registry = module["registry_plugin"](values = [{"hive": "SOFTWARE", "key": "/Classes/Test", "name": "(default)", "type": "REG_EXPAND_SZ", "value": r"%SystemRoot%\test"}], environment = {"SystemRoot": r"C:\ReactOS"})
    machine = emulator.x86(code = b"\xc3")
    machine.use([registry])
    key = machine.allocate(value = binary.encode("Test", encoding = "utf16le", nul = True))
    data = machine.allocate(size = 100)
    size = machine.allocate(size = 4)
    kind = machine.allocate(size = 4)
    function = machine.resolve_export("advapi32.dll", name = "RegGetValueW")
    machine.write_u32le(size, 100)
    result = machine.call(function, args = [0x80000000, key, 0, 2, kind, data, size])
    equal(result.reason, "return", result.detail)
    equal(result.value, 0)
    equal(machine.read_cstring(data, encoding = "utf16le"), r"C:\ReactOS\test")
    equal(machine.read_u32le(kind), 1)
    machine.write_u32le(size, 4)
    machine.write(data, b"xxxx")
    equal(machine.call(function, args = [0x80000000, key, 0, 0x20000002, kind, data, size]).value, 234)
    equal(machine.read(data, 4), b"\x00" * 4)
    true(machine.read_u32le(size) > 4)
    machine.write_u32le(size, 100)
    equal(machine.call(function, args = [0x80000000, key, 0, 0x10000004, kind, data, size]).value, 0)
    equal(machine.read_cstring(data, encoding = "utf16le"), r"%SystemRoot%\test")
    equal(machine.read_u32le(kind), 2)
    equal(machine.call(function, args = [0x80000000, key, 0, 16, kind, 0, 0]).value, 1630)

def test_registration_resource_mapping_skips_initialization():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    calls = []
    def attach(name):
        calls.append(("attach", name))
        return 0x1000000
    def mapping(name):
        calls.append(("map", name))
        return 0x1000000
    kernel = module["kernel32_plugin"](on_module_load = attach, on_module_map = mapping)
    machine = emulator.x86(code = b"\xc3")
    machine.use([kernel])
    name = machine.allocate(value = binary.encode("resource.dll", encoding = "utf16le", nul = True))
    function = machine.resolve_export("kernel32.dll", name = "LoadLibraryExW")
    equal(machine.call(function, args = [name, 0, 2]).value, 0x1000000)
    equal(machine.call(function, args = [name, 0, 2]).value, 0x1000000)
    equal(calls, [("map", "resource.dll")])
    equal(machine.call(function, args = [name, 0, 0]).value, 0x1000000)
    equal(calls, [("map", "resource.dll"), ("attach", "resource.dll")])

def test_registration_debug_prefix_and_va_list():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    kernel = module["kernel32_plugin"]()
    machine = emulator.x86(code = b"\xc3")
    machine.use([kernel])
    prefix = machine.allocate(value = b"registrar: \x00")
    format = machine.allocate(value = b"value=%x\x00")
    arguments = machine.allocate(value = binary.u32le(42))
    result = machine.call(machine.resolve_export("ntdll.dll", name = "vDbgPrintExWithPrefix"), args = [prefix, 0, 0, format, arguments])
    equal(result.reason, "return", result.detail)
    equal(result.value, 0)
    equal(kernel.state["debug_output"], ["registrar: value=2a"])

def test_registration_crt_long_character_search_and_snprintf():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["msvcrt_plugin"]()])
    data = machine.allocate(value = bytes_concat([b"a\x00" * 20000, b"z\x00\x00\x00"]))
    search = machine.resolve_export("msvcrt.dll", name = "wcschr")
    equal(machine.call(search, args = [data, ord("a")]).value, data)
    equal(machine.call(search, args = [data, ord("z")]).value, data + 40000)
    equal(machine.call(search, args = [data, 0]).value, data + 40002)
    # One code unit has no terminator; a forward match must not read beyond it.
    single = machine.allocate(value = b"z\x00")
    equal(machine.call(search, args = [single, ord("z")]).value, single)
    format = machine.allocate(value = b"%s:%u\x00")
    word = machine.allocate(value = b"abc\x00")
    output = machine.allocate(value = b"!!!!!!")
    printf = machine.resolve_export("msvcrt.dll", name = "_snprintf")
    for count, expected, result in [(4, b"abc:!!", 0xffffffff), (5, b"abc:7!", 5), (6, b"abc:7\x00", 5)]:
        machine.write(output, b"!!!!!!")
        call = machine.call(printf, args = [output, count, format, word, 7])
        equal(call.reason, "return", call.detail)
        equal(call.value, result)
        equal(machine.read(output, 6), expected)

def test_lz32_copies_memory_backed_files():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    kernel = module["kernel32_plugin"](files = {r"C:\source.bin": b"test-value"})
    lz = module["lz32_plugin"](kernel)
    machine.use([kernel, lz])
    source_name = machine.allocate(value = b"C:\\source.bin\x00")
    target_name = machine.allocate(value = b"C:\\target.bin\x00")
    source = machine.call(machine.resolve_export("lz32.dll", name = "LZOpenFileA"), args = [source_name, 0, 0]).value
    target = machine.call(machine.resolve_export("lz32.dll", name = "LZOpenFileA"), args = [target_name, 0, 0x1000]).value
    true(source != 0xffffffff)
    true(target != 0xffffffff)
    true(source != target)
    equal(kernel.state["handles"][source]["value"]["offset"], 0)
    equal(kernel.state["handles"][source]["value"]["path"], r"c:\source.bin")
    equal(kernel.state["handles"][target]["value"]["path"], r"c:\target.bin")
    equal(kernel.state["file_data"](kernel.state["handles"][source]["value"]["path"]), b"test-value")
    copied = machine.call(machine.resolve_export("lz32.dll", name = "LZCopy"), args = [source, target]).value
    equal(lz.state["calls"][-1]["api"], "lzcopy")
    equal(lz.state["calls"][-1]["arguments"], [source, target])
    equal(kernel.state["file_data"](r"c:\target.bin"), b"test-value")
    equal(copied, 10)
    equal(kernel.state["file_data"](r"c:\source.bin"), kernel.state["file_data"](r"c:\target.bin"))
    equal(machine.call(machine.resolve_export("lz32.dll", name = "LZClose"), args = [source]).value, 0)

def test_kernel_dos_file_time_round_trip():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["kernel32_plugin"]()])
    file_time = machine.allocate(size = 8)
    date_output = machine.allocate(size = 2)
    time_output = machine.allocate(size = 2)
    date = ((2001 - 1980) << 9) | (7 << 5) | 5
    time = (13 << 11) | (4 << 5) | (6 // 2)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "DosDateTimeToFileTime"), args = [date, time, file_time]).value, 1)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "FileTimeToDosDateTime"), args = [file_time, date_output, time_output]).value, 1)
    equal(machine.read_u16le(date_output), date)
    equal(machine.read_u16le(time_output), time)

def test_netapi_reports_join_information_with_owned_buffer():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    network = module["netapi_plugin"](domain = "EXAMPLE")
    machine.use([network])
    name_output = machine.allocate(size = 4)
    status_output = machine.allocate(size = 4)
    query = machine.resolve_export("netapi32.dll", name = "NetGetJoinInformation")
    equal(machine.call(query, args = [0, name_output, status_output]).value, 0)
    name = machine.read_u32le(name_output)
    equal(machine.read_cstring(name, encoding = "utf16le"), "EXAMPLE")
    equal(machine.read_u32le(status_output), 3)
    equal(machine.call(machine.resolve_export("netapi32.dll", name = "NetApiBufferFree"), args = [name]).value, 0)
    equal(network.state["allocations"], {})

def test_kernel_file_information_reports_memory_backed_size():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    kernel = module["kernel32_plugin"](files = {r"C:\payload.bin": b"test-value"}, volumes = {"C:": {"serial": 0x12345678}})
    machine.use([kernel])
    path = machine.allocate(value = binary.encode(r"C:\payload.bin", encoding = "utf16le", nul = True))
    handle = machine.call(machine.resolve_export("kernel32.dll", name = "CreateFileW"), args = [path, 0, 0, 0, 3, 0, 0]).value
    information = machine.allocate(size = 52)
    equal(machine.call(machine.resolve_export("kernel32.dll", name = "GetFileInformationByHandle"), args = [handle, information]).value, 1)
    equal(machine.read_u32le(information), 0x80)
    equal(machine.read_u32le(information + 28), 0x12345678)
    equal(machine.read_u32le(information + 32), 0)
    equal(machine.read_u32le(information + 36), 10)
    equal(machine.read_u32le(information + 40), 1)

def test_secure_wide_tokenizer_matches_native_utf16_contexts():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    # Independent target msvcrt.dll wcstok_s (63960) captures, including the
    # end-pointer context and non-BMP UTF-16 offsets. No host tokenization oracle.
    captures = [
        ("2000200061002c002c0062003b000000", "20002c003b000000", [(4,8),(10,14),(None,14),(None,14)], "20002000610000002c00620000000000"),
        ("6100620063000000", "0000", [(0,6),(None,6),(None,6)], "6100620063000000"),
        ("0000", "2c000000", [(None,0),(None,0)], "0000"),
        ("2c002c002c000000", "2c000000", [(None,6),(None,6)], "2c002c002c000000"),
        ("3dd800de2c00b2030000", "2c000000", [(0,6),(6,8),(None,8)], "3dd800de0000b2030000"),
    ]
    for architecture in ["x86","amd64"]:
        for raw_hex,delim_hex,expected,final_hex in captures:
            machine=emulator.machine(code=b"\xc3",architecture=architecture)
            crt=module["msvcrt_plugin"]()
            machine.use(crt)
            raw=binary.decode(raw_hex,"hex")
            delimiters=binary.decode(delim_hex,"hex")
            source=machine.allocate(value=binary.concat([raw,b"GUARDEND"]).bytes())
            delim=machine.allocate(value=binary.concat([delimiters,b"DELIMEND"]).bytes())
            output=machine.allocate(value=b"ZZZZZZZZZZZZZZZZZZZZZZZZ")
            context=output+8
            machine.write_pointer(context,0)
            function=machine.resolve_export("msvcrt.dll",name="wcstok_s")
            actual=[]
            for index in range(len(expected)):
                result=machine.call(function,args=[source if index==0 else 0,delim,context])
                equal(result.reason,"return",result.detail)
                actual.append((result.value-source if result.value else None,machine.read_pointer(context)-source))
            equal(actual,expected)
            equal(machine.read(source,len(raw)),binary.decode(final_hex,"hex"))
            equal(machine.read(source+len(raw),8),b"GUARDEND")
            equal(machine.read(delim,len(delimiters)+8),binary.concat([delimiters,b"DELIMEND"]).bytes())
            equal(machine.read(output,8),b"ZZZZZZZZ")
            equal(machine.read(context+machine.pointer_size,16-machine.pointer_size),b"Z"*(16-machine.pointer_size))
            equal(crt.state.get("errno",{}),{})


def test_secure_wide_tokenizer_contexts_do_not_alias_and_invalid_handler_stops():
    module=testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86","amd64"]:
        machine=emulator.machine(code=b"\xc3",architecture=architecture)
        crt=module["msvcrt_plugin"]()
        machine.use(crt)
        function=machine.resolve_export("msvcrt.dll",name="wcstok_s")
        def wide(text):
            return machine.allocate(value=binary.encode(text,encoding="utf16le",nul=True))
        a,b=wide("one,two;three"),wide("α|β")
        ca,cb=machine.allocate(size=machine.pointer_size),machine.allocate(size=machine.pointer_size)
        comma,semi,pipe=wide(","),wide(";"),wide("|")
        for source,delim,context,wanted in [(a,comma,ca,a),(b,pipe,cb,b),(0,semi,ca,a+8),(0,pipe,cb,b+4),(0,semi,ca,a+16)]:
            result=machine.call(function,args=[source,delim,context])
            equal(result.reason,"return",result.detail)
            equal(result.value,wanted)
        equal(machine.read_pointer(cb),b+6)
        equal(machine.read_pointer(ca),a+26)
        c=wide("replacement")
        equal(machine.call(function,args=[c,comma,ca]).value,c)
        equal(machine.read_pointer(ca),c+22)
        equal(crt.state["wcstok_next"],0)
        for invalid in ["context","delimiter","input"]:
            machine=emulator.machine(code=b"\xc3",architecture=architecture)
            crt=module["msvcrt_plugin"]()
            machine.use(crt)
            raw=binary.encode("a,b",encoding="utf16le",nul=True)
            source=machine.allocate(value=raw)
            delim=machine.allocate(value=binary.encode(",",encoding="utf16le",nul=True))
            context=machine.allocate(size=machine.pointer_size)
            result=machine.call(machine.resolve_export("msvcrt.dll",name="wcstok_s"),args=[0 if invalid=="input" else source,0 if invalid=="delimiter" else delim,0 if invalid=="context" else context])
            equal(result.reason,"CRT wcstok_s invalid-parameter handler is not modeled")
            equal(machine.read(source,len(raw)),raw)
            equal(machine.read_pointer(context),0)
            equal(machine.read_u32le(crt.state["errno"].values()[0]),22)


def test_legacy_wcsicmp_null_arguments_match_native():
    # Windows 26300.9457 AMD64 MSVCRT: _wcsicmp RVA 60a00, errno 7f10.
    # Native default handler captured context, looked up genuine .pdata,
    # ran native RtlVirtualUnwind, emitted a diagnostic, and returned normally.
    module=testing.module("@stdlib//windows/selfreg:win32.star")
    machine=emulator.machine(code=b"\xc3",architecture="amd64")
    kernel=module["kernel32_plugin"]()
    crt=module["msvcrt_plugin"](kernel=kernel)
    machine.use([kernel,crt])
    compare=machine.resolve_export("msvcrt.dll",name="_wcsicmp")
    errno=machine.call(machine.resolve_export("msvcrt.dll",name="_errno")).value
    raw=b"\x00\x00GUARDEND"
    empty=machine.allocate(value=raw)
    for args in [[empty,0],[0,empty],[0,0],[0x1234,0],[0,0x1234]]:
        machine.write_u32le(errno,123)
        result=machine.call(compare,args=args)
        equal(result.reason,"return",result.detail)
        equal(result.value,0x7fffffff)
        equal(machine.read_u32le(errno),22)
        equal(machine.read(empty,len(raw)),raw)
    equal(len(crt.state["actions"]),5)
    left=machine.allocate(value=binary.encode("BaTTeRy",encoding="utf16le",nul=True))
    right=machine.allocate(value=binary.encode("battery",encoding="utf16le",nul=True))
    machine.write_u32le(errno,123)
    equal(machine.call(compare,args=[left,right]).value,0)
    equal(machine.read_u32le(errno),123)
    # Do not silently apply the legacy contract to a UCRT/API-set export.
    def modern_callback(event):
        return module["_crt_legacy_wcsicmp_invalid"](event,errno)
    modern=machine.provide_export(modern_callback,module="ucrtbase.dll",name="_wcsicmp",argc=2)
    result=machine.call(machine.resolve_export("ucrtbase.dll",name="_wcsicmp"),args=[empty,0])
    equal(result.reason,"CRT _wcsicmp invalid-parameter handler is not modeled for this runtime")


def test_kernel_large_readonly_file_mapping_is_budgeted_and_lazy():
    module=testing.module("@stdlib//windows/selfreg:win32.star")
    size=(17<<20)+8
    source=binary.concat([b"HEAD",b"x"*(17<<20),b"TAIL"])
    for architecture in ["x86","amd64"]:
        for budget in [4<<20,32<<20]:
            machine=emulator.machine(code=b"\xc3",architecture=architecture,memory_limit=budget)
            kernel=module["kernel32_plugin"](files={"C:/large.bin":source})
            machine.use(kernel)
            path=machine.allocate(value=binary.encode("C:/large.bin",encoding="utf16le",nul=True))
            def call(name,args):
                result=machine.call(machine.resolve_export("kernel32.dll",name=name),args=args)
                equal(result.reason,"return",result.detail)
                return result.value
            opened=call("CreateFileW",[path,0x80000000,7,0,3,0,0])
            mapping=call("CreateFileMappingW",[opened,0,2,0,0,0])
            true(mapping!=0)
            entry=kernel.state["paths"]["c:"+chr(92)+"large.bin"]
            true("data" not in entry,"mapping creation materialized source")
            # A small EOF range succeeds even when the whole source exceeds
            # the guest memory budget, and never reads unrelated source bytes.
            tail=call("MapViewOfFile",[mapping,4,0,17<<20,8])
            equal(machine.read(tail,8),b"xxxxTAIL")
            true("data" not in entry)
            equal(call("UnmapViewOfFile",[tail]),1)
            equal(call("MapViewOfFile",[mapping,2,0,0,4]),0)
            equal(kernel.state["last_error"],5)
            equal(call("MapViewOfFile",[mapping,4,0,size-2,3]),0)
            equal(kernel.state["last_error"],87)
            result=machine.call(machine.resolve_export("kernel32.dll",name="MapViewOfFile"),args=[mapping,4,0,0,0])
            if budget==4<<20:
                true(result.reason!="return", "over-budget map fabricated an OS result")
                equal(len(kernel.state["views"]),0)
                true("data" not in entry)
            else:
                equal(result.reason,"return",result.detail)
                view=result.value
                true(view!=0)
                equal(machine.read(view,4),b"HEAD")
                equal(machine.read(view+size-4,4),b"TAIL")
                equal(machine.read(view+(1<<20)-1,3),b"xxx")
                true("data" not in entry)
                equal(call("UnmapViewOfFile",[view]),1)
                true(not entry.get("dirty",False))
            equal(call("CloseHandle",[mapping]),1)
            equal(call("CloseHandle",[opened]),1)



def test_registry_backup_restore_effective_token_access():
    registry_module = testing.module("@stdlib//windows/selfreg:registry.star")
    win32 = testing.module("@stdlib//windows/selfreg:win32.star")
    abi = testing.module("@stdlib//windows/emulation:abi.star")
    for architecture in ["x86", "amd64"]:
        machine = emulator.machine(code=b"\xc3",architecture=architecture)
        security = win32["security_plugin"](token_privileges={17:0,18:0})
        registry = registry_module["registry_plugin"](keys=[dict(hive="SYSTEM",key="/BackupProbe")],effective_token_privileges=security.effective_privileges)
        machine.use([security,registry])
        width=machine.pointer_size
        strings=abi["counted_string_layout"](width)
        objects=abi["object_attributes_layout"](width)
        raw=binary.encode(r"\Registry\Machine\SYSTEM\BackupProbe",encoding="utf16le")
        text=machine.allocate(value=raw)
        name=machine.allocate(size=strings["Size"])
        machine.write_u16le(name,len(raw))
        machine.write_u16le(name+2,len(raw))
        machine.write_pointer(name+strings["Buffer"],text)
        attrs=machine.allocate(size=objects["Size"])
        machine.write_u32le(attrs,objects["Size"])
        machine.write_pointer(attrs+objects["ObjectName"],name)
        output=machine.allocate(value=b"Z"*(width+4))
        disposition=machine.allocate(value=b"Z"*8)
        data=machine.allocate(value=b"abcd")
        value_name=machine.allocate(size=strings["Size"])
        high=0x600000000000 if width==8 else 0
        def call(api,args):
            result=machine.call(machine.resolve_export("ntdll.dll",name=api),args=args)
            equal(result.reason,"return")
            return result.value
        # Deliberately request full access; backup must not grant write/delete.
        for privileges,expected in [({17:0,18:0},0),({17:1,18:1},0),({17:2},0x1020019),({18:2},0x1030006),({17:3,18:2},0x103001f)]:
            security.state["process_token"]["privileges"]=privileges
            for api in ["NtOpenKeyEx","NtCreateKey"]:
                machine.write(output,b"Z"*(width+4))
                machine.write(disposition,b"Z"*8)
                before=dict(registry.state["handles"])
                args=[output,0xf003f,attrs,high|12] if api=="NtOpenKeyEx" else [output,0xf003f,attrs,0,0,high|4,disposition]
                status=call(api,args)
                equal(status,0 if expected else 0xc0000022)
                if not expected:
                    equal(machine.read(output,width+4),b"Z"*(width+4))
                    equal(machine.read(disposition,8),b"Z"*8)
                    equal(registry.state["handles"],before)
                    continue
                handle=machine.read_pointer(output)
                equal(registry.state["handle_access"][handle],expected)
                equal(machine.read(output+width,4),b"ZZZZ")
                if api=="NtCreateKey":
                    equal(machine.read_u32le(disposition),2)
                    equal(machine.read(disposition+4,4),b"ZZZZ")
                equal(call("NtSetValueKey",[handle,value_name,0,3,data,4]),0 if expected&2 else 0xc0000022)
                if not expected&0x10000: equal(call("NtDeleteKey",[handle]),0xc0000022)
        # A thread token replaces (never unions with) process privileges.
        security.state["process_token"]["privileges"]={17:2,18:2}
        for level,privileges,expected in [(2,{},0),(1,{17:2,18:2},0),(2,{17:2},0x1020019),(3,{18:2},0x1030006)]:
            security.state["thread_tokens"][8]=dict(type=2,impersonation_level=level,privileges=privileges)
            equal(call("NtOpenKeyEx",[output,0,attrs,4]),0 if expected else 0xc0000022)
            if expected: equal(registry.state["handle_access"][machine.read_pointer(output)],expected)
        security.state["thread_tokens"].clear()
        equal(call("NtOpenKeyEx",[output,0,attrs,4]),0)
        equal(registry.state["handle_access"][machine.read_pointer(output)],0x103001f)
        # A transaction view keeps the same dynamic token query, not a snapshot.
        child=registry._fork(0x20000)
        def child_open(event): return child._dispatch(event, "ntopenkeyex")
        child_address=machine.provide_export(child_open,module="probe",name="OpenChild",argc=4)
        security.state["process_token"]["privileges"]={}
        denied=machine.call(child_address,args=[output,0,attrs,4])
        equal(denied.reason,"return")
        equal(denied.value,0xc0000022)
        security.state["process_token"]["privileges"]={17:2}
        allowed=machine.call(child_address,args=[output,0,attrs,4])
        equal(allowed.reason,"return")
        equal(allowed.value,0)
        equal(child.state["handle_access"][machine.read_pointer(output)],0x1020019)
        # Unknown key creation remains fail-closed before any mutation.
        missing=binary.encode(r"\Registry\Machine\SYSTEM\MissingBackupKey",encoding="utf16le")
        pointer=machine.allocate(value=missing)
        machine.write_u16le(name,len(missing))
        machine.write_u16le(name+2,len(missing))
        machine.write_pointer(name+strings["Buffer"],pointer)
        security.state["process_token"]["privileges"]={18:2}
        before=registry.effects()
        denied=machine.call(machine.resolve_export("ntdll.dll",name="NtCreateKey"),args=[output,0,attrs,0,0,4,disposition])
        equal(denied.reason,"plugin")
        true("creation security" in denied.detail)
        equal(registry.effects(),before)

TEST_SUITE = suite("stdlib/internal", [
    case("kernel_large_readonly_mapping", test_kernel_large_readonly_file_mapping_is_budgeted_and_lazy),
    case("crt_legacy_wcsicmp_null", test_legacy_wcsicmp_null_arguments_match_native),
    case("crt_secure_wide_tokenizer", test_secure_wide_tokenizer_matches_native_utf16_contexts),
    case("crt_secure_wide_tokenizer_contexts", test_secure_wide_tokenizer_contexts_do_not_alias_and_invalid_handler_stops),
    case("registry_initial_assignment_modes", test_registry_initial_assignment_modes),
    case("gdb_integer_codecs", test_gdb_integer_codecs),
    case("resource_patch_normalization", test_resource_patch_normalization),
    case("registration_execution_preserves_static_server_path", test_registration_execution_preserves_static_server_path),
    case("partial_class_registration_accepts_only_completed_hkcr_writes", test_partial_class_registration_accepts_only_completed_hkcr_writes),
    case("registration_result_conventions", test_registration_result_conventions),
    case("incomplete_structured_class_registration_is_detected", test_incomplete_structured_class_registration_is_detected),
    case("recursive_registry_deletion", test_recursive_registry_deletion),
    case("registry_value_deletion", test_registry_value_deletion),
    case("registry_multi_string_decode", test_registry_multi_string_decode),
    case("registry_qword_round_trip", test_registry_qword_round_trip),
    case("registry_key_information", test_registry_key_information),
    case("registry_native_enumerate_full_value_information", test_registry_native_enumerate_full_value_information),
    case("registry_key_name_cache_tracks_mutation_and_source_reload", test_registry_key_name_cache_tracks_mutation_and_source_reload),
    case("registry_deleted_ancestor_boundaries", test_registry_deleted_ancestor_boundaries),
    case("registry_cached_information_after_many_source_deletions", test_registry_cached_information_after_many_source_deletions),
    case("registry_native_cached_key_information", test_registry_native_cached_key_information),
    case("registry_native_set_value_effects", test_registry_native_set_value_effects),
    case("registry_native_partial_value_query", test_registry_native_partial_value_query),
    case("registry_native_enumerate_long_key_buffer", test_registry_native_enumerate_long_key_buffer),
    case("registry_native_delete_key_lifetime", test_registry_native_delete_key_lifetime),
    case("registry_creation_security_provider", test_registry_creation_security_provider),
    case("registry_win32_delete_key_ex_lifetime", test_registry_win32_delete_key_ex_lifetime),
    case("registry_native_object_pointer_width", test_registry_native_object_pointer_width),
    case("registry_backup_restore_effective_token_access", test_registry_backup_restore_effective_token_access),
    case("registry_plugin_publishes_late_bound_exports", test_registry_plugin_publishes_late_bound_exports),
    case("registry_set_key_value_uses_existing_subkey_and_win64_dwords", test_registry_set_key_value_uses_existing_subkey_and_win64_dwords),
    case("registry_provider_recognizes_api_set_contracts", test_registry_provider_recognizes_api_set_contracts),
    case("registry_plugin_reads_source_hives_lazily", test_registry_plugin_reads_source_hives_lazily),
    case("registry_native_literal_absolute", test_registry_native_absolute_names_keep_literal_slashes),
    case("registry_structured_key_parts_preserve_literal_slashes", test_registry_structured_key_parts_preserve_literal_slashes),
    case("registry_initial_keys_are_baseline_state", test_registry_initial_keys_are_baseline_state),
    case("registry_predefined_root_override_redirects_operations", test_registry_predefined_root_override_redirects_operations),
    case("registry_can_emit_folded_key_spelling", test_registry_can_emit_folded_key_spelling),
    case("registry_system_root_routing", test_registry_system_root_routing),
    case("automation_type_library_resource_paths", test_automation_type_library_resource_paths),
    case("advanced_inf_command_and_registry_adapters", test_advanced_inf_command_and_registry_adapters),
    case("acme_setup_table_adapters", test_acme_setup_table_adapters),
    case("registered_type_library_resolution", test_registered_type_library_resolution),
    case("setupapi_inf_lines", test_setupapi_inf_lines),
    case("kernel_synchronization_signatures", test_kernel_synchronization_signatures),
    case("crt_eh_prolog_frame", test_crt_eh_prolog_frame),
    case("kernel_overlapped_file_io_uses_explicit_offsets", test_kernel_overlapped_file_io_uses_explicit_offsets),
    case("kernel_legacy_profile_and_file_metadata", test_kernel_legacy_profile_and_file_metadata),
    case("kernel_file_mappings_observe_file_writes", test_kernel_file_mappings_observe_file_writes),
    case("crt_bounded_string_comparison", test_crt_bounded_string_comparison),
    case("crt_bounded_memory_comparison", test_crt_bounded_memory_comparison),
    case("crt_wide_case_conversion", test_crt_wide_case_conversion),
    case("crt_ui64_wide_formatting", test_crt_ui64_wide_formatting),
    case("crt_wide_floating_conversion", test_crt_wide_floating_conversion),
    case("crt_scanf_floating_point", test_crt_scanf_floating_point),
    case("crt_errno_is_stable_and_writable", test_crt_errno_is_stable_and_writable),
    case("crt_imported_mode_data_matches_accessors", test_crt_imported_mode_data_matches_accessors),
    case("security_native_descriptor_control", test_security_native_descriptor_control_preserves_native_write_order),
    case("security_native_owned_tokens", test_security_native_duplicate_and_adjust_preserve_token_ownership),
    case("security_impersonate_self", test_security_impersonate_self_clones_only_owned_primary_token),
    case("crt_private_memory_contract", test_crt_private_memory_contract_preserves_abi_and_overlap),
    case("crt_api_set_contracts", test_crt_api_set_contracts),
    case("query_actctx_basic_bounds", test_query_actctx_basic_bounds),
    case("fixed_timezone_and_secure_wide_crt", test_fixed_timezone_and_secure_wide_crt),
    case("rpc_pointer_outputs_and_release", test_rpc_pointer_outputs_and_release),
    case("crt_unsigned_char_locale_initialization", test_crt_unsigned_char_locale_initialization),
    case("kernel_budget_threads_remain_runnable", test_kernel_budget_threads_remain_runnable),
    case("kernel_immediate_timer_and_thread_priority", test_kernel_immediate_timer_and_thread_priority),
    case("kernel_threadpool_timer_lifecycle", test_kernel_threadpool_timer_lifecycle),
    case("kernel_amd64_thread_and_module_handle_width", test_kernel_amd64_thread_and_module_handle_width),
    case("kernel_create_process_information_pointer_width", test_kernel_create_process_information_pointer_width),
    case("kernel_named_semaphore_open", test_kernel_named_semaphore_open),
    case("shell32_create_directory_ex_records_recursive_memory_directories", test_shell32_create_directory_ex_records_recursive_memory_directories),
    case("kernel_provider_recognizes_api_set_contracts", test_kernel_provider_recognizes_api_set_contracts),
    case("kernel_open_process_tracks_current_process", test_kernel_open_process_tracks_current_process),
    case("kernel_reports_consistent_default_language", test_kernel_reports_consistent_default_language),
    case("kernel_validates_supported_code_pages", test_kernel_validates_supported_code_pages),
    case("kernel_initializes_x86_slist_header", test_kernel_initializes_x86_slist_header),
    case("kernel_reports_deterministic_current_thread_times", test_kernel_reports_deterministic_current_thread_times),
    case("kernel_tls_apis_share_the_x86_teb_array", test_kernel_tls_apis_share_the_x86_teb_array),
    case("kernel_short_path_preserves_components_without_aliases", test_kernel_short_path_preserves_components_without_aliases),
    case("kernel_current_directory_resolves_relative_file_paths", test_kernel_current_directory_resolves_relative_file_paths),
    case("shlwapi_provider_recognizes_api_set_contracts", test_shlwapi_provider_recognizes_api_set_contracts),
    case("kernel_init_once_begin_complete_matches_native_states", test_kernel_init_once_begin_complete_matches_native_states),
    case("kernel_init_once_execute_retry_and_private_context", test_kernel_init_once_execute_retry_and_private_context),
    case("kernel_init_once_executes_callback_once_and_preserves_context", test_kernel_init_once_executes_callback_once_and_preserves_context),
    case("kernel_resolves_rva_delay_imports", test_kernel_resolves_rva_delay_imports),
    case("ole_com_contract_aliases_share_state", test_ole_com_contract_aliases_share_state),
    case("advpack_string_table_pointer_width", test_advpack_string_table_pointer_width),
    case("shlwapi_ansi_to_unicode_ordinal", test_shlwapi_ansi_to_unicode_ordinal),
    case("shell32_special_folder_location_round_trip", test_shell32_special_folder_location_round_trip),
    case("oleaut_variant_time_by_value_abi", test_oleaut_variant_time_by_value_abi),
    case("shell32_known_folder_path_uses_process_environment", test_shell32_known_folder_path_uses_process_environment),
    case("userenv_profile_and_environment_block_contracts", test_userenv_profile_and_environment_block_contracts),
    case("shell32_command_line_to_argv_uses_local_allocation", test_shell32_command_line_to_argv_uses_local_allocation),
    case("winsock_helper_signatures", test_winsock_helper_signatures),
    case("wer_process_registrations_are_reversible", test_wer_process_registrations_are_reversible),
    case("appmodel_reports_unpacked_desktop_process", test_appmodel_reports_unpacked_desktop_process),
    case("rpc_runtime_signatures", test_rpc_runtime_signatures),
    case("kernel_virtual_file_entries", test_kernel_virtual_file_entries),
    case("profile_section_parser", test_profile_section_parser),
    case("event_log_provider_recognizes_api_set_contracts", test_event_log_provider_recognizes_api_set_contracts),
    case("event_log_exports_support_late_loaded_modules", test_event_log_exports_support_late_loaded_modules),
    case("cabinet_callback_stream_and_native_notifications", test_cabinet_callback_stream_and_native_notifications),
    case("kernel_explicit_file_write_bound", test_kernel_explicit_file_write_bound),
    case("security_reports_required_sid_length", test_security_reports_required_sid_length),
    case("security_native_allow_ace_ex_contract", test_security_native_allow_ace_ex_contract),
    case("security_native_descriptor_validation", test_security_native_descriptor_validation),
    case("security_native_absolute_to_self_relative", test_security_native_absolute_to_self_relative),
    case("create_service_default_account", test_create_service_default_account),
    case("service_dispatcher_pointer_width", test_service_dispatcher_pointer_width),
    case("automation_registration_signatures", test_automation_registration_signatures),
    case("com_target_invocation_continues_budget", test_com_target_invocation_continues_budget),
    case("virtual_protect_restores_image_execution", test_virtual_protect_restores_image_execution),
    case("virtual_alloc_commits_reserved_subrange", test_virtual_alloc_commits_reserved_subrange),
    case("kernel_tls_api_shares_teb_slots", test_kernel_tls_api_shares_teb_slots),
    case("virtual_alloc_reserves_released_fixed_address", test_virtual_alloc_reserves_released_fixed_address),
    case("kernel_non_debugged_process_introspection", test_kernel_non_debugged_process_introspection),
    case("kernel_system_query_provider_preserves_target_status_contract", test_kernel_system_query_provider_preserves_target_status_contract),
    case("kernel_thread_page_priority_and_process_termination", test_kernel_thread_page_priority_and_process_termination),
    case("kernel_critical_section_blocks_other_execution_and_is_recursive", test_kernel_critical_section_blocks_other_execution_and_is_recursive),
    case("rtl_relative_nt_path_status", test_rtl_relative_nt_path_status_and_buffer_ownership),
    case("cryptoapi_delay_contract", test_cryptoapi_delay_contract_shares_owned_contexts),
    case("cryptoapi_verification_context_lifecycle", test_cryptoapi_verification_context_lifecycle),
    case("security_adjusts_only_owned_privileges", test_security_adjusts_only_owned_privileges),
    case("security_token_object_lifetime", test_security_token_object_lifetime),
    case("nt_open_process_owned_query_handle", test_nt_open_process_owned_query_handle),
    case("security_access_mapping", test_security_access_mapping),
    case("sddl_security_descriptor", test_sddl_security_descriptor),
    case("mandatory_label_ace", test_mandatory_label_ace),
    case("win32_dynamic_format_width", test_win32_dynamic_format_width),
    case("user32_wsprintf_reads_all_variadic_arguments", test_user32_wsprintf_reads_all_variadic_arguments),
    case("binary_floating_point_codecs", test_binary_floating_point_codecs),
    case("binary_xml_round_trip", test_binary_xml_round_trip),
    case("com_guid_string_pointer_width", test_com_guid_string_uses_pointer_sized_output),
    case("win32_tracked_reallocate", test_win32_tracked_reallocate),
    case("binary_hex", test_binary_hex),
    case("installshield5_conventional_component_locations", test_installshield5_conventional_component_locations),
    case("registration_ui_object_handles", test_registration_ui_object_handles),
    case("registration_bitmap_ownership", test_registration_bitmap_ownership),
    case("registration_compatible_dc_and_typelib_attributes", test_registration_compatible_dc_and_typelib_attributes),
    case("kernel_final_path_owned_handle", test_kernel_final_path_owned_handle),
    case("version_resource_mixed_providers", test_version_resource_mixed_providers),
    case("registration_named_resource_case", test_registration_named_resource_case),
    case("registration_load_bitmap_resource", test_registration_load_bitmap_resource),
    case("registration_activation_context_lifetime", test_registration_activation_context_lifetime),
    case("registration_registry_delete_tree", test_registration_registry_delete_tree),
    case("registration_reggetvalue_contract", test_registration_reggetvalue_contract),
    case("registration_resource_mapping_skips_initialization", test_registration_resource_mapping_skips_initialization),
    case("registration_debug_prefix_and_va_list", test_registration_debug_prefix_and_va_list),
    case("registration_crt_long_character_search_and_snprintf", test_registration_crt_long_character_search_and_snprintf),
    case("lz32_copies_memory_backed_files", test_lz32_copies_memory_backed_files),
    case("kernel_dos_file_time_round_trip", test_kernel_dos_file_time_round_trip),
    case("netapi_reports_join_information_with_owned_buffer", test_netapi_reports_join_information_with_owned_buffer),
    case("kernel_file_information_reports_memory_backed_size", test_kernel_file_information_reports_memory_backed_size),
    case("compare_string_amd64_int_lengths", test_compare_string_amd64_int_lengths),
    case("kernel_integer_to_char_native_boundaries", test_kernel_integer_to_char_native_boundaries),
    case("cabinet_non_cabinet_copy_reports_fdi_error", test_cabinet_non_cabinet_copy_reports_fdi_error),
    case("kernel_exclusive_srw_native_alias_contention", test_kernel_exclusive_srw_native_alias_contention),
    case("profile_string_native_dword_capacity", test_profile_string_native_dword_capacity),
    case("crt_toupper_ascii_int_width", test_crt_toupper_ascii_int_width),
    case("catalog_hash_native_sizing_and_file_handle", test_catalog_hash_native_sizing_and_file_handle),
    case("kernel_hard_link_identity_and_lifetime", test_kernel_hard_link_identity_and_lifetime),
    case("kernel_delete_on_close_open_object_lifetime", test_kernel_delete_on_close_open_object_lifetime),
    case("kernel_hard_link_mappings_and_clone", test_kernel_hard_link_mappings_and_clone),
    case("kernel_copy_file_ex_effects_and_failure_atomicity", test_kernel_copy_file_ex_effects_and_failure_atomicity),
    case("kernel_dos_device_name_native_boundaries", test_kernel_dos_device_name_native_boundaries),
    case("kernel_ansi_char_native_pointer_advance", test_kernel_ansi_char_native_pointer_advance),
    case("kernel_upcase_unicode_char_parameter_width", test_kernel_upcase_unicode_char_parameter_width),
    case("kernel_find_failure_handle_native_width", test_kernel_find_failure_handle_native_width),
    case("kernel_child_process_exit_code_and_handle_lifetime", test_kernel_child_process_exit_code_and_handle_lifetime),
    case("kernel_redirection_trust_policy", test_kernel_redirection_trust_policy),
    case("kernel_mutex_handle_independence", test_kernel_mutex_handle_independence),
    case("kernel_guid_from_counted_string_native_effects", test_kernel_guid_from_counted_string_native_effects),
    case("crt_integer_end_pointer_native_width", test_crt_integer_end_pointer_native_width),
    case("kernel_file_mapping_native_dword_widths", test_kernel_file_mapping_native_dword_widths),
    case("kernel_compare_string_ordinal_units", test_kernel_compare_string_ordinal_units),
    case("kernel_duplicate_unicode_string_native_contract", test_kernel_duplicate_unicode_string_native_contract),
    case("kernel_prefix_counted_unicode_strings", test_kernel_prefix_counted_unicode_strings),
    case("kernel_equal_counted_unicode_strings", test_kernel_equal_counted_unicode_strings),
    case("kernel_create_unicode_string_owned_buffer", test_kernel_create_unicode_string_owned_buffer),
    case("kernel_multiple_wait_native_width", test_kernel_multiple_wait_native_width),
    case("kernel_ldr_load_dll_native_pointer_width", test_kernel_ldr_load_dll_native_pointer_width),
    case("kernel_system_windows_directory_capacity", test_kernel_system_windows_directory_capacity),
    case("kernel_unicode_string_ex_native_boundaries", test_kernel_unicode_string_ex_native_boundaries),
    case("device_family_info_optional_outputs", test_device_family_info_optional_outputs),
    case("crt_bsearch_calls_target_comparator", test_crt_bsearch_calls_target_comparator),
    case("crt_wcspbrk_returns_first_matching_unit", test_crt_wcspbrk_returns_first_matching_unit),
    case("crt_secure_memory_copy_checks_capacity", test_crt_secure_memory_copy_checks_capacity),
])

