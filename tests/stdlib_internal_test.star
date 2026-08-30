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

def test_registry_plugin_publishes_late_bound_exports():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["registry_plugin"]()])
    true(machine.resolve_export("advapi32.dll", name = "RegEnumValueW") != 0)
    true(machine.resolve_export("kernel32.dll", name = "RegOpenKeyExW") != 0)
    true(machine.resolve_export("ntdll.dll", name = "NtEnumerateKey") != 0)
    true(machine.resolve_export("shlwapi.dll", name = "SHRegGetValueW") != 0)
    true(machine.resolve_export("shlwapi.dll", ordinal = 128) != 0)

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

def test_registry_initial_keys_are_baseline_state():
    module = testing.module("@stdlib//windows/selfreg:registry.star")
    registry = module["registry_plugin"](keys = [{
        "hive": "SOFTWARE",
        "key": "/Microsoft/Setup/Empty",
    }])
    equal(registry.keys(), [])
    equal(registry.state["flushes"], [])

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
    atom_name = machine.allocate(value = b"TinyRangeX\x00")
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

def test_event_log_exports_support_late_loaded_modules():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    provider = module["event_log_plugin"]()
    machine.use([provider])
    handle_pointer = machine.allocate(8)
    register = machine.resolve_export("advapi32.dll", name = "RegisterTraceGuidsW")
    unregister = machine.resolve_export("advapi32.dll", name = "UnregisterTraceGuids")
    true(register != 0)
    true(unregister != 0)
    equal(machine.call(register, args = [0, 0, 0, 0, 0, 0, 0, handle_pointer]).value, 0)
    handle = machine.read_u64le(handle_pointer)
    true(handle != 0)
    equal(machine.call(unregister, args = [handle & 0xffffffff, handle >> 32]).value, 0)
    equal(provider.state["trace_providers"], {})

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
    ]:
        target = machine.resolve_export("kernel32.dll", name = name)
        equal(machine.call(target).value, 0x0409)

def test_kernel_resolves_rva_delay_imports():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    target = machine.provide_export(lambda unused: 42, module = "sample.dll", name = "Answer", argc = 0)
    kernel = module["kernel32_plugin"]()
    machine.use([kernel])

    image = machine.allocate(size = 256, alignment = 256, name = "delay import image")
    descriptor = image + 0x20
    module_slot = image + 0x50
    iat = image + 0x60
    names = image + 0x70
    dll_name = image + 0x80
    import_name = image + 0xa0
    machine.write_u32le(descriptor, 1)
    machine.write_u32le(descriptor + 4, dll_name - image)
    machine.write_u32le(descriptor + 8, module_slot - image)
    machine.write_u32le(descriptor + 12, iat - image)
    machine.write_u32le(descriptor + 16, names - image)
    machine.write_u32le(names, import_name - image)
    machine.write(dll_name, b"sample.dll\x00")
    machine.write(import_name, b"\x00\x00Answer\x00")

    resolver = machine.resolve_export("kernel32.dll", name = "ResolveDelayLoadedAPI")
    result = machine.call(resolver, args = [image, descriptor, 0, 0, iat, 0])
    equal(result.value, target)
    equal(machine.read_u32le(iat), target)
    sample_base = [loaded.base for loaded in machine.modules if loaded.name == "sample.dll"][0]
    equal(machine.read_u32le(module_slot), sample_base)
    equal(kernel.state["procedure_queries"][-1], {"module": "sample.dll", "procedure": "Answer", "found": True})
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
    roundtrip_source = machine.allocate(value = binary.encode("My Documents", encoding = "utf16le", nul = True))
    roundtrip_destination = machine.allocate(size = 32)
    roundtrip_address = machine.resolve_export("shlwapi.dll", ordinal = 365)
    true(roundtrip_address != 0)
    roundtrip = machine.call(roundtrip_address, args = [roundtrip_source, roundtrip_destination, 32])
    equal((roundtrip.reason, roundtrip.value, machine.read_cstring(roundtrip_destination)), ("return", 1, "My Documents"))

def test_shell32_special_folder_location_round_trip():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    machine.use([module["shell32_plugin"]("C:\\WINDOWS\\SYSTEM\\shell32.dll")])
    output = machine.allocate(size = 4)
    located = machine.call(machine.resolve_export("shell32.dll", name = "SHGetSpecialFolderLocation"), args = [0, 0x1a, output])
    equal((located.reason, located.value), ("return", 0))
    pidl = machine.read_u32le(output)
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

def test_winsock_helper_signatures():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    signatures = module["_WS2HELP_SIGNATURES"]
    equal(signatures["wahcreatehandlecontexttable"], 1)
    equal(signatures["wahdestroyhandlecontexttable"], 1)
    equal(signatures["wahopenapchelper"], 1)
    equal(signatures["wahcloseapchelper"], 1)
    equal(signatures["wahopencurrentthread"], 2)
    equal(signatures["wahclosethread"], 1)
    equal(module["_WINSOCK_ORDINAL_SIGNATURES"], {8: 1, 9: 1, 14: 1, 15: 1, 111: 0, 112: 1, 114: 0, 115: 2, 116: 0})
    machine = emulator.x86(code = b"\xc3")
    winsock = module["winsock_plugin"]()
    machine.use([winsock])
    data = machine.allocate(size = 400)
    startup = machine.call(machine.resolve_export("wsock32.dll", ordinal = 115), args = [0x0101, data])
    equal((startup.reason, startup.value, machine.read_u16le(data), machine.read_u16le(data + 2)), ("return", 0, 0x0101, 0x0101))
    equal(machine.call(machine.resolve_export("wsock32.dll", ordinal = 112), args = [10061]).value, 0)
    equal(machine.call(machine.resolve_export("wsock32.dll", ordinal = 111)).value, 10061)
    equal(machine.call(machine.resolve_export("wsock32.dll", ordinal = 116)).value, 0)

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
    service = module["service_manager_plugin"](registry)
    machine.use([service])
    true(machine.resolve_export("advapi32.dll", name = "OpenSCManagerW") != 0)
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

def test_security_access_mapping():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    true(module["_security_provider_module"]("advapi32.dll"))
    true(module["_security_provider_module"]("api-ms-win-security-sddl-l1-1-0.dll"))
    true(module["_security_provider_module"]("EXT-MS-WIN-SECURITY-BASE-L1-1-0.DLL"))
    true(not module["_security_provider_module"]("api-ms-win-core-file-l1-1-0.dll"))
    mapping = [0x0001, 0x0002, 0x0004, 0x0008]
    equal(module["_map_generic_access"](0x80000010, mapping), 0x0011)
    equal(module["_map_generic_access"](0xf0000000, mapping), 0x000f)
    equal(module["_map_generic_access"](0x02000000, mapping), 0x02000000)
    security = module["security_plugin"]()
    equal(security.name, "windows.security")

def test_sddl_security_descriptor():
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
    modeless = machine.call(machine.resolve_export("user32.dll", name = "CreateDialogParamA"), args = [0, 1, 0, 0, 0])
    true(modeless.value != 0)
    equal(machine.call(machine.resolve_export("user32.dll", name = "IsWindow"), args = [modeless.value]).value, 1)
    equal(machine.call(machine.resolve_export("user32.dll", name = "GetActiveWindow")).value, modeless.value)
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

def test_lz32_copies_memory_backed_files():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    machine = emulator.x86(code = b"\xc3")
    kernel = module["kernel32_plugin"](files = {r"C:\source.bin": b"TinyRangeX"})
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
    equal(kernel.state["file_data"](kernel.state["handles"][source]["value"]["path"]), b"TinyRangeX")
    copied = machine.call(machine.resolve_export("lz32.dll", name = "LZCopy"), args = [source, target]).value
    equal(lz.state["calls"][-1]["api"], "lzcopy")
    equal(lz.state["calls"][-1]["arguments"], [source, target])
    equal(kernel.state["file_data"](r"c:\target.bin"), b"TinyRangeX")
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

TEST_SUITE = suite("stdlib/internal", [
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
    case("registry_plugin_publishes_late_bound_exports", test_registry_plugin_publishes_late_bound_exports),
    case("registry_provider_recognizes_api_set_contracts", test_registry_provider_recognizes_api_set_contracts),
    case("registry_plugin_reads_source_hives_lazily", test_registry_plugin_reads_source_hives_lazily),
    case("registry_structured_key_parts_preserve_literal_slashes", test_registry_structured_key_parts_preserve_literal_slashes),
    case("registry_initial_keys_are_baseline_state", test_registry_initial_keys_are_baseline_state),
    case("registry_can_emit_folded_key_spelling", test_registry_can_emit_folded_key_spelling),
    case("registry_system_root_routing", test_registry_system_root_routing),
    case("automation_type_library_resource_paths", test_automation_type_library_resource_paths),
    case("advanced_inf_command_and_registry_adapters", test_advanced_inf_command_and_registry_adapters),
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
    case("kernel_budget_threads_remain_runnable", test_kernel_budget_threads_remain_runnable),
    case("kernel_immediate_timer_and_thread_priority", test_kernel_immediate_timer_and_thread_priority),
    case("kernel_provider_recognizes_api_set_contracts", test_kernel_provider_recognizes_api_set_contracts),
    case("kernel_open_process_tracks_current_process", test_kernel_open_process_tracks_current_process),
    case("kernel_reports_consistent_default_language", test_kernel_reports_consistent_default_language),
    case("kernel_resolves_rva_delay_imports", test_kernel_resolves_rva_delay_imports),
    case("shlwapi_ansi_to_unicode_ordinal", test_shlwapi_ansi_to_unicode_ordinal),
    case("shell32_special_folder_location_round_trip", test_shell32_special_folder_location_round_trip),
    case("oleaut_variant_time_by_value_abi", test_oleaut_variant_time_by_value_abi),
    case("winsock_helper_signatures", test_winsock_helper_signatures),
    case("rpc_runtime_signatures", test_rpc_runtime_signatures),
    case("kernel_virtual_file_entries", test_kernel_virtual_file_entries),
    case("profile_section_parser", test_profile_section_parser),
    case("event_log_provider_recognizes_api_set_contracts", test_event_log_provider_recognizes_api_set_contracts),
    case("create_service_default_account", test_create_service_default_account),
    case("automation_registration_signatures", test_automation_registration_signatures),
    case("com_target_invocation_continues_budget", test_com_target_invocation_continues_budget),
    case("virtual_protect_restores_image_execution", test_virtual_protect_restores_image_execution),
    case("kernel_non_debugged_process_introspection", test_kernel_non_debugged_process_introspection),
    case("kernel_system_query_provider_preserves_target_status_contract", test_kernel_system_query_provider_preserves_target_status_contract),
    case("kernel_thread_page_priority_and_process_termination", test_kernel_thread_page_priority_and_process_termination),
    case("kernel_critical_section_blocks_other_execution_and_is_recursive", test_kernel_critical_section_blocks_other_execution_and_is_recursive),
    case("cryptoapi_verification_context_lifecycle", test_cryptoapi_verification_context_lifecycle),
    case("security_access_mapping", test_security_access_mapping),
    case("sddl_security_descriptor", test_sddl_security_descriptor),
    case("win32_dynamic_format_width", test_win32_dynamic_format_width),
    case("user32_wsprintf_reads_all_variadic_arguments", test_user32_wsprintf_reads_all_variadic_arguments),
    case("binary_floating_point_codecs", test_binary_floating_point_codecs),
    case("binary_xml_round_trip", test_binary_xml_round_trip),
    case("win32_tracked_reallocate", test_win32_tracked_reallocate),
    case("binary_hex", test_binary_hex),
    case("installshield5_conventional_component_locations", test_installshield5_conventional_component_locations),
    case("registration_ui_object_handles", test_registration_ui_object_handles),
    case("lz32_copies_memory_backed_files", test_lz32_copies_memory_backed_files),
    case("kernel_dos_file_time_round_trip", test_kernel_dos_file_time_round_trip),
])
