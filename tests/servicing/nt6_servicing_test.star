"""Regression checks for complete metadata closure before CBS admission."""

load("//tests:testing.star", "case", "equal", "raises", "run", "suite")

policy = testing.module("@stdlib//windows/servicing:population.star")
close_metadata = policy["_close_servicing_metadata"]

_SUFFIX = "~31bf3856ad364e35~amd64~~10.0.1.0"

def _identity(name):
    return '<assemblyIdentity name="%s" version="10.0.1.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/>' % name

def _manifest(name, body = ""):
    return '<assembly xmlns="urn:schemas-microsoft-com:asm.v3">%s<package>%s</package></assembly>' % (_identity(name), body)

def _fixtures():
    files = directory()
    files.write("/Root", _manifest("Root", '<update name="root-child"><package contained="false">%s</package></update>' % _identity("Child")))
    files.write("/Child", _manifest("Child", '<parent>%s</parent><update name="next"><package>%s</package></update>' % (_identity("OtherEdition"), _identity("Leaf"))))
    # A cycle must terminate. An unavailable reference must remain explicit.
    files.write("/Leaf", _manifest("Leaf", '<update name="cycle"><package>%s</package></update><update name="missing"><package>%s</package></update>' % (_identity("Root"), _identity("Unavailable"))))
    available = {(n + _SUFFIX).lower(): [(n + _SUFFIX, "update", "/" + n)] for n in ["Root", "Child", "Leaf"]}
    def open_entry(name, catalog, path):
        return files.find(path)
    return files, available, open_entry


def test_stage_does_not_admit_superseded_family():
    plan = policy["plan_servicing_population"]
    prefix = "/Microsoft/Windows/CurrentVersion/Component Based Servicing/"
    def name(package, version):
        return package + "~31bf3856ad364e35~amd64~~" + version
    def identity(package, version):
        return '<assemblyIdentity name="%s" version="%s" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/>' % (package, version)
    old = name("Root", "10.0.1.0")
    new = name("Root", "10.0.2.0")
    leaf = name("OldLeaf", "10.0.1.0")
    stable = name("Stable", "10.0.1.0")
    files = directory()
    manifest_files = {}
    for n, child in [(old, "OldLeaf"), (new, "Stable"), (leaf, None), (stable, None)]:
        package, version = n.split("~")[0], n.split("~")[-1]
        body = '<update name="child"><package>%s</package></update>' % identity(child, "10.0.1.0") if child else ""
        files.write("/" + n, '<assembly xmlns="urn:schemas-microsoft-com:asm.v3">%s<package identifier="test" releaseType="Update">%s</package></assembly>' % (identity(package, version), body))
        manifest_files[n] = files.find("/" + n)
    patches = [dict(key=prefix+k, name="fixture", type="REG_DWORD", value=0) for k in ["Packages", "PackageDetect", "UpdateDetect", "PackageIndex", "CapabilityIndex"]]
    for n in [old, leaf, stable]:
        patches.append(dict(key=prefix+"Packages/"+n, name="CurrentState", type="REG_DWORD", value=112))
    patches.append(dict(key=prefix+"Packages/"+leaf+"/Owners", name=old, type="REG_DWORD", value=(2<<16)|112))
    software = windows.hive(windows.hive_from_patches("SOFTWARE", patches))
    components = windows.hive_from_patches("COMPONENTS", [dict(key=k, name="fixture", type="REG_DWORD", value=0) for k in ["/CanonicalData/Deployments", "/DerivedData/Components"]])
    closure = dict(files=manifest_files, xmls={n:binary.xml(f).root for n,f in manifest_files.items()}, software=software, roots=[new])
    for phase in ["stage", "prestage"]:
        staged = plan(None, "", closure, hives={"COMPONENTS":components}, phase=phase)
        executions = {e.package:e for e in staged.executions}
        equal(sorted(executions), sorted([new, stable]))
        equal(executions[new].intended_state, 64)
        # Existing package references remain admitted: only supersedence
        # recursion is suppressed, not all old/installed package identities.
        equal(executions[stable].owners[0].owner, new)
    installed = plan(None, "", closure, hives={"COMPONENTS":components})
    executions = {e.package:e for e in installed.executions}
    equal(sorted(executions), sorted([old, new, leaf, stable]))
    equal(executions[new].intended_state, 112)
    equal(software.find(prefix+"Packages/"+old).values["CurrentState"], 112)
    phases = testing.module("@stdlib//windows/servicing:plan.star")["plan_package_phases"]
    prepared = phases(None, "", closure, hives={"COMPONENTS":components})
    equal(prepared["closure"]["catalog_hint_packages"], [new, stable])
    equal(prepared["closure"]["xmls"], None)
    equal(len(closure["xmls"]), 4)
    equal("catalog_hint_packages" in closure, False)
    equal(sorted(closure["files"]), sorted([old, new, leaf, stable]))
    equal({e.package:e.intended_state for e in prepared["population"].executions},
          {e.package:e.intended_state for e in installed.executions})



def test_reinstall_selects_highest_superseded_predecessor():
    prefix = "/Microsoft/Windows/CurrentVersion/Component Based Servicing/"
    def name(package, version):
        return package + "~31bf3856ad364e35~amd64~~" + version
    def identity(package, version):
        return '<assemblyIdentity name="%s" version="%s" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/>' % (package, version)
    old = name("Root", "10.0.1.0")
    new = name("Root", "10.0.2.0")
    leaf = name("Leaf", "10.0.3.0")
    high = name("Leaf", "10.0.2.0")
    low = name("Leaf", "10.0.1.0")
    files = directory()
    manifests = {}
    # Deliberately enumerate the greatest predecessor before the lesser one.
    for n in [old, new, leaf, high, low]:
        body = '<update name="leaf"><package>%s</package></update>' % identity("Leaf", "10.0.3.0") if n == old else ""
        files.write("/" + n, '<assembly xmlns="urn:schemas-microsoft-com:asm.v3">%s<package identifier="test" releaseType="Update">%s</package></assembly>' % (identity(n.split("~")[0], n.split("~")[-1]), body))
        manifests[n] = files.find("/" + n)
    patches = [dict(key=prefix+k, name="fixture", type="REG_DWORD", value=0) for k in ["Packages", "PackageDetect", "UpdateDetect", "PackageIndex", "CapabilityIndex"]]
    for n, state in [(old,112),(leaf,112),(high,80),(low,80)]:
        patches.append(dict(key=prefix+"Packages/"+n, name="CurrentState", type="REG_DWORD", value=state))
    patches.append(dict(key=prefix+"Packages/"+leaf+"/Owners", name=old, type="REG_DWORD", value=(2<<16)|112))
    software = windows.hive(windows.hive_from_patches("SOFTWARE", patches))
    components = windows.hive_from_patches("COMPONENTS", [dict(key=k, name="fixture", type="REG_DWORD", value=0) for k in ["/CanonicalData/Deployments", "/DerivedData/Components"]])
    closure = dict(files=manifests, xmls={n:binary.xml(f).root for n,f in manifests.items()}, software=software, roots=[new])
    result = policy["plan_servicing_population"](None, "", closure, hives={"COMPONENTS":components})
    executions = {e.package:e for e in result.executions}
    equal(high in executions, True)
    equal(low in executions, False)
    equal(executions[high].intended_state, 112)
    equal(executions[high].owners, [])
    equal(software.find(prefix+"Packages/"+high).values["CurrentState"], 80)

def test_capability_reference_versions():
    version_filter = policy["_capability_version_filter"]
    matches = policy["_capability_version_matches"]
    equal(version_filter(dict(name="XPS.Viewer", version="1.0")), 65536)
    for identity in [dict(name="XPS.Viewer"), dict(name="XPS.Viewer", version="0.0")]:
        equal(matches(version_filter(identity), "0.0.1.0"), True)
    selected = version_filter(dict(name="XPS.Viewer", version="1.0"))
    equal(matches(selected, "0.0.1.0"), True)
    equal(matches(selected, "4.7.1.0"), True)
    equal(matches(selected, "0.0.2.0"), False)
    equal(matches(selected, "0.0.1.1"), False)
    raises(matches, args=[selected, "1.0"], message="version")
    for value in ["1", "1.0.0.0", "-1.0", "65536.0", "1."]:
        raises(version_filter, args=[dict(name="XPS.Viewer", version=value)], message="version")
    raises(version_filter, args=[dict(name="XPS.Viewer", language="en-US")], message="language")

def test_complete_closure_not_payload_selection():
    files, available, open_entry = _fixtures()
    result = close_metadata([], ["Root" + _SUFFIX], available, open_entry, 3)
    equal(sorted(result["files"]), ["Child" + _SUFFIX, "Leaf" + _SUFFIX, "Root" + _SUFFIX])
    equal(result["missing"], {"Unavailable" + _SUFFIX: [("Leaf" + _SUFFIX, "missing")]})
    equal(result["origins"], {n + _SUFFIX: "update" for n in ["Root", "Child", "Leaf"]})
    # The closure includes both the contained=false child and its descendant,
    # even though its edition parent is absent. Neither means "install it".
    raises(close_metadata, args = [[], ["Root" + _SUFFIX], available, open_entry, 2], message = "limit")
    raises(close_metadata, args = [[], ["Unknown" + _SUFFIX], available, open_entry, 3], message = "unavailable")

def test_identity_and_duplicate_provenance():
    files, available, open_entry = _fixtures()
    files.write("/Alias", _manifest("Root", '<update name="root-child"><package contained="false">%s</package></update>' % _identity("Child")))
    available[("Root" + _SUFFIX).lower()].append(("Root" + _SUFFIX, None, "/Alias"))
    equal(len(close_metadata([], ["Root" + _SUFFIX], available, open_entry, 3)["files"]), 3)
    files.write("/Alias", _manifest("Root", "<different/>"))
    raises(close_metadata, args = [[], ["Root" + _SUFFIX], available, open_entry, 3], message = "conflicting")
    files, available, open_entry = _fixtures()
    files.write("/Child", _manifest("Different"))
    raises(close_metadata, args = [[], ["Root" + _SUFFIX], available, open_entry, 3], message = "identity mismatch")

def test_batched_closure_order_and_provenance():
    files, available, open_entry = _fixtures()
    calls = []
    def batch(entries):
        calls.append([entry[0] for entry in entries])
        return [open_entry(*entry) for entry in entries]
    # More than one batch of registered roots, each leading to the same cycle.
    registered = []
    for i in range(260):
        name = "Seed" + str(i)
        files.write("/" + name, _manifest(name, '<update name="child"><package>%s</package></update>' % _identity("Root")))
        available[(name + _SUFFIX).lower()] = [(name + _SUFFIX, None, "/" + name)]
        registered.append(name + _SUFFIX)
    serial = close_metadata(registered, ["Root"+_SUFFIX], available, open_entry, 263)
    batched = close_metadata(registered, ["Root"+_SUFFIX], available, open_entry, 263, open_entries=batch)
    for key in ["origins", "missing", "roots"]: equal(batched[key], serial[key])
    equal(list(batched["files"]), list(serial["files"]))
    for name in serial["files"]:
        equal(batched["files"][name].bytes(), serial["files"][name].bytes())
        equal(batched["xmls"][name].attribute_map(), serial["xmls"][name].attribute_map())
    equal([len(call) for call in calls], [256, 5, 1, 1])
    raises(close_metadata, args=[registered, ["Root"+_SUFFIX], available, open_entry, 262], kwargs=dict(open_entries=batch), message="limit")
    files.write("/Alias", _manifest("Root", "<different/>"))
    available[("Root"+_SUFFIX).lower()].append(("Root"+_SUFFIX, None, "/Alias"))
    raises(close_metadata, args=[registered, ["Root"+_SUFFIX], available, open_entry, 263], kwargs=dict(open_entries=batch), message="conflicting")
    available[("Root"+_SUFFIX).lower()].pop()
    files.write("/Child", _manifest("Different"))
    raises(close_metadata, args=[registered, ["Root"+_SUFFIX], available, open_entry, 263], kwargs=dict(open_entries=batch), message="identity mismatch")

def _runtime_files(body, architecture = "amd64"):
    files = directory()
    files.write("/manifest", '<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="sample" processorArchitecture="%s"/>%s</assembly>' % (architecture, body))
    return {"transitions": [dict(identity = "sample", before = None, after = files.find("/manifest"))]}

def test_native_runtime_file_paths():
    analyze = testing.module("@stdlib//windows/servicing:runtime.star")["analyze_servicing_file_paths"]
    # Real manifest spelling is writeableType, not writableType. Its loss
    # would incorrectly classify a mutable destination as a shared hardlink.
    fixture = _runtime_files('<file name="dssec.dat" destinationPath="$(Runtime.System32)\\" writeableType="systemData"/><file name="source.dll" destinationName="renamed.dll"/><file xmlns="foreign" name="ignored"/>', "wow64")
    result = analyze(fixture, "amd64")
    equal(result["writable_files"], 1)
    equal(result["directory_ids"], {41: 1})
    equal(len(result["records"]), 2)
    equal(result["records"][0]["writable_type"], "systemData")
    equal(result["records"][0]["attributes"], 0xa0)
    equal(windows.csi_file_attributes("hidden system readOnly"), 7)
    equal(windows.csi_file_attributes(""), 0)
    raises(windows.csi_file_attributes, args = ["normal"])
    equal(result["records"][0]["suffix"], "\\")
    equal(result["records"][1]["directory_id"], None)
    equal(result["records"][1]["destination_name"], "renamed.dll")
    fixture["transitions"][0]["before"] = fixture["transitions"][0]["after"]
    equal(analyze(fixture, "amd64")["writable_files"], 2)

def test_runtime_manifest_snapshot_binding():
    policy = testing.module("@stdlib//windows/servicing:runtime.star")
    fixture = _runtime_files('<file name="first.dll"/>')
    change = fixture["transitions"][0]
    original = change["after"]
    snapshot = binary.xml(original).root
    change["documents"] = {"after": (original, snapshot)}
    equal(policy["_runtime_manifest_root"](change, "after"), snapshot)
    replacement = _runtime_files('<file name="replacement.dll"/>')["transitions"][0]["after"]
    change["after"] = replacement
    result = policy["analyze_servicing_file_paths"](fixture, "amd64")
    equal([r["name"] for r in result["records"]], ["replacement.dll"])


def test_runtime_path_policy_fails_closed():
    analyze = testing.module("@stdlib//windows/servicing:runtime.star")["analyze_servicing_file_paths"]
    for path in ["$(runtime.unknown)", "$(runtime.system32)file", "$(runtime.system32)\\$(other)", "C:\\Windows"]:
        fixture = _runtime_files('<file name="file" destinationPath="%s"/>' % path)
        raises(analyze, args = [fixture, "amd64"])
    raises(analyze, args = [_runtime_files('<file name="file" writeableType="unsupported"/>'), "amd64"], message = "writeableType")
    raises(analyze, args = [_runtime_files('<file name="file" destinationPath="$(runtime.system32)"/>', "arm64"), "amd64"], message = "architecture")


def test_offline_image_path_mapping():
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    context = runtime["offline_servicing_path_context"]("X:\\Windows", "/Windows")
    map_path = runtime["map_servicing_offline_path"]
    expand = runtime["expand_servicing_environment_path"]
    equal(map_path(context, "x:\\Program Files\\Common Files\\"), "/Program Files/Common Files")
    equal(map_path(context, expand(context, "%sYsTeMdRiVe%\\Users\\Default")), "/Users/Default")
    equal(map_path(context, expand(context, "%windir%\\System32")), "/Windows/System32")
    equal(map_path(context, expand(context, "%SystemRoot%\\Fonts")), "/Windows/Fonts")
    other = runtime["offline_servicing_path_context"]("D:\\WinNT", "/image/WinNT")
    equal(map_path(other, "D:\\Users\\CustomDefault"), "/image/Users/CustomDefault")
    equal(map_path(other, "D:\\"), "/image/")
    # Another disk must not silently become part of the selected image.
    raises(map_path, args = [context, "D:\\Windows\\file"], message = "unmapped")
    raises(runtime["offline_servicing_path_context"], args = ["X:\\WinNT", "/Windows"], message = "differs")
    raises(runtime["offline_servicing_path_context"], args = ["X:\\Parent\\Windows", "/Parent/Windows"], message = "one-component")
    for value in ["C:relative", "\\\\server\\share", "\\??\\X:\\Windows", "X:\\Windows\\..\\outside", "X:\\Windows\\.\\file", "X:\\Windows\\file:stream", "X:/Windows/file", "X:\\Windows\\file.", "X:\\Windows\\file ", "X:\\Windows\\\\file", "X:\\Windows\\file\x00", "X:\\Windows\\file\n"]:
        raises(map_path, args = [context, value])
    for value in ["%USERPROFILE%\\file", "%UNKNOWN%", "%SystemRoot", "%%\\file"]:
        raises(expand, args = [context, value])


def test_offline_registry_path_roots():
    resolve = testing.module("@stdlib//windows/servicing:runtime.star")["servicing_registry_path_roots"]
    patches = []
    for key, values in {
        "Microsoft/Windows NT/CurrentVersion": {"SystemRoot": "R:\\WinNT"},
        "Microsoft/Windows/CurrentVersion": {"ProgramFilesDir": "R:\\Apps", "ProgramFilesDir (x86)": "R:\\Apps32", "CommonFilesDir": "R:\\Shared", "CommonFilesDir (x86)": "R:\\Shared32"},
        "Microsoft/Windows NT/CurrentVersion/ProfileList": {"Default": "%SystemDrive%\\Profiles\\Template", "ProgramData": "%SystemDrive%\\Data", "ProfilesDirectory": "%SystemDrive%\\Homes", "Public": "Q:\\NotTheNativeSource"},
    }.items():
        for name, value in values.items():
            patches.append(dict(key = "/" + key, name = name, type = "REG_EXPAND_SZ" if "%" in value else "REG_SZ", value = value))
    def hive():
        return windows.hive(windows.hive_from_patches("SOFTWARE", patches))
    result = resolve(hive(), "/WinNT")
    equal(result["roots"], {36: "/WinNT", 38: "/Apps", 42: "/Apps32", 43: "/Shared", 44: "/Shared32", 0x110000: "/Profiles/Template", 0xd0000: "/Data", 0x3e: "/Homes", 0x100000: "/"})
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    roots = runtime["servicing_file_path_roots"](hive(), "/WinNT", "amd64")
    # The all-users Start Menu and no-SID Default profile are distinct roots.
    equal(roots["roots"][11], "/Data/Microsoft/Windows/Start Menu")
    equal(roots["roots"][0x110000], "/Profiles/Template")
    equal(roots["roots"][0x3e], "/Homes")
    equal(roots["roots"][0xc0000], "/Homes/Public")
    equal(roots["roots"][0xb0000], "/WinNT/AppPatch")
    equal(roots["roots"][0x50000], "/WinNT/System")
    equal(roots["roots"][7], "/Data/Microsoft/Windows/Start Menu/Programs/Startup")
    equal(roots["roots"][0x100000], "/")
    fixture = _runtime_files('<file name="source.dat" destinationName="mutable.dat" destinationPath="$(runtime.system32)\\config\" writeableType="systemData"/>', "wow64")
    declarations = runtime["analyze_servicing_file_paths"](fixture, "amd64")
    projected = runtime["resolve_servicing_file_paths"](declarations, roots)["records"]
    equal(projected[0]["destination"], "/WinNT/SysWOW64/config/mutable.dat")
    equal(projected[0]["writable_type"], "systemData")
    equal("destination" in declarations["records"][0], False)
    absent = runtime["analyze_servicing_file_paths"](_runtime_files('<file name="file"/>'), "amd64")
    absent_result = runtime["resolve_servicing_file_paths"](absent, roots)
    equal(absent_result["records"], [])
    equal(absent_result["unresolved"], absent["records"])
    equal(absent_result["unprojected"], [])
    absent["records"][0]["component_identity"] = b"sample, Culture=neutral, Version=1.0.0.0, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"
    ordinary = runtime["resolve_servicing_file_paths"](absent, roots)
    equal(ordinary["unresolved"], [])
    equal(ordinary["unprojected"], absent["records"])
    # Ordinary native transactions force dual-mode drivers to source-only,
    # rather than inventing runtime projection from their destination metadata.
    absent["records"][0]["component_identity"] = bytes(str(absent["records"][0]["component_identity"]) + ", type=dualModeDriver")
    driver = runtime["resolve_servicing_file_paths"](absent, roots)
    equal(driver["unprojected"], absent["records"])
    equal(driver["unresolved"], [])
    for body in ['<file name="file" destinationPath="$(runtime.system32)\\..\\outside"/>', '<file name="file" destinationName="" destinationPath="$(runtime.system32)"/>', '<file name="file" destinationName="dir\\file" destinationPath="$(runtime.system32)"/>']:
        declarations = runtime["analyze_servicing_file_paths"](_runtime_files(body), "amd64")
        raises(runtime["resolve_servicing_file_paths"], args = [declarations, roots])
    raises(runtime["servicing_file_path_roots"], args = [hive(), "/WinNT", "arm64"], message = "architecture")
    # A profile on another volume needs a separate, explicit mapping.
    patches.append(dict(key = "/Microsoft/Windows NT/CurrentVersion/ProfileList", name = "Default", type = "REG_SZ", value = "Q:\\Profiles\\Template"))
    raises(resolve, args = [hive(), "/WinNT"], message = "unmapped")
    raises(resolve, args = [windows.hive(windows.hive_from_patches("SOFTWARE", [])), "/Windows"], message = "missing")


def test_extra_runtime_link_paths():
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    analyze = runtime["analyze_servicing_file_paths"]
    resolve = runtime["resolve_servicing_file_paths"]
    context = runtime["offline_servicing_path_context"]("X:\\Windows", "/Windows")
    roots = dict(context = context, source_roots = {37: "X:\\Windows\\System32", 41: "X:\\Windows\\SysWOW64", 36: "X:\\Windows"})
    fixture = _runtime_files('<file name="loader.efi" destinationPath="$(runtime.system32)\\"><link destination="$(runtime.system32)\\Boot\\renamed.efi"/><link destination="$(runtime.windows)\\Alternate\\loader.efi"/><link xmlns="foreign" destination="ignored"/></file>', "wow64")
    paths = analyze(fixture, "amd64")
    result = resolve(paths, roots)
    equal(len(result["records"]), 1)
    equal(result["records"][0]["destination"], "/Windows/SysWOW64/loader.efi")
    equal([r["destination"] for r in result["links"]], ["/Windows/SysWOW64/Boot/renamed.efi", "/Windows/Alternate/loader.efi"])
    equal([r["name"] for r in result["links"]], ["loader.efi", "loader.efi"])
    equal(result["unresolved"], [])
    for content in ['<link/>', '<link destination="relative"/>', '<link destination="$(runtime.system32)\\"/>', '<link destination="$(runtime.system32)\\file" unknown="true"/>', '<link destination="$(runtime.system32)\\file"><unknown/></link>']:
        raises(analyze, args = [_runtime_files('<file name="file" destinationPath="$(runtime.system32)">' + content + '</file>'), "amd64"])
    unsafe = analyze(_runtime_files('<file name="file" destinationPath="$(runtime.system32)"><link destination="$(runtime.windows)\\..\\escape"/></file>'), "amd64")
    raises(resolve, args = [unsafe, roots], message = "ambiguous")

def test_manifest_local_file_security():
    analyze = testing.module("@stdlib//windows/servicing:runtime.star")["analyze_servicing_file_security"]
    def trust(definitions):
        return '<trustInfo><security><accessControl><securityDescriptorDefinitions>' + definitions + '</securityDescriptorDefinitions></accessControl></security></trustInfo>'
    definition = '<securityDescriptorDefinition name="same" sddl="(inherit)" operationHint="replace"/>'
    files = '<file name="explicit"><securityDescriptor name="same" buildFilter=""/></file><file name="absent"><securityDescriptor xmlns="foreign" name="missing"/></file>'
    fixture = _runtime_files(files + trust(definition))
    before = _runtime_files(files + trust(definition.replace('(inherit)', 'O:SYG:SYD:AIS:AI')))
    fixture["transitions"][0]["before"] = before["transitions"][0]["after"]
    records = analyze(fixture)
    compiled = testing.module("@stdlib//windows/servicing:runtime.star")["compile_servicing_file_security"](records)
    equal([r["state"] for r in compiled], ["explicit", "absent", "inherit", "absent"])
    equal(compiled[0]["data"], windows.compile_sddl("O:SYG:SYD:AIS:AI"))
    equal(compiled[2]["data"], None)
    equal(len(records), 4)
    equal(records[0]["descriptor"]["sddl"], "O:SYG:SYD:AIS:AI")
    equal(records[2]["descriptor"]["sddl"], "(inherit)")
    equal(records[2]["descriptor"]["operation_hint"], "replace")
    equal(records[1]["descriptor"], None)
    equal(records[3]["reference_attributes"], None)
    equal(records[2]["reference_attributes"][1]["name"], "buildFilter")
    for body in [files, files + '<other>' + trust(definition) + '</other>', files + trust(definition.replace(' name=', ' xmlns="foreign" name='))]:
        raises(analyze, args = [_runtime_files(body)], message = "unresolved")
    raises(analyze, args = [_runtime_files(files + trust(definition + definition))], message = "duplicate")
    raises(analyze, args = [_runtime_files('<file name="double"><securityDescriptor name="same"/><securityDescriptor name="same"/></file>' + trust(definition))], message = "duplicate")
    raises(analyze, args = [_runtime_files(files + trust('<securityDescriptorDefinition name="same"/>'))], message = "requires")

def test_directory_declarations_and_paths():
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    analyze = runtime["analyze_servicing_directories"]
    resolve = runtime["resolve_servicing_directory_paths"]
    trust = '<trustInfo><security><accessControl><securityDescriptorDefinitions><securityDescriptorDefinition name="local" sddl="(inherit)" operationHint="replace"/></securityDescriptorDefinitions></accessControl></security></trustInfo>'
    declaration = '<directory destinationPath="$(runtime.system32)\\New" owner="False" compression="none"><securityDescriptor name="local"/></directory>'
    body = '<directories>' + declaration + declaration + '<directory destinationPath="$(runtime.windows)"/></directories>'
    # Nested lookalikes and file parents are not directory declarations.
    body += '<other><directories>' + declaration + '</directories></other><file name="x" destinationPath="$(runtime.system32)\\Implicit"/>'
    fixture = _runtime_files(body + trust, "wow64")
    before = _runtime_files(body + trust.replace('(inherit)', 'O:SYG:SYD:P(A;OICI;FA;;;SY)'), "wow64")
    fixture["transitions"][0]["before"] = before["transitions"][0]["after"]
    records = analyze(fixture, "amd64")
    equal(len(records), 6)
    equal([r["side"] for r in records], ["before"] * 3 + ["after"] * 3)
    equal([r["directory_id"] for r in records], [41, 41, 36] * 2)
    equal({a["name"]: a["value"] for a in records[0]["attributes"]}["owner"], "False")
    equal(records[3]["descriptor"]["operation_hint"], "replace")
    compiled = runtime["compile_servicing_file_security"](records)
    equal([r["state"] for r in compiled], ["explicit", "explicit", "absent", "inherit", "inherit", "absent"])
    roots = dict(context = runtime["offline_servicing_path_context"]("X:\\Windows", "/Windows"), source_roots = {41: "X:\\Windows\\SysWOW64", 36: "X:\\Windows"})
    equal([r["destination"] for r in resolve(records, roots)], ["/Windows/SysWOW64/New", "/Windows/SysWOW64/New", "/Windows"] * 2)
    drive = analyze(_runtime_files('<directories><directory destinationPath="$(runtime.bootDrive)"/></directories>'), "amd64")
    roots["source_roots"][0x100000] = "X:\\"
    equal(resolve(drive, roots)[0]["destination"], "/")
    recycle = analyze(_runtime_files('<directories><directory destinationPath="$(runtime.bootDrive)\\$Recycle.Bin"/></directories>'), "amd64")
    equal(resolve(recycle, roots)[0]["destination"], "/$Recycle.Bin")
    raises(analyze, args = [_runtime_files(body), "amd64"], message = "unresolved")
    raises(analyze, args = [_runtime_files('<directories>' + declaration.replace('<securityDescriptor name="local"/>', '<securityDescriptor name="local"/><securityDescriptor name="local"/>') + '</directories>' + trust), "amd64"], message = "duplicate")
    for path in ["$(runtime.system32)\\..\\escape", "$(runtime.system32)\\bad:stream"]:
        unsafe = analyze(_runtime_files('<directories><directory destinationPath="%s"/></directories>' % path), "amd64")
        raises(resolve, args = [unsafe, roots])
    unknown = analyze(_runtime_files('<directories><directory destinationPath="$(runtime.public)"/></directories>'), "amd64")
    raises(resolve, args = [unknown, roots], message = "unresolved")

def test_native_file_security_defaults():
    prepare = testing.module("@stdlib//windows/servicing:runtime.star")["prepare_servicing_file_security"]
    # Independent native ApplyWithDefaults setter captures: each missing
    # principal is SY, absent ACLs are empty, protection is independent,
    # ID flags survive this boundary, and generic file rights are mapped.
    for source, expected, control in [
        ("O:SYG:SY", "O:SYG:SYD:S:", 0x8014),
        ("O:BAG:WD", "O:BAG:WDD:S:", 0x8014),
        ("G:BAD:(A;ID;FR;;;BA)", "O:SYG:BAD:(A;ID;FR;;;BA)S:", 0x8014),
        ("O:BAD:P(A;;GR;;;BA)S:P(AU;SA;GR;;;WD)", "O:BAG:SYD:P(A;;FR;;;BA)S:P(AU;SA;FR;;;WD)", 0xb014),
        ("O:SYG:SYD:AIARS:AIAR", "O:SYG:SYD:S:", 0x8014),
    ]:
        raw = windows.compile_sddl(source)
        result = prepare(raw)
        equal(raw, windows.compile_sddl(source))
        equal(binary.read_u16le(result, 2), control)
        expected_data = windows.compile_sddl(expected)
        for offset in [4, 8, 12, 16]:
            actual_start = binary.read_u32le(result, offset)
            expected_start = binary.read_u32le(expected_data, offset)
            size = binary.read_u16le(expected_data, expected_start + 2) if offset >= 12 else 8 + 4 * binary.read_u8(expected_data, expected_start + 1)
            equal(result[actual_start:actual_start + size], expected_data[expected_start:expected_start + size])
        # Exercise the actual next phase as well, with its independently
        # native-tested canonical layout and protected/ID selection policy.
        equal(windows.inherit_file_security(result), windows.inherit_file_security(expected_data))
    absent_protected = binary.builder()
    absent_protected.append(windows.compile_sddl("O:SYG:SY"))
    absent_protected.patch_u16le(2, 0xb000)
    equal(binary.read_u16le(prepare(absent_protected.bytes()), 2), 0x8014)
    raises(prepare, args = [None], message = "selected descriptor")
    raises(prepare, args = [windows.compile_sddl("O:SYG:SYD:NO_ACCESS_CONTROL")], message = "NULL")
    raises(prepare, args = [b"truncated"], message = "security descriptor")
    bad = binary.builder()
    bad.append(windows.compile_sddl("O:SYG:SYD:S:"))
    bad.patch_u16le(2, 0x8015)  # Owner-defaulted is not this token-free path.
    raises(prepare, args = [bad.bytes()], message = "controls")


def test_native_file_security_request():
    build = testing.module("@stdlib//windows/servicing:runtime.star")["build_servicing_file_security_request"]
    parent_sddl = "O:SYG:SYD:(A;OICI;FR;;;BU)S:(AU;OICISA;FR;;;WD)"
    parent = windows.compile_sddl(parent_sddl)
    # Independent WCP 26100.9441 SetSecurityObjectWithInheritance captures,
    # stopped at its provider setter. The parent query uses native RTL and
    # the declared SYSTEM token fixture; no filesystem mutation is modeled.
    for source, expected, info in [
        ("O:SYG:SYD:S:", "O:SYG:SYD:(A;ID;FR;;;BU)S:(AU;IDSA;FR;;;WD)", 0x3000000f),
        ("O:BAG:WDD:P(A;;GR;;;BA)S:P", "O:BAG:WDD:P(A;;FR;;;BA)S:P", 0xc000000f),
        ("O:SYG:SYD:P(A;ID;FA;;;SY)S:", "O:SYG:SYD:P(A;;FA;;;SY)S:(AU;IDSA;FR;;;WD)", 0x9000000f),
        ("O:SYG:SYD:(A;OICI;FA;;;SY)S:(AU;SA;FR;;;SY)", "O:SYG:SYD:(A;;FA;;;SY)(A;ID;FR;;;BU)S:(AU;SA;FR;;;SY)(AU;IDSA;FR;;;WD)", 0x3000000f),
        ("O:SYG:SYD:(A;ID;FA;;;SY)S:P", "O:SYG:SYD:(A;ID;FR;;;BU)S:P", 0x6000000f),
        ("O:SYG:SYD:PS:P", "O:SYG:SYD:PS:P", 0xc000000f),
    ]:
        data = windows.compile_sddl(source)
        result = build(data, parent)
        equal(result["security_information"], info)
        equal(windows.security_descriptor_parts(result["descriptor"]), windows.security_descriptor_parts(windows.compile_sddl(expected)))
        equal(data, windows.compile_sddl(source))
        equal(parent, windows.compile_sddl(parent_sddl))
    empty = windows.compile_sddl("O:SYG:SYD:S:")
    result = build(empty, empty)
    # Security-sensitive native asymmetry: preserve the empty DACL; the
    # unprotected zero-ACE SACL becomes present-NULL, not absent.
    equal(result["security_information"], 0x3000000f)
    equal(windows.security_descriptor_parts(result["descriptor"]), windows.security_descriptor_parts(windows.compile_sddl("O:SYG:SYD:S:NO_ACCESS_CONTROL")))
    raises(build, args = [empty, None], message = "actual parent")
    raises(build, args = [windows.compile_sddl("O:SYG:SYD:NO_ACCESS_CONTROL"), empty], message = "NULL")
    raises(build, args = [empty, b"truncated"], message = "security descriptor")


def test_native_file_security_assignment():
    assign = testing.module("@stdlib//windows/servicing:runtime.star")["assign_servicing_file_security"]
    # Exact-base ntoskrnl SeSetSecurityDescriptorInfoEx, using NTFS's observed
    # 0x4000 flags. The native fixture executes owner validation and ACL code;
    # only declared subject/resource and bounded pool boundaries are modeled.
    label = "(ML;ID;0x1;;;S-1-16-8192)"
    for old, incoming, info, expected, control in [
        ("O:SYG:SYD:S:", "O:SYG:SYD:P(A;;FA;;;SY)S:P", 0xc000000f, "O:SYG:SYD:P(A;;FA;;;SY)S:NO_ACCESS_CONTROL", 0xb014),
        ("O:SYG:SYD:S:" + label, "O:SYG:SYD:P(A;;FA;;;SY)S:P", 0xc000000f, "O:SYG:SYD:P(A;;FA;;;SY)S:P" + label, 0xb014),
        ("O:SYG:SYD:S:(AU;FA;FW;;;SY)" + label, "O:SYG:SYD:P(A;;FA;;;SY)S:(AU;SA;FR;;;WD)", 0x9000000f, "O:SYG:SYD:P(A;;FA;;;SY)S:(AU;SA;FR;;;WD)" + label, 0x9014),
        ("O:SYG:SYD:PAIS:PAI", "O:SYG:SYD:S:NO_ACCESS_CONTROL", 0x3000000f, "O:SYG:SYD:S:NO_ACCESS_CONTROL", 0x8014),
        ("O:SYG:SYD:S:", "O:SYG:SYD:P(A;;FR;;;SY)(D;;FW;;;SY)(A;;FR;;;SY)(A;;FW;;;SY)(D;;FW;;;SY)S:", 0x9000000f, "O:SYG:SYD:P(A;;FR;;;SY)(D;;FW;;;SY)(A;;FW;;;SY)(D;;FW;;;SY)S:NO_ACCESS_CONTROL", 0x9014),
    ]:
        current = windows.compile_sddl(old)
        incoming_data = windows.compile_sddl(incoming)
        request = dict(descriptor = incoming_data, security_information = info)
        result = assign(current, request)
        expected_parts = windows.security_descriptor_parts(windows.compile_sddl(expected))
        # The bounded SDDL compiler cannot spell protected present-NULL SACL.
        # These controls were captured independently from the native result.
        expected_parts["control"] = control
        equal(windows.security_descriptor_parts(result), expected_parts)
        equal(current, windows.compile_sddl(old))
        equal(request, dict(descriptor = incoming_data, security_information = info))
    callback = '(XA;;0x1200A9;;;BU;(WIN://SYSAPPID Contains "MicrosoftWindows.Client.CBS_cw5n1h2txyewy"))'
    repeated = windows.compile_sddl("O:SYG:SYD:P" + callback * 2 + "S:")
    empty = windows.compile_sddl("O:SYG:SYD:S:")
    result = assign(empty, dict(descriptor = repeated, security_information = 0x9000000f))
    equal(windows.security_descriptor_parts(result)["dacl"], windows.security_descriptor_parts(repeated)["dacl"])
    request = dict(descriptor = empty, security_information = 0x3000000f)
    raises(assign, args = [empty, dict(request, security_information = 0x3000001f)], message = "information mask")
    raises(assign, args = [empty, dict(request, descriptor = windows.compile_sddl("O:SYG:SYD:NO_ACCESS_CONTROLS:"))], message = "non-NULL DACL")
    raises(assign, args = [empty, dict(request, descriptor = windows.compile_sddl("O:SYG:SYD:(A;;GR;;;SY)S:"))], message = "DACL entry")
    # The exact Sense task parent contributes ACCESS_SYSTEM_SECURITY to
    # its inherited audit ACE. Native RTL retains that bit for audit, not
    # effective allow ACEs; assignment must not clip or reject it.
    audit_sddl = "O:SYG:SYD:P(A;;FA;;;SY)S:(AU;IDFASA;0x010d0000;;;WD)"
    audit_data = windows.compile_sddl(audit_sddl)
    result = assign(empty, dict(descriptor=audit_data, security_information=0x9000000f))
    equal(windows.security_descriptor_parts(result)["sacl"], windows.security_descriptor_parts(audit_data)["sacl"])
    raises(assign, args=[empty, dict(descriptor=windows.compile_sddl("O:SYG:SYD:(A;;0x01000000;;;SY)S:"), security_information=0x3000000f)], message="DACL entry")
    # A category not yet modeled must never be silently lost from the old SACL.
    unknown = binary.builder()
    unknown.append(windows.compile_sddl("O:SYG:SYD:S:" + label))
    unknown.patch_u8(binary.read_u32le(unknown.bytes(), 12) + 8, 0x7f)
    raises(assign, args = [unknown.bytes(), request], message = "SACL category")
    # Both source ACLs fit independently; their required combination does not.
    many_labels = windows.compile_sddl("O:SYG:SYD:S:" + label * 1800)
    many_audits = windows.compile_sddl("O:SYG:SYD:S:" + "(AU;SA;FR;;;SY)" * 1800)
    raises(assign, args = [many_labels, dict(request, descriptor = many_audits)], message = "limit")


def test_native_default_directory_security():
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    build = runtime["build_servicing_directory_security_request"]
    assign = runtime["assign_servicing_directory_security"]
    parent = windows.compile_sddl("O:SYG:SYD:AI(A;OICI;GA;;;SY)")
    # Fresh native existing-directory commit: old flags=1, new flags=3,
    # both owned, no security pair. Using old flags=3 is a different no-op.
    golden = binary.decode("0100048f44000000500000000000000014000000020030000200000000101400ff011f00010100000000000512000000001b140000000010010100000000000512000000010100000000000512000000010100000000000512000000", "hex")
    request = build(None, parent, default = True)
    expected = windows.security_descriptor_parts(golden)
    equal(request["security_information"], 0x3000000f)
    equal(windows.security_descriptor_parts(request["descriptor"]), expected)
    expected["control"] = 0x8c14
    equal(windows.security_descriptor_parts(assign(parent, request)), expected)
    raises(build, args = [None, parent], message = "selected and parent")
    raises(build, args = [parent, parent], kwargs = dict(default = True), message = "cannot carry")
    raises(build, args = [None, windows.compile_sddl("O:SYG:SY")], kwargs = dict(default = True), message = "inherited DACL")


def test_native_servicing_creation_security():
    build = testing.module("@stdlib//windows/servicing:runtime.star")["build_servicing_created_security"]
    parent = windows.compile_sddl("O:SYG:SYD:AI(A;OICI;GA;;;SY)")
    # Exact-base SeAssignSecurityEx, flags 0x4001, declared SYSTEM subject
    # with an owner-enabled TrustedInstaller group. File creator NULL;
    # directory creator O:SYG:SY. These are independent kernel byte captures.
    for directory, golden in [
        (False, "01000484300000003c000000000000001400000002001c000100000000101400ff011f00010100000000000512000000010100000000000512000000010100000000000512000000"),
        (True, "0100048444000000500000000000000014000000020030000200000000101400ff011f00010100000000000512000000001b140000000010010100000000000512000000010100000000000512000000010100000000000512000000"),
    ]:
        result = build(parent, directory = directory)
        expected = windows.security_descriptor_parts(binary.decode(golden, "hex"))
        equal(windows.security_descriptor_parts(result), expected)
        # Independent native flags-4003 controls: absent versus present-NULL
        # SACL parents both preserve SACL_AUTO_INHERITED, not SACL_PRESENT.
        for control in [0x8c04, 0x8c14]:
            changed = binary.builder()
            changed.append(parent)
            changed.patch_u16le(2, control)
            equal(windows.security_descriptor_parts(build(changed.bytes(), directory = directory)), dict(expected, control = 0x8c04))
    equal(parent, windows.compile_sddl("O:SYG:SYD:AI(A;OICI;GA;;;SY)"))
    raises(build, args = [None], message = "actual parent")
    raises(build, args = [windows.compile_sddl("O:SYG:SYD:(A;OICI;GA;;;SY)")], message = "auto-inherited")
    raises(build, args = [windows.compile_sddl("O:SYG:SYD:AI(A;;GA;;;SY)")], message = "default-DACL fallback")
    raises(build, args = [windows.compile_sddl("O:SYG:SYD:AI(A;OICI;GA;;;SY)S:(ML;;0x1;;;LW)")], message = "parent SACL")


def test_native_creation_token_default_dacl():
    build = testing.module("@stdlib//windows/servicing:runtime.star")["build_servicing_created_security"]
    # Actual FileMaps parent: no inheritable DACL ACEs; noninheritable audit.
    # Independent SeAssignSecurityEx file/directory captures with flags4003,
    # SYSTEM subject, TI owner-enabled group and this two-ACE default DACL.
    parent = binary.decode("0100149c1400000034000000f800000054000000010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487010600000000000550000000b589fb381984c2cb5c6c236d5700776ec00264870200a4000600000000002800ff011f00010600000000000550000000b589fb381984c2cb5c6c236d5700776ec002648700001800a90012000102000000000005200000002002000000001400a900120001010000000000051200000000001800a90012000102000000000005200000002102000000001800a9001200010200000000000f020000000100000000001800a9001200010200000000000f020000000200000002001c000100000002c0140016011f00010100000000000100000000", "hex")
    default = binary.decode("020034000200000000001400ff011f00010100000000000512000000000018008900120001020000000000052000000020020000", "hex")
    for directory, golden in [(False, "0100048c48000000540000000000000014000000020034000200000000001400ff011f00010100000000000512000000000018008900120001020000000000052000000020020000010100000000000512000000010100000000000512000000"), (True, "0100048c48000000540000000000000014000000020034000200000000001400ff011f00010100000000000512000000000018008900120001020000000000052000000020020000010100000000000512000000010100000000000512000000")]:
        result = build(parent, directory = directory, token_default_dacl = default)
        equal(windows.security_descriptor_parts(result), windows.security_descriptor_parts(binary.decode(golden, "hex")))
    raises(build, args = [parent], message = "default-DACL fallback")
    inheritable = windows.compile_sddl("O:SYG:SYD:AI(A;OICI;FA;;;SY)")
    equal(build(inheritable, token_default_dacl = default), build(inheritable))
    for sddl in ["D:(A;OI;FA;;;SY)", "D:(A;;GA;;;SY)", "D:(D;;FA;;;SY)", "D:"]:
        unsupported = windows.security_descriptor_parts(windows.compile_sddl(sddl))["dacl"]
        raises(build, args = [parent], kwargs = dict(token_default_dacl = unsupported), message = "token default DACL")
    inheritable_audit = windows.compile_sddl("O:SYG:SYD:AI(A;;FA;;;SY)S:(AU;OIFASA;FA;;;WD)")
    raises(build, args = [inheritable_audit], kwargs = dict(token_default_dacl = default), message = "parent SACL")


def test_native_directory_security_request_and_assignment():
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    build = runtime["build_servicing_directory_security_request"]
    assign = runtime["assign_servicing_directory_security"]
    ti = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    cbs = 'O:' + ti + 'G:' + ti + 'D:P(A;CI;GA;;;' + ti + ')(A;;0x1301bf;;;SY)(A;IOCIOI;GA;;;SY)(A;;0x1301bf;;;BA)(A;IOCIOI;GA;;;BA)(A;CIOI;GRGX;;;BU)(A;OICIIO;GA;;;CO)(A;CIOI;GRGX;;;S-1-15-2-1)(A;CIOI;GRGX;;;S-1-15-2-2)(XA;OICI;0x1200A9;;;BU;(WIN://SYSAPPID Contains "MicrosoftWindows.Client.CBS_cw5n1h2txyewy"))'
    whesvc = "D:P(A;;GA;;;SY)(A;OICIIO;GA;;;SY)(A;;GA;;;BA)(A;OICIIO;GA;;;BA)"
    # Independent byte captures at NtSetSecurityObject from fresh WCP
    # 26100.9441 CommitDirectoryChanges, not output from this implementation.
    vectors = [
        (whesvc, "0100049f74000000800000000000000014000000020060000400000000001400ff011f00010100000000000512000000000b14000000001001010000000000051200000000001800ff011f0001020000000000052000000020020000000b18000000001001020000000000052000000020020000010100000000000512000000010100000000000512000000"),
        (cbs, "0100049f000200002002000000000000140000000200ec010e00000000002800ff011f00010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487000a280000000010010600000000000550000000b589fb381984c2cb5c6c236d5700776ec002648700001400bf011300010100000000000512000000000b14000000001001010000000000051200000000001800bf01130001020000000000052000000020020000000b1800000000100102000000000005200000002002000000001800a900120001020000000000052000000021020000000b1800000000a001020000000000052000000021020000000b14000000001001010000000000030000000000001800a9001200010200000000000f0200000001000000000b1800000000a0010200000000000f020000000100000000001800a9001200010200000000000f0200000002000000000b1800000000a0010200000000000f020000000200000009039800a90012000102000000000005200000002102000061727478f81c000000570049004e003a002f002f005300590053004100500050004900440010520000004d006900630072006f0073006f0066007400570069006e0064006f00770073002e0043006c00690065006e0074002e004300420053005f006300770035006e0031006800320074007800790065007700790086000000010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487"),
        (cbs.replace("Client.CBS", "60909653.Filons"), "0100049f080200002802000000000000140000000200f4010e00000000002800ff011f00010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487000a280000000010010600000000000550000000b589fb381984c2cb5c6c236d5700776ec002648700001400bf011300010100000000000512000000000b14000000001001010000000000051200000000001800bf01130001020000000000052000000020020000000b1800000000100102000000000005200000002002000000001800a900120001020000000000052000000021020000000b1800000000a001020000000000052000000021020000000b14000000001001010000000000030000000000001800a9001200010200000000000f0200000001000000000b1800000000a0010200000000000f020000000100000000001800a9001200010200000000000f0200000002000000000b1800000000a0010200000000000f02000000020000000903a000a90012000102000000000005200000002102000061727478f81c000000570049004e003a002f002f0053005900530041005000500049004400105c0000004d006900630072006f0073006f0066007400570069006e0064006f00770073002e00360030003900300039003600350033002e00460069006c006f006e0073005f006300770035006e003100680032007400780079006500770079008600010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487"),
    ]
    parent = windows.compile_sddl("O:SYG:SYD:AI(A;OICI;FR;;;BU)")
    current = windows.compile_sddl("O:SYG:SYD:AI(A;CIID;FA;;;SY)")
    label = "(ML;ID;0x1;;;S-1-16-8192)"
    labeled = windows.compile_sddl("O:SYG:SYD:S:(AU;FA;FW;;;SY)" + label)
    for sddl, golden_hex in vectors:
        selected = windows.compile_sddl(sddl)
        golden = binary.decode(golden_hex, "hex")
        expected = windows.security_descriptor_parts(golden)
        request = build(selected, parent)
        equal(request["security_information"], 0x9000000f)
        equal(windows.security_descriptor_parts(request["descriptor"]), expected)
        null_parent = binary.builder()
        null_parent.append(parent)
        null_parent.patch_u16le(2, 0x8c14)
        equal(windows.security_descriptor_parts(build(selected, null_parent.bytes())["descriptor"]), expected)
        # Independently executed SeSetSecurityDescriptorInfoEx retained all
        # components but returned 9c14, not the WCP input control 9f04.
        expected["control"] = 0x9c14
        equal(windows.security_descriptor_parts(assign(current, request)), expected)
        expected["sacl"] = windows.security_descriptor_parts(windows.compile_sddl("S:" + label))["sacl"]
        equal(windows.security_descriptor_parts(assign(labeled, request)), expected)
        equal(selected, windows.compile_sddl(sddl))
    raises(build, args = [None, parent], message = "selected and parent")
    raises(build, args = [windows.compile_sddl("D:AI(A;;FA;;;SY)"), parent], message = "controls")
    raises(build, args = [windows.compile_sddl(whesvc), labeled], message = "parent SACL")
    request = build(windows.compile_sddl(whesvc), parent)
    raises(assign, args = [current, dict(request, security_information = 0x9000001f)], message = "information mask")
    raises(runtime["assign_servicing_file_security"], args = [current, request], message = "controls")
    wrong = binary.builder()
    wrong.append(request["descriptor"])
    wrong.patch_u16le(2, 0x9c04)
    raises(assign, args = [current, dict(request, descriptor = wrong.bytes())], message = "directory assignment controls")


def test_native_unprotected_directory_request():
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    build = runtime["build_servicing_directory_security_request"]
    parent = windows.compile_sddl("O:SYG:SYD:AI(A;OICI;FR;;;BU)")
    selected = windows.compile_sddl("O:BAG:SYD:(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGX;;;BU)(A;;GRGX;;;S-1-15-2-1)")
    # Independent WCP CBS Logs request, repeated old/new ownership pairs.
    golden = binary.decode("0100048f90000000a0000000000000001400000002007c000500000000001800ff011f000102000000000005200000002002000000001400ff011f0001010000000000051200000000001800a90012000102000000000005200000002102000000001800a9001200010200000000000f020000000100000000131800890012000102000000000005200000002102000001020000000000052000000020020000010100000000000512000000", "hex")
    request = build(selected, parent)
    equal(request["security_information"], 0x3000000f)
    equal(windows.security_descriptor_parts(request["descriptor"]), windows.security_descriptor_parts(golden))


def test_native_interned_directory_preprocessing():
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    descriptor = dict(sddl = "D:AI(A;OICIID;FA;;;S-1-5-80-3635958274-2059881490-2225992882-984577281-633327304)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)")
    attrs = [dict(name = "owner", namespace = "", value = "true")]
    before = dict(destination = "/Windows/System32/networklist/icons", side = "before", identity = "network", attributes = attrs, descriptor = descriptor)
    after = dict(before, side = "after")
    # Fresh coordinator cache + native ProcessDirectory/Preprocess: zero
    # changes and zero commit effects (836 instructions), despite ID ACEs.
    # Repeated ownership must still force a write; do not suppress bit1.
    for records, changed, flags in [([before, after], False, 10), ([before, after, before, after], True, 3)]:
        reduced = runtime["reduce_servicing_directory_declarations"](records)
        result = runtime["preprocess_servicing_directory_declarations"](reduced)
        item = result[before["destination"].lower()]
        equal(item["own_changed"], changed)
        equal(item["security_flags"], flags)


def test_native_directory_audit_security():
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    build = runtime["build_servicing_directory_security_request"]
    assign = runtime["assign_servicing_directory_security"]
    ti = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    sddl = "O:" + ti + "G:" + ti + "D:P(A;CIOI;GA;;;" + ti + ")(A;CIOI;GRGX;;;SY)(A;CIOI;GRGX;;;BA)(A;CIOI;GRGX;;;BU)(A;CIOI;GRGX;;;S-1-15-2-1)(A;CIOI;GRGX;;;S-1-15-2-2)S:(AU;FASA;SDWDWOFW;;;WD)"
    # Captured from WCP with two ordered old/new ownership pairs, using
    # actual Windows/servicing metadata. A single pair is a native no-op.
    # The real Packages parent (with noninheritable audit ACE) produced
    # exactly the same request. Kernel assignment took 3969 instructions,
    # preserving all components and clearing only the two AR controls.
    golden = windows.security_descriptor_parts(binary.decode("0100149f7001000090010000140000003000000002001c000100000002c0140016011f00010100000000000100000000020040010c00000000002800ff011f00010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487000b280000000010010600000000000550000000b589fb381984c2cb5c6c236d5700776ec002648700001400a9001200010100000000000512000000000b1400000000a001010000000000051200000000001800a900120001020000000000052000000020020000000b1800000000a00102000000000005200000002002000000001800a900120001020000000000052000000021020000000b1800000000a00102000000000005200000002102000000001800a9001200010200000000000f0200000001000000000b1800000000a0010200000000000f020000000100000000001800a9001200010200000000000f0200000002000000000b1800000000a0010200000000000f0200000002000000010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487", "hex"))
    selected = windows.compile_sddl(sddl)
    for parent_sddl in ["O:SYG:SYD:AI(A;OICI;FA;;;SY)", sddl]:
        parent = windows.compile_sddl(parent_sddl)
        request = build(selected, parent)
        equal(request["security_information"], 0x9000000f)
        equal(windows.security_descriptor_parts(request["descriptor"]), golden)
        expected = dict(golden, control = 0x9c14)
        equal(windows.security_descriptor_parts(assign(selected, request)), expected)
    unsupported = windows.compile_sddl("O:SYG:SYD:P(A;;FA;;;SY)S:(ML;OICI;NW;;;LW)")
    raises(build, args = [unsupported, selected], message = "selected SACL")
    raises(build, args = [selected, unsupported], message = "parent SACL")


def test_native_directory_inheritable_audit():
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    build = runtime["build_servicing_directory_security_request"]
    assign = runtime["assign_servicing_directory_security"]
    # Server NTDLL RtlNewSecurityObjectEx, then kernel
    # SeSetSecurityDescriptorInfoEx flags4000: full component comparison passes.
    # The SYSTEM subject owns the descriptor; no security decision is hooked.
    vectors = [("SAFA", [0xc0]), ("OISAFA", [0xc1, 0xd9]),
               ("CISAFA", [0xc2, 0xd2]), ("OICISAFA", [0xc3, 0xd3]),
               ("OICINPSAFA", [0xc7, 0xd0]), ("OICIIOSAFA", [0xcb, 0xd3]),
               ("OICIIDSAFA", [0xd3])]
    for flags, expected in vectors:
        audit = "S:(AU;" + flags + ";0x010d0000;;;WD)"
        selected = windows.compile_sddl("O:SYG:SYD:P(A;OICI;FA;;;SY)" + audit)
        parent = windows.compile_sddl("O:SYG:SYD:AI(A;OICI;FA;;;SY)" + audit)
        request = build(selected, parent)
        parts = windows.security_descriptor_parts(request["descriptor"])
        equal(request["security_information"], 0x9000000f)
        equal(parts["control"], 0x9f14)
        aces = windows.acl_entries(parts["sacl"])["entries"]
        equal([(a["type"], a["flags"], a["mask"]) for a in aces], [(2, f, 0x010d0000) for f in expected])
        equal(windows.security_descriptor_parts(assign(parent, request)), dict(parts, control=0x9c14))
    # Legacy creation inheritance remains separate from the setter path;
    # it must not silently discard propagating audits.
    raises(runtime["build_servicing_created_security"], args=[parent], message="parent SACL")


def test_native_creation_inheritable_audit():
    build = testing.module("@stdlib//windows/servicing:runtime.star")["build_servicing_created_security"]
    # Native Server 26100.32230 SeAssignSecurityEx, SYSTEM subject and
    # mapping, flags4003, NULL file creator / O:SYG:SY directory creator.
    # Independent native captures compare all descriptor components.
    vectors = [("SAFA", None, None), ("OISAFA", 0xd0, 0xd9),
               ("CISAFA", None, 0xd2), ("OICISAFA", 0xd0, 0xd3),
               ("OICINPSAFA", 0xd0, 0xd0), ("OICIIOSAFA", 0xd0, 0xd3),
               ("OICIIDSAFA", 0xd0, 0xd3)]
    system = windows.security_descriptor_parts(windows.compile_sddl("O:SYG:SY"))
    for flags, file_flags, directory_flags in vectors:
        parent = windows.compile_sddl("O:SYG:SYD:AI(A;OICI;FA;;;SY)S:AI(AU;" + flags + ";0x010d0000;;;WD)")
        for directory, expected in [(False, file_flags), (True, directory_flags)]:
            parts = windows.security_descriptor_parts(build(parent, directory = directory))
            equal(parts["owner"], system["owner"])
            equal(parts["group"], system["group"])
            equal(parts["control"], 0x8c04 if expected == None else 0x8c14)
            equal(parts["resource_manager_control"], 0)
            dacl = windows.security_descriptor_parts(windows.compile_sddl("D:(A;" + ("OICIID" if directory else "ID") + ";FA;;;SY)"))["dacl"]
            equal(parts["dacl"], dacl)
            if expected == None:
                equal(parts["sacl"], None)
            else:
                entries = windows.acl_entries(parts["sacl"])["entries"]
                equal([(e["type"], e["flags"], e["mask"], e["sid"]) for e in entries], [(2, expected, 0x010d0000, windows.security_descriptor_parts(windows.compile_sddl("O:WD"))["owner"])])
    # Legacy propagation differs: native flags4001 emits c0 rather than d0.
    legacy = windows.compile_sddl("O:SYG:SYD:AI(A;OICI;FA;;;SY)S:(AU;OISAFA;FA;;;WD)")
    raises(build, args = [legacy], message = "parent SACL")
    unsupported = windows.compile_sddl("O:SYG:SYD:AI(A;OICI;FA;;;SY)S:AI(ML;OICI;NW;;;LW)")
    raises(build, args = [unsupported], message = "parent SACL")


def test_native_directory_contribution_reduction():
    reduce = testing.module("@stdlib//windows/servicing:runtime.star")["reduce_servicing_directory_declarations"]
    label = dict(sddl = "D:(A;OICI;FA;;;SY)S:(ML;OIIO;0x1;;;LW)")
    def record(side, owner = False, attributes = None, descriptor = None):
        attrs = [dict(name = "owner", namespace = "", value = "True" if owner else "false")]
        if attributes != None:
            attrs.append(dict(name = "attributes", namespace = "", value = attributes))
        return dict(destination = "/$Recycle.Bin", side = side, identity = "explorer", attributes = attrs, descriptor = descriptor)
    before = record("before", True, "hidden system", label)
    after = record("after", True, "hidden system", label)
    # Independent native constructor + ProcessDirectory vectors: fields at
    # 88,8c,90,91,92,93,94 before PreprocessCurrentObject. The native fixture
    # uses separate descriptor allocations for the equal old/new references.
    vectors = [
        ([record("before"), record("after")], [128, 128, 3, 3, 3, 10, 8]),
        ([record("before", True), record("after", True)], [128, 128, 4, 4, 3, 42, 8]),
        ([before, after], [134, 134, 4, 4, 3, 10, 8]),
        ([before, after, before, after], [134, 134, 4, 4, 3, 11, 8]),
        ([record("after")], [128, 128, 3, 0, 1, 8, 0]),
        ([record("after", True)], [128, 128, 4, 0, 1, 40, 0]),
        ([record("before")], [128, 128, 0, 3, 2, 10, 8]),
        ([before, record("after")], [128, 134, 3, 4, 3, 10, 8]),
        ([before, record("after", True, "hidden", label), record("after")], [130, 134, 4, 4, 3, 10, 8]),
    ]
    preprocess = testing.module("@stdlib//windows/servicing:runtime.star")["preprocess_servicing_directory_declarations"]
    native_post = [(10, 8, False), (34, 8, True), (10, 8, False), (3, 8, True), (8, 1, True), (32, 1, True), (10, 9, True), (66, 9, True), (74, 8, True)]
    for index in range(len(vectors)):
        records, expected = vectors[index]
        reduced = reduce(records)
        item = reduced["/$recycle.bin"]
        post = preprocess(reduced)["/$recycle.bin"]
        equal((post["security_flags"], post["directory_flags"], post["own_changed"]), native_post[index])
        equal([item["after"]["attributes"], item["before"]["attributes"], item["after"]["state"], item["before"]["state"], item["operation"], item["security_flags"], item["directory_flags"]], expected)
        equal(item["contributions"], records)
    repeated = reduce([before, after, before, after])["/$recycle.bin"]
    equal(repeated["owned_addition_collisions"], 1)
    equal(repeated["after"]["descriptor"], label)
    # A later owned declaration without a reference does not erase the
    # previously selected descriptor, unlike a last-record-wins map.
    selected = reduce([after, record("after", True)])["/$recycle.bin"]
    equal(selected["after"]["descriptor"], label)
    equal(selected["security_flags"], 8)
    bad = dict(after, destination = "/Windows/../escape")
    raises(reduce, args = [[bad]], message = "resolved image path")
    raises(reduce, args = [[dict(after, side = "repair")]], message = "operation")
    raises(reduce, args = [[record("after", descriptor = dict(sddl = "(inherit)"))]], message = "separate selection")


def test_native_servicing_descriptor_comparison():
    compare = testing.module("@stdlib//windows/servicing:runtime.star")["servicing_file_security_matches_manifest"]
    # Independent native WCP CompareSecurityDescriptorFromObjectAgainstManifest
    # (flags=2), separately allocated source descriptors, all status zero.
    for old, new, expected in [
        ("O:SYG:SYD:(A;;GA;;;SY)S:", "O:SYG:SYD:(A;;FA;;;SY)S:", True),
        ("O:SYG:SYD:(A;ID;FA;;;SY)S:", "O:SYG:SYD:(A;ID;FA;;;SY)S:", False),
        ("O:SYG:SYD:(A;ID;FA;;;SY)S:", "O:SYG:SYD:S:", True),
        ("O:SYG:SYD:S:NO_ACCESS_CONTROL", "O:SYG:SYD:S:", True),
        ("O:SYG:SYD:AI(A;;FA;;;SY)S:", "O:SYG:SYD:(A;;FA;;;SY)S:", True),
        ("O:SYG:SYD:P(A;;FA;;;SY)S:", "O:SYG:SYD:(A;;FA;;;SY)S:", False),
        ("O:SYG:SYD:NO_ACCESS_CONTROL", "O:SYG:SYD:", False),
        ("O:SYG:SYD:S:", "O:SYG:SYD:", False),
        ("O:SYG:SYD:S:(AU;IDSA;FA;;;SY)", "O:SYG:SYD:S:NO_ACCESS_CONTROL", True),
    ]:
        equal(compare(windows.compile_sddl(old), windows.compile_sddl(new)), expected)
    callback = 'O:SYG:SYD:P(XA;OICI;GA;;;BU;(WIN://SYSAPPID Contains "MicrosoftWindows.Client.CBS_cw5n1h2txyewy"))S:'
    equal(compare(windows.compile_sddl(callback), windows.compile_sddl(callback.replace(";GA;", ";FA;"))), True)
    equal(compare(windows.compile_sddl(callback), windows.compile_sddl(callback.replace("Client.CBS", "Client.ABS"))), False)
    label = windows.compile_sddl("O:SYG:SYD:S:(ML;OIIO;0x1;;;LW)")
    equal(compare(label, label), True)
    equal(compare(label, windows.compile_sddl("O:SYG:SYD:S:(ML;OIIO;0x2;;;LW)")), False)
    equal(compare(None, None), True)
    equal(compare(None, label), False)
    raises(compare, args = [b"truncated", label], message = "descriptor")


def test_directory_propagation_configuration():
    select = testing.module("@stdlib//windows/servicing:runtime.star")["servicing_directory_propagation_policy"]
    def h(root, path, values):
        return windows.hive(windows.hive_from_patches(root, [dict(key = path, name = name, type = typ, value = value) for name, typ, value in values]))
    def check(policy, store):
        return select(h("SOFTWARE", "/Microsoft/Windows/CurrentVersion/Policies/Servicing", policy), h("COMPONENTS", "/Configuration", store))
    result = check([], [])
    equal(result["enumerate_children"], False)
    equal(result["mobile_store"], dict(value = 0, origin = "default"))
    equal(result["immutable_primaries"], True)
    equal(check([], [("SmiHiveUpdates", "REG_DWORD", 0x20000)])["immutable_primaries"], False)
    equal(check([("SmiHiveUpdates", "REG_DWORD", 0)], [("SmiHiveUpdates", "REG_DWORD", 0x20000)])["immutable_primaries"], True)
    store = [("MobileStore", "REG_DWORD", 1)]
    equal(check([], store)["enumerate_children"], True)
    # Policy zero is an explicit override, not a missing/falsy value.
    result = check([("mobilestore", "REG_DWORD", 0)], store)
    equal(result["enumerate_children"], False)
    equal(result["mobile_store"]["origin"], "policy")
    # Native tests DWORD type and exactly four bytes before using a value.
    equal(check([("MobileStore", "REG_SZ", "0")], store)["enumerate_children"], True)
    equal(check([("MobileStore", "REG_BINARY", b"\x00\x00\x00\x00")], store)["enumerate_children"], True)
    # MobileStore uses equality with 1, whereas SmiHiveUpdates is ORed raw.
    equal(check([("MobileStore", "REG_DWORD", 2)], store)["enumerate_children"], False)
    equal(check([], [("SmiHiveUpdates", "REG_DWORD", 0x80)])["enumerate_children"], True)
    equal(check([], [("SmiHiveUpdates", "REG_DWORD", 1)])["enumerate_children"], False)


def test_native_subtree_preprocessing():
    graph = testing.module("@stdlib//windows/servicing:runtime.star")["preprocess_servicing_path_hierarchy"]
    clean = dict(own_changed = False, directory_flags = 8, security_flags = 8)
    dirty = dict(own_changed = True, directory_flags = 8, security_flags = 8)
    # Native 10edcc fixture: removed grandchild dirties unchanged parent/root;
    # clean sibling receives skip bit4. No filesystem callbacks were required.
    result = graph({"/clean": clean, "/parent": clean, "/parent/removed": dirty}, {})
    equal([result[p]["directory_flags"] for p in ["/clean", "/parent", "/parent/removed"]], [12, 8, 8])
    equal(result["/"]["subtree_changed"], True)
    result = graph({"/clean": clean, "/parent": clean, "/parent/removed": clean}, {})
    equal([result[p]["directory_flags"] for p in ["/clean", "/parent", "/parent/removed"]], [12, 12, 12])
    equal(result["/"]["subtree_changed"], False)
    equal(result["/"]["directory_flags"], 0)
    # Independent native file fixture had own flag80 set; its implicit parent
    # must be visited even with no directory declaration at that destination.
    result = graph({"/clean": clean}, {"/new/parent/file": dirty})
    equal(result["/new/parent"]["implicit"], True)
    equal(result["/new"]["subtree_changed"], True)
    equal(result["/new/parent/file"]["directory_flags"], 8)
    equal(result["/clean"]["directory_flags"], 12)
    equal(clean["directory_flags"], 8)
    raises(graph, args = [{"/same": clean}, {"/SAME": dirty}], message = "collision")
    raises(graph, args = [{"/file/child": clean}, {"/file": dirty}], message = "ancestor")
    raises(graph, args = [{"/parent/../other": clean}, {}], message = "canonical")
    raises(graph, args = [{"/parent": {}}, {}], message = "preprocessed")


def test_runtime_side_specific_source_identity():
    policy = testing.module("@stdlib//windows/servicing:runtime.star")
    old = "sample, Culture=neutral, Version=10.0.1.0, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"
    new = old.replace("10.0.1.0", "10.0.2.0")
    body = '<file name="file" destinationPath="$(runtime.system32)\\"/><directories><directory destinationPath="$(runtime.windows)\\sample"/></directories>'
    xml = '<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="sample" processorArchitecture="amd64" version="10.0.1.0"/>%s</assembly>' % body
    tree = directory()
    tree.write("/old", xml)
    tree.write("/new", xml.replace("10.0.1.0", "10.0.2.0"))
    result = policy["analyze_servicing_runtime"](dict(winner_changes = [dict(identity = bytes(old), shadowed = "10.0.1.0", winner = "10.0.2.0")], manifests = {new.lower(): tree.find("/new")}, resident_manifests = {old.lower(): tree.find("/old")}))
    equal(result["transitions"][0]["component_identities"], dict(before = bytes(old), after = bytes(new)))
    files = policy["analyze_servicing_file_paths"](result, "amd64")["records"]
    security = policy["analyze_servicing_file_security"](result)
    directories = policy["analyze_servicing_directories"](result, "amd64")
    for records in [files, security, directories]:
        equal([r["identity"] for r in records], [bytes(old), bytes(old)])
        equal([r["component_identity"] for r in records], [bytes(old), bytes(new)])



def _native_file_record(side, flags, identity, path = "/Windows/System32/test.dll", name = "test.dll"):
    return dict(side = side, process_flags = flags, component_identity = identity, name = name, destination = path, attributes = 0x80, descriptor = None, source_hash = dict(digest_method = 2, transform = 1, digest = b"0123456789abcdef0123456789abcdef"))


def test_native_file_source_interning():
    key = testing.module("@stdlib//windows/servicing:runtime.star")["servicing_file_source_key"]
    old = "Microsoft-Windows-explorer, Culture=neutral, Version=10.0.26100.9444, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS"
    new = old.replace("9444", "9711")
    # Native InsertFileInfo, not merely the family hash: distinct parsed
    # identities differing only in version return the SAME FileInfo pointer.
    equal(key(bytes(old), "Case.dll"), key(bytes(new.upper()), "case.DLL"))
    bare = old.replace(", versionScope=nonSxS", "")
    equal(key(bytes(bare), "test.dll"), key(bytes(bare.replace("9444", "9711")), "test.dll"))
    # Native GDI+ 1.0/1.1 do not collide. Absent scope retains major/minor
    # while ignoring build/revision, independent of the identity type.
    for version, same_bare in [("10.0.26200.9444", True), ("10.1.26100.9444", False), ("11.0.26100.9444", False)]:
        equal(key(bytes(bare), "test.dll") == key(bytes(bare.replace("10.0.26100.9444", version)), "test.dll"), same_bare)
        equal(key(bytes(old), "test.dll"), key(bytes(old.replace("10.0.26100.9444", version)), "test.dll"))
    for other in [bare, old.replace("amd64", "x86"), old.replace("explorer", "other"), old + ", type=win32"]:
        equal(key(bytes(old), "test.dll") == key(bytes(other), "test.dll"), False)
    equal(key(bytes(old), "test.dll") == key(bytes(old), "other.dll"), False)
    equal(key(bytes(old), "Amd64\\UNIDRV.DLL"), key(bytes(new), "amd64\\unidrv.dll"))
    equal(key(bytes(old), "Amd64\\UNIDRV.DLL") == key(bytes(old), "UNIDRV.DLL"), False)
    raises(key, args = [bytes(old.replace("nonSxS", "unknown")), "test.dll"], message = "versionScope")
    raises(key, args = [bytes(old), "a/b"], message = "relative source")
    raises(key, args = [bytes(old), "naïve.dll"], message = "ASCII")


def test_native_file_record_reduction():
    policy = testing.module("@stdlib//windows/servicing:runtime.star")
    reduce = policy["reduce_servicing_file_declarations"]
    preprocess = policy["preprocess_servicing_file_declarations"]
    old = b"Microsoft-Windows-explorer, Culture=neutral, Version=10.0.26100.9444, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS"
    new = bytes(str(old).replace("9444", "9711"))
    # Captured WCP+bc478 then +10eeac outputs: new state, old state,
    # operation, flags93/94/95, own changed. Before is processed first.
    vectors = [
        (0, 1, [2, 0, 3, 8, 0x88, 1, False]),
        (0x40, 0x41, [2, 0, 3, 0x38, 0x88, 1, False]),
        (0, 0x41, [2, 0, 3, 0x20, 0x88, 1, True]),
        (8, 8, [1, 0, 3, 8, 0xe8, 1, False]),
        (0, 8, [1, 0, 3, 8, 0xaa, 1, True]),
        (0x20, 0x23, [2, 0, 3, 8, 0x98, 1, False]),
        (0x10, 0x10, [7, 7, 3, 0x88, 0x88, 7, True]),
        (0x10, 0x11, [2, 7, 3, 0x88, 0x88, 5, True]),
        (0x18, 0x18, [7, 7, 3, 0x88, 0x88, 7, True]),
        (None, 1, [2, 0, 1, 0x88, 0x80, 0, True]),
        (0, None, [0, 0, 2, 0x88, 8, 1, True]),
    ]
    for before, after, expected in vectors:
        records = []
        if before != None:
            records.append(_native_file_record("before", before, old))
        if after != None:
            records.append(_native_file_record("after", after, new))
        reduced = reduce(records)
        raw_flags = reduced["paths"]["/windows/system32/test.dll"]["security_flags"]
        output = preprocess(reduced)["/windows/system32/test.dll"]
        equal([output["after"]["state"], output["before"]["state"], output["operation"], output["security_flags"], output["directory_flags"], output["file_flags"], output["own_changed"]], expected)
        equal(reduced["paths"]["/windows/system32/test.dll"]["security_flags"], raw_flags)
    # Different family with identical bytes still has different FileInfo.
    records = [_native_file_record("before", 0, old), _native_file_record("after", 1, bytes(str(new).replace("amd64", "x86")))]
    output = preprocess(reduce(records))["/windows/system32/test.dll"]
    equal([output["security_flags"], output["own_changed"]], [0x88, True])
    # Identical source identity cannot hide a changed digest or algorithm.
    for field, value in [("digest", b"different"), ("digest_method", 3), ("transform", 2)]:
        records = [_native_file_record("before", 0, old), _native_file_record("after", 1, new)]
        records[1]["source_hash"][field] = value
        output = preprocess(reduce(records))["/windows/system32/test.dll"]
        equal([output["security_flags"], output["own_changed"]], [0x88, True])
    bad = _native_file_record("after", 0x201, new)
    raises(reduce, args = [[bad]], message = "ProcessFile flags")
    bad = _native_file_record("after", 1, new)
    raises(reduce, args = [[bad, dict(bad)]], message = "collision policy")


def test_native_file_overlap_reduction():
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    reduce = runtime["reduce_servicing_file_declarations"]
    identity = "Microsoft-Windows-Printing-AdminScripts.Resources, Culture=en-US, Version=10.0.26100.32860, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=%s, versionScope=nonSxS"
    ids = [bytes(identity % arch) for arch in ["wow64", "x86"]]
    tolerant = dict(strict_directories=False)
    # Captured from Server WCP bf948: last identity, operation, flags93/94/95.
    # Architecture changes do not coalesce FileInfo, even with equal hashes.
    for side, flags, expected in [("after", 1, [1, 8, 0x80, 0x20]), ("before", 0, [2, 8, 8, 1])]:
        for order in [ids, list(reversed(ids))]:
            records = [_native_file_record(side, flags, ident) for ident in order]
            result = reduce(records, collision_policy=tolerant)
            path = result["paths"]["/windows/system32/test.dll"]
            equal(path[side]["component_identity"], order[-1])
            equal([path[k] for k in ["operation", "security_flags", "directory_flags", "file_flags"]], expected)
            equal(len(result["sources"]), 2)
            equal(path["contributions"], records)
            # Content equality is not the policy: native selects in call order.
            records[1]["source_hash"]["digest"] = b"different"
            result = reduce(records, collision_policy=tolerant)
            selected = result["paths"]["/windows/system32/test.dll"][side]["source_key"]
            equal(result["sources"][selected][side]["hash"]["digest"], b"different")
            raises(reduce, args=[records], message="collision policy")
            raises(reduce, args=[records, (), dict(strict_directories=True)], message="collision policy")
            raises(reduce, args=[records, (), {}], message="collision policy")
    for flags in [8, 0x10, 0x11]:
        records = [_native_file_record("after", flags, ident) for ident in ids]
        raises(reduce, args=[records, (), tolerant], message="writable or link")
    records = [_native_file_record("after", 1, ident) for ident in ids]
    records[1]["attributes"] |= 2
    raises(reduce, args=[records, (), tolerant], message="mixed-metadata")
    repeated = _native_file_record("after", 1, ids[0])
    raises(reduce, args=[[repeated, dict(repeated)], (), tolerant], message="primary file source")


def test_native_link_primary_hash_sharing():
    policy = testing.module("@stdlib//windows/servicing:runtime.star")
    identity = b"Microsoft-Windows-explorer, Culture=neutral, Version=10.0.26100.9444, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS"
    records = [_native_file_record("before", 0, identity), _native_file_record("after", 1, identity)]
    for side, flags in [("before", 0x10), ("after", 0x10)]:
        link = _native_file_record(side, flags, identity, path = "/Windows/System32/linked.dll")
        link.update(source_hash = None, attributes = 7, descriptor = dict(sddl = "D:(A;;FA;;;SY)"))
        records.append(link)
    reduced = policy["reduce_servicing_file_declarations"](records)
    equal(len(reduced["sources"]), 1)
    output = policy["preprocess_servicing_file_declarations"](reduced)
    link = output["/windows/system32/linked.dll"]
    # Native link controls are clean with 7/7 states and ignored link
    # metadata, because the primary populated both shared FileInfo hashes.
    equal([link["after"]["state"], link["before"]["state"], link["security_flags"], link["directory_flags"], link["file_flags"], link["own_changed"]], [7, 7, 8, 0x88, 7, False])
    equal([link["before"]["attributes"], link["after"]["attributes"], link["after"]["descriptor"]], [0x80, 0x80, None])
    graph = policy["preprocess_servicing_path_hierarchy"]({}, output)
    equal(graph["/"]["subtree_changed"], False)
    records[1]["source_hash"]["digest"] = b"updated"
    graph = policy["preprocess_servicing_path_hierarchy"]({}, policy["preprocess_servicing_file_declarations"](policy["reduce_servicing_file_declarations"](records)))
    equal(graph["/"]["subtree_changed"], True)
    equal(graph["/windows/system32/linked.dll"]["own_changed"], True)



def test_native_selected_file_hash():
    select = testing.module("@stdlib//windows/servicing:runtime.star")["select_servicing_file_hash"]
    digest_text = "o6xi/UzfYZp8U/cco/5ftC9yAgl1Zw/ymv42A/ZBao4="
    body = '<file name="tar.exe"><hash xmlns="urn:schemas-microsoft-com:asm.v2" xmlns:d="http://www.w3.org/2000/09/xmldsig#"><d:Transforms><d:Transform Algorithm="urn:schemas-microsoft-com:HashTransforms.Identity"/></d:Transforms><d:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha256"/><d:DigestValue>%s</d:DigestValue></hash></file>' % digest_text
    tree = directory()
    xml = '<assembly xmlns="urn:schemas-microsoft-com:asm.v3">%s%s</assembly>' % (_identity("sample"), body)
    tree.write("/manifest", xml)
    # Native CmsGetFileHashInformation returned exactly method 2, transform
    # 1 and these 32 decoded bytes in the direct parsed-structure control.
    file = windows.assembly_manifest(tree.find("/manifest")).files[0]
    equal(select(file), dict(digest_method = 2, transform = 1, digest = binary.decode(digest_text, "base64")))
    tree.write("/dual", xml.replace('name="tar.exe"', 'name="tar.exe" hash="3316ab326411981bd20925f0591c26bc99126437" hashalg="SHA1"'))
    equal(select(windows.assembly_manifest(tree.find("/dual")).files[0]), select(file))
    tree.write("/legacy", xml.replace('name="tar.exe"', 'name="tar.exe" hash="0011" hashalg="SHA1"'))
    raises(select, args = [windows.assembly_manifest(tree.find("/legacy")).files[0]], message = "hash shape")
    tree.write("/transform", xml.replace("HashTransforms.Identity", "HashTransforms.Unknown"))
    raises(select, args = [windows.assembly_manifest(tree.find("/transform")).files[0]], message = "transform")


def test_native_boot_membership_and_file_inputs():
    policy = testing.module("@stdlib//windows/servicing:runtime.star")
    analyze = policy["analyze_servicing_file_paths"]
    membership = '<memberships><categoryMembership><id name="Microsoft.Windows.Categories" publicKeyToken="365143bb27e7ac8b" typeName="BootCritical" version="1.0.0.0"/></categoryMembership></memberships>'
    for text, expected in [(membership, True), (membership.replace("BootCritical", "BOOTCRITICAL"), True), (membership.replace("1.0.0.0", "1.0.0.1"), False), (membership.replace("BootCritical", "BootRecovery"), False), (membership.replace("365143bb27e7ac8b", "31bf3856ad364e35"), False), ("", False)]:
        records = analyze(_runtime_files(text + '<file name="sample.dll"/>'), "amd64")["records"]
        equal([records[0]["boot_critical"], records[0]["compress"], records[0]["load_from"]], [expected, True, None])
    raises(analyze, args = [_runtime_files('<file name="sample.dll" compress="maybe"/>'), "amd64"], message = "compress")
    prepare = policy["prepare_servicing_projected_files"]
    old = b"sample, Version=1.0.0.0, ProcessorArchitecture=amd64"
    new = b"sample, Version=1.0.0.1, ProcessorArchitecture=amd64"
    records = [dict(side = side, component_identity = identity, name = "sample.dll", compress = False, load_from = None, boot_critical = True, writable_type = None) for side, identity in [("before", old), ("after", new)]]
    links = [dict(record, kind = "link") for record in records]
    security = [dict(record, descriptor = dict(sddl = "(inherit)")) for record in records]
    hashes = {(identity, "sample.dll"): dict(digest_method = 2, transform = 1, digest = b"hash") for identity in [old, new]}
    resolved = dict(records = records, links = links, unresolved = [dict(reason = "missing destination")], unprojected = [dict(name = "retained.dll")])
    ordinary = dict(enumerate_children = False, immutable_primaries = True, compression_mode = 1)
    result = prepare(resolved, security, hashes, ordinary)
    # Captured native old/new primary flags differ from old/new link flags:
    # only the primary receives immutable bit1; only new gets boot bit2.
    equal([r["process_flags"] for r in result["records"]], [0x40, 0x43, 0x50, 0x52])
    equal([r["source_hash"] for r in result["records"][2:]], [None, None])
    equal([r["descriptor"] for r in result["records"][2:]], [None, None])
    equal(result["unresolved"], resolved["unresolved"])
    equal(result["unprojected"], resolved["unprojected"])
    result["unresolved"].append("control")
    equal(len(resolved["unresolved"]), 1)
    equal([r["process_flags"] for r in prepare(resolved, security, hashes, dict(ordinary, immutable_primaries = False))["records"]], [0x40, 0x42, 0x50, 0x52])
    records[1]["writable_type"] = "systemData"
    equal(prepare(resolved, security, hashes, ordinary)["records"][1]["process_flags"], 0x4a)
    raises(prepare, args = [resolved, security[:1], hashes, ordinary], message = "exact file security")
    raises(prepare, args = [resolved, security, {(old, "sample.dll"): hashes[(old, "sample.dll")]}, ordinary], message = "exact file hash")
    raises(prepare, args = [resolved, security, hashes, dict(ordinary, enumerate_children = True)], message = "non-enumerating")
    records[1]["compress"] = True
    equal(prepare(resolved, security, hashes, ordinary)["records"][1]["process_flags"], 0x4a)
    equal(prepare(resolved, security, hashes, dict(ordinary, compression_mode = 2))["records"][1]["process_flags"], 0x6a)
    records[1]["compress"] = False
    records[1]["load_from"] = "external"
    raises(prepare, args = [resolved, security, hashes, ordinary], message = "external")


def test_native_compact_mode_configuration():
    select = testing.module("@stdlib//windows/servicing:runtime.star")["servicing_file_compression_policy"]
    for typ, value, mode in [("REG_DWORD", 0, 1), ("REG_DWORD", 1, 2), ("REG_DWORD", 2, 2), ("REG_SZ", "1", 1), ("REG_BINARY", b"1234", 1)]:
        hive = windows.hive(windows.hive_from_patches("SYSTEM", [dict(key = "/Setup", name = "cOmPaCt", type = typ, value = value)]))
        equal(select(hive)["compression_mode"], mode)
    equal(select(windows.hive(windows.hive_from_patches("SYSTEM", []))), dict(compression_mode = 1, compact_enabled = False, compact_origin = "default"))



def test_native_dual_mode_source_only_files():
    policy = testing.module("@stdlib//windows/servicing:runtime.star")
    # WCP 26100.9441 DoComponentOperation 5f734 keeps the projection byte
    # zero for a dual-mode identity; InstallComponent bc282 calls
    # ProcessUnprojectedFile and returns before the runtime-link loop.
    body = '<file name="driver.sys" destinationPath="$(runtime.system32)\\drivers"><link destination="$(runtime.system32)\\alias.sys"/></file><file name="store.dat"/><directories><directory destinationPath="$(runtime.windows)\\DriverDirectory"/></directories>'
    fixture = _runtime_files(body)
    change = fixture["transitions"][0]
    old = b"sample, Culture=neutral, Type=dualModeDriver, Version=1.0.0.0, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, VersionScope=nonSxS"
    new = bytes(str(old).replace("1.0.0.0", "1.0.1.0"))
    change.update(before=change["after"], component_identities=dict(before=old, after=new))
    paths = policy["analyze_servicing_file_paths"](fixture, "amd64")
    # There is deliberately no runtime-root map: none of these declarations
    # may require destination resolution in the ordinary file installer.
    resolved = policy["resolve_servicing_file_paths"](paths, {})
    equal(resolved["records"], [])
    equal(resolved["links"], [])
    equal(resolved["unresolved"], [])
    equal(len(resolved["unprojected"]), 4)
    equal(policy["analyze_servicing_directories"](fixture, "amd64"), [])
    # Independent authorization may resolve declared destinations, but only
    # an actual native driver output can consume these candidates.
    declared = dict(paths, records=[r for r in paths["records"] if r["directory_id"] != None])
    roots = dict(source_roots={37: "C:"+chr(92)+"Windows"+chr(92)+"System32"}, context=policy["offline_servicing_path_context"]("C:"+chr(92)+"Windows", "/Windows"))
    candidates = policy["resolve_servicing_file_paths"](declared, roots, driver_projection_candidates=True)
    equal([r["destination"] for r in candidates["records"]], ["/Windows/System32/drivers/driver.sys"]*2)
    equal([r["destination"] for r in candidates["links"]], ["/Windows/System32/alias.sys"]*2)
    equal([r["component_identity"] for r in candidates["records"]], [old,new])
    equal(candidates["unresolved"], [])
    hashes = {(identity, name): dict(digest_method=2, transform=1, digest=b"x"*32) for identity in [old,new] for name in ["driver.sys", "store.dat"]}
    inputs = policy["prepare_servicing_unprojected_files"](resolved, hashes, dict(enumerate_children=False, compression_mode=1))
    reduced = policy["reduce_servicing_file_declarations"]([], inputs)
    equal(reduced["paths"], {})
    equal(len(reduced["sources"]), 2)
    for source in reduced["sources"].values():
        equal(source["before"]["component_identity"], old)
        equal(source["after"]["component_identity"], new)
        equal(source["after"]["hash"]["digest"], b"x"*32)
    # Ordinary components still need real destination roots and retain their
    # explicit directory work. Driver identity, not filename, is decisive.
    change["component_identities"] = {side:bytes(str(identity).replace("Type=dualModeDriver, ", "")) for side,identity in [("before",old),("after",new)]}
    ordinary = policy["analyze_servicing_file_paths"](fixture, "amd64")
    raises(policy["resolve_servicing_file_paths"], args=[ordinary, dict(source_roots={})], message="unresolved runtime file directory")
    equal(len(policy["analyze_servicing_directories"](fixture, "amd64")), 2)

def test_native_unprojected_source_reduction():
    policy = testing.module("@stdlib//windows/servicing:runtime.star")
    old = b"Microsoft.Windows.GdiPlus, Culture=neutral, Type=win32, Version=1.0.26100.9444, PublicKeyToken=6595b64144ccf1df, ProcessorArchitecture=amd64"
    new = bytes(str(old).replace("9444", "9711"))
    records = [dict(side = side, component_identity = identity, name = "GdiPlus.dll", template = None, load_from = None, compress = True, managed_assembly = True) for side, identity in [("before", old), ("after", new)]]
    hashes = {(identity, "gdiplus.dll"): dict(digest_method = 2, transform = 1, digest = b"hash") for identity in [old, new]}
    prepare = policy["prepare_servicing_unprojected_files"]
    for mode, expected in [(1, [0, 1]), (2, [0x20, 0x21])]:
        inputs = prepare(dict(unprojected = records), hashes, dict(enumerate_children = False, compression_mode = mode))
        equal([r["process_flags"] for r in inputs], expected)
    reduce = policy["reduce_servicing_file_declarations"]
    reduced = reduce([], inputs)
    equal(reduced["paths"], {})
    equal(len(reduced["sources"]), 1)
    source = reduced["sources"].values()[0]
    equal([source[side]["hash"] for side in ["before", "after"]], [hashes[(old, "gdiplus.dll")], hashes[(new, "gdiplus.dll")]])
    # A declared runtime link uses hashes supplied by ProcessUnprojectedFile,
    # without inventing a projected primary for the underlying store file.
    links = [_native_file_record(side, 0x10, identity, name = "GdiPlus.dll") for side, identity in [("before", old), ("after", new)]]
    result = policy["preprocess_servicing_file_declarations"](reduce(links, inputs))
    equal(result["/windows/system32/test.dll"]["own_changed"], False)
    other_minor = [dict(r, component_identity = bytes(str(r["component_identity"]).replace("1.0.26100", "1.1.26100"))) for r in inputs]
    equal(len(reduce([], inputs + other_minor)["sources"]), 2)
    raises(reduce, args = [[], inputs + inputs], message = "collision policy")
    raises(reduce, args = [[], [dict(inputs[0], destination = "/wrong")]], message = "runtime destination")
    raises(reduce, args = [[], [dict(inputs[0], process_flags = 1)]], message = "ProcessUnprojectedFile flags")
    # The native marker scans the entire component, not only this file.
    analysis = policy["analyze_servicing_file_paths"](_runtime_files('<file name="managed.dll"><gac/></file><file name="sibling.dat"/>'), "amd64")
    equal([r["managed_assembly"] for r in analysis["records"]], [True, True])
    analysis = policy["analyze_servicing_file_paths"](_runtime_files('<file name="managed.dll"><gac xmlns="foreign"/></file><file name="sibling.dat"/>'), "amd64")
    equal([r["managed_assembly"] for r in analysis["records"]], [False, False])



def test_native_writable_projection_preservation():
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    decide = runtime["select_servicing_writable_file_action"]
    old = b"Microsoft-Windows-explorer, Culture=neutral, Version=10.0.26100.9444, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS"
    records = [_native_file_record("before", 0x48, old), _native_file_record("after", 0x48, bytes(str(old).replace("9444", "9711")))]
    # Independent native final-pass controls used these exact fixture contents;
    # the real PSModule full-CommitChanges controls also distinguish the same
    # unchanged versus modified destination outcomes. Never compare to new hash.
    records[0]["source_hash"]["digest"] = digest(b"old-fixture-file")
    records[1]["source_hash"]["digest"] = digest(b"new-fixture-file")
    reduced = runtime["reduce_servicing_file_declarations"](records)
    item = runtime["preprocess_servicing_file_declarations"](reduced)["/windows/system32/test.dll"]
    equal([item["security_flags"], item["directory_flags"], item["file_flags"]], [0xb8, 0xe8, 1])
    # Actual writable components supply explicit equal cached security descriptors.
    descriptor = dict(sddl = "O:SYG:SYD:(A;;FA;;;SY)")
    for record in records:
        record["descriptor"] = descriptor
    reduced = runtime["reduce_servicing_file_declarations"](records)
    item = runtime["preprocess_servicing_file_declarations"](reduced)["/windows/system32/test.dll"]
    sources = reduced["sources"]
    equal(decide(item, sources, b"old-fixture-file"), "replace")
    for contents in [b"modified-fixture-file", b"new-fixture-file", b""]:
        equal(decide(item, sources, contents), "preserve")
    raises(decide, args = [item, sources, None], message = "missing")
    raises(decide, args = [dict(item, operation = 1), sources, b"old-fixture-file"], message = "transition")
    key = item["before"]["source_key"]
    bad_primary = dict(sources[key]["before"], component_identity = b"unrelated")
    raises(decide, args = [item, {key: dict(sources[key], before = bad_primary)}, b"old-fixture-file"], message = "identity")
    bad_primary = dict(sources[key]["before"], hash = dict(records[0]["source_hash"], transform = 2))
    raises(decide, args = [item, {key: dict(sources[key], before = bad_primary)}, b"old-fixture-file"], message = "hash")


def test_native_file_commit_phase_selection():
    select = testing.module("@stdlib//windows/servicing:runtime.star")["select_servicing_file_commit_paths"]
    # Independent WCP281f4c probes stop before CommitFileChanges or immediately
    # after the file loop. No file operation or selection decision is hooked.
    for phase, flags, kind, selected in [
        (1, 0x98, "file", True),
        (1, 0x88, "file", False),
        (2, 0x98, "file", False),
        (2, 0x88, "file", True),
        (0, 0x98, "file", True),
        (1, 0x9c, "file", False),
        (1, 0x98, "directory", False),
    ]:
        node = dict(kind = kind, directory_flags = flags, subtree_changed = not bool(flags & 4))
        equal(select({"/x": node}, phase), ["/x"] if selected else [])
    # A mixture must partition without including clean files or directories.
    nodes = {
        "/early": dict(kind = "file", directory_flags = 0x98, subtree_changed = True),
        "/late": dict(kind = "file", directory_flags = 0x88, subtree_changed = True),
        "/clean": dict(kind = "file", directory_flags = 0x9c, subtree_changed = False),
        "/dir": dict(kind = "directory", directory_flags = 0x98, subtree_changed = True),
    }
    equal(select(nodes, 1), ["/early"])
    equal(select(nodes, 2), ["/late"])
    equal(select(nodes, 0), ["/early", "/late"])
    equal(nodes["/early"]["directory_flags"], 0x98)
    raises(select, args = [nodes, 3], message = "unsupported")
    raises(select, args = [{"/x": dict(kind = "file", directory_flags = 0x98)}, 1], message = "preprocessed")
    raises(select, args = [{"/x": dict(kind = "file", directory_flags = 256, subtree_changed = True)}, 1], message = "flags")


def test_native_filemap_actions():
    plan = testing.module("@stdlib//windows/servicing:runtime.star")["plan_servicing_filemap"]
    owner = [("", "Name", "Component"), ("", "Version", "10.0.26100.1")]
    doc = dict(path = "System32", root_selector = 1, identities = [owner], entries = [dict(name = "example.dll", display_name = "example.dll", flags = 0, identity = 0)])
    add = dict(name = "example.dll", operation = 1, state = 2, directory_flags = 0, file_flags = 1, before_identity = None, after_identity = owner)
    remove = dict(add, operation = 2, state = 0, after_identity = None)
    # Native282b74 boundary captures: records win regardless of residency;
    # empty resident removes; empty absent skips. No effects are implemented.
    for resident, nodes, operation in [(doc, [], "write"), (None, [add], "write"), (doc, [remove], "remove"), (None, [], "none")]:
        result = plan(resident, nodes, "/Windows/System32", "C:")
        equal(result["operation"], operation)
        equal(result["path"], "/Windows/WinSxS/FileMaps/$$_system32_21f9a9c4a2f8b514.cdf-ms")
        equal(result["directory_collisions"], [])
        if operation == "write":
            equal(windows.cdf_filemap(result["content"]), result["document"])
            equal(result["document"]["path"], "System32")
            equal(result["document"]["root_selector"], 1)
        else:
            equal(result["content"], None)
    root = dict(doc, path = "", root_selector = 2)
    result = plan(root, [], "/", "C:")
    equal(result["document"]["path"], r"\??\C:")
    equal(result["document"]["root_selector"], 0)
    equal(root["path"], "")
    equal(root["root_selector"], 2)
    equal(len(doc["entries"]), 1)
    raises(plan, args = [dict(doc, entries = []), [], "/", "C:"], message = "nonempty")
    raises(plan, args = [None, [], "/Windows/../other", "C:"], message = "canonical")


def test_runtime_source_exact_provenance():
    csi = testing.module("@stdlib//windows/servicing:components.star")
    bind = csi["bind_servicing_runtime_sources"]
    open_source = csi["open_servicing_runtime_source"]
    tree = directory()
    base = {"/image/Windows/WinSxS/Manifests": tree}
    old = b"Example, Culture=neutral, Version=10.0.1.0, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS"
    new = bytes(str(old).replace("10.0.1.0", "10.0.2.0"))
    sources = {"same-family": {}}
    manifests = {}
    paths = {}
    for side, identity, content in [("before", old, b"old"), ("after", new, b"new")]:
        stem = "fixture_%x" % windows.csi_identity_hash(identity)
        path = "/Windows/WinSxS/" + stem + "/nested/file.dll"
        tree.write("/image/Windows/WinSxS/Manifests/" + stem + ".manifest", b"metadata resolved separately")
        tree.write("/image" + path, content)
        base["/image" + path] = tree.find("/image" + path)
        manifests[str(identity).lower()] = True
        sources["same-family"][side] = dict(component_identity = identity, hash = dict(digest_method = 2, transform = 1, digest = crypto.hash("sha256", content)), record = dict(name = "nested" + chr(92) + "file.dll", attributes = 160))
        paths[side] = path
    payloads = dict(stages = {}, components = {})
    analysis = dict(resident_manifests = manifests)
    bindings = bind(base, "/image", payloads, analysis, sources)
    for side, expected in [("before", b"old"), ("after", b"new")]:
        binding = bindings[("same-family", side)]
        equal(binding["path"], paths[side])
        equal(open_source(base, payloads, binding).bytes(), expected)
    # Same-family identity cannot borrow another version's payload.
    base.pop("/image" + paths["after"])
    raises(bind, args = [base, "/image", payloads, analysis, sources], message = "missing exact runtime store source")
    tree.write("/image" + paths["after"], b"old")
    base["/image" + paths["after"]] = tree.find("/image" + paths["after"])
    raises(open_source, args = [base, payloads, bindings[("same-family", "after")]], message = "does not match exact declaration")
    raises(bind, args = [base, "/image", payloads, dict(resident_manifests = {}), sources], message = "exact component provenance")
    # Hash suffix alone cannot choose between two store stems.
    h = windows.csi_identity_hash(old)
    tree.write("/image/Windows/WinSxS/Manifests/collision_%x.manifest" % h, b"other")
    raises(bind, args = [base, "/image", payloads, analysis, sources], message = "ambiguous runtime store stem")


def test_native_immutable_inherit_selection():
    build = testing.module("@stdlib//windows/servicing:runtime.star")["build_servicing_immutable_file_security_request"]
    # Full native CommitFileChanges with actual System32 parent: paired
    # flags b8 and new-only e0 both emit this independent 168-byte request.
    parent = binary.decode("0100049414000000340000000000000054000000010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487020054010d00000000002800ff011f00010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487000a280000000010010600000000000550000000b589fb381984c2cb5c6c236d5700776ec002648700001400bf011300010100000000000512000000000b14000000001001010000000000051200000000001800bf01130001020000000000052000000020020000000b1800000000100102000000000005200000002002000000001800a900120001020000000000052000000021020000000b1800000000a001020000000000052000000021020000000b14000000001001010000000000030000000000001800a9001200010200000000000f0200000001000000000b1800000000a0010200000000000f020000000100000000001800a9001200010200000000000f0200000002000000000b1800000000a0010200000000000f0200000002000000", "hex")
    expected = binary.decode("01001480900000009c000000000000001400000002007c000500000000101400ff011f0001010000000000051200000000101800ff011f000102000000000005200000002002000000101800a90012000102000000000005200000002102000000101800a9001200010200000000000f020000000100000000101800a9001200010200000000000f0200000002000000010100000000000512000000010100000000000512000000", "hex")
    for operation, flags in [(3, 0xb8), (1, 0xe0)]:
        item = dict(operation = operation, own_changed = True, security_flags = flags, after = dict(state = 2, process_flags = 0x41, descriptor = None))
        result = build(item, parent)
        equal(result["security_information"], 0x3000000f)
        equal(windows.security_descriptor_parts(result["descriptor"]), windows.security_descriptor_parts(expected))
        boot = dict(item, after = dict(item["after"], process_flags = 0x43))
        equal(build(boot, parent), result)
        raises(build, args = [dict(item, security_flags = 0x88 if operation == 3 else 0xc0), parent], message = "selection disagrees")
        raises(build, args = [dict(item, after = dict(item["after"], state = 1)), parent], message = "transition")
        raises(build, args = [dict(item, own_changed = False), parent], message = "transition")
        raises(build, args = [dict(item, after = dict(item["after"], process_flags = 0x61)), parent], message = "flags")


def test_native_staged_file_security_request():
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    build = runtime["build_servicing_staged_file_security_request"]
    # Exact base component-store parent; native WCP 1c8f38 to NtSetSecurityObject.
    # Changing only the identity type to driverUpdate changes SYSTEM to FA.
    parent = binary.decode("0100149c14000000340000000000000054000000010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487020018010b00000000032800ff011f00010600000000000550000000b589fb381984c2cb5c6c236d5700776ec002648700001800a900120001020000000000052000000020020000000b1800000000a00102000000000005200000002002000000001400a9001200010100000000000512000000000b1400000000a001010000000000051200000000001800a900120001020000000000052000000021020000000b1800000000a00102000000000005200000002102000000001800a9001200010200000000000f0200000001000000000b1800000000a0010200000000000f020000000100000000001800a9001200010200000000000f0200000002000000000b1800000000a0010200000000000f0200000002000000", "hex")
    goldens = [
        "01001490b8000000d800000000000000140000000200a4000600000000002800ff011f00010600000000000550000000b589fb381984c2cb5c6c236d5700776ec002648700001800a90012000102000000000005200000002002000000001400a900120001010000000000051200000000001800a90012000102000000000005200000002102000000001800a9001200010200000000000f020000000100000000001800a9001200010200000000000f0200000002000000010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487",
        "01001490b8000000d800000000000000140000000200a4000600000000002800ff011f00010600000000000550000000b589fb381984c2cb5c6c236d5700776ec002648700001800a90012000102000000000005200000002002000000001400ff011f0001010000000000051200000000001800a90012000102000000000005200000002102000000001800a9001200010200000000000f020000000100000000001800a9001200010200000000000f0200000002000000010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487",
    ]
    for driver, golden in zip([False, True], goldens):
        result = build(parent, driver = driver)
        equal(result["security_information"], 0x9000001f)
        equal(windows.security_descriptor_parts(result["descriptor"]), windows.security_descriptor_parts(binary.decode(golden, "hex")))
        raises(runtime["assign_servicing_file_security"], args = [parent, result], message = "information mask")
        # Native SeSetSecurityDescriptorInfoEx, flags 0x4000, clears an old
        # medium label with mask 0x9000001f but retains it with 0x9000000f.
        old = windows.compile_sddl("O:SYG:SYD:(A;;FA;;;SY)S:(ML;;0x1;;;S-1-16-8192)")
        staged = runtime["assign_servicing_staged_file_security"](old, result)
        equal(windows.security_descriptor_parts(staged), windows.security_descriptor_parts(binary.decode(golden, "hex")))
        ordinary = dict(result, security_information = result["security_information"] & ~0x10)
        retained = runtime["assign_servicing_file_security"](old, ordinary)
        equal(windows.security_descriptor_parts(retained)["sacl"], windows.security_descriptor_parts(old)["sacl"])
        raises(runtime["assign_servicing_staged_file_security"], args = [old, ordinary], message = "information mask")
        raises(runtime["assign_servicing_staged_file_security"], args = [old, dict(result, descriptor = old)], message = "NULL SACL")
    raises(build, args = [None], message = "actual parent")
    raises(build, args = [parent, "driverUpdate"], message = "boolean")


def test_native_filemap_collision_policy():
    runtime = testing.module("@stdlib//windows/servicing:runtime.star")
    select = runtime["servicing_filemap_collision_policy"]
    status = runtime["servicing_filemap_collision_status"]
    def h(root, path, values):
        return windows.hive(windows.hive_from_patches(root, [dict(key = path, name = name, type = typ, value = value) for name, typ, value in values]))
    def check(policy, store):
        return select(h("SOFTWARE", "/Microsoft/Windows/CurrentVersion/Policies/Servicing", policy), h("COMPONENTS", "/Configuration", store))
    ordinary = check([], [])
    strict = check([], [("SingleResourceOwnership", "REG_DWORD", 2)])
    equal(ordinary["single_resource_ownership"], dict(value = 0, origin = "default"))
    equal(strict["strict_directories"], True)
    # Native CommitChanges final block 281d66..281f19, not a status mock:
    # empty=0, 19 tolerant=0, 19 strict=80188316, file=80188306.
    equal(status(ordinary, 0, 0), 0)
    equal(status(ordinary, 0, 19), 0)
    equal(status(strict, 0, 19), 0x80188316)
    equal(status(ordinary, 1, 0), 0x80188306)
    equal(status(strict, 1, 19), 0x80188306)
    store = [("SingleResourceOwnership", "REG_DWORD", 1)]
    equal(check([("singleresourceownership", "REG_DWORD", 0)], store)["strict_directories"], False)
    equal(check([("SingleResourceOwnership", "REG_SZ", "0")], store)["strict_directories"], True)
    equal(check([], [("SmiHiveUpdates", "REG_DWORD", 0x800)])["strict_directories"], True)
    equal(check([], [("SmiHiveUpdates", "REG_DWORD", 0x80)])["strict_directories"], False)
    equal(check([("SmiHiveUpdates", "REG_DWORD", 0)], [("SmiHiveUpdates", "REG_DWORD", 0x800)])["strict_directories"], False)
    for invalid in [-1, True, 1 << 64]:
        raises(status, args = [ordinary, invalid, 0], message = "count")
    raises(status, args = [dict(strict_directories = 1), 0, 0], message = "boolean")


def test_native_paired_registry_dword_preservation():
    select = testing.module("@stdlib//windows/servicing:runtime.star")["select_servicing_paired_registry_dword_action"]
    old = dict(type = 4, raw = b"\x01\x00\x00\x00")
    new = dict(type = 4, raw = b"\x02\x00\x00\x00")
    modified = dict(type = 4, raw = b"\x09\x00\x00\x00")
    wrong_type = dict(type = 3, raw = old["raw"])
    # Native 187c0 -> 143f7c -> 10aba4 with real SIL/NT key boundary:
    # mutable unchanged-current writes; modified, missing or wrong-type
    # current values survive. Ordinary changed values write unconditionally.
    equal(select(old, new, old, True), "set")
    equal(select(old, new, modified, True), "preserve")
    equal(select(old, new, None, True), "preserve")
    equal(select(old, new, wrong_type, True), "preserve")
    equal(select(old, new, modified), "set")
    equal(select(old, new, None), "set")
    # Native equal-declaration commit returns in 76 instructions, no query/set.
    equal(select(old, old, modified), "none")
    equal(select(old, old, None), "none")
    raises(select, args = [old, new, None, 1], message = "boolean")
    raises(select, args = [old, dict(type = 4, raw = b"short"), None], message = "DWORD")
    raises(select, args = [wrong_type, new, None], message = "DWORD")
    raises(select, args = [old, new, dict(type = True, raw = b"")], message = "current")


def test_native_paired_registry_raw_preservation():
    select = testing.module("@stdlib//windows/servicing:runtime.star")["select_servicing_paired_registry_value_action"]
    sz = dict(type = 1, raw = b"O\x00l\x00d\x00\x00\x00")
    new = dict(type = 1, raw = b"N\x00e\x00w\x00 \x00l\x00o\x00n\x00g\x00e\x00r\x00\x00\x00")
    # Native full CreateValuesInKey: exact matches set (1987 steps), case
    # differences preserve (1168), missing terminator/length preserve (1161).
    equal(select(sz, new, sz, True), "set")
    equal(select(sz, new, dict(type = 1, raw = b"o\x00l\x00d\x00\x00\x00"), True), "preserve")
    equal(select(sz, new, dict(type = 1, raw = sz["raw"][:-2]), True), "preserve")
    equal(select(sz, new, None, True), "preserve")
    equal(select(sz, sz, None, True), "none")
    for kind, old_raw, new_raw in [(2, sz["raw"], new["raw"]), (3, b"\x01\x02", b"\x03\x04\x05"), (11, b"\x00\x00\x00\x00\x00\x00\x00\x01", b"\x00\x00\x00\x00\x00\x00\x00\x02")]:
        before, after = dict(type = kind, raw = old_raw), dict(type = kind, raw = new_raw)
        equal(select(before, after, before, True), "set")
        equal(select(before, after, dict(type = kind, raw = b"\x09"), True), "preserve")
        equal(select(before, before, None, True), "none")
    for kind in [0xffff0012, 0x00020004, 0x00100000]:
        before, after = dict(type = kind, raw = b"\x01\x02"), dict(type = kind, raw = b"\x03\x04\x05")
        equal(select(before, after, before, True), "set")
        equal(select(before, after, dict(type = kind, raw = b"\x09"), True), "preserve")
    none = dict(type = 0, raw = b"")
    equal(select(none, none, None, True), "none")
    raises(select, args = [dict(type = 0, raw = b"\x01"), none, None], message = "REG_NONE")
    # Native MULTI_SZ modifies even a user-modified current list: exclude it.
    raises(select, args = [dict(type = 7, raw = sz["raw"]), new, None], message = "supported")
    raises(select, args = [dict(type = 1.0, raw = sz["raw"]), new, None], message = "supported")
    raises(select, args = [dict(type = 1, raw = b"x"), new, None], message = "UTF-16")
    raises(select, args = [dict(type = 11, raw = b"x"), new, None], message = "length")
    dword = dict(type = 4, raw = b"\x01\x00\x00\x00")
    binary_value = dict(type = 3, raw = dword["raw"])
    # Same bytes with a changed type are not a native preprocessing no-op.
    equal(select(dword, binary_value, dword), "set")
    equal(select(dword, binary_value, dword, True), "set")
    equal(select(dword, binary_value, binary_value, True), "preserve")


def test_native_paired_registry_multi_merge():
    select = testing.module("@stdlib//windows/servicing:runtime.star")["select_servicing_paired_registry_multi_action"]
    def value(entries):
        return dict(type = 7, raw = binary.encode("\x00".join(entries) + "\x00\x00", encoding = "utf16le"))
    # Golden results from native ProcessValue/preprocess/CreateValuesInKey.
    for before, after, current, want in [
        (["One"], ["Two"], ["One", "User"], ["User", "Two"]),
        (["One"], ["Two"], ["one"], ["one", "Two"]),
        (["One"], ["Two"], ["One", "One", "User", "Two", "Two"], ["One", "User", "Two", "Two"]),
        (["One", "One"], ["Two"], ["One", "One", "One", "User"], ["One", "User", "Two"]),
        (["One", "Keep"], ["Keep", "Two"], ["Keep", "User", "One", "Keep"], ["User", "Keep", "Two"]),
        (["One"], ["Two", "Two"], ["User"], ["User", "Two"]),
        (["One"], ["Two"], ["Two"], ["Two"]),
    ]:
        equal(select(before, after, value(current)), dict(action = "set", value = value(want)))
    equal(select(["One"], ["Two"], None), dict(action = "set", value = value(["Two"])))
    wrong = dict(type = 4, raw = b"\x01\x00\x00\x00")
    equal(select(["One"], ["Two"], wrong), dict(action = "set", value = value(["Two"])))
    equal(select(["One"], [], value(["One"])), dict(action = "delete"))
    equal(select(["One"], [], wrong), dict(action = "delete"))
    equal(select(["One"], [], None), dict(action = "none"))
    equal(select(["One"], ["One"], value(["User"])), dict(action = "none"))
    equal(select(["One"], ["A", "B"], value(["One", "User"]), "prepend"), dict(action = "set", value = value(["A", "B", "User"])))
    equal(select(["One"], ["A", "B"], value(["B", "User", "One", "A"]), "prepend"), dict(action = "set", value = value(["B", "User", "A"])))
    equal(select(["One"], ["Two"], value(["User"]), "replace"), dict(action = "set", value = value(["Two"])))
    equal(select(["One"], [], value(["User"]), "replace"), dict(action = "set", value = value([])))
    equal(select(["One"], ["Two"], value(["User"]), "replace", True), dict(action = "preserve"))
    equal(select(["One"], ["Two"], value(["One"]), "replace", True), dict(action = "set", value = value(["Two"])))
    equal(select(["One"], ["Two"], None, "replace", True), dict(action = "preserve"))
    raises(select, args = [["One"], ["Two"], None, "unknown"], message = "hint")
    raises(select, args = [["One"], ["Two"], None, "append", 1], message = "boolean")
    raises(select, args = [["One"], ["Two", "Two"], None, "replace"], message = "arbitration")
    raises(select, args = [[""], ["Two"], None], message = "nonempty")
    raises(select, args = [["One"], ["Two"], dict(type = 7, raw = b"x")], message = "terminated")
    raises(select, args = [["One"], ["Two"], value(["A", "", "B"])], message = "interior")


def test_native_single_registry_value_actions():
    select = testing.module("@stdlib//windows/servicing:runtime.star")["select_servicing_registry_value_action"]
    declared = dict(type = 4, raw = b"\x02\x00\x00\x00")
    modified = dict(type = 4, raw = b"\x09\x00\x00\x00")
    # Native single add writes without query even if mutable and modified.
    # Single remove deletes without query; missing delete status is tolerated.
    equal(select(None, declared, modified, True), "set")
    equal(select(None, declared, None, True), "set")
    equal(select(declared, None, modified, True), "delete")
    equal(select(declared, None, None, True), "delete")
    for kind, raw, action in [(1, b"N\x00e\x00w\x00\x00\x00", "set"), (3, b"\x01\x02", "set"), (11, b"\x00\x00\x00\x00\x00\x00\x00\x01", "delete")]:
        value = dict(type = kind, raw = raw)
        equal(select(None if action == "set" else value, value if action == "set" else None, dict(type = kind, raw = b"\x09"), True), action)
    raises(select, args = [None, None, None], message = "declaration")
    raises(select, args = [None, dict(type = 7, raw = b""), None], message = "supported")


def test_native_registry_machine_redirection():
    redirect = testing.module("@stdlib//windows/servicing:runtime.star")["redirect_servicing_machine_registry_path"]
    root = "\\Registry\\Machine\\"
    def path(value):
        return root + value.replace("/", "\\")
    # Native TranslateWowRegistryPath (14c) and real SetCurrentComponent ->
    # MakePathRedirectedIfRequired controls. SYSTEM/shared branches do not
    # acquire a WOW6432Node; software and selected COM subtrees do.
    for source, destination in [
        ("SYSTEM/CurrentControlSet/Services/Fixture", "SYSTEM/CurrentControlSet/Services/Fixture"),
        ("Software/Fixture", "Software/WOW6432Node/Fixture"),
        ("Software", "Software/WOW6432Node"),
        ("Software/Classes", "Software/Classes"),
        ("Software/Classes/Fixture", "Software/Classes/Fixture"),
        ("Software/Classes/CLSID/{fixture}", "Software/Classes/WOW6432Node/CLSID/{fixture}"),
        ("Software/Classes/Interface/{fixture}", "Software/Classes/WOW6432Node/Interface/{fixture}"),
        ("Software/Classes/CLSIDx", "Software/Classes/CLSIDx"),
        ("Software/ClientsExtra", "Software/WOW6432Node/ClientsExtra"),
        ("Software/Microsoft/Windows/CurrentVersion/Run", "Software/WOW6432Node/Microsoft/Windows/CurrentVersion/Run"),
        ("Software/Microsoft/Windows/CurrentVersion/Policies/Fixture", "Software/Microsoft/Windows/CurrentVersion/Policies/Fixture"),
        ("Software/Wow6432Node/Fixture", "Software/Wow6432Node/Fixture"),
        ("Software/Wow6432Node/Classes/Fixture", "Software/Classes/Fixture"),
        ("Software/Wow6432Node/Classes/CLSID/{fixture}", "Software/Classes/WOW6432Node/CLSID/{fixture}"),
        ("Software/Classes/Wow6432Node/CLSID/{fixture}", "Software/Classes/Wow6432Node/CLSID/{fixture}"),
    ]:
        equal(redirect(path(source), "x86"), path(destination))
        equal(redirect(path(source), "wow64"), path(destination))
        equal(redirect(path(source), "amd64"), path(source))
    raises(redirect, args = ["HKEY_LOCAL_MACHINE\\Software", "x86"], message = "NT machine")
    raises(redirect, args = [path("Software/Wow6432Node/Wow6432Node/Fixture"), "x86"], message = "placement")
    raises(redirect, args = [path("Software/Fixture"), "arm64"], message = "architecture")


def test_native_registry_machine_roots():
    resolve = testing.module("@stdlib//windows/servicing:runtime.star")["resolve_servicing_machine_registry_key"]
    equal(resolve("HKEY_LOCAL_MACHINE\\Software\\Fixture", "amd64"), "\\Registry\\Machine\\Software\\Fixture")
    equal(resolve("HKLM\\Software\\Fixture", "amd64"), "\\Registry\\Machine\\Software\\Fixture")
    equal(resolve("HKEY_CLASSES_ROOT\\CLSID\\{fixture}", "amd64"), "\\Registry\\Machine\\SOFTWARE\\Classes\\CLSID\\{fixture}")
    equal(resolve("HKCR\\Fixture", "amd64"), "\\Registry\\Machine\\SOFTWARE\\Classes\\Fixture")
    equal(resolve("HKCR\\CLSID\\{fixture}\\", "wow64"), "\\Registry\\Machine\\SOFTWARE\\Classes\\WOW6432Node\\CLSID\\{fixture}")
    raises(resolve, args = ["HKEY_CURRENT_USER\\Software", "amd64"], message = "non-machine")
    raises(resolve, args = ["HKLM\\$(unknown)", "amd64"], message = "expanded")



def test_native_registry_admission():
    analyze = testing.module("@stdlib//windows/servicing:runtime.star")["analyze_servicing_registry_declarations"]
    files = directory()
    transitions = []
    for name, kind, sides in [("dual", "dualModeDriver", ["before", "after"]), ("removed", "dualModeDriver", ["before"]), ("driver", "driverUpdate", ["after"]), ("case", "DualModeDriver", ["after"]), ("ordinary", "", ["before", "after"])]:
        identities = {}
        manifests = {"before": None, "after": None}
        for side in sides:
            version = "10.0.26100.9441" if side == "before" else "10.0.26100.9711"
            identity = bytes(name + ", Culture=neutral, " + ("Type=" + kind + ", " if kind else "") + "Version=" + version + ", PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS")
            path = "/" + name + side
            descriptor = "O:SYG:SYD:(A;;KR;;;SY)" if side == "before" else "O:SYG:SYD:(A;;KA;;;SY)"
            files.write(path, r'<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="%s" %s version="%s"/><file name="kept.dll"/><registryKeys><registryKey keyName="HKEY_LOCAL_MACHINE\Software\Fixture" owner="true"><registryValue name="" valueType="REG_SZ" value="$(runtime.windows)"/><securityDescriptor name="fixture"/></registryKey><registryKey keyName="HKEY_LOCAL_MACHINE\Software\Empty"/></registryKeys><trustInfo><security><accessControl><securityDescriptorDefinitions><securityDescriptorDefinition name="fixture" sddl="%s"/></securityDescriptorDefinitions></accessControl></security></trustInfo></assembly>' % (name, 'type="%s"' % kind if kind else "", version, descriptor))
            manifests[side] = files.find(path)
            identities[side] = identity
        transitions.append(dict(identity = identity, component_identities = identities, **manifests))
    runtime = dict(transitions = transitions)
    result = analyze(runtime, 256)
    equal([t["identity"] for t in result["bypassed_transitions"]], [transitions[0]["identity"], transitions[1]["identity"]])
    equal(len(result["values"]), 4)
    equal(len(result["keys"]), 8)
    equal(result["dual_mode_driver_primitives"], False)
    # Empty keys, key policy, security and unexpanded text are not lost just
    # because no value write can yet be planned. Exact side provenance survives.
    equal(result["values"][-2]["identity"], transitions[-1]["component_identities"]["before"])
    equal(result["values"][-1]["identity"], transitions[-1]["component_identities"]["after"])
    equal(result["values"][0]["attributes"]["value"], "$(runtime.windows)")
    equal(result["keys"][0]["key_attributes"]["owner"], "true")
    equal([n.name for n in result["keys"][0]["node"].children], ["registryValue", "securityDescriptor"])
    equal(result["keys"][1]["node"].children, [])
    equal(result["keys"][1]["descriptor"], None)
    equal(result["keys"][-4]["descriptor"]["sddl"], "O:SYG:SYD:(A;;KR;;;SY)")
    equal(result["keys"][-2]["descriptor"]["sddl"], "O:SYG:SYD:(A;;KA;;;SY)")
    # This gate must not mutate the shared transition set: its dual-mode files
    # and its separate driver processing remain required.
    equal(len(runtime["transitions"]), 5)
    equal(binary.xml(result["bypassed_transitions"][0]["after"]).root.children[1].name, "file")
    enabled = analyze(runtime, 0x133)
    equal(len(enabled["values"]), 7)
    equal(enabled["bypassed_transitions"], [])
    equal(len(analyze(runtime, 0x32)["values"]), 4)
    raises(analyze, args = [runtime, True], message = "uint32")
    raises(analyze, args = [runtime, 0x100000000], message = "uint32")
    bad = dict(transitions[0], component_identities = {"before": transitions[0]["component_identities"]["before"], "after": transitions[2]["component_identities"]["after"]})
    raises(analyze, args = [dict(transitions = [bad]), 256], message = "consistent identity types")

def test_native_registry_security_comparison():
    compare = testing.module("@stdlib//windows/servicing:runtime.star")["servicing_registry_security_matches_manifest"]
    # Independent pinned WCP flags-1 controls. Using file generic mappings or
    # symmetric byte equality here gives wrong answers for real key security.
    for old, new, expected in [
        ("O:SYG:SYD:(A;;GA;;;SY)S:", "O:SYG:SYD:(A;;KA;;;SY)S:", True),
        ("O:SYG:SYD:(A;;GA;;;SY)S:", "O:SYG:SYD:(A;;FA;;;SY)S:", False),
        ("O:SYG:SYD:(A;;GR;;;SY)S:", "O:SYG:SYD:(A;;KR;;;SY)S:", True),
        ("O:SYG:SYD:(A;ID;KA;;;SY)S:", "O:SYG:SYD:S:", True),
        ("O:SYG:SYD:(A;ID;KA;;;SY)S:", "O:SYG:SYD:(A;ID;KA;;;SY)S:", False),
        ("O:SYG:SYD:P(A;;KA;;;SY)S:", "O:SYG:SYD:(A;;KA;;;SY)S:", False),
    ]:
        equal(compare(windows.compile_sddl(old), windows.compile_sddl(new)), expected)
    equal(compare(None, None), True)
    equal(compare(None, windows.compile_sddl("O:SYG:SYD:")), False)
    raises(compare, args = [b"truncated", windows.compile_sddl("O:SYG:SYD:")], message = "descriptor")


def test_native_registry_security_requests():
    build = testing.module("@stdlib//windows/servicing:runtime.star")["build_servicing_registry_security_request"]
    parent = "O:SYG:SYD:P(A;CI;KA;;;SY)"
    labeled_parent = parent + "S:(ML;CI;1;;;S-1-16-8192)"
    # Independently captured NtSetSecurityObject requests from WCP 83800,
    # native NTDLL inheritance, explicit SYSTEM token and parent query fixture.
    # Compare component bytes, not the serializer's choice of component offsets.
    cases = [
        ("O:SYG:SYD:P(A;;KA;;;SY)", parent, 0x9000000f, "0100049f300000003c000000000000001400000002001c0001000000000014003f000f00010100000000000512000000010100000000000512000000010100000000000512000000"),
        ("D:P(A;CI;GA;;;BU)", parent, 0x9000000f, "0100049f4c0000005800000000000000140000000200380002000000000018003f000f0001020000000000052000000021020000000a18000000001001020000000000052000000021020000010100000000000512000000010100000000000512000000"),
        ("O:SYG:SYD:(A;;KA;;;SY)S:(ML;;;;;LW)", labeled_parent, 0x3000001f, "0100148f600000006c000000140000003000000002001c000100000011001400000000000101000000000010001000000200300002000000000014003f000f00010100000000000512000000001214003f000f00010100000000000512000000010100000000000512000000010100000000000512000000"),
        ("O:SYG:SYD:(A;;KA;;;SY)", labeled_parent, 0x3000000f, "0100148f600000006c000000140000003000000002001c000100000011121400010000000101000000000010002000000200300002000000000014003f000f00010100000000000512000000001214003f000f00010100000000000512000000010100000000000512000000010100000000000512000000"),
        ("D:S:P(AU;SA;KR;;;WD)", parent, 0x6000000f, "010014af4c00000058000000140000003000000002001c0001000000024014001900020001010000000000010000000002001c0001000000001214003f000f00010100000000000512000000010100000000000512000000010100000000000512000000"),
        ("D:S:(ML;;;;;LW)(AU;SA;KR;;;WD)", parent, 0x3000001f, "0100148f600000006c000000140000004400000002003000020000000240140019000200010100000000000100000000110014000000000001010000000000100010000002001c0001000000001214003f000f00010100000000000512000000010100000000000512000000010100000000000512000000"),
        ("D:PS:P", parent, 0xc000000f, "010014bf2400000030000000140000001c00000002000800000000000200080000000000010100000000000512000000010100000000000512000000"),
        ("D:S:P", labeled_parent, 0x6000000f, "010014af3800000044000000140000001c000000020008000000000002001c0001000000001214003f000f00010100000000000512000000010100000000000512000000010100000000000512000000"),
    ]
    for sddl in ["D:S:", "D:S:NO_ACCESS_CONTROL"]:
        cases.append((sddl, parent, 0x3000000f, "0100048f300000003c000000000000001400000002001c0001000000001214003f000f00010100000000000512000000010100000000000512000000010100000000000512000000"))
        cases.append((sddl, parent + "S:(AU;CISA;KR;;;WD)", 0x3000000f, "0100148f4c00000058000000140000003000000002001c0001000000025214001900020001010000000000010000000002001c0001000000001214003f000f00010100000000000512000000010100000000000512000000010100000000000512000000"))
    for sddl, ancestor, info, expected in cases:
        request = build(windows.compile_sddl(sddl), windows.compile_sddl(ancestor))
        equal(request["security_information"], info)
        equal(windows.security_descriptor_parts(request["descriptor"]), windows.security_descriptor_parts(binary.decode(expected, "hex")))
    for sddl in ["D:S:(ML;;;;;LW)(ML;;;;;LW)", "D:S:(ML;CI;;;;LW)"]:
        raises(build, args = [windows.compile_sddl(sddl), windows.compile_sddl(parent)], message = "mandatory label")
    raises(build, args = [windows.compile_sddl("O:SYG:SY"), windows.compile_sddl(parent)], message = "non-NULL DACL")
    null_sacl = windows.compile_sddl("D:S:NO_ACCESS_CONTROL")
    patched = binary.builder(limit = 65536)
    patched.append(null_sacl)
    patched.patch_u16le(2, binary.read_u16le(null_sacl, 2) | 0x2000)
    raises(build, args = [patched.bytes(), windows.compile_sddl(parent)], message = "protected NULL")


def test_native_registry_default_and_deferred_requests():
    build = testing.module("@stdlib//windows/servicing:runtime.star")["build_servicing_registry_security_request"]
    # Native GetRegistryDefaultSecurity flags 1 and 2 both return
    # O:SYG:SYD:AIARS:AIAR. These vectors are subsequent 84220 requests.
    parent = windows.compile_sddl("O:SYG:SYD:P(A;CI;KA;;;SY)S:(ML;CI;1;;;S-1-16-8192)")
    request = build(None, parent, default = True)
    equal(request["security_information"], 0x3000000f)
    equal(windows.security_descriptor_parts(request["descriptor"]), windows.security_descriptor_parts(binary.decode("0100148f4c00000058000000140000003000000002001c0001000000111214000100000001010000000000100020000002001c0001000000001214003f000f00010100000000000512000000010100000000000512000000010100000000000512000000", "hex")))
    request = build(None, default = True, defer_inheritance = True)
    equal(request["security_information"], 0x3000000f)
    equal(windows.security_descriptor_parts(request["descriptor"]), windows.security_descriptor_parts(binary.decode("010014851c0000002800000000000000140000000200080000000000010100000000000512000000010100000000000512000000", "hex")))
    # 83800 flag1 (84220 flag2) does not query the parent or token.
    # Rights, creator identities, inherited flags and SACL order stay raw.
    for text, info, expected in [
        ("D:(A;CI;GA;;;BU)", 0x3000000f, "01001485340000004000000000000000140000000200200001000000000218000000001001020000000000052000000021020000010100000000000512000000010100000000000512000000"),
        ("D:P(A;CI;GA;;;BU)", 0x9000000f, "01001495340000004000000000000000140000000200200001000000000218000000001001020000000000052000000021020000010100000000000512000000010100000000000512000000"),
        ("D:AI(A;CIID;GR;;;BU)S:(AU;CISA;GA;;;WD)", 0x3000000f, "0100148f500000005c000000140000003000000002001c000100000002421400000000100101000000000001000000000200200001000000001218000000008001020000000000052000000021020000010100000000000512000000010100000000000512000000"),
        ("D:PS:P", 0xc000000f, "010014bf2400000030000000140000001c00000002000800000000000200080000000000010100000000000512000000010100000000000512000000"),
        ("D:(A;CI;GA;;;CO)", 0x3000000f, "01001485300000003c000000000000001400000002001c00010000000002140000000010010100000000000300000000010100000000000512000000010100000000000512000000"),
        ("D:S:(ML;;;;;LW)(AU;SA;KR;;;WD)", 0x3000001f, "0100148f4c0000005800000014000000440000000200300002000000110014000000000001010000000000100010000002401400190002000101000000000001000000000200080000000000010100000000000512000000010100000000000512000000"),
    ]:
        request = build(windows.compile_sddl(text), defer_inheritance = True)
        equal(request["security_information"], info)
        equal(windows.security_descriptor_parts(request["descriptor"]), windows.security_descriptor_parts(binary.decode(expected, "hex")))
    raises(build, args = [windows.compile_sddl("D:"), parent], kwargs = dict(default = True), message = "cannot carry")


def test_native_registry_pass_resolution():
    policy = testing.module("@stdlib//windows/servicing:runtime.star")
    resolve = policy["resolve_servicing_registry_key_pass"]
    reduce = policy["reduce_servicing_registry_keys"]
    preprocess = policy["preprocess_servicing_registry_keys"]
    # Native ProcessKeys flags 0/1 omit HKCU; bit 2 produces its separate
    # USER-rooted hierarchy. Explicit USERS/.DEFAULT stays in the system pass.
    # A real no-SID CUserProfile opens \\REGISTRY\\USER\\Template at commit,
    # not .DEFAULT. Neither this resolver nor reduction mounts either hive.
    for source, scope, path in [
        ("HKEY_CURRENT_USER\\Software\\Microsoft\\Fixture", "user", "\\Registry\\User\\Software\\Microsoft\\Fixture"),
        ("HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\Fixture", "user", "\\Registry\\User\\Software\\Classes\\CLSID\\Fixture"),
        ("HKEY_CURRENT_USER\\Control Panel\\Fixture", "user", "\\Registry\\User\\Control Panel\\Fixture"),
        ("HKEY_USERS\\.DEFAULT\\Software\\Microsoft\\Fixture", "system", "\\Registry\\User\\.DEFAULT\\Software\\Microsoft\\Fixture"),
    ]:
        for architecture in ["amd64", "wow64"]:
            actual = resolve(source, architecture)
            equal(actual, dict(scope = scope, path = path))
            record = dict(actual, side = "after", identity = "fixture", descriptor = None, key_attributes = {})
            reduced = reduce([record], scope = scope)
            result = preprocess(reduced, {path.lower(): True}, {})
            for name, item in result.items():
                equal(item["operation"], 1)
                equal(item["security_flags"], 0x2a if name == "\\registry\\user\\.default" else 0x28)
            raises(reduce, args = [[record]], kwargs = dict(scope = "system" if scope == "user" else "user"), message = "mix passes")
    equal(resolve("HKEY_LOCAL_MACHINE\\Software\\Fixture", "wow64"), dict(scope = "system", path = "\\Registry\\Machine\\Software\\WOW6432Node\\Fixture"))
    raises(resolve, args = ["HKEY_USERS\\S-1-5-18\\Software", "amd64"], message = "root")
    raises(resolve, args = ["HKEY_CURRENT_USER\\Software\\WOW6432Node\\Fixture", "wow64"], message = "WOW")
    raises(resolve, args = ["HKEY_CURRENT_USER\\Software\\\\Fixture", "amd64"], message = "components")


def test_native_registry_string_expansion():
    expand = testing.module("@stdlib//windows/servicing:runtime.star")["expand_servicing_registry_string"]
    roots = {36: "Z:\\FixtureOS\\", 37: "Z:\\FixtureOS\\System32\\", 41: "Z:\\FixtureOS\\SysWOW64\\"}
    # Native real SIL + real CUserProfile, with a supplied cached Windows path
    # \\??\\Z:\\FixtureOS\\. Only profile selection is a fixture boundary;
    # LookupStringReplacement, GetSpecialDirectoryPath, ProcessKeys and the
    # hierarchy commit remain native. Exact successful NtSetValueKey data:
    for value, expected in [
        ("$(runtime.system32)", "Z:\\FixtureOS\\System32"),
        ("$(runtime.windows)", "Z:\\FixtureOS"),
        ("@$(Runtime.System32)\\fixture.dll,-1", "@Z:\\FixtureOS\\System32\\fixture.dll,-1"),
        ("%SystemRoot%\\$(runtime.windows)", "%SystemRoot%\\Z:\\FixtureOS"),
        ("$(runtime.windows)|$(runtime.system32)", "Z:\\FixtureOS|Z:\\FixtureOS\\System32"),
        ("@{$(build.PackageMoniker)?resource}", "@{$(build.PackageMoniker)?resource}"),
        ("$$(assembly.empty)(Registry:HKLM/key)", "$(Registry:HKLM/key)"),
        ("before$(Assembly.Empty)after", "beforeafter"),
        ("$(runtime.windows)\\Name", "Z:\\FixtureOS\\Name"),
    ]:
        equal(expand(value, roots, "amd64", "amd64"), expected)
    # Architecture-to-ID mapping was independently checked against native
    # LookupStringReplacement; registry values use source DOS paths, not /Windows.
    equal(expand("$(runtime.system32)", roots, "amd64", "wow64"), "Z:\\FixtureOS\\SysWOW64")
    raises(expand, args = ["$(runtime.system32)", {}, "amd64", "amd64"], message = "resolved source")
    raises(expand, args = ["$(runtime.system32)", {37: "/Windows/System32"}, "amd64", "amd64"], message = "drive-absolute")
    raises(expand, args = ["$(runtime.windows", roots, "amd64", "amd64"], message = "unterminated")
    raises(expand, args = ["$(unknown)", roots, "amd64", "amd64"])


def test_native_registry_key_reduction():
    policy = testing.module("@stdlib//windows/servicing:runtime.star")
    reduce = policy["reduce_servicing_registry_keys"]
    preprocess = policy["preprocess_servicing_registry_keys"]
    path = "\\Registry\\Machine\\Software\\Fixture"
    key = path.lower()
    parent = "\\registry\\machine\\software"
    a = dict(sddl = "O:SYG:SYD:P(A;;KA;;;SY)")
    b = dict(sddl = "O:SYG:SYD:P(A;;KA;;;BA)")
    compiled = {d["sddl"]: windows.compile_sddl(d["sddl"]) for d in [a, b]}
    def record(side, descriptor, owner = "false"):
        return dict(path = path, side = side, descriptor = descriptor, identity = side, key_attributes = dict(owner = owner))
    # Flags independently read from the native processed hierarchy, including
    # the implicit Software ancestor and install/remove operation byte.
    for old, new, changed, leaf_flags, parent_flags in [
        (a, a, False, 0x48, 0x4a),
        (None, None, False, 0x48, 0x4a),
        (a, b, False, 0, 0x0a),
        (None, a, False, 0, 0x0a),
        (a, None, False, 0, 0x0a),
        (a, a, True, 8, 0x0a),
    ]:
        records = [record("before", old), record("after", new)]
        for ordered in [records, list(reversed(records))]:
            reduced = reduce(ordered)
            result = preprocess(reduced, {key: changed}, compiled)
            equal([result[key]["operation"], result[key]["security_flags"], result[key]["auxiliary_flags"]], [1, leaf_flags, 0])
            equal([result[parent]["operation"], result[parent]["security_flags"], result[parent]["auxiliary_flags"]], [1, parent_flags, 0])
            equal(result[key]["owner"], "after" if new != None else None)
            equal(reduced[parent]["explicit"], False)
    for side, descriptor, owner, operation, leaf_flags, parent_flags in [
        ("after", a, "false", 1, 0x20, 0x2a),
        ("after", None, "false", 1, 0x28, 0x2a),
        ("after", None, "true", 1, 0x28, 0x2a),
        ("before", a, "false", 2, 8, 0x0a),
    ]:
        result = preprocess(reduce([record(side, descriptor, owner)]), {key: False}, compiled)
        equal([result[key]["operation"], result[key]["security_flags"]], [operation, leaf_flags])
        equal([result[parent]["operation"], result[parent]["security_flags"]], [operation, parent_flags])
    # Native deeper-path and explicit-hive-root captures establish that bit 2
    # marks the hive boundary, NOT every implicit ancestor or non-explicit key.
    deep = dict(record("after", None), path = "\\Registry\\Machine\\Software\\Deep\\Fixture")
    deep_key = deep["path"].lower()
    result = preprocess(reduce([deep]), {deep_key: True}, compiled)
    equal(result[parent]["security_flags"], 0x2a)
    equal(result[parent + "\\deep"]["security_flags"], 0x28)
    equal(result[deep_key]["security_flags"], 0x28)
    # Registry names are not filesystem components: dots and slash are literal.
    for literal in [".", "..", "application/vnd.fixture"]:
        dotted = dict(record("after", None), path = "\\Registry\\Machine\\Software\\" + literal + "\\Fixture")
        dotted_key = dotted["path"].lower()
        result = preprocess(reduce([dotted]), {dotted_key: True}, compiled)
        equal(result[parent + "\\" + literal]["security_flags"], 0x28)
        equal(result[dotted_key]["parent"], parent + "\\" + literal)
    hive = dict(record("after", None), path = "\\Registry\\Machine\\Software")
    result = preprocess(reduce([hive]), {parent: True}, compiled)
    equal(result[parent]["security_flags"], 0x2a)
    reduced = reduce([record("before", a), record("after", a)])
    raises(preprocess, args = [reduced, {}, compiled], message = "complete")
    raises(preprocess, args = [reduced, {key: False}, {}], message = "compiled")
    raises(preprocess, args = [reduced, {key: 0}, compiled], message = "boolean")
    # Native cross-component overlap selects the last concrete descriptor,
    # but preserves the FIRST owning identity. A later absent SD does not clear
    # an earlier selection. Reduction does not authorize overlap policy.
    first = dict(record("after", a), identity = "first")
    second = dict(record("after", b), identity = "second")
    overlap = reduce([first, second, record("after", None)])[key]
    equal(overlap["owner"], "first")
    equal(overlap["after_descriptor"], b)
    equal(overlap["owned_addition_collisions"], 1)
    equal(len(overlap["contributions"]), 3)
    old_overlap = reduce([record("before", a), record("before", b)])[key]
    equal(old_overlap["before_descriptor"], b)
    equal(old_overlap["owner"], None)
    equal(old_overlap["owned_addition_collisions"], 0)
    # Real native hierarchy traces return success with ordinary key calls
    # only, both for existing keys and actual create disposition 1.
    for attrs in [dict(owner = "true"), dict(owner = "false"), dict(perUserVirtualization = "Disable"), dict(perUserVirtualization = "DisableRecurse"), dict(mapDesiredAccessToMaxAllowedAccess = "False")]:
        result = preprocess(reduce([dict(record("after", None), key_attributes = attrs)]), {key: True}, compiled)
        equal(result[key]["security_flags"], 0x28)
        equal(result[key]["auxiliary_flags"], 0)
        equal(result[key]["owner"], "after" if attrs.get("owner") == "true" else None)
    for attrs in [dict(perUserVirtualization = "Enable"), dict(mapDesiredAccessToMaxAllowedAccess = "True"), dict(unknown = "true")]:
        raises(reduce, args = [[dict(first, key_attributes = attrs)]], message = "unsupported registry")
    for bad in ["\\Registry\\MachineEvil\\Software", "\\Registry\\Machine", path + "\\", "HKLM\\Software"]:
        raises(reduce, args = [[dict(record("after", a), path = bad)]], message = "resolved")


def test_native_registry_key_commit_selection():
    policy = testing.module("@stdlib//windows/servicing:runtime.star")
    select = policy["select_servicing_registry_key_commit"]
    empty = policy["select_servicing_registry_empty_delete"]
    sd = windows.compile_sddl("O:SYG:SYD:P(A;;KA;;;SY)")
    # Independent WCP 26100.9441 ProcessKeys/PreprocessTree/CreateKeysInKey
    # captures, not a reduction implemented in this test. Each pair used
    # identical component identity and ordinary REG_SZ Value=Fixture.
    for name, flags, descriptor, existing_security, new_security in [
        ("same", 0x48, sd, "none", "none"),
        ("security-change", 0, sd, "explicit", "explicit"),
        ("security-added", 0, sd, "explicit", "explicit"),
        ("security-removed", 0, None, "default", "default"),
        ("value-change", 8, sd, "none", "explicit"),
        ("new-only", 0x20, sd, "explicit", "explicit"),
    ]:
        for created, expected in [(False, existing_security), (True, new_security)]:
            actual = select(1, flags, descriptor, created = created)
            equal(actual["security"], expected)
            equal(actual["action"], "skip" if name == "same" else "create_or_open")
            equal(actual["defer_inheritance"], False)
            equal(actual["queue_empty_delete"], False)
    # Software is implicit. An existing changed ancestor does not reset its
    # security; if newly created, its default setter uses deferred inheritance.
    equal(select(1, 0x0a, None)["security"], "none")
    equal(select(1, 0x0a, None, created = True), dict(action = "create_or_open", security = "default", defer_inheritance = True, queue_empty_delete = False))
    equal(select(1, 0x4a, None)["action"], "skip")
    # Full native hierarchy removal deleted Value, then Fixture if empty.
    # An undeclared Untouched value retained Fixture; an unrelated subkey
    # retained Software. Empty implicit Software was also a deletion candidate.
    for flags in [8, 0x0a]:
        equal(select(2, flags, None), dict(action = "open", security = "none", defer_inheritance = False, queue_empty_delete = True))
    equal(empty(0, 0), True)
    equal(empty(0, 1), False)
    equal(empty(1, 0), False)
    for flags in [1, 0x10, 0x80, 256, -1]:
        raises(select, args = [1, flags, sd], message = "registry key")
    raises(select, args = [1, 8, sd], kwargs = dict(parent_security_flags = 0x80), message = "policy")
    raises(select, args = [1, 8, sd], kwargs = dict(auxiliary_flags = 2), message = "policy")
    raises(select, args = [2, 8, sd], kwargs = dict(created = True), message = "disposition")
    raises(empty, args = [-1, 0], message = "uint32")


def test_native_registry_value_preparation():
    prepare = testing.module("@stdlib//windows/servicing:runtime.star")["prepare_servicing_registry_value_data"]
    roots = {36: "Z:\\FixtureOS", 37: "Z:\\FixtureOS\\System32"}
    for spelling, kind, text, expected in [
        ("REG_SZ", 1, "$(runtime.system32)", "Z:\\FixtureOS\\System32\x00"),
        ("REG_EXPAND_SZ", 2, "$(runtime.windows)", "Z:\\FixtureOS\x00"),
        ("REG_MULTI_SZ", 7, '"$(runtime.windows)","$(runtime.system32)"', "Z:\\FixtureOS\x00Z:\\FixtureOS\\System32\x00\x00"),
    ]:
        attrs = dict(name = "$(runtime.windows)\\Name", valueType = spelling, value = text, operationHint = "replace", IEDownlevelValue = "Downlevel")
        actual = prepare(attrs, roots, "amd64", "amd64")
        equal(actual["type"], kind)
        equal(actual["raw"], binary.encode(expected, encoding = "utf16le"))
        equal(actual["name"], "Z:\\FixtureOS\\Name")
        equal(actual["attributes"], attrs)
    none = prepare(dict(name = "", valueType = "REG_NONE", value = "$(not.a.path)"), roots, "amd64", "amd64")
    equal(none["raw"], b"")
    empty = prepare(dict(name = "M", valueType = "REG_MULTI_SZ", value = ""), roots, "amd64", "amd64")
    quoted = prepare(dict(name = "M", valueType = "REG_MULTI_SZ", value = '""'), roots, "amd64", "amd64")
    equal(empty["raw"], quoted["raw"])
    equal((empty["unquoted_empty"], quoted["unquoted_empty"]), (True, False))
    raises(prepare, args = [dict(name = "V", valueType = "REG_SZ", value = "x", priority = "1"), roots, "amd64", "amd64"], message = "attributes")


def test_native_new_registry_multi_action():
    select = testing.module("@stdlib//windows/servicing:runtime.star")["select_servicing_new_registry_multi_action"]
    current = dict(type = 7, raw = binary.encode("Existing\x00Shared\x00\x00", encoding = "utf16le"))
    for hint, expected in [("append", "Existing\x00Shared\x00Added\x00\x00"), ("prepend", "Added\x00Existing\x00Shared\x00\x00"), ("replace", "Shared\x00Added\x00\x00")]:
        result = select(["Shared", "Added"], current, operation_hint = hint)
        equal(result, dict(action = "set", value = dict(type = 7, raw = binary.encode(expected, encoding = "utf16le"))))
    equal(select(["Shared", "Added"], current), select(["Shared", "Added"], current, operation_hint = "append"))
    raises(select, args = [[], current], message = "nonempty")


def test_native_primitive_family_capacity():
    capacity = testing.module("@stdlib//windows/servicing:runtime.star")["servicing_primitive_family_capacity"]
    identity = "Fixture%s, Culture=neutral, Version=10.0.26100.1, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS"
    marks = [binary.encode(identity % i, encoding = "utf8") for i in range(37)]
    equal(capacity(marks[:35]), dict(bucket_count = 7, minimum_families = 35, maximum_families = 35))
    equal(capacity(marks[:36]), dict(bucket_count = 72, minimum_families = 36, maximum_families = 36))
    equal(capacity(marks), dict(bucket_count = 72, minimum_families = 37, maximum_families = 37))
    variants = [binary.encode((identity % 1).replace("10.0.26100.1", "10.0.26100.%d" % i), encoding = "utf8") for i in range(37)]
    raises(capacity, args = [variants], message = "exact version-scoped counts")


def test_native_registry_overlap_status():
    policy = testing.module("@stdlib//windows/servicing:runtime.star")
    status = policy["servicing_registry_overlap_status"]
    zero = dict(keys = 0, critical_keys = 0, values = 0, critical_values = 0, state_separation = 0, hkcu = 0)
    for strict in [False, True]:
        gates = dict(strict_keys = strict, strict_values = strict)
        equal(status(gates, zero), 0)
        for name, expected in [("keys", 0x80188309 if strict else 0), ("critical_keys", 0x80188309), ("values", 0x80188309 if strict else 0), ("critical_values", 0x80188309), ("state_separation", 0x8018830e), ("hkcu", 0x80188317)]:
            counts = dict(zero)
            counts[name] = 1
            equal(status(gates, counts), expected)
    raises(status, args = [gates, {}], message = "complete")
    raises(status, args = [gates, dict(zero, keys = -1)], message = "uint64")
    software = windows.hive(windows.hive_from_patches("SOFTWARE", []))
    components = windows.hive(windows.hive_from_patches("COMPONENTS", []))
    actual = policy["servicing_registry_overlap_policy"](software, components)
    equal((actual["strict_keys"], actual["strict_values"]), (False, False))
    software = windows.hive(windows.hive_from_patches("SOFTWARE", [dict(key = "Microsoft/Windows/CurrentVersion/Policies/Servicing", name = "SmiHiveUpdates", type = "REG_DWORD", value = 0x800)]))
    actual = policy["servicing_registry_overlap_policy"](software, components)
    equal((actual["strict_keys"], actual["strict_values"]), (True, True))


def _csi_writer_fixture(drop_pin=False):
    files = directory()
    identity = b"sample, Culture=neutral, Version=10.0.1.0, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=NonSxS"
    files.write("/component", '<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="sample" version="10.0.1.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="NonSxS"/></assembly>')
    files.write("/package", _manifest("Package", '<update name="update"><component>' + _identity("sample") + '</component></update>'))
    data = windows.cbs_deployment_source_data(files.find("/package"), "update")
    # Resident source payloads can contain opaque secondary data. Keep it even
    # when a source kind disappears; never regenerate the remaining p!/s!.
    data = bytes(str(data[:4]) + "\x01\x00\x00\x00" + str(data[8:]) + "8")
    source_key = windows.cbs_deployment_source(data).source_key
    before = [dict(name=kind + source_key, type=3, data=data) for kind in ["p!", "s!", "i!"]]
    noop = windows.csi_source_plan(before, [])
    changes = [dict(kind=2, delete=True, data=data)]
    if drop_pin:
        changes.append(dict(kind=1, delete=True, data=data))
    install = windows.csi_source_plan(before, changes)
    final = [v for v in before if not v["name"].startswith("i!") and not (drop_pin and v["name"].startswith("p!"))]
    name = windows.csi_deployment_key(identity)
    deployment = "/CanonicalData/Deployments/" + name
    component = "/DerivedData/Components/resident"
    patches = [
        dict(key=component, name="identity", type=3, value=identity),
        dict(key=component, name="S256H", type=3, value=digest(files.find("/component"), algorithm="sha256")),
        dict(key=component, name="CF", type="REG_DWORD", value=0x1234),
        dict(key=component, name="f!sample.dll", type="REG_DWORD", value=0x221),
        dict(key=component, name="c!" + name, type=3, value=b""),
        dict(key=deployment, name="appid", type=3, value=identity),
        dict(key=deployment, name="CatalogThumbprint", type="REG_SZ", value="existing-catalog-choice"),
        dict(key=deployment, name="untouched", type=3, value=b"opaque"),
    ] + [dict(key=deployment, name=v["name"], type=v["type"], value=v["data"]) for v in before]
    files.write("/Windows/System32/config/COMPONENTS", windows.hive_from_patches("COMPONENTS", patches))
    family = windows.csi_winner_family_key(identity)
    winner = "/Microsoft/Windows/CurrentVersion/SideBySide/Winners/" + family
    files.write("/Windows/System32/config/SOFTWARE", windows.hive_from_patches("SOFTWARE", [
        dict(key=winner, name="", type="REG_SZ", value="10.0"),
        dict(key=winner + "/10.0", name="", type="REG_SZ", value="10.0.1.0"),
        dict(key=winner + "/10.0", name="10.0.1.0", type=3, value=b"\x01"),
        dict(key=winner + "/11.0", name="untouched", type=3, value=b"preserve"),
    ]))
    def resolve(unused):
        return files.find("/component")
    exact = str(identity).lower()
    sources = {exact: dict(identity=identity, driver=False, plans=dict(pin=noop, stage=noop, install=install), final_sources=final)}
    analysis = dict(compositions={exact: windows.csi_composition(identity, resolve)}, winner_plans=[windows.csi_winner_plan(identity, "10.0.1.0", ["10.0.1.0"], [dict(version="10.0.1.0", installed=False, impactful_install=False)])])
    return files, sources, analysis, component, deployment, winner, source_key, data

def test_boot_csi_initial_source_states():
    root, sources, analysis, component, deployment, winner, key, data = _csi_writer_fixture()
    state = testing.module("@stdlib//windows/servicing:population.star")["_initial_servicing_component_state"]
    source = windows.cbs_deployment_source(data)
    equal(state({}, source.primary), 0)
    equal(state({"p!" + key: source}, source.primary), 0x20)
    equal(state({"p!" + key: source, "s!" + key: source}, source.primary), 0x40)
    equal(state({"p!" + key: source, "s!" + key: source, "i!" + key: source}, source.primary), 0x70)
    equal(state({"p!" + key: source, "s!" + key: source, "i!" + key: source}, source.primary + ".other"), 0)

def test_boot_csi_value_scoped_writes():
    apply = testing.module("@stdlib//windows/servicing:csi.star")["apply_csi_state"]
    for drop_pin in [False, True]:
        root, sources, analysis, component, deployment, winner, source_key, data = _csi_writer_fixture(drop_pin)
        report = apply(root, dict(stages={}), sources, analysis)
        actual = windows.hive(root.find("/Windows/System32/config/COMPONENTS"))
        values = actual.find(component).values
        equal(values["CF"], 0x1234)
        equal(values["f!sample.dll"], 0x221)
        equal(any([n.startswith("c!") for n in values]), not drop_pin)
        values = actual.find(deployment).values
        equal(values["CatalogThumbprint"], "existing-catalog-choice")
        equal(values["untouched"], b"opaque")
        equal(values["s!" + source_key], data)
        equal("p!" + source_key in values, not drop_pin)
        equal("i!" + source_key in values, False)
        software = windows.hive(root.find("/Windows/System32/config/SOFTWARE"))
        equal(software.find(winner).values, {})
        equal(software.find(winner + "/10.0").values, {})
        equal(software.find(winner + "/11.0").values["untouched"], b"preserve")
        equal(report["verified_sources"], 1)
        equal(report["verified_winner_plans"], 1)
    # Failed readback invariants must not publish either candidate hive.
    root, sources, analysis, component, deployment, winner, source_key, data = _csi_writer_fixture()
    original = [digest(root.find("/Windows/System32/config/" + h), algorithm="sha256") for h in ["COMPONENTS", "SOFTWARE"]]
    list(sources.values())[0]["final_sources"] = []
    raises(apply, args=[root, dict(stages={}), sources, analysis], message="serialized CSI source")
    equal([digest(root.find("/Windows/System32/config/" + h), algorithm="sha256") for h in ["COMPONENTS", "SOFTWARE"]], original)

def _reference_registry_key_pass(key, architecture):
    """Resolve the pinned system/per-user declaration passes, not hive mounts.

    HKCU is an abstract per-profile root. It is NOT HKEY_USERS/.DEFAULT.
    Native ProcessKeys bit 2 selects HKCU; the system pass includes explicit
    HKEY_USERS/.DEFAULT. Commit binds the per-user root through the supplied
    profile's OpenProfileRootKey (the no-SID fixture opens USER/Template).
    Other explicit user SIDs and explicit WOW nodes remain outside this recipe.
    """
    if type(key) != "string" or "\x00" in key or "$(" in key:
        fail("registry pass requires a resolved key string")
    fields = key.rstrip("\\").split("\\")
    if any([not part for part in fields]):
        fail("registry pass requires nonempty ordinary key components")
    root = fields[0].lower()
    if root in ["hkey_local_machine", "hklm", "hkey_classes_root", "hkcr"]:
        return dict(scope = "system", path = testing.module("@stdlib//windows/servicing:runtime.star")["resolve_servicing_machine_registry_key"](key, architecture))
    if architecture not in ["amd64", "x86", "wow64"]:
        fail("unsupported registry user architecture")
    if any([part.lower() == "wow6432node" for part in fields[1:]]):
        fail("explicit user WOW node requires separate policy")
    if root == "hkey_current_user":
        return dict(scope = "user", path = "\\Registry\\User" + ("\\" + "\\".join(fields[1:]) if len(fields) > 1 else ""))
    if root == "hkey_users" and len(fields) > 1 and fields[1].lower() == ".default":
        return dict(scope = "system", path = "\\Registry\\User\\" + "\\".join(fields[1:]))
    fail("unsupported registry declaration root")


def test_compiled_registry_path_mapping():
    p = testing.module("@stdlib//windows/servicing:runtime.star")
    old = _reference_registry_key_pass
    new = p["resolve_servicing_registry_key_pass"]
    keys = ["", "HKLM", "HKEY_CURRENT_USER", "HKEY_USERS\\.DEFAULT", "HKCU\\Software", "HKEY_USERS\\S-1-5-18", "HKLM\\$(bad)", "HKLM\\A\x00B", "HKLM\\\\Software", "HKEY_CURRENT_USER\\Wow6432Node"]
    for prefix, flags in p["_SERVICING_MACHINE_REGISTRY_RULES"]:
        relative = prefix[len("\\REGISTRY\\MACHINE"):]
        for alias in ["HKLM", "hKeY_lOcAl_MaChInE"]:
            for suffix in ["", "\\", "\\Fixture", "Extra", "\\ÉKİ😀"]:
                keys.append(alias + relative + suffix)
    keys += ["HKCR\\"+tail for tail in ["", "CLSID", "CLSID\\Fixture", "Wow6432Node\\CLSID", "Fixture\\Wow6432Node"]]
    count = 0
    for key in keys:
        for arch in ["amd64", "x86", "wow64", "arm64"]:
            a = testing.attempt(old,args=[key,arch])
            b = testing.attempt(new,args=[key,arch])
            if a.ok != b.ok or (a.ok and a.value != b.value): fail(str((key,arch,a,b)))
            count += 1
    print("registry mapper differential cases",count)



def _reference_registry_contributions(runtime, config, source_roots, target, key_prefix=None):
    # Deliberately use the pre-bulk declaration/codec path as an independent
    # differential oracle. Do not add a production fallback to this loop.
    p = testing.module("@stdlib//windows/servicing:runtime.star")
    groups, keys = {}, {}
    for owner, change in enumerate(runtime["transitions"]):
        admitted = p["analyze_servicing_registry_declarations"](dict(transitions=[change]), config)
        for key in admitted["keys"]:
            arch = windows.csi_identity(key["identity"]).processor_architecture
            resolved = p["resolve_servicing_registry_key_pass"](key["key"], arch)
            identity = (resolved["scope"], resolved["path"].lower())
            if key_prefix != None and identity[1].startswith(key_prefix.lower()):
                keys.setdefault(identity, [resolved["path"], False, False])[1+int(key["side"]=="after")] = True
        for record in admitted["values"]:
            arch = windows.csi_identity(record["identity"]).processor_architecture
            resolved = p["resolve_servicing_registry_key_pass"](record["key"], arch)
            value = p["prepare_servicing_registry_value_data"](record["attributes"], source_roots, target, arch)
            key = (resolved["scope"], resolved["path"].lower(), value["name"].lower())
            attrs = value["attributes"]
            groups.setdefault(key,[[],[]])[int(record["side"]=="after")].append((owner,value["type"],value["raw"],attrs.get("mutable","false"),attrs.get("operationHint",""),value["unquoted_empty"]))
    return dict(groups=groups, keys=keys)


def _registry_collector_fixture(bodies, architecture="amd64", kind="", namespace="urn:schemas-microsoft-com:asm.v3"):
    files = directory()
    sides, identities = {"before":None, "after":None}, {}
    for side, body in bodies.items():
        identity = bytes("fixture, Culture=neutral, " + ("Type="+kind+", " if kind else "") + "Version=1.0.0."+str(int(side=="after"))+", PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture="+architecture+", versionScope=nonSxS")
        files.write("/"+side, '<assembly xmlns="'+namespace+'">'+body+'</assembly>')
        sides[side], identities[side] = files.find("/"+side), identity
    return dict(identity=identity, component_identities=identities, **sides)


def test_native_registry_collector_differential():
    p = testing.module("@stdlib//windows/servicing:runtime.star")
    native = p["collect_servicing_registry_contributions"]
    source_roots = {36:r"C:\Windows", 37:r"C:\Windows\System32", 41:r"C:\Windows\SysWOW64"}
    declarations = [
        ('REG_NONE','$(unexpanded)'),('REG_SZ','É😀'),('REG_SZ',r'$(runtime.windows)\Fixture'),
        ('REG_EXPAND_SZ',r'%SystemRoot%\Literal'),('REG_BINARY','00aB'),('REG_DWORD','-1'),
        ('REG_DWORD','0xffffffff'),('REG_QWORD','0000004001000000'),('REG_QWORD','0x100000000'),
        ('REG_MULTI_SZ','&quot;A&quot;,&quot;&quot;,&quot;B&quot;'),('REG_MULTI_SZ',''),('REG_MULTI_SZ','&quot;&quot;'),
        ('REG_MULTI_SZ','One,Keep'),('REG_SZ','$(build.PackageMoniker)'),
    ]
    # Values with colliding case-folded names, duplicate contributions, changed
    # and unchanged owners, empty keys, literal separators, foreign namespaces.
    body = r'<registryKeys><registryKey keyName="HKEY_LOCAL_MACHINE\Software\Fixture" owner="true">'
    for kind,text in declarations:
        body += '<registryValue name="'+kind+'" valueType="'+kind+'" value="'+text+'"/>'
    body += '<registryValue name="REG_SZ" valueType="REG_SZ" value="mutable" mutable="true" operationHint="prepend" IEDownlevelValue="ignored"/><registryValue xmlns="foreign"/></registryKey>'
    body += r'<registryKey keyName="HKEY_CURRENT_USER\Software\Fixture"><registryValue name="User" valueType="REG_SZ" value="profile"/></registryKey>'
    body += r'<registryKey keyName="HKLM\Software\Empty"/><registryKey keyName="HKLM\Software\A/B\.."/></registryKeys>'
    transitions = []
    for arch in ['amd64','x86','wow64']:
        for kind in ['','dualModeDriver','driverUpdate','DualModeDriver']:
            transitions.append(_registry_collector_fixture(dict(before=body,after=body.replace('É😀','Updated')),arch,kind))
    transitions.append(_registry_collector_fixture(dict(before=body),namespace='urn:schemas-microsoft-com:asm.v1'))
    runtime = dict(transitions=transitions)
    for config in [0x100,0x133]:
        for prefix in [None,'',r'\registry\machine\software\empty']:
            old = _reference_registry_contributions(runtime,config,source_roots,'amd64',key_prefix=prefix)
            new = native(runtime,config,source_roots,'amd64',key_prefix=prefix)
            equal(list(new['groups'].items()),list(old['groups'].items()))
            equal(list(new['keys'].items()),list(old['keys'].items()))
        captured_keys = native(runtime,config,source_roots,'amd64',capture_key_records=True)['key_records']
        expected_keys = {}
        for owner,change in enumerate(transitions):
            declarations = p['analyze_servicing_registry_declarations'](dict(transitions=[change]),config)
            for row in declarations['keys']:
                resolved = p['resolve_servicing_registry_key_pass'](row['key'],windows.csi_identity(row['identity']).processor_architecture)
                text = row['descriptor']['sddl'] if row['descriptor'] != None else None
                expected_keys.setdefault(owner,[]).append((row['side'],resolved['scope'],resolved['path'],row['key_attributes'],text))
        equal(captured_keys,expected_keys)
    # A captured document may never be reused after the transition file changes.
    change = transitions[0]
    captured = dict(change,documents={side:(change[side],binary.xml(change[side]).root) for side in ['before','after']})
    replacement = _registry_collector_fixture(dict(after=body.replace('É😀','replacement')))
    captured['after'] = replacement['after']
    current = dict(transitions=[captured])
    equal(native(current,0x100,source_roots,'amd64'),_reference_registry_contributions(current,0x100,source_roots,'amd64'))


def test_native_registry_collector_rejections():
    p = testing.module("@stdlib//windows/servicing:runtime.star")
    native = p["collect_servicing_registry_contributions"]
    source_roots={36:r"C:\Windows"}
    start = r'<registryKeys><registryKey keyName="HKLM\Software\Fixture">'
    end = '</registryKey></registryKeys>'
    invalid = [
        '<registryValue name="x" valueType="REG_SZ" value="x" extra="x"/>',
        '<registryValue name="x" valueType="REG_SZ" value="$(unknown)"/>',
        '<registryValue name="$(broken" valueType="REG_SZ" value="x"/>',
        '<registryValue name="x" valueType="reg_sz" value="x"/>',
        '<registryValue name="x" valueType="REG_DWORD" value="4294967296"/>',
        '<registryValue name="x" valueType="REG_MULTI_SZ" value="&quot;a&quot;, &quot;b&quot;"/>',
        '<registryValue name="x" valueType="REG_BINARY" value="0"/>',
        '<registryValue name="x" valueType="REG_QWORD" value="00"/>',
        '<registryValue name="x" valueType="REG_SZ" value="x" mutable="True"/>',
        '<registryValue name="x" valueType="REG_SZ" value="x" operationHint="unknown"/>',
        '<registryValue name="x" valueType="REG_DWORD"/>',
        '<registryValue name="x" valueType="REG_SZ" value="x">text</registryValue>',
        '<registryValue name="x" valueType="REG_SZ" value="x"><child/></registryValue>',
        '<registryValue xmlns:q="foreign" q:name="x" valueType="REG_SZ" value="x"/>',
        '<securityDescriptor name="missing"/>',
    ]
    for body in invalid:
        runtime=dict(transitions=[_registry_collector_fixture(dict(before=start+body+end,after=start+body+end))])
        old=testing.attempt(_reference_registry_contributions,args=[runtime,0x100,source_roots,'amd64'])
        new=testing.attempt(native,args=[runtime,0x100,source_roots,'amd64'])
        equal((body,old.ok,new.ok),(body,False,False))
    # Missing/duplicate security definitions and references are rejected even
    # on empty keys; irrelevant foreign-namespace containers stay irrelevant.
    definitions='<trustInfo><security><accessControl><securityDescriptorDefinitions>%s</securityDescriptorDefinitions></accessControl></security></trustInfo>'
    definition='<securityDescriptorDefinition name="one" sddl="D:"/>'
    for body in [definitions % (definition+definition), definitions % '<securityDescriptorDefinition name="one"/>', start+'<securityDescriptor name="one"/><securityDescriptor name="one"/>'+end+definitions % definition, '<registryKeys><unexpected/></registryKeys>']:
        runtime=dict(transitions=[_registry_collector_fixture(dict(after=body))])
        equal(testing.attempt(_reference_registry_contributions,args=[runtime,0x100,source_roots,'amd64']).ok,False)
        equal(testing.attempt(native,args=[runtime,0x100,source_roots,'amd64']).ok,False)
    invalid_runtime=dict(transitions=[_registry_collector_fixture(dict(after=start+invalid[0]+end),kind='dualModeDriver')])
    # Admission intentionally happens before registry validation, in both paths.
    equal(native(invalid_runtime,0x100,source_roots,'amd64'),dict(groups={},keys={}))
    equal(testing.attempt(native,args=[invalid_runtime,0x133,source_roots,'amd64']).ok,False)

def test_manifest_identity_spelling():
    files, available, open_entry = _fixtures()
    # Canonical CAB filenames are lowercase while the MUM identities and
    # native population callbacks retain their original spelling.
    available = {key: [(name.lower(), catalog, path) for name,catalog,path in entries] for key,entries in available.items()}
    for batched in [False, True]:
        def open_entries(entries):
            return [open_entry(*entry) for entry in entries]
        result = close_metadata([], ["Root" + _SUFFIX], available, open_entry, 10, open_entries=open_entries if batched else None)
        equal(sorted(result["files"]), sorted([n + _SUFFIX for n in ["Root", "Child", "Leaf"]]))
        equal(sorted(result["xmls"]), sorted(result["files"]))
        equal(sorted(result["origins"]), sorted(result["files"]))
        equal(result["missing"], {"Unavailable" + _SUFFIX: [("Leaf" + _SUFFIX, "missing")]})

TEST_SUITE = suite("nt6/servicing", [
    case("manifest_identity_spelling", test_manifest_identity_spelling),
    case("reinstall_highest_predecessor", test_reinstall_selects_highest_superseded_predecessor),
    case("registry_collector_differential", test_native_registry_collector_differential),
    case("registry_collector_rejections", test_native_registry_collector_rejections),
    case("compiled_registry_path_mapping", test_compiled_registry_path_mapping),
    case("runtime_manifest_snapshot_binding", test_runtime_manifest_snapshot_binding),
    case("native_registry_overlap_status", test_native_registry_overlap_status),
    case("native_primitive_family_capacity", test_native_primitive_family_capacity),
    case("native_new_registry_multi_action", test_native_new_registry_multi_action),
    case("native_registry_value_preparation", test_native_registry_value_preparation),
    case("native_registry_pass_resolution", test_native_registry_pass_resolution),
    case("native_registry_string_expansion", test_native_registry_string_expansion),
    case("native_registry_key_reduction", test_native_registry_key_reduction),
    case("native_registry_key_commit_selection", test_native_registry_key_commit_selection),
    case("native_registry_default_and_deferred_requests", test_native_registry_default_and_deferred_requests),
    case("boot_csi_initial_source_states", test_boot_csi_initial_source_states),
    case("boot_csi_value_scoped_writes", test_boot_csi_value_scoped_writes),
    case("native_registry_security_requests", test_native_registry_security_requests),
    case("native_registry_security_comparison", test_native_registry_security_comparison),
    case("native_registry_admission", test_native_registry_admission),
    case("native_registry_machine_roots", test_native_registry_machine_roots),
    case("native_registry_machine_redirection", test_native_registry_machine_redirection),
    case("native_single_registry_value_actions", test_native_single_registry_value_actions),
    case("native_paired_registry_multi_merge", test_native_paired_registry_multi_merge),
    case("native_paired_registry_raw_preservation", test_native_paired_registry_raw_preservation),
    case("native_paired_registry_dword_preservation", test_native_paired_registry_dword_preservation),
    case("native_filemap_collision_policy", test_native_filemap_collision_policy),
    case("native_staged_file_security_request", test_native_staged_file_security_request),
    case("native_immutable_inherit_selection", test_native_immutable_inherit_selection),
    case("runtime_source_exact_provenance", test_runtime_source_exact_provenance),
    case("native_filemap_actions", test_native_filemap_actions),
    case("native_file_commit_phase_selection", test_native_file_commit_phase_selection),
    case("native_creation_token_default_dacl", test_native_creation_token_default_dacl),
    case("native_dual_mode_source_only_files", test_native_dual_mode_source_only_files),
    case("native_unprojected_source_reduction", test_native_unprojected_source_reduction),
    case("native_compact_mode_configuration", test_native_compact_mode_configuration),
    case("native_boot_membership_and_file_inputs", test_native_boot_membership_and_file_inputs),
    case("native_selected_file_hash", test_native_selected_file_hash),
    case("native_writable_projection_preservation", test_native_writable_projection_preservation),
    case("native_file_source_interning", test_native_file_source_interning),
    case("native_file_record_reduction", test_native_file_record_reduction),
    case("native_file_overlap_reduction", test_native_file_overlap_reduction),
    case("native_link_primary_hash_sharing", test_native_link_primary_hash_sharing),
    case("runtime_side_specific_source_identity", test_runtime_side_specific_source_identity),
    case("native_subtree_preprocessing", test_native_subtree_preprocessing),
    case("directory_propagation_configuration", test_directory_propagation_configuration),
    case("native_servicing_descriptor_comparison", test_native_servicing_descriptor_comparison),
    case("native_directory_contribution_reduction", test_native_directory_contribution_reduction),
    case("stage_population_supersedence", test_stage_does_not_admit_superseded_family),
    case("capability_reference_versions", test_capability_reference_versions),
    case("complete_metadata_closure", test_complete_closure_not_payload_selection),
    case("batched_metadata_closure", test_batched_closure_order_and_provenance),
    case("identity_and_duplicate_provenance", test_identity_and_duplicate_provenance),
    case("native_runtime_file_paths", test_native_runtime_file_paths),
    case("runtime_path_policy_fails_closed", test_runtime_path_policy_fails_closed),
    case("offline_image_path_mapping", test_offline_image_path_mapping),
    case("offline_registry_path_roots", test_offline_registry_path_roots),
    case("extra_runtime_link_paths", test_extra_runtime_link_paths),
    case("manifest_local_file_security", test_manifest_local_file_security),
    case("directory_declarations_and_paths", test_directory_declarations_and_paths),
    case("native_file_security_defaults", test_native_file_security_defaults),
    case("native_file_security_request", test_native_file_security_request),
    case("native_file_security_assignment", test_native_file_security_assignment),
    case("native_directory_security_request_and_assignment", test_native_directory_security_request_and_assignment),
    case("native_servicing_creation_security", test_native_servicing_creation_security),
    case("native_default_directory_security", test_native_default_directory_security),
    case("native_directory_audit_security", test_native_directory_audit_security),
    case("native_directory_inheritable_audit", test_native_directory_inheritable_audit),
    case("native_creation_inheritable_audit", test_native_creation_inheritable_audit),
    case("native_unprotected_directory_request", test_native_unprotected_directory_request),
    case("native_interned_directory_preprocessing", test_native_interned_directory_preprocessing),
])

def main(args):
    run([TEST_SUITE])
