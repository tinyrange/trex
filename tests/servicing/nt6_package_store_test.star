"""CBS metadata-index regressions from the 26100 package-store control."""

load("//tests:testing.star", "case", "equal", "raises", "run", "suite")
load("@stdlib//windows/servicing:package_indexes.star", "plan_servicing_package_indexes")

_SUFFIX = "~31bf3856ad364e35~amd64~~10.0.1.0"
_CBS = "/Microsoft/Windows/CurrentVersion/Component Based Servicing/"

def _identity(name, version="10.0.1.0", arch="amd64", token="31bf3856ad364e35"):
    return '<assemblyIdentity name="%s" version="%s" processorArchitecture="%s" publicKeyToken="%s" language="neutral"/>' % (name, version, arch, token)

def _file(body, attributes=""):
    tree = directory()
    tree.write("/package", '<assembly xmlns="urn:schemas-microsoft-com:asm.v3">' + _identity("Example") + '<package ' + attributes + '>' + body + '</package></assembly>')
    return tree.find("/package")

def _entries(patches, index):
    prefix = _CBS + index + "/"
    return {(p["key"][len(prefix):], p["name"]): (p["type"], p["value"]) for p in patches if p["key"].startswith(prefix)}

def test_parent_metadata_is_not_owner_or_package_state():
    file = _file('<parent integrate="standalone">' + _identity("Ignored") + '<parent integrate="delegate">' + _identity("Delegated") + '</parent></parent><parent>' + _identity("Separate") + '</parent><parent integrate="subsume">' + _identity("Subsumed") + '</parent>')
    patches = plan_servicing_package_indexes(file)
    equal(_entries(patches, "PackageDetect"), {
        ("Delegated~31bf3856ad364e35~amd64~~0.0.0.0", "Example" + _SUFFIX): ("REG_DWORD", 3),
        ("Separate~31bf3856ad364e35~amd64~~0.0.0.0", "Example" + _SUFFIX): ("REG_DWORD", 2),
        ("Subsumed~31bf3856ad364e35~amd64~~0.0.0.0", "Example" + _SUFFIX): ("REG_DWORD", 4),
    })
    equal(len(patches), 4)
    equal(any([p["name"] in ["CurrentState", "Visibility", "Active", "InstallTimeHigh", "InstallTimeLow"] or "/Owners/" in p["key"] for p in patches]), False)

def test_parent_update_index_and_special_release_indexes():
    body = '<update name="Here"><applicable><detectUpdate><update name="Local"/></detectUpdate><applicable><detectUpdate><parent name="ParentFeature"/></detectUpdate></applicable><detectUpdate><parent name="ParentFeature"/></detectUpdate></applicable></update>'
    patches = plan_servicing_package_indexes(_file(body, 'releaseType="Foundation"'))
    equal(_entries(patches, "UpdateDetect"), {("ParentFeature", "Example" + _SUFFIX): ("REG_DWORD", 0)})
    equal(_entries(patches, "PackageIndex"), {
        ("Example~31bf3856ad364e35~amd64~~0.0.0.0", "Example" + _SUFFIX): ("REG_DWORD", 0),
        ("System", "Example" + _SUFFIX): ("REG_DWORD", 0),
    })
    equal(("Product", "Example" + _SUFFIX) in _entries(plan_servicing_package_indexes(_file("", 'releaseType="Product"')), "PackageIndex"), True)

def test_multiple_parent_detector_indexes_are_not_applicability_pruned():
    body = '<update name="Here"><applicable><detectUpdate><parent name="Server-Gui-Mgmt"/><parent name="RSATClient-ServerManager"/><update name="Local"/><parent name="Server-Gui-Mgmt"/></detectUpdate></applicable></update>'
    entries = _entries(plan_servicing_package_indexes(_file(body)), "UpdateDetect")
    equal(entries, {(parent, "Example" + _SUFFIX): ("REG_DWORD", 0) for parent in ["Server-Gui-Mgmt", "RSATClient-ServerManager"]})
    raises(plan_servicing_package_indexes, args=[_file(body.replace('<update name="Local"/>', '<unknown/>'))], message="parent/local references")

def test_component_index_uses_native_key_and_base_elevation():
    # Native ComponentDetect fixture: full family hash is dc711313304a06dc,
    # not the version-omitting Winners hash. Alternative targets store @8,
    # whereas CBSDeploymentSourceData's secondary flags are 9 for this list.
    targets = _identity("accessibility", "4.0.15920.100", token="b03f5f7f11d50a3a") + _identity("accessibility", "4.0.15920.100", arch="x86", token="b03f5f7f11d50a3a")
    file = _file('<update name="Exact.Source"><applicable><updateComponent elevate="build">' + targets + '</updateComponent></applicable></update>')
    entries = _entries(plan_servicing_package_indexes(file), "ComponentDetect")
    equal(len(entries), 2)
    equal(entries[("amd64_accessibility_b03f5f7f11d50a3a_4.0.0.0_none_dc711313304a06dc", "Example" + _SUFFIX + ".Exact.Source")], ("REG_SZ", "4.0.15920.100@8"))
    equal([value for kind,value in entries.values()], ["4.0.15920.100@8", "4.0.15920.100@8"])
    source = windows.hive_from_patches("SOFTWARE", [dict(key="/Unrelated",name="Retain",type="REG_DWORD",value=99)])
    written = windows.hive(windows.hive_from_patches("SOFTWARE", plan_servicing_package_indexes(file), source=source))
    equal(written.find("/Unrelated").values["Retain"], 99)
    equal(written.find(_CBS + "ComponentDetect/amd64_accessibility_b03f5f7f11d50a3a_4.0.0.0_none_dc711313304a06dc").values["Example" + _SUFFIX + ".Exact.Source"], "4.0.15920.100@8")

def test_unsupported_index_inputs_fail_closed():
    for body in [
        '<parent integrate="unknown">' + _identity("Parent") + '</parent>',
        '<update name="u"><applicable><updateComponent elevate="future">' + _identity("Target") + '</updateComponent></applicable></update>',
        '<update name="u"><applicable><updateComponent elevate="build"/></applicable></update>',
        '<update name="u"><applicable><detectUpdate><parent name="Bad/Path"/></detectUpdate></applicable></update>',
        '<update name="u"><applicable><detectUpdate/></applicable></update>',
    ]:
        raises(plan_servicing_package_indexes, args=[_file(body)])

def _resolved_fixture(integration=2, component=False, dormant_owner=False, target=0x70, owner_state=None):
    root = directory()
    name = "Example" + _SUFFIX
    file = _file('<update name="f"><component>' + _identity("Payload") + '</component></update>' if component else '<update name="f"/>')
    root.write("/Windows/servicing/Packages/" + name + ".mum", file)
    root.write("/Windows/System32/config/SOFTWARE", windows.hive_from_patches("SOFTWARE", [dict(key=_CBS + "Packages/Existing", name="CurrentState", type="REG_DWORD", value=0x70)]))
    root.write("/Windows/System32/config/COMPONENTS", windows.hive_from_patches("COMPONENTS", [], keys=["/DerivedData/Components", "/CanonicalData/Deployments"]))
    index = windows.cbs_update_index([dict(manifest=file, intended_state=0)])
    def applicable(unused_package, unused_snapshot):
        return target
    def mum(unused_package, unused_snapshot, unused_action):
        return dict(before_updates=[], deferred=[])
    request = dict(package=name, owner=name, state=target if owner_state == None else owner_state, integration=integration, ceiling=0x1000)
    def initial(unused_package,unused_update,unused_target,unused_snapshot):
        return dict(state=0,has_deployments=component)
    def no_requests(*unused):
        return []
    requests = [request] + ([dict(request,owner="AbsentOwner" + _SUFFIX,state=0)] if dormant_owner else [])
    population = index.ordinary_population(requests, [], applicable, mum, 100, watch=dict(initial_update=initial,dependents=no_requests,satellites=no_requests))
    closure = dict(files={name:file})
    catalogs = dict(catalogs=2, mum_memberships=2, packages=[name,"Existing"])
    return root, name, closure, population, catalogs

def test_metadata_survives_converged_population_action():
    select = testing.module("@stdlib//windows/servicing:package_store.star")["package_metadata_executions"]
    root, name, closure, population, catalogs = _resolved_fixture(dormant_owner=True)
    execution = population.selected_executions([name])[0]
    equal(execution.action, 0)
    equal(execution.mum_populated, True)
    equal(execution.intended_state, 0x70)
    # A last-action filter loses this newly admitted package and its signed
    # metadata even though the install request was already processed.
    equal(population.selected_executions([name], actions=[2,3]), [])
    equal([e.package for e in select(population, [name])], [name])
    equal(select(population, ["unadmitted" + _SUFFIX]), [])


def test_publication_preserves_admitted_dispositions():
    persist = testing.module("@stdlib//windows/servicing:package_store.star")["publish_package_metadata"]
    for integration in [2,3]:
        root, name, closure, population, catalogs = _resolved_fixture(integration)
        report = persist(root, directory(), "/image6", closure, population, dict(), catalogs)
        hive = windows.hive(root.find("/Windows/System32/config/SOFTWARE"))
        key = hive.find(_CBS + "Packages/" + name)
        equal(key.values["CurrentState"], 0x70)
        equal(key.values["Visibility"], 2 if integration == 3 else 1)
        equal(hive.find(_CBS + "Packages/" + name + "/Owners").values[name], (integration << 16) | 0x70)
        equal(hive.find(_CBS + "Packages/Existing").values["CurrentState"], 0x70)
        equal(any([n in key.values for n in ["InstallTimeHigh","InstallTimeLow","InstallUser","Active","Complete"]]), False)
        equal(report["dispositions"][0]["state"], 0x70)

def test_resolved_phase_rejects_missing_proof_atomically():
    persist = testing.module("@stdlib//windows/servicing:package_store.star")["publish_package_metadata"]
    root, name, closure, population, catalogs = _resolved_fixture()
    original = digest(root.find("/Windows/System32/config/SOFTWARE"),algorithm="sha256")
    raises(persist,args=[root,directory(),"/image6",closure,population,dict(),dict(catalogs, mum_memberships=0)],message="signed MUM")
    root.write("/Windows/servicing/Packages/" + name + ".mum", _file('<update name="changed"/>'))
    raises(persist,args=[root,directory(),"/image6",closure,population,dict(),catalogs],message="actual resolved MUM differs")
    equal(digest(root.find("/Windows/System32/config/SOFTWARE"),algorithm="sha256"),original)

def _catalog_fixture(member):
    # Unsigned CTL for the index reader only; not a signature/trust fixture.
    def cat(*parts):
        return binary.concat(list(parts)).bytes()
    def der(tag,data):
        size = "%x" % len(data)
        if len(size) % 2:
            size = "0" + size
        if len(data) > 255:
            fail("test CTL exceeds its small fixture bound")
        length = cat(b"\x81" if len(data) >= 128 else b"", binary.decode(size,"hex",maximum=1))
        return cat(tag,length,data)
    entry = der(b"\x30",cat(der(b"\x04",member),b"\x31\x00"))
    algorithm = der(b"\x30",b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x0c\x01\x03")
    ctl = der(b"\x30",cat(b"\x30\x00",der(b"\x17",b"261022000000Z"),algorithm,der(b"\x30",entry)))
    content = der(b"\x30",cat(b"\x06\x09\x2b\x06\x01\x04\x01\x82\x37\x0a\x01",der(b"\xa0",ctl)))
    signed = der(b"\x30",cat(b"\x02\x01\x01\x31\x00",content,b"\x31\x00"))
    return der(b"\x30",cat(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02",der(b"\xa0",signed)))

def test_resolved_phase_requires_actual_pins_and_manifest_bytes():
    persist = testing.module("@stdlib//windows/servicing:package_store.star")["publish_package_metadata"]
    root, name, closure, population, catalogs = _resolved_fixture(component=True)
    identity = b"Payload, Culture=neutral, Version=10.0.1.0, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"
    deployment_name = windows.csi_deployment_key(identity)
    source = windows.cbs_deployment_source_data(closure["files"][name],"f")
    pin_name = "p!" + windows.cbs_deployment_source(source).source_key
    component = "/DerivedData/Components/payload"
    deployment = "/CanonicalData/Deployments/" + deployment_name
    root.write("/Windows/WinSxS/Manifests/payload.manifest", '<assembly xmlns="urn:schemas-microsoft-com:asm.v3">' + _identity("Payload") + '</assembly>')
    manifest = root.find("/Windows/WinSxS/Manifests/payload.manifest")
    root.write("/Windows/servicing/Packages/" + name + ".cat",_catalog_fixture(digest(manifest,algorithm="sha256")))
    def resolve(unused):
        return manifest
    analysis = dict(compositions={str(identity).lower():windows.csi_composition(identity,resolve)},manifests={str(identity).lower():manifest},resident_manifests={})
    patches = [
        dict(key=component,name="identity",type=3,value=identity),
        dict(key=component,name="S256H",type=3,value=digest(manifest,algorithm="sha256")),
        dict(key=component,name="c!" + deployment_name,type=3,value=b""),
        dict(key=deployment,name="appid",type=3,value=identity),
        dict(key=deployment,name=pin_name,type=3,value=source),
    ]
    # The missing-pin and corrupt-byte variants must fail before publishing any
    # package state, even though admitted targets and digest metadata look valid.
    software_hash = digest(root.find("/Windows/System32/config/SOFTWARE"),algorithm="sha256")
    root.write("/Windows/System32/config/COMPONENTS",windows.hive_from_patches("COMPONENTS",patches[:-1]))
    raises(persist,args=[root,directory(),"/image6",closure,population,analysis,catalogs],message="manifest pin")
    equal(digest(root.find("/Windows/System32/config/SOFTWARE"),algorithm="sha256"),software_hash)
    root.write("/Windows/System32/config/COMPONENTS",windows.hive_from_patches("COMPONENTS",patches))
    root.write("/Windows/WinSxS/Manifests/payload.manifest","corrupt")
    raises(persist,args=[root,directory(),"/image6",closure,population,analysis,catalogs],message="actual resolved manifest bytes")
    equal(digest(root.find("/Windows/System32/config/SOFTWARE"),algorithm="sha256"),software_hash)
    root.write("/Windows/WinSxS/Manifests/payload.manifest",manifest)
    report = persist(root,directory(),"/image6",closure,population,analysis,catalogs)
    equal((report["manifest_pins"],report["verified_manifests"],report["dispositions"][0]["state"]),(1,1,0x70))

def test_resolved_phase_uses_proof_not_last_action_or_absent_owner():
    persist = testing.module("@stdlib//windows/servicing:package_store.star")["publish_package_metadata"]
    root, name, closure, population, catalogs = _resolved_fixture(dormant_owner=True)
    equal(population.executions[0].action,0)
    equal(population.executions[0].mum_populated,True)
    persist(root,directory(),"/image6",closure,population,dict(),catalogs)
    hive = windows.hive(root.find("/Windows/System32/config/SOFTWARE"))
    equal(hive.find(_CBS + "Packages/" + name + "/Owners").values,{name:(2 << 16)|0x70})


def test_stage_only_is_not_promoted_and_unknown_state_is_not_published():
    persist = testing.module("@stdlib//windows/servicing:package_store.star")["publish_package_metadata"]
    root, name, closure, population, catalogs = _resolved_fixture(target=0x40)
    report = persist(root, directory(), "/image6", closure, population, dict(), catalogs)
    hive = windows.hive(root.find("/Windows/System32/config/SOFTWARE"))
    equal(hive.find(_CBS + "Packages/" + name).values["CurrentState"], 0x40)
    equal(hive.find(_CBS + "Packages/" + name + "/Owners").values[name], 0x20040)
    equal(report["dispositions"][0]["evidence"], "admitted stage-only disposition")
    # No admitted installation: do not publish either Installed or a guessed
    # Resolved fallback, and do not partially mutate the source hive.
    root, name, closure, population, catalogs = _resolved_fixture(target=0x20)
    before = digest(root.find("/Windows/System32/config/SOFTWARE"), algorithm="sha256")
    raises(persist, args=[root, directory(), "/image6", closure, population, dict(), catalogs], message="supported admitted stage/install")
    equal(digest(root.find("/Windows/System32/config/SOFTWARE"), algorithm="sha256"), before)

def test_owner_request_is_not_capped_to_package_state():
    persist = testing.module("@stdlib//windows/servicing:package_store.star")["publish_package_metadata"]
    root, name, closure, population, catalogs = _resolved_fixture(target=0x70, owner_state=0x80)
    persist(root, directory(), "/image6", closure, population, dict(), catalogs)
    hive = windows.hive(root.find("/Windows/System32/config/SOFTWARE"))
    equal(hive.find(_CBS + "Packages/" + name).values["CurrentState"], 0x70)
    equal(hive.find(_CBS + "Packages/" + name + "/Owners").values[name], 0x20080)


def test_inventory_audit_detects_downgrades_and_missing_metadata():
    audit = testing.module("@stdlib//windows/servicing:package_audit.star")["audit_package_states"]
    persist = testing.module("@stdlib//windows/servicing:package_store.star")["publish_package_metadata"]
    root, name, closure, population, catalogs = _resolved_fixture()
    path = "/Windows/System32/config/SOFTWARE"
    original = root.find(path)
    publication = persist(root, directory(), "/image6", closure, population, dict(), catalogs)
    for package in [name, "Existing"]:
        for extension in [".mum", ".cat"]:
            if root.find("/Windows/servicing/Packages/" + package + extension) == None:
                root.write("/Windows/servicing/Packages/" + package + extension, "metadata")
    report = audit(root, original, publication, dict(patches=[]))
    equal(report["packages"], 2)
    equal(report["issues"], [])
    # Readback of a fabricated lower state is a contradiction, not evidence
    # that an installed package is incomplete. Audit must not mutate it.
    root.write(path, windows.patch_hive(root.find(path), [dict(key=_CBS + "Packages/" + name, name="CurrentState", type="REG_DWORD", value=0x20)]))
    root.remove("/Windows/servicing/Packages/" + name + ".cat")
    before = digest(root.find(path), algorithm="sha256")
    report = audit(root, original, publication, dict(patches=[]))
    equal(len(report["issues"]), 1)
    equal(len(report["issues"][0]["findings"]), 2)
    equal(digest(root.find(path), algorithm="sha256"), before)

def test_resident_supersession_is_published_not_normalized_or_ignored():
    persist = testing.module("@stdlib//windows/servicing:package_store.star")["publish_package_metadata"]
    root, name, closure, unused, catalogs = _resolved_fixture()
    old = "Example~31bf3856ad364e35~amd64~~10.0.0.0"
    old_file = _file('<update name="f"/>')
    text = binary.text(old_file.bytes(), encoding="utf-8").replace('version="10.0.1.0"', 'version="10.0.0.0"')
    root.write("/Windows/servicing/Packages/" + old + ".mum", text)
    old_file = root.find("/Windows/servicing/Packages/" + old + ".mum")
    path = "/Windows/System32/config/SOFTWARE"
    key = _CBS + "Packages/" + old
    root.write(path, windows.patch_hive(root.find(path), [
        dict(key=key, name="CurrentState", type="REG_DWORD", value=0x70),
        dict(key=key, name="InstallClient", type="REG_SZ", value="Native"),
        dict(key=key+"/Owners", name=("Parent" + _SUFFIX), type="REG_DWORD", value=0x30070),
        dict(key=key+"/Owners", name=("Retained" + _SUFFIX), type="REG_DWORD", value=0x20040),
    ]))
    index = windows.cbs_update_index([dict(manifest=closure["files"][name], intended_state=0), dict(manifest=old_file, intended_state=0x70)])
    def applicable(package, unused_snapshot):
        return 0x50 if package == old else 0x70
    def mum(package, unused_snapshot, unused_action):
        return dict(before_updates=[dict(package=old, owner=("Parent" + _SUFFIX), state=0x50, integration=3, ceiling=0x1000)] if package == name else [], deferred=[])
    population = index.ordinary_population([dict(package=name,owner=name,state=0x70,integration=2,ceiling=0x1000)],
        [dict(package=old,owner=("Parent" + _SUFFIX),state=0x70,integration=3),dict(package=old,owner=("Retained" + _SUFFIX),state=0x40,integration=2)], applicable, mum, 100)
    equal(population.selected_executions([old])[0].intended_state, 0x50)
    report = persist(root, directory(), "/image6", closure, population, dict(), catalogs)
    hive = windows.hive(root.find(path))
    equal(hive.find(key).values["CurrentState"], 0x50)
    equal(hive.find(key).values["InstallClient"], "Native")
    equal(hive.find(key+"/Owners").values, {("Parent" + _SUFFIX):0x30050,("Retained" + _SUFFIX):0x20040})
    equal(hive.find(_CBS+"Packages/"+name).values["CurrentState"], 0x70)
    equal(report["resident_transitions"], 1)
    equal([r["state"] for r in report["dispositions"] if r["package"] == old], [0x50])

def test_resident_owner_deletion_and_unsupported_transition_are_atomic():
    persist = testing.module("@stdlib//windows/servicing:package_store.star")["publish_package_metadata"]
    root, name, closure, unused, catalogs = _resolved_fixture()
    path = "/Windows/System32/config/SOFTWARE"
    key = _CBS + "Packages/" + name
    removed, retained = "Removed"+_SUFFIX, "Retained"+_SUFFIX
    root.write(path, windows.patch_hive(root.find(path), [
        dict(key=key,name="CurrentState",type="REG_DWORD",value=0x70),
        dict(key=key+"/Owners",name=removed,type="REG_DWORD",value=0x30070),
        dict(key=key+"/Owners",name=retained,type="REG_DWORD",value=0x20070),
    ]))
    index = windows.cbs_update_index([dict(manifest=closure["files"][name],intended_state=0x70)])
    def mum(*unused):
        return dict(before_updates=[],deferred=[])
    def keep(*unused):
        return 0x70
    owners = [dict(package=name,owner=removed,state=0x70,integration=3),dict(package=name,owner=retained,state=0x70,integration=2)]
    request = dict(package=name,owner=removed,state=0,integration=3,ceiling=0x1000)
    population = index.ordinary_population([request],owners,keep,mum,100)
    equal(population.selected_executions([name])[0].intended_state,0x70)
    persist(root,directory(),"/image6",closure,population,dict(),catalogs)
    equal(windows.hive(root.find(path)).find(key+"/Owners").values,{retained:0x20070})
    def remove(*unused):
        return 0
    unsupported = index.ordinary_population([dict(request,owner=retained)],[],remove,mum,100)
    before = digest(root.find(path))
    raises(persist,args=[root,directory(),"/image6",closure,unsupported,dict(),catalogs],message="unsupported resident package transition")
    equal(digest(root.find(path)),before)

TEST_SUITE = suite("nt6_package_store", [
    case("multiple_parent_detector_indexes", test_multiple_parent_detector_indexes_are_not_applicability_pruned),
    case("resident_owner_delete_and_atomic_failure", test_resident_owner_deletion_and_unsupported_transition_are_atomic),
    case("resident_supersession", test_resident_supersession_is_published_not_normalized_or_ignored),
    case("inventory_audit_contradictions", test_inventory_audit_detects_downgrades_and_missing_metadata),
    case("stage_only_and_unsupported", test_stage_only_is_not_promoted_and_unknown_state_is_not_published),
    case("owner_request_not_capped", test_owner_request_is_not_capped_to_package_state),
    case("metadata_survives_converged_action", test_metadata_survives_converged_population_action),
    case("resolved_phase_uses_proof_not_last_action", test_resolved_phase_uses_proof_not_last_action_or_absent_owner),
    case("resolved_phase_requires_actual_pins_and_bytes", test_resolved_phase_requires_actual_pins_and_manifest_bytes),
    case("publication_preserves_admitted_dispositions", test_publication_preserves_admitted_dispositions),
    case("resolved_phase_rejects_missing_proof_atomically", test_resolved_phase_rejects_missing_proof_atomically),
    case("parent_metadata_is_not_owner_or_package_state", test_parent_metadata_is_not_owner_or_package_state),
    case("parent_update_index_and_special_release_indexes", test_parent_update_index_and_special_release_indexes),
    case("component_index_native_key_and_base_elevation", test_component_index_uses_native_key_and_base_elevation),
    case("unsupported_index_inputs_fail_closed", test_unsupported_index_inputs_fail_closed),
])

def main(args):
    return run([TEST_SUITE], args)
