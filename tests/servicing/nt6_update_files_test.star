"""Whole-image-tree invariants for the native update FileMap pass."""

load("//tests:testing.star", "case", "equal", "raises", "run", "suite")

files = testing.module("@stdlib//windows/servicing:files.star")
apply_files = testing.module("@stdlib//windows/servicing:file_apply.star")
map_security_policy = testing.module("@stdlib//windows/servicing:filemap_security.star")
commit_files = testing.module("@stdlib//windows/servicing:file_commit.star")
runtime_policy = testing.module("@stdlib//windows/servicing:runtime.star")


def _fixture():
    root = directory()
    identity = b"Microsoft-Windows-Test, Culture=neutral, Version=10.0.1.0, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"
    new_identity = bytes(str(identity).replace("10.0.1.0", "10.0.2.0"))
    owner = files["_map_identity"](identity)
    document = dict(path="\\??\\C:\\Windows\\System32", root_selector=0, identities=[owner], entries=[dict(name="target.dll", display_name="target.dll", flags=0, identity=0), dict(name="sibling.dll", display_name="sibling.dll", flags=0, identity=0)])
    leaf = "/Windows/WinSxS/FileMaps/" + windows.cdf_filemap_name("/Windows/System32")
    root.write(leaf, windows.cdf_filemap_encode(document))
    root.write("/Windows/System32/target.dll", "actual new payload")
    node = dict(destination="/Windows/System32/target.dll", before=dict(state=0, component_identity=identity), after=dict(state=2, component_identity=new_identity), operation=3, security_flags=0x88, directory_flags=0x88, file_flags=1, own_changed=True)
    hierarchy = runtime_policy["preprocess_servicing_path_hierarchy"]({}, {"/windows/system32/target.dll": node})
    return root, leaf, document, dict(hierarchy=hierarchy, collision_policy=dict(strict_directories=False)), new_identity


def test_filemap_owner_replacement_preserves_siblings():
    root, leaf, original, prepared, new_identity = _fixture()
    plan = files["plan_update_filemaps"](root, prepared)
    selected = [p for p in plan["plans"] if p["path"] == leaf][0]
    after = selected["document"]
    entries = {e["name"]: e for e in after["entries"]}
    equal(after["identities"][entries["target.dll"]["identity"]], files["_map_identity"](new_identity))
    equal(after["identities"][entries["sibling.dll"]["identity"]], original["identities"][0])
    # Planning must not prematurely overwrite maps or payloads.
    equal(files["_map_logical"](windows.cdf_filemap(root.find(leaf).bytes())), files["_map_logical"](original))
    equal(root.find("/Windows/System32/target.dll").read(), "actual new payload")
    descriptor = windows.compile_sddl("O:SYG:SYD:P(A;;FA;;;SY)")
    security = {p["path"]: descriptor for p in plan["plans"] if p["operation"] == "write"}
    result = files["apply_update_filemaps"](root, plan, security)
    equal(result["writes"], 1)
    equal(files["_map_logical"](windows.cdf_filemap(root.find(leaf).bytes())), files["_map_logical"](after))
    equal(root.get_security(leaf), descriptor)


def test_filemap_clean_payload_still_transfers_exact_owner():
    root, leaf, original, prepared, new_identity = _fixture()
    child = dict(prepared["hierarchy"]["/windows/system32/target.dll"])
    child["own_changed"] = False
    # A nonSxS update can have identical hashes, attributes and security.
    # The payload loop must stay empty, but the map must acquire the new owner.
    hierarchy = runtime_policy["preprocess_servicing_path_hierarchy"]({}, {"/windows/system32/target.dll": child})
    equal(runtime_policy["select_servicing_file_commit_paths"](hierarchy, 0), [])
    prepared["hierarchy"] = hierarchy
    plan = files["plan_update_filemaps"](root, prepared)
    equal(len(plan["plans"]), 1)
    after = plan["plans"][0]["document"]
    entries = {e["name"]: e for e in after["entries"]}
    equal(after["identities"][entries["target.dll"]["identity"]], files["_map_identity"](new_identity))
    equal(after["identities"][entries["sibling.dll"]["identity"]], original["identities"][0])
    equal(root.find("/Windows/System32/target.dll").read(), "actual new payload")
    # No identity transition and no payload changes remains a true no-op.
    child["before"] = dict(child["after"])
    prepared["hierarchy"] = runtime_policy["preprocess_servicing_path_hierarchy"]({}, {"/windows/system32/target.dll": child})
    equal(files["plan_update_filemaps"](root, prepared)["plans"], [])


def test_filemap_clean_directory_still_transfers_exact_owner():
    root, leaf, original, prepared, new_identity = _fixture()
    old_identity = prepared["hierarchy"]["/windows/system32/target.dll"]["before"]["component_identity"]
    original["entries"].append(dict(name=".", display_name=".", flags=0, identity=0))
    root.write(leaf, windows.cdf_filemap_encode(original))
    node = dict(before=dict(state=4, identity=old_identity), after=dict(state=4, identity=new_identity), operation=3, security_flags=8, directory_flags=0, own_changed=False)
    prepared["hierarchy"] = runtime_policy["preprocess_servicing_path_hierarchy"]({"/windows/system32": node}, {})
    plan = files["plan_update_filemaps"](root, prepared)
    equal(len(plan["plans"]), 1)
    after = plan["plans"][0]["document"]
    entries = {e["name"]: e for e in after["entries"]}
    equal(after["identities"][entries["."]["identity"]], files["_map_identity"](new_identity))
    equal(after["identities"][entries["target.dll"]["identity"]], original["identities"][0])
    # Native leaves an older resident directory incarnation alone when the
    # selected predecessor is not that exact owner and no payload work occurs.
    original["identities"][0] = files["_map_identity"](bytes(str(old_identity).replace("10.0.1.0", "10.0.0.0")))
    root.write(leaf, windows.cdf_filemap_encode(original))
    equal(files["plan_update_filemaps"](root, prepared)["plans"], [])


def test_filemap_apply_rejects_stale_baseline_and_missing_security():
    root, leaf, original, prepared, new_identity = _fixture()
    plan = files["plan_update_filemaps"](root, prepared)
    before = root.find(leaf).bytes()
    raises(files["apply_update_filemaps"], args=[root, plan, {}], message="security is missing")
    equal(root.find(leaf).bytes(), before)
    root.write(leaf, "concurrent edit")
    descriptor = windows.compile_sddl("O:SYG:SYD:P(A;;FA;;;SY)")
    security = {p["path"]: descriptor for p in plan["plans"] if p["operation"] == "write"}
    raises(files["apply_update_filemaps"], args=[root, plan, security], message="baseline changed")
    equal(root.find(leaf).read(), "concurrent edit")


def _commit_fixture(modified=False):
    root = directory()
    parent = windows.compile_sddl("O:SYG:SYD:AI(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)")
    root.mkdir("/Windows/System32")
    root.mkdir("/Windows/WinSxS/new")
    for path in ["/", "/Windows", "/Windows/System32", "/Windows/WinSxS", "/Windows/WinSxS/new"]:
        root.set_security(path, parent)
    root.write("/Windows/WinSxS/new/target.dll", "new payload")
    root.write("/Windows/WinSxS/new/settings.ini", "new settings")
    root.write("/Windows/System32/target.dll", "old payload")
    root.hardlink("/Windows/System32/target.dll", "/Windows/WinSxS/old-target.dll")
    root.write("/Windows/System32/obsolete.dll", "obsolete")
    root.hardlink("/Windows/System32/obsolete.dll", "/Windows/WinSxS/old-obsolete.dll")
    root.write("/Windows/System32/settings.ini", "custom settings" if modified else "old settings")
    for path in root.files:
        root.set_security(path, parent)
    root.set_times("/Windows/WinSxS/new/target.dll", 101, 102, 103)
    identity = b"Microsoft-Windows-Test, Culture=neutral, Version=10.0.2.0, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"
    descriptor = dict(sddl="O:SYG:SYD:P(A;;FA;;;SY)")
    sources = {}
    paths = {}
    nodes = {}
    for name, old, new, state in [("target.dll", "old payload", "new payload", 2), ("settings.ini", "old settings", "new settings", 1)]:
        key = (name,)
        hashes = {side: dict(digest_method=2, transform=1, digest=digest(text)) for side,text in [("before", old),("after", new)]}
        sources[key] = {side: dict(component_identity=identity, hash=hashes[side]) for side in ["before", "after"]}
        before = dict(state=0, attributes=0xa0, source_key=key, descriptor=descriptor, component_identity=identity, process_flags=0x48 if state == 1 else 0x40)
        after = dict(before)
        after.update(state=state, attributes=0x81 if state == 2 else 0xa0, process_flags=0x48 if state == 1 else 0x41)
        destination = "/Windows/System32/" + name
        nodes[destination.lower()] = dict(destination=destination, before=before, after=after, operation=3, security_flags=0x88, directory_flags=0xe8 if state == 1 else 0x88, file_flags=1, own_changed=True)
        paths[key] = "/Windows/WinSxS/new/" + name
    primary = nodes["/windows/system32/target.dll"]
    before = dict(primary["before"])
    after = dict(primary["after"])
    before.update(state=7, process_flags=0x50)
    after.update(state=7, process_flags=0x50)
    nodes["/windows/system32/alias.dll"] = dict(destination="/Windows/System32/alias.dll", before=before, after=after, operation=3, security_flags=0x88, directory_flags=0x88, file_flags=7, own_changed=True)
    nodes["/windows/system32/obsolete.dll"] = dict(destination="/Windows/System32/obsolete.dll", before=dict(state=0, process_flags=0x40), after=dict(state=0), operation=2, security_flags=0xc0, directory_flags=8, file_flags=1, own_changed=True)
    hierarchy = runtime_policy["preprocess_servicing_path_hierarchy"]({}, nodes)
    prepared = dict(hierarchy=hierarchy, sources=sources, policy=dict(enumerate_children=False))
    directories = commit_files["plan_update_directories"](root, prepared)
    return root, prepared, paths, directories


def test_runtime_commit_preserves_objects_not_replaced_paths():
    root, prepared, paths, directories = _commit_fixture(modified=True)
    original_security = root.get_security("/Windows/System32/settings.ini")
    plan = commit_files["plan_update_file_commits"](root, prepared, paths, directories)
    equal(root.find("/Windows/System32/target.dll").read(), "old payload")
    equal(root.find("/Windows/System32/obsolete.dll").read(), "obsolete")
    result = commit_files["apply_update_file_commits"](root, plan, 2)
    equal(result, dict(hardlinks=2, copies=0, preserved_writable=1, removed=1, already_absent=0))
    for path in ["/Windows/System32/target.dll", "/Windows/System32/alias.dll"]:
        equal(root.find(path).read(), "new payload")
        equal(root.get_metadata(path).hard_link_id, root.get_metadata(paths[("target.dll",)]).hard_link_id)
        equal(root.get_metadata(path).last_write_time, 102)
        equal(root.get_metadata(path).file_attributes, 1)
        equal(root.get_security(path), root.get_security(paths[("target.dll",)]))
    equal(root.find("/Windows/WinSxS/old-target.dll").read(), "old payload")
    equal(root.find("/Windows/WinSxS/old-obsolete.dll").read(), "obsolete")
    equal(root.find("/Windows/System32/obsolete.dll"), None)
    equal(root.find("/Windows/System32/settings.ini").read(), "custom settings")
    equal(root.get_security("/Windows/System32/settings.ini"), original_security)


def test_runtime_copy_rejects_stale_sources_before_unlink():
    root, prepared, paths, directories = _commit_fixture()
    plan = commit_files["plan_update_file_commits"](root, prepared, paths, directories)
    root.write(paths[("settings.ini",)], "tampered source")
    raises(commit_files["apply_update_file_commits"], args=[root, plan, 2], message="source changed")
    equal(root.find("/Windows/System32/obsolete.dll").read(), "obsolete")
    equal(root.find("/Windows/System32/target.dll").read(), "old payload")
    equal(root.find("/Windows/System32/settings.ini").read(), "old settings")
    root.write(paths[("settings.ini",)], "new settings")
    # A replacement binding requires a fresh plan even if its bytes match.
    plan = commit_files["plan_update_file_commits"](root, prepared, paths, directories)
    result = commit_files["apply_update_file_commits"](root, plan, 2)
    equal(result["copies"], 1)
    equal(root.find("/Windows/System32/settings.ini").read(), "new settings")
    equal(root.get_metadata("/Windows/System32/settings.ini").hard_link_id, 0)
    equal(root.get_metadata(paths[("settings.ini",)]).hard_link_id, 0)


def test_empty_directory_removal_requires_absent_map_ownership():
    root = directory()
    root.mkdir("/Windows/System32/Retired")
    root.mkdir("/Windows/System32/Owned")
    root.mkdir("/Windows/System32/Nonempty/Child")
    identity = b"Microsoft-Windows-Test, Culture=neutral, Version=10.0.1.0, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"
    document = dict(path="\\??\\C:\\Windows\\System32\\Owned", root_selector=0, identities=[files["_map_identity"](identity)], entries=[dict(name=".", display_name=".", flags=4, identity=0)])
    map_path = "/Windows/WinSxS/FileMaps/" + windows.cdf_filemap_name("/Windows/System32/Owned")
    root.write(map_path, windows.cdf_filemap_encode(document))
    hierarchy = {}
    names = {}
    for name in ["Retired","Owned","Nonempty"]:
        actual="/Windows/System32/"+name
        key=actual.lower()
        names[key]=actual
        hierarchy[key]=dict(kind="directory",subtree_changed=True,implicit=False,after=dict(state=0))
    result = apply_files["apply_update_directory_removals"](root,dict(hierarchy=hierarchy),names)
    equal(result["removed"], ["/Windows/System32/Retired"])
    equal(result["retained_owned"], ["/Windows/System32/Owned"])
    equal(testing.attempt(root.get_metadata,args=["/Windows/System32/Retired"]).ok, False)
    equal(testing.attempt(root.get_metadata,args=["/Windows/System32/Owned"]).ok, True)
    equal(root.list_dir("/Windows/System32/Nonempty"),["/Windows/System32/Nonempty/Child"])


def test_filemap_final_security_retains_only_existing_labels():
    root=directory()
    root.mkdir("/Windows/WinSxS/FileMaps")
    root.set_security("/Windows/WinSxS/FileMaps",windows.compile_sddl("O:SYG:SYD:PAI(A;;FA;;;SY)S:AI(AU;FASA;FW;;;WD)"))
    old="/Windows/WinSxS/FileMaps/old.cdf-ms"
    new="/Windows/WinSxS/FileMaps/new.cdf-ms"
    root.write(old,"old map")
    root.set_security(old,windows.compile_sddl("O:SYG:SYD:(A;;FA;;;SY)S:(ML;;0x1;;;S-1-16-8192)"))
    plans=dict(plans=[dict(operation="write",path=old),dict(operation="write",path=new)])
    result=map_security_policy["prepare_update_filemap_security"](root,plans)
    # Final native map default is TI-owned with six protected DACL entries,
    # audit mask 1f0116, and a retained label only for the existing object.
    for path,kinds in [(old,[2,17]),(new,[2])]:
        parts=windows.security_descriptor_parts(result[path])
        equal(parts["control"],0x9014)
        equal(len(windows.acl_entries(parts["dacl"])["entries"]),6)
        audit=windows.acl_entries(parts["sacl"])["entries"]
        equal([e["type"] for e in audit],kinds)
        equal(audit[0]["mask"],0x1f0116)
    equal(root.find(new),None)
    equal(root.find(old).read(),"old map")


def _driver_file_fixture():
    policy = testing.module("@stdlib//windows/servicing:driver_files.star")
    win32 = testing.module("@stdlib//windows/selfreg:win32.star")
    root = directory()
    parent = windows.compile_sddl("O:SYG:SYD:AI(A;OICI;FA;;;SY)(A;OICI;FRFX;;;BU)")
    leaf = windows.compile_sddl("O:SYG:SYD:P(A;;FA;;;SY)(A;;FRFX;;;BU)")
    root.write("/Windows/INF/example.inf","old INF")
    root.hardlink("/Windows/INF/example.inf","/Windows/WinSxS/old/example.inf")
    root.write("/Windows/System32/DriverStore/FileRepository/old/driver.sys","old SYS")
    root.write("/Windows/WinSxS/selected/example.inf","new INF")
    root.write("/Windows/WinSxS/selected/driver.sys","new SYS")
    for path in commit_files["image_path_names"](root).values():
        root.set_security(path,parent)
    initial = win32["virtual_file_entries"]({"D:"+p:root.find(p) for p in root.files})
    kernel = win32["kernel32_plugin"](prepared_file_entries=initial)
    def native(path):
        return ("D:"+path).replace("/",chr(92)).lower()
    inf = native("/Windows/INF/example.inf")
    repo = native("/Windows/System32/DriverStore/FileRepository/new")
    sys = repo+chr(92)+"driver.sys"
    contents = {inf:b"new INF",sys:b"new SYS"}
    generated = {p:dict(directory=False,data=data,security=leaf,attributes=0x81,creation_time=100,write_time=200,access_time=300,extended_attributes=[dict(name='$CI.CatalogHint',flags=0,value=b'catalog hint')]) for p,data in contents.items()}
    for path,canonical in [("/Windows/WinSxS/selected/example.inf",inf),("/Windows/System32/DriverStore/FileRepository/new/example.inf",inf),("/Windows/WinSxS/selected/driver.sys",sys)]:
        item = dict(generated[canonical])
        item["hardlink_to"] = canonical
        generated[native(path)] = item
    generated[repo] = dict(directory=True)
    kernel.state["paths"].update(generated)
    report = dict(generated_entries=generated,file_queries=[dict(api="createdirectoryw",path=repo,security_attributes=False)])
    return policy,root,report,initial,kernel


def test_native_driver_effects_construct_shared_objects_and_keep_old_siblings():
    policy,root,report,initial,kernel = _driver_file_fixture()
    old_id = root.get_metadata("/Windows/WinSxS/old/example.inf").hard_link_id
    plan = policy["plan_update_driver_file_effects"](root,report,initial,kernel)
    equal(root.find("/Windows/INF/example.inf").read(),"old INF")
    result = policy["apply_update_driver_file_effects"](root,plan)
    equal(result,dict(files=2,hardlinks=3,removed=0,directories=1,verified_hives=0))
    canonical = root.get_metadata("/Windows/INF/example.inf")
    equal(canonical.creation_time,100)
    equal(canonical.extended_attributes,[dict(name='$CI.CatalogHint',flags=0,value=b'catalog hint')])
    equal(canonical.file_attributes,1)
    for path in ["/Windows/WinSxS/selected/example.inf","/Windows/System32/DriverStore/FileRepository/new/example.inf"]:
        equal(root.find(path).bytes(),b"new INF")
        equal(root.get_metadata(path).hard_link_id,canonical.hard_link_id)
        equal(root.get_security(path),root.get_security("/Windows/INF/example.inf"))
    equal(root.find("/Windows/WinSxS/old/example.inf").read(),"old INF")
    equal(root.get_metadata("/Windows/WinSxS/old/example.inf").hard_link_id,old_id)
    equal(canonical.hard_link_id!=old_id,True)
    equal(root.find("/Windows/System32/DriverStore/FileRepository/old/driver.sys").read(),"old SYS")


def test_native_driver_effects_reject_incomplete_or_stale_metadata():
    policy,root,report,initial,kernel = _driver_file_fixture()
    first = list(report["generated_entries"])[0]
    descriptor = report["generated_entries"][first].pop("security")
    raises(policy["plan_update_driver_file_effects"],args=[root,report,initial,kernel],message="no final security")
    equal(root.find("/Windows/INF/example.inf").read(),"old INF")
    report["generated_entries"][first]["security"] = descriptor
    report["file_queries"][0]["security_attributes"] = True
    raises(policy["plan_update_driver_file_effects"],args=[root,report,initial,kernel],message="creation security is unestablished")
    report["file_queries"][0]["security_attributes"] = False
    plan = policy["plan_update_driver_file_effects"](root,report,initial,kernel)
    root.set_security("/Windows/INF/example.inf",windows.compile_sddl("O:SYG:SYD:P(A;;FR;;;SY)"))
    raises(policy["apply_update_driver_file_effects"],args=[root,plan],message="baseline changed before commit")
    equal(root.find("/Windows/INF/example.inf").read(),"old INF")
    equal(testing.attempt(root.get_security,args=["/Windows/System32/DriverStore/FileRepository/new"]).ok,False)


def _driver_transaction_fixture():
    policy, root, report, initial, kernel = _driver_file_fixture()
    win32 = testing.module("@stdlib//windows/selfreg:win32.star")
    backing = directory()
    paths = {}
    for name in ["SYSTEM", "SOFTWARE", "DRIVERS"]:
        path = "/Windows/System32/config/" + name
        source = windows.hive_from_patches(name, [dict(key="/Proof", name="Version", type="REG_DWORD", value=1)])
        changed = windows.hive_from_patches(name, [dict(key="/Proof", name="Version", type="REG_DWORD", value=2)])
        root.write(path, source)
        root.set_security(path, root.get_security("/Windows"))
        backing.write(path, changed)
        paths["D:"+path] = source
        native = ("D:"+path).replace("/",chr(92)).lower()
        report["generated_entries"][native] = dict(directory=False,data=changed)
    added = win32["virtual_file_entries"](paths)
    initial.update(added)
    kernel.state["paths"].update(added)
    def install(m):
        pass
    mount = emulator.plugin(install,name="closed-mount-fixture",state=dict(mounts={},pending={},epochs={}))
    return policy,root,report,initial,kernel,backing,mount


def test_driver_transaction_publishes_hives_and_files_together():
    policy,root,report,initial,kernel,backing,mount = _driver_transaction_fixture()
    result = policy["prepare_update_driver_transaction"](root,report,initial,kernel,backing,mount)
    candidate = result["root"]
    equal(result["counts"]["verified_hives"],3)
    equal(candidate.find("/Windows/INF/example.inf").bytes(),b"new INF")
    equal(root.find("/Windows/INF/example.inf").bytes(),b"old INF")
    for name in ["SYSTEM","SOFTWARE","DRIVERS"]:
        path = "/Windows/System32/config/"+name
        equal(windows.hive(root.find(path)).find("/Proof").values["Version"],1)
        equal(windows.hive(candidate.find(path)).find("/Proof").values["Version"],2)
        equal(candidate.get_security(path),root.get_security(path))
    equal(root.find("/Windows/System32/DriverStore/FileRepository/new/driver.sys"),None)


def test_driver_transaction_failure_never_publishes_hive_only_state():
    policy,root,report,initial,kernel,backing,mount = _driver_transaction_fixture()
    native = "d:"+chr(92)+"windows"+chr(92)+"inf"+chr(92)+"example.inf"
    report["generated_entries"][native].pop("security")
    raises(policy["prepare_update_driver_transaction"], args=[root,report,initial,kernel,backing,mount], message="no final security")
    for name in ["SYSTEM","SOFTWARE","DRIVERS"]:
        equal(windows.hive(root.find("/Windows/System32/config/"+name)).find("/Proof").values["Version"],1)
    equal(root.find("/Windows/INF/example.inf").bytes(),b"old INF")
    mount.state["pending"]["owned"] = True
    raises(policy["prepare_update_driver_transaction"], args=[root,report,initial,kernel,backing,mount], message="mounted hive epochs")


def test_driver_initial_metadata_staleness_is_not_hidden_by_matching_content():
    policy,root,report,initial,kernel = _driver_file_fixture()
    native = "d:"+chr(92)+"windows"+chr(92)+"inf"+chr(92)+"example.inf"
    initial[native]["security"] = root.get_security("/Windows/INF/example.inf")
    root.set_security("/Windows/INF/example.inf",windows.compile_sddl("O:SYG:SYD:P(A;;FR;;;SY)"))
    raises(policy["plan_update_driver_file_effects"],args=[root,report,initial,kernel],message="source metadata changed")
    equal(root.find("/Windows/INF/example.inf").bytes(),b"old INF")




def test_driver_runtime_destinations_require_manifest_hash_and_stable_baseline():
    policy,root,report,initial,kernel = _driver_file_fixture()
    qualification = testing.module('@stdlib//windows/servicing:driver_destinations.star')
    path = '/Windows/System32/drivers/example.sys'
    root.write(path,b'old runtime bytes')
    security = root.get_security('/Windows/WinSxS/selected/driver.sys')
    root.set_security('/Windows/System32/drivers',security)
    root.set_security(path,security)
    native = ('D:'+path).replace('/',chr(92)).lower()
    source = ('D:/Windows/System32/DriverStore/FileRepository/new/driver.sys').replace('/',chr(92)).lower()
    entry = dict(report['generated_entries'][source],hardlink_to=source)
    report['generated_entries'][native] = entry
    kernel.state['paths'][native] = entry
    expected = digest(entry['data'],algorithm='sha256')
    prepared = dict(hierarchy={path.lower():dict(kind='file',after=dict(state=2,source_key='exact'))},sources={'exact':dict(after=dict(hash=dict(digest_method=2,transform=1,digest=expected)))})
    payloads = dict(stages={})
    qualified = qualification['qualify_update_driver_destinations'](root,prepared,payloads,report['generated_entries'])
    equal(qualified['counts'],dict(runtime=1,unchanged=0,catalogs=0))
    raises(policy['plan_update_driver_file_effects'],args=[root,report,initial,kernel],message='unmodeled persistent')
    plan = policy['plan_update_driver_file_effects'](root,report,initial,kernel,authorized=qualified['paths'])
    root.write(path,b'concurrent replacement')
    raises(policy['plan_update_driver_file_effects'],args=[root,report,initial,kernel],kwargs=dict(authorized=qualified['paths']),message='qualification changed')
    root.write(path,b'old runtime bytes')
    policy['apply_update_driver_file_effects'](root,plan)
    equal(root.find(path).bytes(),b'new SYS')
    equal(root.get_metadata(path).hard_link_id,root.get_metadata('/Windows/System32/DriverStore/FileRepository/new/driver.sys').hard_link_id)
    prepared['sources']['exact']['after']['hash']['digest'] = b'wrong manifest digest'
    raises(qualification['qualify_update_driver_destinations'],args=[root,prepared,payloads,report['generated_entries']],message='differs from the admitted manifest')


def test_driver_destination_authority_never_accepts_unrelated_paths_or_catalog_names():
    qualification = testing.module('@stdlib//windows/servicing:driver_destinations.star')
    root = directory()
    root.write('/Windows/System32/unrelated.dll',b'same bytes')
    entry = dict(directory=False,data=b'same bytes')
    prepared = dict(hierarchy={},sources={})
    raises(qualification['qualify_update_driver_destinations'],args=[root,prepared,dict(stages={}),{'d:/windows/system32/unrelated.dll':entry}],message='no independent construction authority')
    catalog = 'd:/windows/system32/catroot/{f750e6c3-38ee-11d1-85e5-00c04fc295ee}/unrelated.cat'
    raises(qualification['qualify_update_driver_destinations'],args=[root,prepared,dict(stages={}),{catalog:entry}],message='differs from its staged source')



def test_runtime_default_does_not_read_payloads():
    root, prepared, paths, directories = _commit_fixture()
    profiler = clock.read_profiler(min_seconds=0.0)
    for path in paths.values():
        root.write(path, profiler.file(root.find(path), path))
    calls = []
    def planning():
        calls.append("planned")
    plan = commit_files["plan_update_file_commits"](root, prepared, paths, directories, while_verifying=planning)
    equal(calls, ["planned"])
    equal(profiler.snapshot()["total"]["calls"], 0)
    # Include both native commit phases so neither can hide a hash sweep.
    commit_files["apply_update_file_commits"](root, plan, 1)
    commit_files["apply_update_file_commits"](root, plan, 2)
    equal(profiler.snapshot()["total"]["calls"], 0)
    equal(root.find("/Windows/System32/alias.dll").read(), "new payload")
    equal(root.find("/Windows/System32/settings.ini").read(), "new settings")
    equal(profiler.snapshot()["total"]["calls"] > 0, True)


def test_runtime_explicit_audit_reads_and_rejects_corruption():
    root, prepared, paths, directories = _commit_fixture()
    profiler = clock.read_profiler(min_seconds=0.0)
    for path in paths.values():
        root.write(path, profiler.file(root.find(path), path))
    calls = []
    def planning():
        calls.append("planned")
    plan = commit_files["plan_update_file_commits"](root, prepared, paths, directories, while_verifying=planning, audit_payloads=True)
    equal(calls, ["planned"])
    equal(sorted([f["label"] for f in profiler.snapshot()["files"]]), sorted(paths.values()))
    equal(plan["audit_payloads"], True)
    root.write(paths[("target.dll",)], "bad payload")
    raises(commit_files["plan_update_file_commits"], args=[root, prepared, paths, directories], kwargs=dict(audit_payloads=True), message="source hash mismatch")
    equal(root.find("/Windows/System32/target.dll").read(), "old payload")
    equal(root.find("/Windows/System32/obsolete.dll").read(), "obsolete")


def test_runtime_default_rejects_removed_source_and_changed_writable():
    root, prepared, paths, directories = _commit_fixture()
    plan = commit_files["plan_update_file_commits"](root, prepared, paths, directories)
    root.remove(paths[("target.dll",)])
    raises(commit_files["apply_update_file_commits"], args=[root, plan, 2], message="source changed")
    equal(root.find("/Windows/System32/target.dll").read(), "old payload")
    root, prepared, paths, directories = _commit_fixture()
    plan = commit_files["plan_update_file_commits"](root, prepared, paths, directories)
    root.write("/Windows/System32/settings.ini", "new user change")
    raises(commit_files["apply_update_file_commits"], args=[root, plan, 2], message="writable projection changed")
    equal(root.find("/Windows/System32/target.dll").read(), "old payload")
    equal(root.find("/Windows/System32/settings.ini").read(), "new user change")


def test_source_folder_security_matches_native_image_control():
    stage = testing.module("@stdlib//windows/servicing:file_stage.star")
    parent = windows.compile_sddl("O:SYG:SYD:AI(A;OICI;FA;;;SY)S:AI")
    # Captured from the 26100.9441 amd64 servicing-stack source directory.
    # Eleven ACEs include separate effective and inherit-only generic grants;
    # replacing this with the ordinary six-ACE file policy is incorrect.
    expected = binary.decode("0100149c14000000340000000000000054000000010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487020018010b00000000032800ff011f00010600000000000550000000b589fb381984c2cb5c6c236d5700776ec002648700001800a900120001020000000000052000000020020000000b1800000000a00102000000000005200000002002000000001400a9001200010100000000000512000000000b1400000000a001010000000000051200000000001800a900120001020000000000052000000021020000000b1800000000a00102000000000005200000002102000000001800a9001200010200000000000f0200000001000000000b1800000000a0010200000000000f020000000100000000001800a9001200010200000000000f0200000002000000000b1800000000a0010200000000000f0200000002000000", "hex")
    equal(stage["build_update_source_folder_security"](parent),expected)
    unsupported = windows.compile_sddl("O:SYG:SYD:AI(A;OICI;FA;;;SY)S:AI(AU;OICISA;FA;;;WD)")
    raises(stage["build_update_source_folder_security"],args=[unsupported],message="parent SACL")

TEST_SUITE = suite("nt6_update_files", [
    case("clean_payload_owner_transfer", test_filemap_clean_payload_still_transfers_exact_owner),
    case("clean_directory_owner_transfer", test_filemap_clean_directory_still_transfers_exact_owner),
    case("source_folder_security",test_source_folder_security_matches_native_image_control),
    case("lazy_default_payloads", test_runtime_default_does_not_read_payloads),
    case("explicit_payload_audit", test_runtime_explicit_audit_reads_and_rejects_corruption),
    case("lazy_source_and_writable_stability", test_runtime_default_rejects_removed_source_and_changed_writable),
    case("qualified_runtime_overwrite",test_driver_runtime_destinations_require_manifest_hash_and_stable_baseline),
    case("destination_authority_rejections",test_driver_destination_authority_never_accepts_unrelated_paths_or_catalog_names),
    case("owner_replacement_preserves_siblings", test_filemap_owner_replacement_preserves_siblings),
    case("stale_baseline_and_security", test_filemap_apply_rejects_stale_baseline_and_missing_security),
    case("directory_removal_ownership", test_empty_directory_removal_requires_absent_map_ownership),
    case("filemap_final_label_policy", test_filemap_final_security_retains_only_existing_labels),
    case("runtime_object_effects", test_runtime_commit_preserves_objects_not_replaced_paths),
    case("runtime_stale_source_and_writable_copy", test_runtime_copy_rejects_stale_sources_before_unlink),
    case("native_driver_objects", test_native_driver_effects_construct_shared_objects_and_keep_old_siblings),
    case("native_driver_preflight", test_native_driver_effects_reject_incomplete_or_stale_metadata),
    case("native_driver_atomic_publish", test_driver_transaction_publishes_hives_and_files_together),
    case("native_driver_atomic_failure", test_driver_transaction_failure_never_publishes_hive_only_state),
    case("native_driver_stale_metadata", test_driver_initial_metadata_staleness_is_not_hidden_by_matching_content),
])


def main(args):
    run([TEST_SUITE])
