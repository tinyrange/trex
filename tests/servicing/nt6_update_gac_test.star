"""Managed cache refresh: declared hashes, companions and atomic preflight."""
load("//tests:testing.star", "case", "equal", "raises", "run", "suite")
gac = testing.module("@stdlib//windows/servicing:gac.star")

def _manifest(payload, companion, arch="msil", culture=""):
    files = ""
    for name, content, tag in [("Example.dll", payload, '<gac clrversion="4.0" managedversion="3.0.0.0" managedculture="'+culture+'"/>'), ("data.json", companion, "")]:
        files += '<file name="'+name+'">'+tag+'<hash xmlns="urn:schemas-microsoft-com:asm.v2"><Transforms xmlns="http://www.w3.org/2000/09/xmldsig#"><Transform Algorithm="urn:schemas-microsoft-com:HashTransforms.Identity"/></Transforms><DigestMethod xmlns="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2000/09/xmldsig#sha256"/><DigestValue xmlns="http://www.w3.org/2000/09/xmldsig#">'+binary.base64(digest(content, algorithm="sha256"))+'</DigestValue></hash></file>'
    return '<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0"><assemblyIdentity name="Example" version="10.0.1.0" processorArchitecture="'+arch+'" publicKeyToken="31bf3856ad364e35" language="neutral"/>'+files+'</assembly>'

def _fixture():
    before = _manifest("old", "old companion")
    after = _manifest("new", "new companion")
    cache = gac["_managed_declaration"](after)["path"]
    root = directory()
    security = windows.compile_sddl("O:SYG:SYD:P(A;;FA;;;SY)")
    for name, old, new in [("Example.dll", "old", "new"), ("data.json", "old companion", "new companion")]:
        root.write(cache+"/"+name, old)
        root.write("/Windows/WinSxS/exact/"+name, new)
        root.set_security("/Windows/WinSxS/exact/"+name, security)
    runtime = dict(transitions=[dict(before=before, after=after, component_identities=dict(after=b"exact identity"))])
    return root, runtime, {b"exact identity":"exact"}, cache

def test_cache_and_companions_use_exact_store_objects():
    root, runtime, stems, cache = _fixture()
    plans = gac["plan_update_gac"](root, runtime, stems)
    equal(len(plans), 2)
    equal(root.find(cache+"/Example.dll").read(), "old")
    result = gac["apply_update_gac"](root, plans)
    equal(result["refreshed_files"], 2)
    equal(root.find(cache+"/Example.dll").read(), "new")
    equal(root.find(cache+"/data.json").read(), "new companion")
    for p in plans:
        equal(root.get_metadata(p["path"]).hard_link_id, root.get_metadata(p["source"]).hard_link_id)
        equal(root.get_security(p["path"]), root.get_security(p["source"]))

def test_preflight_rejects_corruption_and_preserves_whole_batch():
    root, runtime, stems, cache = _fixture()
    root.write("/Windows/WinSxS/exact/data.json", "corrupt")
    raises(gac["plan_update_gac"], args=[root, runtime, stems], message="source hash mismatch")
    equal(root.find(cache+"/Example.dll").read(), "old")
    root, runtime, stems, cache = _fixture()
    plans = gac["plan_update_gac"](root, runtime, stems)
    root.write(cache+"/data.json", "concurrent edit")
    raises(gac["apply_update_gac"], args=[root, plans], message="changed after planning")
    equal(root.find(cache+"/Example.dll").read(), "old")
    equal(root.find(cache+"/data.json").read(), "concurrent edit")

def test_identity_and_unhandled_lifecycle_are_not_guessed():
    for arch, expected in [("msil", "MSIL"), ("amd64", "64"), ("wow64", "32")]:
        result = gac["_managed_declaration"](_manifest("a", "b", arch, "en"))
        equal(result["path"], "/Windows/Microsoft.NET/assembly/GAC_"+expected+"/Example/v4.0_3.0.0.0_en_31bf3856ad364e35")
    root, runtime, stems, cache = _fixture()
    runtime["transitions"][0]["before"] = None
    raises(gac["plan_update_gac"], args=[root, runtime, stems], message="Fusion lifecycle")
    raises(gac["_managed_declaration"], args=[_manifest("a", "b").replace('name="Example.dll"', 'name="../escape.dll"')], message="safe path leaf")

def test_fusion_notification_uses_file_time_and_one_transaction_counter():
    root,runtime,stems,cache=_fixture()
    path='/Windows/System32/config/SOFTWARE'
    key='/Microsoft/Fusion/GACChangeNotification/Default'
    root.write(path,windows.hive_from_patches('SOFTWARE',[
        dict(key=key,name=n,type='REG_DWORD',value=6) for n in ['StoreChangeId','StoreChangeIdFor32BitProcesses','StoreChangeIdFor64BitProcesses']
    ]+[dict(key=key,name='unrelated',type='REG_BINARY',value=b'keep')]))
    raises(gac['plan_update_gac_notifications'],args=[root,runtime],message='not refreshed')
    root.set_times('/Windows/WinSxS/exact/Example.dll',101,102,103)
    gac['apply_update_gac'](root,gac['plan_update_gac'](root,runtime,stems))
    plan=gac['plan_update_gac_notifications'](root,runtime)
    stamp=root.get_metadata(cache+'/Example.dll').last_write_time
    equal(plan['notifications'],1)
    result=gac['apply_update_gac_notifications'](root,plan)
    equal(result['counters'],3)
    values=windows.hive(root.find(path)).find(key).values
    equal(values['example,3.0.0.0,,31bf3856ad364e35,msil'],binary.u64le(stamp))
    equal(values['StoreChangeId'],7)
    equal(values['StoreChangeIdFor32BitProcesses'],7)
    equal(values['StoreChangeIdFor64BitProcesses'],7)
    equal(values['unrelated'],b'keep')
    plan=gac['plan_update_gac_notifications'](root,runtime)
    before=digest(root.find(path))
    root.set_times(cache+'/Example.dll',201,202,203)
    raises(gac['apply_update_gac_notifications'],args=[root,plan],message='changed before notification')
    equal(digest(root.find(path)),before)

TEST_SUITE = suite("nt6_update_gac", [
    case("fusion_notifications", test_fusion_notification_uses_file_time_and_one_transaction_counter),
    case("cache_and_companions", test_cache_and_companions_use_exact_store_objects),
    case("batch_preflight", test_preflight_rejects_corruption_and_preserves_whole_batch),
    case("identity_and_lifecycle", test_identity_and_unhandled_lifecycle_are_not_guessed),
])
def main(args):
    run([TEST_SUITE])
