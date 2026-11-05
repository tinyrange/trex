"""Atomic publication and delete/recreate controls for native Events effects."""
load("//tests:testing.star", "case", "equal", "raises", "suite")
load("@stdlib//windows/servicing:events_native.star", "plan_native_events")
load("@stdlib//windows/servicing:registry_effects.star", "apply_update_registry_effects")

_KEY="/Microsoft/Windows/CurrentVersion/WINEVT/Publishers/{9db0fdb5-3b21-440e-a94b-63738a4be5de}"
_LOG="/ControlSet002/Control/WMI/Autologger/EventLog-System"
# Exact measured NULL-creator SYSTEM policy, not an arbitrary ACL fallback.
_SECURITY=binary.decode("01000480580000006400000000000000140000000200440003000000000214003f000f0001010000000000051200000000021400000002000101000000000003040000000002140019000200010100000000000100000000010100000000000512000000010100000000000512000000","hex")
_OLD=windows.compile_sddl("O:BAG:BAD:P(A;;KA;;;BA)")

def _fixture():
    root=directory()
    parent=_KEY.rsplit("/",1)[0]
    software=windows.hive_from_patches("SOFTWARE",[
        dict(key=_KEY,name="Stale",type="REG_DWORD",value=9),
        dict(key=_KEY+"/StaleChild",name="Old",type="REG_SZ",value="remove"),
        dict(key=parent+"/Other",name="Keep",type="REG_SZ",value="unchanged"),
    ],keys=[dict(key=parent,security=_SECURITY),dict(key=_KEY,security=_OLD)])
    system=windows.hive_from_patches("SYSTEM",[
        dict(key="/Select",name="Current",type="REG_DWORD",value=2),
        dict(key=_LOG,name="Start",type="REG_DWORD",value=0),
        dict(key=_LOG,name="Keep",type="REG_SZ",value="unchanged"),
        dict(key=_LOG.replace("002","001"),name="Start",type="REG_DWORD",value=7),
    ],keys=[dict(key=_LOG,security=_SECURITY)])
    for hive,file in [("SOFTWARE",software),("SYSTEM",system)]: root.write("/Windows/System32/config/"+hive,file)
    return root

def _effects():
    return dict(keys=[dict(hive="SOFTWARE",key=_KEY)],key_deletions=[dict(hive="SOFTWARE",key=_KEY)],value_deletions=[],values=[
        dict(hive="SOFTWARE",key=_KEY,name="",type=1,value=binary.encode("Native Publisher",encoding="utf16le",nul=True)),
        dict(hive="SYSTEM",key=_LOG,name="Start",type=4,value=binary.u32le(1)),
    ])

def _hashes(root):
    return [digest(root.find("/Windows/System32/config/"+hive)) for hive in ["SOFTWARE","SYSTEM"]]

def test_publication_recreates_security_and_preserves_neighbors():
    root=_fixture()
    before=_hashes(root)
    plans=plan_native_events(root,_effects())
    equal(_hashes(root),before)
    equal(apply_update_registry_effects(root,plans)["hives"],2)
    software=windows.hive(root.find("/Windows/System32/config/SOFTWARE"))
    node=software.find(_KEY)
    equal(node.security,_SECURITY)
    equal(node.values,{"(default)":"Native Publisher"})
    equal(software.find(_KEY+"/StaleChild"),None)
    equal(software.find(_KEY.rsplit("/",1)[0]+"/Other").values["Keep"],"unchanged")
    system=windows.hive(root.find("/Windows/System32/config/SYSTEM"))
    equal(system.find(_LOG).security,_SECURITY)
    equal(system.find(_LOG).values,{"Start":1,"Keep":"unchanged"})
    equal(system.find(_LOG.replace("002","001")).values["Start"],7)

def test_late_rejection_and_stale_sources_are_atomic():
    root=_fixture()
    before=_hashes(root)
    for key in [_LOG.replace("002","001"),"/ControlSet002/Services/Unexpected","/ControlSet002/Services/Eventlog","/ControlSet002/Services/Eventlog/System","/ControlSet002/Services/Eventlog/Security/Source","/ControlSet001/Services/Eventlog/System/Source","/ControlSet002/Services/Eventlog/System/Source/Child"]:
        effects=_effects()
        effects["values"].append(dict(hive="SYSTEM",key=key,name="x",type=4,value=binary.u32le(1)))
        raises(plan_native_events,args=[root,effects],message="authority")
        equal(_hashes(root),before)
    plans=plan_native_events(root,_effects())
    path="/Windows/System32/config/SYSTEM"
    root.write(path,windows.patch_hive(root.find(path),[dict(key="/Select",name="Current",type="REG_DWORD",value=1)]))
    changed=_hashes(root)
    raises(apply_update_registry_effects,args=[root,plans],message="changed before commit")
    equal(_hashes(root),changed)

def test_classic_source_recreation_is_leaf_scoped():
    root=_fixture()
    key="/ControlSet002/Services/Eventlog/System/Native-Source"
    neighbor=key.rsplit("/",1)[0]+"/Other"
    path="/Windows/System32/config/SYSTEM"
    root.write(path,windows.patch_hive(root.find(path),[
        dict(key=key,name="Stale",type="REG_SZ",value="remove"),
        dict(key=neighbor,name="Keep",type="REG_DWORD",value=1),
        dict(key=key.rsplit("/",1)[0],name="MaxSize",type="REG_DWORD",value=65536),
    ],keys=[dict(key=key.rsplit("/",1)[0],security=_SECURITY),dict(key=key,security=_OLD)]))
    effects=dict(keys=[dict(hive="SYSTEM",key=key)],key_deletions=[dict(hive="SYSTEM",key=key)],value_deletions=[],values=[dict(hive="SYSTEM",key=key,name="EventMessageFile",type=2,value=binary.encode("%SystemRoot%\\System32\\native.dll",encoding="utf16le",nul=True))])
    before=_hashes(root)
    plans=plan_native_events(root,effects)
    equal(_hashes(root),before)
    equal(apply_update_registry_effects(root,plans)["hives"],1)
    hive=windows.hive(root.find(path))
    equal(hive.find(key).values,{"EventMessageFile":"%SystemRoot%\\System32\\native.dll"})
    equal(hive.find(key).security,_SECURITY)
    equal(hive.find(neighbor).values,{"Keep":1})
    equal(hive.find(key.rsplit("/",1)[0]).values,{"MaxSize":65536})
    equal(_hashes(root)[0],before[0])

TEST_SUITE=suite("nt6/update-events-publication",[
    case("recreate_security_and_preserve_neighbors",test_publication_recreates_security_and_preserves_neighbors),
    case("late_rejection_and_stale_sources_are_atomic",test_late_rejection_and_stale_sources_are_atomic),
    case("classic_source_recreation_is_leaf_scoped",test_classic_source_recreation_is_leaf_scoped),
])
