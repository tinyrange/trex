"""Ordered native key-flag effects and multi-hive atomic admission."""
load("//tests:testing.star", "case", "equal", "raises", "suite")
load("@stdlib//windows/servicing:system_protection_native.star", "plan_native_key_flags")
load("@stdlib//windows/servicing:registry_effects.star", "apply_update_registry_effects")

_SECURITY=windows.compile_sddl("O:SYG:SYD:P(A;;KA;;;SY)")

def _fixture():
    root=directory()
    for hive in ["SOFTWARE","SYSTEM"]:
        source=windows.hive_from_patches(hive,[dict(key="/Key",name="Keep",type="REG_SZ",value="unchanged"),dict(key="/Neighbor",name="Keep",type=3,value=b"neighbor")],keys=[dict(key="/Key",flags=0xa0,security=_SECURITY),"/Key/Child"])
        source=windows.patch_hive(source,[],key_flags=[dict(key="/Key",user_flags=13,virtualization_flags=1)])
        root.write("/Windows/System32/config/"+hive,source)
    return root

def _hashes(root): return [digest(root.find("/Windows/System32/config/"+h)) for h in ["SOFTWARE","SYSTEM"]]

def test_ordered_disable_then_enable_does_not_restore_virtual_store():
    root=_fixture()
    before=_hashes(root)
    records=[dict(hive="SOFTWARE",key_parts=["Key"],virtualization_flags=f) for f in [2,0,1]]
    records.append(dict(hive="SYSTEM",key_parts=["Key"],virtualization_flags=10))
    plans=plan_native_key_flags(root,records)
    equal(_hashes(root),before)
    equal(apply_update_registry_effects(root,plans)["hives"],2)
    for hive,flags in [("SOFTWARE",1),("SYSTEM",10)]:
        target=windows.hive(root.find("/Windows/System32/config/"+hive))
        key=target.find("/Key")
        equal((key.virtualization_flags,key.user_flags,key.flags),(flags,13,0x20))
        equal(key.security,_SECURITY)
        equal(key.values,{"Keep":"unchanged"})
        equal([c.name for c in key.children],["Child"])
        equal(target.find("/Neighbor").values,{"Keep":b"neighbor"})

def test_late_rejection_and_stale_second_hive_publish_nothing():
    root=_fixture()
    before=_hashes(root)
    records=[dict(hive=h,key_parts=["Key"],virtualization_flags=10) for h in ["SOFTWARE","SYSTEM"]]
    for bad in [dict(records[1],key_parts=["Absent"]),dict(records[1],virtualization_flags=16),dict(records[1],hive="SAM"),dict(records[1],key_parts=[]),dict(records[1],user_flags=1)]:
        equal(testing.attempt(plan_native_key_flags,args=[root,records[:1]+[bad]]).ok,False)
        equal(_hashes(root),before)
    plans=plan_native_key_flags(root,records)
    path="/Windows/System32/config/SYSTEM"
    root.write(path,windows.patch_hive(root.find(path),[dict(key="/Key",name="Changed",type=3,value=b"later")]))
    changed=_hashes(root)
    raises(apply_update_registry_effects,args=[root,plans],message="changed before commit")
    equal(_hashes(root),changed)

TEST_SUITE=suite("nt6/update-key-flags-publication",[
    case("ordered_disable",test_ordered_disable_then_enable_does_not_restore_virtual_store),
    case("atomic_admission",test_late_rejection_and_stale_second_hive_publish_nothing),
])
