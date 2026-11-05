"""Native Appx deletion authority, preservation and failure atomicity."""
load("//tests:testing.star","case","equal","raises","suite")
load("@stdlib//windows/servicing:appx_native.star","plan_native_appx")
load("@stdlib//windows/servicing:registry_effects.star","apply_update_registry_effects")

_PATH="/Windows/System32/config/SOFTWARE"
_ROOT="/Microsoft/Windows/CurrentVersion/Appx/AppxAllUserStore"
_USER="S-1-5-21-1-2-3-500"
_PACKAGE="Native.Package_1.0.0.0_neutral__publisher"
_SD=windows.compile_sddl("O:BAG:BAD:P(A;;KA;;;BA)")

def _fixture():
    key=_ROOT+"/"+_USER+"/"+_PACKAGE
    root=directory()
    source=windows.hive_from_patches("SOFTWARE",[
        dict(key=key,name="Path",type="REG_SZ",value="C:"+chr(92)+"Native"),
        dict(key=key,name="NumberOfAttempts",type="REG_DWORD",value=2),
        dict(key=_ROOT+"/InboxApplications/"+_PACKAGE,name="Path",type="REG_SZ",value="keep inbox"),
        dict(key=_ROOT+"/"+_USER+"/Other.Package",name="Path",type="REG_SZ",value="keep user"),
    ],keys=[dict(key=_ROOT,security=_SD),dict(key=key,security=_SD)])
    root.write(_PATH,source)
    declared="HKEY_LOCAL_MACHINE"+chr(92)+"SOFTWARE"+(_ROOT+"/InboxApplications/"+_PACKAGE).replace("/",chr(92))
    manifest=binary.concat(['<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><appxRegistration/><registryKeys><registryKey keyName="'+declared+'"/></registryKeys></assembly>'])
    effects=dict(keys=[],values=[],key_deletions=[dict(hive="SOFTWARE",key=key)],value_deletions=[dict(hive="SOFTWARE",key=key,name="Path"),dict(hive="SOFTWARE",key=key,name="NumberOfAttempts")])
    return root,source,[(1,manifest)],effects

def test_preserve_inbox_and_other_registrations():
    root,source,jobs,effects=_fixture()
    plans=plan_native_appx(root,jobs,effects,source)
    equal(digest(root.find(_PATH)),digest(source))
    equal(apply_update_registry_effects(root,plans),dict(hives=1,values=0,deleted_values=2,removed_keys=1))
    hive=windows.hive(root.find(_PATH))
    equal(hive.find(effects["key_deletions"][0]["key"]),None)
    equal(hive.find(_ROOT+"/InboxApplications/"+_PACKAGE).values,{"Path":"keep inbox"})
    equal(hive.find(_ROOT+"/"+_USER+"/Other.Package").values,{"Path":"keep user"})
    equal(hive.find(_ROOT).security,_SD)

def test_reject_late_authority_and_epoch_changes():
    root,source,jobs,effects=_fixture()
    for key in [_ROOT+"/InboxApplications/"+_PACKAGE,_ROOT+"/"+_USER+"/Other.Package",_ROOT+"/S-1-5-18/"+_PACKAGE,_ROOT+"/"+_USER,effects["key_deletions"][0]["key"]]:
        bad=dict(effects,key_deletions=effects["key_deletions"]+[dict(hive="SOFTWARE",key=key)])
        equal(testing.attempt(plan_native_appx,args=[root,jobs,bad,source]).ok,False)
        equal(digest(root.find(_PATH)),digest(source))
    bad=dict(effects,value_deletions=effects["value_deletions"]+[dict(hive="SOFTWARE",key=_ROOT+"/InboxApplications/"+_PACKAGE,name="Path")])
    raises(plan_native_appx,args=[root,jobs,bad,source],message="outside removed")
    bad=dict(effects,values=[dict(hive="SOFTWARE",key=_ROOT,name="Bad",type=4,value=binary.u32le(1))])
    raises(plan_native_appx,args=[root,jobs,bad,source],message="non-deletion")
    plans=plan_native_appx(root,jobs,effects,source)
    root.write(_PATH,windows.patch_hive(source,[dict(key=_ROOT,name="Other",type="REG_DWORD",value=1)]))
    changed=digest(root.find(_PATH))
    raises(apply_update_registry_effects,args=[root,plans],message="changed before commit")
    raises(plan_native_appx,args=[root,jobs,effects,source],message="changed before planning")
    equal(digest(root.find(_PATH)),changed)

TEST_SUITE=suite("nt6/update-appx-native",[
    case("preserve_inbox_and_other_registrations",test_preserve_inbox_and_other_registrations),
    case("reject_late_authority_and_epoch_changes",test_reject_late_authority_and_epoch_changes),
])
