"""Boot-installer publication boundaries and caller-supplied real-DLL checks."""
load("//tests:testing.star", "case", "equal", "contains", "raises", "suite")
load("@stdlib//windows/servicing:installer.star", "run_basic_installer")
load("@stdlib//windows/servicing:boot_installers.star", "publish_secureboot_effects")

_PATH="/Windows/System32/config/SYSTEM"
_KEY="/ControlSet002/Control/SecureBoot"
_SECURITY=windows.compile_sddl("O:SYG:SYD:P(A;;KA;;;SY)")

def _fixture(kind=None,value=None):
    root=directory()
    patches=[dict(key="/Select",name="Current",type="REG_DWORD",value=2),dict(key=_KEY,name="Unrelated",type="REG_SZ",value="retain"),dict(key=_KEY.replace("002","001"),name="AvailableUpdates",type="REG_DWORD",value=7)]
    if kind!=None: patches.append(dict(key=_KEY,name="aVAILABLEuPDATES",type=kind,value=value))
    root.write(_PATH,windows.hive_from_patches("SYSTEM",patches,keys=[dict(key_parts=_KEY[1:].split("/"),security=_SECURITY)]))
    return root

def _effect():
    return dict(hive="SYSTEM",key=_KEY,name="AvailableUpdates",type=4,raw=binary.u32le(0x402))

def test_secureboot_publication():
    for kind,value in [(None,None),("REG_DWORD",9),("REG_BINARY",binary.u32le(0x402)),("REG_DWORD",0x402)]:
        root=_fixture(kind,value)
        original=root.find(_PATH)
        changed=publish_secureboot_effects(root,[_effect()])
        equal(len(changed),0 if kind=="REG_DWORD" and value==0x402 else 1)
        actual=windows.hive(root.find(_PATH))
        node=actual.find(_KEY)
        name="aVAILABLEuPDATES" if kind!=None else "AvailableUpdates"
        equal(node.values[name],0x402)
        equal(node.value_records[name].type,4)
        equal(node.values["Unrelated"],"retain")
        equal(node.security,_SECURITY)
        equal(actual.find(_KEY.replace("002","001")).values["AvailableUpdates"],7)
        equal(publish_secureboot_effects(root,[_effect()]),[])
        equal(windows.hive(original).find(_KEY).values.get(name),value)

def test_secureboot_rejection_is_atomic():
    root=_fixture()
    before=digest(root.find(_PATH))
    for effects in [[],[_effect(),_effect()],[dict(_effect(),key=_KEY.replace("002","001"))],[dict(_effect(),raw=binary.u32le(7))],[dict(_effect(),type=3)]]:
        raises(publish_secureboot_effects,args=[root,effects])
        equal(digest(root.find(_PATH)),before)
    empty=directory()
    empty.write(_PATH,windows.hive_from_patches("SYSTEM",[dict(key="/Select",name="Current",type="REG_DWORD",value=2)]))
    raises(publish_secureboot_effects,args=[empty,[_effect()]],message="inherited security")

def verify_boot_installers(fve,secureboot):
    # Real Microsoft DLLs are supplied explicitly by the media-backed probe.
    rows=[]
    for kind,value in [(None,None),("REG_DWORD",9),("REG_BINARY",binary.u32le(0x402))]:
        root=_fixture(kind,value)
        source=root.find(_PATH)
        before=digest(source)
        hive=windows.hive(source)
        fv=run_basic_installer(fve,"fve",{"SYSTEM":hive})
        equal(fv["patches"],[])
        native=run_basic_installer(secureboot,"secureboot",{"SYSTEM":hive})
        equal(native["patches"],[_effect()])
        equal(digest(root.find(_PATH)),before)
        equal(len(publish_secureboot_effects(root,native["patches"])),1)
        replay=run_basic_installer(secureboot,"secureboot",{"SYSTEM":windows.hive(root.find(_PATH))})
        equal(replay["patches"],[_effect()])
        equal(publish_secureboot_effects(root,replay["patches"]),[])
        failure=raises(run_basic_installer,args=[secureboot,"secureboot",{"SYSTEM":hive}],kwargs=dict(instruction_limit=native["result"].steps-20))
        contains(failure,"instruction-limit")
        contains(failure,"native CSI initialization failed")
        equal(digest(source),before)
        actual=windows.hive(root.find(_PATH)).find(_KEY)
        equal(actual.security,_SECURITY)
        equal(actual.values["Unrelated"],"retain")
        rows.append(dict(original_type=kind,steps=native["result"].steps,fve_steps=fv["result"].steps,native_writes=1,replay_physical_writes=0,initialization_budget_failure=failure))
    return dict(passed=True,cases=rows)

TEST_SUITE=suite("nt6/update-boot-installers",[
    case("secureboot_publication",test_secureboot_publication),
    case("secureboot_rejection_is_atomic",test_secureboot_rejection_is_atomic),
])
