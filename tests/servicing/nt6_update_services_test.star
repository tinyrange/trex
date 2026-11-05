"""Native service queue binding, authority and atomic publication controls."""
load("//tests:testing.star","case","equal","raises","suite")
load("@stdlib//windows/servicing:native_midground.star","service_category_jobs")
load("@stdlib//windows/servicing:services_native.star","plan_native_service_category")
load("@stdlib//windows/servicing:registry_effects.star","apply_update_registry_effects")

_KEY="/Microsoft/Windows NT/CurrentVersion/SvcHost"
_PATH="/Windows/System32/config/SOFTWARE"
_SD=windows.compile_sddl("O:BAG:BAD:P(A;;KA;;;BA)")

def _manifest(arch,group):
    return binary.concat(['<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="fixture" processorArchitecture="'+arch+'"/><memberships><categoryMembership><id name="Microsoft.Windows.Categories" version="1.0.0.0" publicKeyToken="365143bb27e7ac8b" typeName="SvcHost"/><categoryInstance subcategory="'+group+'"><serviceGroup position="last" serviceName="NativeService"/></categoryInstance></categoryMembership></memberships></assembly>'])

def _fixture():
    root=directory()
    root.write(_PATH,windows.hive_from_patches("SOFTWARE",[
        dict(key=_KEY,name="Group",type="REG_MULTI_SZ",value=["Old","Keep"]),
        dict(key=_KEY,name="Remove",type="REG_MULTI_SZ",value=["Old"]),
        dict(key=_KEY,name="Other",type="REG_SZ",value="untouched"),
        dict(key="/Wow6432Node"+_KEY,name="Group",type="REG_MULTI_SZ",value=["WowOld"]),
    ],keys=[dict(key=_KEY,security=_SD),dict(key="/Wow6432Node"+_KEY,security=_SD)]))
    return root,[(None,_manifest("amd64","Group"),None),(_manifest("amd64","Remove"),None,None)]

def _effects():
    return dict(keys=[],key_deletions=[],values=[dict(hive="SOFTWARE",key=_KEY,name="Group",type=7,value=binary.encode("Keep"+chr(0)+"NativeService"+chr(0)*2,encoding="utf16le"))],value_deletions=[dict(hive="SOFTWARE",key=_KEY,name="Remove")])

def test_preserve_order_security_and_other_view():
    root,jobs=_fixture()
    source=root.find(_PATH)
    plans=plan_native_service_category(root,jobs,_effects(),source)
    equal(digest(root.find(_PATH)),digest(source))
    equal(apply_update_registry_effects(root,plans),dict(hives=1,values=1,deleted_values=1,removed_keys=0))
    hive=windows.hive(root.find(_PATH))
    equal(hive.find(_KEY).values,{"Group":["Keep","NativeService"],"Other":"untouched"})
    equal(hive.find(_KEY).security,_SD)
    equal(hive.find("/Wow6432Node"+_KEY).values,{"Group":["WowOld"]})
    equal(hive.find("/Wow6432Node"+_KEY).security,_SD)

def test_late_rejections_and_stale_epochs():
    root,jobs=_fixture()
    source=root.find(_PATH)
    for fields in [dict(hive="SYSTEM"),dict(key="/Wow6432Node"+_KEY),dict(key=_KEY+"/Child"),dict(name="Other"),dict(type=1),dict(value=b"x"),dict(value=binary.encode("x"+chr(0),encoding="utf16le")),dict(value=binary.encode("x"+chr(0)*3,encoding="utf16le"))]:
        effects=_effects()
        bad=dict(effects["values"][0]); bad.update(fields)
        if "type" in fields or "value" in fields:
            effects["values"]=[bad]
        else:
            effects["values"].append(bad)
        equal(testing.attempt(plan_native_service_category,args=[root,jobs,effects,source]).ok,False)
        equal(digest(root.find(_PATH)),digest(source))
    effects=_effects(); effects["keys"]=[dict(hive="SOFTWARE",key=_KEY,security=_SD)]
    raises(plan_native_service_category,args=[root,jobs,effects,source],message="key effects")
    plans=plan_native_service_category(root,jobs,_effects(),source)
    root.write(_PATH,windows.patch_hive(source,[dict(key=_KEY,name="Other",type="REG_SZ",value="new epoch")]))
    changed=digest(root.find(_PATH))
    raises(apply_update_registry_effects,args=[root,plans],message="changed before commit")
    raises(plan_native_service_category,args=[root,jobs,_effects(),source],message="changed before planning")
    equal(digest(root.find(_PATH)),changed)

def test_queue_bindings_and_rejection():
    old,new,resident=[_manifest("amd64",n) for n in ["Old","New","Resident"]]
    row=dict(installer="2c10a69c378b534b9acc4e2ec0217057",phase=3,operation=2,flags=0,before=(0,"before"),after=(0,"after"),inspect=None)
    inspect=dict(row,operation=4,before=None,after=None,inspect=(0,"inspect"))
    queue=dict(finalized=True,inspection_required=True,inspection_inventory_supplied=True,entries=[row,inspect])
    equal(service_category_jobs(queue,[(old,new)],[resident]),[(old,new,None),(None,None,resident)])
    equal(service_category_jobs(dict(queue,entries=[dict(inspect,inspect=(0,"before"))]),[(old,new)],[resident]),[(None,None,old)])
    for fields in [dict(finalized=False),dict(inspection_inventory_supplied=False)]:
        bad=dict(queue); bad.update(fields)
        raises(service_category_jobs,args=[bad,[(old,new)],[resident]],message="finalized")
    for fields in [dict(phase=9),dict(flags=1),dict(before=(0,"after")),dict(after=(-1,"after")),dict(before=None,after=None),dict(operation=4),dict(inspect=(0,"inspect"))]:
        bad=dict(row); bad.update(fields)
        equal(testing.attempt(service_category_jobs,args=[dict(queue,entries=[bad]),[(old,new)],[resident]]).ok,False)

TEST_SUITE=suite("nt6/update-services-native",[
    case("preserve_order_security_and_other_view",test_preserve_order_security_and_other_view),
    case("late_rejections_and_stale_epochs",test_late_rejections_and_stale_epochs),
    case("queue_bindings_and_rejection",test_queue_bindings_and_rejection),
])
