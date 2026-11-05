"""Native basic phase ordering and exact HTTP mutation authority."""
load("//tests:testing.star", "case", "equal", "raises", "suite")
load("@stdlib//windows/servicing:installer.star", "basic_jobs_from_queue")
load("@stdlib//windows/servicing:http_native.star", "plan_native_http_effects")
load("@stdlib//windows/servicing:registry_effects.star", "apply_update_registry_effects")

_HTTP="1ae0fe864a95df11bc0ccea7dfd72085"
_PATH="/Windows/System32/config/SYSTEM"
_KEY="/ControlSet002/Services/HTTP/Parameters/UrlAclInfo"
_SD=windows.compile_sddl("D:(A;;GX;;;NS)")
_SECURITY=windows.compile_sddl("O:SYG:SYD:P(A;;KA;;;SY)")

def _entry(phase,operation,**kw):
    result=dict(installer=_HTTP,flags=0,phase=phase,operation=operation,before=(0,"before"),after=(0,"after"),inspect=None)
    result.update(kw)
    return result

def _queue(entries): return dict(finalized=True,entries=entries)

def test_phase_binding_is_not_smart_operation_numbering():
    old,new=[binary.concat([s]) for s in ["old","new"]]
    jobs=basic_jobs_from_queue(_queue([_entry(8,1),_entry(10,3)]),"http",[(old,new)])
    equal([(j["operation"],j["phase"],j["manifest"]) for j in jobs],[("uninstall",8,old),("install",10,new)])
    equal([(j["before"],j["after"]) for j in jobs],[(old,new)]*2)
    for entries in [[_entry(10,3),_entry(8,1)],[_entry(8,2)],[_entry(9,2)],[_entry(8,1,flags=1)],[_entry(8,1,before=None)],[_entry(10,3,after=None)],[_entry(10,3,after=(1,"after"))],[_entry(8,1,before=(0,"after"))],[_entry(8,1,inspect=(0,"inspect"))]]:
        equal(testing.attempt(basic_jobs_from_queue,args=[_queue(entries),"http",[(old,new)]]).ok,False)
    raises(basic_jobs_from_queue,args=[_queue([_entry(10,3,after=(1,"after"))]),"http",[(old,new),(old,new)]],message="mixed change pairs")
    raises(basic_jobs_from_queue,args=[dict(finalized=False,entries=[]),"http",[]],message="finalized")

def _fixture():
    root=directory()
    patches=[dict(key="/Select",name="Current",type="REG_DWORD",value=2)]
    for key in [_KEY,_KEY.replace("002","001")]:
        for name in ["http://+:80/old/","http://+:80/unrelated/"]:
            patches.append(dict(key=key,name=name,type=3,value=b"preserved"))
    root.write(_PATH,windows.hive_from_patches("SYSTEM",patches,keys=[dict(key=_KEY,security=_SECURITY)]))
    return root

def test_remove_then_install_preserves_neighbors_and_security():
    root=_fixture()
    before=digest(root.find(_PATH))
    old=[dict(url="http://+:80/old/",sddl="D:(A;;GX;;;NS)")]
    removed=dict(operation="uninstall",phase=8,patches=[],value_deletions=[dict(hive="SYSTEM",key=_KEY,name=old[0]["url"])])
    plans=plan_native_http_effects(root,old,removed)
    equal(digest(root.find(_PATH)),before)
    apply_update_registry_effects(root,plans)
    equal(windows.hive(root.find(_PATH)).find(_KEY).values.get(old[0]["url"]),None)
    new=[dict(url="http://+:80/new/",sddl="D:(A;;GX;;;NS)")]
    installed=dict(operation="install",phase=10,value_deletions=[],patches=[dict(key=_KEY,name=new[0]["url"],type=3,raw=_SD)])
    apply_update_registry_effects(root,plan_native_http_effects(root,new,installed))
    hive=windows.hive(root.find(_PATH))
    equal(hive.find(_KEY).security,_SECURITY)
    equal(hive.find(_KEY).values,{"http://+:80/unrelated/":b"preserved",new[0]["url"]:_SD})
    equal(hive.find(_KEY.replace("002","001")).values[old[0]["url"]],b"preserved")

def test_late_bad_native_effect_cannot_publish():
    root=_fixture()
    before=digest(root.find(_PATH))
    rows=[dict(url="http://+:80/old/",sddl="D:(A;;GX;;;NS)")]
    good=dict(hive="SYSTEM",key=_KEY,name=rows[0]["url"])
    for bad in [dict(good,key=_KEY.replace("002","001")),dict(good,name="http://+:80/unrelated/"),dict(good,hive="SOFTWARE"),good]:
        result=dict(operation="uninstall",phase=8,patches=[],value_deletions=[good,bad])
        raises(plan_native_http_effects,args=[root,rows,result],message="authority")
        equal(digest(root.find(_PATH)),before)
    result=dict(operation="uninstall",phase=8,patches=[],value_deletions=[])
    raises(plan_native_http_effects,args=[root,rows,result],message="complete input table")
    equal(digest(root.find(_PATH)),before)

TEST_SUITE=suite("nt6/update-basic-queue",[
    case("phase_binding",test_phase_binding_is_not_smart_operation_numbering),
    case("remove_install_preservation",test_remove_then_install_preserves_neighbors_and_security),
    case("late_rejection",test_late_bad_native_effect_cannot_publish),
])
