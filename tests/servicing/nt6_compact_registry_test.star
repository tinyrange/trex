"""Differential compact planning against the detailed inspection reducer."""
load("//tests:testing.star", "case", "equal", "raises", "suite")
load("@stdlib//windows/servicing:registry.star", "prepare_update_registry_keys", "plan_update_ordinary_registry", "changed_update_registry_values")

_RESOLVE = windows.registry_path_mapper([(r"\registry\machine\software", 3)])
_FIELDS = ["path", "parent", "before_present", "after_present", "explicit", "hive_boundary", "owner", "owned_addition_collisions", "operation", "security_flags", "auxiliary_flags", "descriptor", "old_descriptor", "subtree_changed"]

def _manifest(path, side, owner, text=None, attrs="", value="", architecture="amd64"):
    security = '' if text == None else '<trustInfo><security><accessControl><securityDescriptorDefinitions><securityDescriptorDefinition name="sd" sddl="'+text+'"/></securityDescriptorDefinitions></accessControl></security></trustInfo>'
    reference = '' if text == None else '<securityDescriptor name="sd"/>'
    xml = '<assembly xmlns="urn:schemas-microsoft-com:asm.v3">'+security+'<registryKeys><registryKey keyName="'+path+'" '+attrs+'>'+reference+value+'</registryKey></registryKeys></assembly>'
    return dict(root=binary.xml(xml).root, side=side, owner=owner, architecture=architecture)

def _collect(rows, compact):
    return windows.registry_contributions(rows, _RESOLVE, lambda text,arch: text, capture_key_records=True, compact_key_records=compact)

def _runtime(buckets):
    return dict(transitions=[dict(component_identities=dict(before="old"+str(i), after="new"+str(i))) for i in range(len(buckets))])

def _compare(rows, buckets):
    results=[]
    for compact in [False, True]:
        collected=_collect(rows,compact)
        if compact: collected["groups"] = changed_update_registry_values(collected["groups"])
        results.append(prepare_update_registry_keys(_runtime(buckets),collected["groups"],buckets,collected["key_records"]))
    for scope in ["system","user"]:
        equal(sorted(results[0][scope]),sorted(results[1][scope]))
        for path in results[0][scope]:
            for field in _FIELDS:
                equal(results[0][scope][path][field],results[1][scope][path][field],scope+":"+path+":"+field)
    return results

def test_differential_hierarchy_security_ownership_and_values():
    # Equal text with inherited ACEs uses interning; unequal text must use the
    # asymmetric rights comparison. Null security is distinct from empty ACL.
    texts=[None,"O:SYG:SYD:P(A;;KA;;;SY)","O:SYG:SYD:P(A;;KR;;;SY)","O:SYG:SYD:P(A;ID;KA;;;SY)"]
    for before in texts:
        for after in texts:
            rows=[
                _manifest(r"HKLM\Software\Fixture\Child","after",0,after,'owner="true"'),
                _manifest(r"HKLM\Software\Fixture\Child","before",0,before),
                _manifest(r"HKLM\Software\Fixture","after",1,None,'owner="TRUE" perUserVirtualization="DisableRecurse" mapDesiredAccessToMaxAllowedAccess="False"'),
                _manifest(r"HKLM\Software\Fixture\Child","after",1,after),
                _manifest(r"HKLM\Software\Retired\Leaf","before",0),
                _manifest(r"HKEY_CURRENT_USER\Software\Fixture","before",0,before),
                _manifest(r"HKEY_CURRENT_USER\Software\Fixture","after",0,after),
                _manifest(r"HKLM\Software\Wow","after",0,None,architecture="x86"),
                _manifest(r"HKLM\Software\Literal/Slash\.","before",0),
                _manifest(r"HKLM\Software\Literal/Slash\.","after",0),
            ]
            # Opposite family order checks priority independently of input order.
            _compare(rows,{0:8,1:2})
    for old,new in [('1','2'),('2','2')]:
        value=lambda v: '<registryValue name="N" valueType="REG_DWORD" value="'+v+'"/>'
        rows=[_manifest(r"HKLM\Software\Fixture","before",0,value=value(old)),_manifest(r"HKLM\Software\Fixture","after",1,value=value(new))]
        _compare(rows,{0:0,1:0})
    # Owner-only provenance changes do not make identical value multisets dirty;
    # duplicate multiplicity and empty MULTI_SZ provenance still do.
    # A duplicated equal value on just one side is not an unchanged multiset.
    same = '<registryValue name="N" valueType="REG_DWORD" value="1"/>'
    duplicated = [_manifest(r"HKLM\Software\Fixture","before",0,value=same), _manifest(r"HKLM\Software\Fixture","after",0,value=same+same)]
    equal(len(changed_update_registry_values(_collect(duplicated,True)["groups"])),1)
    _compare(duplicated,{0:0})
    for a,b in [('','&quot;&quot;'),('','')]:
        value=lambda v: '<registryValue name="N" valueType="REG_MULTI_SZ" value="'+v+'"/>'
        _compare([_manifest(r"HKLM\Software\Fixture","before",0,value=value(a)),_manifest(r"HKLM\Software\Fixture","after",1,value=value(b))],{0:0,1:1})

def test_ties_rejections_and_reuse():
    a="O:SYG:SYD:P(A;;KA;;;SY)"
    b="O:SYG:SYD:P(A;;KR;;;SY)"
    for owners in [(0,1),(0,0)]:
        rows=[_manifest(r"HKLM\Software\Fixture","after",owners[0],a),_manifest(r"HKLM\Software\Fixture","after",owners[1],b)]
        for compact in [False,True]:
            collected=_collect(rows,compact)
            raises(prepare_update_registry_keys,args=[_runtime({0:1,1:1}),collected["groups"],{0:1,1:1},collected["key_records"]],message="family-bucket tie")
    priority = _compare([_manifest(r"HKLM\Software\Fixture","after",0,a), _manifest(r"HKLM\Software\Fixture","after",1,b)],{0:9,1:1})
    equal(priority[1]["system"][r"\registry\machine\software\fixture"]["descriptor"],windows.compile_sddl(a))
    equal(priority[1]["system"][r"\registry\machine\software\fixture"]["owner"],"new1")
    rows=[_manifest(r"HKLM\Software\Fixture","after",0,a)]
    collected=_collect(rows,True)
    one=prepare_update_registry_keys(_runtime({0:1}),{}, {0:1},collected["key_records"])
    two=prepare_update_registry_keys(_runtime({0:1}),{}, {0:1},collected["key_records"])
    for path in one["system"]:
        for field in _FIELDS: equal(one["system"][path][field],two["system"][path][field])
    groups={("system",r"\registry\machine\software\absent","n"):[[],[(0,4,b"1234","false","",False)]]}
    raises(prepare_update_registry_keys,args=[_runtime({0:1}),groups,{0:1},collected["key_records"]],message="no corresponding admitted key")
    for attrs in ['owner="invalid"','unexpected="x"','perUserVirtualization="Enable"','mapDesiredAccessToMaxAllowedAccess="True"']:
        rows=[_manifest(r"HKLM\Software\Fixture","after",0,attrs=attrs)]
        raises(_collect,args=[rows,True],message="unsupported registry")

def test_physical_plans_preserve_delete_and_create_behavior():
    text="O:SYG:SYD:P(A;;KA;;;SY)"
    value=lambda v: '<registryValue name="N" valueType="REG_DWORD" value="'+v+'"/>'
    rows=[_manifest(r"HKLM\Software\Existing","before",0,value=value('1')),
          _manifest(r"HKLM\Software\Existing","after",0,value=value('2')),
          _manifest(r"HKLM\Software\Retired","before",0),
          _manifest(r"HKLM\Software\New","after",0,text,value=value('3'))]
    keys=_compare(rows,{0:1})
    collected=_collect(rows,True)
    outputs=[]
    for tree in keys:
        root=directory()
        source=windows.hive_from_patches("SOFTWARE",[dict(key="/Existing",name="N",type="REG_DWORD",value=1),dict(key="/Neighbor",name="Keep",type=3,value=b"original")],keys=["/Retired"])
        root.write("/Windows/System32/config/SOFTWARE",source)
        result=plan_update_ordinary_registry(root,tree,collected["groups"],{0:1},"controlset001")
        equal(result["report"]["removed_keys"],1)
        hive=windows.hive(result["plans"][0]["file"])
        equal(hive.find("/Retired"),None)
        # Sparse retirement preserves existing value spelling; only new
        # values use the normalized declaration spelling.
        equal(hive.find("/Existing").values,{"N":2})
        equal(hive.find("/New").values,{"n":3})
        equal(hive.find("/Neighbor").values,{"Keep":b"original"})
        outputs.append((result["report"],hive.find("/New").security))
    equal(outputs[0],outputs[1])

TEST_SUITE=suite("nt6/compact-registry",[
    case("differential",test_differential_hierarchy_security_ownership_and_values),
    case("guards_and_reuse",test_ties_rejections_and_reuse),
    case("physical_plans",test_physical_plans_preserve_delete_and_create_behavior),
])
