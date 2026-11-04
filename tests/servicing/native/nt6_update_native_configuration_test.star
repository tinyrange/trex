"""Explicit-media native policy precedence and malformed-value controls."""
load("@stdlib//windows/servicing:native_configuration.star", "query_native_mobile_store_version","query_native_installer_options")

def verify_native_configuration(wcp,software,runner=query_native_mobile_store_version):
    original=digest(software)
    actual=runner(wcp,windows.hive(software))
    paths=["/Microsoft/Windows/CurrentVersion/SideBySide/Configuration","/Microsoft/Windows/CurrentVersion/Policies/Servicing"]
    cases=[
        ("absent",None,None,2),
        ("store",("REG_DWORD",4),None,4),
        ("policy",None,("REG_DWORD",4),4),
        ("policy-overrides-store",("REG_DWORD",4),("REG_DWORD",2),2),
        ("zero-is-valid",("REG_DWORD",4),("REG_DWORD",0),0),
        ("wrong-policy-type",("REG_DWORD",4),("REG_SZ","2"),4),
        ("short-policy-dword",("REG_DWORD",4),(4,b"\x02"),4),
        ("long-store-dword",(4,b"\x04\x00\x00\x00\x00"),None,2),
        ("wrong-store-type",("REG_SZ","4"),None,2),
    ]
    observations=[]
    for name,store,policy,expected in cases:
        patches=[dict(key=path,name="MobileStoreVersion",type=value[0],value=value[1]) for path,value in zip(paths,[store,policy]) if value!=None]
        source=windows.hive_from_patches("SOFTWARE",patches)
        before=digest(source)
        result=runner(wcp,windows.hive(source))
        if result["value"]!=expected or result["suppress_installers"]!=(expected==4): fail("native configuration mismatch: "+name+" "+str(result))
        if digest(source)!=before: fail("native configuration mutated input")
        policy_valid=policy!=None and policy[0]=="REG_DWORD"
        store_queries=[q for q in result["queries"] if q["kind"]=="value" and q["parts"][-1]=="Configuration"]
        if len(store_queries)!=(1 if store!=None and not policy_valid else 0): fail("native configuration policy precedence query mismatch")
        observations.append(dict(case=name,value=result["value"],steps=result["steps"]))
    if digest(software)!=original: fail("native configuration changed source")
    return dict(actual=actual,controls=observations,source_unchanged=True)


def verify_native_installer_options(wcp,software,runner=query_native_installer_options):
    """Compare the distinct native DWORD/Boolean option policies."""
    original=digest(software)
    actual=runner(wcp,windows.hive(software))
    store="/Microsoft/Windows/CurrentVersion/SideBySide/Configuration"
    policy="/Microsoft/Windows/CurrentVersion/Policies/Servicing"
    cases=[
        ("defaults",[],dict(mobile_store=0,mobile_store_version=2,smi_hive_updates=0,single_resource_ownership=0)),
        ("store-values",[(store,"MobileStore",1),(store,"MobileStoreVersion",4),(store,"SmiHiveUpdates",0x1200),(store,"SingleResourceOwnership",2)],dict(mobile_store=1,mobile_store_version=4,smi_hive_updates=0x1200,single_resource_ownership=1)),
        ("distinct-policy-rules",[(store,"MobileStore",1),(store,"SmiHiveUpdates",0x100),(policy,"MobileStore",2),(policy,"SmiHiveUpdates",0x800),(policy,"SingleResourceOwnership",1)],dict(mobile_store=2,mobile_store_version=2,smi_hive_updates=0x800,single_resource_ownership=0)),
    ]
    controls=[]
    for name,values,expected in cases:
        hive=windows.hive_from_patches("SOFTWARE",[dict(key=k,name=n,type="REG_DWORD",value=v) for k,n,v in values])
        before=digest(hive)
        result=runner(wcp,windows.hive(hive))
        if result["values"]!=expected or result["is_mobile_store"]!=(expected["mobile_store"]==1) or result["state_separated"]!=(expected["mobile_store_version"]==4): fail("native installer option mismatch: "+name)
        if digest(hive)!=before: fail("native installer options changed source")
        controls.append(dict(case=name,values=result["values"]))
    if digest(software)!=original: fail("native options changed target source")
    return dict(actual=actual,controls=controls,source_unchanged=True)
