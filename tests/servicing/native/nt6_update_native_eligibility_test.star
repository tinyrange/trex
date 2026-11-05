"""Native eligibility controls with explicit WCP and target SOFTWARE inputs."""
load("@stdlib//windows/servicing:native_eligibility.star", "determine_per_user_eligibility")

def verify_per_user_eligibility(wcp,software,runner=determine_per_user_eligibility):
    ids=["05ff0ff65c7cdd48a1d2b75aa14ad9b4","2bfdb93b1e359c4bb1fced0758805998"]
    path="/Microsoft/Windows/CurrentVersion/Component Based Servicing/PackagesPending"
    original=digest(software)
    actual=runner(wcp,windows.hive(software),ids,False,False)
    observations=[]
    cases=[("absent",None,False),("missing-value",dict(name="Other",type="REG_DWORD",value=1),False),("zero",dict(name="FODOrOCPended",type="REG_DWORD",value=0),False),("one",dict(name="FODOrOCPended",type="REG_DWORD",value=1),True),("nonzero",dict(name="FODOrOCPended",type="REG_DWORD",value=0xffffffff),True),("wrong-type",dict(name="FODOrOCPended",type="REG_SZ",value="1"),False)]
    for name,value,expected in cases:
        patches=[]
        if value!=None:
            patch=dict(value)
            patch["key"]=path
            patches.append(patch)
        source=windows.hive_from_patches("SOFTWARE",patches)
        before=digest(source)
        result=runner(wcp,windows.hive(source),ids,False,False)
        if [v["should_run"] for v in result["results"]]!=[expected,True]: fail("native eligibility mismatch: "+name+" "+str(result))
        if len(result["queries"])!=(1 if name=="absent" else 2): fail("native eligibility registry query mismatch")
        if digest(source)!=before: fail("eligibility mutated controlled hive")
        observations.append(dict(case=name,results=result["results"],queries=len(result["queries"])))
    for force,suppress,expected in [(True,False,[True,True]),(False,True,[False,False]),(True,True,[False,False])]:
        result=runner(wcp,windows.hive(software),ids,force,suppress)
        if [v["should_run"] for v in result["results"]]!=expected or result["queries"]: fail("native executor state precedence mismatch")
    denied=testing.attempt(runner,args=[wcp,windows.hive(software),ids,False,False],kwargs=dict(instruction_limit=1))
    if denied.ok or "instruction-limit" not in denied.error: fail("native eligibility budget failure not propagated")
    if digest(software)!=original: fail("native eligibility mutated source")
    return dict(actual=actual,controls=observations,executor_state_precedence=True,budget_failure_atomic=True,source_unchanged=True)
