"""Explicit-media native phase-8 controls; no recipe publication implied."""
load("@stdlib//windows/servicing:installer.star", "run_basic_installer")

def verify_basic_removals(http, fve, runner=run_basic_installer):
    key="/ControlSet002/Services/HTTP/Parameters/UrlAclInfo"
    rows=[dict(url="http://+:80/Native-Present/",sddl="D:(A;;GX;;;NS)"),dict(url="http://+:80/Native-Missing/",sddl="D:(A;;GX;;;NS)")]
    file=windows.hive_from_patches("SYSTEM",[
        dict(key="/Select",name="Current",type="REG_DWORD",value=2),
        dict(key=key,name=rows[0]["url"],type="REG_BINARY",value=b"old"),
        dict(key=key,name="http://+:80/Unrelated/",type="REG_BINARY",value=b"keep"),
        dict(key=key.replace("002","001"),name=rows[0]["url"],type="REG_BINARY",value=b"inactive"),
    ])
    original=digest(file)
    hive=windows.hive(file)
    removed=runner(http,"http",{"SYSTEM":hive},rows=rows,operation="uninstall",phase=8)
    expected=[dict(hive="SYSTEM",key=key,name=row["url"]) for row in rows]
    if removed["patches"] or removed["value_deletions"]!=expected:
        fail("native HTTP removal did not target exactly its two selected-control-set URLs")
    installed=runner(http,"http",{"SYSTEM":hive},rows=rows)
    if installed["value_deletions"] or len(installed["patches"])!=2:
        fail("native HTTP install/removal ABI did not distinguish effects")
    fv=runner(fve,"fve",{"SYSTEM":hive},operation="uninstall",phase=8)
    if fv["patches"] or fv["value_deletions"]: fail("offline FVE removal unexpectedly changed registry")
    limited=testing.attempt(runner,args=[http,"http",{"SYSTEM":hive}],kwargs=dict(rows=rows,operation="uninstall",phase=8,instruction_limit=removed["result"].steps-20))
    if limited.ok or "instruction-limit" not in limited.error:
        fail("partial native removal exposed effects")
    wrong=testing.attempt(runner,args=[http,"http",{"SYSTEM":hive}],kwargs=dict(rows=rows,operation="uninstall",phase=10))
    if wrong.ok or "operation/phase" not in wrong.error: fail("unsupported native phase admitted")
    if digest(file)!=original: fail("native basic removal changed source hive")
    return dict(http_deletions=len(expected),http_steps=removed["result"].steps,http_install_writes=len(installed["patches"]),fve_steps=fv["result"].steps,partial_failure_atomic=True,wrong_phase_rejected=True,sources_unchanged=True)
