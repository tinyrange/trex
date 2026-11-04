"""Media-backed native HTTPAI regression; takes a caller-supplied serviced DLL.

Invoke verify_http_installer(file) in the existing prepared update REPL. No
Microsoft binary is embedded and no guest OS or installer repair is used.
"""
load("//tests:testing.star", "equal", "raises", "contains")
load("@stdlib//windows/servicing:installer.star", "run_http_installer")
load("@stdlib//windows/servicing:http.star", "publish_http_effects")

_PATH = "/Windows/System32/config/SYSTEM"
_KEY = "/ControlSet002/Services/HTTP/Parameters/UrlAclInfo"
_SD = binary.decode("010004800000000000000000000000001400000002001c00010000000000140000000020010100000000000514000000", "hex")
_SECURITY = windows.compile_sddl("O:SYG:SYD:P(A;;KA;;;SY)")

def verify_http_installer(file):
    rows = [dict(url="http://+:80/%s/"%n,sddl="D:(A;;GX;;;NS)") for n in ["missing","stale","wrongtype","correct"]]
    root=directory()
    patches=[dict(key="/Select",name="Current",type="REG_DWORD",value=2)]
    for name,kind,value in [
        ("HTTP://+:80/STALE/","REG_BINARY",b"stale"),
        (rows[2]["url"],"REG_NONE",_SD),
        (rows[3]["url"],"REG_BINARY",_SD),
        ("https://+:443/unrelated/","REG_BINARY",b"unrelated"),
    ]:
        patches.append(dict(key=_KEY,name=name,type=kind,value=value))
    patches.append(dict(key=_KEY.replace("002","001"),name=rows[0]["url"],type="REG_SZ",value="inactive control set"))
    source=windows.hive_from_patches("SYSTEM",patches,keys=[dict(key_parts=_KEY[1:].split("/"),security=_SECURITY)])
    root.write(_PATH,source)
    result=run_http_installer(file,windows.hive(source),rows)
    equal(result["result"].reason,"return")
    equal(result["result"].value,0)
    equal([(p["key"],p["name"],p["type"],p["raw"]) for p in result["patches"]],[(_KEY,row["url"],3,_SD) for row in rows])
    reservations={row["url"].lower():row for row in rows}
    equal(len(publish_http_effects(root,reservations,result["patches"])),3)
    actual=windows.hive(root.find(_PATH))
    key=actual.find(_KEY)
    equal(key.security,_SECURITY)
    equal(key.values["https://+:443/unrelated/"],b"unrelated")
    equal(actual.find(_KEY.replace("002","001")).values[rows[0]["url"]],"inactive control set")
    equal(key.values["HTTP://+:80/STALE/"],_SD)
    before=digest(root.find(_PATH))
    repeat=run_http_installer(file,actual,rows)
    equal(len(repeat["patches"]),4)  # Native replay runs even on equal values.
    equal(publish_http_effects(root,reservations,repeat["patches"]),[])
    equal(digest(root.find(_PATH)),before)
    # A real native call fails after its first successful write. Partial output
    # must never escape the execution boundary or reach the caller's image.
    raises(run_http_installer,args=[file,actual,[rows[0],dict(rows[1],sddl="not-an-sddl-descriptor")]],message="writes=1")
    equal(digest(root.find(_PATH)),before)
    budget=raises(run_http_installer,args=[file,actual,rows],kwargs=dict(instruction_limit=1))
    contains(budget,"instruction-limit")
    equal(digest(root.find(_PATH)),before)
    return dict(passed=True,native_writes=len(result["patches"]),changed_values=3,replay_writes=len(repeat["patches"]),replay_changes=0,partial_failure_rejected=True,budget_failure=budget)
