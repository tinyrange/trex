"""Execute native HTTP queue phases against a private hive, then publish once."""
load("@stdlib//windows/servicing:installer.star", "basic_jobs_from_queue", "run_http_installer")
load("@stdlib//windows/servicing:http.star", reservations_from_document="http_reservations")
load("@stdlib//windows/servicing:registry_effects.star", "plan_update_registry_effects", "apply_update_registry_effects")

_PATH="/Windows/System32/config/SYSTEM"
_HASH="cf6e64fe29b3726acd814dd56e1de9416d3ed97d6da119f99c44e5da339dfaa8"

def plan_native_http_effects(root,rows,result):
    """Check exact per-call URL authority before building any new hive bytes."""
    source=root.find(_PATH)
    hive=windows.hive(source)
    select=hive.find("/Select")
    current=None if select==None else select.values.get("Current")
    if type(current)!="int" or current<1 or current>999 or select.value_records["Current"].type!=4:
        fail("invalid native HTTP control set")
    key="/ControlSet"+("00"+str(current))[-3:]+"/Services/HTTP/Parameters/UrlAclInfo"
    if hive.find(key)==None: fail("native HTTP key creation requires established security")
    expected={row["url"].lower():True for row in rows}
    if len(expected)!=len(rows): fail("duplicate native HTTP input URL")
    operation,phase=result["operation"],result["phase"]
    if (operation,phase) not in [("uninstall",8),("install",10)]: fail("unsupported native HTTP result phase")
    if operation=="install" and result["value_deletions"] or operation=="uninstall" and result["patches"]:
        fail("native HTTP result mixed install and removal effects")
    effects=dict(keys=[],key_deletions=[],values=[],value_deletions=[])
    seen={}
    records=result["patches"] if operation=="install" else result["value_deletions"]
    for record in records:
        name=record["name"].lower()
        if record.get("hive","SYSTEM")!="SYSTEM" or record["key"].lower()!=key.lower() or name not in expected or name in seen:
            fail("native HTTP effect outside exact queue authority")
        seen[name]=True
        if operation=="install":
            if record["type"]!=3 or type(record["raw"])!="bytes" or not record["raw"]: fail("invalid native HTTP security value")
            windows.security_descriptor_parts(record["raw"])
            effects["values"].append(dict(hive="SYSTEM",key=key,name=record["name"],type=3,value=record["raw"]))
        else:
            effects["value_deletions"].append(dict(hive="SYSTEM",key=key,name=record["name"]))
    if sorted(seen)!=sorted(expected): fail("native HTTP did not execute its complete input table")
    bindings=[dict(hive="SYSTEM",prefix="/",target="SYSTEM",path=_PATH,source=source)]
    return plan_update_registry_effects(root,effects,bindings)

def apply_native_http(root,file,queue,changes):
    """Run both native phases in order; a late failure publishes neither phase."""
    if hex(digest(file,algorithm="sha256"))!=_HASH: fail("native HTTP requires exact serviced DLL bytes")
    jobs=basic_jobs_from_queue(queue,"http",changes)
    source=root.find(_PATH)
    if source==None: fail("native HTTP target SYSTEM missing")
    private=directory()
    private.write(_PATH,source)
    executions=[]
    for job in jobs:
        rows=list(reservations_from_document(binary.xml(job["manifest"],discard_whitespace=True).root).values())
        result=run_http_installer(file,windows.hive(private.find(_PATH)),rows,operation=job["operation"],phase=job["phase"])
        plans=plan_native_http_effects(private,rows,result)
        counts=apply_update_registry_effects(private,plans)
        executions.append(dict(operation=job["operation"],phase=job["phase"],rows=len(rows),steps=result["result"].steps,publication=counts))
    if digest(root.find(_PATH))!=digest(source): fail("native HTTP source changed during execution")
    if jobs: root.write(_PATH,private.find(_PATH))
    return dict(jobs=len(jobs),executions=executions,policy="native HTTP phases only; no other-installer or CBS completion claim")
