"""Publish AppxReg's native queued user-registration invalidations atomically.

Manifest registry declarations constrain package names only. The real AppxReg
Commit and WCP primitive executor decide which existing user records to remove.
This is not AppX deployment, provisioning, or a CBS completion declaration.
"""
load("@stdlib//windows/servicing:smart_installer.star", "smart_jobs_from_queue", "run_appx_installer")
load("@stdlib//windows/servicing:registry_effects.star", "plan_update_registry_effects", "apply_update_registry_effects")

_NS="urn:schemas-microsoft-com:asm.v3"
_PATH="/Windows/System32/config/SOFTWARE"
_ROOT="/Microsoft/Windows/CurrentVersion/Appx/AppxAllUserStore"

def _children(node,name):
    return [n for n in node.children if n.namespace==_NS and n.name==name]

def _attributes(node):
    attrs={a["name"]:a["value"] for a in node.attributes if not a["namespace"]}
    if len(attrs)!=len(node.attributes): fail("ambiguous Appx authority attributes")
    return attrs

def appx_package_authority(jobs):
    """Derive deletion authority from bounded, explicitly selected AppX jobs."""
    authority={}
    prefix=("HKEY_LOCAL_MACHINE"+chr(92)+"SOFTWARE"+_ROOT.replace("/",chr(92))+chr(92)+"InboxApplications"+chr(92)).lower()
    for operation,file in jobs:
        if operation not in [1,2,3] or file.size>8<<20: fail("invalid Appx authority job")
        document=binary.xml(file,discard_whitespace=True).root
        if len(_children(document,"appxRegistration"))!=1: fail("Appx authority requires one native registration declaration")
        found=0
        for group in _children(document,"registryKeys"):
            for key in _children(group,"registryKey"):
                path=_attributes(key).get("keyName","")
                if not path.lower().startswith(prefix): continue
                package=path[len(prefix):]
                if not package or any([s in package for s in [chr(92),"/",chr(0),"$(","%"]]) or package in [".",".."]: fail("invalid Appx package authority")
                authority[package.lower()]=True
                found+=1
        if not found: fail("Appx job has no declared inbox package authority")
    return authority

def plan_native_appx(root,jobs,effects,source):
    """Validate deletion-only AppX effects against job authority and the exact source hive; return registry plans without publication."""
    if sorted(effects)!=["key_deletions","keys","value_deletions","values"] or effects["keys"] or effects["values"]:
        fail("native Appx publication has unsupported non-deletion effects")
    current=root.find(_PATH)
    if source==None or current==None or digest(current)!=digest(source): fail("native Appx source changed before planning")
    authority=appx_package_authority(jobs)
    hive=windows.hive(source)
    store=hive.find(_ROOT)
    users={child.name.lower():True for child in store.children if child.name.startswith("S-1-")} if store!=None else {}
    deleted={}
    prefix=_ROOT.lower()+"/"
    for record in effects["key_deletions"]:
        key=record["key"].lower()
        parts=key[len(prefix):].split("/") if key.startswith(prefix) else []
        if record["hive"]!="SOFTWARE" or len(parts)!=2 or parts[0] not in users or parts[1] not in authority:
            fail("native Appx deletion outside admitted user/package authority")
        if key in deleted: fail("duplicate native Appx key deletion")
        node=hive.find(record["key"])
        if node==None or node.children: fail("native Appx deletion requires an existing registration leaf")
        deleted[key]=True
    values={}
    for record in effects["value_deletions"]:
        key=record["key"].lower()
        identity=(key,record["name"].lower())
        if record["hive"]!="SOFTWARE" or key not in deleted or identity in values: fail("native Appx value deletion outside removed registration")
        values[identity]=True
    return plan_update_registry_effects(root,effects,[dict(hive="SOFTWARE",prefix="/",target="SOFTWARE",path=_PATH,source=source)])

def apply_native_appx(root,file,wcp_file,queue,changes,inspect_manifests,token_privileges,instruction_limit=500000000):
    """Run the qualified native AppX queue and publish authorized deletions on root; reject missing hives, incomplete queues and stale sources."""
    jobs=smart_jobs_from_queue(queue,"appx",changes,inspect_manifests)
    if not jobs: return dict(jobs=0,publication=dict(hives=0,values=0,deleted_values=0,removed_keys=0))
    sources={k:root.find("/Windows/System32/config/"+k) for k in ["SOFTWARE","SYSTEM"]}
    if any([f==None for f in sources.values()]): fail("native Appx target hives missing")
    result=run_appx_installer(file,wcp_file,{k:windows.hive(f) for k,f in sources.items()},jobs,token_privileges=token_privileges,instruction_limit=instruction_limit)
    for hive,source in sources.items():
        if digest(root.find("/Windows/System32/config/"+hive))!=digest(source): fail("native Appx source changed during execution")
    plans=plan_native_appx(root,jobs,result["effects"],sources["SOFTWARE"])
    result["publication"]=apply_update_registry_effects(root,plans)
    return result
