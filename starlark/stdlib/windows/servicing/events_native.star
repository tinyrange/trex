"""Validate and atomically publish real Events-installer hive effects.

Jobs must already come from native queue admission. This module does not infer
jobs from XML, execute online phases, or declare CBS package completion.
"""
load("@stdlib//windows/servicing:smart_installer.star", "run_events_installer", "smart_jobs_from_queue")
load("@stdlib//windows/servicing:registry_effects.star", "plan_update_registry_effects", "apply_update_registry_effects", "build_update_driver_key_security")

def _parts(key):
    if not key.startswith("/") or key.endswith("/"):
        fail("native Events requires an encoded absolute key")
    parts=[]
    for part in key[1:].split("/"):
        decoded=part.replace("%2f","/").replace("%2F","/").replace("%25","%")
        if not part or decoded in [".",".."] or chr(0) in decoded or chr(92) in decoded or decoded.replace("%","%25").replace("/","%2f").lower()!=part.lower():
            fail("native Events emitted an invalid key component")
        parts.append(decoded)
    if len(parts)>128: fail("native Events key depth exceeds bound")
    return parts

def plan_native_events(root,effects):
    """Build all target hive bytes; no image mutation occurs on any rejection."""
    if sorted(effects)!=["key_deletions","keys","value_deletions","values"]:
        fail("unknown native Events effect class")
    sources={k:root.find("/Windows/System32/config/"+k) for k in ["SOFTWARE","SYSTEM"]}
    if any([f==None for f in sources.values()]): fail("native Events target hives missing")
    hives={k:windows.hive(f) for k,f in sources.items()}
    select=hives["SYSTEM"].find("/Select")
    current=None if select==None else select.values.get("Current")
    if type(current)!="int" or current<1 or current>999 or select.value_records["Current"].type!=4:
        fail("native Events target control set is invalid")
    control="controlset"+("00"+str(current))[-3:]
    required,removed,provided,touched={},{},{},{}
    for field in ["keys","values","value_deletions","key_deletions"]:
        for record in effects[field]:
            hive=record["hive"]
            if hive not in sources: fail("native Events escaped target hives")
            parts=_parts(record["key"])
            folded=tuple([p.lower() for p in parts])
            software=hive=="SOFTWARE" and len(parts)>=6 and folded[:4]==("microsoft","windows","currentversion","winevt") and folded[4] in ["publishers","channels"]
            system=hive=="SYSTEM" and len(parts)>=5 and folded[:4]==(control,"control","wmi","autologger")
            # Classic event sources are distinct from the Eventlog service or
            # log configuration keys. Native System-Events registration touches
            # only source-level leaves under Application and System.
            classic=hive=="SYSTEM" and len(parts)==5 and folded[:3]==(control,"services","eventlog") and folded[3] in ["application","system"]
            if not software and not system and not classic: fail("native Events effect outside publisher/channel/autologger/classic-source authority")
            touched[hive]=True
            if field=="key_deletions":
                removed[(hive,folded)]=True
            else:
                for count in range(len(parts)+1):
                    key=(hive,folded[:count])
                    required[key]=parts[:count]
                if field=="keys" and "security" in record:
                    if (hive,folded) in provided and provided[(hive,folded)]!=record["security"]: fail("conflicting native Events key security")
                    provided[(hive,folded)]=record["security"]
    security={}
    def resolve(hive,parts):
        folded=tuple([p.lower() for p in parts])
        key=(hive,folded)
        if key in security: return security[key]
        value=provided.get(key)
        existing=hives[hive].find(parts)
        deleted=any([(hive,folded[:i]) in removed for i in range(len(parts)+1)])
        if value==None:
            if existing!=None and not deleted:
                value=existing.security
            else:
                if not parts: fail("native Events cannot create a hive root")
                value=build_update_driver_key_security(resolve(hive,parts[:-1]))
        windows.security_descriptor_parts(value)
        security[key]=value
        return value
    for (hive,_),parts in required.items(): resolve(hive,parts)
    bindings=[dict(hive=hive,prefix="/",target=hive,path="/Windows/System32/config/"+hive,source=sources[hive]) for hive in sorted(touched)]
    return plan_update_registry_effects(root,effects,bindings,key_security=security)

def apply_native_events(root,file,wcp_file,jobs,instruction_limit=20000000):
    """Execute all explicit jobs before committing any native registry effect."""
    sources={k:root.find("/Windows/System32/config/"+k) for k in ["SOFTWARE","SYSTEM"]}
    if any([f==None for f in sources.values()]): fail("native Events target hives missing")
    result=run_events_installer(file,wcp_file,{k:windows.hive(f) for k,f in sources.items()},jobs,instruction_limit=instruction_limit)
    for hive,source in sources.items():
        if digest(root.find("/Windows/System32/config/"+hive))!=digest(source): fail("native Events source changed during execution")
    plans=plan_native_events(root,result["effects"])
    published=apply_update_registry_effects(root,plans)
    return dict(jobs=result["jobs"],parse_steps=result["parse_steps"],queue_steps=result["queue_steps"],commit_steps=result["commit_steps"],publication=published)


def events_jobs_from_queue(queue,changes,inspect_manifests=None):
    """Use the common native smart-installer job mapping for Events."""
    return smart_jobs_from_queue(queue,"events",changes,inspect_manifests)
