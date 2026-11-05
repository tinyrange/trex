"""Publish native System Protection key metadata only after complete execution."""
load("@stdlib//windows/servicing:smart_installer.star", "run_system_protection_installer", "smart_jobs_from_queue")
load("@stdlib//windows/servicing:registry_effects.star", "apply_update_registry_effects")

def plan_native_key_flags(root,records):
    """Build and verify existing-key flag edits without changing values/security."""
    if len(records)>65536: fail("native key flag publication bound")
    states={}
    for record in records:
        if sorted(record)!=["hive","key_parts","virtualization_flags"]: fail("unsupported native key flag effect")
        hive,parts,flags=record["hive"],record["key_parts"],record["virtualization_flags"]
        if hive not in ["SOFTWARE","SYSTEM"] or type(flags)!="int" or flags<0 or flags>15 or not parts or len(parts)>128 or any([not p or p in [".",".."] or chr(92) in p or chr(0) in p for p in parts]):
            fail("invalid native key flag target")
        if hive not in states:
            path="/Windows/System32/config/"+hive
            source=root.find(path)
            if source==None: fail("native key flag hive missing")
            states[hive]=dict(path=path,source=source,hive=windows.hive(source),patches=[],final={})
        state=states[hive]
        key=state["hive"].find(parts)
        if key==None or key.flags&0x11: fail("native key flag target must be an existing stable non-link key")
        identity=tuple([p.lower() for p in parts])
        patch=dict(key_parts=parts,virtualization_flags=flags)
        state["patches"].append(patch)
        cleared=bool(flags&2) or state["final"].get(identity,({},False))[1]
        state["final"][identity]=(patch,cleared)
    plans=[]
    for hive,state in states.items():
        patches=state["patches"]
        updated=windows.patch_hive(state["source"],[],key_flags=patches)
        after=windows.hive(updated)
        for patch,cleared in state["final"].values():
            old=state["hive"].find(patch["key_parts"])
            new=after.find(patch["key_parts"])
            expected_flags=old.flags&~0x80 if cleared else old.flags
            if new==None or new.virtualization_flags!=patch["virtualization_flags"] or new.user_flags!=old.user_flags or new.flags!=expected_flags or new.security!=old.security:
                fail("native key flag metadata readback differs")
            if {n:(r.type,r.raw) for n,r in new.value_records.items()}!={n:(r.type,r.raw) for n,r in old.value_records.items()} or [c.name for c in new.children]!=[c.name for c in old.children]:
                fail("native key flag publication changed values or children")
        plans.append(dict(target=hive,path=state["path"],source_hash=digest(state["source"]),file=updated,values=0,deleted_values=0,removed_keys=0,key_flags=len(patches)))
    return plans

def apply_native_system_protection(root,file,wcp_file,queue,changes,inspect_manifests=None,instruction_limit=20000000):
    """Run qualified System Protection jobs and publish validated key flags; return queue/parse/commit evidence."""
    jobs=smart_jobs_from_queue(queue,"system-protection",changes,inspect_manifests)
    if not jobs: return dict(jobs=0,key_flags=0,parse_steps=0,queue_steps=0,commit_steps=0)
    sources={h:root.find("/Windows/System32/config/"+h) for h in ["SOFTWARE","SYSTEM"]}
    if any([f==None for f in sources.values()]): fail("native System Protection target hives missing")
    result=run_system_protection_installer(file,wcp_file,{h:windows.hive(f) for h,f in sources.items()},jobs,instruction_limit=instruction_limit)
    if any(result["effects"].values()): fail("native System Protection produced non-metadata registry effects")
    for hive,source in sources.items():
        if digest(root.find("/Windows/System32/config/"+hive))!=digest(source): fail("native System Protection source changed during execution")
    plans=plan_native_key_flags(root,result["key_flags"])
    publication=apply_update_registry_effects(root,plans)
    return dict(jobs=len(jobs),key_flags=len(result["key_flags"]),parse_steps=result["parse_steps"],queue_steps=result["queue_steps"],commit_steps=result["commit_steps"],publication=publication)
