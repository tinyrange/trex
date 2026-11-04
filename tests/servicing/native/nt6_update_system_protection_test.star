"""Explicit-media native System Protection controls, without image publication."""
load("@stdlib//windows/servicing:smart_installer.star", "run_system_protection_installer")

def verify_system_protection(file,wcp,software,system,amd64_before,amd64_after,wow64_after,runner=run_system_protection_installer):
    sources=[digest(software),digest(system)]
    results=[]
    for architecture,manifest,prefix in [("amd64",amd64_after,[]),("wow64",wow64_after,["WOW6432Node"])]:
        parent=prefix+["Microsoft","Function Discovery"]
        parts=[parent,parent+["RegistryStore"],parent+["RegistryStore","Association DB"]]
        descendant=parent+["RegistryStore","Native-Recursive-Control"]
        neighbor=prefix+["Microsoft","Native-Unrelated-Control"]
        controlled=windows.patch_hive(software,[],keys=[dict(key_parts=descendant),dict(key_parts=neighbor)],key_flags=[dict(key_parts=p,virtualization_flags=0) for p in parts+[descendant]]+[dict(key_parts=neighbor,virtualization_flags=1)])
        before=digest(controlled)
        hives={"SOFTWARE":windows.hive(controlled),"SYSTEM":windows.hive(system)}
        positive=runner(file,wcp,hives,[(1,manifest)])
        expected={tuple(p):10 for p in parts+[descendant]}
        actual={tuple(p["key_parts"]):p["virtualization_flags"] for p in positive["key_flags"] if p["hive"]=="SOFTWARE"}
        if actual!=expected or len(positive["key_flags"])!=4: fail("native System Protection did not apply exact recursive flags")
        if any(positive["effects"].values()): fail("System Protection changed registry values")
        patches=[dict(key_parts=p["key_parts"],virtualization_flags=p["virtualization_flags"]) for p in positive["key_flags"]]
        updated=windows.patch_hive(controlled,[],key_flags=patches)
        target=windows.hive(updated)
        for p in parts+[descendant]:
            if target.find(p).virtualization_flags!=10 or target.find(p).security!=hives["SOFTWARE"].find(p).security: fail("native flag readback or security preservation failed")
        if target.find(neighbor).virtualization_flags!=1: fail("native flags escaped declared subtree")
        replay=runner(file,wcp,{"SOFTWARE":target,"SYSTEM":hives["SYSTEM"]},[(1,manifest)])
        if replay["key_flags"]: fail("System Protection replay was not idempotent")
        inspected=runner(file,wcp,hives,[(3,manifest)])
        if inspected["key_flags"]: fail("native Inspect unexpectedly installed absent flags")
        if digest(controlled)!=before: fail("native execution modified source hive")
        if architecture=="amd64":
            delta=runner(file,wcp,hives,[(1,amd64_after),(2,amd64_before)])
            if delta["key_flags"] or delta["key_queries"]: fail("unchanged declaration pair did not cancel natively")
        limited=testing.attempt(runner,args=[file,wcp,hives,[(1,manifest)]],kwargs=dict(instruction_limit=positive["parse_steps"]-1))
        if limited.ok or "instruction-limit" not in limited.error: fail("failed native parsing exposed effects")
        if digest(controlled)!=before: fail("failed native run modified source")
        results.append(dict(architecture=architecture,parse_steps=positive["parse_steps"],queue_steps=positive["queue_steps"],commit_steps=positive["commit_steps"],recursive_writes=len(positive["key_flags"]),inspect_writes=len(inspected["key_flags"]),replay_writes=0,wow_paths=positive["wow_paths"]))
    if [digest(software),digest(system)]!=sources: fail("System Protection source hive mutation")
    return dict(controls=results,sources_unchanged=True,parse_failure_atomic=True,unchanged_pair_cancels=True)
