"""Explicit-media regression for the native Events smart-installer adapter."""
load("@stdlib//windows/servicing:smart_installer.star", "run_events_installer")
load("@stdlib//windows/servicing:events_native.star", "apply_native_events")

def verify_events_installer(file,wcp,sources,manifest):
    if hex(digest(manifest,algorithm="sha256"))!="20d3116cebed714670541c25b500984352a75878ac4f42fc202f6f1c9691c9ed":
        fail("Events regression requires the inspected amd64 FunDisc 26100.9549 manifest")
    original={k:hex(digest(v,algorithm="sha256")) for k,v in sources.items()}
    hives={k:windows.hive(v) for k,v in sources.items()}
    inspected=run_events_installer(file,wcp,hives,[(3,manifest)])
    if any(inspected["effects"].values()): fail("healthy native Inspect unexpectedly changed registration")
    installed=run_events_installer(file,wcp,hives,[(1,manifest)])
    key="/Microsoft/Windows/CurrentVersion/WINEVT/Publishers/{9db0fdb5-3b21-440e-a94b-63738a4be5de}"
    def publisher_name(result):
        values=[v for v in result["effects"]["values"] if v["hive"]=="SOFTWARE" and v["key"].lower()==key.lower() and v["name"]==""]
        if len(values)!=1 or values[0]["type"]!=1: fail("native Events omitted publisher identity")
        return binary.text(values[0]["value"],encoding="utf16le")
    if publisher_name(installed)!="Microsoft-Windows-FunctionDiscovery"+chr(0):
        fail("native Events published the wrong identity")
    # Changing actual manifest input must change the actual native output.
    altered=binary.concat([manifest.read().replace('name="Microsoft-Windows-FunctionDiscovery"','name="Native-Fixture-FunctionDiscovery"')])
    changed=run_events_installer(file,wcp,hives,[(1,altered)])
    if publisher_name(changed)!="Native-Fixture-FunctionDiscovery"+chr(0):
        fail("native Events output did not follow manifest input")
    limited=testing.attempt(run_events_installer,args=[file,wcp,hives,[(1,manifest)]],kwargs={"instruction_limit":4640000})
    if limited.ok or "offline commit" not in limited.error or "instruction-limit" not in limited.error:
        fail("Events partial-commit instruction limit did not reject execution: "+str(limited))
    malformed=testing.attempt(run_events_installer,args=[file,wcp,hives,[(1,binary.concat(["<assembly"]))]])
    if malformed.ok or "manifest parse" not in malformed.error:
        fail("malformed manifest did not fail in native WCP parsing")
    if {k:hex(digest(v,algorithm="sha256")) for k,v in sources.items()}!=original:
        fail("native Events experiment mutated source hive bytes")
    return dict(inspect={k:v for k,v in inspected.items() if k!="effects"},install={k:v for k,v in installed.items() if k!="effects"},install_effect_counts={k:len(v) for k,v in installed["effects"].items()},changed_input=True,partial_commit_rejected=True,malformed_manifest_rejected=True,source_hives_unchanged=True)


def verify_events_publication(file,wcp,sources,manifest):
    root=directory()
    for hive,source in sources.items(): root.write("/Windows/System32/config/"+hive,source)
    def hashes():
        return {h:hex(digest(root.find("/Windows/System32/config/"+h),algorithm="sha256")) for h in sources}
    original=hashes()
    limited=testing.attempt(apply_native_events,args=[root,file,wcp,[(1,manifest)]],kwargs={"instruction_limit":4640000})
    if limited.ok or "offline commit" not in limited.error or "instruction-limit" not in limited.error or hashes()!=original:
        fail("native Events partial-commit failure escaped into the image")
    installed=apply_native_events(root,file,wcp,[(1,manifest)])
    after=hashes()
    if installed["publication"]!=dict(hives=1,values=12,deleted_values=0,removed_keys=3):
        fail("unexpected native Events fixture publication: "+str(installed))
    if after["SYSTEM"]!=original["SYSTEM"]: fail("native Events changed the untouched SYSTEM hive")
    node=windows.hive(root.find("/Windows/System32/config/SOFTWARE")).find("/Microsoft/Windows/CurrentVersion/WINEVT/Publishers/{9db0fdb5-3b21-440e-a94b-63738a4be5de}")
    if node==None or node.values.get("(default)")!="Microsoft-Windows-FunctionDiscovery":
        fail("native Events publisher failed serialized readback")
    replay=apply_native_events(root,file,wcp,[(1,manifest)])
    if hashes()!=after: fail("native Events replay changed its fixed-point hive bytes")
    inspected=apply_native_events(root,file,wcp,[(3,manifest)])
    if inspected["publication"]!=dict(hives=0,values=0,deleted_values=0,removed_keys=0) or hashes()!=after:
        fail("native Events Inspect changed healthy registration")
    if {h:hex(digest(f,algorithm="sha256")) for h,f in sources.items()}!=original:
        fail("native Events publisher mutated input hive sources")
    return dict(install=installed,replay=replay,inspect=inspected,partial_commit_atomic=True,replay_byte_stable=True,source_hives_unchanged=True)
