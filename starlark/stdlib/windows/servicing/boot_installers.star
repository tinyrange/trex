"""Native offline FVE/SecureBoot admission; not firmware or CBS completion."""
load("@stdlib//windows/servicing:installer.star", "run_basic_installer", "select_basic_installer")

_NS = "urn:schemas-microsoft-com:asm.v3"
_SYSTEM = "/Windows/System32/config/SYSTEM"
def boot_installer_jobs(runtime):
    """Collect supported offline FVE and SecureBoot jobs from admitted runtime transitions; reject unsupported declarations."""
    jobs=[]
    for transition in runtime["transitions"]:
        for tag,profile,attribute,values in [
            ("fveUpdateAI","fve","fveCommand",["bootmgr","memtest"]),
            ("SecureBoot","secureboot","UpdateType",["DbOnly","DbxOnly"]),
        ]:
            if not any([d.get((_NS,tag),0) for d in transition["directives"]]): continue
            if transition["after"]==None: fail("boot installer removal requires its native phase")
            identity=windows.csi_identity(transition["component_identities"]["after"])
            if identity.processor_architecture not in (["amd64","wow64","x86"] if profile=="fve" else ["amd64"]):
                fail("unsupported boot installer component architecture")
            nodes=[n for n in transition["documents"]["after"][1].children if n.namespace==_NS and n.name==tag]
            if len(nodes)!=1 or nodes[0].children or len(nodes[0].attributes)!=1:
                fail("unsupported boot installer directive")
            attr=nodes[0].attributes[0]
            if attr["namespace"] or attr["name"]!=attribute or attr["value"] not in values:
                fail("unsupported boot installer attribute")
            # The inspected phase-10 paths never read component CDF fields.
            # The shared adapter rejects CDF access for these profiles, so a
            # newly reached input dependency cannot silently become empty data.
            jobs.append(dict(profile=profile,identity=str(transition["component_identities"]["after"]),directive=attr["value"]))
    return jobs

def _secureboot_key(hive):
    select=hive.find("/Select")
    current=None if select==None else select.values.get("Current")
    if type(current)!="int" or current<1 or current>999 or select.value_records["Current"].type!=4:
        fail("invalid boot installer control set")
    return "/ControlSet"+("00"+str(current))[-3:]+"/Control/SecureBoot"

def validate_secureboot_effects(hive,effects):
    """Require the single supported native AvailableUpdates write and return its selected SYSTEM key."""
    key=_secureboot_key(hive)
    if len(effects)!=1: fail("SecureBoot must produce its one native offline effect")
    effect=effects[0]
    if effect["hive"]!="SYSTEM" or effect["key"].lower()!=key.lower() or effect["name"].lower()!="availableupdates" or effect["type"]!=4 or effect["raw"]!=binary.u32le(0x402):
        fail("native SecureBoot effect outside admitted authority")
    return key

def publish_secureboot_effects(root,effects):
    """Validate and publish the qualified SecureBoot value on root; return emitted patches, not firmware-update completion."""
    source=root.find(_SYSTEM)
    hive=windows.hive(source)
    key=validate_secureboot_effects(hive,effects)
    node=hive.find(key)
    if node==None: fail("SecureBoot key creation requires inherited security")
    prior={n.lower():(n,r.type,r.raw) for n,r in node.value_records.items()}.get("availableupdates")
    effect=effects[0]
    if prior!=None and prior[1:]==(effect["type"],effect["raw"]): return []
    patches=[dict(key=key,name=prior[0] if prior!=None else effect["name"],type=effect["type"],value=effect["raw"])]
    updated=windows.patch_hive(source,patches)
    actual=windows.hive(updated).find(key)
    expected={n.lower():(r.type,r.raw) for n,r in node.value_records.items()}
    expected["availableupdates"]=(effect["type"],effect["raw"])
    if actual.security!=node.security or {n.lower():(r.type,r.raw) for n,r in actual.value_records.items()}!=expected:
        fail("SecureBoot serialized values/security differ")
    if digest(root.find(_SYSTEM))!=digest(source): fail("SecureBoot source hive changed")
    root.write(_SYSTEM,updated)
    return patches

def apply_update_boot_installers(root,runtime):
    """Execute bounded offline boot-installer jobs and publish checked effects; online firmware and CBS lifecycle remain separate."""
    jobs=boot_installer_jobs(runtime)
    if not jobs: return dict(components=0,native_writes=0,values=0,executions=[])
    started=clock.monotonic()
    source=root.find(_SYSTEM)
    hive=windows.hive(source)
    installers={}
    for profile in {j["profile"]:True for j in jobs}:
        file,expected=select_basic_installer(root,profile)
        installers[profile]=file
    executions=[]
    effects=[]
    for job in jobs:
        native=run_basic_installer(installers[job["profile"]],job["profile"],{"SYSTEM":hive})
        if job["profile"]=="fve":
            if native["patches"]: fail("native offline FVE unexpectedly wrote registry state")
        else:
            validate_secureboot_effects(hive,native["patches"])
            effects.extend(native["patches"])
        executions.append(dict(job,phase=10,steps=native["result"].steps,writes=len(native["patches"])))
    if digest(root.find(_SYSTEM))!=digest(source): fail("boot installer source changed during emulation")
    # Both admitted SecureBoot components issue the same unconditional write.
    # Validate every invocation before coalescing; publish only after all pass.
    patches=publish_secureboot_effects(root,effects[:1]) if effects else []
    return dict(components=len(jobs),native_writes=len(effects),values=len(patches),changes=patches,executions=executions,seconds=clock.monotonic()-started,policy="executed native offline phase 10; online firmware/FVE and CBS lifecycle remain separate")
