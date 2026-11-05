"""Native offline timezone installer admission and atomic effect publication."""
load("@stdlib//windows/servicing:runtime.star", "select_servicing_file_hash")
load("@stdlib//windows/servicing:installer.star", "run_basic_installer")

_ZONES = "/Microsoft/Windows NT/CurrentVersion/Time Zones"
_INSTALLER_PATH = "/Windows/WinSxS/amd64_microsoft-windows-s..-installers-onecore_31bf3856ad364e35_10.0.26100.9703_none_875daae85585b1d5/timezoneai.dll"
_INSTALLER_SHA256 = "12228f33047d2bf84e6ceb1431020419d31d91fa4d1bdebce899348aadad83a8"

def _values(key):
    return {n.lower():(r.type,key.values[n]) for n,r in key.value_records.items()} if key!=None else {}

def publish_timezone_effects(root,effects):
    """Validate timezone writes against actual SOFTWARE/SYSTEM and the selected control set before publishing patches."""
    sources={h:root.find("/Windows/System32/config/"+h) for h in ["SOFTWARE","SYSTEM"]}
    hives={h:windows.hive(f) for h,f in sources.items()}
    select=hives["SYSTEM"].find("/Select")
    current=None if select==None else select.values.get("Current")
    if type(current)!="int" or current<1 or current>999 or select.value_records["Current"].type!=4:
        fail("invalid timezone publication control set")
    current_key="/ControlSet"+("00"+str(current))[-3:]+"/Control/TimeZoneInformation"
    patches={h:[] for h in sources}
    touched={}
    seen={}
    for effect in effects:
        hive,key,name=effect["hive"],effect["key"],effect["name"]
        zone=key.lower().startswith(_ZONES.lower()+"/") and len(key.split("/"))==len(_ZONES.split("/"))+1
        allowed=hive=="SOFTWARE" and zone and name.lower() in ["display","dlt","std"] or hive=="SYSTEM" and key.lower()==current_key.lower() and name.lower() in ["standardname","daylightname"]
        if not allowed or effect["type"]!=1:
            fail("native timezone effect outside admitted authority")
        text=binary.text(effect["raw"],encoding="utf16le")
        if not text.endswith(chr(0)) or chr(0) in text[:-1]: fail("native timezone string is not singly terminated")
        identity=(hive,key.lower(),name.lower())
        if identity in seen: fail("duplicate native timezone effect")
        seen[identity]=True
        node=hives[hive].find(key)
        if node==None: fail("timezone key creation requires inherited security")
        touched[(hive,key)]=node
        prior={n.lower():(n,r.type,r.raw) for n,r in node.value_records.items()}.get(name.lower())
        if prior!=None and prior[1:]==(1,effect["raw"]): continue
        patches[hive].append(dict(key=key,name=name if prior==None else prior[0],type=1,value=effect["raw"]))
    updated={h:windows.patch_hive(sources[h],p) for h,p in patches.items() if p}
    for (hive,key),prior in touched.items():
        actual=windows.hive(updated.get(hive,sources[hive])).find(key)
        if actual==None or actual.security!=prior.security: fail("timezone changed key security")
        expected={n.lower():(r.type,r.raw) for n,r in prior.value_records.items()}
        for patch in patches[hive]:
            if patch["key"].lower()==key.lower(): expected[patch["name"].lower()]=(1,patch["value"])
        if expected!={n.lower():(r.type,r.raw) for n,r in actual.value_records.items()}:
            fail("timezone serialized value readback differs")
    for hive,source in sources.items():
        if digest(root.find("/Windows/System32/config/"+hive))!=digest(source): fail("timezone source hive changed")
    for hive,file in updated.items(): root.write("/Windows/System32/config/"+hive,file)
    return patches

def apply_update_timezone(root,runtime):
    """Execute qualified offline timezone resource handlers and publish checked effects; return resource/native-write evidence."""
    started=clock.monotonic()
    changes=[]
    primary=[]
    for transition in runtime["transitions"]:
        if any([d.get(("urn:schemas-microsoft-com:asm.v3","timezoneAI"),0) for d in transition["directives"]]):
            if transition["after"]==None: fail("timezone removal requires its native phase")
            primary.append(transition)
        if any([d.get(("urn:schemas-microsoft-com:asm.v3","timezoneresourceAI"),0) for d in transition["directives"]]):
            changes.append(transition)
    if not changes and not primary: return dict(resource_components=0,primary_components=0,native_writes=0,values=0)
    # Native selection tries preferred UI languages, then installation language.
    # Admit the proven single-language image; do not guess a fallback ordering.
    files={h:root.find("/Windows/System32/config/"+h) for h in ["SOFTWARE","SYSTEM"]}
    hives={h:windows.hive(f) for h,f in files.items()}
    resource=None
    if changes:
        current=hives["SYSTEM"].find("/Select").values.get("Current")
        if type(current)!="int" or current<1 or current>999: fail("invalid timezone control set")
        control_set="ControlSet"+("00"+str(current))[-3:]
        preferred=_values(hives["SYSTEM"].find("/"+control_set+"/Control/MUI/Settings"))
        language=_values(hives["SYSTEM"].find("/"+control_set+"/Control/Nls/Language"))
        if "preferreduilanguages" in preferred or language.get("installlanguage")!=(1,"0409"):
            fail("timezone resource language selection is not the admitted en-US installation")
        hashes=[]
        for transition in changes:
            if transition["after"]==None: fail("timezone resource removal requires a separate policy")
            identity=windows.csi_identity(transition["component_identities"]["after"])
            if identity.processor_architecture!="amd64" or identity.language.lower()!="en-us":
                fail("unsupported timezone resource transition")
            document=transition["documents"]["after"][1]
            nodes=[n for n in document.children if n.name=="timezoneresourceAI" and n.namespace=="urn:schemas-microsoft-com:asm.v3"]
            if len(nodes)!=1 or nodes[0].attributes or nodes[0].children:
                fail("unsupported timezone installer directive")
            declarations=windows.assembly_manifest(transition["after"]).files
            if len(declarations)!=1 or declarations[0].name.lower()!="tzres.dll.mui":
                fail("timezone resources require one exact manifest file")
            hashes.append(select_servicing_file_hash(declarations[0])["digest"])
        names={p.lower():p for p in root.files}
        if len(names)!=len(root.files): fail("ambiguous timezone image paths")
        resource=root.find(names.get("/windows/system32/en-us/tzres.dll.mui","/Windows/System32/en-US/tzres.dll.mui"))
        if resource==None or any([digest(resource,algorithm="sha256")!=h for h in hashes]):
            fail("final timezone resource differs from its admitted manifest")
        entries=windows.pe(resource).strings
        if not entries or any([e.lang!="#1033" for e in entries]): fail("ambiguous timezone string-table language")
    installer=root.find(_INSTALLER_PATH)
    if installer==None or hex(digest(installer,algorithm="sha256"))!=_INSTALLER_SHA256:
        fail("timezone installer requires exact serviced source bytes")
    executions=[]
    for transition in primary:
        identity=windows.csi_identity(transition["component_identities"]["after"])
        nodes=[n for n in transition["documents"]["after"][1].children if n.name=="timezoneAI" and n.namespace=="urn:schemas-microsoft-com:asm.v3"]
        if identity.processor_architecture not in ["amd64","wow64"] or len(nodes)!=1 or nodes[0].attributes or nodes[0].children:
            fail("unsupported primary timezone directive")
        native=run_basic_installer(installer,"timezone",hives)
        if native["patches"]: fail("primary offline timezone handler unexpectedly wrote state")
        executions.append(dict(profile="timezone",identity=str(transition["component_identities"]["after"]),steps=native["result"].steps,writes=0))
    effects=[]
    for transition in changes:
        native=run_basic_installer(installer,"timezone-resource",hives,files={"C:/Windows/System32/en-US/tzres.dll.mui":resource})
        effects.extend(native["patches"])
        executions.append(dict(profile="timezone-resource",identity=str(transition["component_identities"]["after"]),steps=native["result"].steps,writes=len(native["patches"])))
    for hive,source in files.items():
        if digest(root.find("/Windows/System32/config/"+hive))!=digest(source): fail("timezone source changed during emulation")
    patches=publish_timezone_effects(root,effects)
    return dict(resource_components=len(changes),primary_components=len(primary),resource_sha256=hex(digest(resource,algorithm="sha256")) if resource!=None else None,installer_sha256=_INSTALLER_SHA256,values=len(patches["SOFTWARE"])+len(patches["SYSTEM"]),native_writes=len(effects),changes=patches,executions=executions,seconds=clock.monotonic()-started,policy="executed native offline timezone handlers; not complete CBS installation")
