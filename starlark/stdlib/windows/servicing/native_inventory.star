"""Read-only native CSI install-map inputs for complete inspection inventory."""
load("@stdlib//windows/emulation:runner.star",native_run="run")
load("@stdlib//windows/servicing:queue_registry.star","create_install_map_registry")

def query_native_install_map(file,software,identities):
    """Query native winning versions and identity kinds, without guessing inventory.

    This does not itself count installed ownership or exclude changed identities.
    Callers supply complete candidates and validated reference counts separately.
    """
    pe=windows.pe(file)
    if hex(digest(file,algorithm="sha256"))!="1a5d390bfbf10e24f124fd423916d15e00af06b7b8a6c982ca00ac1fd7991d85" or pe.codeview==None or pe.codeview["key"]!="7CC21FAF1E625E052DD8ADB23E8B25F21":
        fail("native install-map requires inspected WCP")
    if not identities or len(identities)>512 or any([type(v)!="bytes" or len(v)>65534 for v in identities]):
        fail("native install-map identity batch exceeds bound")
    state=dict(results=[])
    def install(m): pass
    plugin=emulator.plugin(install,name="native.install-map-control",state=state)
    def execute(m):
        base=[v.base for v in m.modules if v.primary][0]
        def checked(address,args,label,hresult=True):
            r=m.call(address,args=args)
            if r.reason!="return" or (hresult and r.value): fail(label,r.reason,hex(r.value),hex(r.pc),r.detail)
            return r
        sil,key=create_install_map_registry(m,{"SOFTWARE":software},state,"registry",base+0x38630,base+0x33fb0)
        owner=m.allocate(size=8)
        checked(base+0x70b10,[0,owner],"authority")
        authority=m.read_pointer(owner)
        layout=m.allocate(size=32)
        checked(base+0x11eab0,[layout],"install-map constructor",False)
        checked(base+0xa5610,[layout,1,authority,key,sil],"install-map initialization")
        for identity in identities:
            data=binary.encode(str(identity),encoding="utf16le")
            text=m.allocate(value=data)
            string=m.allocate(value=binary.concat([binary.u64le(len(data)),binary.u64le(len(data)),binary.u64le(text)]).bytes())
            ident=m.allocate(size=8)
            checked(base+0x3cb60,[authority,0,string,ident],"identity parse")
            pointer=m.read_pointer(ident)
            builtins=m.allocate(size=8)
            checked(m.read_pointer(m.read_pointer(pointer)+24),[pointer,0,builtins],"identity builtins")
            attributes=m.read_pointer(builtins)
            non_sxs=checked(base+0x93758,[attributes],"identity kind",False).value&255
            if non_sxs not in [0,1]: fail("native identity kind is not boolean")
            identity_version=m.read_u64le(attributes+0x20)
            output=m.allocate(value=b"\xa5"*16)
            found=m.allocate(value=b"\xa5"*8)
            r=checked(base+0x26bf0,[layout,pointer,output,found,0],"native winner")
            if m.read_u8(found) not in [0,1] or m.read(found+1,7)!=b"\xa5"*7 or m.read(output+8,8)!=b"\xa5"*8: fail("winner output guard")
            state["results"].append(dict(identity=identity,non_sxs=bool(non_sxs),identity_version=identity_version,present=bool(m.read_u8(found)),version=m.read_u64le(output),steps=r.steps))
            checked(m.read_pointer(m.read_pointer(pointer)),[pointer],"identity release",False)
            for a in [text,string,ident,output,found,builtins]: m.free(a)
        checked(base+0x7c890,[layout],"install-map destructor",False)
        checked(m.read_pointer(m.read_pointer(authority)),[authority],"authority release",False)
        for a in [owner,layout]: m.free(a)
        if any([o["refs"]!=(1 if p in [sil,key] else 0) for p,o in state["registry"]["objects"].items()]): fail("install-map retained keys")
        for p,o in state["registry"]["objects"].items():
            m.free(o["table"])
            m.free(p)
        return r
    report=native_run(file,"wcp.dll",plugins=[plugin],execute=execute,initialize=True,instruction_limit=2000000,memory_limit=128<<20)
    if report["result"].reason!="return" or report["result"].value: fail("winner control failed",report["result"].detail)
    for field in ["generated_entries","setup_actions","advpack_actions","service_activations","network_actions","process_queries","exceptions","security_actions"]:
        if report[field]: fail("native install-map query produced effects",field)
    if any(report["registry_effects"].values()): fail("native install-map modified registry")
    return dict(results=state["results"],queries=state["registry"]["queries"])

def inspection_candidates(components):
    """Read every persisted component and sum all installed-source backlinks."""
    deployments=components.find("/CanonicalData/Deployments")
    persisted=components.find("/DerivedData/Components")
    if deployments==None or persisted==None or len(persisted.children)>65536:
        fail("missing or oversized native component inventory")
    counts={}
    for key in deployments.children:
        name=key.name.lower()
        if name in counts: fail("ambiguous canonical deployment")
        counts[name]=len([n for n in key.values if n.lower().startswith("i!")])
    result={}
    for key in persisted.children:
        values=key.values
        identity=values.get("identity")
        if type(identity)!="bytes" or not identity: fail("component has no binary identity")
        name=str(identity).lower()
        if name in result: fail("duplicate component identity")
        count=0
        for backlink in values:
            if backlink.lower().startswith("c!"):
                owner=backlink[2:].lower()
                if owner not in counts: fail("component backlink has no canonical deployment")
                count+=counts[owner]
        result[name]=dict(identity=identity,installed_marks=count)
    return result

def select_inspection_inventory(candidates, changes, native_rows, expected_marks=None):
    """Select the native Fetch(flags=40h) inventory, minus both changed sides.

    native_rows must come from query_native_install_map against the exact target
    SOFTWARE hive. Complete row coverage is mandatory, including unowned staged
    components. The optional expected_marks independently reconciles population
    analysis against persisted source counts; it cannot supply missing counts.
    """
    if expected_marks!=None:
        expected={str(mark.identity).lower():mark.final for mark in expected_marks}
        if len(expected)!=len(expected_marks): fail("duplicate expected install mark")
        for key,count in expected.items():
            if key not in candidates or candidates[key]["installed_marks"]!=count:
                fail("persisted installed count differs from population analysis",key)
        if any([item["installed_marks"] for key,item in candidates.items() if key not in expected]):
            fail("population analysis omitted an installed component")
    excluded={}
    for before,after in changes:
        for identity in [before,after]:
            if identity!=None:
                key=str(identity).lower()
                if key not in candidates:
                    fail("changed identity absent from retained component inventory",key)
                excluded[key]=True
    rows={}
    installed=[]
    selected=[]
    for row in native_rows:
        key=str(row["identity"]).lower()
        if key in rows or key not in candidates or row["identity"]!=candidates[key]["identity"]:
            fail("native install-map row is duplicated or outside candidate inventory")
        rows[key]=True
        matches=row["present"] and row["version"]==row["identity_version"]
        # WCP 9703 CCSDirectComponentEnumerator::Fetch 1dac39..1dae38.
        # NonSxS requires a matching winner. Other identities reject a present
        # different winner, then require a positive installed-source count.
        eligible=matches if row["non_sxs"] else ((not row["present"] or matches) and candidates[key]["installed_marks"]>0)
        if eligible:
            installed.append(row["identity"])
            if key not in excluded:
                selected.append(row["identity"])
    if len(rows)!=len(candidates): fail("native install-map inventory is incomplete")
    return dict(identities=selected,candidates=len(candidates),installed=len(installed),excluded_changed=len(excluded))

def build_native_inspection_inventory(wcp_file, root, changes, expected_marks=None, progress=None):
    """Query every target candidate before returning an unchanged inventory."""
    sources={name:root.find("/Windows/System32/config/"+name) for name in ["COMPONENTS","SOFTWARE"]}
    if any([f==None for f in sources.values()]): fail("inspection inventory target hives missing")
    hashes={name:digest(f) for name,f in sources.items()}
    candidates=inspection_candidates(windows.hive(sources["COMPONENTS"]))
    software=windows.hive(sources["SOFTWARE"])
    identities=[candidates[key]["identity"] for key in sorted(candidates)]
    rows=[]
    for start in range(0,len(identities),512):
        rows.extend(query_native_install_map(wcp_file,software,identities[start:start+512])["results"])
        if progress!=None: progress(dict(stage="inventory",completed=len(rows),total=len(identities)))
    if any([digest(root.find("/Windows/System32/config/"+name))!=hashes[name] for name in hashes]):
        fail("inspection inventory hive changed during native queries")
    result=select_inspection_inventory(candidates,changes,rows,expected_marks=expected_marks)
    result["source_hashes"]=hashes
    return result


def resolve_inspection_manifests(components, identities, manifests, open_resident_components):
    """Bind selected native identities to exact decoded manifests and CSI hashes.

    Analysis intentionally preloads only changed compositions. Complete native
    inspection also needs unchanged components outside those compositions. Read
    those through the exact resident source, never a guessed stem or reference
    image. A missing or mismatched manifest rejects the entire input batch.
    """
    if len(identities)>32768:
        fail("native inspection manifest inventory exceeds bound")
    selected={str(identity).lower():identity for identity in identities}
    if len(selected)!=len(identities): fail("duplicate native inspection identity")
    parent=components.find("/DerivedData/Components")
    if parent==None: fail("native inspection component inventory missing")
    hashes={}
    for key in parent.children:
        values={n.lower():v for n,v in key.values.items()}
        identity=values.get("identity")
        if type(identity)!="bytes": fail("invalid persisted component identity")
        exact=str(identity).lower()
        if exact not in selected: continue
        if exact in hashes: fail("ambiguous native inspection component")
        digest_value=values.get("s256h")
        if type(digest_value)!="bytes" or len(digest_value)!=32:
            fail("native inspection component lacks SHA256")
        hashes[exact]=digest_value
    if len(hashes)!=len(selected): fail("native inspection identity not persisted")
    files={key:manifests[key] for key in selected if key in manifests}
    missing=[identity for identity in identities if str(identity).lower() not in files]
    if missing:
        decoded=open_resident_components(missing,workers=4)
        if len(decoded)!=len(missing): fail("resident inspection decoder count mismatch")
        files.update({str(identity).lower():f for identity,f in zip(missing,decoded)})
    total=0
    result=[]
    for identity in identities:
        exact=str(identity).lower()
        file=files.get(exact)
        if file==None or file.size>16<<20:
            fail("missing or oversized exact inspection manifest: "+exact)
        total+=file.size
        if total>512<<20: fail("native inspection manifest bytes exceed bound")
        if digest(file,algorithm="sha256")!=hashes[exact]:
            fail("native inspection manifest differs from persisted digest: "+exact)
        result.append(file)
    return result
