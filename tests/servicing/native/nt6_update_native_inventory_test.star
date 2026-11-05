"""Explicit-media native install-map regression controls."""
load("@stdlib//windows/servicing:native_inventory.star","query_native_install_map","inspection_candidates","select_inspection_inventory","resolve_inspection_manifests")

def verify_native_install_map(wcp):
    definitions=[
        b"InventoryControl.NonSxs, Culture=neutral, Version=10.0.1.1, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS",
        b"InventoryControl.Sxs, Culture=neutral, Type=win32, Version=10.0.1.1, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64",
        b"InventoryControl.Policy, Culture=neutral, Type=win32-policy, Version=10.0.1.1, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64",
        b"InventoryControl.Absent, Culture=neutral, Version=10.0.1.1, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS",
        b"InventoryControl.NoBranch, Culture=neutral, Type=win32, Version=10.0.1.1, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64",
    ]
    patches=[]
    prefix="/Microsoft/Windows/CurrentVersion/SideBySide/Winners/"
    for identity in definitions[:3]+definitions[4:]:
        key=prefix+windows.csi_winner_family_key(identity)
        patches.append(dict(key=key,name="",type="REG_SZ",value="11.0"))
        patches.append(dict(key=key+"/11.0",name="",type="REG_SZ",value="11.0.2.2"))
        if identity!=definitions[4]:
            patches.append(dict(key=key+"/10.0",name="",type="REG_SZ",value="10.0.1.1"))
    file=windows.hive_from_patches("SOFTWARE",patches)
    before=digest(file)
    result=query_native_install_map(wcp,windows.hive(file),definitions)
    v10=(10<<48)+(1<<16)+1
    v11=(11<<48)+(2<<16)+2
    expected=[(True,True,v11),(False,True,v10),(False,True,v11),(True,False,0),(False,False,0)]
    actual=[(r["non_sxs"],r["present"],r["version"]) for r in result["results"]]
    if actual!=expected or any([r["identity_version"]!=v10 for r in result["results"]]):
        fail("native install-map cross-branch/same-branch/absent control mismatch",actual)
    if digest(file)!=before: fail("native install-map changed source hive")
    return dict(cases=len(expected),queries=len(result["queries"]))

def verify_native_inspection_selection(wcp):
    first=b"InventorySelection.NonSxs, Culture=neutral, Version=10.0.1.1, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS"
    second=b"InventorySelection.Sxs, Culture=neutral, Type=win32, Version=10.0.1.1, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"
    third=b"InventorySelection.NoWinner, Culture=neutral, Type=win32, Version=10.0.1.1, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"
    fourth=bytes(str(first).replace("10.0.1.1","11.0.2.2"))
    definitions=[first,second,third,fourth]
    software=[]
    prefix="/Microsoft/Windows/CurrentVersion/SideBySide/Winners/"
    for identity,branch,version in [(first,"11.0","11.0.2.2"),(second,"10.0","10.0.1.1")]:
        key=prefix+windows.csi_winner_family_key(identity)
        software.extend([dict(key=key,name="",type="REG_SZ",value=branch),dict(key=key+"/"+branch,name="",type="REG_SZ",value=version)])
    components=[dict(key="/CanonicalData/Deployments/owner",name="i!source1",type=3,value=b"one"),dict(key="/CanonicalData/Deployments/owner",name="i!source2",type=3,value=b"two")]
    for index,identity in enumerate(definitions):
        key="/DerivedData/Components/c"+str(index)
        components.append(dict(key=key,name="identity",type=3,value=identity))
        if identity in [first,third]: components.append(dict(key=key,name="c!owner",type=3,value=b""))
    candidates=inspection_candidates(windows.hive(windows.hive_from_patches("COMPONENTS",components)))
    if candidates[str(third).lower()]["installed_marks"]!=2: fail("installed sources were collapsed into an owner boolean")
    queried=query_native_install_map(wcp,windows.hive(windows.hive_from_patches("SOFTWARE",software)),definitions)["results"]
    result=select_inspection_inventory(candidates,[],queried)
    # Positive marks cannot rescue a non-winning NonSxS component; a matching
    # winner cannot rescue an unowned SxS component. Missing SxS winner plus
    # marks is eligible, as is a matching NonSxS winner without marks.
    if result["identities"]!=[third,fourth]: fail("native inventory predicate mismatch",result)
    excluded=select_inspection_inventory(candidates,[(third,fourth)],queried)
    if excluded["identities"] or excluded["excluded_changed"]!=2: fail("both changed sides must be excluded")
    for rows in [queried[:-1],queried+[queried[0]]]:
        attempt=testing.attempt(select_inspection_inventory,args=[candidates,[],rows])
        if attempt.ok: fail("partial or duplicated native inventory accepted")
    return dict(source_count=2,complete_candidates=4,installed=2,both_changed_sides_excluded=True)


def verify_inspection_manifest_binding():
    identities=[b"cached",b"unchanged"]
    files=[binary.concat(["cached manifest"]),binary.concat(["resident manifest"])]
    patches=[]
    for identity,file in zip(identities,files):
        key="/DerivedData/Components/"+str(identity)
        patches.extend([dict(key=key,name="identity",type=3,value=identity),
            dict(key=key,name="S256H",type=3,value=digest(file,algorithm="sha256"))])
    components=windows.hive(windows.hive_from_patches("COMPONENTS",patches))
    requested=[]
    def decode(wanted,workers):
        requested.extend(wanted)
        return [files[1] for identity in wanted]
    result=resolve_inspection_manifests(components,identities,{"cached":files[0]},decode)
    if result!=files or requested!=[b"unchanged"]:
        fail("inspection failed to preserve exact order or resolve unchanged manifests")
    for selected,cached in [(identities,{"cached":files[1]}),
            (identities+identities[:1],{"cached":files[0]}),
            ([b"not-persisted"],{})]:
        attempt=testing.attempt(resolve_inspection_manifests,args=[components,selected,cached,decode])
        if attempt.ok: fail("inspection admitted mismatched, duplicate or unbound manifest")
    return dict(exact_resident_resolution=True,digest_mismatch_rejected=True,
        duplicate_rejected=True,unpersisted_identity_rejected=True)
