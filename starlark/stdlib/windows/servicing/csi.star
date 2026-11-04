"""Value-scoped CSI publication for a caller-owned candidate directory.

Not a complete CBS transaction or package-completion writer.
"""

load("@stdlib//windows/emulation:runner.star", _emulate_cbs_metadata="run")
load("@stdlib//windows/servicing:registry_effects.star", "build_update_driver_key_security")
load("@stdlib//windows/servicing:recovery.star", "retained_recovery_flags")

def _plan_csi_component_changes(root, payloads, sources, analysis):
    """Apply explicit CSI records, not package success or a complete transaction.

    Only new raw component descriptions are created. Existing storage flags,
    opaque source bytes and unrelated values are preserved. Catalog choices
    advance only for new deployments or explicit install-source edits.
    Full transitive compositions drive c! edges, including resident components.
    """
    path = "/Windows/System32/config/COMPONENTS"
    source = root.find(path)
    hive = windows.hive(source)
    components = {}
    stems = {}
    for key in hive.find("/DerivedData/Components").children:
        persisted = key.values
        identity = persisted["identity"]
        exact = str(identity).lower()
        if exact in components:
            fail("duplicate persisted CSI component identity")
        components[exact] = dict(stem=key.name, values={n.lower():v for n,v in persisted.items() if n.lower() == "s256h" or n[:2].lower() == "c!"})
        stems[key.name.lower()] = exact
    patches = []
    deletes = []
    created_keys = {}
    creation_security = {}
    def protect_new_key(key):
        parent = key.rsplit("/", 1)[0]
        if parent not in creation_security:
            node = hive.find(parent)
            if node == None or node.security == None:
                fail("CSI key creation requires an existing protected parent: " + parent)
            creation_security[parent] = build_update_driver_key_security(node.security)
        created_keys[key.lower()] = dict(key=key, security=creation_security[parent])
    report = dict(new_components=0, preserved_components=0, file_records=0, new_deployments=0, owner_additions=0, owner_deletions=0, source_sets=0, source_deletes=0, catalog_memberships=0, winner_sets=0, winner_deletes=0, driver_deployments=0)
    for plan in payloads["stages"].values():
        for record in plan.components:
            exact = str(record.identity).lower()
            if record.stem.lower() in stems and stems[record.stem.lower()] != exact:
                fail("CSI component stem collision")
            old = components.get(exact)
            if old != None:
                if old["stem"].lower() != record.stem.lower() or old["values"]["s256h"] != record.manifest_sha256:
                    fail("staged component disagrees with persisted identity/digest")
                # Existing physical flags describe actual retained storage, not
                # new RAW files. Do not silently keep compression flags after
                # rewriting a resident payload as RAW.
                if record.files:
                    fail("restaging a resident component requires storage-state reconciliation")
                report["preserved_components"] += 1
                continue
            key = "/DerivedData/Components/" + record.stem
            protect_new_key(key)
            patches.extend([
                dict(key=key, name="identity", type=3, value=record.identity),
                dict(key=key, name="S256H", type=3, value=record.manifest_sha256),
            ])
            values = dict(identity=record.identity, s256h=record.manifest_sha256)
            for name, flags in record.files.items():
                flags = retained_recovery_flags(root, payloads, record.stem, name, flags)
                patches.append(dict(key=key, name=name, type="REG_DWORD", value=flags))
                report["file_records"] += 1
            components[exact] = dict(stem=record.stem, values=values)
            stems[record.stem.lower()] = exact
            report["new_components"] += 1
    deployments = {k.name.lower(): k.values["appid"] for k in hive.find("/CanonicalData/Deployments").children}
    names = {p.lower(): p for p in root.files}
    catalogs = {}
    catalog_files = {}
    catalog_parent = hive.find("/CanonicalData/Catalogs")
    existing_catalogs = {k.name.lower(): True for k in catalog_parent.children} if catalog_parent != None else {}
    def get_catalog(package, manifest_hash):
        catkey = package.lower()
        if catkey not in catalogs:
            catalog_path = names.get(("/Windows/servicing/Packages/" + package + ".cat").lower())
            if catalog_path == None:
                fail("missing pinned source catalog: " + package)
            file = root.find(catalog_path)
            catalogs[catkey] = dict(path=catalog_path, thumbprint=hex(digest(file, algorithm="sha256")), members={v: True for v in windows.catalog_index(file)["sha256"]})
        catalog = catalogs[catkey]
        if manifest_hash not in catalog["members"]:
            fail("deployment root is not in exact source catalog: " + package)
        return catalog
    for position, (exact, row) in enumerate(sources.items()):
        identity = row["identity"]
        name = windows.csi_deployment_key(identity)
        key = "/CanonicalData/Deployments/" + name
        old = deployments.get(name.lower())
        if old != None and str(old).lower() != exact:
            fail("canonical CSI deployment collision")
        if exact not in components or exact not in analysis["compositions"]:
            fail("CSI deployment has no exact root component/composition")
        manifest_hash = components[exact]["values"]["s256h"]
        candidates = []
        for edit in row["plans"]["pin"].edits:
            if edit.delete:
                continue
            package = windows.cbs_deployment_source(edit.data).package
            catalog = get_catalog(package, manifest_hash)
            candidates.append(catalog)
            report["catalog_memberships"] += 1
        if old == None:
            if not candidates:
                fail("new CSI deployment has no verified catalog")
            protect_new_key(key)
            patches.append(dict(key=key, name="appid", type=3, value=identity))
            report["new_deployments"] += 1
        else:
            # Existing deployment pins alone do not publish a new catalog.
            # Installation does; preserve the source-plan execution order.
            candidates = [get_catalog(windows.cbs_deployment_source(edit.data).package, manifest_hash)
                          for edit in row["plans"]["install"].edits
                          if not edit.delete and edit.name.lower().startswith("i!")]
        for catalog in candidates:
            thumb = catalog["thumbprint"]
            if thumb.lower() not in existing_catalogs:
                protect_new_key("/CanonicalData/Catalogs/" + thumb)
            patches.append(dict(key="/CanonicalData/Catalogs/" + thumb, name="c!" + name, type=3, value=b""))
            # Later executed sources select the deployment's preferred catalog;
            # every authenticated source keeps its own catalog backlink.
            patches.append(dict(key=key, name="CatalogThumbprint", type="REG_SZ", value=thumb))
            destination = names.get(("/Windows/WinSxS/Catalogs/" + thumb + ".cat").lower(), "/Windows/WinSxS/Catalogs/" + thumb + ".cat")
            if destination not in catalog_files:
                present = root.find(destination)
                if present != None and hex(digest(present, algorithm="sha256")) != thumb:
                    fail("existing CSI catalog does not match its content-addressed name")
                catalog_files[destination] = dict(path=destination, source=catalog["path"], thumbprint=thumb, create=present==None)
        source_edits = {}
        for phase in ["pin", "stage", "install"]:
            for edit in row["plans"][phase].edits:
                source_edits[edit.name.lower()] = edit
        for edit in source_edits.values():
            if edit.delete:
                deletes.append(dict(key=key, name=edit.name))
                report["source_deletes"] += 1
            else:
                patches.append(dict(key=key, name=edit.name, type=edit.type, value=edit.data))
                report["source_sets"] += 1
        retained = row["plans"]["install"].after
        owned = retained.pinned != 0 or retained.installed != 0
        owner = "c!" + name
        for member in analysis["compositions"][exact]:
            component = components.get(str(member.identity).lower())
            if component == None:
                fail("CSI transitive composition member was not staged/resident")
            present = owner.lower() in component["values"]
            ckey = "/DerivedData/Components/" + component["stem"]
            if owned and not present:
                patches.append(dict(key=ckey, name=owner, type=3, value=b""))
                report["owner_additions"] += 1
            elif not owned and present:
                deletes.append(dict(key=ckey, name=owner))
                report["owner_deletions"] += 1
        if row["driver"]:
            report["driver_deployments"] += 1
    # Source plans can edit a value more than once across phases. Reduce to
    # the final value-level operation before writing, never delete a whole key.
    final = {}
    for patch in patches:
        final[(patch["key"].lower(), patch["name"].lower())] = patch
    for deletion in deletes:
        pair = (deletion["key"].lower(), deletion["name"].lower())
        if pair in final:
            fail("CSI source phases require ordered set/delete reduction")
    report["new_keys_protected"] = len(created_keys)
    return dict(source=source,patches=list(final.values()),deletes=deletes,keys=list(created_keys.values()),
        stems={exact:component['stem'] for exact,component in components.items()},catalog_files=list(catalog_files.values()),report=report)

def _build_csi_component_changes(root, payloads, sources, analysis):
    # Finish planning in its own frame. Release parsed catalogs, entire source
    # key inventories and interpreter temporaries before the native hive build.
    planned = _plan_csi_component_changes(root,payloads,sources,analysis)
    deletions = [dict(key=d["key"], name=d["name"], type="REG_NONE", value=b"", delete=True) for d in planned["deletes"]]
    component_file = windows.patch_hive(planned["source"], deletions + planned["patches"], keys=planned["keys"])
    written = windows.hive(component_file)
    parents = {}
    for record in planned["keys"]:
        parent, name = record["key"].rsplit("/", 1)
        if parent not in parents:
            parents[parent] = {k.name.lower(): k for k in written.find(parent).children}
        node = parents[parent].get(name.lower())
        if node == None or windows.security_descriptor_parts(node.security) != windows.security_descriptor_parts(record["security"]):
            fail("serialized CSI key creation security disagrees: " + record["key"])
    return component_file,planned['stems'],planned['report'],planned['catalog_files']

def apply_csi_state(root, payloads, sources, analysis):
    """Build and read back COMPONENTS and SOFTWARE changes before publication; preserve unrelated values and return CSI effects, not package completion."""
    # Read back both serialized hives before atomically publishing either.
    # This frame retains no plan dictionaries while building the second hive.
    component_file,component_stems,report,catalog_files = _build_csi_component_changes(root,payloads,sources,analysis)
    path = "/Windows/System32/config/COMPONENTS"
    software_path = "/Windows/System32/config/SOFTWARE"
    winner_patches = []
    winner_deletes = []
    for plan in analysis["winner_plans"]:
        for edit in plan.edits:
            key = "/Microsoft/Windows/CurrentVersion/SideBySide/Winners/" + plan.family
            if edit.branch:
                key += "/" + edit.branch
            if edit.delete:
                winner_deletes.append(dict(key=key, name=edit.name or "(default)"))
                report["winner_deletes"] += 1
            else:
                winner_patches.append(dict(key=key, name=edit.name, type=edit.type, value=edit.data))
                report["winner_sets"] += 1
    deletions = [dict(key=d["key"], name=d["name"], type="REG_NONE", value=b"", delete=True) for d in winner_deletes]
    software_file = windows.patch_hive(root.find(software_path), deletions + winner_patches)
    # Read the emitted bytes, not just the planned dictionaries. These checks
    # distinguish successful serialization from a plausible-looking report.
    written = windows.hive(component_file)
    # Native find() scans sibling nk cells. Index each emitted inventory once
    # rather than rescanning tens of thousands of components per owner edge.
    written_deployments = {k.name.lower(): k for k in written.find("/CanonicalData/Deployments").children}
    written_components = {k.name.lower(): k for k in written.find("/DerivedData/Components").children}
    verified_components = {}
    for exact, row in sources.items():
        name = windows.csi_deployment_key(row["identity"])
        node = written_deployments.get(name.lower())
        if node == None:
            fail("serialized CSI deployment is missing: " + name)
        actual = {n.lower(): (v.type, v.raw) for n,v in node.value_records.items() if n[:2].lower() in ["p!", "s!", "i!"]}
        expected = {v["name"].lower(): (v["type"], v["data"]) for v in row["final_sources"]}
        if actual != expected:
            fail("serialized CSI source values disagree with the full source plan: " + name)
        retained = row["plans"]["install"].after
        owned = retained.pinned != 0 or retained.installed != 0
        for member in analysis["compositions"][exact]:
            stem = component_stems[str(member.identity).lower()].lower()
            if stem not in verified_components:
                if stem not in written_components:
                    fail("serialized CSI component is missing: " + stem)
                verified_components[stem] = {n.lower():True for n in written_components[stem].values if n[:2].lower() == "c!"}
            values = verified_components[stem]
            if (("c!" + name).lower() in values) != owned:
                fail("serialized CSI ownership disagrees with retained sources")
    winners = windows.hive(software_file)
    families = {k.name.lower(): k for k in winners.find("/Microsoft/Windows/CurrentVersion/SideBySide/Winners").children}
    branches = {}
    for plan in analysis["winner_plans"]:
        for edit in plan.edits:
            key = "/Microsoft/Windows/CurrentVersion/SideBySide/Winners/" + plan.family
            if edit.branch:
                key += "/" + edit.branch
            family = families.get(plan.family.lower())
            node = family
            if edit.branch and family != None:
                if plan.family not in branches:
                    branches[plan.family] = {k.name.lower():k for k in family.children}
                node = branches[plan.family].get(edit.branch.lower())
            record = node.value_records.get(edit.name.lower() or "(default)") if node != None else None
            if edit.delete:
                if record != None:
                    fail("serialized winner deletion did not take effect")
            elif record == None or record.type != edit.type or record.raw != edit.data:
                fail("serialized winner value disagrees with native write plan")
    # Validate the complete file publication batch before any path is linked.
    for item in catalog_files:
        if hex(digest(root.find(item["source"]), algorithm="sha256")) != item["thumbprint"]:
            fail("CSI catalog source changed before publication")
        if item["create"] and root.find(item["path"]) != None:
            fail("CSI catalog destination appeared before publication")
    for item in catalog_files:
        if item["create"]:
            root.hardlink(item["source"], item["path"])
    root.write(path, component_file)
    root.write(software_path, software_file)
    report["catalog_files_created"] = len([p for p in catalog_files if p["create"]])
    report["verified_sources"] = len(sources)
    report["verified_winner_plans"] = len(analysis["winner_plans"])
    report["policy"] = "CSI value edits from full population; no package completion, lifecycle, driver completion, filemaps, or catalog database claim"
    return report



def inspect_native_package_context(cbs_file, wcp_file, ucrt_file, manifest, hives, files={}):
    """Inspect the exact 9703 CBS metadata prefix; no image writes or commit.

    Runs the real serviced CRT, MUM parser, WCP identity factory, constructors
    and package population against caller-supplied parsed hive sources. These
    are function-level controls, NOT a fully initialized servicing session or a
    completed stage/install. Only ordinary object inputs are linked manually:
    the native identity authority and the constructed store-parameter object.
    No package/session/CSI success, Active or completion flag is supplied.

    Version-gated private addresses come from the exact matching public PDBs.
    Returns the runner's effects/stop evidence; result retains machine, pointers
    and bounded steps for follow-up in the inspection REPL. Do not infer success
    from a returned dictionary: require each native step's return/value. A fresh
    run is needed after contributing code/input changes; snapshots share plugin
    state and must not be treated as independent registry/filesystem variants.
    """
    identities = [
        (cbs_file, "A3649FD182275D7156E38C3A438791D71"),
        (wcp_file, "7CC21FAF1E625E052DD8ADB23E8B25F21"),
        (ucrt_file, "66A3E8DFB8B886146544529E6A6DD4F41"),
    ]
    for file, key in identities:
        pe = windows.pe(file)
        if pe.info["machine"] != 0x8664 or pe.codeview == None or pe.codeview["key"] != key:
            fail("native CBS metadata control requires exact serviced PE identities")
    cbs = windows.pe(cbs_file)

    def private_crt_alias(context):
        def callback(event):
            # Exact real UCRT exports, preserving the native call ABI. Load all
            # real modules before plugin installation so API-set imports are
            # hooked as well; late load_module alone misses those import hooks.
            event.machine.transfer(event.machine.resolve_export("ucrtbase.dll", name=event.name))
        def install(machine):
            for imported in cbs.imports:
                if "crt-private" in imported["dll"].lower():
                    machine.provide_export(callback, module=imported["dll"], name=imported["name"], argc=0, convention="win64")
        return emulator.plugin(install, name="native CBS private CRT forwards")

    def execute(machine):
        out = dict(machine=machine, steps=[])
        primary = [m for m in machine.modules if m.primary][0]
        crt = [m for m in machine.modules if m.name.lower() == "ucrtbase.dll"][0]
        def call(name, address, args, expected=0):
            result = machine.call(address, args=args)
            out["steps"].append(dict(name=name, reason=result.reason, detail=result.detail, value=result.value, instructions=result.steps))
            return result.reason == "return" and result.value == expected
        def construct(name, rva, size, args=[]):
            pointer = machine.allocate(size=size, name=name)
            return pointer if call(name, primary.base+rva, [pointer]+args, expected=pointer) else 0
        if not call("ucrt_attach", crt.entry, [crt.base,1,0], expected=1):
            return out
        if not call("cbs_attach", primary.entry, [primary.base,1,0], expected=1):
            return out
        parsing = construct("parser_ctor", 161312, 4096)
        if not parsing:
            return out
        data = machine.allocate(value=manifest.bytes(), name="exact CBS MUM")
        if not call("parse", primary.base+1876608, [data,manifest.size,parsing]):
            return out
        out["parse_session"] = parsing
        parameters = construct("params_ctor", 1776672, 4096)
        if not parameters or not call("params_init", primary.base+596012, [parameters,0,0,0,0]):
            return out
        authority = machine.allocate(size=8, name="native identity authority output")
        if not call("identity_factory", machine.resolve_export("wcp.dll",name="GetIdentityAuthority"), [authority]):
            return out
        machine.write_pointer(primary.base+0x3732b8, machine.read_pointer(authority))
        identity = machine.allocate(size=8, name="native package identity output")
        # PrepareInitializeEx uses ParsingSession+0x38 and inline identity+0x130.
        parsed_package = machine.read_pointer(parsing+0x38)
        if not call("package_identity", primary.base+290736, [parsed_package+0x130,identity,0]):
            return out
        session = construct("session_ctor", 463616, 16384)
        if not session:
            return out
        machine.write_pointer(session+0x348, parameters)
        # The identity-taking constructor supplies package+0x70. A default
        # constructor is not a valid PopulatePackage input (native parent code
        # requires the existing identity); never replace that fault with flags.
        package = construct("package_ctor", 185080, 4096, [machine.read_pointer(identity)])
        if not package:
            return out
        out.update(session=session, package=package, params=parameters)
        if call("populate", primary.base+0x16584c, [package,session,0,parsing,parsed_package]):
            text = machine.allocate(size=8, name="native package display identity")
            if call("identity_string", primary.base+0x67600, [package,text]):
                out["identity_string"] = machine.read_cstring(machine.read_pointer(text), encoding="utf16le", maximum=4096)
        return out

    return _emulate_cbs_metadata(cbs_file, "cbscore.dll", execute=execute,
        initialize=False, modules={"ucrtbase.dll":ucrt_file, "wcp.dll":wcp_file},
        plugin_factories=[private_crt_alias], registry_hives=hives, files=files,
        instruction_limit=2000000, memory_limit=96<<20)
