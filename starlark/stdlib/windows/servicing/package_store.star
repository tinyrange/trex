"""Publish admitted package dispositions after constructing their effects.

CBS state is consumed by Windows servicing, not an internal confidence flag.
Never cap installed packages or owner requests at Resolved because validation
is outstanding. See docs/windows-package-state-policy.md.
"""

load("@stdlib//windows/servicing:package_indexes.star", "plan_servicing_package_indexes")

_NS = "urn:schemas-microsoft-com:asm.v3"
_CBS = "/Microsoft/Windows/CurrentVersion/Component Based Servicing/"

def package_metadata_executions(population, packages):
    """Select admitted metadata, not merely the last population action.

    Merge can converge a previously processed stage/install to ActionNone.
    MUMPopulated records that admission; the final target still limits lifetime.
    This selects metadata; final state publication follows the applied effects.
    """
    return [e for e in population.selected_executions(packages)
            if e.action in [2, 3] or e.mum_populated and e.intended_state >= 0x20]


def _identity_bytes(identity):
    fields = [identity.name, "Culture=" + (identity.language or "neutral")]
    if identity.type:
        fields.append("Type=" + identity.type)
    fields += ["Version=" + identity.version, "PublicKeyToken=" + identity.public_key_token, "ProcessorArchitecture=" + identity.processor_architecture]
    if identity.version_scope:
        fields.append("versionScope=" + identity.version_scope)
    return bytes(", ".join(fields))

def _staged_manifest_sources(payloads):
    result = {}
    for plan in payloads["stages"].values() if payloads != None else []:
        entries = {entry.store_path.lower(): i for i,entry in enumerate(plan.files) if entry.kind == "component-manifest"}
        for record in plan.components:
            path = "/Windows/WinSxS/Manifests/" + record.stem + ".manifest"
            if path.lower() not in entries:
                fail("staged component description has no exact encoded manifest source")
            exact = str(record.identity).lower()
            if exact in result:
                fail("ambiguous exact staged manifest source")
            result[exact] = dict(plan=plan,index=entries[path.lower()],sha256=record.manifest_sha256)
    return result

def plan_resident_package_dispositions(software, population):
    """Persist explicit resident execution transitions after construction effects.

    FinalCommitPackagesState retains 0x50; dirty/action normalization to 0x40
    does not apply to persistence. Owner overlays retain unmentioned owners.
    Only the observed installed-to-superseded transition is supported here;
    removal/reinstallation requires its own effects and must fail closed.
    """
    hive = windows.hive(software, snapshot=True)
    registered = {n.name.lower(): n for n in hive.find(_CBS + "Packages").children}
    patches, deleted, audit = [], [], []
    for execution in population.selected_executions(list(registered)):
        node = registered[execution.package.lower()]
        before = node.values["CurrentState"]
        target = execution.intended_state
        if target != before and (before, target) != (0x70, 0x50):
            fail("unsupported resident package transition: " + node.name)
        key = _CBS + "Packages/" + node.name
        owner_node = hive.find(key + "/Owners")
        owners = dict(owner_node.values) if owner_node != None else {}
        original_owners = dict(owners)
        for owner in execution.owners:
            if not owner.owner or owner.integration not in [2,3,4] or owner.state not in [0,0x40,0x50,0x70,0x80]:
                fail("unsupported resident owner transition: " + node.name)
            existing = [name for name in owners if name.lower() == owner.owner.lower()]
            name = existing[0] if existing else owner.owner
            if owner.state == 0:
                if name in owners:
                    owners.pop(name)
                    deleted.append(dict(key=key + "/Owners", name=name))
            else:
                word = (owner.integration << 16) | owner.state
                if owners.get(name) != word:
                    patches.append(dict(key=key + "/Owners", name=name, type="REG_DWORD", value=word))
                    owners[name] = word
        if target != before:
            patches.append(dict(key=key, name="CurrentState", type="REG_DWORD", value=target))
        if target != before or owners != original_owners:
            audit.append(dict(package=node.name, state=target, source_state=before,
                owners=owners, evidence="resident execution transition after construction; native final-commit target and owner overlays"))
    return dict(patches=patches, deleted_values=deleted, dispositions=audit)


def publish_package_metadata(root, base, image, closure, population, analysis, catalogs, payloads=None, audit=True):
    """Publish new packages with their admitted stage/install dispositions.

    Called after file, registry, installer and CSI effects have been applied.
    Exact signed MUM membership is mandatory. Optional audit mode also reads
    back emitted composition, payload bytes and serialized dispositions.
    Unchanged native packages are preserved; explicit resident transitions
    are persisted alongside new packages. Unsupported dispositions fail
    without writing a conservative placeholder into Windows' registry.
    """
    if catalogs.get("mum_memberships") != catalogs["catalogs"] or not catalogs.get("packages"):
        fail("resolved metadata requires complete signed MUM catalog membership")
    software_path = "/Windows/System32/config/SOFTWARE"
    software_file = root.find(software_path)
    software = windows.hive(software_file, snapshot=True)
    registered = {k.name.lower(): k for k in software.find(_CBS + "Packages").children}
    files = {name.lower(): file for name,file in closure["files"].items()}
    selected = {name.lower(): name for name in catalogs["packages"] if name.lower() not in registered}
    executions = {e.package.lower(): e for e in population.selected_executions(list(selected))}
    verified, encoded_new, encoded_resident, pins = {}, 0, 0, 0
    if audit:
        components_hive = windows.hive(root.find("/Windows/System32/config/COMPONENTS"))
        components = {str(k.values["identity"]).lower(): k for k in components_hive.find("/DerivedData/Components").children}
        deployments = {k.name.lower(): k for k in components_hive.find("/CanonicalData/Deployments").children}
        staged_manifests = _staged_manifest_sources(payloads)
        member_catalogs = {}
        parsed_packages = {}
        for action in population.deployment_actions(changed_only=True):
            if not action.stage or action.package.lower() not in selected:
                continue
            identity = _identity_bytes(action.deployment)
            key = str(identity).lower()
            deployment_name = windows.csi_deployment_key(identity)
            deployment = deployments.get(deployment_name.lower())
            package = action.package.lower()
            if package not in parsed_packages: parsed_packages[package] = windows.cbs_manifest(files[package])
            data = windows.cbs_deployment_source_data(parsed_packages[package], action.update)
            source = windows.cbs_deployment_source(data)
            values = {n.lower(): v for n,v in deployment.values.items()} if deployment != None else {}
            pin = values.get(("p!" + source.source_key).lower())
            if pin == None or windows.cbs_deployment_source(pin).primary != source.primary:
                fail("resolved package lacks its emitted exact manifest pin: " + action.package)
            if key not in analysis["compositions"]:
                fail("resolved source lacks its complete transitive composition")
            if action.package.lower() not in member_catalogs:
                file = root.find("/Windows/servicing/Packages/" + action.package + ".cat")
                member_catalogs[action.package.lower()] = {h: True for h in windows.catalog_index(file)["sha256"]}
            catalog_members = member_catalogs[action.package.lower()]
            for member in analysis["compositions"][key]:
                exact = str(member.identity).lower()
                component = components.get(exact)
                if component == None:
                    fail("resolved composition member is not persisted")
                component_values = {n.lower(): v for n,v in component.values.items()}
                if ("c!" + deployment_name).lower() not in component_values:
                    fail("resolved composition lacks its emitted ownership backlink")
                if component_values.get("s256h") not in catalog_members:
                    fail("resolved transitive manifest is outside its source package catalog: " + action.package)
                if exact in verified:
                    continue
                expected = analysis["manifests"].get(exact) or analysis["resident_manifests"].get(exact)
                if expected == None or digest(expected, algorithm="sha256") != component_values.get("s256h"):
                    fail("resolved manifest disagrees with emitted component digest")
                path = "/Windows/WinSxS/Manifests/" + component.name + ".manifest"
                actual = root.find(path)
                if actual == None:
                    fail("resolved manifest is not present in the actual image")
                if actual.size >= 4 and actual.bytes(0,4) == b"DCM\x01":
                    staged = staged_manifests.get(exact)
                    if staged != None:
                        # The native exact staging plan retains the encoded manifest
                        # and derives this digest by decoding that same source with
                        # the stage's WCP dictionary. Bind BOTH forms; never compare
                        # encoded DCM bytes directly to the decoded catalog digest.
                        if staged["sha256"] != component_values["s256h"] or digest(actual,algorithm="sha256") != digest(staged["plan"].open(staged["index"]),algorithm="sha256"):
                            fail("actual encoded manifest differs from its validated exact staging source: " + path)
                        encoded_new += 1
                    else:
                        # Resident DCM is bound to the unchanged base and dictionary,
                        # whose decoded exact identity/digest analysis validated.
                        if image + path not in base or digest(actual,algorithm="sha256") != digest(base[image + path],algorithm="sha256"):
                            fail("resolved compressed manifest differs from validated resident source: " + path)
                        encoded_resident += 1
                elif digest(actual, algorithm="sha256") != component_values["s256h"]:
                    fail("actual resolved manifest bytes disagree with CSI metadata")
                verified[exact] = True
            pins += 1
    patches = []
    names = []
    owners_count = 0
    dispositions = {}
    state_audit = []
    for lower,name in sorted(selected.items()):
        execution = executions.get(lower)
        if execution == None or not execution.mum_populated or execution.intended_state not in [0x40, 0x70]:
            fail("new package has no supported admitted stage/install disposition: " + name)
        actual = root.find("/Windows/servicing/Packages/" + name + ".mum")
        if lower not in files or actual == None or digest(actual,algorithm="sha256") != digest(files[lower],algorithm="sha256"):
            fail("actual resolved MUM differs from the admitted exact metadata")
        package = binary.xml(actual).root.child("package",namespace=_NS)
        self_update = package.attribute("selfUpdate","false")
        if self_update not in ["true","false"]:
            fail("unsupported resolved package self-update flag")
        owner_words = {}
        # A later ordinary merge can leave action=None after earlier admission;
        # use actual manifest proof plus retained MUM admission, not last action.
        for owner in execution.owners:
            # Zero-state requests remove an owner in the native nonpending
            # store. These are NEW keys, so there is nothing to delete.
            if owner.state == 0:
                continue
            if owner.integration not in [2,3,4] or not owner.owner or owner.state not in [0x40, 0x70, 0x80]:
                fail("package owner requires unsupported state/integration policy")
            owner_words[owner.owner] = (owner.integration << 16) | owner.state
        parents = package.children_named("parent",namespace=_NS)
        hidden_parent = bool(parents) and all([p.attribute("integrate","") == "subsume" for p in parents])
        hidden_owner = bool(owner_words) and all([word >> 16 == 3 for word in owner_words.values()])
        key = _CBS + "Packages/" + name
        for value_name,kind,value in [
            ("CurrentState","REG_DWORD",execution.intended_state),
            ("InstallClient","REG_SZ","TinyRangeX"),
            ("InstallName","REG_SZ",name + ".mum"),
            ("InstallLocation","REG_SZ",chr(92)*2 + "?" + chr(92) + "C:" + chr(92) + "Windows" + chr(92) + "servicing" + chr(92) + "Packages" + chr(92)),
            ("SelfUpdate","REG_DWORD",int(self_update == "true")),
            ("Visibility","REG_DWORD",2 if hidden_parent or hidden_owner else 1),
        ]:
            patches.append(dict(key=key,name=value_name,type=kind,value=value))
        for owner,word in owner_words.items():
            patches.append(dict(key=key + "/Owners",name=owner,type="REG_DWORD",value=word))
            owners_count += 1
        patches.extend(plan_servicing_package_indexes(actual))
        names.append(name)
        dispositions[name.lower()] = execution.intended_state
        state_audit.append(dict(package=name, state=execution.intended_state,
            owners=owner_words, evidence="admitted stage-only disposition" if execution.intended_state == 0x40 else "admitted installation; construction effects applied before publication"))
    resident = plan_resident_package_dispositions(software_file, population)
    patches.extend(resident["patches"])
    state_audit.extend(resident["dispositions"])
    updated = windows.patch_hive(software_file, patches, delete_values=resident["deleted_values"])
    if audit:
        written = windows.hive(updated, snapshot=True)
        written_packages = {k.name.lower(): k for k in written.find(_CBS + "Packages").children}
        for name in names:
            key = written_packages.get(name.lower())
            if key == None or key.values.get("CurrentState") != dispositions[name.lower()] or key.values.get("InstallName") != name + ".mum":
                fail("serialized package disposition is missing")
    root.write(software_path,updated)
    return dict(readback_audit="completed" if audit else "not-performed",packages=len(names),resident_transitions=len(resident["dispositions"]),manifest_pins=pins,verified_manifests=len(verified),encoded_new=encoded_new,encoded_resident=encoded_resident,published_owners=owners_count,dispositions=state_audit,policy="published admitted dispositions after construction; validation uncertainty is not a CBS state")
