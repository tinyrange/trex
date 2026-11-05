"""Store-file preparation for the bounded offline update construction.

This implements source-folder and component-file ACL effects, manifest creation
security, logical payloads and exact source joins. Driver queues and component/
CBS lifecycle finalization remain separate.
"""

load("@stdlib//windows/servicing:file_commit.star", "image_path_names")
load("@stdlib//windows/servicing:recovery.star", "plan_inherited_recovery", "apply_inherited_recovery", "plan_generated_recovery", "apply_generated_recovery", "SERVICING_RECOVERY_FILETIME")
load("@stdlib//windows/servicing:runtime.star", "build_servicing_created_security", "build_servicing_staged_file_security_request", "assign_servicing_staged_file_security", "build_servicing_directory_security_request", "assign_servicing_directory_security")


def build_update_source_folder_security(parent):
    """Derive the established native source-folder descriptor from the actual parent security; return descriptor bytes."""
    # WCP 5D2C0A2BEA78B8EEBEC74A88722B0F541 constructor 0x827af/0x827eb
    # caches filesystem default 0x40. AddComponentFile 0x13d28c/0x13d2a5
    # applies it only to newly created real-store component directories.
    # ApplySecurityToObject decomposes the default into principals/ACLs;
    # its S:AI bit is not passed through that interface. CDirectory then
    # performs the established directory auto-inheritance/assignment path.
    ti = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    selected = windows.compile_sddl("O:"+ti+"G:"+ti+"D:P(A;CIOI;FA;;;"+ti+")(A;CIOI;GRGX;;;BA)(A;CIOI;GRGX;;;SY)(A;CIOI;GRGX;;;BU)(A;CIOI;GRGX;;;S-1-15-2-1)(A;CIOI;GRGX;;;S-1-15-2-2)S:")
    created = build_servicing_created_security(parent, directory=True)
    request = build_servicing_directory_security_request(selected, parent)
    return assign_servicing_directory_security(created, request)


def stage_update_payload_files(root, payloads):
    """Materialize admitted payload sources and their security/metadata on root; do not replay this after native driver publication."""
    names = image_path_names(root)
    folder_security = {"/": root.get_security("/")}
    identities = {}
    driver_kinds = {}
    requests = {}
    assigned_security = {}
    created_security = {}
    source_folder_security = {}
    seed_security = windows.compile_sddl("O:SYG:SY")
    def created(parent, directory=False):
        key = (parent, directory)
        if key not in created_security:
            created_security[key] = build_servicing_created_security(parent, directory=directory)
        return created_security[key]
    for plan in payloads["stages"].values():
        for component in plan.components:
            key = component.stem.lower()
            if key in identities and identities[key] != component.identity:
                fail("conflicting exact staging component identity")
            identities[key] = component.identity
    preserved = {}
    payloads["preserved_staging_paths"] = preserved
    counts = dict(files=0, preserved_files=0, component_file_security=0, created_parents=0, source_folder_security=0, manifest_security=0)
    for feature, plan in payloads["stages"].items():
        started = clock.monotonic()
        for position, index in enumerate(plan.read_order):
            if position % 512 == 0:
                print("store staging", feature, position, "of", len(plan.files), "elapsed", clock.monotonic() - started, "seconds; next", plan.files[index].store_path)
            entry = plan.files[index]
            path = names.get(entry.store_path.lower(), entry.store_path)
            # TurboStack 26100.9703 PrestageFile 0xea1d7..0xea2c4:
            # the first pass marks an existing target staged without opening
            # the incoming payload or replacing the target object. In
            # particular, preserve its aliases, EAs, storage and security.
            # WriteManifestFile has a separate overwrite contract below.
            if entry.kind == "component-file" and root.find(path) != None:
                preserved[path.lower()] = True
                counts["preserved_files"] += 1
                counts["files"] += 1
                continue
            parts = path.split("/")
            parent = "/"
            for i in range(2, len(parts)):
                declared = "/".join(parts[:i])
                current = names.get(declared.lower(), parent.rstrip("/") + "/" + parts[i-1])
                if current not in folder_security:
                    existing = testing.attempt(root.get_security, args=[current])
                    if existing.ok:
                        if existing.value == None:
                            fail("existing store parent lacks security: " + current)
                        folder_security[current] = existing.value
                    else:
                        if declared.lower().startswith("/windows/winsxs/") and i==4 and parts[i-1].lower() in identities:
                            ancestor = folder_security[parent]
                            if ancestor not in source_folder_security:
                                source_folder_security[ancestor] = build_update_source_folder_security(ancestor)
                            descriptor = source_folder_security[ancestor]
                            counts["source_folder_security"] += 1
                        else:
                            descriptor = created(folder_security[parent], directory=True)
                        root.mkdir(current)
                        root.set_security(current, descriptor)
                        folder_security[current] = descriptor
                        names[declared.lower()] = current
                        counts["created_parents"] += 1
                parent = current
            path = parent.rstrip("/") + "/" + parts[-1]
            source = plan.open(index, lazy=True)
            # Payload/predecessor descriptors identify logical bytes: their
            # native resolvers expand WIM DCS bases before checking hashes.
            # Probing their magic would reconstruct every unused lazy file
            # (and could incorrectly expand an actual logical DCS file twice).
            # Only archive/installed fallbacks can still be storage-encoded.
            if entry.kind == "component-file" and entry.source_mode not in ["payload", "predecessor"] and source.size >= 4 and source.slice(0, 4).bytes() == b"DCS\x01":
                source = archive.dcs(source)
            prior = root.get_security(path) if root.find(path) != None else None
            if root.find(path) != None:
                root.remove(path)
            root.write(path, source)
            names[path.lower()] = path
            if entry.kind == "component-file":
                stem = entry.store_path.split("/")[3].lower()
                identity = identities.get(stem)
                if identity == None:
                    fail("staged file has no exact component identity: " + path)
                if identity not in driver_kinds:
                    driver_kinds[identity] = windows.csi_identity(identity).type.lower() in ["driverupdate", "dualmodedriver"]
                request_key = (folder_security[parent], driver_kinds[identity])
                if request_key not in requests:
                    requests[request_key] = build_servicing_staged_file_security_request(folder_security[parent], driver=driver_kinds[identity])
                request = requests[request_key]
                # Staging overwrites all owner/group/ACL/label categories.
                # Its final NULL-SACL result is independent of creation's
                # token-default DACL; this seed is not a creation descriptor.
                # Share only pure transformations of byte-identical inputs.
                # Distinct existing descriptors still pass the full validator.
                security_key = (prior or seed_security, request_key)
                if security_key not in assigned_security:
                    assigned_security[security_key] = assign_servicing_staged_file_security(security_key[0], request)
                root.set_security(path, assigned_security[security_key])
                counts["component_file_security"] += 1
            else:
                # WriteManifestFile 0x1ac1d4 opens with FILE_OVERWRITE_IF,
                # NULL creator security and no subsequent security setter.
                # Existing security survives; new files inherit from the
                # actual Manifests directory under the declared SYSTEM subject.
                if entry.kind != "component-manifest":
                    fail("unestablished noncomponent staging security")
                if prior != None:
                    root.set_security(path, prior)
                else:
                    root.set_security(path, created(folder_security[parent]))
                counts["manifest_security"] += 1
            counts["files"] += 1
        print("store payloads prepared", feature, len(plan.files))
    recovery = plan_inherited_recovery(root, payloads)
    payloads["retained_recovery"] = apply_inherited_recovery(root, recovery)
    counts["inherited_recovery"] = len(recovery)
    generated = plan_generated_recovery(root, payloads, SERVICING_RECOVERY_FILETIME)
    generated_markers = apply_generated_recovery(root, generated)
    for stem, records in generated_markers.items():
        retained = payloads["retained_recovery"].setdefault(stem, {})
        for name, proof in records.items():
            if name in retained:
                fail("conflicting inherited/generated recovery marker")
            retained[name] = proof
    counts["generated_recovery"] = len(generated)
    return counts


def resolve_update_source_paths(root, prepared, payloads):
    """Bind prepared source identities to exact staged or resident paths in root; reject missing or ambiguous sources."""
    names = {p.lower():p for p in root.files}
    stems = {}
    for path in root.files:
        if path.lower().startswith("/windows/winsxs/manifests/") and path.lower().endswith(".manifest"):
            stem = path.rsplit("/",1)[1][:-9]
            stems.setdefault(int(stem.rsplit("_",1)[1],16), {})[stem.lower()] = stem
    for plan in payloads["stages"].values():
        for component in plan.components:
            stems.setdefault(windows.csi_identity_hash(component.identity), {})[component.stem.lower()] = component.stem
    result = {}
    for key, pair in prepared["sources"].items():
        primary = pair.get("after")
        if primary == None:
            continue
        candidates = stems.get(windows.csi_identity_hash(primary["component_identity"]), {})
        if len(candidates) != 1:
            fail("ambiguous exact runtime component source")
        stem = list(candidates.values())[0]
        path = "/Windows/WinSxS/" + stem + "/" + primary["record"]["name"].replace(chr(92),"/")
        result[key] = names.get(path.lower(), path)
    return result
