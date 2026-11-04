"""Native path/FileMap construction for caller-owned offline images.

Planning is separate from applying effects. In particular a complete map plan
is not permission to mark a package installed or discard driver-store state.
"""

load("@stdlib//windows/servicing:runtime.star", "analyze_servicing_file_paths", "resolve_servicing_file_paths", "servicing_file_path_roots", "analyze_servicing_file_security", "analyze_servicing_directories", "resolve_servicing_directory_paths")
load("@stdlib//windows/servicing:runtime.star", "servicing_directory_propagation_policy", "servicing_file_compression_policy", "select_servicing_file_hash", "prepare_servicing_projected_files", "prepare_servicing_unprojected_files", "reduce_servicing_file_declarations", "preprocess_servicing_file_declarations", "reduce_servicing_directory_declarations", "preprocess_servicing_directory_declarations", "preprocess_servicing_path_hierarchy", "select_servicing_file_commit_paths")
load("@stdlib//windows/servicing:runtime.star", "plan_servicing_filemap", "servicing_filemap_collision_policy", "servicing_filemap_collision_status")


def prepare_update_file_hierarchy(runtime, hives, driver_projection_candidates=False):
    """Resolve amd64 runtime paths, hashes and security against explicit baseline hives; return reduced hierarchy, sources and collision policy."""
    software = windows.hive(hives["SOFTWARE"])
    components = windows.hive(hives["COMPONENTS"])
    roots = servicing_file_path_roots(software, "/Windows", "amd64")
    resolved = resolve_servicing_file_paths(analyze_servicing_file_paths(runtime, "amd64"), roots, driver_projection_candidates=driver_projection_candidates)
    policy = servicing_directory_propagation_policy(software, components)
    policy.update(servicing_file_compression_policy(windows.hive(hives["SYSTEM"])))
    hashes = {}
    for transition in runtime["transitions"]:
        for side in ["before", "after"]:
            if transition[side] == None:
                continue
            identity = transition["component_identities"][side]
            for file in windows.assembly_manifest(transition[side]).files:
                key = (identity, file.name.lower())
                expected = select_servicing_file_hash(file)
                if key in hashes and hashes[key] != expected:
                    fail("conflicting exact file hashes")
                hashes[key] = expected
    projected = prepare_servicing_projected_files(resolved, analyze_servicing_file_security(runtime), hashes, policy)
    if projected["unresolved"]:
        fail("file hierarchy has unresolved destinations")
    reduced = reduce_servicing_file_declarations(projected["records"], prepare_servicing_unprojected_files(resolved, hashes, policy))
    files = preprocess_servicing_file_declarations(reduced)
    directories = preprocess_servicing_directory_declarations(reduce_servicing_directory_declarations(resolve_servicing_directory_paths(analyze_servicing_directories(runtime, "amd64"), roots)))
    return dict(hierarchy=preprocess_servicing_path_hierarchy(directories, files), sources=reduced["sources"], policy=policy, collision_policy=servicing_filemap_collision_policy(software, components))


def _map_identity(identity):
    if identity == None:
        return None
    d = windows.csi_identity(identity)
    attrs = [("", "name", d.name), ("", "version", d.version), ("", "processorArchitecture", d.processor_architecture), ("", "publicKeyToken", d.public_key_token)]
    if d.language and d.language != "neutral":
        attrs.append(("", "culture", d.language))
    if d.type:
        attrs.append(("", "type", d.type))
    if d.version_scope:
        attrs.append(("", "versionScope", d.version_scope))
    return attrs


def _map_nodes(node, hierarchy):
    result = []
    if not node["implicit"]:
        result.append(dict(name=".", operation=node["operation"], state=node["after"]["state"], directory_flags=node["directory_flags"], file_flags=0, before_identity=_map_identity(node["before"]["identity"]), after_identity=_map_identity(node["after"]["identity"])))
    for path in node["children"]:
        child = hierarchy[path]
        if child["kind"] != "file":
            continue
        result.append(dict(name=path.rsplit("/", 1)[1], operation=child["operation"], state=child["after"]["state"], directory_flags=child["directory_flags"], file_flags=child["file_flags"], before_identity=_map_identity(child["before"].get("component_identity")), after_identity=_map_identity(child["after"].get("component_identity"))))
    return result


def plan_update_filemaps(root, prepared, volume="C:"):
    """Plan the complete LUA pass against unchanged baseline maps.

    The caller must complete the preliminary boot-critical file pass first.
    Only its already-state-2 immutable shape is supported here; accepting a
    writable/link state without the real pass would manufacture post-pass state.
    Directory collisions retain resident ownership and obey the actual hive's
    native strict-directory policy. Any file-owner conflict fails before writes.
    """
    hierarchy = prepared["hierarchy"]
    for path in select_servicing_file_commit_paths(hierarchy, 1):
        if hierarchy[path]["after"]["state"] != 2:
            fail("FileMaps require an unimplemented preliminary file transition: " + path)
    names = {p.lower():p for p in root.files}
    plans = []
    collisions = 0
    for depth,path in sorted([(p.count("/"), p) for p in hierarchy]):
        node = hierarchy[path]
        if node["kind"] != "directory":
            continue
        nodes = _map_nodes(node, hierarchy)
        # FileInfo interning deliberately ignores nonSxS component versions.
        # Consequently identical bytes/security can leave the file subtree
        # clean while its exact FileMap owner changes. Do not turn that into
        # payload work: the map pass has its own ownership dirty predicate.
        ownership_changed = any([n["before_identity"] != n["after_identity"] for n in nodes])
        if not node["subtree_changed"] and not ownership_changed:
            continue
        target = "/Windows/WinSxS/FileMaps/" + windows.cdf_filemap_name(path)
        actual = names.get(target.lower(), target)
        file = root.find(actual)
        resident = windows.cdf_filemap(file.bytes()) if file != None else None
        if not node["subtree_changed"]:
            # A clean directory can still be owned by an older component
            # incarnation, not the selected before winner. Version alone does
            # not authorize taking that resident directory ownership.
            dot = [e for e in resident["entries"] if e["name"] == "."] if resident != None else []
            resident_owner = resident["identities"][dot[0]["identity"]] if dot else None
            def same_owner(a, b):
                return a != None and b != None and sorted([(ns.lower(), k.lower(), v.lower()) for ns,k,v in a]) == sorted([(ns.lower(), k.lower(), v.lower()) for ns,k,v in b])
            if not any([n["before_identity"] != n["after_identity"] and (n["name"] != "." or same_owner(n["before_identity"], resident_owner)) for n in nodes]):
                continue
        plan = plan_servicing_filemap(resident, nodes, path, volume)
        plan.update(path=actual, directory=path, before=None if file == None else digest(file, algorithm="sha256"))
        collisions += len(plan["directory_collisions"])
        plans.append(plan)
    status = servicing_filemap_collision_status(prepared["collision_policy"], 0, collisions)
    if status:
        fail("native FileMap collision policy rejected construction: " + hex(status))
    return dict(plans=plans, directory_collisions=collisions)


def _map_logical(document):
    # Native serialization may reorder hash-table entries and prune/reindex
    # identities. Compare resolved ownership rather than physical array IDs.
    return (document["path"], document["root_selector"], {entry["name"]: (entry["display_name"], entry["flags"], sorted(document["identities"][entry["identity"]])) for entry in document["entries"]})


def apply_update_filemaps(root, planned, security):
    """Apply a validated LUA plan with explicit final map descriptors.

    Security is keyed by the plan's exact output path; it must come from the
    native security constructor, not default filesystem inheritance. The entire
    plan's source digests and descriptors are checked before any mutation.
    This does not apply the final file/directory pass or commit package state.
    """
    for plan in planned["plans"]:
        file = root.find(plan["path"])
        before = None if file == None else digest(file, algorithm="sha256")
        if before != plan["before"]:
            fail("FileMap plan baseline changed: " + plan["path"])
        if plan["operation"] == "write":
            descriptor = security.get(plan["path"])
            if descriptor == None:
                fail("FileMap final security is missing: " + plan["path"])
            windows.security_descriptor_parts(descriptor)
            if _map_logical(windows.cdf_filemap(plan["content"])) != _map_logical(plan["document"]):
                fail("encoded FileMap disagrees with resolved ownership")
        elif plan["operation"] not in ["remove", "none"]:
            fail("unsupported FileMap operation")
    counts = dict(writes=0, removals=0, retained_directory_owners=planned["directory_collisions"])
    for plan in planned["plans"]:
        if plan["operation"] == "write":
            root.write(plan["path"], plan["content"])
            root.set_security(plan["path"], security[plan["path"]])
            if _map_logical(windows.cdf_filemap(root.find(plan["path"]).bytes())) != _map_logical(plan["document"]) or root.get_security(plan["path"]) != security[plan["path"]]:
                fail("serialized FileMap or security mismatch")
            counts["writes"] += 1
        elif plan["operation"] == "remove":
            root.remove(plan["path"])
            if root.find(plan["path"]) != None:
                fail("FileMap removal did not persist")
            counts["removals"] += 1
    return counts
