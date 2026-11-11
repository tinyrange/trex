"""Apply bounded native CSI file effects, never package lifecycle shortcuts.

Inputs are the full hierarchy and already-staged, hash-qualified WinSxS sources.
Planning reads the image but does not modify it. It rejects absent source
security instead of silently preserving the destination's old WIM descriptor.
"""

load("@stdlib//windows/servicing:runtime.star", "build_servicing_created_security", "build_servicing_directory_security_request", "assign_servicing_directory_security", "build_servicing_file_security_request", "assign_servicing_file_security", "build_servicing_immutable_file_security_request", "select_servicing_writable_file_action", "select_servicing_file_commit_paths")


def image_path_names(root, mutable=True):
    """Return the case-folded file-derived namespace, excluding empty directories; mutable=False requests a read-only index."""
    # Preserve the file-derived namespace used by the planner, without decoding
    # payloads or repeatedly synthesizing every ancestor in the interpreter.
    if not mutable:
        return root.path_index(lower=True, include_empty=False)
    return root.path_names(lower=True, include_empty=False)


def plan_update_directories(root, prepared):
    """Construct effective ancestor security before any file/map mutation.

    Directory child-enumeration propagation must be disabled by actual native
    configuration. Missing implicit ancestors use the bounded SYSTEM creation
    policy, not WRP permissions copied from a nearby directory.
    """
    if prepared["policy"]["enumerate_children"]:
        fail("directory child-security propagation is not implemented")
    hierarchy = prepared["hierarchy"]
    names = image_path_names(root)
    security = {}
    changes = []
    needed = {}
    for depth, path in sorted([(p.count("/"), p) for p in hierarchy], reverse=True):
        node = hierarchy[path]
        needed[path] = (node["kind"] == "file" and node["operation"] in [1, 3] and node["after"]["state"] != 0) or (node["kind"] == "directory" and not node["implicit"] and node["after"]["state"] != 0) or any([needed[p] for p in node["children"]])
    for depth, path in sorted([(p.count("/"), p) for p in hierarchy]):
        node = hierarchy[path]
        if node["kind"] != "directory":
            continue
        parent = path.rsplit("/", 1)[0] or "/"
        preferred = node.get("destination", path)
        destination = names.get(path, names.get(parent, parent).rstrip("/") + "/" + preferred.rsplit("/", 1)[1])
        if path == "/":
            destination = "/"
        observed = testing.attempt(root.get_security, args=[destination])
        exists = observed.ok
        current = observed.value if exists else None
        if exists and current == None:
            fail("directory has unspecified security: " + destination)
        if not exists and (not needed[path] or not node["subtree_changed"]):
            continue
        parent = path.rsplit("/", 1)[0] or "/"
        ancestor = security[parent] if path != "/" else None
        if not exists:
            if not node["subtree_changed"]:
                # A clean missing declared directory is not installed by this
                # transaction. It cannot supply a real ancestor for a child.
                continue
            current = build_servicing_created_security(ancestor, directory=True)
        result = current
        if not node["implicit"] and node["own_changed"] and node["after"]["state"] == 4 and not node["security_flags"] & 8:
            definition = node["after"]["descriptor"]
            request = build_servicing_directory_security_request(None if definition == None else windows.compile_sddl(definition["sddl"]), ancestor, default=definition == None)
            result = assign_servicing_directory_security(current, request)
        security[path] = result
        names[path] = destination
        if not exists or result != current:
            changes.append(dict(path=destination, key=path, create=not exists, before=None if not exists else current, security=result))
    return dict(changes=changes, security=security, names=names)


def _source_digest(expected, path):
    if expected == None or expected["digest_method"] != 2 or expected["transform"] != 1 or type(expected["digest"]) != "bytes" or len(expected["digest"]) != 32:
        fail("unsupported exact runtime source hash: " + path)
    return expected["digest"]

def _source_hash(source, expected, path):
    if digest(source, algorithm="sha256") != _source_digest(expected, path):
        fail("runtime source hash mismatch: " + path)


def plan_update_file_commits(root, prepared, source_paths, directories, while_verifying=None, audit_payloads=False):
    """Plan all dirty primary/link/removal effects against unchanged paths.

    source_paths maps the native FileInfo key to its exact staged store path.
    Validate source metadata, security, link prerequisites and writable
    decisions before any mutation. Exhaustive byte verification is opt-in. User-modified writable files preserve bytes
    AND metadata. Old-only immutable projections are unlinked without hashing.
    """
    hierarchy = prepared["hierarchy"]
    names = directories["names"]
    plans = []
    sources = {}
    source_checks = {}
    source_versions = {}
    pending_names = {}
    for path in select_servicing_file_commit_paths(hierarchy, 0):
        item = hierarchy[path]
        after = item["after"]
        parent = path.rsplit("/", 1)[0] or "/"
        actual = names.get(path, names.get(parent, parent).rstrip("/") + "/" + item["destination"].rsplit("/", 1)[1])
        current = root.find(actual)
        plan = dict(path=actual, key=path, phase=1 if item["directory_flags"] & 0x10 else 2, attributes=None, security=None)
        if item["operation"] == 2:
            before = item["before"]
            shape = (before["state"], before.get("process_flags"), item["file_flags"])
            if after["state"] != 0 or shape not in [(0, 0x40, 1), (0, 0x48, 1), (7, 0x50, 5)]:
                fail("unsupported removed runtime file: " + actual)
            writable = before["process_flags"] == 0x48
            if bool(item["directory_flags"] & 0x40) != writable:
                fail("inconsistent removed runtime writable flag: " + actual)
            plan.update(operation="pending_delete" if writable else "remove", exists=current != None)
            if writable:
                # WCP CommitFileChanges calls MoveFileToPendingDeletes(false):
                # move the actual object, including modified bytes, without a
                # hash comparison or immediate deletion. Never convert this
                # into an ordinary unlink or retain it at its retired path.
                plan["write_order"] = root.get_metadata(actual).write_order if current != None else None
                if current != None:
                    pending = "/Windows/WinSxS/Temp/PendingDeletes"
                    entries = testing.attempt(root.list_dir, args=[pending])
                    if not entries.ok or root.get_security(pending) == None:
                        fail("pending-delete directory/security is missing")
                    occupied = {name.rsplit("/", 1)[1].lower(): True for name in entries.value}
                    leaf = actual.rsplit("/", 1)[1]
                    # Native uses 128 bits of uniqueness + '.' + file name.
                    # Use stable, collision-checked uniqueness for image builds;
                    # the random native value is not a servicing identity.
                    target = None
                    for attempt in range(1024):
                        name = binary.hex(digest(actual.lower() + ":" + str(plan["write_order"]) + ":" + str(attempt)))[:32] + "." + leaf
                        if name.lower() not in occupied and name.lower() not in pending_names:
                            target = pending + "/" + name
                            pending_names[name.lower()] = True
                            break
                    if target == None:
                        fail("pending-delete name space exhausted")
                    plan.update(pending=target, pending_security=root.get_security(pending))
            plans.append(plan)
            continue
        if after["state"] not in [1, 2, 7]:
            fail("unsupported runtime file state: " + actual)
        source_key = after["source_key"]
        primary = prepared["sources"].get(source_key, {}).get("after")
        source_path = source_paths.get(source_key)
        if primary == None or primary["component_identity"] != after["component_identity"] or source_path == None:
            fail("missing exact primary source: " + actual)
        source_path = names.get(source_path.lower(), source_path)
        source = root.find(source_path)
        if source == None:
            fail("staged runtime source is missing: " + source_path)
        if source_key not in sources:
            expected = _source_digest(primary["hash"], source_path)
            if source_path in source_checks and source_checks[source_path] != expected:
                fail("conflicting runtime source digests: " + source_path)
            source_checks[source_path] = expected
            source_versions[source_path] = root.get_metadata(source_path).write_order
            if root.get_security(source_path) == None:
                fail("staged runtime source has unspecified security: " + source_path)
            sources[source_key] = source_path
        plan.update(source=source_path, source_hash=primary["hash"]["digest"], exists=current != None)
        parent = path.rsplit("/", 1)[0] or "/"
        parent_security = directories["security"].get(parent)
        if parent_security == None:
            fail("runtime destination parent is missing: " + actual)
        if after["state"] == 2:
            request = build_servicing_immutable_file_security_request(item, parent_security)
            plan.update(operation="hardlink", security=assign_servicing_file_security(root.get_security(source_path), request))
            if after["attributes"] != 0xa0:
                plan["attributes"] = after["attributes"]
        elif after["state"] == 7:
            if after.get("process_flags") != 0x50 or (item["operation"], item["file_flags"]) not in [(1, 2), (3, 7)]:
                fail("unsupported extra runtime hardlink: " + actual)
            plan["operation"] = "hardlink"
        else:
            action = select_servicing_writable_file_action(item, prepared["sources"], current)
            plan.update(operation="copy" if action == "replace" else "preserve", before=digest(current, algorithm="sha256") if current != None else None)
            if action == "replace":
                definition = after["descriptor"]
                if definition == None:
                    fail("writable runtime security requires explicit selection")
                created = build_servicing_created_security(parent_security)
                request = build_servicing_file_security_request(windows.compile_sddl(definition["sddl"]), parent_security)
                plan.update(security=assign_servicing_file_security(created, request), attributes=after["attributes"])
        plans.append(plan)
    if audit_payloads:
        # Read every distinct source before any image mutation. Native workers
        # overlap independent decompression; aliases do not rehash the same file.
        started = clock.monotonic()
        # Verification order is not commit order. Keep every source and digest,
        # but finish with native runtime and declared boot-critical sources so
        # the bounded cache is not handed to the guest full of WOW64 tail files.
        priority = {}
        for plan in plans:
            if "source" not in plan:
                continue
            rank = 2 if plan["phase"] == 1 else (1 if plan["path"].lower().startswith("/windows/system32/") else 0)
            priority[plan["source"]] = max(priority.get(plan["source"], 0), rank)
        checked_paths = [path for rank in [0, 1, 2] for path in source_checks if priority.get(path, 0) == rank]
        tier_counts, tier_bytes = [0, 0, 0], [0, 0, 0]
        for path in checked_paths:
            rank = priority.get(path, 0)
            tier_counts[rank] += 1
            tier_bytes[rank] += root.find(path).size
        print("runtime verification tiers", tier_counts, tier_bytes)
        print("runtime source verification begin", len(checked_paths))
        inputs = [root.find(p) for p in checked_paths]
        hashes = digest_many(inputs, workers=8, while_running=while_verifying) if while_verifying != None else digest_many(inputs, workers=8)
        for path, actual in zip(checked_paths, hashes):
            if actual != source_checks[path]:
                fail("runtime source hash mismatch: " + path)
        print("runtime sources verified", len(checked_paths), "elapsed", clock.monotonic()-started)
    elif while_verifying != None:
        # Required read-only planning still runs once, without an eager sweep.
        while_verifying()
    # Shared objects cannot receive two contradictory final descriptors.
    descriptors = {}
    for plan in plans:
        if plan["operation"] == "hardlink" and plan["security"] != None:
            source = plan["source"]
            if source in descriptors and descriptors[source] != plan["security"]:
                fail("runtime aliases require conflicting source security: " + source)
            descriptors[source] = plan["security"]
    return dict(plans=plans, source_security=descriptors, source_versions=source_versions, audit_payloads=audit_payloads)


def apply_update_directories(root, planned):
    """Preflight directory existence/security before creating directories and applying planned descriptors; return effect counts."""
    for change in planned["changes"]:
        existing = testing.attempt(root.get_security, args=[change["path"]])
        if existing.ok != (not change["create"]) or (existing.ok and existing.value != change["before"]):
            fail("directory plan baseline changed: " + change["path"])
    for change in planned["changes"]:
        if change["create"]:
            root.mkdir(change["path"])
        root.set_security(change["path"], change["security"])
        if root.get_security(change["path"]) != change["security"]:
            fail("directory security readback mismatch")
    return dict(created=len([p for p in planned["changes"] if p["create"]]), security_writes=len(planned["changes"]))


def apply_update_file_commits(root, planned, phase):
    """Apply one native pass: 1 before LUA maps, 2 after LUA maps.

    The caller preserves the hierarchy's directory-security and LUA ordering.
    This applies portable object effects; it neither completes driver queues nor
    advances CBS package/component lifecycle or pretends to execute a session.
    """
    if phase not in [1, 2]:
        fail("unsupported file commit phase")
    selected = [p for p in planned["plans"] if p["phase"] == phase]
    # Check payload stability and mutable projections before unlinking anything.
    sources = {}
    for plan in selected:
        if plan["operation"] not in ["remove", "pending_delete", "preserve"]:
            path = plan["source"]
            if path in sources and sources[path] != plan["source_hash"]:
                fail("conflicting runtime source digests: " + path)
            sources[path] = plan["source_hash"]
    paths = list(sources)
    # Detect path replacement without touching immutable payload readers.
    # This is not a claim that unread bytes have been verified.
    for path in paths:
        current = testing.attempt(root.get_metadata, args=[path])
        if not current.ok or current.value.write_order != planned["source_versions"][path]:
            fail("runtime source changed after planning: " + path)
    if planned["audit_payloads"]:
        for path, actual in zip(paths, digest_many([root.find(p) for p in paths], workers=4)):
            if actual != sources[path]:
                fail("runtime source changed after planning: " + path)
    for plan in selected:
        if plan["operation"] in ["copy", "preserve"] and (digest(root.find(plan["path"]), algorithm="sha256") if root.find(plan["path"]) != None else None) != plan["before"]:
            fail("writable projection changed after planning: " + plan["path"])
    for plan in selected:
        if plan["operation"] != "pending_delete":
            continue
        current = root.find(plan["path"])
        if (current != None) != plan["exists"] or (current != None and root.get_metadata(plan["path"]).write_order != plan["write_order"]):
            fail("pending-delete source changed after planning: " + plan["path"])
        if current != None:
            pending = plan["pending"].rsplit("/", 1)[0]
            if root.get_security(pending) != plan["pending_security"] or plan["pending"].rsplit("/", 1)[1].lower() in [n.rsplit("/", 1)[1].lower() for n in root.list_dir(pending)]:
                fail("pending-delete destination changed after planning")
    counts = dict(hardlinks=0, copies=0, preserved_writable=0, removed=0, already_absent=0)
    for plan in selected:
        path = plan["path"]
        operation = plan["operation"]
        if operation == "preserve":
            counts["preserved_writable"] += 1
            continue
        existing = root.find(path)
        if operation == "pending_delete":
            if existing != None:
                # Link before unlink preserves bytes, security, timestamps, EAs
                # and other aliases. The temporary object remains for Windows
                # cleanup; no CBS/POQ completion is inferred here.
                root.hardlink(path, plan["pending"])
                root.remove(path)
            counts["removed" if existing != None else "already_absent"] += 1
            continue
        if existing != None:
            root.remove(path)
        if operation == "remove":
            counts["removed" if existing != None else "already_absent"] += 1
            continue
        if operation == "hardlink":
            root.hardlink(plan["source"], path)
            counts["hardlinks"] += 1
        else:
            root.write(path, root.find(plan["source"]))
            counts["copies"] += 1
        if plan["attributes"] != None:
            root.set_file_attributes(path, plan["attributes"])
        if plan["security"] != None:
            root.set_security(path, plan["security"])
        if operation == "hardlink":
            identity = root.get_metadata(path).hard_link_id
            if not identity or identity != root.get_metadata(plan["source"]).hard_link_id:
                fail("runtime link is not the exact store object: " + path)
        if plan["security"] != None and root.get_security(path) != plan["security"]:
            fail("runtime security readback mismatch: " + path)
    return counts
