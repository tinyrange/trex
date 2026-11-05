"""Native ordinary registry planning, separate from hive publication.

A complete before/after contribution inventory is required even when only a
small subtree changes. Provider disposition and security assignment happen
later against the actual candidate hives, never against a declaration count.
"""

load("@stdlib//windows/servicing:runtime.star", "select_servicing_registry_key_commit", "build_servicing_registry_security_request", "select_servicing_registry_value_action", "select_servicing_paired_registry_multi_action")

load("@stdlib//windows/servicing:runtime.star", "reduce_servicing_registry_keys", "preprocess_servicing_registry_keys")


def prepare_update_registry_keys(runtime, groups, buckets, key_records, account_domain_sid=None):
    """Reduce exact admitted keys in family order, retaining separate profiles.

    `buckets` must come from the complete affected install-closure capacity.
    Equal-bucket contributions are allowed only when ordering cannot alter
    descriptor selection. The native reducer preserves first ownership and
    last nonempty security independently; dictionary iteration is not priority.
    """
    if sorted(buckets) != list(range(len(runtime["transitions"]))):
        fail("registry key planning requires every transition's family bucket")
    records = dict(system=[], user=[])
    tied = {}
    compiled = {}
    for index in sorted(buckets, key=lambda i: (buckets[i], i)):
        change = runtime["transitions"][index]
        for side, scope, path, attributes, text in key_records.get(index, []):
            identity = change["component_identities"][side]
            definition = None if text == None else dict(sddl=text)
            if text != None:
                if text == "(inherit)":
                    fail("registry inherit sentinel requires explicit selection")
                if text not in compiled:
                    compiled[text] = windows.compile_sddl(text, account_domain_sid=account_domain_sid)
                tie = (scope, path.lower(), side, buckets[index])
                previous = tied.get(tie)
                if previous != None and previous != (index, text) and previous[1] != text:
                    fail("registry descriptor priority has an unresolved family-bucket tie: " + path)
                tied[tie] = (index, text)
            records[scope].append(dict(path=path, scope=scope, side=side, identity=identity, descriptor=definition, key_attributes=attributes))
    changed = {}
    for (scope, path, name), (before, after) in groups.items():
        # This comparison excludes provenance only; raw type, bytes and value
        # policy attributes all participate, including empty multi semantics.
        if sorted([v[1:] for v in before]) != sorted([v[1:] for v in after]):
            changed[(scope, path)] = True
    result = {}
    for scope in ["system", "user"]:
        reduced = reduce_servicing_registry_keys(records[scope], scope=scope)
        value_changes = {path: changed.get((scope, path), False) for path, item in reduced.items() if item["explicit"]}
        result[scope] = preprocess_servicing_registry_keys(reduced, value_changes, compiled)
    for scope, path in changed:
        if path not in result.get(scope, {}) or not result[scope][path]["explicit"]:
            fail("registry value has no corresponding admitted key: " + path)
    return result




def _registry_route(path, control_set):
    parts = path.split(chr(92))
    if parts[:3] == ["", "registry", "machine"] and len(parts) >= 4:
        target, suffix = parts[3].upper(), parts[4:]
    elif parts[:4] == ["", "registry", "user", ".default"]:
        target, suffix = "DEFAULT", parts[4:]
    else:
        fail("registry key has no physical machine binding: " + path)
    if target not in ["SOFTWARE", "SYSTEM", "DEFAULT", "COMPONENTS", "SAM", "SECURITY"] or any([not p or chr(0) in p for p in suffix]):
        fail("unsupported physical registry path: " + path)
    if target == "SYSTEM" and suffix and suffix[0] == "currentcontrolset":
        suffix[0] = control_set
    return target, tuple(suffix)


def _registry_node(state, parts):
    if parts not in state["nodes"]:
        node = state["hive"].find(list(parts))
        state["nodes"][parts] = None if node == None else dict(
            security=node.security,
            children={child.name.lower(): True for child in node.children},
            values={("" if name == "(default)" else name.lower()): dict(type=value.type, raw=value.raw) for name,value in node.value_records.items()},
        )
    return state["nodes"][parts]


def _registry_value_selection(values, buckets):
    if not values:
        return None
    ordered = sorted(values, key=lambda v: (buckets[v[0]], v[0]))
    last = ordered[-1]
    for value in ordered:
        if buckets[value[0]] == buckets[last[0]] and value[1:] != last[1:]:
            fail("unresolved registry value family-bucket tie")
    return last


def _registry_value_bytes(value):
    if value == None:
        return None
    kind, raw = value[1:3]
    if kind in [1, 2, 7]:
        text = binary.text(raw, encoding="utf16le").replace("X:" + chr(92), "C:" + chr(92)).replace("x:" + chr(92), "c:" + chr(92))
        raw = binary.encode(text, encoding="utf16le")
    return dict(type=kind, raw=raw)


def _registry_multi_entries(value):
    if value == None:
        return []
    raw = value["raw"]
    if value["type"] != 7 or len(raw) < 4 or len(raw) % 2 or raw[-4:] != b"\x00\x00\x00\x00":
        fail("registry contribution requires canonical MULTI_SZ")
    text = binary.text(raw, encoding="utf16le")
    if binary.encode(text, encoding="utf16le") != raw:
        fail("registry contribution contains invalid UTF-16")
    return text[:-2].split(chr(0)) if text[:-2] else []


def _registry_set_security(state, parts, selected, default, deferred, created):
    node = _registry_node(state, parts)
    parent = _registry_node(state, parts[:-1]) if parts else None
    if not deferred and parent == None:
        fail("registry security requires an existing physical parent")
    if created:
        # Full assignment overwrites all creation fields except mandatory labels.
        # For the measured SYSTEM creation path, a parent without a label does
        # not create one. Do not substitute parent-copy ACLs for creation policy.
        sacl = windows.security_descriptor_parts(parent["security"])["sacl"]
        if sacl != None and any([e["type"] == 17 for e in windows.acl_entries(sacl)["entries"]]):
            fail("new registry key requires mandatory-label creation policy")
        current = windows.compile_sddl("O:SYG:SYD:")
    else:
        current = node["security"]
    request = build_servicing_registry_security_request(selected, parent=None if parent == None else parent["security"], default=default, defer_inheritance=deferred)
    assigned = windows.assign_registry_security(current, request["descriptor"], request["security_information"])
    node["security"] = assigned
    state["keys"][parts] = dict(key_parts=list(parts), security=assigned)


def plan_update_ordinary_registry(root, keys, groups, buckets, control_set):
    """Plan complete ordinary keys/values against the actual constructed image.

    No hive is published until every target passes native readback. Unchanged
    user-profile trees require no binding. Changed profiles, atomic mutable
    trees and nonempty retired-security cleanup fail closed, never get reported
    as completed. Literal key components are retained, including dot and slash.
    """
    if not control_set.startswith("controlset") or len(control_set) != 13 or not control_set[10:].isdigit():
        fail("registry requires an explicit selected control set")
    if any([k["subtree_changed"] for k in keys["user"].values()]):
        fail("changed per-user registry trees require explicit profile bindings")
    changed_values = {}
    for (scope,path,name), (before,after) in groups.items():
        if sorted([v[1:] for v in before]) != sorted([v[1:] for v in after]):
            if scope != "system":
                fail("changed per-user registry values require explicit profile bindings")
            changed_values.setdefault(path, []).append((name,before,after))
    states = {}
    queued = []
    report = dict(set_values=0, deleted_values=0, created_keys=0, removed_keys=0, security_keys=0, preserved_values=0)
    machine = keys["system"]
    for path in sorted(machine, key=lambda p: (p.count(chr(92)),p)):
        item = machine[path]
        decision = select_servicing_registry_key_commit(item["operation"],item["security_flags"],item["descriptor"],auxiliary_flags=item["auxiliary_flags"])
        if decision["action"] == "skip":
            if path in changed_values:
                fail("changed registry values were hidden by subtree skip")
            continue
        target, parts = _registry_route(path,control_set)
        if target not in states:
            hpath = "/Windows/System32/config/"+target
            source = root.find(hpath)
            if source == None:
                fail("missing physical registry hive: "+target)
            states[target] = dict(path=hpath, source=source, source_hash=digest(source), hive=windows.hive(source), nodes={}, keys={}, patches=[], deletes=[], removed={})
        state = states[target]
        node = _registry_node(state,parts)
        if decision["action"] == "open" and node == None:
            continue
        created = node == None
        if created:
            if not parts or _registry_node(state,parts[:-1]) == None:
                fail("registry creation encountered an unplanned missing parent: "+path)
            node = dict(security=None, children={}, values={})
            state["nodes"][parts] = node
            _registry_node(state,parts[:-1])["children"][parts[-1]] = True
            decision = select_servicing_registry_key_commit(item["operation"],item["security_flags"],item["descriptor"],created=True,auxiliary_flags=item["auxiliary_flags"])
            report["created_keys"] += 1
        if decision["security"] != "none":
            _registry_set_security(state, parts, item["descriptor"], decision["security"] == "default", decision["defer_inheritance"], created)
        elif created:
            fail("new registry key has no final security assignment")
        if decision["queue_empty_delete"]:
            queued.append((target,parts,item["old_descriptor"] != None))
        for name,before,after in changed_values.get(path,[]):
            old, new = _registry_value_selection(before,buckets), _registry_value_selection(after,buckets)
            selected = [v for v in [old,new] if v != None]
            if any([v[3] not in ["true","false"] or v[5] for v in selected]):
                fail("unsupported registry value policy: "+path)
            if len(selected)==2 and (old[3] != new[3] or old[4] != new[4]):
                fail("registry value policy changed across owners")
            mutable = selected[-1][3] == "true"
            prior, value = _registry_value_bytes(old), _registry_value_bytes(new)
            current = node["values"].get(name)
            if any([v[1]==7 for v in selected]):
                if any([len(side)>1 for side in [before,after]]):
                    fail("overlapping MULTI_SZ owners require contribution arbitration")
                hint = selected[-1][4] or "append"
                outcome = select_servicing_paired_registry_multi_action(_registry_multi_entries(prior),_registry_multi_entries(value),current,operation_hint=hint,mutable=mutable if old != None and new != None else False)
                action,value = outcome["action"],outcome.get("value")
            else:
                if any([v[4] for v in selected]):
                    fail("ordinary registry value has a nonordinary operation hint")
                action = select_servicing_registry_value_action(prior,value,current,mutable)
            if action == "set":
                state["patches"].append(dict(key_parts=list(parts),name=name,type=value["type"],value=value["raw"]))
                node["values"][name] = value
                report["set_values"] += 1
            elif action == "delete":
                state["deletes"].append(dict(key_parts=list(parts),name=name))
                node["values"].pop(name,None)
                report["deleted_values"] += 1
            elif action == "preserve":
                report["preserved_values"] += 1
            elif action != "none":
                fail("unsupported registry value action")
    # Reverse hierarchy order: real residual contents include undeclared keys
    # and values. A declaration disappearing does not justify recursive delete.
    for target,parts,had_security in reversed(queued):
        state = states[target]
        node = _registry_node(state,parts)
        if not node["children"] and not node["values"]:
            if not parts:
                fail("registry cleanup cannot delete a hive boundary")
            state["removed"][parts] = True
            state["nodes"][parts] = None
            _registry_node(state,parts[:-1])["children"].pop(parts[-1],None)
            report["removed_keys"] += 1
        elif had_security:
            fail("nonempty retired key requires configured default-security propagation: "+target+":"+repr(parts))
    plans = []
    for target,state in states.items():
        file = windows.hive_from_patches(target,state["patches"],source=state["source"],keys=list(state["keys"].values()),exclude_keys=[dict(key_parts=list(p)) for p in state["removed"]],exclude_values=state["deletes"])
        actual = windows.hive(file)
        for parts,expected in state["nodes"].items():
            found = actual.find(list(parts))
            if expected == None:
                if found != None:
                    fail("registry deletion readback disagrees")
                continue
            if found == None or found.security != expected["security"]:
                fail("registry security readback disagrees")
            values = {("" if name == "(default)" else name.lower()):dict(type=v.type,raw=v.raw) for name,v in found.value_records.items()}
            if values != expected["values"] or sorted([c.name.lower() for c in found.children]) != sorted(expected["children"]):
                fail("registry key contents readback disagrees")
        report["security_keys"] += len(state["keys"])
        plans.append(dict(target=target,path=state["path"],source_hash=state["source_hash"],file=file,values=len(state["patches"]),deleted_values=len(state["deletes"]),removed_keys=len(state["removed"])))
    return dict(plans=plans,report=report)
