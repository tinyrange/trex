"""Apply the final native driver's file objects, not content-only copies.

Requires closed native file/mapping references and no pending deletions. Native
hive writes are verified against the mount provider's already-built backing
files. Unknown target paths, missing final file security and unobserved directory
creation policy fail before changing the image.
"""

load("@stdlib//windows/servicing:file_commit.star", "image_path_names")
load("@stdlib//windows/servicing:runtime.star", "build_servicing_created_security")


def _driver_path(path, authorized = {}):
    path = path.replace(chr(92), "/")
    if not path.lower().startswith("d:/windows/"):
        fail("native driver effect is outside the explicit offline Windows volume")
    parts = path[2:].split("/")
    if any([not p or p in [".", ".."] or ":" in p or chr(0) in p for p in parts[1:]]):
        fail("invalid native driver effect path")
    result = path[2:]
    lower = result.lower()
    if lower.startswith("/windows/system32/config/"):
        if lower not in ["/windows/system32/config/"+n for n in ["system","software","drivers"]]:
            fail("unmodeled native driver hive effect")
    elif not any([lower.startswith(p) for p in ["/windows/inf/", "/windows/winsxs/", "/windows/system32/driverstore/filerepository/"]]):
        if lower not in authorized:
            fail("unmodeled persistent native driver file effect: " + result)
    return result


def _entry_source(entry):
    return entry["data"] if "data" in entry else entry["source"]


def _file_metadata(entry):
    return (entry["security"], entry.get("attributes",0x80) & ~0x80, entry.get("creation_time",0), entry.get("write_time",0), entry.get("access_time",0), entry.get("extended_attributes",[]))


def _driver_guard(root,path):
    file = root.find(path)
    if file == None:
        return None
    m = root.get_metadata(path)
    return (digest(file),root.get_security(path),m.creation_time,m.last_write_time,m.last_access_time,m.file_attributes,m.has_file_attributes,m.hard_link_id,m.extended_attributes)


def plan_update_driver_file_effects(root, report, initial_entries, kernel, authorized = {}):
    """Plan native file-object publication only after handles, views and pending deletes are closed; return guarded file/directory effects."""
    state = kernel.state
    if state["views"] or state["pending_file_deletes"] or any([type(h)=="dict" and h.get("kind") in ["file","mapping"] for h in state["handles"].values()]):
        fail("native driver file effects still have live references or deletions")
    names = image_path_names(root)
    directories = []
    files = {}
    verified_hives = []
    guards = {}
    generated = report["generated_entries"]
    security = {}
    ea_check = directory()
    ea_check.write("/check", b"")
    for native, entry in sorted(generated.items(),key=lambda item:(item[0].count(chr(92)),item[0])):
        declared = _driver_path(native, authorized)
        ea_check.set_extended_attributes("/check",entry.get("extended_attributes",[]))
        attributes = entry.get("attributes",0x10 if entry["directory"] else 0x80)
        if type(attributes)!="int" or attributes<0 or attributes & ~(0x31a7 | (0x10 if entry["directory"] else 0)):
            fail("unsupported native driver file attributes")
        for field in ["creation_time","write_time","access_time"]:
            value = entry.get(field,0)
            if type(value)!="int" or value<0 or value>0xffffffffffffffff:
                fail("invalid native driver file time")
        parent = declared.rsplit("/",1)[0]
        actual_parent = names.get(parent.lower())
        if actual_parent == None:
            fail("native driver effect has no actual parent")
        path = names.get(declared.lower(),actual_parent+"/"+declared.rsplit("/",1)[1])
        names[declared.lower()] = path
        if entry["directory"]:
            prior = testing.attempt(root.get_security,args=[path])
            descriptor = entry.get("security")
            if descriptor == None and prior.ok:
                descriptor = prior.value
            if descriptor == None:
                observed = [q for q in report["file_queries"] if q["api"] in ["createdirectoryw","createdirectorya"] and q["path"]==native]
                if len(observed)!=1 or observed[0].get("security_attributes") != False:
                    fail("native driver directory creation security is unestablished")
                ancestor = security.get(actual_parent)
                if ancestor == None:
                    ancestor = root.get_security(actual_parent)
                descriptor = build_servicing_created_security(ancestor,directory=True)
            if descriptor == None:
                fail("native driver directory has no final security")
            windows.security_descriptor_parts(descriptor)
            directories.append(dict(path=path,security=descriptor,existed=prior.ok,prior=prior.value if prior.ok else None,entry=entry))
            security[path] = descriptor
            continue
        current = root.find(path)
        if declared.lower().startswith("/windows/system32/config/"):
            if current==None or digest(current)!=digest(entry["data"]):
                fail("native driver backing hive was not actually committed")
            verified_hives.append(path)
            guards[path] = _driver_guard(root,path)
            continue
        if entry.get("security") == None:
            fail("native driver file has no final security")
        windows.security_descriptor_parts(entry["security"])
        qualification = authorized.get(declared.lower())
        if qualification != None:
            prior_hash = digest(current,algorithm='sha256') if current != None else None
            if qualification.get('directory',False) or qualification['prior_sha256'] != prior_hash or qualification['sha256'] != digest(entry['data'],algorithm='sha256'):
                fail('native driver destination qualification changed: ' + path)
        if native in initial_entries:
            original = initial_entries[native]
            _check_driver_initial(root,path,original)
        elif current!=None:
            if qualification == None:
                fail("native driver created file collides with the actual image: " + path)
        if current==None and testing.attempt(root.get_security,args=[path]).ok:
            fail("native driver file collides with an image directory")
        files[native] = dict(path=path,entry=entry)
        guards[path] = _driver_guard(root,path)
    removed = []
    for native, initial in initial_entries.items():
        if native in state["paths"] or not native.startswith("d:"):
            continue
        declared = _driver_path(native, authorized)
        path = names.get(declared.lower())
        if initial["directory"]:
            fail("native driver directory deletion needs a separate empty-tree proof")
        current = root.find(path) if path!=None else None
        if current==None:
            fail("native driver deleted source changed after execution")
        _check_driver_initial(root,path,initial)
        guards[path] = _driver_guard(root,path)
        removed.append(path)
    for native, item in files.items():
        entry = item["entry"]
        target = entry.get("hardlink_to")
        if target == None:
            continue
        canonical = files.get(target)
        if canonical==None or canonical["entry"].get("hardlink_to")!=None or digest(entry["data"])!=digest(canonical["entry"]["data"]) or _file_metadata(entry)!=_file_metadata(canonical["entry"]):
            fail("native driver hard-link object metadata disagrees")
        item["link"] = canonical["path"]
    return dict(directories=directories,files=files,removed=removed,guards=guards,verified_hives=verified_hives)


def apply_update_driver_file_effects(root, plan):
    """Recheck all native file-plan guards, then publish files, metadata, links and deletions to root; return effect counts."""
    for path, expected in plan["guards"].items():
        if _driver_guard(root,path)!=expected:
            fail("native driver file baseline changed before commit")
    for item in plan["directories"]:
        prior = testing.attempt(root.get_security,args=[item["path"]])
        if prior.ok!=item["existed"] or prior.ok and prior.value!=item["prior"]:
            fail("native driver directory baseline changed before commit")
    for item in plan["directories"]:
        if not item["existed"]:
            root.mkdir(item["path"])
        root.set_security(item["path"],item["security"])
        entry = item["entry"]
        if "attributes" in entry:
            root.set_file_attributes(item["path"],entry["attributes"] & ~0x10)
        if any([field in entry for field in ["creation_time","write_time","access_time"]]):
            root.set_times(item["path"],entry.get("creation_time",0),entry.get("write_time",0),entry.get("access_time",0))
        if "extended_attributes" in entry:
            root.set_extended_attributes(item["path"],entry["extended_attributes"])
    for item in plan["files"].values():
        if "link" in item:
            continue
        path, entry = item["path"],item["entry"]
        if root.find(path)!=None:
            root.remove(path)
        root.write(path,entry["data"])
        root.set_security(path,entry["security"])
        root.set_file_attributes(path,entry.get("attributes",0x80))
        root.set_times(path,entry.get("creation_time",0),entry.get("write_time",0),entry.get("access_time",0))
        root.set_extended_attributes(path,entry.get("extended_attributes",[]))
    for item in plan["files"].values():
        if "link" in item:
            root.hardlink(item["link"],item["path"])
    for path in plan["removed"]:
        root.remove(path)
    for item in plan["directories"]:
        if root.get_security(item["path"])!=item["security"]:
            fail("native driver directory effect readback disagrees")
    counts = dict(files=0,hardlinks=0,removed=len(plan["removed"]),directories=len(plan["directories"]),verified_hives=len(plan["verified_hives"]))
    for item in plan["files"].values():
        path, entry = item["path"],item["entry"]
        metadata = root.get_metadata(path)
        actual = (root.get_security(path),metadata.file_attributes,metadata.creation_time,metadata.last_write_time,metadata.last_access_time,metadata.extended_attributes)
        if digest(root.find(path))!=digest(entry["data"]) or actual!=_file_metadata(entry):
            fail("native driver file effect readback disagrees")
        if "link" in item:
            if not metadata.hard_link_id or metadata.hard_link_id!=root.get_metadata(item["link"]).hard_link_id:
                fail("native driver hard-link identity was not constructed")
            counts["hardlinks"] += 1
        else:
            counts["files"] += 1
    return counts


def _check_driver_initial(root, path, original):
    current = root.find(path)
    if current == None or original["directory"] or digest(current) != digest(_entry_source(original)):
        fail("native driver source changed after execution")
    metadata = root.get_metadata(path)
    expected = {
        "security": root.get_security(path),
        "attributes": metadata.file_attributes,
        "creation_time": metadata.creation_time,
        "write_time": metadata.last_write_time,
        "access_time": metadata.last_access_time,
        "extended_attributes": metadata.extended_attributes,
    }
    for field, value in expected.items():
        if field in original and original[field] != value:
            fail("native driver source metadata changed after execution: " + field)


def prepare_update_driver_transaction(root, report, initial_entries, kernel, hive_root, mount, authorized = {}):
    """Return a fully verified independent tree; never partially publish effects.

    The native mount provider must have closed every hive epoch. Its independently
    committed backing hives and the final kernel file objects describe one native
    execution. Callers publish only the returned root after this function succeeds.
    """
    if any([mount.state[field] for field in ["mounts", "pending", "epochs"]]):
        fail("native driver transaction still has mounted hive epochs")
    candidate = root.clone()
    for name in ["SYSTEM", "SOFTWARE", "DRIVERS"]:
        path = "/Windows/System32/config/" + name
        native = ("D:" + path).replace("/", chr(92)).lower()
        original = initial_entries.get(native)
        if original == None:
            fail("native driver transaction lacks its original hive source")
        _check_driver_initial(root, path, original)
        backing = hive_root.find(path)
        generated = report["generated_entries"].get(native)
        if backing == None:
            fail("native driver transaction lacks a committed backing hive")
        windows.hive(backing)
        if generated == None:
            if digest(backing) != digest(_entry_source(original)):
                fail("changed native hive lacks a final kernel file object")
        elif generated["directory"] or digest(backing) != digest(generated["data"]):
            fail("native driver hive and final file object disagree")
        candidate.write(path, backing)
    plan = plan_update_driver_file_effects(candidate, report, initial_entries, kernel, authorized=authorized)
    counts = apply_update_driver_file_effects(candidate, plan)
    return dict(root=candidate, counts=counts)


def collect_update_driver_entries(kernel):
    """Snapshot changed native file entries and link targets from the supplied kernel state."""
    output = {}
    link_targets = {}
    for path, entry in sorted(kernel.state["paths"].items()):
        if entry.get("initial", False) and not entry.get("dirty", False):
            continue
        value = {"directory": entry.get("directory", False)}
        if not value["directory"]:
            value["data"] = kernel.state["file_data"](entry)
            identity = entry.get("file_id")
            if identity != None:
                if identity in link_targets:
                    value["hardlink_to"] = link_targets[identity]
                else:
                    link_targets[identity] = path
        for key in ["security", "attributes", "creation_time", "access_time", "write_time", "extended_attributes"]:
            if key in entry:
                value[key] = [dict(ea) for ea in entry[key]] if key == "extended_attributes" else entry[key]
        output[path] = value
    return output
