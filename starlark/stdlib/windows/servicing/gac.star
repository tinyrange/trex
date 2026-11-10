"""Guarded refresh of existing legacy/CLR4 GAC assemblies from CSI declarations.

This is not Fusion registration or NGEN completion. New cache directories,
assembly identity changes and removals require their own installer phases and
are rejected. New companion files may be linked into an existing cache identity
only when absent and backed by an exact declared staged hash. No oracle paths, hashes or registry results enter this planner.
"""
load("@stdlib//windows/servicing:runtime.star", "servicing_runtime_manifest_root")
load("@stdlib//windows/servicing:runtime.star", "select_servicing_file_hash")
load("@stdlib//windows/servicing:registry_effects.star", "plan_update_registry_effects", "apply_update_registry_effects")

_NS = "urn:schemas-microsoft-com:asm.v3"

def _attrs(node):
    result = {}
    for a in node.attributes:
        if a["name"] == "xmlns" and a["namespace"] == "xmlns" and a["value"] == node.namespace:
            continue
        if a["namespace"] or a["name"] in result:
            fail("unsupported managed declaration attributes")
        result[a["name"]] = a["value"]
    return result

def _leaf(value):
    if not value or value in [".", ".."] or any([c in value for c in ["/", "\\", ":", "\x00"]]):
        fail("managed declaration requires a safe path leaf")
    return value

def _managed_declaration(document, change=None, side="after"):
    if 'gac' not in windows.assembly_manifest(document).file_elements: return None
    tree = servicing_runtime_manifest_root(change, side) if change!=None else binary.xml(document, discard_whitespace=True).root
    managed = []
    for node in tree.children:
        if node.namespace == _NS and node.name == "file":
            for child in node.children:
                if child.namespace == _NS and child.name == "gac":
                    if child.children:
                        fail("unsupported nested GAC declaration")
                    managed.append((_attrs(node), _attrs(child)))
    if not managed:
        return None
    if len(managed) != 1:
        fail("multiple GAC assemblies in one component require Fusion selection")
    manifest = windows.assembly_manifest(document)
    ids = [n for n in tree.children if n.namespace == _NS and n.name == "assemblyIdentity"]
    if len(ids) != 1:
        fail("managed component requires one identity")
    identity = _attrs(ids[0])
    file, gac = managed[0]
    if any([k not in ["clrversion", "clrarch", "fileCopy", "managedversion", "managedculture", "parameter"] for k in gac]):
        fail("unsupported GAC identity override")
    # The native GAC parser has no parameter identity field. Admit only the
    # empty/single-space annotation present in the serviced Server manifests;
    # do not turn arbitrary command text into silently ignored configuration.
    if gac.get("parameter", "") not in ["", " "]:
        fail("unsupported GAC parameters")
    copy = gac.get("fileCopy", "true")
    if copy not in ["true", "false"]:
        fail("unsupported GAC fileCopy value")
    clr_arch = gac.get("clrarch")
    if clr_arch != None and clr_arch not in ["amd64", "x86", "msil"]:
        fail("unsupported GAC CLR architecture")
    clr = gac.get("clrversion")
    if clr not in [None, "4.0"]:
        fail("unsupported GAC CLR version")
    version = gac.get("managedversion", "")
    if len(version.split(".")) != 4 or any([not p or not all([c in "0123456789" for c in p.elems()]) for p in version.split(".")]):
        fail("invalid managed version")
    culture = gac.get("managedculture", "")
    if culture:
        _leaf(culture)
    token = identity.get("publicKeyToken", "").lower()
    if len(token) != 16 or any([c not in "0123456789abcdef" for c in token.elems()]):
        fail("invalid managed public key token")
    architecture = {"amd64":"64", "wow64":"32", "x86":"32", "msil":"MSIL"}.get(clr_arch if clr_arch != None else identity.get("processorArchitecture", ""))
    if architecture == None:
        fail("unsupported managed component architecture")
    name = _leaf(file["name"])
    if not name.lower().endswith(".dll") and not name.lower().endswith(".exe"):
        fail("managed cache refresh requires a DLL or EXE assembly")
    assembly = _leaf(name[:-4])
    # No clrversion is the legacy Fusion store, not an implicit CLR4 request.
    # Only refresh already existing identities; never create/choose a cache.
    prefix = "/Windows/Microsoft.NET/assembly/GAC_" if clr == "4.0" else "/Windows/assembly/GAC_"
    version_prefix = "v4.0_" if clr == "4.0" else ""
    path = prefix + architecture + "/" + assembly + "/" + version_prefix + version + "_" + culture + "_" + token
    # Fusion caches the component's companion files as well as the marked DLL.
    files = {}
    for item in manifest.files:
        name = _leaf(item.name)
        if name.lower() in files:
            fail("duplicate managed companion file")
        files[name.lower()] = dict(name=name, hash=select_servicing_file_hash(item)["digest"])
    return dict(path=path, files=files, copy=copy == "true", assembly_file=_leaf(file["name"]), notification=identity["name"]+","+version+","+culture+","+token+","+{"64":"amd64","32":"x86","MSIL":"msil"}[architecture], architecture=architecture)

def plan_update_gac(root, runtime, component_stems, audit=True):
    """Plan Fusion cache refreshes with namespace guards and optional payload auditing.

    Non-audit mode does not verify baseline or source bytes. The caller must
    supply admitted sources; publication binds their captured write epochs.
    fileCopy=false requires pre-published content or the exact staged file
    object; shared hardlink identity avoids decoding the same object twice.
    """
    # CSI identity comparison is case-insensitive, including versionScope.
    # Keep the exact admitted stem; never derive a store path from an identity.
    stems = {}
    for identity, stem in component_stems.items():
        key = str(identity).lower()
        if key in stems and stems[key].lower() != stem.lower():
            fail("conflicting managed staged source identity")
        stems[key] = stem
    names = root.path_index(lower=True)
    plans = []
    destinations = {}
    for transition in runtime["transitions"]:
        before = _managed_declaration(transition["before"], transition, "before") if transition["before"] != None else None
        after = _managed_declaration(transition["after"], transition, "after") if transition["after"] != None else None
        if before == None and after == None:
            continue
        if before == None or after == None or before["path"].lower() != after["path"].lower():
            fail("GAC addition/removal or identity change requires Fusion lifecycle")
        if any([key not in after["files"] for key in before["files"]]):
            fail("GAC companion removal requires Fusion lifecycle")
        parent = names.get(after["path"].lower())
        if parent == None:
            fail("managed cache directory is absent")
        identity = transition["component_identities"]["after"]
        stem = stems.get(str(identity).lower())
        if stem == None:
            fail("managed component lacks exact staged source identity")
        _leaf(stem)
        for key, item in after["files"].items():
            destination = names.get((after["path"] + "/" + item["name"]).lower())
            source = names.get(("/Windows/WinSxS/" + stem + "/" + item["name"]).lower())
            added = key not in before["files"]
            if source == None or (destination == None and not added):
                fail("managed refresh requires existing cache and staged source files: " + str(identity) + "/" + item["name"])
            if added:
                if destination != None:
                    fail("new managed companion destination already exists")
                destination = parent + "/" + item["name"]
            if destination.lower() in destinations:
                fail("conflicting managed destination")
            destinations[destination.lower()] = True
            # Non-audit publication binds namespace epochs, not eager payload
            # reconstruction. fileCopy=false needs the exact staged object
            # or content proof: no replacement is published for that declaration.
            source_link = root.get_metadata(source).hard_link_id
            shared = not added and source_link != 0 and source_link == root.get_metadata(destination).hard_link_id
            verify = audit or (not after["copy"] and not shared)
            current = digest(root.find(destination), algorithm="sha256") if verify and not added else None
            if verify and not added and current not in [before["files"][key]["hash"], item["hash"]]:
                fail("managed cache content differs from declared baseline")
            if verify and digest(root.find(source), algorithm="sha256") != item["hash"]:
                fail("managed source hash mismatch")
            security = root.get_security(source)
            if security == None:
                fail("managed source has no security descriptor")
            windows.security_descriptor_parts(security)
            if not after["copy"] and (added or (not shared and current != item["hash"])):
                fail("GAC fileCopy=false requires pre-published cache files")
            plans.append(dict(added=added, audited=verify, shared=shared, copy=after["copy"], parent=parent, parent_order=root.get_metadata(parent).write_order, path=destination, source=source, before=current, after=item["hash"], security=security, source_order=root.get_metadata(source).write_order, destination_order=None if added else root.get_metadata(destination).write_order))
    return plans

def apply_update_gac(root, plans, audit=True):
    """Validate the full GAC batch before refreshing files; runtime Fusion/NGen validation is not implied."""
    # Validate the entire batch before unlinking any destination.
    for p in plans:
        source = root.find(p["source"])
        destination = root.find(p["path"])
        added = p.get("added", p["before"] == None)
        if audit and not p.get("audited", True):
            fail("managed refresh audit requires audited planning")
        if root.get_metadata(p["parent"]).write_order != p["parent_order"]:
            fail("managed cache directory changed after planning")
        if source == None or (destination == None and not added):
            fail("managed refresh path disappeared after planning")
        if added and destination != None:
            fail("new managed companion destination appeared after planning")
        if root.get_metadata(p["source"]).write_order != p["source_order"] or (not added and root.get_metadata(p["path"]).write_order != p["destination_order"]):
            fail("managed refresh path changed after planning")
        shared = p.get("shared", False)
        if shared and (not root.get_metadata(p["source"]).hard_link_id or root.get_metadata(p["source"]).hard_link_id != root.get_metadata(p["path"]).hard_link_id):
            fail("managed refresh shared file object changed")
        if root.get_security(p["source"]) != p["security"] or ((audit or (not p["copy"] and not shared)) and (digest(source, algorithm="sha256") != p["after"] or (not added and digest(destination, algorithm="sha256") != p["before"]))):
            fail("managed refresh content/security changed after planning")
    for p in plans:
        if not p["copy"]:
            continue
        if not p.get("added", p["before"] == None):
            root.remove(p["path"])
        root.hardlink(p["source"], p["path"])
        if not root.get_metadata(p["path"]).hard_link_id or root.get_metadata(p["path"]).hard_link_id != root.get_metadata(p["source"]).hard_link_id:
            fail("managed cache is not the staged file object")
    return dict(refreshed_files=len([p for p in plans if p["copy"]]), verified_files=len([p for p in plans if not p["copy"]]), validation="runtime Fusion/NGen validation not performed by this file-publication helper")


def plan_update_gac_notifications(root, runtime, audit=True):
    """Notify Fusion using the installed assembly's last-write FILETIME.

    This is NOT a wall clock and must agree with the file Fusion will inspect.
    Optional audit verifies the declared payload hash; epochs and timestamps
    are always checked before publication.
    Existing cache identities only: lifecycle changes are rejected by the same
    guarded cache planner. Reference counting is unchanged for these replacements.
    """
    path='/Windows/System32/config/SOFTWARE'
    key='/Microsoft/Fusion/GACChangeNotification/Default'
    source=root.find(path)
    if source==None: fail('Fusion notifications require SOFTWARE')
    hive=windows.hive(source, snapshot=True)
    parent=hive.find(key)
    if parent==None: fail('Fusion notification parent is missing')
    names=root.path_index(lower=True)
    notifications={}
    inputs=[]
    architectures={}
    for transition in runtime['transitions']:
        before=_managed_declaration(transition['before'], transition, "before") if transition['before']!=None else None
        after=_managed_declaration(transition['after'], transition, "after") if transition['after']!=None else None
        if before==None and after==None: continue
        if before==None or after==None or before['notification'].lower()!=after['notification'].lower():
            fail('Fusion notification requires stable managed identity')
        target=names.get((after['path']+'/'+after['assembly_file']).lower())
        if target==None: fail('Fusion notification cache file is missing')
        file=root.find(target)
        if audit and digest(file,algorithm='sha256')!=after['files'][after['assembly_file'].lower()]['hash']:
            fail('Fusion notification cache file is not refreshed')
        metadata=root.get_metadata(target)
        stamp=metadata.last_write_time
        if type(stamp)!='int' or stamp<0 or stamp>0xffffffffffffffff: fail('invalid Fusion notification file time')
        name=after['notification'].lower()
        if name in notifications and notifications[name]!=stamp: fail('conflicting Fusion notification timestamps')
        notifications[name]=stamp
        architectures[after['architecture']]=True
        inputs.append((target,metadata.write_order,stamp))
    effects=dict(keys=[],values=[],key_deletions=[],value_deletions=[])
    for name,stamp in notifications.items():
        effects['values'].append(dict(hive='SOFTWARE',key=key,name=name,type=3,value=binary.u64le(stamp)))
    counters=[]
    if architectures:
        counters.append('StoreChangeId')
        if '32' in architectures or 'MSIL' in architectures: counters.append('StoreChangeIdFor32BitProcesses')
        if '64' in architectures or 'MSIL' in architectures: counters.append('StoreChangeIdFor64BitProcesses')
    values={name.lower():v for name,v in parent.value_records.items()}
    for name in counters:
        old=values.get(name.lower())
        if old==None or old.type!=4 or len(old.raw)!=4: fail('Fusion counter must be an existing DWORD')
        value=binary.read_u32le(old.raw)
        effects['values'].append(dict(hive='SOFTWARE',key=key,name=name,type=4,value=binary.u32le((value+1)&0xffffffff)))
    plans=plan_update_registry_effects(root,effects,[dict(hive='SOFTWARE',target='SOFTWARE',prefix='/',path=path,source=source)])
    return dict(plans=plans,inputs=inputs,notifications=len(notifications),counters=len(counters))

def apply_update_gac_notifications(root, plan):
    """Check file epochs/timestamps before publishing prepared Fusion counters and notifications."""
    for path,order,stamp in plan['inputs']:
        if root.find(path)==None or root.get_metadata(path).write_order!=order or root.get_metadata(path).last_write_time!=stamp:
            fail('Fusion cache file changed before notification')
    return dict(notifications=plan['notifications'],counters=plan['counters'],publication=apply_update_registry_effects(root,plan['plans']))
