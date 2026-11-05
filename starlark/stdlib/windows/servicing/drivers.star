"""Ordinary empty-queue driver planning, not driver-store/CBS completion.

Keep MUM declaration provenance, exact INF digest, and each package/update owner.
Planning neither installs drivers nor authorizes package completion or file removal.
"""

load("@stdlib//windows/servicing:runtime.star", "select_servicing_file_hash")


def _identity(d):
    fields = [d.name, "Culture=" + (d.language or "neutral")]
    if d.type:
        fields.append("Type=" + d.type)
    fields += ["Version=" + d.version, "PublicKeyToken=" + d.public_key_token, "ProcessorArchitecture=" + d.processor_architecture]
    if d.version_scope:
        fields.append("versionScope=" + d.version_scope)
    value = bytes(", ".join(fields))
    windows.csi_identity(value)
    return value


def reduce_update_driver_queue(records, existing_queue):
    """Reduce new, uncompleted operations using the observed native queue rules.

    The caller must supply an explicit persisted-queue inventory. Nonempty queues
    require native load/recovery policy and are rejected. Records require exact
    identity text and owner (package~update); comparisons are CASE SENSITIVE.
    Conflicting duplicate metadata fails rather than relying on native first-win.
    Native completed-state reversal is deliberately outside this empty-queue path.
    """
    if type(existing_queue) != "list":
        fail("driver queue requires an explicit persisted inventory list")
    if existing_queue:
        fail("existing driver queue requires native load/recovery policy")
    if len(records) > 1048576:
        fail("driver queue exceeds operation bound")
    queue = []
    active = {}
    duplicates = 0
    canceled = 0
    for record in records:
        if record["kind"] not in [0, 1] or not record["identity"] or not record["owner"]:
            fail("unsupported ordinary driver queue operation")
        if any([field in record for field in ["state", "flags", "sequence", "canceled"]]):
            fail("driver queue cannot import fabricated or persisted execution state")
        key = (record["identity"], record["owner"])
        previous = active.get(key)
        if previous != None:
            if {k:v for k,v in previous.items() if k not in ["kind", "sequence", "canceled"]} != {k:v for k,v in record.items() if k != "kind"}:
                fail("conflicting duplicate driver queue metadata")
            if previous["kind"] == record["kind"]:
                duplicates += 1
            else:
                previous["canceled"] = True
                active.pop(key)
                canceled += 1
            continue
        item = dict(record, sequence=len(queue) + 1, canceled=False)
        queue.append(item)
        active[key] = item
    return dict(operations=[r for r in queue if not r["canceled"]], entries=queue, duplicates=duplicates, canceled=canceled)


def plan_update_driver_operations(actions, manifests, existing_queue):
    """Bind admitted ordinary actions to declared INF metadata and manifest hash.

    manifests is an exact canonical CSI identity (casefolded) to decoded manifest
    map, including resident declarations. Only normal/force ranking declarations
    are retained; this does not map them to native driver-store flags. Payload
    verification, staging, new-owner key security, driver-store effects and queue
    execution remain mandatory separate phases. No image mutations occur here.
    """
    records = []
    stages = []
    staged_only = []
    for action in actions:
        if not action.driver or (not action.stage and action.action == 0):
            continue
        if action.action not in [0, 3, 4]:
            fail("driver plan requires ordinary install/uninstall actions")
        attributes = {}
        for attribute in action.driver_attributes:
            if attribute.namespace or attribute.name not in ["inf", "ranking"] or attribute.name in attributes:
                fail("unestablished or duplicate MUM driver declaration policy")
            attributes[attribute.name] = attribute.value
        inf = attributes.get("inf", "")
        ranking = attributes.get("ranking", "")
        if not inf or inf in [".", ".."] or any([c in inf for c in ["/", chr(92), ":", chr(0)]]) or not inf.lower().endswith(".inf"):
            fail("driver plan requires an explicit INF leaf from its MUM")
        if ranking not in ["normal", "force"]:
            fail("unestablished MUM driver ranking")
        identity = _identity(action.deployment)
        source = manifests.get(str(identity).lower())
        if source == None:
            fail("missing exact driver deployment manifest")
        manifest = windows.assembly_manifest(source)
        declared = {a.name:a.value for a in manifest.identity if not a.namespace}
        expected = action.deployment
        for field, value in [("name", expected.name), ("version", expected.version), ("processorArchitecture", expected.processor_architecture), ("publicKeyToken", expected.public_key_token), ("type", expected.type), ("versionScope", expected.version_scope)]:
            if declared.get(field, "").lower() != value.lower():
                fail("driver manifest disagrees with exact action identity")
        if declared.get("language", "neutral").lower() != (expected.language or "neutral").lower():
            fail("driver manifest culture disagrees with exact action identity")
        candidates = [f for f in manifest.files if f.name.lower() == inf.lower()]
        if len(candidates) != 1:
            fail("driver manifest has no unique declared INF file")
        selected = candidates[0]
        select_servicing_file_hash(selected)
        # Native GetFileHashFromManifest retains the selected file's hash text.
        # Reject unestablished whitespace rather than silently renaming a key.
        hash_text = selected.digest.value
        if hash_text != "".join(hash_text.split()):
            fail("driver ownership hash has unestablished whitespace")
        if not action.package or not action.update or any([chr(0) in v for v in [action.package, action.update]]) or "~" in action.update or "." in action.update:
            fail("invalid exact driver package/update owner")
        record = dict(identity=str(identity), owner=action.package + "~" + action.update, architecture=expected.processor_architecture, inf=inf, hash=hash_text, ranking=ranking, manifest_sha256=digest(source, algorithm="sha256"))
        if action.stage:
            stages.append(record)
        if action.action == 0:
            staged_only.append(record)
        else:
            records.append(dict(record, kind=0 if action.action == 3 else 1))
    reduced = reduce_update_driver_queue(records, existing_queue)
    reduced.update(stages=stages, staged_only=staged_only)
    return reduced


def select_update_driver_source_paths(root,component_roots):
    """Select actual descendants of already-bound component source roots.

    INF SourceDisks paths can name nested architecture directories. Selection
    retains that existing hierarchy, not a flattened list or synthetic aliases.
    Binding roots to admitted manifests/driver jobs remains the caller's duty.
    """
    selected={}
    for path in component_roots:
        parts=path.rstrip('/').split('/')
        if len(parts)!=4 or [p.lower() for p in parts[:3]]!=['','windows','winsxs'] or not parts[3] or parts[3] in ['.','..'] or chr(92) in path or chr(0) in path or ':' in path:
            fail('driver source root must be an exact WinSxS component directory')
        selected['/'.join(parts).lower()]=False
    output=[]
    for path in root.files:
        parts=path.split('/')
        if len(parts)<5: continue
        component='/'.join(parts[:4]).lower()
        if component in selected:
            selected[component]=True
            output.append(path)
    if any([not found for found in selected.values()]): fail('bound driver source component is absent')
    return output
