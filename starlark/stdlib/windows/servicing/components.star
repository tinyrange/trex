"""Exact CSI composition, installed-mark and winner analysis. No state writes.

The result is not complete servicing: driver operations, payload/effect
materialization, catalog verification and transaction persistence are separate.
"""

def _identity_bytes(d):
    fields = [d.name, "Culture=" + (d.language or "neutral")]
    if d.type:
        fields.append("Type=" + d.type)
    fields += ["Version=" + d.version, "PublicKeyToken=" + d.public_key_token, "ProcessorArchitecture=" + d.processor_architecture]
    if d.version_scope:
        fields.append("versionScope=" + d.version_scope)
    return bytes(", ".join(fields))

def _winner_group(identity):
    d = windows.csi_identity(identity)
    kind = d.type.lower()
    policy = kind == "policy" or (kind != "-policy" and kind.endswith("-policy"))
    across = d.version_scope.lower() == "nonsxs" or policy
    return (windows.csi_identity_hash(identity, omit_version = True), "" if across else ".".join(d.version.split(".")[:2]))

def analyze_servicing_components(base, image, source, features, population, hives=None, audit_baseline=True):
    """Count complete installed ownership and project changed compositions.

    Unchanged deployments use persisted c! membership, not guessed dispositions.
    Every changed/staged deployment still follows its complete manifest graph.
    audit_baseline additionally recomputes and checks every unchanged graph.
    """
    hive = windows.hive(hives["COMPONENTS"] if hives != None else base[image + "/Windows/System32/config/COMPONENTS"])
    software = windows.hive(hives["SOFTWARE"] if hives != None else base[image + "/Windows/System32/config/SOFTWARE"])
    deployments = {k.name.lower(): k.values for k in hive.find("/CanonicalData/Deployments").children}
    components = {k.name.lower(): k.values for k in hive.find("/DerivedData/Components").children}
    resident_identities = {str(c["identity"]).lower(): c["identity"] for c in components.values()}
    owners = {name: {} for name in deployments}
    for component in components.values():
        identity = component["identity"]
        key = str(identity).lower()
        for name in component:
            if name.lower().startswith("c!"):
                owner = name[2:].lower()
                if owner not in owners:
                    fail("CSI component has an unknown deployment backlink: " + owner)
                owners[owner][key] = identity
    actions = population.deployment_actions(changed_only=True)
    changed = {str(_identity_bytes(a.deployment)).lower(): True for a in actions if a.stage or a.action in [3, 4]}
    # Prefetch only changed compositions in normal construction. Unchanged
    # ownership still contributes every installed source to the shared counts.
    required = {}
    for name, values in deployments.items():
        if audit_baseline or str(values["appid"]).lower() in changed:
            required.update(owners[name])
            required[str(values["appid"]).lower()] = values["appid"]
    resident_started = clock.monotonic()
    resident_ids = list(required.values())
    resident_files = source.open_resident_components(resident_ids, workers = 4)
    print("resident manifest batch", len(resident_files), clock.monotonic() - resident_started, "seconds")
    resident_cache = {str(identity).lower(): file for identity, file in zip(resident_ids, resident_files) if file != None}
    def resident(identity):
        key = str(identity).lower()
        if key not in resident_cache:
            file = source.open_resident_component(identity)
            if file == None:
                fail("missing exact resident CSI manifest: " + key)
            resident_cache[key] = file
        return resident_cache[key]
    # Reuse immutable native parses across overlapping deployment graphs.
    # Keep original files separately for subsequent payload/runtime readers.
    parsed_resident = {}
    def resident_composition(identity):
        key = str(identity).lower()
        if key not in parsed_resident:
            parsed_resident[key] = windows.cbs_manifest(resident(identity))
        return parsed_resident[key]
    inventory = []
    composition_by_identity = {}
    for name, values in deployments.items():
        identity = values["appid"]
        key = str(identity).lower()
        if key in composition_by_identity:
            fail("duplicate exact canonical deployment: " + key)
        composition = None
        if audit_baseline or key in changed:
            composition = windows.csi_composition(identity, resident_composition)
            # Retained p!/i! sources own the graph. An unowned canonical key
            # can survive removal; staged-only sources do not retain it.
            retained = any([n[:2].lower() in ["p!", "i!"] for n in values])
            actual = {str(m.identity).lower(): True for m in composition} if retained else {}
            if set(actual) != set(owners[name]):
                fail("resident composition disagrees with native c! ownership: " + name)
        sources = []
        for value_name, data in values.items():
            if value_name.lower().startswith("i!"):
                if not value_name.lower().startswith("i!cbs_"):
                    fail("non-CBS installed source requires explicit policy: " + value_name)
                parsed = windows.cbs_deployment_source(data)
                if value_name[2:].lower() != parsed.source_key.lower():
                    fail("installed source name disagrees with its native payload")
                sources.append(data)
        if composition != None:
            composition_by_identity[key] = composition
            inventory.append(dict(identity = identity, composition = composition, installed_sources = sources))
        else:
            inventory.append(dict(identity = identity, persisted_members = list(owners[name].values()), installed_sources = sources))
    metadata = {feature: source.servicing_metadata(feature) for feature in features}
    manifests = {}
    manifest_features = {}
    def resolve(identity):
        key = str(identity).lower()
        # Residency comes from the installed inventory, not from whether a
        # manifest happened to be needed by an earlier changed graph. Keep its
        # exact source available even if an update carries the same identity.
        if key in resident_identities and key not in resident_cache:
            resident(identity)
        if key not in manifests:
            found = [(feature, file) for feature, file in [(feature, m.open_component(identity)) for feature, m in metadata.items()] if file != None]
            if len(found) > 1:
                fail("ambiguous full-inventory component: " + key)
            manifests[key] = found[0][1] if found else resident(identity)
            if found:
                manifest_features[key] = found[0][0]
        return manifests[key]
    parsed_updates = {}
    def update_composition(identity):
        key = str(identity).lower()
        if key not in parsed_updates:
            file = resolve(identity)
            parsed_updates[key] = parsed_resident[key] if key in parsed_resident and file == resident_cache.get(key) else windows.cbs_manifest(file)
        return parsed_updates[key]
    for action in actions:
        if not action.stage and action.action not in [3, 4]:
            continue
        identity = _identity_bytes(action.deployment)
        key = str(identity).lower()
        if key not in composition_by_identity:
            composition = windows.csi_composition(identity, update_composition)
            composition_by_identity[key] = composition
            inventory.append(dict(identity = identity, composition = composition, installed_sources = []))
    marks = population.install_marks(inventory)
    winners = {}
    for key in software.find("/Microsoft/Windows/CurrentVersion/SideBySide/Winners").children:
        hash = int(key.name.rsplit("_", 1)[1], 16)
        if hash in winners:
            fail("duplicate native winner family hash")
        winners[hash] = key
    baseline = {}
    before = {}
    final = {}
    affected = {}
    families = {}
    for mark in marks:
        identity = mark.identity
        d = windows.csi_identity(identity)
        group = _winner_group(identity)
        family = (d.name.lower(), d.language.lower(), d.public_key_token.lower(), d.processor_architecture.lower(), d.type.lower(), d.version_scope.lower())
        if group[0] in families and families[group[0]] != family:
            fail("CSI winner hash collision between full identities")
        families[group[0]] = family
        if group[0] in winners and windows.csi_winner_family_key(identity) != winners[group[0]].name:
            fail("CSI full identity disagrees with native winner family name")
        branch = ".".join(d.version.split(".")[:2])
        if mark.initial:
            before.setdefault(group, {})[d.version] = True
            baseline.setdefault(group[0], {}).setdefault(branch, {})[d.version] = True
        if mark.final:
            final.setdefault(group, {})[d.version] = identity
        if mark.affected:
            affected.setdefault(group, {})[d.version] = mark
    # Independent native control: membership bits must equal source-derived
    # baseline counts. Defaults intentionally are NOT rebuilt from membership.
    actual_baseline = {}
    for hash, key in winners.items():
        branches = {}
        for child in key.children:
            versions = {}
            for name, value in child.values.items():
                if name == "(default)":
                    continue
                if value != b"\x01":
                    fail("unexpected native winner membership value")
                versions[name] = True
            branches[child.name] = versions
        actual_baseline[hash] = branches
    if baseline != actual_baseline:
        fail("CSI source-derived membership disagrees with native Winners")
    changes = []
    winner_plans = []
    for group, versions in affected.items():
        key = winners.get(group[0])
        current = ""
        if key != None:
            branch = group[1] if group[1] else key.values.get("(default)", "")
            children = {k.name: k for k in key.children}
            if branch in children:
                current = children[branch].values.get("(default)", "")
            elif branch and not group[1]:
                fail("selected native winner branch is missing")
        changed = [dict(version = v, installed = m.final != 0, impactful_install = m.impactful_install) for v, m in versions.items()]
        identity = list(versions.values())[0].identity
        result = windows.csi_winner_plan(identity, current, list(before.get(group, {})), changed)
        control = windows.csi_winner_change(identity, current, list(final.get(group, {})), changed)
        if result.winner != control.winner or result.shadowed != control.shadowed:
            fail("CSI winner write plan disagrees with final mark analysis")
        if result.edits:
            winner_plans.append(result)
        if result.winner or result.shadowed:
            changes.append(dict(identity = identity, group = group, winner = result.winner, shadowed = result.shadowed))
    for change in changes:
        identity = change["identity"]
        d = windows.csi_identity(identity)
        marker = ", Version=" + d.version + ","
        for version in [change["winner"], change["shadowed"]]:
            if not version: continue
            exact = bytes(str(identity).replace(marker, ", Version=" + version + ","))
            key = str(exact).lower()
            if key not in manifests and key not in resident_cache:
                resident(exact)
    return dict(inventory = inventory, compositions = composition_by_identity, marks = marks, winner_changes = changes, winner_plans = winner_plans, manifests = manifests, manifest_features = manifest_features, resident_manifests = resident_cache)


def _verify_projected_sources(rows, analysis):
    counts = {}
    inventory = {}
    for deployment in analysis["inventory"]:
        key = str(deployment["identity"]).lower()
        inventory[key] = True
        if key in rows:
            sources = [v for v in rows[key]["final_sources"] if v["name"].lower().startswith("i!")]
            n = len(sources)
        else:
            n = len(deployment["installed_sources"])
        members = deployment.get("persisted_members")
        if members == None: members = [m.identity for m in deployment["composition"]]
        for identity in members:
            component = str(identity).lower()
            counts[component] = counts.get(component, 0) + n
    if [key for key in rows if key not in inventory]:
        fail("source projection has a deployment outside composition analysis")
    if len(counts) != len(analysis["marks"]):
        fail("source projection component universe mismatch")
    for mark in analysis["marks"]:
        if counts[str(mark.identity).lower()] != mark.final:
            fail("projected source edits disagree with final component marks")

def project_servicing_sources(base, image, closure, population, analysis, hives=None):
    """Project source edits for successful staging then ordinary installation.

    This is conditional construction analysis, NOT evidence that those phases
    succeeded. Pin edits require staged manifests; staged-source edits require
    completed payload staging. Pending-content staging is not modeled here.
    Driver references still require their separate operation queue. No writes
    are applied and no composition/status/payload completion is inferred.
    """
    hive = windows.hive(hives["COMPONENTS"] if hives != None else base[image + "/Windows/System32/config/COMPONENTS"])
    records = {}
    for key in hive.find("/CanonicalData/Deployments").children:
        values = key.value_records
        identity = values["appid"].raw
        identity_key = str(identity).lower()
        if identity_key in records:
            fail("duplicate exact CSI source deployment")
        before = []
        for name, value in values.items():
            if name[:2].lower() in ["p!", "i!", "s!"]:
                before.append(dict(name = name, type = value.type, data = value.raw))
        # Validate even unchanged owners; omitting non-CBS sources is unsafe.
        windows.csi_source_plan(before, [])
        records[identity_key] = dict(identity = identity, baseline = before, pin = [], stage = [], install = [], driver = False)
    files = {name.lower(): file for name, file in closure["files"].items()}
    payloads = {}
    parsed_packages = {}
    for action in population.deployment_actions(changed_only=True):
        if not action.stage and action.action == 0:
            continue
        if action.action not in [0, 3, 4]:
            fail("source projection requires ordinary install/uninstall actions")
        identity = _identity_bytes(action.deployment)
        identity_key = str(identity).lower()
        if identity_key not in records:
            records[identity_key] = dict(identity = identity, baseline = [], pin = [], stage = [], install = [], driver = False)
        row = records[identity_key]
        row["driver"] = row["driver"] or action.driver
        source_key = (action.package.lower(), action.update.lower())
        if source_key not in payloads:
            if source_key[0] not in files:
                fail("missing source package metadata: " + action.package)
            if source_key[0] not in parsed_packages:
                parsed_packages[source_key[0]] = windows.cbs_manifest(files[source_key[0]])
            data = windows.cbs_deployment_source_data(parsed_packages[source_key[0]], action.update)
            parsed = windows.cbs_deployment_source(data)
            if parsed.package.lower() != source_key[0] or parsed.update.lower() != source_key[1]:
                fail("source metadata does not match exact action")
            payloads[source_key] = data
        data = payloads[source_key]
        if action.stage:
            row["pin"].append(dict(kind = 1, delete = False, data = data))
            row["stage"].append(dict(kind = 4, delete = False, data = data))
        if action.action in [3, 4]:
            row["install"].append(dict(kind = 2, delete = action.action == 4, data = data))
    result = {}
    for identity_key, row in records.items():
        if not row["pin"] and not row["stage"] and not row["install"]:
            continue
        state = {v["name"].lower(): v for v in row["baseline"]}
        plans = {}
        for phase in ["pin", "stage", "install"]:
            plan = windows.csi_source_plan(list(state.values()), row[phase])
            plans[phase] = plan
            for edit in plan.edits:
                key = edit.name.lower()
                if edit.delete:
                    state.pop(key)
                else:
                    state[key] = dict(name = edit.name, type = edit.type, data = edit.data)
        result[identity_key] = dict(identity = row["identity"], driver = row["driver"], plans = plans, final_sources = list(state.values()))
    _verify_projected_sources(result, analysis)
    return result


def plan_servicing_payloads(source, features, population, analysis):
    """Join exact staging compositions to store-file plans, not runtime effects.

    Resident manifests are classified for subsequent payload verification, not
    treated as evidence of completed staging. New plans contain every selected
    component's manifest and declared files; package catalogs remain separate.
    """
    staging = {str(_identity_bytes(a.deployment)).lower(): True for a in population.deployment_actions(changed_only=True) if a.stage}
    required = {}
    covered = {}
    for row in analysis["inventory"]:
        key = str(row["identity"]).lower()
        if key not in staging:
            continue
        covered[key] = True
        for member in row["composition"]:
            required[str(member.identity).lower()] = member.identity
    if covered != staging:
        fail("staging deployment has no exact composition")
    metadata = {f: source.servicing_metadata(f) for f in features}
    stage_ids = {f: [] for f in features}
    resident = {}
    for key, identity in required.items():
        if key in analysis["resident_manifests"]:
            resident[key] = identity
            continue
        # Composition resolution already checked every feature and rejected
        # ambiguous full identities. Retain that provenance instead of opening
        # and parsing the same manifest merely to rediscover its feature. The
        # native staging plan still independently validates each exact identity.
        feature = analysis["manifest_features"].get(key)
        if feature not in metadata:
            fail("missing exact staging component provenance: " + key)
        stage_ids[feature].append(identity)
    # Reuse only the index-bound immutable snapshots opened by composition.
    # Native code checks the exact source index and full identity again; equal
    # bytes from another stage or a caller-created file cannot supply provenance.
    plans = {f: metadata[f].plan_components(ids, manifests=[analysis["manifests"][str(identity).lower()] for identity in ids]) for f, ids in stage_ids.items()}
    return dict(stages = plans, resident = resident, components = required)

def verify_servicing_payloads(payloads):
    """Force native reconstruction and reads; no installed-state claims/writes.

    This verifies new component content against available graph/manifest hashes.
    It does not establish catalog trust or validate the resident content reused.
    The result retains plans rather than all decoded file bytes in memory.
    """
    result = {}
    for feature, plan in payloads["stages"].items():
        count = 0
        size = 0
        for index in plan.read_order:
            file = plan.open(index)
            size += len(file.bytes())
            count += 1
        if count != len(plan.files):
            fail("component payload read order omitted files")
        result[feature] = dict(files = count, bytes = size)
    return result

def verify_resident_payloads(base, image, payloads, analysis):
    """Verify exact resident store files after DCS expansion; no catalog trust.

    Nested Identity SHA-1/SHA-256 and legacy SHA-1 ImageDigest declarations
    are checked independently. Unsupported hash policies fail, never bypass.
    COMPONENTS-backed manifest resolution has already validated full identities;
    reject path-hash collisions rather than selecting a filename by version.
    """
    paths = {}
    for p in base[image + "/Windows/WinSxS/Manifests"].files:
        if p.lower().endswith(".manifest"):
            hash = int(p.rsplit("_", 1)[1][:-9], 16)
            paths.setdefault(hash, []).append(p)
    result = dict(components = 0, files = 0, bytes = 0, compressed = 0, image_digests = 0)
    for key, identity in payloads["resident"].items():
        candidates = paths.get(windows.csi_identity_hash(identity), [])
        if len(candidates) != 1:
            fail("missing or ambiguous resident component path: " + key)
        stem = candidates[0].rsplit("/", 1)[1][:-9]
        manifest = windows.assembly_manifest(analysis["resident_manifests"][key])
        for f in manifest.files:
            name = f.name.replace(chr(92), "/")
            if name.startswith("/") or ":" in name or any([v in ["", ".", ".."] for v in name.split("/")]):
                fail("unsafe resident component filename: " + name)
            p = image + "/Windows/WinSxS/" + stem + "/" + name
            if p not in base:
                fail("missing exact resident file: " + p)
            file = base[p]
            if file.size >= 4 and file.slice(0, 4).bytes() == b"DCS\x01":
                file = archive.dcs(file)
                result["compressed"] += 1
            if file.size > 512 << 20:
                fail("resident file exceeds verification bound: " + p)
            if f.digest == None and not f.hash:
                fail("resident file has no declared digest: " + p)
            if f.digest != None:
                d = f.digest
                if any([t != "urn:schemas-microsoft-com:HashTransforms.Identity" for t in d.transforms]):
                    fail("unsupported resident file hash transform: " + p)
                algorithm = {
                    "http://www.w3.org/2000/09/xmldsig#sha1": "sha1",
                    "http://www.w3.org/2000/09/xmldsig#sha256": "sha256",
                    "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
                }.get(d.algorithm)
                if algorithm == None:
                    fail("unsupported resident digest algorithm: " + d.algorithm)
                expected = binary.decode("".join(d.value.split()), "base64", maximum = 64)
                if crypto.hash(algorithm, file.bytes()) != expected:
                    fail("resident file digest mismatch: " + p)
            if f.hash:
                if f.hash_algorithm.lower() not in ["sha1", "sha-1"]:
                    fail("unsupported legacy resident hash algorithm: " + f.hash_algorithm)
                if binary.hex(windows.image_digest(file, algorithm = "sha1")).lower() != f.hash:
                    fail("resident ImageDigest mismatch: " + p)
                result["image_digests"] += 1
            result["files"] += 1
            result["bytes"] += file.size
        result["components"] += 1
    return result


def verify_servicing_catalogs(base, image, source, features, closure, population, analysis):
    """Check staged-source catalog integrity, complete membership and X.509 paths.

    Anchors come only from the unchanged base ROOT registry store. Code-signing
    and timestamping paths are checked at each authenticated timestamp. This is
    NOT Windows trust-provider policy: root-store property policy, revocation,
    disallowed CTLs and CBS publisher policy still require separate validation.
    Nothing is installed, staged or marked by this content inspection.
    """
    software = windows.hive(base[image + "/Windows/System32/config/SOFTWARE"])
    root_key = software.find("/Microsoft/SystemCertificates/ROOT/Certificates")
    if root_key == None or not root_key.children or len(root_key.children) > 64:
        fail("base ROOT inventory is missing or exceeds its bound")
    roots = []
    for key in root_key.children:
        record = windows.serialized_certificate(key.values["Blob"])
        if record.certificate.sha1 != key.name.lower():
            fail("base ROOT key disagrees with its certificate fingerprint")
        roots.append(record.certificate.der)
    metadata = {}
    for feature in features:
        index = source.servicing_metadata(feature)
        for package in index.packages:
            name = package.lower()
            if name in metadata:
                fail("ambiguous exact package catalog source: " + name)
            metadata[name] = index
    catalogs = {}
    chain_checks = {}
    hashes = {}
    deployments = {}
    references = 0
    memberships = 0
    for action in population.deployment_actions(changed_only=True):
        if not action.stage:
            continue
        package = action.package
        if package not in catalogs:
            if package.lower() not in metadata:
                fail("staged source package has no update catalog: " + package)
            file = metadata[package.lower()].open_catalog(package)
            integrity = windows.catalog_signature(file)
            timestamp = integrity.timestamp
            if timestamp == None:
                fail("staged source catalog lacks an authenticated timestamp: " + package)
            chain_key = (integrity.signer, tuple(integrity.certificates), timestamp.signer, tuple(timestamp.certificates), timestamp.unix)
            if chain_key not in chain_checks:
                windows.certificate_chain(timestamp.signer, roots, timestamp.certificates, timestamp.unix, "timestamping")
                windows.certificate_chain(integrity.signer, roots, integrity.certificates, timestamp.unix, "code_signing")
                chain_checks[chain_key] = True
            members = {digest: True for digest in windows.catalog_index(file)["sha256"]}
            if crypto.hash("sha256", closure["files"][package]) not in members:
                fail("owning MUM is outside its signed catalog: " + package)
            catalogs[package] = members
        root = str(_identity_bytes(action.deployment)).lower()
        deployments[root] = True
        for member in analysis["compositions"][root]:
            key = str(member.identity).lower()
            if key not in hashes:
                file = analysis["manifests"].get(key) or analysis["resident_manifests"].get(key)
                if file == None:
                    fail("missing exact composed manifest: " + key)
                hashes[key] = crypto.hash("sha256", file)
            if hashes[key] not in catalogs[package]:
                fail("composed manifest is outside its owning signed catalog: " + package + " " + key)
            memberships += 1
        references += 1
    return dict(catalogs = len(catalogs), deployment_references = references, deployments = len(deployments), components = len(hashes), memberships = memberships, chain_checks = len(chain_checks), base_roots = len(roots))


def bind_servicing_runtime_sources(base, image, payloads, analysis, sources):
    """Bind exact versioned runtime sources to staged/resident store entries.

    This does not stage files or authorize activation. Family keys are never
    used as payload identities. Hash-derived paths must be unique, and each
    exact identity must have been resolved by component analysis or staging.
    Returned lazy references retain provenance; callers still need content,
    security, attributes, compression and transaction policy before writing.
    """
    stems = {}
    for path in base[image + "/Windows/WinSxS/Manifests"].files:
        if not path.lower().endswith(".manifest"):
            continue
        stem = path.rsplit("/", 1)[1][:-9]
        h = int(stem.rsplit("_", 1)[1], 16)
        stems.setdefault(h, {})[stem.lower()] = stem
    staged = {}
    for feature, plan in payloads["stages"].items():
        for index, entry in enumerate(plan.files):
            path = entry.store_path
            if not path.startswith("/Windows/WinSxS/") or any([part in ["", ".", ".."] for part in path[1:].split("/")]) or chr(92) in path or ":" in path:
                fail("unsafe staged store path")
            key = path.lower()
            if key in staged:
                fail("ambiguous staged store path: " + path)
            staged[key] = dict(path = path, origin = "staged", feature = feature, index = index, kind = entry.kind)
            if entry.kind == "component-manifest":
                if not path.startswith("/Windows/WinSxS/Manifests/") or not path.endswith(".manifest"):
                    fail("invalid staged manifest path")
                stem = path.rsplit("/", 1)[1][:-9]
                h = int(stem.rsplit("_", 1)[1], 16)
                stems.setdefault(h, {})[stem.lower()] = stem
    result = {}
    identities = {}
    for source_key, pair in sources.items():
        for side in ["before", "after"]:
            selected = pair[side]
            if selected == None:
                continue
            identity = selected["component_identity"]
            exact = str(identity).lower()
            if exact not in analysis["resident_manifests"] and exact not in payloads["components"]:
                fail("runtime source has no exact component provenance: " + exact)
            h = windows.csi_identity_hash(identity)
            if h in identities and identities[h] != exact:
                fail("runtime component identity hash collision")
            identities[h] = exact
            candidates = stems.get(h, {})
            if len(candidates) != 1:
                fail("missing or ambiguous runtime store stem: " + exact)
            name = selected["record"]["name"].replace(chr(92), "/")
            if name.startswith("/") or ":" in name or any([part in ["", ".", ".."] for part in name.split("/")]):
                fail("unsafe runtime source filename")
            path = "/Windows/WinSxS/" + list(candidates.values())[0] + "/" + name
            entry = staged.get(path.lower()) if side == "after" else None
            if entry != None:
                if entry["kind"] != "component-file":
                    fail("runtime source selected non-payload staged entry")
                binding = dict(entry)
            else:
                if exact not in analysis["resident_manifests"] or image + path not in base:
                    fail("missing exact runtime store source: " + path)
                binding = dict(path = path, origin = "resident", base_path = image + path)
            binding.update(component_identity = identity, hash = selected["hash"], attributes = selected["record"]["attributes"])
            result[(source_key, side)] = binding
    return result


def open_servicing_runtime_source(base, payloads, binding):
    """Open and revalidate one exact runtime source; never mutate an image.

    DCS is a resident storage container, not the projected file's byte stream.
    The bounded native Identity/SHA256 policy must agree after expansion.
    """
    if binding["origin"] == "resident":
        file = base[binding["base_path"]]
        if file.size >= 4 and file.slice(0, 4).bytes() == b"DCS\x01":
            file = archive.dcs(file)
    elif binding["origin"] == "staged":
        plan = payloads["stages"][binding["feature"]]
        entry = plan.files[binding["index"]]
        if entry.kind != "component-file" or entry.store_path != binding["path"]:
            fail("runtime source plan no longer matches binding")
        file = plan.open(binding["index"])
    else:
        fail("unsupported runtime source origin")
    expected = binding["hash"]
    if expected == None or expected["digest_method"] != 2 or expected["transform"] != 1 or type(expected["digest"]) != "bytes" or len(expected["digest"]) != 32:
        fail("unsupported runtime source digest")
    if file.size > 512 << 20:
        fail("runtime source exceeds verification bound")
    if digest(file, algorithm = "sha256") != expected["digest"]:
        fail("runtime source content does not match exact declaration: " + binding["path"])
    return file
