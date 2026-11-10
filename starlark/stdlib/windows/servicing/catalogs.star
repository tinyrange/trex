"""Package catalog preparation and candidate publication.

Optional signature auditing qualifies trust against unchanged ROOT anchors.
MUM membership is always checked; neither mode fabricates a trust verdict.
"""
load("@stdlib//windows/servicing:package_store.star", "package_metadata_executions")
load("@stdlib//windows/servicing:package_security.star", "new_package_manifest_security", "new_package_catalog_security")

def _replace(root, path, file, names, new_security=None):
    actual = names.get(path.lower(), path)
    security = new_security
    if root.find(actual) != None:
        security = root.get_security(actual)
        # A write replaces the path's reader but intentionally preserves tree
        # metadata. Remove first to detach the old WIM hardlink identity.
        root.remove(actual)
    root.write(actual, file)
    if security != None:
        root.set_security(actual, security)
    names[path.lower()] = actual

def prepare_package_catalogs(root, source, features, population, manifests=None, while_opening=None, audit=True):
    """Capture catalog/MUM bytes and membership without changing the tree.

    Signature/timestamp-chain auditing defaults on. Explicit non-audit mode
    requires caller-admitted transport sources and never asserts trust.
    """
    indexes = {}
    feature_by_package = {}
    feature_indexes = {}
    for feature in features:
        index = source.servicing_metadata(feature)
        feature_indexes[feature] = index
        for package in index.packages:
            key = package.lower()
            if key in indexes:
                fail("ambiguous update package catalog source")
            indexes[key] = index
            feature_by_package[key] = feature
    selected = {action.package: True for action in population.deployment_actions(changed_only=True) if action.stage}
    # Package wrappers can have no component deployments of their own. Their
    # native package-level stage/install action still requires MUM and CAT.
    # Selecting only deployment owners omitted the LCU and SSU root packages.
    wrappers = []
    for execution in package_metadata_executions(population, list(indexes)):
        if execution.package.lower() in indexes and execution.package not in selected:
            selected[execution.package] = True
            wrappers.append(execution.package)
    names = {p.lower(): p for p in root.files}
    prepared = []
    resident = 0
    memberships = 0
    roots = []
    if audit:
        software = windows.hive(root.find("/Windows/System32/config/SOFTWARE"))
        anchors = software.find("/Microsoft/SystemCertificates/ROOT/Certificates")
        if anchors == None or not anchors.children or len(anchors.children) > 64:
            fail("catalog validation requires the bounded unchanged ROOT inventory")
        roots = []
        for key in anchors.children:
            certificate = windows.serialized_certificate(key.values["Blob"]).certificate
            if certificate.sha1 != key.name.lower():
                fail("catalog ROOT key disagrees with its certificate fingerprint")
            roots.append(certificate.der)
    # Only immutable source readers run in parallel. Registry planning stays on
    # this caller thread and reads unchanged baseline hives. Join every worker
    # before validating signatures or publishing any catalog/file effects.
    batches = {feature: [] for feature in features}
    for package in sorted(selected):
        feature = feature_by_package.get(package.lower())
        if feature != None:
            batches[feature].append(package)
    captured_catalogs = {}
    order = sorted(features, key=lambda feature: len(batches[feature]))
    for feature in order:
        packages = batches[feature]
        kwargs = {}
        if manifests != None:
            kwargs["manifests"] = [manifests[p] for p in packages]
        if while_opening != None and feature == order[-1]:
            kwargs["while_opening"] = while_opening
        catalogs = feature_indexes[feature].open_catalogs(packages, **kwargs)
        captured_catalogs.update({package: catalogs[i] for i, package in enumerate(packages)})
    if not order and while_opening != None:
        while_opening()
    chains = {}
    for package in sorted(selected):
        if any([c in package for c in ["/", chr(92), chr(0)]]) or len(package) > 252:
            fail("unsafe catalog package name")
        index = indexes.get(package.lower())
        if index == None:
            # A resolved manifest pin can be staged again by ordinary CBS
            # population. Its exact package metadata may be resident-only,
            # rather than a member of the new update's transport inventory.
            mum_path = names.get(("/Windows/servicing/Packages/" + package + ".mum").lower())
            cat_path = names.get(("/Windows/servicing/Packages/" + package + ".cat").lower())
            if mum_path == None or cat_path == None:
                fail("missing exact staged package metadata: " + package)
            manifest, catalog = root.find(mum_path), root.find(cat_path)
            resident += 1
        else:
            manifest = manifests[package] if manifests != None else index.open_package(package)
            catalog = captured_catalogs[package]
        # Retain the exact bytes subjected to signature and membership checks.
        # Transport WIMs use large solid LZMS chunks: retaining tiny lazy CAT
        # readers makes every later CSI/index/hash pass decompress those chunks
        # again after eviction. This is owned in-memory content, not a host
        # intermediate. Membership checks and requested audits still run.
        if catalog.size > 64 << 20:
            fail("update catalog exceeds the native parser bound")
        catalog = windows.catalog(catalog)
        if manifest.size > 16 << 20:
            fail("update package manifest exceeds the native parser bound")
        manifest = binary.concat([manifest.bytes()])
        if audit:
            signature = windows.catalog_signature(catalog)
            if signature.timestamp == None:
                fail("update catalog has no authenticated timestamp")
            timestamp = signature.timestamp
            chain_key = (signature.signer, tuple(signature.certificates), timestamp.signer, tuple(timestamp.certificates), timestamp.unix)
            if chain_key not in chains:
                windows.certificate_chain(timestamp.signer, roots, timestamp.certificates, timestamp.unix, "timestamping")
                windows.certificate_chain(signature.signer, roots, signature.certificates, timestamp.unix, "code_signing")
                chains[chain_key] = True
        if digest(manifest, algorithm="sha256") not in windows.catalog_index(catalog)["sha256"]:
            fail("resolved MUM is outside its own signed catalog: " + package)
        memberships += 1
        prepared.append((package, manifest, catalog))
    summary = dict(catalogs=len(prepared), resident_catalogs=resident, packages=sorted(selected), mum_memberships=memberships, chain_checks=len(chains), package_action_additions=sorted(wrappers), catalog_database_rebuilt=False, signature_audit="completed" if audit else "not-performed", validation="MUM membership; signature and timestamp chains audited" if audit else "MUM membership only; signature and chain audit not performed")
    return dict(files=prepared, summary=summary)

def apply_package_catalogs(root, source, features, population, prepared=None):
    """Publish checked MUM/CAT bytes and CatRoot aliases on a candidate tree.

    prepared must be the unchanged result of prepare_package_catalogs against
    this baseline. If omitted, preparation runs first. This mutates root and
    preserves existing file security; the caller owns cross-phase rollback.
    Native trust-provider policy and catalog database rebuilding are separate.
    """
    if prepared == None:
        prepared = prepare_package_catalogs(root, source, features, population)
    # MUM membership and requested audits have passed. Read-only
    # planning (and any explicit payload audit) has finished before publication.
    names = {p.lower(): p for p in root.files}
    manifest_security = new_package_manifest_security(root)
    installed = {a.package.lower():True for a in population.deployment_actions(changed_only=True) if a.action == 3}
    catalog_security = {flag:new_package_catalog_security(root, flag) for flag in [False, True]}
    # All planning and admission checks have finished. Publish independently
    # owned bytes, not parsed catalogs and their membership/signature indexes.
    # A batch shares one bounded decoded cache across the entire metadata set.
    packed = binary.snapshot_many([file for _, manifest, catalog in prepared["files"] for file in [manifest, catalog]], maximum=512<<20, cache_bytes=1<<20)
    for i, (package, _, _) in enumerate(prepared["files"]):
        manifest, catalog = packed[2*i], packed[2*i+1]
        _replace(root, "/Windows/servicing/Packages/" + package + ".mum", manifest, names, new_security=manifest_security)
        path = "/Windows/servicing/Packages/" + package + ".cat"
        new = path.lower() not in names
        _replace(root, path, catalog, names, new_security=catalog_security[package.lower() in installed])
        target = "/Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/" + package + ".cat"
        if new:
            actual = names.get(target.lower(), target)
            if root.find(actual) != None:
                root.remove(actual)
            root.hardlink(names[path.lower()], actual)
            names[target.lower()] = actual
        else:
            _replace(root, target, catalog, names)
    print("package catalogs installed", prepared["summary"]["catalogs"])
    return prepared["summary"]

