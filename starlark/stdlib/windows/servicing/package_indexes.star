"""CBS package metadata indexes, independent of package lifecycle state.

These are MUM-derived lookup/dependency records. Planning them does not prove
manifest resolution, payload staging, installation, owner state or completion.
No CurrentState, Owners, session, Active or completion records are produced.
"""

def _package_name(identity):
    language = identity.attribute("language", "neutral")
    return "~".join([identity.attribute("name"), identity.attribute("publicKeyToken"), identity.attribute("processorArchitecture"), "" if language.lower() in ["neutral", "none", ""] else language, identity.attribute("version")])

_NS = "urn:schemas-microsoft-com:asm.v3"
_CBS = "/Microsoft/Windows/CurrentVersion/Component Based Servicing/"

def _safe_name(name):
    if not name or len(name) > 16383 or any([c in name for c in ["/", chr(92), chr(0)]]) or name in [".", ".."]:
        fail("unsafe CBS metadata index name")
    return name

def _family(identity):
    parts = _package_name(identity).split("~")
    if len(parts) != 5 or not all(parts[:3]):
        fail("CBS package index requires a complete identity")
    return _safe_name("~".join(parts[:4] + ["0.0.0.0"]))

def _component_key(identity):
    version = identity.attribute("version").split(".")
    if len(version) != 4 or any([not v or any([v[i] not in "0123456789" for i in range(len(v))]) or int(v) > 65535 for v in version]):
        fail("CBS component index requires a four-part version")
    scope = identity.attribute("versionScope", "")
    family_version = "0.0.0.0" if scope.lower() == "nonsxs" else ".".join(version[:2] + ["0", "0"])
    fields = [identity.attribute("name"), "Culture=" + identity.attribute("language", "neutral")]
    kind = identity.attribute("type", "")
    if kind:
        fields.append("Type=" + kind)
    fields += ["Version=" + family_version, "PublicKeyToken=" + identity.attribute("publicKeyToken"), "ProcessorArchitecture=" + identity.attribute("processorArchitecture")]
    if scope:
        fields.append("versionScope=" + scope)
    data = bytes(", ".join(fields))
    # Both native key forms use the same readable-prefix canonicalization.
    # ComponentDetect retains the normalized family version in the full hash;
    # Winners omits it. Do not reuse the Winners hash for this index.
    prefix, culture, unused_hash = windows.csi_winner_family_key(data).rsplit("_", 2)
    hash = "%x" % windows.csi_identity_hash(data)
    return prefix + "_" + family_version + "_" + culture + "_" + "0" * (16 - len(hash)) + hash, ".".join([str(int(v)) for v in version])

def plan_servicing_package_indexes(file):
    """Derive value-scoped native indexes from one exact package MUM.

    PackageDetect stores the parent-integration enum, not a state. Standalone
    blocks omit their own identities but still recurse into nested blocks.
    UpdateDetect records parent update references only, never local ones.
    ComponentDetect retains every applicable updateComponent target and source,
    with the base elevation (not the source payload's alternative-target bit).
    No applicability pruning.
    Returned patches are not authorization to apply or to register a package.
    """
    root = binary.xml(file).root
    if root.namespace != _NS or root.name != "assembly":
        fail("CBS metadata indexes require an asm.v3 assembly")
    identity = root.child("assemblyIdentity", namespace=_NS)
    package = root.child("package", namespace=_NS)
    if identity == None or package == None:
        fail("CBS metadata indexes require a package identity/declaration")
    name = _safe_name(_package_name(identity))
    patches = {}
    def add(index, key, value_name, kind, value):
        key, value_name = _safe_name(key), _safe_name(value_name)
        # Native SetValue replaces a repeated exact index entry in traversal
        # order. Keep unrelated packages' records outside this patch list.
        patches[(index, key.lower(), value_name.lower())] = dict(key=_CBS + index + "/" + key, name=value_name, type=kind, value=value)
    add("PackageIndex", _family(identity), name, "REG_DWORD", 0)
    special_index = {"Foundation": "System", "Product": "Product"}.get(package.attribute("releaseType", ""))
    if special_index != None:
        add("PackageIndex", special_index, name, "REG_DWORD", 0)
    queue = list(package.children_named("parent", namespace=_NS))
    for position in range(65536):
        if position == len(queue):
            break
        parent = queue[position]
        integration = {"": 2, "separate": 2, "delegate": 3, "subsume": 4, "standalone": 1}.get(parent.attribute("integrate", ""))
        if integration == None:
            fail("unsupported CBS parent integration")
        if integration != 1:
            for target in parent.children_named("assemblyIdentity", namespace=_NS):
                add("PackageDetect", _family(target), name, "REG_DWORD", integration)
        queue.extend(parent.children_named("parent", namespace=_NS))
        if len(queue) > 65536:
            fail("CBS parent metadata index traversal exceeds bound")
    for update in package.children_named("update", namespace=_NS):
        update_name = _safe_name(update.attribute("name"))
        nodes = [(n, 0) for n in update.children if n.namespace == _NS and n.name in ["applicable", "selectable"]]
        for position in range(1048576):
            if position == len(nodes):
                break
            node, depth = nodes[position]
            if depth > 128:
                fail("CBS condition metadata index traversal exceeds depth")
            if node.name == "detectUpdate":
                references = [n for n in node.children if n.namespace == _NS]
                if not references or len(references) > 65536 or any([r.name not in ["parent", "update"] for r in references]):
                    fail("CBS update detector requires bounded parent/local references")
                # ServerManager-UX has alternative parent updates. Each parent
                # contributes an index record; local references never do.
                for reference in references:
                    if reference.name == "parent":
                        add("UpdateDetect", reference.attribute("name"), name, "REG_DWORD", 0)
            elif node.name == "updateComponent":
                elevation = {"revision": 2, "distribution": 4, "build": 8, "version": 32, "install": 128}.get(node.attribute("elevate", ""))
                targets = node.children_named("assemblyIdentity", namespace=_NS)
                if elevation == None or not targets or len(targets) != len(node.children):
                    fail("unsupported CBS component dependency declaration")
                # ComponentDetect stores the base elevation, unlike the CSI
                # source secondary flags, which add bit 0 for alternatives.
                flags = elevation
                for target in targets:
                    key, version = _component_key(target)
                    add("ComponentDetect", key, name + "." + update_name, "REG_SZ", version + "@" + str(flags))
            elif node.name in ["applicable", "selectable"]:
                nodes.extend([(n, depth + 1) for n in node.children if n.namespace == _NS])
                if len(nodes) > 1048576:
                    fail("CBS condition metadata index traversal exceeds bound")
    return list(patches.values())
