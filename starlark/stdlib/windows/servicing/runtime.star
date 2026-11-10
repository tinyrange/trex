"""Exact winner-transition runtime analysis, not an installer queue or application.

Primitive file/registry effects, dual-mode driver operations and advanced
installer phase/inspection policy remain separate from equivalence predicates.
Record identity is the stable transition label; component_identity is the exact
side-specific source identity, or None for incomplete inspection-only fixtures.
Only the latter identifies exact payloads; native FileInfo interning has its
own servicing-family comparison for supported version scopes.
"""

def _runtime_manifest_documents(analysis):
    # Resolve exact sides first, then parse bounded groups of owned snapshots.
    # This does not select winners or waive the independent MOF predicate.
    sources = {}
    for change in analysis["winner_changes"]:
        identity = change["identity"]
        d = windows.csi_identity(identity)
        marker = ", Version=" + d.version + ","
        if str(identity).count(marker) != 1:
            fail("ambiguous version in CSI transition identity")
        for side in ["shadowed", "winner"]:
            version = change[side]
            if not version: continue
            key = str(identity).replace(marker, ", Version=" + version + ",").lower()
            if key in sources: continue
            file = analysis["manifests"].get(key) or analysis["resident_manifests"].get(key)
            if file == None: fail("missing exact runtime manifest: " + key)
            sources[key] = file
    keys = list(sources)
    documents = {}
    for start in range(0, len(keys), 256):
        batch = keys[start:start+256]
        roots = binary.xml_many([sources[key] for key in batch], discard_whitespace=True, workers=4)
        for key, document in zip(batch, roots):
            documents[key] = (sources[key], document.root)
    return documents

def analyze_servicing_runtime(analysis):
    """Capture manifest-bound component transitions and declaration inventories from composition analysis; MOF equivalence is not an installer queue."""
    parsed_documents = _runtime_manifest_documents(analysis)
    transitions = []
    mof_components = 0
    mof_declarations = 0
    mof_equivalent = 0
    for change in analysis["winner_changes"]:
        identity = change["identity"]
        d = windows.csi_identity(identity)
        marker = ", Version=" + d.version + ","
        if str(identity).count(marker) != 1:
            fail("ambiguous version in CSI transition identity")
        files = []
        documents = {}
        component_identities = {}
        directives = []
        mofs = []
        for side in ["shadowed", "winner"]:
            version = change[side]
            if not version:
                files.append(None)
                directives.append({})
                mofs.append(0)
                continue
            component_identity = bytes(str(identity).replace(marker, ", Version=" + version + ","))
            component_identities["before" if side == "shadowed" else "after"] = component_identity
            key = str(component_identity).lower()
            file, root = parsed_documents[key]
            documents["before" if side == "shadowed" else "after"] = (file, root)
            counts = {}
            mof_count = 0
            for child in root.children:
                tag = (child.namespace, child.name)
                counts[tag] = counts.get(tag, 0) + 1
                if tag == ("urn:schemas-microsoft-com:asm.v3", "mof"):
                    mof_count += 1
            files.append(file)
            directives.append(counts)
            mofs.append(mof_count)
        equivalent = None
        if mofs[0] or mofs[1]:
            mof_components += 1
            mof_declarations += mofs[1]
            if files[0] != None and files[1] != None:
                equivalent = windows.csi_mof_equivalent(files[0], files[1])
                if equivalent:
                    mof_equivalent += 1
            else:
                equivalent = False
        transitions.append(dict(identity = identity, component_identities = component_identities, before = files[0], after = files[1], documents = documents, directives = directives, mof_equivalent = equivalent))
    return dict(transitions = transitions, mof_components = mof_components, mof_declarations = mof_declarations, mof_equivalent = mof_equivalent)



def servicing_runtime_manifest_root(change, side):
    """Return the captured immutable XML root only while its transition source binding matches; otherwise parse the replacement."""
    # Runtime analysis owns immutable parsed manifest snapshots. Reuse its
    # immutable XML tree, but never apply it to a replaced transition input.
    captured = change.get("documents", {}).get(side)
    if captured != None and captured[0] == change[side]:
        return captured[1]
    return binary.xml(change[side], discard_whitespace=True).root


def _runtime_declarations(change, side):
    cached = change.setdefault("declarations", {})
    captured = cached.get(side)
    if captured == None or captured[0] != change[side]:
        captured = (change[side], windows.assembly_declarations(servicing_runtime_manifest_root(change, side)))
        cached[side] = captured
    return captured[1]

def _declaration_security_definitions(declarations):
    definitions = {}
    for node in declarations.security_definitions:
        if not node.name or not node.sddl:
            fail("runtime security definition requires name and sddl")
        if node.name in definitions:
            fail("duplicate runtime security definition: " + node.name)
        definitions[node.name] = dict(name=node.name, sddl=node.sddl, operation_hint=node.operation_hint, attributes=node.attributes)
    return definitions

def _declaration_boot_critical(declarations):
    for ids in declarations.memberships:
        if len(ids) != 1:
            fail("category membership requires one identity")
        category = ids[0]
        if category.name.lower() == "microsoft.windows.categories" and category.publicKeyToken.lower() == "365143bb27e7ac8b" and category.typeName.lower() == "bootcritical" and category.version == "1.0.0.0":
            return True
    return False

def _runtime_directory_macro(template, target, architecture):
    fields = template.split(")", 1)
    if not template.startswith("$(") or len(fields) != 2 or "$(" in fields[1] or ")" in fields[1]:
        fail("unsupported runtime destination template: " + template)
    if fields[1] and not fields[1].startswith("\\"):
        fail("runtime directory macro must end at a path boundary")
    return windows.csi_file_directory_macro(target, architecture, fields[0][2:]), fields[1]



def servicing_manifest_boot_critical(root):
    """Bounded WcpManifest::IsBootCritical category membership predicate."""
    if root.namespace not in ["urn:schemas-microsoft-com:asm.v1", "urn:schemas-microsoft-com:asm.v3"]:
        fail("unsupported servicing manifest namespace")
    for memberships in root.children:
        if memberships.name != "memberships" or memberships.namespace != root.namespace:
            continue
        for membership in memberships.children:
            if membership.name != "categoryMembership" or membership.namespace != root.namespace:
                continue
            ids = [n for n in membership.children if n.name == "id" and n.namespace == root.namespace]
            if len(ids) != 1:
                fail("category membership requires one identity")
            category = ids[0]
            if category.attribute("name", "").lower() == "microsoft.windows.categories" and category.attribute("publicKeyToken", "").lower() == "365143bb27e7ac8b" and category.attribute("typeName", "").lower() == "bootcritical" and category.attribute("version", "") == "1.0.0.0":
                return True
    return False


def analyze_servicing_file_paths(runtime, target):
    """Select native directory IDs, not resolved paths or authorized effects.

    Only direct assembly files with a leading directory macro are decomposed.
    Missing destinationPath remains explicit; driver projection policy is not
    inferred from its absence. Profile lookup and offline root mapping must
    resolve every directory ID before any filesystem changes can be planned.
    """
    records = []
    directory_ids = {}
    links = []
    writable_files = 0
    for change in runtime["transitions"]:
        for side in ["before", "after"]:
            manifest = change[side]
            if manifest == None:
                continue
            declarations = _runtime_declarations(change, side)
            if len(declarations.architectures) != 1:
                fail("runtime file analysis requires one exact root identity")
            architecture = declarations.architectures[0]
            boot_critical = _declaration_boot_critical(declarations)
            managed_assembly = declarations.managed_assembly
            for node in declarations.files:
                name = node.name if node.name != None else ""
                destination_name = windows.csi_file_destination_name(name, node.destination_name)
                template = node.template
                attributes = windows.csi_file_attributes(node.attributes)
                compress = node.compress
                if compress not in ["true", "false"]:
                    fail("unsupported native file compress value")
                writable = node.writable_type
                if writable not in [None, "systemData", "applicationData"]:
                    fail("unsupported writeableType: " + str(writable))
                directory_id = None
                suffix = None
                if template != None:
                    directory_id, suffix = _runtime_directory_macro(template, target, architecture)
                    directory_ids[directory_id] = directory_ids.get(directory_id, 0) + 1
                if writable != None:
                    writable_files += 1
                for link in node.links:
                    if link.has_content:
                        fail("unsupported runtime file link content")
                    for attribute in link.attributes:
                        if attribute["namespace"] == "xmlns":
                            continue
                        if attribute["namespace"] or attribute["name"] != "destination":
                            fail("unsupported runtime file link attribute")
                    destination = link.destination
                    fields = destination.rsplit("\\", 1)
                    if len(fields) != 2 or not fields[1]:
                        fail("runtime file link requires an explicit destination leaf")
                    link_id, link_suffix = _runtime_directory_macro(fields[0], target, architecture)
                    links.append(dict(identity = change["identity"], component_identity = change.get("component_identities", {}).get(side), side = side, name = name, destination_name = fields[1], template = destination, directory_id = link_id, suffix = link_suffix, writable_type = writable, attributes = attributes, boot_critical = boot_critical, managed_assembly = managed_assembly, compress = compress == "true", load_from = node.load_from, kind = "link"))
                records.append(dict(identity = change["identity"], component_identity = change.get("component_identities", {}).get(side), side = side, name = name, destination_name = destination_name, template = template, directory_id = directory_id, suffix = suffix, writable_type = writable, attributes = attributes, boot_critical = boot_critical, managed_assembly = managed_assembly, compress = compress == "true", load_from = node.load_from))
    return dict(records = records, links = links, directory_ids = directory_ids, writable_files = writable_files)


def _offline_absolute_components(value):
    # This recipe supports a single DOS volume, not UNC/device namespaces,
    # drive-relative paths, alternate streams, or normalization by guessing.
    if type(value) != "string" or len(value) < 3 or value[0].lower() not in "abcdefghijklmnopqrstuvwxyz" or value[1:3] != ":\\":
        fail("offline path must be drive-absolute")
    if any([c in value for c in ["/", "\x00", "\n", "\r", "\t", "%", "*", "?", '"', "<", ">", "|"]]) or ":" in value[2:]:
        fail("unsupported offline path syntax")
    tail = value[3:]
    if tail.endswith("\\"):
        tail = tail[:-1]
    parts = tail.split("\\") if tail else []
    for part in parts:
        if not part or part in [".", ".."] or part.endswith(".") or part.endswith(" "):
            fail("ambiguous offline path component")
    return value[:2], parts


def offline_servicing_path_context(system_root, windows_directory):
    """Validate this recipe's one-volume, image-relative path mapping.

    SystemRoot is read from the offline SOFTWARE hive, not the host environment.
    windows_directory is an explicit absolute virtual path within that image.
    It must retain the recorded Windows directory's spelling (ignoring case),
    because the native drive mapping targets the offline Windows parent.
    This is deliberately narrower than native arbitrary provider mappings.
    """
    drive, components = _offline_absolute_components(system_root)
    if len(components) != 1:
        fail("offline recipe requires a one-component Windows directory")
    if type(windows_directory) != "string" or not windows_directory.startswith("/") or "\\" in windows_directory or "\x00" in windows_directory:
        fail("invalid image-relative Windows directory")
    image_components = windows_directory[1:].split("/")
    if any([not p or p in [".", ".."] or ":" in p or p.endswith(".") or p.endswith(" ") for p in image_components]):
        fail("invalid image-relative Windows directory")
    if image_components[-1].lower() != components[0].lower():
        fail("offline Windows directory differs from recorded SystemRoot")
    return dict(drive = drive, system_root = drive + "\\" + components[0], image_parent = "/" + "/".join(image_components[:-1]))


def map_servicing_offline_path(context, value):
    """Map an already expanded DOS path; never infer another volume's mount."""
    drive, components = _offline_absolute_components(value)
    if drive.lower() != context["drive"].lower():
        fail("unmapped offline volume: " + drive)
    return context["image_parent"].rstrip("/") + "/" + "/".join(components)


def expand_servicing_environment_path(context, value):
    """Expand only the three variables installed by the native offline provider.

    ProfileList and ProgramFiles values use this provider, not the host user's
    environment. Unknown variables fail closed rather than being substituted
    with guessed user/profile paths. Expansion is a single pass.
    """
    if type(value) != "string":
        fail("offline environment path must be a string")
    variables = {"systemdrive": context["drive"], "systemroot": context["system_root"], "windir": context["system_root"]}
    parts = value.split("%")
    if len(parts) % 2 == 0:
        fail("unclosed offline environment variable")
    for i in range(1, len(parts), 2):
        key = parts[i].lower()
        if key not in variables:
            fail("unsupported offline environment variable: " + parts[i])
        parts[i] = variables[key]
    expanded = "".join(parts)
    _offline_absolute_components(expanded)
    return expanded


def servicing_registry_path_roots(software, windows_directory):
    """Resolve registry-backed roots for a no-SID offline servicing profile.

    The caller supplies the image's SOFTWARE hive. No host registry, mounted
    volume, current-user profile, or hardcoded Default directory participates.
    Other special-directory IDs remain absent until separately resolved.
    """
    nt = software.find("Microsoft/Windows NT/CurrentVersion")
    current = software.find("Microsoft/Windows/CurrentVersion")
    profiles = software.find("Microsoft/Windows NT/CurrentVersion/ProfileList")
    if nt == None or current == None or profiles == None:
        fail("missing offline path registry keys")
    context = offline_servicing_path_context(nt.values.get("SystemRoot"), windows_directory)
    # The recipe supplies one offline volume root, mapped to image_parent.
    source_roots = {36: context["system_root"], 0x100000: context["drive"] + "\\"}
    for directory_id, name in [(38, "ProgramFilesDir"), (42, "ProgramFilesDir (x86)"), (43, "CommonFilesDir"), (44, "CommonFilesDir (x86)")]:
        source_roots[directory_id] = expand_servicing_environment_path(context, current.values.get(name))
    for directory_id, name in [(0x110000, "Default"), (0xd0000, "ProgramData"), (0x3e, "ProfilesDirectory")]:
        source_roots[directory_id] = expand_servicing_environment_path(context, profiles.values.get(name))
    roots = {}
    for directory_id, source_path in source_roots.items():
        roots[directory_id] = map_servicing_offline_path(context, source_path)
    return dict(context = context, source_roots = source_roots, roots = roots)


def servicing_file_path_roots(software, windows_directory, target):
    """Resolve the observed amd64 offline directory IDs; no file effects."""
    if target != "amd64":
        fail("unsupported offline directory target architecture")
    result = servicing_registry_path_roots(software, windows_directory)
    sources = result["source_roots"]
    # CUserProfile::GetSpecialDirectoryPath, WCP 10.0.26100.9441.
    # Start Menu/Startup use ProgramData, not the no-SID Default profile.
    # Public is ProfilesDirectory + Public, not the registry Public value.
    for directory_id, parent_id, suffix in [
        (37, 36, "System32"),
        (0x50000, 36, "System"),
        (41, 36, "SysWOW64"),
        (0x20000, 36, "System32\\Drivers"),
        (0xe0000, 36, "SysWOW64\\Drivers"),
        (0x70000, 36, "System32\\wbem"),
        (0xf0000, 36, "SysWOW64\\wbem"),
        (0x30000, 36, "Inf"),
        (0xa0000, 36, "Help"),
        (20, 36, "Fonts"),
        (0xb0000, 36, "AppPatch"),
        (0xc0000, 0x3e, "Public"),
        (7, 0xd0000, "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        (11, 0xd0000, "Microsoft\\Windows\\Start Menu"),
    ]:
        sources[directory_id] = sources[parent_id].rstrip("\\") + "\\" + suffix
        result["roots"][directory_id] = map_servicing_offline_path(result["context"], sources[directory_id])
    return result


def resolve_servicing_file_paths(file_paths, path_roots, driver_projection_candidates = False):
    """Resolve explicit paths and retain bounded native unprojected work.
    Ordinary identities without destinationPath use ProcessUnprojectedFile.
    In the ordinary transaction (no 0x400 driver override), native
    DoComponentOperation also forces dual-mode drivers down that source-only
    path, even with destinationPath. Their runtime projection belongs to the
    driver installer, not the generic file installer. Unprojected records still
    require source/hash processing; incomplete identities remain unresolved.

    driver_projection_candidates is only for independently checking actual
    driver-installer outputs against declared hashes. It is not permission to
    feed driver files into the ordinary file/FileMap installer.
    """
    if type(driver_projection_candidates) != "bool":
        fail("driver projection candidate selection must be explicit")
    resolved = []
    unresolved = []
    unprojected = []
    links = []
    for record in file_paths["records"] + file_paths.get("links", []):
        identity = record.get("component_identity")
        if not driver_projection_candidates and identity != None and windows.csi_identity(identity).type.lower() == "dualmodedriver":
            # WCP DoComponentOperation leaves the projection boolean zero for
            # dual-mode drivers. InstallComponent's source-only branch returns
            # before its runtime-link loop; retain the primary, not the links.
            if record.get("kind") != "link":
                unprojected.append(record)
            continue
        directory_id = record["directory_id"]
        if directory_id == None:
            identity = record.get("component_identity")
            if record.get("kind") != "link" and record.get("template") == None and identity != None and windows.csi_identity(identity).type.lower() in ["", "win32"]:
                unprojected.append(record)
            else:
                unresolved.append(record)
            continue
        if directory_id not in path_roots["source_roots"]:
            fail("unresolved runtime file directory: " + str(directory_id))
        name = record["destination_name"]
        if not name or "\\" in name or "/" in name:
            fail("runtime destination name is not a leaf")
        suffix = record["suffix"]
        if type(suffix) != "string" or (suffix and not suffix.startswith("\\")):
            fail("invalid runtime directory suffix")
        source = path_roots["source_roots"][directory_id].rstrip("\\") + suffix
        if not source.endswith("\\"):
            source += "\\"
        source += name
        destination = map_servicing_offline_path(path_roots["context"], source)
        item = dict(record)
        item["destination"] = destination
        if record.get("kind") == "link":
            links.append(item)
        else:
            resolved.append(item)
    return dict(records = resolved, links = links, unresolved = unresolved, unprojected = unprojected)

def _runtime_security_definitions(root):
    nodes = [root]
    for tag in ["trustInfo", "security", "accessControl", "securityDescriptorDefinitions", "securityDescriptorDefinition"]:
        nodes = [child for node in nodes for child in node.children if child.name == tag and child.namespace == root.namespace]
    definitions = {}
    for node in nodes:
        name = node.attribute("name", None)
        sddl = node.attribute("sddl", None)
        if not name or not sddl:
            fail("runtime security definition requires name and sddl")
        if name in definitions:
            fail("duplicate runtime security definition: " + name)
        definitions[name] = dict(name = name, sddl = sddl, operation_hint = node.attribute("operationHint", None), attributes = node.attributes)
    return definitions


def analyze_servicing_file_security(runtime):
    """Resolve manifest-local declarations, not effective object permissions.

    Missing references, the CSI (inherit) marker, and explicit SDDL remain
    distinct. Neither operationHint nor SDDL is interpreted as permission to
    change an object; native defaulting, inheritance and commit policy are
    separate from this analysis. Preserve attributes for that later policy.
    """
    records = []
    for change in runtime["transitions"]:
        for side in ["before", "after"]:
            if change[side] == None:
                continue
            declarations = _runtime_declarations(change, side)
            definitions = _declaration_security_definitions(declarations)
            for file in declarations.files:
                references = file.security_references
                if len(references) > 1:
                    fail("duplicate runtime file security reference")
                descriptor = None
                reference_attributes = None
                if references:
                    reference = references[0]
                    name = reference.name
                    if name not in definitions:
                        fail("unresolved runtime file security reference: " + str(name))
                    descriptor = definitions[name]
                    reference_attributes = reference.attributes
                records.append(dict(identity = change["identity"], component_identity = change.get("component_identities", {}).get(side), side = side, name = file.name, descriptor = descriptor, reference_attributes = reference_attributes))
    return records


def analyze_servicing_directories(runtime, target):
    """Read ordered directory declarations, never infer creation or ownership.

    Only direct assembly/directories/directory nodes participate. Retain raw
    attributes (including owner and compression) for native operation policy.
    A repeated destination is not collapsed, and each side resolves security
    definitions in its own manifest. Implicit file parents are not declarations.
    """
    records = []
    for change in runtime["transitions"]:
        for side in ["before", "after"]:
            if change[side] == None:
                continue
            identity = change.get("component_identities", {}).get(side)
            if identity != None and windows.csi_identity(identity).type.lower() == "dualmodedriver":
                # Ordinary WCP DoComponentOperation returns after its file loop
                # for a dual-mode driver, before processing directories.
                continue
            declarations = _runtime_declarations(change, side)
            if len(declarations.architectures) != 1:
                fail("runtime directory analysis requires one exact root identity")
            architecture = declarations.architectures[0]
            definitions = _declaration_security_definitions(declarations)
            for node in declarations.directories:
                if node.tag != "directory":
                    fail("unsupported runtime directories child: " + node.tag)
                template = node.template
                directory_id, suffix = _runtime_directory_macro(template, target, architecture)
                references = node.security_references
                if len(references) > 1:
                    fail("duplicate runtime directory security reference")
                descriptor = None
                reference_attributes = None
                if references:
                    reference = references[0]
                    name = reference.name
                    if name not in definitions:
                        fail("unresolved runtime directory security reference: " + str(name))
                    descriptor = definitions[name]
                    reference_attributes = reference.attributes
                records.append(dict(identity = change["identity"], component_identity = change.get("component_identities", {}).get(side), side = side, name = template, directory_id = directory_id, suffix = suffix, attributes = node.attributes, descriptor = descriptor, reference_attributes = reference_attributes))
    return records


def resolve_servicing_directory_paths(records, path_roots):
    """Resolve declared directories only; unknown roots fail, not guess."""
    result = []
    for record in records:
        directory_id = record["directory_id"]
        if directory_id not in path_roots["source_roots"]:
            fail("unresolved runtime directory root: " + str(directory_id))
        suffix = record["suffix"]
        if type(suffix) != "string" or (suffix and not suffix.startswith("\\")):
            fail("invalid runtime directory suffix")
        source = path_roots["source_roots"][directory_id]
        if suffix:
            source = source.rstrip("\\") + suffix
        item = dict(record)
        item["destination"] = map_servicing_offline_path(path_roots["context"], source)
        result.append(item)
    return result


def compile_servicing_file_security(records):
    """Compile declaration bytes, retaining absent and CSI inherit separately.

    This does not map generic rights, supply defaults, inherit parent ACEs or
    authorize a filesystem mutation. Cache by exact SDDL, not definition name:
    names are local to each side of each manifest transition.
    """
    compiled = {}
    result = []
    for record in records:
        definition = record["descriptor"]
        state = "absent"
        data = None
        if definition != None:
            sddl = definition["sddl"]
            state = "inherit" if sddl == "(inherit)" else "explicit"
            if state == "explicit":
                if sddl not in compiled:
                    compiled[sddl] = windows.compile_sddl(sddl)
                data = compiled[sddl]
        result.append(dict(record = record, state = state, data = data))
    return result


def prepare_servicing_file_security(data):
    """Build the bounded ordinary-file setter input, not an applied descriptor.

    WCP ApplySecurityToObjectWithDefaults supplies System for each missing
    principal and empty unprotected ACLs for absent ACLs. CFile's option-4 path
    conveys protection separately and does not preserve input AI/AR bits.
    Generic rights are mapped by the native format API, which also validates
    all component extents before these fixed-header patches. The existing
    ACE bytes/order (including ID) otherwise survive until RTL inheritance.

    The caller must first select a descriptor. None/(inherit)/absent references
    are dispatch decisions, not descriptors. Present-NULL and defaulted controls
    remain unsupported here; they require the separate provider/current-object
    paths. No parent query, inheritance, final control pass or mutation occurs.
    """
    if data == None:
        fail("servicing security requires a selected descriptor")
    mapped = windows.map_file_security_rights(data)
    control = binary.read_u16le(mapped, 2)
    if mapped[1:2] != b"\x00" or control & ~0xbf14:
        fail("unsupported servicing security controls")
    output = binary.builder(limit = (1 << 20) + 40)
    output.append(mapped)
    # Revision-1 S-1-5-18 and a revision-2, zero-entry ACL. These defaults
    # come from the observed WCP setter, not a token or the parent owner.
    system = binary.decode("010100000000000512000000", "hex")
    empty_acl = binary.decode("0200080000000000", "hex")
    for offset, present, protected in [(4, 0, 0), (8, 0, 0), (12, 0x10, 0x2000), (16, 4, 0x1000)]:
        if binary.read_u32le(mapped, offset):
            continue
        if present and control & present:
            fail("NULL servicing ACL requires separate provider policy")
        output.align(4)
        output.patch_u32le(offset, output.size)
        output.append(empty_acl if present else system)
        control = (control | present) & ~protected
    output.patch_u16le(2, control & ~0xf00)
    return output.bytes()


def _servicing_security_bytes(control, owner, group, dacl, sacl):
    output = binary.builder(limit = 1 << 20)
    output.append(b"\x00" * 20)
    output.patch_u16le(0, 1)
    output.patch_u16le(2, control)
    for offset, part in [(4, owner), (8, group), (12, sacl), (16, dacl)]:
        if part == None:
            continue
        output.align(4)
        output.patch_u32le(offset, output.size)
        output.append(part)
    return output.bytes()


def build_servicing_file_security_request(data, parent):
    """Construct the bounded WCP ordinary-file request, not an NTFS effect.

    The caller selects the child descriptor and supplies the actual parent.
    This composes the proven defaulting, native-RTL inheritance and WCP final
    file-control policies. It does not select commit flags, authorize a write,
    set kernel security, handle directories or model token-dependent defaults.
    Present-NULL/defaulted child ACLs remain rejected by preparation.
    """
    if parent == None:
        fail("servicing file security requires the actual parent descriptor")
    prepared = prepare_servicing_file_security(data)
    inherited = windows.inherit_file_security(prepared, parent = parent)
    parts = windows.security_descriptor_parts(inherited)
    # WCP's file path clears AI/AR controls before its minimal-descriptor pass.
    # This bounded RTL constructor has already removed file propagation flags
    # and protected ID flags. Its ACLs therefore take the reconstruction path;
    # this is not a general GetMinimalSecurityDescriptor implementation.
    control = parts["control"] & ~0xf00
    sacl = parts["sacl"]
    if sacl != None and not control & 0x2000 and binary.read_u16le(sacl, 4) == 0:
        # WCP reconstructs an empty unprotected SACL as present-NULL. Empty
        # DACLs are deliberately not normalized this way.
        sacl = None
    descriptor = _servicing_security_bytes(control, parts["owner"], parts["group"], parts["dacl"], sacl)
    info = 15 | (0x80000000 if control & 0x1000 else 0x20000000) | (0x40000000 if control & 0x2000 else 0x10000000)
    return dict(security_information = info, descriptor = descriptor)


def build_servicing_created_security(parent, directory = False, token_default_dacl = None):
    """Build the bounded SYSTEM creation descriptor before WCP's setter.

    Models NULL file creator security, or directory creator O:SYG:SY, with
    SYSTEM owner/primary group and SYSTEM integrity. This is not a general
    token-dependent SeAssignSecurityEx implementation. The native NTFS path
    takes auto-DACL inheritance only when the parent has DACL_AUTO_INHERITED.
    Ordinary audit ACEs inherit when the parent SACL is auto-inherited;
    noninheritable parent audit ACEs do not propagate. If no DACL
    inherits, the caller must explicitly supply the subject token default DACL.
    Only nonpropagating allow ACEs with mapped file rights are supported there;
    legacy propagating SACL inheritance and other token/SACL policies
    remain fail-closed.
    """
    if parent == None:
        fail("servicing creation requires the actual parent descriptor")
    parts = windows.security_descriptor_parts(parent)
    if parts["resource_manager_control"] or not parts["control"] & 0x400 or parts["dacl"] == None:
        fail("servicing creation requires an auto-inherited parent DACL")
    # Legacy SACL inheritance does not mark inherited ACEs. Keep that
    # propagating case fail-closed until explicitly modeled.
    _validate_servicing_directory_audit(parts["sacl"], "parent", inheritable = bool(parts["control"] & 0x800))
    if token_default_dacl != None:
        acl = windows.acl_entries(token_default_dacl)
        if acl["revision"] != 2 or not acl["entries"]:
            fail("unsupported servicing token default DACL")
        for entry in acl["entries"]:
            if entry["type"] != 0 or entry["flags"] or entry["mask"] & ~0x1f01ff:
                fail("unsupported servicing token default DACL")
    initial = windows.inherit_file_security(windows.compile_sddl("O:SYG:SY"), parent = parent, directory = directory)
    inherited = windows.security_descriptor_parts(initial)
    dacl = inherited["dacl"]
    if dacl == None or not windows.acl_entries(dacl)["entries"]:
        if token_default_dacl == None:
            fail("servicing creation requires token default-DACL fallback")
        dacl = token_default_dacl
    # Native flags are 0x4001 or 0x4003 according to the parent's SACL AI
    # control, even when that SACL is absent/NULL. SYSTEM adds no label.
    sacl = inherited["sacl"]
    control = 0x8404 | (parts["control"] & 0x800) | (0x10 if sacl != None else 0)
    return _servicing_security_bytes(control, inherited["owner"], inherited["group"], dacl, sacl)


def _validate_servicing_directory_audit(sacl, role, inheritable = False):
    if sacl == None:
        return
    acl = windows.acl_entries(sacl)
    if acl["revision"] != 2:
        fail("unsupported servicing directory " + role + " SACL")
    for entry in acl["entries"]:
        flags = 0xdf if inheritable else 0xc0
        mask = 0x11f01ff if inheritable else 0x1f01ff
        if entry["type"] != 2 or entry["flags"] & ~flags or entry["mask"] & ~mask:
            fail("unsupported servicing directory " + role + " SACL")


def build_servicing_directory_security_request(data, parent, default = False):
    """Build a bounded explicit or selected-default directory request.

    This is WCP's directory setter input, not creation-time inheritance or
    authorization. Covers protected DACLs, explicit unprotected DACLs and
    ordinary audit SACLs, including OI/CI/NP/IO/ID inheritance flags.
    Other control/SACL forms fail closed until separately established.
    """
    if parent == None or (data == None and not default):
        fail("servicing directory security requires selected and parent descriptors")
    if default:
        if data != None:
            fail("default directory selection cannot carry a descriptor")
        data = windows.compile_sddl("O:SYG:SY")
    parts = windows.security_descriptor_parts(data)
    inherited_parent = windows.security_descriptor_parts(parent)
    allowed_controls = [0x8000] if default else [0x8004, 0x9004, 0x9404, 0x9014]
    if parts["resource_manager_control"] or parts["control"] not in allowed_controls or (not default and parts["dacl"] == None):
        fail("unsupported servicing directory security controls")
    _validate_servicing_directory_audit(inherited_parent["sacl"], "parent", inheritable=True)
    _validate_servicing_directory_audit(parts["sacl"], "selected", inheritable=True)
    system = binary.decode("010100000000000512000000", "hex")
    prepared = _servicing_security_bytes(parts["control"], parts["owner"] or system, parts["group"] or system, parts["dacl"], parts["sacl"])
    inherited = windows.inherit_file_security(prepared, parent = parent, directory = True)
    result = windows.security_descriptor_parts(inherited)
    # Unlike the file path, WCP retains directory AI controls and requests
    # both auto-inheritance passes. Inherit-only generic ACEs remain generic.
    if result["dacl"] == None:
        fail("default directory security requires inherited DACL")
    control = result["control"] | 0x300
    descriptor = _servicing_security_bytes(control, result["owner"], result["group"], result["dacl"], result["sacl"])
    return dict(security_information = 0x9000000f if control & 0x1000 else 0x3000000f, descriptor = descriptor)


def _servicing_registry_sacl(sacl, parent = False):
    audit = []
    label = None
    if sacl != None:
        acl = windows.acl_entries(sacl)
        if acl["revision"] != 2:
            fail("unsupported servicing registry SACL revision")
        for entry in acl["entries"]:
            if entry["type"] == 17:
                data = entry["data"]
                if label != None or len(data) != 20 or data[8:16] != binary.decode("0101000000000010", "hex") or entry["mask"] & ~7 or entry["flags"] & ~(0x1f if parent else 0):
                    fail("unsupported servicing registry mandatory label")
                label = data
            elif entry["type"] == 2:
                audit.append(entry["data"])
            else:
                fail("unsupported servicing registry SACL category")
    return audit, label


def build_servicing_registry_security_request(data, parent = None, default = False, defer_inheritance = False):
    """Build the bounded explicit WCP key setter request, not a hive effect.

    Missing principals default to SYSTEM; key rights use container inheritance.
    Empty unprotected audit ACLs disappear, protected empty ACLs survive.
    A selected explicit label suppresses parent labels and requests LABEL_SECURITY
    information; a merely inherited label does not request that category.
    Audit entries precede the label regardless of selected input order.
    default=True selects the observed GetRegistryDefaultSecurity descriptor,
    with no explicit declaration. defer_inheritance=True models the separate
    setter flag: no parent query, no generic-rights/creator transformation,
    and original ACE ordering retained for later propagation.
    No kernel assignment, token ownership authorization, key creation, or
    transaction ordering is implied. Absent/NULL child DACLs and
    protected NULL SACLs remain outside this explicit-declaration path.
    """
    if type(default) != "bool" or type(defer_inheritance) != "bool":
        fail("servicing registry request flags require booleans")
    if default:
        if data != None:
            fail("default registry selection cannot carry a descriptor")
        data = windows.compile_sddl("O:SYG:SYD:AIARS:AIAR")
    if data == None or (parent == None and not defer_inheritance):
        fail("servicing registry security requires selected and parent descriptors")
    parts = windows.security_descriptor_parts(data)
    ancestor = None if defer_inheritance else windows.security_descriptor_parts(parent)
    for item in [parts] if ancestor == None else [parts, ancestor]:
        if item["resource_manager_control"] or item["control"] & ~0xbf14:
            fail("unsupported servicing registry security controls")
    if parts["dacl"] == None:
        fail("servicing registry explicit request requires non-NULL DACL")
    if parts["sacl"] == None and parts["control"] & 0x2010 == 0x2010:
        fail("unsupported servicing registry protected NULL SACL")
    audit, label = _servicing_registry_sacl(parts["sacl"])
    system = binary.decode("010100000000000512000000", "hex")
    owner = parts["owner"] or system
    group = parts["group"] or system
    if defer_inheritance:
        dacl = windows.acl_entries(parts["dacl"])
        if dacl["revision"] != 2 or any([e["type"] not in [0, 1, 9] or e["flags"] & ~0xdf for e in dacl["entries"]]):
            fail("unsupported deferred servicing registry DACL")
        if any([e["flags"] & ~0xdf for e in windows.acl_entries(parts["sacl"])["entries"]]) if parts["sacl"] != None else False:
            fail("unsupported deferred servicing registry SACL")
        sacl = parts["sacl"] if audit or label != None or parts["control"] & 0x2000 else None
        control = 0x8514 | (parts["control"] & 0x3000) | (0xa00 if sacl != None else 0)
        info = 15 | (0x80000000 if control & 0x1000 else 0x20000000) | (0x40000000 if control & 0x2000 else 0x10000000) | (0x10 if label != None else 0)
        return dict(security_information = info, descriptor = _servicing_security_bytes(control, owner, group, parts["dacl"], sacl))
    parent_audit, parent_label = _servicing_registry_sacl(ancestor["sacl"], parent = True)
    sacl = _servicing_acl_bytes(audit) if audit or parts["control"] & 0x2000 else None
    parent_sacl = _servicing_acl_bytes(parent_audit) if parent_audit else None
    prepared = _servicing_security_bytes((parts["control"] & ~0x10) | (0x10 if sacl != None else 0), owner, group, parts["dacl"], sacl)
    prepared_parent = _servicing_security_bytes((ancestor["control"] & ~0x10) | (0x10 if parent_sacl != None else 0), ancestor["owner"], ancestor["group"], ancestor["dacl"], parent_sacl)
    result = windows.security_descriptor_parts(windows.inherit_registry_security(prepared, parent = prepared_parent))
    entries = [] if result["sacl"] == None else [e["data"] for e in windows.acl_entries(result["sacl"])["entries"]]
    if label != None:
        entries.append(label)
    elif parent_label != None and not parts["control"] & 0x2000:
        inherited_label = windows.inherit_file_acl(_servicing_acl_bytes([parent_label]), owner, group, directory = True)
        entries.extend([e["data"] for e in windows.acl_entries(inherited_label)["entries"]])
    sacl = _servicing_acl_bytes(entries) if entries or result["sacl"] != None else None
    control = (result["control"] | 0x300) & ~0x10
    if sacl != None:
        control |= 0x10
    info = 15 | (0x80000000 if control & 0x1000 else 0x20000000) | (0x40000000 if control & 0x2000 else 0x10000000)
    if label != None:
        info |= 0x10
    return dict(security_information = info, descriptor = _servicing_security_bytes(control, owner, group, result["dacl"], sacl))


def assign_servicing_directory_security(current, request):
    """Assign the bounded directory request's metadata, not token authority.

    Native SeSetSecurityDescriptorInfoEx preserves bounded audit components,
    clears AR controls, retains AI and makes absent audit SACLs present-NULL.
    Existing mandatory labels are retained by the common category selection.
    Owner authorization must have been established separately; SYSTEM alone
    cannot assign the TrustedInstaller owner used by the conditional forms.
    """
    return _assign_servicing_security(current, request, directory = True)


def _servicing_acl_bytes(entries):
    output = binary.builder(limit = 0xffff)
    output.append(b"\x00" * 8)
    output.patch_u16le(0, 2)
    for entry in entries:
        output.append(entry)
    output.patch_u16le(2, output.size)
    output.patch_u16le(4, len(entries))
    return output.bytes()


def assign_servicing_file_security(current, request):
    """Construct the bounded kernel-assigned descriptor, without applying it.

    This models the observed NTFS SeSetSecurityDescriptorInfoEx flags-0x4000
    metadata transformation for the ordinary file request above. It is not a
    token authorization check or an NTFS transaction. The caller must supply
    the actual current descriptor, including labels shared by hardlinks.
    Audit updates preserve existing mandatory labels; other SACL categories
    require their own information-mask policy and fail closed here.
    """
    return _assign_servicing_security(current, request)


def _assign_servicing_security(current, request, directory = False, clear_labels = False):
    old = windows.security_descriptor_parts(current)
    parts = windows.security_descriptor_parts(request["descriptor"])
    control = parts["control"]
    expected_info = 15 | (0x80000000 if control & 0x1000 else 0x20000000) | (0x40000000 if control & 0x2000 else 0x10000000)
    if clear_labels:
        expected_info |= 0x10
    if request["security_information"] != expected_info:
        fail("unsupported servicing security information mask")
    if directory:
        if control not in [0x8f04, 0x9f04, 0x9f14]:
            fail("unsupported servicing directory assignment controls")
        _validate_servicing_directory_audit(parts["sacl"], "selected", inheritable=True)
        control = (control & ~0x300) | 0x10
    if old["resource_manager_control"] or old["control"] & ~0xbf14 or parts["resource_manager_control"] or (not directory and (control & ~0xb014 or control & 0x8014 != 0x8014)):
        fail("unsupported servicing security assignment controls")
    if parts["owner"] == None or parts["group"] == None or parts["dacl"] == None:
        fail("servicing security assignment requires principals and non-NULL DACL")
    dacl = windows.acl_entries(parts["dacl"])
    if dacl["revision"] != 2:
        fail("unsupported servicing DACL revision")
    entries = []
    seen_allow = {}
    for entry in dacl["entries"]:
        unsupported_flags = entry["flags"] & ~(0xf if control & 0x1000 else 0x1f) if directory else entry["flags"] & 0xf
        allowed_mask = 0x1f01ff | (0xf0000000 if directory and entry["flags"] & 8 else 0)
        if entry["type"] not in [0, 1, 9] or unsupported_flags or entry["mask"] & ~allowed_mask:
            fail("unsupported servicing DACL entry")
        # Native RtlpNormalizeAcl with no mapping argument removes exact
        # duplicate ordinary allows, even across other ACEs. It neither
        # unions differing masks nor removes duplicate denies/callbacks.
        if entry["type"] == 0:
            if entry["data"] in seen_allow:
                continue
            seen_allow[entry["data"]] = True
        entries.append(entry["data"])
    dacl = _servicing_acl_bytes(entries)
    audit = []
    labels = []
    for source, preserve_labels in [(parts["sacl"], False), (old["sacl"], True)]:
        if source == None:
            continue
        acl = windows.acl_entries(source)
        if acl["revision"] != 2:
            fail("unsupported servicing SACL revision")
        for entry in acl["entries"]:
            kind = entry["type"]
            if kind not in ([2, 3, 17] if preserve_labels else [2, 3]):
                fail("unsupported servicing SACL category")
            if preserve_labels:
                if kind == 17 and not clear_labels:
                    labels.append(entry["data"])
            else:
                # Native audit copying retains ACCESS_SYSTEM_SECURITY;
                # only effective allow ACEs clip that bit. The real Sense
                # task parent carries inherited audit mask 0x010d0000.
                if entry["flags"] & (~0xdf if directory else 0xf) or entry["mask"] & ~0x11f01ff:
                    fail("unsupported servicing audit entry")
                audit.append(entry["data"])
    sacl_entries = audit + labels
    # The kernel normalizes even a protected empty SACL to present-NULL.
    # DACL emptiness retains its different access-control meaning.
    sacl = _servicing_acl_bytes(sacl_entries) if sacl_entries else None
    return _servicing_security_bytes(control, parts["owner"], parts["group"], dacl, sacl)


def reduce_servicing_directory_declarations(records):
    """Reduce ordered declarations, not filesystem effects or commit authority.

    Models the bounded install/remove ProcessDirectory path: no repair,
    filter-list exclusions, implicit ancestors, compression effects or native
    collision-policy authorization. Repeated owned additions are recorded for
    that later policy decision, not silently accepted as authorized writes.
    Descriptor references remain manifest-local opaque definitions here.
    Preprocessing must compare selected descriptor *semantics* and propagate
    changed descendants before any unchanged-subtree optimization is valid.
    """
    result = {}
    for record in records:
        path = record["destination"]
        if not path.startswith("/") or "\\" in path or any([p in ["", ".", ".."] for p in path[1:].split("/")]):
            fail("directory reduction requires a resolved image path")
        side = record["side"]
        if side not in ["before", "after"]:
            fail("unsupported directory operation")
        attrs = {}
        for attr in record["attributes"]:
            if attr["namespace"]:
                continue
            name = attr["name"]
            if name in attrs:
                fail("duplicate directory attribute: " + name)
            if name not in ["destinationPath", "owner", "attributes", "compression"]:
                fail("unsupported directory attribute: " + name)
            attrs[name] = attr["value"]
        owner = attrs.get("owner", "false").lower()
        if owner not in ["true", "false"]:
            fail("unsupported directory owner value")
        if attrs.get("compression", "none") != "none":
            fail("unsupported directory compression")
        attributes = windows.csi_file_attributes(attrs["attributes"]) if "attributes" in attrs else 0x80
        descriptor = record["descriptor"]
        if descriptor != None and descriptor["sddl"] == "(inherit)":
            fail("directory inherit reference needs separate selection")
        key = path.lower()
        if key not in result:
            result[key] = dict(destination = path, before = dict(state = 0, attributes = 0x80, identity = None, descriptor = None), after = dict(state = 0, attributes = 0x80, identity = None, descriptor = None), operation = 0, security_flags = 8, directory_flags = 0, owned_addition_collisions = 0, contributions = [])
        item = result[key]
        item["contributions"].append(record)
        operation = 1 if side == "after" else 2
        if item["operation"] not in [0, operation]:
            operation = 3
        item["operation"] = operation
        selected = item[side]
        owns_metadata = owner == "true" or attributes != 0x80 or descriptor != None
        if owns_metadata:
            if side == "after" and selected["state"] == 4:
                item["owned_addition_collisions"] += 1
            selected["state"] = 4
            selected["identity"] = record.get("component_identity", record["identity"])
            selected["attributes"] = (attributes & ~0x200) | 0x80
            # New-side calls always carry the security-selection flag;
            # old-side calls carry it only for an explicit reference.
            if side == "after" or descriptor != None:
                if descriptor != None:
                    selected["descriptor"] = descriptor
                bit = 0x20 if side == "after" else 0x10
                item["security_flags"] &= ~bit
                if selected["descriptor"] == None:
                    item["security_flags"] |= bit
        elif selected["state"] != 4:
            selected["state"] = 3
        if side == "before":
            flags = item["security_flags"]
            item["security_flags"] = flags | ((flags >> 1) & 1) | 2
            item["directory_flags"] |= 8
    return result


def _servicing_comparison_mask(mask, registry):
    mapped = mask & 0x0fffffff
    rights_by_generic = [(0x80000000, 0x20019), (0x40000000, 0x20006), (0x20000000, 0x20019), (0x10000000, 0xf003f)] if registry else [(0x80000000, 0x120089), (0x40000000, 0x120116), (0x20000000, 0x1200a0), (0x10000000, 0x1f01ff)]
    for generic, rights in rights_by_generic:
        if mask & generic:
            mapped |= rights
    return mapped


def _servicing_comparison_entries(acl):
    if acl == None:
        return []
    entries = windows.acl_entries(acl)["entries"]
    for entry in entries:
        if entry["type"] not in [0, 1, 2, 3, 9, 17] or entry["sid"] == None:
            fail("unsupported servicing comparison ACE")
    return entries


def _servicing_security_matches_manifest(object_descriptor, manifest_descriptor, registry):
    """Bounded WCP flags-1/2 comparison, not symmetric descriptor equality.

    Compare independent self-relative inputs. Only object-side inherited ACEs
    are excluded. ACE order, flags, size, SID and callback application bytes
    matter; generic masks are mapped to the selected object rights. Protection
    and principal-defaulted bits matter; ACL auto-inheritance/defaulted bits do
    not. Present NULL and empty SACLs can match, unlike DACLs. No identity,
    token, inheritance, access authorization or mutation is supplied here.
    """
    if object_descriptor == None or manifest_descriptor == None:
        return object_descriptor == None and manifest_descriptor == None
    old = windows.security_descriptor_parts(object_descriptor)
    new = windows.security_descriptor_parts(manifest_descriptor)
    for part in [old, new]:
        if part["resource_manager_control"] or part["control"] & ~0xbf3f:
            fail("unsupported servicing comparison controls")
    old_acls = {name: _servicing_comparison_entries(old[name]) for name in ["dacl", "sacl"]}
    new_acls = {name: _servicing_comparison_entries(new[name]) for name in ["dacl", "sacl"]}
    if (old["control"] ^ new["control"]) & 0x3003:
        return False
    if old["owner"] != new["owner"] or old["group"] != new["group"]:
        return False
    for name, present in [("dacl", 4), ("sacl", 0x10)]:
        if (old["control"] ^ new["control"]) & present:
            return False
        if not old["control"] & present:
            continue
        if name == "dacl" and (old[name] == None) != (new[name] == None):
            return False
        selected = [e for e in old_acls[name] if not e["flags"] & 0x10]
        expected = new_acls[name]
        if len(selected) != len(expected):
            return False
        for i in range(len(selected)):
            a, b = selected[i], expected[i]
            if a["type"] != b["type"] or a["flags"] != b["flags"] or len(a["data"]) != len(b["data"]):
                return False
            if _servicing_comparison_mask(a["mask"], registry) != _servicing_comparison_mask(b["mask"], registry) or a["data"][8:] != b["data"][8:]:
                return False
    return True


def servicing_file_security_matches_manifest(object_descriptor, manifest_descriptor):
    """Compare independent descriptors with native WCP flags 2 (file rights)."""
    return _servicing_security_matches_manifest(object_descriptor, manifest_descriptor, False)


def servicing_registry_security_matches_manifest(object_descriptor, manifest_descriptor):
    """Compare independent descriptors with native WCP flags 1 (key rights).

    This is the asymmetric comparator used by ArbitrateKeySecurity, not the
    entire arbitration or an applied-key security decision. Interned identical
    descriptors use a separate native pointer-equality fast path; independent
    descriptors with inherited ACEs must not be conflated with that case.
    """
    return _servicing_security_matches_manifest(object_descriptor, manifest_descriptor, True)


def _servicing_manifest_pair_matches(before, after, old, new):
    # The coordinator interns descriptor pairs by exact SDDL. Native WCP
    # 10f098 returns equal for the same pointer before applying the asymmetric
    # object-vs-manifest comparison. Preserve that distinction: equal text
    # with ID ACEs is a no-op, while separate unequal texts still compare.
    if before != None and after != None and before["sddl"] == after["sddl"]:
        return True
    return servicing_file_security_matches_manifest(old, new)


def preprocess_servicing_directory_declarations(reduced):
    """Compute each explicit directory's own change bits, not subtree skips.

    This consumes ordered reduction, retaining all collisions and source
    contributions for later policy validation. It does not include file work,
    implicit ancestors, discovered children, inheritance, or commit effects.
    An unchanged directory here must never suppress changed descendants.
    """
    compiled = {}
    result = {}
    for path, item in reduced.items():
        descriptors = []
        for side in ["before", "after"]:
            definition = item[side]["descriptor"]
            data = None
            if definition != None:
                text = definition["sddl"]
                if text not in compiled:
                    compiled[text] = windows.compile_sddl(text)
                data = compiled[text]
            descriptors.append(data)
        changed = False
        flags = item["security_flags"]
        directory_flags = item["directory_flags"]
        same = _servicing_manifest_pair_matches(item["before"]["descriptor"], item["after"]["descriptor"], descriptors[0], descriptors[1])
        if not same or (flags & 1 and item["after"]["descriptor"] != None) or ((flags ^ (flags >> 1)) & 0x10):
            flags &= ~8
            changed = True
        if item["before"]["state"] != item["after"]["state"]:
            directory_flags |= 1
            changed = True
        if item["before"]["attributes"] != item["after"]["attributes"]:
            flags |= 0x40
            changed = True
        if item["operation"] == 2:
            changed = True
        output = dict(item)
        output["security_flags"] = flags
        output["directory_flags"] = directory_flags
        output["own_changed"] = changed
        result[path] = output
    return result


def _servicing_configuration_dword(software, components, name, default):
    # Native QueryConfigurationOption first checks servicing policy, then the
    # component store's Configuration key. A non-DWORD or non-four-byte value
    # does not override the fallback. Registry names are case insensitive.
    locations = [(software, "/Microsoft/Windows/CurrentVersion/Policies/Servicing", "policy"), (components, "/Configuration", "store")]
    for hive, path, origin in locations:
        key = hive.find(path)
        if key == None:
            continue
        matches = [value for key_name, value in key.value_records.items() if key_name.lower() == name.lower()]
        if len(matches) > 1:
            fail("ambiguous servicing configuration value: " + name)
        if matches and matches[0].type == 4 and len(matches[0].raw) == 4:
            return dict(value = binary.read_u32le(matches[0].raw, 0), origin = origin)
    return dict(value = default, origin = "default")


def servicing_directory_propagation_policy(software, components):
    """Select the ordinary direct-transaction enumeration gate, not effects.

    WCP raw layout +2c is MobileStore == 1. AnalyzePrimitiveInstallers maps
    that byte to primitive flag 10, then PerformPrimitiveInstallation maps it
    to coordinator flag 80. This is not equivalent to offline mode. The
    coordinator also ORs the numeric SmiHiveUpdates configuration result into
    its flags; retain that override rather than assuming it is a boolean.
    This covers ordinary direct transactions only, not HKCU or repair setup.
    The ordinary primitive flag mapping never supplies 20000; only the raw
    SmiHiveUpdates override can set that bit here and suppress the primary
    immutable flag. No full coordinator flag word is inferred from this subset.
    A false enumeration gate does NOT suppress explicitly declared children,
    their own security work, or inherited security on newly created objects.
    """
    mobile = _servicing_configuration_dword(software, components, "MobileStore", 0)
    extra = _servicing_configuration_dword(software, components, "SmiHiveUpdates", 0)
    return dict(mobile_store = mobile, smi_hive_updates = extra, enumerate_children = mobile["value"] == 1 or bool(extra["value"] & 0x80), immutable_primaries = not bool(extra["value"] & 0x20000))


def servicing_filemap_collision_policy(software, components):
    """Select the ordinary direct transaction's ownership strictness gate.

    Coordinator initialization ORs 0x4800 for SingleResourceOwnership and the
    raw SmiHiveUpdates DWORD into its flags. InitializeCFileInstaller copies
    bit 0x800 to the ownership byte (also used by ReportFileCollision).
    The historical strict_directories key names this shared gate. Primitive flags cannot
    supply that bit. This is not a repair/custom-coordinator policy.
    """
    single = _servicing_configuration_dword(software, components, "SingleResourceOwnership", 0)
    extra = _servicing_configuration_dword(software, components, "SmiHiveUpdates", 0)
    return dict(single_resource_ownership = single, smi_hive_updates = extra, strict_directories = bool(single["value"]) or bool(extra["value"] & 0x800))


def servicing_registry_overlap_policy(software, components):
    """Select ordinary direct-transaction overlap gates, not authorization.

    CRegistryInstaller::Initialize copies coordinator bit 0x800 to both its
    strict-key and strict-value bytes. The coordinator sets it from boolean
    SingleResourceOwnership or the raw SmiHiveUpdates flag override. Other
    coordinator modes and critical/state-separation/HKCU counters remain
    independent obligations.
    """
    single = _servicing_configuration_dword(software, components, "SingleResourceOwnership", 0)
    extra = _servicing_configuration_dword(software, components, "SmiHiveUpdates", 0)
    strict = bool(single["value"]) or bool(extra["value"] & 0x800)
    return dict(single_resource_ownership = single, smi_hive_updates = extra, strict_keys = strict, strict_values = strict)


def servicing_registry_overlap_status(policy, counts):
    """Return native DoesOverlapExist status from complete classified counts.

    A total owner collision is not automatically a critical collision. Callers
    must separately establish all six counters; absence cannot mean zero.
    This does not classify contributions, authorize mutation, or replace
    earlier parser/override/security failures.
    """
    names = ["keys", "critical_keys", "values", "critical_values", "state_separation", "hkcu"]
    if sorted(counts) != sorted(names):
        fail("registry overlap status requires complete classified counters")
    for name in names:
        if type(counts[name]) != "int" or counts[name] < 0 or counts[name] > 0xffffffffffffffff:
            fail("registry overlap counter requires uint64")
    if type(policy.get("strict_keys")) != "bool" or type(policy.get("strict_values")) != "bool":
        fail("registry overlap policy requires boolean strict gates")
    if (policy["strict_keys"] and counts["keys"]) or counts["critical_keys"]:
        return 0x80188309
    if (policy["strict_values"] and counts["values"]) or counts["critical_values"]:
        return 0x80188309
    if counts["state_separation"]:
        return 0x8018830e
    if counts["hkcu"]:
        return 0x80188317
    return 0


def servicing_filemap_collision_status(policy, file_collisions, directory_collisions):
    """Return the native final collision HRESULT, not transaction success.

    Directory dot-entry collisions retain the resident owner. Tolerating them
    does not authorize ordinary file collisions or any other commit effects.
    Other native final checks and all earlier failures remain independent.
    """
    if type(policy.get("strict_directories")) != "bool":
        fail("FileMap collision policy requires a boolean strict-directory gate")
    for count in [file_collisions, directory_collisions]:
        if type(count) != "int" or count < 0 or count > 0xffffffffffffffff:
            fail("FileMap collision count must be an unsigned 64-bit integer")
    if file_collisions:
        return 0x80188306
    if directory_collisions and policy["strict_directories"]:
        return 0x80188316
    return 0


def preprocess_servicing_path_hierarchy(directories, files):
    """Propagate already-proven own changes through the complete path graph.

    Both inputs must contain fully reduced and own-preprocessed records. Files
    include extra link destinations. Omitting file work is NOT a supported way
    to produce a directory-only commit plan. This pass adds implicit ancestors
    and native unchanged-subtree bits, without querying or changing the image.
    It does not authorize collisions, removals, phase selection or propagation
    to filesystem children discovered during commit.
    """
    nodes = {}
    for kind, records in [("directory", directories), ("file", files)]:
        for path, item in records.items():
            if not path.startswith("/") or "\\" in path or any([p in ["", ".", ".."] for p in path[1:].split("/")]):
                fail("hierarchy requires a canonical non-root image path")
            key = path.lower()
            if key in nodes:
                fail("servicing hierarchy path collision: " + path)
            if type(item.get("own_changed")) != "bool":
                fail("hierarchy requires own-preprocessed records: " + path)
            node = dict(item)
            node.update(kind = kind, path = key, children = [], implicit = False)
            nodes[key] = node
    for path in list(nodes):
        parts = path[1:].split("/")
        for depth in range(len(parts)):
            parent = "/" + "/".join(parts[:depth])
            if parent in nodes:
                if nodes[parent]["kind"] != "directory":
                    fail("servicing file is also a path ancestor: " + parent)
                continue
            nodes[parent] = dict(kind = "directory", path = parent, children = [], implicit = True, own_changed = False, security_flags = 8, directory_flags = 0, operation = 0)
    if not nodes:
        nodes["/"] = dict(kind = "directory", path = "/", children = [], implicit = True, own_changed = False, security_flags = 8, directory_flags = 0, operation = 0)
    for path, node in nodes.items():
        if path != "/":
            parent = path.rsplit("/", 1)[0] or "/"
            nodes[parent]["children"].append(path)
    # Bottom-up evaluation mirrors recursive PreprocessDirectoryChanges but
    # does not consume interpreter recursion depth for nested image paths.
    for depth, path in sorted([(p.count("/"), p) for p in nodes], reverse = True):
        node = nodes[path]
        changed = node["own_changed"] or any([nodes[p]["subtree_changed"] for p in node["children"]])
        node["subtree_changed"] = changed
        # Native recursion writes the skip bit on children, not its root.
        if path != "/":
            flags = node["directory_flags"] & ~4
            node["directory_flags"] = flags | (0 if changed else 4)
    return nodes


def select_servicing_file_commit_paths(hierarchy, phase):
    """Select native file-loop candidates, not an execution schedule.

    Requires the complete own/subtree-preprocessed hierarchy. Phase 1 selects
    boot-critical flag0x10 files; phase 2 selects its complement; phase 0
    selects both. Clean bit4 and directories are excluded in every phase.
    This models only the ordinary CommitDirectoryChanges file loop. Security-
    only/external-store flags, ancestor opens, recursion order, global enable
    gates and actual effects remain caller obligations. Returned sorted paths
    are for selection/comparison, never authorization to reorder native work.
    """
    if type(phase) != "int" or phase not in [0, 1, 2]:
        fail("unsupported native file commit phase")
    result = []
    for path, node in hierarchy.items():
        if node.get("kind") not in ["file", "directory"] or type(node.get("subtree_changed")) != "bool":
            fail("file phase selection requires a preprocessed hierarchy")
        flags = node.get("directory_flags")
        if type(flags) != "int" or flags < 0 or flags > 255:
            fail("invalid native file directory flags")
        if node["kind"] != "file" or flags & 4:
            continue
        if phase == 1 and not flags & 0x10:
            continue
        if phase == 2 and flags & 0x10:
            continue
        result.append(path)
    return sorted(result)


def plan_servicing_filemap(resident, nodes, directory_path, volume, windows_root = "/Windows"):
    """Build one native FileMap action without applying filesystem effects.

    The caller must select a dirty directory and supply immediate children with
    POST-preliminary-file-pass state. None means the map did not exist; an empty
    resident map is not a supported substitute. This composes the bounded native
    transition, path metadata and encoder. It does not validate transaction-wide
    collision policy, authorize paths, choose traversal order, apply security or
    commit a servicing transaction. A remove action removes the map, NOT its
    directory. No-op and removal have no content and are never encoded.
    """
    metadata = windows.cdf_filemap_path(directory_path, volume, windows_root)
    leaf = windows.cdf_filemap_name(directory_path, windows_root)
    if resident != None and (type(resident) != "dict" or not resident.get("entries")):
        fail("resident FileMap must be nonempty; use None only for an absent map")
    baseline = resident if resident != None else dict(metadata, identities = [], entries = [])
    transition = windows.cdf_filemap_transition(baseline, nodes)
    document = transition["document"]
    content = None
    if document["entries"]:
        operation = "write"
        document.update(metadata)
        content = windows.cdf_filemap_encode(document)
    else:
        operation = "remove" if resident != None else "none"
    return dict(
        path = windows_root + "/WinSxS/FileMaps/" + leaf,
        operation = operation,
        content = content,
        document = document,
        directory_collisions = transition["directory_collisions"],
    )


def servicing_file_source_key(identity, name):
    """Bounded native FileInfo key, NOT an exact payload/store identity.

    InsertFileInfo ignores all version fields for nonSxS scope, but retains
    major/minor for absent scope. The source filename is independently case-folded.
    Preserve the full component_identity on declarations for payload lookup;
    neither a transition label nor this intern key authorizes source bytes.
    Other scopes and non-ASCII comparison require additional native evidence.
    """
    return windows.csi_file_source_key(identity, name)


def prepare_servicing_unprojected_files(resolved, hashes, policy):
    """Prepare source-only native inputs without dropping unprojected work."""
    if policy["enumerate_children"] or policy["compression_mode"] not in [1, 2]:
        fail("unsupported unprojected file policy")
    result = []
    for record in resolved["unprojected"]:
        identity_type = windows.csi_identity(record["component_identity"]).type.lower()
        source_only = identity_type == "dualmodedriver" or (record["template"] == None and identity_type in ["", "win32"])
        if record.get("kind") == "link" or not source_only:
            fail("unprojected file requires absent-destination or dual-mode-driver policy")
        side = record["side"]
        if side not in ["before", "after"]:
            fail("unsupported unprojected operation")
        if record["load_from"]:
            fail("external unprojected source requires native source policy")
        if type(record["compress"]) != "bool" or type(record["managed_assembly"]) != "bool":
            fail("unprojected file requires native metadata")
        flags = 0x20 if policy["compression_mode"] == 2 and record["compress"] else 0
        if side == "after" and record["managed_assembly"]:
            flags |= 1
        key = (record["component_identity"], record["name"].lower())
        if key not in hashes:
            fail("missing exact unprojected file hash")
        result.append(dict(record, kind = "unprojected", process_flags = flags, source_hash = hashes[key]))
    return result


def _copy_servicing_native_file_hash(digest):
    if digest == None:
        return None
    if type(digest) != "dict" or sorted(digest) != ["digest", "digest_method", "transform"]:
        fail("invalid native file hash record")
    if type(digest["digest"]) != "bytes" or any([type(digest[k]) != "int" or digest[k] < 0 or digest[k] > 0xffffffff for k in ["digest_method", "transform"]]):
        fail("invalid native file hash fields")
    return dict(digest)


def reduce_servicing_unprojected_files(records):
    """Retain native ProcessUnprojectedFile source/hash contributions.

    Native 282f10 interns the same FileInfo table as projected files but makes
    no runtime destination record. Flags20 and new-only1 select compression
    and the component-wide GAC/NGEn marker, not projected immutable state.
    """
    sources = {}
    for record in records:
        if record.get("kind") != "unprojected" or "destination" in record:
            fail("unprojected source cannot create a runtime destination")
        side = record["side"]
        flags = record["process_flags"]
        if side not in ["before", "after"] or type(flags) != "int" or flags < 0 or flags & ~0x21 or (side == "before" and flags & 1):
            fail("unsupported native ProcessUnprojectedFile flags")
        identity = record["component_identity"]
        key = servicing_file_source_key(identity, record["name"])
        if key not in sources:
            sources[key] = dict(before = None, after = None)
        if sources[key][side] != None:
            fail("repeated unprojected file source requires native collision policy")
        sources[key][side] = dict(component_identity = identity, hash = _copy_servicing_native_file_hash(record["source_hash"]), record = record)
    return sources

def reduce_servicing_file_declarations(records, unprojected = (), collision_policy = None):
    """Reduce explicit native ProcessFile inputs; do not infer installer flags.

    Each input must supply process_flags and source_hash (None or a native
    digest_method/transform/digest record). This supports ordinary primary/link calls
    with flags 1, 2, 8, 10, 20 and 40 only, not repair, filters, external
    sources. With an explicit non-strict ownership policy, ordinary primary
    overlaps with identical metadata reduce in call order, as native ProcessFile
    does. Mixed metadata, writable/link overlaps, strict-policy overlaps and
    repeated primary sources remain unsupported. Hashes live on interned sources,
    so links use their primary's hashes even at another destination.
    """
    paths = {}
    sources = reduce_servicing_unprojected_files(unprojected)
    boot_file_present = False
    for record in records:
        path = record["destination"]
        if not path.startswith("/") or "\\" in path or any([p in ["", ".", ".."] for p in path[1:].split("/")]):
            fail("file reduction requires a resolved image path")
        side = record["side"]
        if side not in ["before", "after"]:
            fail("unsupported file operation")
        flags = record["process_flags"]
        if type(flags) != "int" or flags < 0 or flags & ~0x7b or (side == "before" and flags & 1):
            fail("unsupported native ProcessFile flags")
        attributes = record["attributes"]
        if type(attributes) != "int" or attributes < 0 or attributes > 0xffffffff:
            fail("invalid native file attributes")
        identity = record["component_identity"]
        source_key = servicing_file_source_key(identity, record["name"])
        if source_key not in sources:
            sources[source_key] = dict(before = None, after = None)
        source = sources[source_key]
        link = bool(flags & 0x10)
        boot_file_present = boot_file_present or bool(flags & 2)
        if not link:
            if source[side] != None:
                fail("repeated primary file source requires native collision policy")
            digest = _copy_servicing_native_file_hash(record["source_hash"])
            source[side] = dict(component_identity = identity, hash = digest, record = record)
        key = path.lower()
        if key not in paths:
            paths[key] = dict(destination = path, before = dict(state = 0, attributes = 0x80, source_key = None, descriptor = None), after = dict(state = 0, attributes = 0x80, source_key = None, descriptor = None), operation = 0, security_flags = 8, directory_flags = 0, file_flags = 0, contributions = [])
        item = paths[key]
        selected = item[side]
        if selected["source_key"] != None:
            if collision_policy == None or type(collision_policy.get("strict_directories")) != "bool" or collision_policy["strict_directories"]:
                fail("repeated file destination requires non-strict native collision policy: " + path)
            if (flags | selected["process_flags"]) & 0x18 or (side == "after" and not flags & 1):
                fail("unsupported writable or link file overlap: " + path)
            previous = sources[selected["source_key"]][side]["record"]
            if any([previous[field] != record[field] for field in ["process_flags", "attributes", "descriptor"]]):
                fail("unsupported mixed-metadata, writable or link file overlap: " + path)
            # WCP 26100.32131 bfB5e..bfB90 reports each repeated addition,
            # sets PathElement+95 bit20, then replaces the selected identity.
            # ReportFileCollision does not increment its fatal counter when
            # CFileInstaller+10 is false. Old contributions also replace the
            # selected source, but do not report an addition collision.
            if side == "after":
                item["file_flags"] |= 0x20
        selected["source_key"] = source_key
        selected["component_identity"] = identity
        selected["process_flags"] = flags
        item["contributions"].append(record)
        item["operation"] |= 1 if side == "after" else 2
        if side == "after":
            # Immutable flag takes precedence over link, not vice versa.
            selected["state"] = 2 if flags & 1 else (7 if link else 1)
            item["directory_flags"] |= 0x80
            if link and not flags & 1:
                item["file_flags"] |= 2
        else:
            selected["state"] = 7 if link else 0
            item["directory_flags"] |= 8
            item["file_flags"] |= 1 | (4 if link else 0)
        if link:
            continue
        selected["attributes"] = (attributes & ~0x200) | 0x80
        if side == "after" and flags & 2:
            item["directory_flags"] |= 0x10
        if flags & 8:
            item["directory_flags"] |= 0x20 if side == "after" else 0x40
        definition = record["descriptor"]
        if definition != None and not flags & 0x40:
            fail("file descriptor requires native selection flag")
        if flags & 0x40:
            if definition != None and definition["sddl"] != "(inherit)":
                selected["descriptor"] = definition
            elif definition == None or definition["sddl"] == "(inherit)":
                item["security_flags"] |= 0x20 if side == "after" else 0x10
    return dict(paths = paths, sources = sources, boot_file_present = boot_file_present)


def preprocess_servicing_file_declarations(reduced):
    """Native own-change bits after all primary/link source contributions.

    State differences alone are NOT file changes (unlike directories).
    FileInfo equality uses the native interning key; hash presence, digest method,
    transform and bytes are compared separately. This pass never reads or
    modifies the image and does not authorize copy, removal or security work.
    """
    compiled = {}
    result = {}
    for path, item in reduced["paths"].items():
        descriptors = []
        hashes = []
        for side in ["before", "after"]:
            selected = item[side]
            definition = selected["descriptor"]
            data = None
            if definition != None:
                text = definition["sddl"]
                if text not in compiled:
                    compiled[text] = windows.compile_sddl(text)
                data = compiled[text]
            descriptors.append(data)
            source_key = selected["source_key"]
            primary = reduced["sources"][source_key][side] if source_key != None else None
            hashes.append(primary["hash"] if primary != None else None)
        changed = False
        flags = item["security_flags"]
        directory_flags = item["directory_flags"]
        same = _servicing_manifest_pair_matches(item["before"]["descriptor"], item["after"]["descriptor"], descriptors[0], descriptors[1])
        if not same or (flags & 1 and item["after"]["descriptor"] != None) or ((flags ^ (flags >> 1)) & 0x10):
            flags &= ~8
            changed = True
        if item["before"]["attributes"] != item["after"]["attributes"]:
            flags |= 0x40
            changed = True
        if hashes[0] == None or hashes[1] == None or hashes[0] != hashes[1] or item["before"]["source_key"] != item["after"]["source_key"]:
            flags |= 0x80
            changed = True
        if item["operation"] == 2 or (not item["file_flags"] & 1 and directory_flags & 0x80):
            changed = True
        if (directory_flags ^ (directory_flags >> 1)) & 0x20:
            directory_flags |= 2
            changed = True
        output = dict(item)
        output.update(security_flags = flags, directory_flags = directory_flags, own_changed = changed)
        result[path] = output
    return result


def select_servicing_file_hash(file):
    """Bounded CmsGetFileHashInformation projection, not payload verification.

    Select the nested SHA256 Identity digest for file projection. .NET may
    additionally retain an obsolete build-time SHA1 attribute. Its syntax is
    checked, but the nested digest is binding; native readers verify SHA256.
    Other algorithms/transforms remain unsupported.
    """
    digest = file.digest
    if digest == None:
        fail("unsupported servicing file hash shape")
    if file.hash or file.hash_algorithm:
        if file.hash_algorithm.lower() not in ["sha1", "sha-1"] or len(file.hash) != 40 or any([file.hash[i].lower() not in "0123456789abcdef" for i in range(len(file.hash))]):
            fail("unsupported servicing file hash shape")
    if digest.algorithm != "http://www.w3.org/2000/09/xmldsig#sha256" or list(digest.transforms) != ["urn:schemas-microsoft-com:HashTransforms.Identity"]:
        fail("unsupported servicing file hash algorithm or transform")
    value = binary.decode("".join(digest.value.split()), "base64")
    if len(value) != 32:
        fail("servicing SHA256 digest must contain 32 bytes")
    return dict(digest_method = 2, transform = 1, digest = value)


def servicing_file_compression_policy(system):
    """Select native CFileInstaller compression mode from SYSTEM/Setup.

    IsCompactOSEnabled accepts only an exact DWORD and treats any nonzero
    value as true. Missing/malformed values select noncompact mode. This
    describes ProcessFile inputs, not authorization to compress file data.
    """
    key = system.find("/Setup")
    matches = [] if key == None else [v for n, v in key.value_records.items() if n.lower() == "compact"]
    if len(matches) > 1:
        fail("ambiguous CompactOS configuration")
    enabled = False
    origin = "default"
    if matches and matches[0].type == 4 and len(matches[0].raw) == 4:
        enabled = binary.read_u32le(matches[0].raw, 0) != 0
        origin = "system"
    return dict(compression_mode = 2 if enabled else 1, compact_enabled = enabled, compact_origin = origin)

def prepare_servicing_projected_files(resolved, security, hashes, policy):
    """Prepare bounded ordinary ProcessFile inputs, retaining unresolved work.

    This is not a full file plan. The unresolved list is carried forward and
    must be discharged before a complete hierarchy/commit can be claimed.
    External-source cases remain unsupported. Compression flags reflect the
    explicitly selected native mode, not a file compression effect. The selected
    policy must be for the ordinary direct transaction, not HKCU or repair.
    """
    if policy["enumerate_children"]:
        fail("projected-file preparation requires ordinary non-enumerating policy")
    if type(policy["immutable_primaries"]) != "bool":
        fail("projected files require an explicit immutable-primary policy")
    if policy["compression_mode"] not in [1, 2]:
        fail("unsupported native file compression mode")
    descriptors = {}
    for record in security:
        key = (record["component_identity"], record["side"], record["name"].lower())
        if key in descriptors:
            fail("duplicate exact file security source")
        descriptors[key] = record["descriptor"]
    records = []
    for record in resolved["records"] + resolved["links"]:
        if type(record["compress"]) != "bool":
            fail("projected file requires native compression metadata")
        if record["load_from"]:
            fail("external projected file source requires native source policy")
        if type(record["boot_critical"]) != "bool":
            fail("projected file requires boot-critical metadata")
        side = record["side"]
        if side not in ["before", "after"]:
            fail("unsupported projected file side")
        writable = record["writable_type"]
        if writable not in [None, "systemData", "applicationData"]:
            fail("unsupported projected file writeability")
        flags = 8 if writable != None else 0
        if record["compress"] and policy["compression_mode"] == 2:
            flags |= 0x20
        if side == "after" and record["boot_critical"]:
            flags |= 2
        key = (record["component_identity"], side, record["name"].lower())
        if key not in descriptors:
            fail("missing exact file security declaration")
        descriptor = descriptors[key]
        if descriptor != None:
            flags |= 0x40
        link = record.get("kind") == "link"
        if link:
            # Native link calls use edi|10, not the primary's esi|edi.
            # Thus they do not inherit primary immutable flag 1.
            flags |= 0x10
        elif side == "after" and writable == None and policy["immutable_primaries"]:
            flags |= 1
        hash_key = (record["component_identity"], record["name"].lower())
        if hash_key not in hashes:
            fail("missing exact file hash declaration")
        output = dict(record)
        output.update(process_flags = flags, descriptor = None if link else descriptor, source_hash = None if link else hashes[hash_key])
        records.append(output)
    return dict(records = records, unresolved = list(resolved["unresolved"]), unprojected = list(resolved.get("unprojected", [])))


def select_servicing_writable_file_action(item, sources, current):
    """Select copy versus preservation for the observed paired writable shape.

    This reads the current projected file, not its possibly DCS-encoded WinSxS
    counterpart. It neither applies effects nor verifies the replacement source,
    security authorization, FileMaps or transaction ordering. Missing projections,
    different flags/states and non-identity hashes require separate native policy.
    """
    before, after = item["before"], item["after"]
    if item["operation"] != 3 or not item["own_changed"] or before["state"] != 0 or after["state"] != 1 or item["security_flags"] != 0x88 or item["directory_flags"] != 0xe8 or item["file_flags"] != 1:
        fail("unsupported writable file transition")
    if current == None:
        fail("writable projection is missing")
    old_hash = None
    for side, selected in [("before", before), ("after", after)]:
        if selected["process_flags"] != 0x48 or selected["source_key"] == None:
            fail("unsupported writable source flags")
        primary = sources.get(selected["source_key"], {}).get(side)
        if primary == None or primary["component_identity"] != selected["component_identity"]:
            fail("writable source identity does not match projection")
        expected = primary["hash"]
        if expected == None or expected["digest_method"] != 2 or expected["transform"] != 1 or type(expected["digest"]) != "bytes" or len(expected["digest"]) != 32:
            fail("unsupported writable source hash")
        if side == "before":
            old_hash = expected["digest"]
    return "replace" if digest(current, algorithm = "sha256") == old_hash else "preserve"


def build_servicing_immutable_file_security_request(item, parent):
    """Select the proven ordinary immutable-file request from native flags.

    The supplied parent is the effective destination parent at commit time,
    not necessarily its base-image descriptor. These added/paired state-2
    cases set security on the linked source object. Source staging metadata,
    hardlink mutation, authorization and ordering remain caller obligations.
    """
    after = item["after"]
    if item["operation"] not in [1, 3] or after["state"] != 2 or not item["own_changed"]:
        fail("unsupported immutable file security transition")
    allowed_security = [0x88, 0xb8] if item["operation"] == 3 else [0xc0, 0xe0]
    # ProcessFile flag2 only selects the boot-critical commit phase; it does
    # not alter the immutable security request, including new-only files.
    allowed_process = [0x41, 0x43]
    if after.get("process_flags") not in allowed_process or item["security_flags"] not in allowed_security:
        fail("unsupported immutable file security flags")
    definition = after["descriptor"]
    inherited = bool(item["security_flags"] & 0x20)
    if inherited != (definition == None):
        fail("immutable file security selection disagrees with declaration")
    # A selected inherit marker passes the native SYSTEM default pair, not
    # the source object's current descriptor and not a NULL setter request.
    data = windows.compile_sddl("O:SYG:SY" if inherited else definition["sddl"])
    return build_servicing_file_security_request(data, parent)


def build_servicing_staged_file_security_request(parent, driver = False):
    """Construct the observed component-file staging request, not its effect.

    The caller must determine driverUpdate/dualModeDriver identity semantics
    and supply the effective component-store parent. This models the ACL part
    of ApplyAclsAndWofCompressIfNecessary with compression disabled, not the
    staging dispatch, source attributes, owner authorization or kernel update.
    Unlike runtime hardlink security, this request also updates integrity
    labels. The ordinary assignment helper deliberately rejects that mask.
    """
    if type(driver) != "bool":
        fail("staged file security requires an explicit driver boolean")
    trusted_installer = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    sddl = "O:%sG:%sD:P(A;;FA;;;%s)(A;;GRGX;;;BA)(A;;%s;;;SY)(A;;GRGX;;;BU)(A;;GRGX;;;S-1-15-2-1)(A;;GRGX;;;S-1-15-2-2)S:AI" % (trusted_installer, trusted_installer, trusted_installer, "FA" if driver else "GRGX")
    request = build_servicing_file_security_request(windows.compile_sddl(sddl), parent)
    request["security_information"] |= 0x10
    return request


def assign_servicing_staged_file_security(current, request):
    """Apply the bounded staging metadata transformation, without authorization.

    Native staging updates labels as well as audit security. The observed
    request has a present-NULL SACL and clears existing labels, unlike the
    runtime hardlink setter. Non-NULL requested SACLs require separate label
    validation policy and are deliberately unsupported by this entry point.
    The native comparison declares a SYSTEM-integrity servicing subject with
    an owner-capable TrustedInstaller group; this does not grant that access.
    """
    if windows.security_descriptor_parts(request["descriptor"])["sacl"] != None:
        fail("staged security assignment requires the observed NULL SACL")
    return _assign_servicing_security(current, request, clear_labels = True)


def select_servicing_paired_registry_value_action(before, after, current, mutable = False):
    """Select the observed single-owner paired ordinary-value commit action.

    Inputs are decoded typed raw records (type=int, raw=bytes), not XML text.
    Supported types are NONE, SZ, EXPAND_SZ, BINARY, DWORD, QWORD and raw
    numeric types greater than 11 (all 32 bits preserved). Both sides
    must have ordinary priority, no override or operation hint, and the same
    effective mutable flag. The caller establishes those
    preconditions; this is not registry manifest arbitration. MULTI_SZ uses
    different native merge behavior and must not enter this selector.
    None means a missing current value, not an unreadable key. No registry
    roots, security, ownership, key creation or effects are handled here.
    """
    if type(mutable) != "bool":
        fail("paired registry value requires a boolean mutable flag")
    for value in [before, after]:
        if type(value) != "dict" or type(value.get("type")) != "int" or (value["type"] not in [0, 1, 2, 3, 4, 11] and not (value["type"] > 11 and value["type"] <= 0xffffffff)) or type(value.get("raw")) != "bytes":
            fail("paired registry value requires supported decoded records")
        kind, raw = value["type"], value["raw"]
        if kind == 0 and raw:
            fail("CSI REG_NONE declaration must decode to empty bytes")
        if (kind == 4 and len(raw) != 4) or (kind == 11 and len(raw) != 8):
            fail("paired registry integer has an invalid byte length")
        if kind in [1, 2] and (len(raw) < 2 or len(raw) % 2 or raw[-2:] != b"\x00\x00"):
            fail("paired registry string requires terminated UTF-16 bytes")
    if current != None and (type(current) != "dict" or type(current.get("type")) != "int" or current["type"] < 0 or current["type"] > 0xffffffff or type(current.get("raw")) != "bytes"):
        fail("current registry value requires a typed raw record or None")
    # Native preprocessing marks identical declarations with value flag 80;
    # CreateValuesInKey skips them without querying the current value.
    if before["type"] == after["type"] and before["raw"] == after["raw"]:
        return "none"
    # Exact bytes, including string terminators and case, are significant.
    if mutable and (current == None or current["type"] != before["type"] or current["raw"] != before["raw"]):
        return "preserve"
    return "set"


def select_servicing_paired_registry_dword_action(before, after, current, mutable = False):
    """DWORD-only compatibility entry point for the paired value selector."""
    for value in [before, after]:
        if type(value) != "dict" or type(value.get("type")) != "int" or value["type"] != 4 or type(value.get("raw")) != "bytes" or len(value["raw"]) != 4:
            fail("paired registry DWORD requires two decoded DWORD records")
    return select_servicing_paired_registry_value_action(before, after, current, mutable)


def select_servicing_paired_registry_multi_action(before, after, current, operation_hint = "append", mutable = False):
    """Return the observed ordinary MULTI_SZ merge effect, without applying it.

    before/after are ordered contribution lists of nonempty strings from one
    owner with ordinary priority and no override. Both sides must use the same
    operation_hint and mutable setting. The caller must resolve the hint;
    the default here explicitly selects append, not manifest default parsing.
    An empty list means no entries (e.g. quoted empty declaration), not
    the distinct unquoted empty-string contribution. Append/prepend merge
    regardless of mutable; replace uses exact old-value preservation.
    Current is a typed raw record or None. Only canonical
    terminated current MULTI_SZ data is accepted; malformed data fails closed.
    The caller establishes reduction/root/key policy. No hive is modified.
    """
    if operation_hint not in ["append", "prepend", "replace"]:
        fail("unsupported multi-string operation hint")
    if type(mutable) != "bool":
        fail("multi-string requires a boolean mutable flag")
    for entries in [before, after]:
        if type(entries) != "list":
            fail("paired multi-string requires contribution lists")
        for entry in entries:
            if type(entry) != "string" or not entry or "\x00" in entry:
                fail("paired multi-string requires nonempty NUL-free entries")
    if current != None and (type(current) != "dict" or type(current.get("type")) != "int" or current["type"] < 0 or current["type"] > 0xffffffff or type(current.get("raw")) != "bytes"):
        fail("current registry value requires a typed raw record or None")
    if operation_hint == "replace":
        for entries in [before, after]:
            if len({entry: True for entry in entries}) != len(entries):
                fail("replace mode duplicate contributions require arbitration")
    if before == after:
        return dict(action = "none")
    if operation_hint == "replace":
        old_raw = binary.encode("\x00".join(before) + "\x00\x00", encoding = "utf16le")
        new_raw = binary.encode("\x00".join(after) + "\x00\x00", encoding = "utf16le")
        if mutable and (current == None or current["type"] != 7 or current["raw"] != old_raw):
            return dict(action = "preserve")
        return dict(action = "set", value = dict(type = 7, raw = new_raw))
    entries = []
    if current != None and current["type"] == 7:
        raw = current["raw"]
        if len(raw) < 4 or len(raw) % 2 or raw[-4:] != b"\x00\x00\x00\x00":
            fail("current multi-string requires canonical terminated bytes")
        text = binary.text(raw, encoding = "utf16le")
        if binary.encode(text, encoding = "utf16le") != raw:
            fail("current multi-string requires valid UTF-16")
        entries = text[:-2].split("\x00") if text[:-2] else []
        if "" in entries:
            fail("current multi-string contains an interior empty entry")
    # Each old contribution removes only the first exact current occurrence.
    # Remaining current order and duplicates survive; new entries append only
    # when not already present. Equality is case-sensitive.
    for old in before:
        if old in entries:
            entries.remove(old)
    additions = []
    for new in after:
        if new not in entries and new not in additions:
            additions.append(new)
    entries = additions + entries if operation_hint == "prepend" else entries + additions
    if not entries:
        return dict(action = "delete" if current != None else "none")
    raw = binary.encode("\x00".join(entries) + "\x00\x00", encoding = "utf16le")
    return dict(action = "set", value = dict(type = 7, raw = raw))





def select_servicing_new_registry_multi_action(after, current, operation_hint = "append"):
    """Select a new-only nonempty MULTI_SZ contribution's observed effect.

    Missing manifest hint is append in the pinned native ProcessValue path.
    Existing strings survive append/prepend; an already present new entry is
    not moved. New-only replace overwrites without mutable preservation.
    Empty/unquoted-empty contributions and overlapping owners need separate
    reduction, and must not be collapsed into this bounded single-owner case.
    """
    if type(after) != "list" or not after:
        fail("new registry multi action requires nonempty contributions")
    return select_servicing_paired_registry_multi_action([], after, current, operation_hint = operation_hint, mutable = False)


def expand_servicing_registry_string(value, source_roots, target, architecture):
    """Expand a registry string/name against explicitly resolved DOS paths.

    source_roots is the source_roots map from the offline path policy, NOT its
    image-relative roots map. Registry data remains DOS syntax, not NT device
    syntax or image paths. Environment references remain literal. The observed
    unresolved build.PackageMoniker is also literal; other unknown macros fail
    closed. This helper does not decide which registry data types expand text.
    """
    if type(value) != "string" or "\x00" in value:
        fail("registry expansion requires a NUL-free string")
    if "$(" not in value:
        return value
    variables = {}
    for rest in value.split("$(")[1:]:
        fields = rest.split(")", 1)
        if len(fields) != 2:
            fail("unterminated registry macro")
        name = fields[0]
        if name.lower() == "assembly.empty":
            # .NET uses $$(assembly.empty)(Registry:...) to store a literal
            # MSBuild expression. Expand this span once; never rescan output.
            variables[name.lower()] = ""
            continue
        if name.lower() == "build.packagemoniker":
            # Native registry InterpretValueData retains this unresolved name.
            # Case variants would conflict in the ordinary variables map, so
            # leave literal spans outside that case-folded expansion below.
            continue
        directory_id = windows.csi_file_directory_macro(target, architecture, name)
        if directory_id not in source_roots:
            fail("registry macro requires a resolved source directory: " + name)
        path = source_roots[directory_id]
        _offline_absolute_components(path)
        if "$(" in path:
            fail("registry macro source cannot contain macros")
        variables[name.lower()] = path.rstrip("\\")
    # Expand only known spans. Replacements are never rescanned as input.
    parts = value.split("$(")
    result = [parts[0]]
    for rest in parts[1:]:
        name, suffix = rest.split(")", 1)
        result.append("$(" + name + ")" if name.lower() == "build.packagemoniker" else variables[name.lower()])
        result.append(suffix)
    return "".join(result)

def prepare_servicing_registry_value_data(attributes, source_roots, target, architecture):
    """Decode one ordinary modern registry declaration, not its commit policy.

    The pinned native modern-profile path selects value, not IEDownlevelValue.
    Options are retained verbatim for the reducer; decoding does not authorize
    mutable writes, replace/merge behavior, priorities, or overlapping owners.
    MULTI_SZ entries and unquoted-empty provenance must survive even though
    their canonical raw encoding can coincide. No profile/key binding occurs.
    """
    allowed = ["name", "valueType", "value", "mutable", "operationHint", "IEDownlevelValue"]
    if type(attributes) != "dict" or any([name not in allowed for name in attributes]):
        fail("unsupported registry value preparation attributes")
    if "name" in attributes and type(attributes["name"]) != "string":
        fail("registry value preparation requires string name")
    for name in ["valueType", "value"]:
        if type(attributes.get(name, "" if name == "value" and attributes.get("valueType") == "REG_SZ" else None)) != "string":
            fail("registry value preparation requires " + name)
    kinds = {"REG_NONE": 0, "REG_SZ": 1, "REG_EXPAND_SZ": 2, "REG_BINARY": 3, "REG_DWORD": 4, "REG_MULTI_SZ": 7, "REG_QWORD": 11}
    spelling = attributes["valueType"]
    if spelling not in kinds:
        fail("unsupported ordinary registry value type: " + spelling)
    if attributes.get("mutable", "false") not in ["true", "false"]:
        fail("unsupported registry mutable spelling")
    if attributes.get("operationHint", "") not in ["", "append", "prepend", "replace"]:
        fail("unsupported registry operation hint")
    name = expand_servicing_registry_string(attributes.get("name", ""), source_roots, target, architecture)
    text = attributes.get("value", "")
    kind = kinds[spelling]
    if kind in [1, 2, 7]:
        text = expand_servicing_registry_string(text, source_roots, target, architecture)
    decoded = windows.assembly_registry_data(spelling, text)
    entries = None
    if kind in [1, 2]:
        raw = binary.encode(decoded + "\x00", encoding = "utf16le")
    elif kind == 7:
        entries = decoded
        raw = binary.encode("\x00".join(entries) + "\x00\x00", encoding = "utf16le")
    elif kind in [4, 11]:
        builder = binary.builder()
        if kind == 4:
            builder.u32le(decoded)
        else:
            builder.u64le(decoded)
        raw = builder.bytes()
    else:
        raw = decoded
    return dict(name = name, type = kind, raw = raw, entries = entries, unquoted_empty = kind == 7 and text == "", attributes = dict(attributes))


def reduce_servicing_registry_keys(records, scope = "system"):
    """Reduce a bounded ordered set of resolved ordinary keys in one pass.

    Input records carry path, side, identity, descriptor and key_attributes.
    Paths are already macro-expanded, rooted and view-redirected. This models
    native last-nonempty descriptor selection separately from first-owner
    retention. Overlapping owned additions are counted, not authorized. Either
    side can arrive first; the caller supplies the native contribution order.
    Implicit ancestors are retained, but namespace/profile anchors are provider-
    owned. System and per-user passes must never share one reduction mapping.
    No value reduction, exclusion authorization or hive writes happen here.
    """
    result = {}
    if scope not in ["system", "user"]:
        fail("unsupported registry reduction scope")
    roots = ["\\registry\\machine", "\\registry\\user"] if scope == "system" else ["\\registry\\user"]
    for record in records:
        if record.get("scope", scope) != scope:
            fail("registry reduction cannot mix passes")
        path = record["path"]
        if type(path) != "string" or "\x00" in path or "$(" in path:
            fail("registry reduction requires a resolved machine path")
        parts = path.split("\\")
        if len(parts) < 4 or "\\".join(parts[:3]).lower() not in roots or any([not p for p in parts[1:]]):
            fail("registry reduction requires a resolved child path")
        if scope == "system" and "\\".join(parts[:3]).lower() == "\\registry\\user" and parts[3].lower() != ".default":
            fail("explicit user hive requires separate reduction policy")
        side = record["side"]
        if side not in ["before", "after"]:
            fail("unsupported registry key side")
        attrs = record["key_attributes"]
        for name in attrs:
            if name not in ["keyName", "owner", "perUserVirtualization", "mapDesiredAccessToMaxAllowedAccess"]:
                fail("unsupported registry key reduction attribute: " + name)
        # These exact declarations produced no additional key operation in
        # native ProcessKeys + CreateHierarchyInSil, for existing and newly
        # created ordinary keys. Do not generalize to other attribute values.
        if "perUserVirtualization" in attrs and attrs["perUserVirtualization"] not in ["Disable", "DisableRecurse"]:
            fail("unsupported registry virtualization declaration")
        if "mapDesiredAccessToMaxAllowedAccess" in attrs and attrs["mapDesiredAccessToMaxAllowedAccess"] != "False":
            fail("unsupported registry maximum-access declaration")
        owner = attrs.get("owner", "false").lower()
        if owner not in ["true", "false"]:
            fail("unsupported registry key owner")
        definition = record["descriptor"]
        if definition != None and definition["sddl"] == "(inherit)":
            fail("registry inherit reference requires separate selection")
        # Presence is monotone within a pass. Once an ancestor already has
        # this side, all its ancestors do too. Visit the leaf first and stop
        # that redundant walk; never skip its ordered contribution reduction.
        for depth in reversed(range(3, len(parts))):
            destination = "\\".join(parts[:depth + 1])
            key = destination.lower()
            if key not in result:
                result[key] = dict(path = destination, parent = "\\".join(parts[:depth]).lower(), before = None, after = None, before_present = False, after_present = False, before_descriptor = None, after_descriptor = None, explicit = False, hive_boundary = scope == "system" and depth == 3, owner = None, owned_addition_collisions = 0, contributions = [])
            item = result[key]
            if depth != len(parts) - 1 and item[side + "_present"]:
                break
            item[side + "_present"] = True
            if depth != len(parts) - 1:
                continue
            item[side] = record
            if definition != None:
                item[side + "_descriptor"] = definition
            item["explicit"] = True
            item["contributions"].append(record)
            if side == "after" and (owner == "true" or definition != None):
                if item["owner"] == None:
                    item["owner"] = record["identity"]
                else:
                    item["owned_addition_collisions"] += 1
    return result


def preprocess_servicing_registry_keys(reduced, value_changes, compiled_security):
    """Compute ordinary key flags after independent complete value reduction.

    value_changes maps EVERY explicit reduced key to its manifest-value change
    boolean, even keys with no values. It is not a comparison against live hive
    data. compiled_security maps exact SDDL to bytes compiled with the target's
    identity context. Native pointer interning preserves equal-text equality;
    different texts use the asymmetric registry-rights comparison.
    The returned mapping does not authorize traversal order or hive mutation.
    """
    explicit = {path: True for path, item in reduced.items() if item["explicit"]}
    if sorted(explicit) != sorted(value_changes):
        fail("registry preprocessing requires complete explicit-key value changes")
    if any([type(changed) != "bool" for changed in value_changes.values()]):
        fail("registry value change must be boolean")
    result = {}
    for path, item in reduced.items():
        operation = 1 if item["after_present"] else 2
        flags = 8 | (2 if item["hive_boundary"] else 0) | (0 if item["before_present"] else 0x20)
        definitions = [item[side + "_descriptor"] for side in ["before", "after"]]
        descriptors = []
        for definition in definitions:
            data = None
            if definition != None:
                text = definition["sddl"]
                if text not in compiled_security:
                    fail("registry preprocessing requires compiled selected security")
                data = compiled_security[text]
                if data == None:
                    fail("registry selected descriptor cannot be null")
            descriptors.append(data)
        if operation == 1:
            same_text = definitions[0] != None and definitions[1] != None and definitions[0]["sddl"] == definitions[1]["sddl"]
            same = same_text or servicing_registry_security_matches_manifest(descriptors[0], descriptors[1])
            if not same:
                flags &= ~8
        result[path] = dict(item, operation = operation, security_flags = flags, auxiliary_flags = 0, descriptor = descriptors[1], old_descriptor = descriptors[0], subtree_changed = value_changes.get(path, False))
    # Children must establish their change state before the parent's skip bit.
    for path in sorted(result, key = _servicing_registry_key_depth, reverse = True):
        item = result[path]
        flags = item["security_flags"]
        if item["operation"] == 1 and not flags & 0x20 and not item["subtree_changed"] and flags & 8:
            flags |= 0x40
        item["security_flags"] = flags
        item["subtree_changed"] = not bool(flags & 0x40)
        parent = item["parent"]
        if parent in result and item["subtree_changed"]:
            result[parent]["subtree_changed"] = True
    return result


def _servicing_registry_key_depth(path):
    return path.count("\\")

def select_servicing_registry_key_commit(operation, security_flags, descriptor, created = False, auxiliary_flags = 0, parent_security_flags = 0):
    """Select ordinary CreateKeysInKey work from a preprocessed native node.

    This is not declaration reduction or permission to mutate a hive. The
    caller must establish ordering, overlap/exclusion policy and parent state
    first. `created` is the actual create disposition, not an existence guess.
    Removal only queues an emptiness check AFTER value and descendant work;
    implicit ancestors participate too. Missing removal keys are tolerated by
    the provider. Mutable/protected-subtree and special auxiliary policies
    deliberately remain outside this bounded selector.
    """
    if operation not in [1, 2]:
        fail("registry key commit requires install/remove operation")
    for flags in [security_flags, auxiliary_flags, parent_security_flags]:
        if type(flags) != "int" or flags < 0 or flags > 255:
            fail("registry key flags must be bytes")
    if security_flags & ~0x6a or parent_security_flags & 0x80 or auxiliary_flags:
        fail("unsupported registry key commit policy")
    if type(created) != "bool" or (operation == 2 and created):
        fail("invalid registry creation disposition")
    # The unchanged-subtree optimization precedes any provider lookup. A
    # missing key is NOT sufficient reason to defeat this optimization.
    if security_flags & 0x40:
        return dict(action = "skip", security = "none", defer_inheritance = False, queue_empty_delete = False)
    if operation == 2:
        return dict(action = "open", security = "none", defer_inheritance = False, queue_empty_delete = True)
    flags = security_flags & ~8 if created else security_flags
    security = "none"
    if not flags & 8:
        security = "explicit" if descriptor != None else "default"
    return dict(action = "create_or_open", security = security, defer_inheritance = bool(flags & 2) if security != "none" else False, queue_empty_delete = False)


def select_servicing_registry_empty_delete(subkey_count, value_count):
    """Evaluate a queued key AFTER descendants and values have been processed.

    Counts must come from the current physical key, including undeclared
    contents; declaration counts cannot establish emptiness. Nonempty-key
    security reset/propagation requires a separate configured policy.
    """
    for count in [subkey_count, value_count]:
        if type(count) != "int" or count < 0 or count > 0xffffffff:
            fail("registry key counts must be uint32")
    return subkey_count == 0 and value_count == 0

def select_servicing_registry_value_action(before, after, current, mutable = False):
    """Select a bounded ordinary single-owner registry value action.

    Uses the paired ordinary-value selector's types and reduction preconditions.
    None on one declaration side means that side has no contribution. Unlike
    paired mutable updates, a new-only value overwrites without querying and
    an old-only value deletes without checking whether it was user-modified.
    A missing value during deletion is tolerated by the native commit path.
    MULTI_SZ contributions require their separate merge/replace policy.
    """
    if before == None and after == None:
        fail("registry action requires at least one declaration")
    if before == None:
        select_servicing_paired_registry_value_action(after, after, current, mutable)
        return "set"
    if after == None:
        select_servicing_paired_registry_value_action(before, before, current, mutable)
        return "delete"
    return select_servicing_paired_registry_value_action(before, after, current, mutable)


# Pinned WCP 10.0.26100.9441 machine-hive WOW64 rule prefixes. Extracted from
# the native static rule graph and checked against TranslateWowRegistryPath
# for every prefix + a child. Flags: bit 0 redirects, bit 1 sets insertion
# point. Later equal-length entries refine the same prefix's insertion point.
_SERVICING_MACHINE_REGISTRY_RULES = [
    ("\\REGISTRY\\MACHINE", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE", 3),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes", 2),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID", 1),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID\\{1BD51F8C-8CFC-4708-A88D-5690DE4D5C16}", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID\\{36BBB745-0999-4FD8-A538-4D4D84E4BD09}", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID\\{963F9E1B-197A-4664-B7D1-BCF5443A528D}", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID\\{FE10D39B-A7F1-412c-83BA-D00788532ABB}", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\DirectShow", 1),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\Interface", 1),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\Media Type", 1),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\MediaFoundation", 1),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Clients", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cellular", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\COM3", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\Current", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\Readers", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Services", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\CTF\\SystemShared", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\DeviceReg", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\DFS", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Driver Signing", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\EnterpriseCertificates", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\EventSystem", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\FingerKB", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\FuzzyDS", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Input", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\LanguageOverlay", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Messaging", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\MSMQ", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\MTF", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\MTFFuzzyFactors", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\MTFInputType", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\MTFKeyboardMappings", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Non-Driver Signing", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Notepad\\DefaultFonts", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Ole", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Phone", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Pim", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Poom", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Ras", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Rpc", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\SecurityManager", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Semgr", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Shell", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Software\\Microsoft\\Shared Tools\\Msinfo", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\TermServLicensing", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Transaction Server", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Unified Store", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\UserData", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Console", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Containers", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontDPI", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontLink", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontMapper", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\GRE_Initialize", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\LanguagePack", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Ports", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization\\HvSocket", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Search", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Cursors\\Schemes", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Theme", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\ThemeVolatile", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\KindMap", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Parental Controls", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PreviewHandlers", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Telephony\\Locations", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\XAML", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\Policies", 0),
    ("\\REGISTRY\\MACHINE\\SOFTWARE\\RegisteredApplications", 0),
]


_SERVICING_REGISTRY_PATH_MAPPER = windows.registry_path_mapper(_SERVICING_MACHINE_REGISTRY_RULES)

_SERVICING_MACHINE_REGISTRY_RULE_INDEX = {prefix.lower(): flags for prefix, flags in _SERVICING_MACHINE_REGISTRY_RULES}

def redirect_servicing_machine_registry_path(path, architecture):
    """Map a canonical NT machine-hive path for the pinned amd64 profile.

    This is the observed 26100.9441 WCP rule set, not generic Windows version
    policy. amd64 leaves paths unchanged; x86/wow64 use the native machine
    rules. One explicit WOW6432Node at Software or Software/Classes is handled;
    deeper/multiple explicit nodes fail closed. USER roots, root aliases,
    provider mounts and value macro expansion are outside this helper.
    """
    if type(path) != "string" or "\x00" in path:
        fail("registry path requires a NUL-free string")
    root = "\\Registry\\Machine"
    folded = path.lower()
    if folded != root.lower() and not folded.startswith(root.lower() + "\\"):
        fail("registry path requires the NT machine root")
    if "\\\\" in path or (path.endswith("\\") and path != root + "\\"):
        fail("registry path requires canonical separators without trailing slash")
    if architecture not in ["amd64", "x86", "wow64"]:
        fail("unsupported servicing registry architecture")
    if architecture == "amd64":
        return path
    original = path
    parts = path.split("\\")
    explicit = [i for i in range(len(parts)) if parts[i].lower() == "wow6432node"]
    if explicit:
        index = explicit[0]
        if len(explicit) != 1 or parts[3].lower() != "software" or not (index == 4 or (index == 5 and parts[4].lower() == "classes")):
            fail("unsupported explicit WOW6432Node placement")
        parts = parts[:index] + parts[index+1:]
        path = "\\".join(parts)
        folded = path.lower()
    matched = None
    anchor = None
    # The native rule match is by complete path component, longest first.
    # Probe only actual ancestors instead of folding/scanning every rule for
    # each declaration. Later duplicate rules retain the original tie policy.
    candidate = folded
    for _ in range(len(parts) + 1):
        flags = _SERVICING_MACHINE_REGISTRY_RULE_INDEX.get(candidate)
        if flags != None:
            if matched == None:
                matched = (candidate, flags)
            if flags & 2 and anchor == None:
                anchor = candidate
        if not candidate:
            break
        candidate = candidate.rsplit(chr(92), 1)[0]
    if matched != None and matched[1] & 1:
        if anchor == None:
            fail("missing registry redirection insertion point")
        path = path[:len(anchor)] + "\\WOW6432Node" + path[len(anchor):]
    # Native retains the input spelling when its physical destination is equal.
    return original if path.lower() == original.lower() else path


def resolve_servicing_machine_registry_key(key, architecture):
    """Resolve verified HKLM/HKCR root aliases and the pinned registry view.

    Keys must already have macros expanded. HKCU/HKU, provider hive mounts,
    CurrentControlSet resolution, virtualization and key security are separate.
    Returned paths are canonical NT paths without a trailing separator.
    """
    if type(key) != "string" or "\x00" in key or "$(" in key:
        fail("registry key requires an expanded NUL-free string")
    fields = key.rstrip("\\").split("\\", 1)
    roots = {
        "hkey_local_machine": "\\Registry\\Machine",
        "hklm": "\\Registry\\Machine",
        "hkey_classes_root": "\\Registry\\Machine\\SOFTWARE\\Classes",
        "hkcr": "\\Registry\\Machine\\SOFTWARE\\Classes",
    }
    root = roots.get(fields[0].lower())
    if root == None:
        fail("unsupported non-machine registry root")
    path = root + ("\\" + fields[1] if len(fields) == 2 else "")
    return redirect_servicing_machine_registry_path(path, architecture)



def resolve_servicing_registry_key_pass(key, architecture):
    """Map a manifest registry key to its architecture-qualified pass using the compiled native path mapper."""
    return _SERVICING_REGISTRY_PATH_MAPPER(key, architecture)

def servicing_primitive_family_capacity(affected_identities):
    """Bound the native table capacity from complete affected TLC closures.

    GenerateServicingFamilies inserts only install/uninstall operations (0/1),
    and all members of their complete compositional closures. Stage, unstage,
    pin and unpin operations do not add entries. The caller must supply the
    identities from the verified complete affected install-mark analysis,
    not merely changed winners.

    Version-independent hashes give a lower bound on native family count;
    distinct full identities give an upper bound, covering version-scoped
    families without assuming their hash policy. Both bounds must imply the
    same capacity. This does not resolve within-bucket insertion order.
    """
    lower = {}
    upper = {}
    for identity in affected_identities:
        lower[windows.csi_identity_hash(identity, omit_version = True)] = True
        upper[str(identity).lower()] = True
    capacities = []
    for count in [len(lower), len(upper)]:
        capacity = 7
        for _ in range(32):
            if count <= capacity * 5:
                break
            # Native growth requests twice the entry count at the first
            # insertion exceeding load five, not twice the bucket count.
            capacity = 2 * (capacity * 5 + 1)
        if count > capacity * 5:
            fail("primitive family count exceeds capacity bound")
        capacities.append(capacity)
    if capacities[0] != capacities[1]:
        fail("primitive family capacity requires exact version-scoped counts")
    return dict(bucket_count = capacities[0], minimum_families = len(lower), maximum_families = len(upper))


def servicing_registry_driver_options(system):
    """Read the pinned existing-store configuration, without changing store mode.

    A missing/malformed value is outside this bounded recipe; it is not an
    instruction to create a driver database or enable the offline-new-store
    override. SYSTEM and DRIVERS are separate logical hives.
    """
    key = system.find("/DriverDatabase")
    if key == None:
        fail("existing store requires SYSTEM/DriverDatabase configuration")
    records = [r for name, r in key.value_records.items() if name.lower() == "configoptions"]
    if len(records) != 1 or records[0].type != 4 or len(records[0].raw) != 4:
        fail("existing store requires DWORD DriverDatabase ConfigOptions")
    return records[0].value


def _servicing_registry_xml_attributes(node):
    return node.attribute_map(strict=True)


def _servicing_registry_admitted(change, override):
    identities = change.get("component_identities", {})
    types = []
    for side in ["before", "after"]:
        if change[side] == None:
            continue
        identity = identities.get(side)
        if identity == None:
            fail("registry admission requires exact side-specific identities")
        types.append(windows.csi_identity(identity).type)
    if not types or any([kind != types[0] for kind in types]):
        fail("registry transition requires consistent identity types")
    return override or types[0] != "dualModeDriver"


def collect_servicing_registry_contributions(runtime, driver_config_options, source_roots, target, key_prefix=None, capture_key_records=False, compact_key_records=False):
    """Decode admitted values in native loops; do not select or apply winners.

    Admission, version-specific path rules, macro roots and key capture policy
    remain explicit recipe inputs. All contributors survive, including equal
    before/after declarations and duplicates. There is no unsupported fallback.
    """
    if type(driver_config_options) != "int" or driver_config_options < 0 or driver_config_options > 0xffffffff:
        fail("registry admission requires uint32 driver configuration")
    override = driver_config_options & 0x33 == 0x33
    manifests = []
    architectures = {}
    for index, change in enumerate(runtime["transitions"]):
        if not _servicing_registry_admitted(change, override):
            continue
        for side in ["before", "after"]:
            if change[side] == None:
                continue
            identity = change["component_identities"][side]
            if identity not in architectures:
                architectures[identity] = windows.csi_identity(identity).processor_architecture
            manifests.append(dict(root=servicing_runtime_manifest_root(change, side), architecture=architectures[identity], side=side, owner=index))
    def expand(value, architecture):
        return expand_servicing_registry_string(value, source_roots, target, architecture)
    return windows.registry_contributions(manifests, _SERVICING_REGISTRY_PATH_MAPPER, expand, key_prefix=key_prefix, capture_key_records=capture_key_records, compact_key_records=compact_key_records)


def analyze_servicing_registry_declarations(runtime, driver_config_options):
    """Collect admitted primitive declarations, not an ordered registry plan.

    Native 26100.9441 ProcessChange bypasses registry and later primitives for
    exact Type=dualModeDriver unless the existing-store ConfigOptions has all
    bits 0x33. Earlier file processing and separate CBS driver operations are
    NOT bypassed. Excluded transitions remain explicit for those consumers.
    Case folding Type here would disagree with native identity classification.

    Keys include their complete XML node (including security/empty keys), and
    values retain unexpanded attributes and side-specific source identity.
    Nothing is decoded, reduced, ordered, rooted, authorized or applied.
    """
    if type(driver_config_options) != "int" or driver_config_options < 0 or driver_config_options > 0xffffffff:
        fail("registry admission requires uint32 driver configuration")
    override = driver_config_options & 0x33 == 0x33
    keys = []
    values = []
    bypassed = []
    for change in runtime["transitions"]:
        identities = change.get("component_identities", {})
        if not _servicing_registry_admitted(change, override):
            bypassed.append(change)
            continue
        for side in ["before", "after"]:
            manifest = change[side]
            if manifest == None:
                continue
            root = servicing_runtime_manifest_root(change, side)
            if root.namespace not in ["urn:schemas-microsoft-com:asm.v1", "urn:schemas-microsoft-com:asm.v3"]:
                fail("unsupported runtime registry assembly namespace")
            definitions = _runtime_security_definitions(root)
            for container in root.children:
                if container.name != "registryKeys" or container.namespace != root.namespace:
                    continue
                for node in container.children:
                    if node.name != "registryKey" or node.namespace != root.namespace:
                        fail("unsupported registryKeys child")
                    attributes = _servicing_registry_xml_attributes(node)
                    key = attributes.get("keyName")
                    if key == None or not key:
                        fail("registry declaration requires keyName")
                    common = dict(family = change["identity"], identity = identities[side], side = side, key = key, key_attributes = attributes)
                    references = [n for n in node.children if n.name == "securityDescriptor" and n.namespace == root.namespace]
                    if len(references) > 1:
                        fail("duplicate runtime registry security reference")
                    descriptor = None
                    reference_attributes = None
                    if references:
                        name = references[0].attribute("name", None)
                        if name not in definitions:
                            fail("unresolved runtime registry security reference: " + str(name))
                        descriptor = definitions[name]
                        reference_attributes = references[0].attributes
                    keys.append(dict(common, node = node, descriptor = descriptor, reference_attributes = reference_attributes))
                    for value in node.children:
                        if value.name == "registryValue" and value.namespace == root.namespace:
                            if value.children or value.text.strip():
                                fail("unsupported registryValue content")
                            values.append(dict(common, attributes = _servicing_registry_xml_attributes(value)))
    return dict(keys = keys, values = values, bypassed_transitions = bypassed, dual_mode_driver_primitives = override)
