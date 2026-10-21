"""Basic Alpine APK v2 handling. Policy stays in Starlark, formats in Go.

Inputs are caller-pinned: read_package requires an independently trusted full
APK SHA-256. Embedded signatures are retained for inspection, not interpreted
as authentication. This is image construction, not an apk-tools replacement:
install scripts/triggers are returned and never silently executed or discarded.
"""

_TYPES = {"file": 0o100000, "directory": 0o040000, "symlink": 0o120000, "hardlink": 0o100000, "character_device": 0o020000, "block_device": 0o060000, "fifo": 0o010000}

def _path(name):
    if not name or name.startswith("/") or ".." in name.split("/") or "\x00" in name or "\\" in name:
        fail("alpine: unsafe archive path " + repr(name))
    parts = [part for part in name.split("/") if part and part != "."]
    return "/".join(parts) if parts else "."

def _fields(text, separator):
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        pair = line.split(separator, 1)
        if len(pair) != 2 or not pair[0].strip():
            fail("alpine: malformed metadata line " + repr(line))
        key, value = pair[0].strip(), pair[1].strip()
        if key not in out:
            out[key] = []
        out[key].append(value)
    return out

def _one(fields, name):
    values = fields.get(name, [])
    if len(values) != 1 or not values[0]:
        fail("alpine: exactly one " + name + " required")
    return values[0]

def parse_index(text, maximum_entries = 100000):
    """Parse APKINDEX text, retaining dependency/provides/checksum fields."""
    if maximum_entries <= 0:
        fail("alpine: positive maximum_entries required")
    records = []
    for paragraph in text.strip().split("\n\n"):
        if not paragraph.strip():
            continue
        fields = _fields(paragraph, ":")
        name, version, arch = _one(fields, "P"), _one(fields, "V"), _one(fields, "A")
        if not name or any([c in name for c in ["/", "\x00", " "]]) or any([c in version for c in ["/", "\x00", " "]]):
            fail("alpine: invalid index identity")
        size = int(_one(fields, "S"))
        if size <= 0:
            fail("alpine: invalid package size")
        records.append({"name": name, "version": version, "arch": arch, "size": size, "checksum": _one(fields, "C"), "depends": fields.get("D", [""])[0].split(), "provides": fields.get("p", [""])[0].split(), "fields": fields})
        if len(records) > maximum_entries:
            fail("alpine: maximum_entries exceeded")
    return records

def read_index(source, sha256, maximum_bytes = 32 << 20):
    """Read a trusted pinned APKINDEX.tar.gz; package signatures are not trust."""
    _verify(source, sha256)
    members = archive.gzip_members(source, maximum_bytes = maximum_bytes, maximum_members = 4)
    found = None
    for member in members:
        tar = archive.tar(archive.gzip(member, maximum_bytes = maximum_bytes))
        for entry in tar.entries:
            if _path(entry.name) == "APKINDEX":
                if found != None or entry.entry_type != "file":
                    fail("alpine: duplicate or non-file APKINDEX")
                found = parse_index(entry.read())
    if found == None:
        fail("alpine: APKINDEX missing")
    return found

def select(index, pins, arch = "x86_64"):
    """Select exact name -> version pins, never whichever release is newest.

    Dependency resolution is deliberately separate: pins must include the
    desired closure; validate_dependencies checks it after reading packages.
    """
    out = []
    for name in sorted(pins):
        candidates = [p for p in index if p["name"] == name and p["version"] == pins[name] and p["arch"] in [arch, "noarch"]]
        if len(candidates) != 1:
            fail("alpine: pin is absent or ambiguous: " + name + "=" + pins[name])
        out.append(candidates[0])
    return out

def _verify(source, sha256):
    if len(sha256) != 64 or any([sha256.lower()[i] not in "0123456789abcdef" for i in range(len(sha256))]):
        fail("alpine: trusted full-file SHA-256 required")
    if binary.hex(digest(source)) != sha256.lower():
        fail("alpine: SHA-256 mismatch")

def read_package(source, sha256, expected = None, maximum_bytes = 512 << 20, maximum_entries = 100000):
    """Validate pinned APK v2 and return metadata, entries and install effects."""
    _verify(source, sha256)
    members = archive.gzip_members(source, maximum_bytes = maximum_bytes, maximum_members = 3)
    if len(members) not in [2, 3]:
        fail("alpine: APK v2 requires control/data and optional signature members")
    control_member, data_member = members[-2], members[-1]
    signature = archive.tar(archive.gzip(members[0]), maximum_entries = maximum_entries) if len(members) == 3 else None
    if signature != None:
        for entry in signature.entries:
            if entry.entry_type != "file" or not _path(entry.name).startswith(".SIGN."):
                fail("alpine: invalid signature member")
    control = archive.tar(archive.gzip(control_member), maximum_entries = maximum_entries)
    metadata = None
    effects = {}
    for entry in control.entries:
        name = _path(entry.name)
        if name == ".PKGINFO":
            if metadata != None or entry.entry_type != "file":
                fail("alpine: duplicate or non-file .PKGINFO")
            metadata = _fields(entry.read(), "=")
        else:
            if entry.entry_type != "file" or not name.startswith(".") or "/" in name or name in effects:
                fail("alpine: invalid control entry " + name)
            effects[name] = entry
    if metadata == None:
        fail("alpine: .PKGINFO missing")
    name, version, arch = _one(metadata, "pkgname"), _one(metadata, "pkgver"), _one(metadata, "arch")
    if binary.hex(digest(data_member)) != _one(metadata, "datahash"):
        fail("alpine: datahash mismatch")
    if expected != None:
        if [name, version, arch] != [expected["name"], expected["version"], expected["arch"]] or source.size != expected["size"]:
            fail("alpine: package identity differs from pinned index")
        checksum = "Q1" + binary.base64(crypto.hash("sha1", control_member))
        if checksum != expected["checksum"]:
            fail("alpine: control checksum differs from index")
    tar = archive.tar(archive.gzip(data_member), maximum_entries = maximum_entries)
    entries = []
    seen = {}
    for item in tar.entries:
        path = _path(item.name)
        if path in seen:
            fail("alpine: duplicate data path " + path)
        seen[path] = True
        if item.entry_type not in _TYPES:
            fail("alpine: unsupported data entry " + item.entry_type)
        e = {"path": path, "mode": _TYPES[item.entry_type] | (item.mode & 0o7777), "uid": item.uid, "gid": item.gid, "mtime": item.mtime}
        if item.entry_type == "file":
            e["data"] = item
        elif item.entry_type == "hardlink":
            e["target"] = _path(item.link)
            e["hardlink"] = True
        elif item.entry_type == "symlink":
            e["target"] = item.link
        elif item.entry_type in ["character_device", "block_device"]:
            e["major"], e["minor"] = item.major, item.minor
        entries.append(e)
    return {"name": name, "version": version, "arch": arch, "metadata": metadata, "depends": metadata.get("depend", []), "provides": metadata.get("provides", []), "entries": entries, "effects": effects, "signatures": signature, "sha256": sha256.lower()}

def merge(packages, modifications = [], allow_effects = False):
    """Merge package payloads; conflicting files/effects require explicit policy."""
    out = {}
    owners = {}
    identities = {}
    for package in packages:
        if package["name"] in identities:
            fail("alpine: duplicate package identity")
        identities[package["name"]] = True
        if package["effects"] and not allow_effects:
            fail("alpine: installation effects require explicit policy: " + package["name"])
        for entry in package["entries"]:
            name = entry["path"]
            if name in out:
                if entry["mode"] & 0o170000 != 0o040000 or out[name]["mode"] & 0o170000 != 0o040000:
                    fail("alpine: conflicting payload " + name + " from " + owners[name] + " and " + package["name"])
                if any([entry.get(k, 0) != out[name].get(k, 0) for k in ["mode", "uid", "gid"]]):
                    fail("alpine: conflicting directory metadata " + name)
                continue
            out[name] = dict(entry)
            owners[name] = package["name"]
    modified = {}
    for entry in modifications:
        name = _path(entry["path"])
        if name in modified:
            fail("alpine: duplicate modification " + name)
        modified[name] = True
        e = dict(entry)
        e["path"] = name
        out[name] = e
    return [out[name] for name in sorted(out)]

def _dependency(value):
    for i in range(len(value)):
        if value[i] in "=<>~":
            return value[:i], value[i:]
    return value, ""

def _dependency_graph(packages, external):
    providers = {name: [(None, "")] for name in external}
    identities = {}
    for p in packages:
        if p["name"] in identities:
            fail("alpine: duplicate package identity " + p["name"])
        identities[p["name"]] = p
        for value in [p["name"] + "=" + p["version"]] + p["provides"]:
            name, constraint = _dependency(value)
            if not name or (constraint and (not constraint.startswith("=") or not constraint[1:])):
                fail("alpine: unsupported provider constraint " + value)
            item = (p["name"], constraint[1:] if constraint else "")
            if name not in providers:
                providers[name] = []
            if item not in providers[name]:
                providers[name].append(item)
    graph = {}
    for p in packages:
        dependencies = {}
        for value in p["depends"]:
            conflict = value.startswith("!")
            name, constraint = _dependency(value[1:] if conflict else value)
            if not name or (constraint and (not constraint.startswith("=") or not constraint[1:])):
                fail("alpine: range constraint needs apk version policy: " + value)
            matches = [owner for owner, version in providers.get(name, []) if not constraint or version == constraint[1:]]
            if conflict:
                if matches:
                    fail("alpine: dependency conflict: " + value + " for " + p["name"])
                continue
            if not matches:
                fail("alpine: missing dependency: " + value + " for " + p["name"])
            if len(matches) != 1:
                fail("alpine: ambiguous provider for " + value)
            if matches[0] != None and matches[0] != p["name"]:
                dependencies[matches[0]] = True
        graph[p["name"]] = sorted(dependencies)
    return graph

def validate_dependencies(packages, external = []):
    """Check bare/exact dependencies, virtual provides and conflicts.

    Range/tilde constraints fail explicitly: this basic pinned policy does not
    implement apk version ordering or silently relax unsupported constraints.
    External capabilities must be explicitly named by the caller.
    """
    _dependency_graph(packages, external)
    return True

def install_plan(packages, modifications = [], external = []):
    """Return dependency-ordered payloads and explicit install-effect records.

    Inspired by pkg2's declarative package plans, not its guest script runner.
    No effect is executed. Each record retains its original script file and
    trigger patterns; unknown control effects are retained as phase "other".
    A consumer must implement or explicitly replace every relevant effect.
    Dependency cycles and ambiguous virtual providers require caller policy.
    """
    graph = _dependency_graph(packages, external)
    by_name = {p["name"]: p for p in packages}
    ordered = []
    emitted = {}
    for _ in range(len(packages) + 1):
        progress = False
        for name in sorted(graph):
            if name not in emitted and all([dep in emitted for dep in graph[name]]):
                ordered.append(by_name[name])
                emitted[name] = True
                progress = True
        if len(emitted) == len(packages):
            break
        if not progress:
            fail("alpine: package dependency cycle")
    effects = []
    phases = {".pre-install": "pre-install", ".post-install": "post-install", ".pre-upgrade": "pre-upgrade", ".post-upgrade": "post-upgrade", ".pre-deinstall": "pre-deinstall", ".post-deinstall": "post-deinstall", ".trigger": "trigger"}
    for p in ordered:
        for name in sorted(p["effects"]):
            effects.append({"package": p["name"], "name": name, "phase": phases.get(name, "other"), "script": p["effects"][name], "trigger_patterns": [pattern for value in p["metadata"].get("triggers", []) for pattern in value.split()] if name == ".trigger" else []})
    return {"packages": ordered, "dependencies": graph, "entries": merge(ordered, modifications, allow_effects = True), "effects": effects}
