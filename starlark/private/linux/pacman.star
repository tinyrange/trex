"""Build additive Pacman package plans and install their native file records."""

load(":tree.star", "file_entry", "tar_tree")

def _spec(value):
    for operator in [">=", "<=", "=", ">", "<"]:
        parts = value.split(operator, 1)
        if len(parts) == 2:
            return (parts[0], operator, parts[1])
    return (value, "", "")

def _satisfies(version, operator, required):
    if not operator:
        return True
    if not version:
        return False
    cmp = archive.pacman_compare(version, required)
    return cmp == 0 if operator == "=" else cmp >= 0 if operator == ">=" else cmp <= 0 if operator == "<=" else cmp > 0 if operator == ">" else cmp < 0

def _provides(record):
    fields = record["fields"]
    return [(fields["NAME"][0], fields["VERSION"][0])] + [(name, version) for name, _, version in [_spec(v) for v in fields.get("PROVIDES", [])]]

def _index_provides(index, record):
    for name, version in _provides(record):
        index.setdefault(name, []).append((version, record))

def _candidates(index, requirement):
    name, operator, version = _spec(requirement)
    return [record for candidate, record in index.get(name, []) if _satisfies(candidate, operator, version)]

def _catalog(repositories):
    records = {}
    for repo, source in repositories:
        tar = archive.tar(archive.gzip(source, maximum_bytes = 128 << 20, cache = True))
        for info in tar.entries:
            if info.entry_type == "file" and info.path.endswith("/desc"):
                fields = archive.pacman_metadata(info)
                name = fields["NAME"][0]
                if fields["ARCH"][0] in ["x86_64", "any"] and name not in records:
                    records[name] = {"repo": repo, "fields": fields}
    return records

def pacman_plan(installed, repositories, requested):
    """Resolve an additive transaction from the supplied repository indexes. Existing package versions stay installed."""
    catalog = _catalog(repositories)
    pool, current = {}, {}
    for record in catalog.values():
        _index_provides(pool, record)
    for fields in installed:
        record = {"fields": fields}
        current[fields["NAME"][0]] = record
    available = {}
    for record in current.values():
        _index_provides(available, record)
    selected = []
    pending = list(requested)
    for _ in range(len(catalog) + 1):
        if not pending:
            break
        dependencies = []
        for requirement in pending:
            if _candidates(available, requirement):
                continue
            candidates = _candidates(pool, requirement)
            wanted = _spec(requirement)[0]
            exact = [p for p in candidates if p["fields"]["NAME"][0] == wanted]
            candidates = exact or sorted(candidates, key = lambda p: p["fields"]["NAME"][0])
            if not candidates:
                fail("Pacman dependency has no provider: " + requirement)
            record = candidates[0]
            fields = record["fields"]
            name = fields["NAME"][0]
            if name in current:
                fail("Pacman desktop plan requires replacing " + name + " for " + requirement)
            current[name] = record
            _index_provides(available, record)
            selected.append(record)
            dependencies.extend(fields.get("DEPENDS", []))
        pending = dependencies
    if pending:
        fail("Pacman dependency expansion did not terminate")
    for record in selected:
        fields = record["fields"]
        for other in fields.get("CONFLICTS", []):
            if any([candidate != record for candidate in _candidates(available, other)]):
                fail(fields["NAME"][0] + " conflicts with " + other)
    return selected

def pacman_add(entries, plan, sources, explicit, permit_hook = None):
    """Apply repository packages and generate local records from their original archives."""
    additions = {}
    for record in plan:
        fields = record["fields"]
        name, version, filename = fields["NAME"][0], fields["VERSION"][0], fields["FILENAME"][0]
        source = sources[filename]
        if binary.hex(digest(source)) != fields["SHA256SUM"][0]:
            fail("Pacman package digest mismatch for " + filename)
        archive_file = archive.tar(binary.snapshot(archive.zstd(source), maximum = 512 << 20, fast = True))
        metadata = archive.pacman_metadata(archive_file["/.PKGINFO"], pkginfo = True)
        if metadata["pkgname"] != [name] or metadata["pkgver"] != [version]:
            fail("Pacman archive identity mismatch for " + filename)
        install = archive_file.find("/.INSTALL")
        if install != None and (permit_hook == None or not permit_hook(name, install)):
            fail("unmodeled Pacman install script for " + name)
        payload = tar_tree(archive_file)
        paths, backups = [], []
        for path, entry in payload.items():
            if path in [".", ".BUILDINFO", ".INSTALL", ".MTREE", ".PKGINFO"]:
                continue
            is_directory = entry["mode"] & 0o170000 == 0o040000
            paths.append(path + "/" if is_directory else path)
            prior = entries.get(path, additions.get(path))
            if prior != None:
                if is_directory and prior["mode"] & 0o170000 == 0o040000:
                    continue
                fail("Pacman payload collision at " + path + " for " + name)
            additions[path] = entry
        for path in metadata.get("backup", []):
            path = path.lstrip("/")
            backups.append(path + "\t" + binary.hex(digest(payload[path]["data"], algorithm = "md5")))
        local = "var/lib/pacman/local/" + name + "-" + version
        records = archive.pacman_installed(fields, sorted(paths), sorted(backups), explicit = name in explicit)
        additions[local + "/desc"] = file_entry(local + "/desc", records.desc)
        additions[local + "/files"] = file_entry(local + "/files", records.files)
        mtree = archive_file.find("/.MTREE")
        if mtree != None:
            additions[local + "/mtree"] = file_entry(local + "/mtree", mtree)
        if install != None:
            additions[local + "/install"] = file_entry(local + "/install", install)
    entries.update(additions)
