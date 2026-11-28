"""Compose a prevalidated additive Debian package into an installed system."""

load(":tree.star", "file_entry", "tar_tree")

_STATUS = "var/lib/dpkg/status"
_INFO = "var/lib/dpkg/info/"

def _tar(container, prefix):
    names = [name for name in container.files if name == prefix + ".tar" or name.startswith(prefix + ".tar.")]
    if len(names) != 1:
        fail("Debian package must contain one " + prefix + " tar archive")
    name = names[0]
    source = container[name]
    if name.endswith(".zst"):
        source = binary.snapshot(archive.zstd(source), maximum = 256 << 20, fast = True)
    elif name.endswith(".xz"):
        source = archive.xz(source)
    elif name.endswith(".gz"):
        source = archive.gzip(source, cache = True, maximum_bytes = 256 << 20)
    elif not name.endswith(".tar"):
        fail("unsupported Debian tar compression: " + name)
    return archive.tar(source)

def _canonical(entries, path):
    prefix, separator, rest = path.partition("/")
    link = entries.get(prefix, {})
    target = link.get("target")
    if prefix in ["bin", "sbin", "lib", "lib64", "lib32", "libx32"] and target in ["usr/" + prefix, "/usr/" + prefix]:
        return "usr/" + prefix + separator + rest
    return path

def dpkg_add(entries, source, sha256, validate):
    """Install a standalone .deb with no maintainer scripts or conffiles."""
    if sha256 != None and binary.hex(digest(source)) != sha256.lower():
        fail("Debian archive digest mismatch")
    container = archive.ar(source, maximum_entries = 10)
    if container["debian-binary"].read() != "2.0\n":
        fail("unsupported Debian package format")
    control = _tar(container, "control")
    paragraphs = archive.debian_control(control["/control"])
    if len(paragraphs) != 1:
        fail("Debian package must have one control paragraph")
    package = paragraphs[0]
    fields = package.fields
    name = fields["package"]
    if not name or any([c not in "abcdefghijklmnopqrstuvwxyz0123456789+.-" for c in name.elems()]):
        fail("invalid Debian package name: " + name)
    if fields.get("multi-arch") == "same" or "status" in fields:
        fail("Debian package requires a different installed record: " + name)
    for member in tar_tree(control):
        if member not in [".", "control", "md5sums"]:
            fail("unmodeled Debian control member for " + name + ": " + member)

    status_file = entries[_STATUS]["data"]
    if type(status_file) == "string":
        status_file = binary.concat([status_file])
    installed = archive.debian_control(status_file)
    if any([record.fields["package"] == name for record in installed]):
        fail("Debian package is already in the status database: " + name)
    validate(fields, installed)
    payload = tar_tree(_tar(container, "data"))
    paths, additions = ["/."], {}
    for original, entry in payload.items():
        if original == ".":
            continue
        path = _canonical(entries, original)
        paths.append("/" + original)
        if path in entries or path in additions:
            prior = entries.get(path, additions.get(path))
            if entry["mode"] & 0o170000 == 0o040000 and prior["mode"] & 0o170000 == 0o040000:
                continue
            fail("Debian payload collision for " + name + ": " + path)
        entry["path"] = path
        if entry.get("hardlink"):
            entry["target"] = _canonical(entries, entry["target"])
        additions[path] = entry
    entries.update(additions)
    listing = _INFO + name + ".list"
    entries[listing] = file_entry(listing, "\n".join(paths) + "\n")
    sums = control.find("/md5sums")
    if sums != None:
        path = _INFO + name + ".md5sums"
        entries[path] = file_entry(path, sums)
    existing = status_file.read().rstrip("\n")
    entries[_STATUS] = file_entry(_STATUS, existing + "\n\nStatus: install ok installed\n" + package.raw + "\n\n")
