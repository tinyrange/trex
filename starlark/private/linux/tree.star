"""Copy portable Unix filesystem metadata into image-builder entries."""

_TYPES = {
    "file": 0o100000,
    "directory": 0o040000,
    "symlink": 0o120000,
    "character_device": 0o020000,
    "block_device": 0o060000,
    "fifo": 0o010000,
    "socket": 0o140000,
}
_SQUASHFS_SPECIAL = {4: "block_device", 5: "character_device", 6: "fifo", 7: "socket"}

def file_entry(path, data, mode = 0o644):
    return {"path": path, "mode": 0o100000 | mode, "data": data}

def symlink_entry(path, target):
    return {"path": path, "mode": 0o120777, "target": target}

def filesystem_entry(node, path, links):
    """Describe one auto filesystem node, borrowing its regular-file data."""
    summary = node.summary
    attrs = summary["attributes"]
    kind = summary["kind"]
    if kind == "special":
        kind = _SQUASHFS_SPECIAL[attrs["inode_type"]]
    elif kind == "device":
        kind = "character_device" if attrs["mode"] & 0o170000 == 0o020000 else "block_device"
    entry = {"path": path, "mode": _TYPES[kind] | (attrs["mode"] & 0o7777), "uid": attrs["uid"], "gid": attrs["gid"], "mtime": attrs["mtime"]}
    if "xattrs" in attrs:
        entry["xattrs"] = {name: binary.decode(value, "base64") for name, value in attrs["xattrs"].items()}
    if kind == "file":
        identity = attrs.get("inode", attrs.get("nid")) if attrs.get("nlink", attrs.get("links", 1)) > 1 else None
        if identity != None and identity in links:
            entry.update({"hardlink": True, "target": links[identity]})
        else:
            entry["data"] = node.file
            if identity != None:
                links[identity] = path
    elif kind == "symlink":
        entry["target"] = attrs["target"]
    elif kind in ["character_device", "block_device"]:
        if "rdev" in attrs or "device" in attrs:
            raw = attrs.get("rdev", attrs.get("device"))
            entry["major"] = (raw >> 8) & 0xfff
            entry["minor"] = (raw & 0xff) | ((raw >> 12) & 0xfff00)
        else:
            entry["major"] = attrs["major"]
            entry["minor"] = attrs["minor"]
    return entry

def filesystem_tree(root, maximum_entries = 500000, prefix = "", names = None):
    """Walk one filesystem and retain its paths and hardlinks."""
    roots = root.files if names == None else [root.find(name) for name in names]
    if None in roots:
        fail("a selected filesystem root is missing")
    pending = [(node, prefix + node.name) for node in reversed(roots)]
    entries = {}
    links = {}
    for _ in range(maximum_entries):
        if not pending:
            return entries
        node, path = pending.pop()
        if path in entries:
            fail("duplicate filesystem path " + path)
        entry = filesystem_entry(node, path, links)
        entries[path] = entry
        if entry["mode"] & 0o170000 == 0o040000:
            pending.extend([(child, path + "/" + child.name) for child in reversed(node.files)])
    if pending:
        fail("filesystem tree exceeds the entry limit")
    return entries

def tar_tree(archive):
    """Assemble portable entries from a Unix root archive."""
    entries = {}
    for item in archive.entries:
        name = item.name
        if name.startswith("/") or ".." in name.split("/") or "\x00" in name:
            fail("unsafe Unix archive path " + repr(name))
        path = "/".join([part for part in name.split("/") if part and part != "."]) or "."
        if path in entries:
            fail("duplicate Unix archive path " + path)
        kind = item.entry_type
        entry = {"path": path, "mode": _TYPES["file" if kind == "hardlink" else kind] | (item.mode & 0o7777), "uid": item.uid, "gid": item.gid, "mtime": max(0, item.mtime)}
        if kind == "file":
            entry["data"] = item
        elif kind == "hardlink":
            entry["target"], entry["hardlink"] = item.link, True
        elif kind == "symlink":
            entry["target"] = item.link
        elif kind in ["character_device", "block_device"]:
            entry["major"], entry["minor"] = item.major, item.minor
        entries[path] = entry
    return entries

def install_systemd_smoke(entries, command):
    """Run a bounded serial proof after normal systemd initialization."""
    service = "etc/systemd/system/trex-smoke.service"
    enabled = "etc/systemd/system/multi-user.target.wants/trex-smoke.service"
    program = "usr/libexec/trex-smoke"
    entries[program] = file_entry(program, command, 0o755)
    entries[service] = file_entry(service, """[Unit]
Description=Trex installed Linux smoke
After=systemd-user-sessions.service

[Service]
Type=oneshot
ExecStart=/usr/libexec/trex-smoke
TimeoutStartSec=30s
StandardOutput=journal+console
StandardError=journal+console
""")
    entries[enabled] = symlink_entry(enabled, "../trex-smoke.service")
    for path, exemplar in [
        (program, "usr/bin/bash"),
        (service, "usr/lib/systemd/system/systemd-user-sessions.service"),
        (enabled, "usr/lib/systemd/system/systemd-user-sessions.service"),
    ]:
        context = entries.get(exemplar, {}).get("xattrs", {}).get("security.selinux")
        if context != None:
            entries[path]["xattrs"] = {"security.selinux": context}
