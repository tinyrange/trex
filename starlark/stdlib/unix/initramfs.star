"""Declarative Linux initramfs construction using native newc file views."""

def build(entries, init = None):
    """Build an uncompressed initramfs; supplied /init must be executable.

    Entries use Unix on-disk mode bits. Parent directories are supplied by
    the native builder. No payload is extracted or mounted on the host.
    """
    selected = {e["path"]: dict(e) for e in entries}
    if len(selected) != len(entries):
        fail("initramfs: duplicate paths")
    if init != None:
        if "init" in selected:
            fail("initramfs: init supplied twice")
        selected["init"] = {"path": "init", "mode": 0o100755, "data": init}
    if "init" not in selected or selected["init"].get("mode", 0o100644) & 0o170000 != 0o100000 or not selected["init"].get("mode", 0o100644) & 0o111:
        fail("initramfs: executable regular init required")
    for name in ["dev", "proc", "sys", "run", "tmp"]:
        if name not in selected:
            selected[name] = {"path": name, "mode": 0o041777 if name == "tmp" else 0o040755}
    for name, minor in [("console", 1), ("null", 3)]:
        full = "dev/" + name
        if full not in selected:
            selected[full] = {"path": full, "mode": 0o020600 if name == "console" else 0o020666, "major": 5 if name == "console" else 1, "minor": minor}
    return archive.cpio_build([selected[name] for name in sorted(selected)])
