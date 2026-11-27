"""Build an IRIX 6.5.22 maintenance-stream Indy system from its original discs."""

load("//scripts/smoke:irix_ip24.star", "prepare_disk")
load("//scripts/smoke:irix_ip24_desktop.star", "start_desktop_on", "verify_constructed_desktop")

_INDY = {
    "MACHINE": "IP22",
    "CPUBOARD": "IP22",
    "CPUARCH": "R4000",
    "GFXBOARD": "NEWPORT",
    "SUBGR": "NG1",
    "MODE": "32bit",
    "VIDEO": "VINO",
}

_MODES = {"file": 0o100000, "directory": 0o040000, "symlink": 0o120000,
          "character_device": 0o020000, "block_device": 0o060000, "fifo": 0o010000}

_OBSOLETE_MANPAGES = [
    "/usr/share/catman/p_man/cat2/standard/_sqrt_d.z",
    "/usr/share/catman/p_man/cat2/standard/_sqrt_s.z",
    "/usr/share/catman/p_man/cat2/standard/sqrt.z",
]

_DESKTOP_PRODUCTS = ["desktop_eoe", "desktop_tools", "sysadmdesktop"]

def _cd(source):
    entries = archive.sevenzip(source).entries
    discs = [e for e in entries if e.entry_type == "file" and e.path.lower().endswith(".iso")]
    if len(discs) != 1:
        fail("Expected one SGI CD image in the archive")
    # EFS seeks throughout the CD. Decode the compressed member once.
    volume = filesystem.sgi(binary.view(discs[0].bytes()))
    parts = [p.data for p in volume.partitions if p.index == 7]
    if len(parts) != 1:
        fail("Expected the SGI CD's distribution partition", discs[0].path)
    return filesystem.efs(parts[0]), volume

def _add_catalog(dist, descriptors, indexes, images, names = []):
    for entry in dist.entries:
        if entry.entry_type != "file" or not entry.path.startswith("/dist/") or not entry.path.endswith(".idb"):
            continue
        base = entry.path[:-4]
        if base.count("/") != 2:
            # Platform and separately bundled options have their own catalogs.
            continue
        if names and base.split("/")[-1] not in names:
            continue
        descriptor = dist.find(base)
        if descriptor == None or descriptor.data.bytes(0, 5) != b"pd001":
            continue
        descriptors.append(descriptor.data)
        for product in archive.irix_product(descriptor.data).products:
            for image in product.images:
                version = "@" + str(image.version)
                index_key = product.name + version
                if index_key in indexes and indexes[index_key] != entry.data:
                    fail("Multiple physical catalogs share an IRIX product and version", index_key)
                indexes[index_key] = entry.data
                payload = dist.find(base + "." + image.name)
                if payload != None:
                    images[product.name + "." + image.name + version] = payload.data

def system_catalog(foundation1, foundation2, overlay1, overlay2, overlay3, applications = None):
    """Open the core media and optionally add the complete desktop products."""
    foundation, overlays, indexes, images = [], [], {}, {}
    boot_dist, boot_volume = _cd(overlay1)
    kernel = boot_dist.find("/dist/miniroot/unix.IP22")
    miniroot = [f.data for f in boot_volume.files if f.name == "mr"]
    if kernel == None or len(miniroot) != 1:
        fail("Expected the original 6.5.22 IP22 kernel and miniroot on Overlay 1")
    _add_catalog(boot_dist, overlays, indexes, images)
    for source in [foundation1, foundation2]:
        dist, _ = _cd(source)
        _add_catalog(dist, foundation, indexes, images)
    if applications != None:
        dist, _ = _cd(applications)
        _add_catalog(dist, foundation, indexes, images, names = _DESKTOP_PRODUCTS)
    for source in [overlay2, overlay3]:
        dist, _ = _cd(source)
        _add_catalog(dist, overlays, indexes, images)
    return {"foundation": foundation, "overlays": overlays, "indexes": indexes, "images": images,
            "kernel": kernel.data, "miniroot": miniroot[0], "interactive_desktop": applications != None}

def plan_system(catalog):
    """Resolve Foundation and Overlay actions in installation order."""
    foundation = archive.irix_plan(catalog["foundation"], [], machine = _INDY,
                                   indexes = catalog["indexes"], images = catalog["images"])
    installed = {selection.name: selection.version for selection in foundation.selected}
    overlay = archive.irix_plan(catalog["overlays"], [], machine = _INDY, installed = installed,
                                indexes = catalog["indexes"], images = catalog["images"])
    return foundation, overlay

def _ids(file):
    ids = {}
    for line in file.read().splitlines():
        fields = line.split(":")
        if len(fields) >= 3 and fields[2].isdigit():
            ids[fields[0]] = int(fields[2])
    return ids

def _canonical_parent(name, symlinks):
    # Follow only ancestor aliases. The terminal record itself is installed
    # at its canonical parent, including when it is a symbolic link.
    pending, parts = name[1:].split("/"), []
    for _ in range(256):
        if not pending:
            return "/" + "/".join(parts)
        component, pending = pending[0], pending[1:]
        if component in ["", "."]:
            continue
        if component == "..":
            if parts:
                parts.pop()
            continue
        parts.append(component)
        target = symlinks.get("/" + "/".join(parts))
        if pending and target != None:
            parts.pop()
            if target.startswith("/"):
                parts = []
            pending = target.split("/") + pending
    fail("Too many IRIX directory alias components", name)

def _installed_rows(foundation, overlay):
    files = {op.path: op for op in foundation.operations}
    overlay_paths = {op.path: True for op in overlay.operations}
    # Overlay images are incremental. Preserve Foundation paths for which
    # the overlay provides no operation, even inside an upgraded subsystem.
    for op in overlay.operations:
        if op.kind == "unsupported" and op.path in _OBSOLETE_MANPAGES and op.path not in files:
            continue  # The Foundation catalogs contain no file at these paths.
        files[op.path] = op
    symlinks = {name: op.target for name, op in files.items() if op.kind == "symlink"}
    sources, precedence = {}, {}
    for name in files:
        destination = _canonical_parent(name, symlinks)
        rank = (2 if name in overlay_paths else 0) + (1 if name == destination else 0)
        # Prefer the later layer and use the canonical physical record
        # when both spellings occur in that layer.
        if rank > precedence.get(destination, -1):
            sources[destination] = name
            precedence[destination] = rank

    uid = _ids(files["/etc/passwd"].data)
    gid = _ids(files["/etc/group"].data)
    rows, links = {}, []
    for dest, source in sources.items():
        op = files[source]
        if op.kind == "hardlink":
            links.append((dest, _canonical_parent(op.target, symlinks)))
            continue
        if op.kind not in _MODES:
            fail("Unsupported IRIX install operation", op.path, op.kind)
        row = {"path": dest[1:] or ".", "mode": _MODES[op.kind] | (op.mode & 0o7777),
               "uid": uid[op.owner], "gid": gid[op.group]}
        if op.kind == "file":
            if op.data == None:
                fail("Missing IRIX payload", op.path, op.image)
            row["data"] = op.data
        elif op.kind == "symlink":
            row["target"] = op.target
        elif op.kind in ["block_device", "character_device"]:
            row.update(major = op.major, minor = op.minor)
        rows[dest] = row
    for dest, target in links:
        row = dict(rows[target], path = dest[1:], target = target[1:], hardlink = True)
        row.pop("data")
        rows[dest] = row
    return rows

def _initial_devices(rows, miniroot):
    # The original miniroot supplies the static console and memory devices.
    for e in filesystem.xfs(miniroot, path = "/dev").entries:
        if e.entry_type in ["character_device", "block_device"]:
            rows[e.path] = {"path": e.path[1:], "mode": e.mode, "uid": e.uid, "gid": e.gid,
                            "major": e.major, "minor": e.minor}
    # MAKEDEV links the historical names to the kernel's hardware graph.
    aliases = {"root": "/hw/disk/root", "rroot": "/hw/rdisk/root", "swap": "/hw/disk/swap",
               "rswap": "/hw/rdisk/swap", "dsk": "/hw/disk", "rdsk": "/hw/rdisk",
               "scsi": "/hw/scsi",
               "ttyd1": "/hw/ttys/ttyd1", "ttyd2": "/hw/ttys/ttyd2",
               "keybd": "/hw/input/keyboard", "mouse": "/hw/input/mouse",
               "input/keyboard": "/hw/input/keyboard", "input/mouse": "/hw/input/mouse",
               "input/tablet": "/hw/input/tablet"}
    for name, target in aliases.items():
        rows["/dev/" + name] = {"path": "dev/" + name, "mode": 0o120755, "target": target}
    rows["/dev/pts"] = {"path": "dev/pts", "mode": 0o040755}
    for name, major, minor, permissions in [
        ("tty", 2, 0, 0o666), ("graphics", 57, 0, 0o666), ("gfx", 10, 56, 0o666),
        ("ptc", 10, 14, 0o666), ("ptmx", 10, 14, 0o666), ("ptc1", 10, 104, 0o666),
        ("ptc2", 10, 106, 0o666), ("ptc3", 10, 108, 0o666), ("ptc4", 10, 110, 0o666),
        ("mem", 1, 0, 0o640), ("kmem", 1, 1, 0o640), ("mmem", 1, 3, 0o666),
        ("log", 10, 80, 0o666),
        ("shmiq", 10, 54, 0o666), ("qcntl0", 55, 0, 0o666), ("opengl", 57, 1, 0o666),
        ("xconns", 265, 0, 0o600),
    ] + [("ttyq" + str(n), 15, n, 0o600) for n in range(11)]:
        rows["/dev/" + name] = {"path": "dev/" + name, "mode": 0o020000 | permissions,
                                "major": major, "minor": minor}

def build_system(catalog, size = 1870 << 20):
    """Materialize the selected 6.5.22m files in a generated SGI disk."""
    foundation, overlay = plan_system(catalog)
    rows = _installed_rows(foundation, overlay)
    _initial_devices(rows, catalog["miniroot"])
    # The distribution kernel cannot open its primary swap device during
    # early boot. rc2 can add the partition once the device graph is mounted.
    rows["/etc/fstab"] = {"path": "etc/fstab", "mode": 0o100644,
                         "data": "/dev/root / xfs rw,raw=/dev/rroot 0 0\n" +
                                 "/dev/dsk/dks0d1s0 swap swap pri=0 0 0\n"}
    # brc mounts the device graph before rc2. Add swap before rc2 starts
    # daemons that can exhaust the distribution kernel's initial memory.
    swap_start = rows.pop("/etc/rc2.d/S49swap")
    rows["/etc/rc2.d/S01swap"] = dict(swap_start, path = "etc/rc2.d/S01swap")
    rows["/tmp"] = {"path": "tmp", "mode": 0o041777}
    rows["/var/tmp"] = {"path": "var/tmp", "mode": 0o041777, "uid": 4}
    rows["/unix"] = {"path": "unix", "mode": 0o100755, "data": catalog["kernel"]}
    if catalog.get("interactive_desktop"):
        for path in ["/etc/rc2.d/S98xdm", "/usr/Cadmin/bin/clogin",
                     "/var/X11/xdm/Xsession.dt", "/usr/lib/desktop/makeDotDesktop"]:
            if path not in rows:
                fail("Missing installed Interactive Desktop file", path)
        # Start the display manager after networking, swap, and temporary
        # directory setup, before the remaining workstation services.
        xdm = rows.pop("/etc/rc2.d/S98xdm")
        rows["/etc/rc2.d/S59xdm"] = dict(xdm, path = "etc/rc2.d/S59xdm")
        rows["/etc/config/visuallogin"] = {"path": "etc/config/visuallogin", "mode": 0o100644, "data": "on\n"}
    # The inst postops move these two files into the volume header.
    volume_files = {"sash": rows.pop("/stand/sash")["data"], "ide": rows.pop("/stand/ideloader")["data"]}
    root = filesystem.xfs_build(rows.values(), size, b"IRIX6522IndyXFS1", label = "IRIX6.5.22")
    swap = block.view(block.blank(128 << 20))
    # The unmodified distribution kernel defaults to root partition 1.
    image = filesystem.sgi_build([(0, 3, swap), (1, 10, root)], root = 1, swap = 0,
                                 bootfile = "unix", header_blocks = 4096, volume_files = volume_files)
    return {"disk": image, "root": root, "kernel": catalog["kernel"], "plans": [foundation, overlay]}

def start_system(system, single_user = True):
    """Start the media-built XFS root on the Newport Indy."""
    return prepare_disk(system["disk"], system["kernel"], "dksc(0,1,1)", newport = True, single_user = single_user,
                        kernel_options = ["swap=/dev/dsk/dks0d1s0"])

def main(args):
    if len(args) != 6:
        fail("usage: irix_ip24_system.star FOUNDATION1.7z FOUNDATION2.7z OVERLAY1.7z OVERLAY2.7z OVERLAY3.7z DESKTOP.png")
    system = build_system(system_catalog(*[open(name) for name in args[:5]]))
    root = system["root"]
    for name, kind in [("/bin", "symlink"), ("/etc/rc2", "file"), ("/sbin/init", "file"),
                       ("/dev/graphics", "character_device"), ("/var/tmp", "directory"),
                       ("/usr/gfx/arch/IP22NG1/Xsgi", "file"), ("/usr/bin/X11/xcalc", "file")]:
        entry = filesystem.xfs_lookup(root, name)
        if entry == None or entry.entry_type != kind:
            fail("Missing installed IRIX filesystem entry", name, kind)
    volume = filesystem.sgi(system["disk"])
    if [entry.name for entry in volume.files] != ["sash", "ide"]:
        fail("Missing IRIX volume-header programs")
    machine, _ = start_system(system)
    _, console = start_desktop_on(machine)
    verify_constructed_desktop(machine, console, args[5])
    machine.close()
    print("Booted IRIX 6.5.22m from the generated XFS filesystem and verified Calculator")
