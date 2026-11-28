"""Construct an Alpine installed disk from original APK and ISO media."""

load("@stdlib//unix:alpine.star", "read_index", "read_package")
load("@stdlib//unix:initramfs.star", initramfs = "build")
load("@stdlib//unix:kernel.star", "modules", "select")
load("//starlark/private/linux:disk.star", "disk_image", "root_partition_id")

_INSTALLED = "lib/apk/db/installed"
_SCRIPTS = "lib/apk/db/scripts.tar"
_TRIGGERS = "lib/apk/db/triggers"
_ROOT_PATH = "/dev/nvme0n1p2"

_ARCHIVE_MODES = {
    "file": 0o100000,
    "directory": 0o040000,
    "symlink": 0o120000,
    "hardlink": 0o100000,
    "character_device": 0o020000,
    "block_device": 0o060000,
    "fifo": 0o010000,
}

_WORLD = ["alpine-base", "ifupdown-ng", "jq", "linux-virt", "mkinitfs"]
_UPGRADE_EFFECTS = [".pre-deinstall", ".post-deinstall", ".pre-upgrade", ".post-upgrade"]

def _tar_entry(item):
    path = item.path.lstrip("/") or "."
    entry = {"path": path, "mode": _ARCHIVE_MODES[item.entry_type] | item.mode, "uid": item.uid, "gid": item.gid, "mtime": item.mtime}
    if item.entry_type == "file":
        entry["data"] = item
    elif item.entry_type == "symlink":
        entry["target"] = item.link
    elif item.entry_type == "hardlink":
        entry["target"] = item.link[2:] if item.link.startswith("./") else item.link
        entry["hardlink"] = True
    elif item.entry_type in ["character_device", "block_device"]:
        entry.update(major = item.major, minor = item.minor)
    return entry

def _base_records(value):
    return [{line[0]: line[2:] for line in record.splitlines() if len(line) >= 2 and line[0] in "PVDpk"}
            for record in value.strip().split("\n\n")]

def _base_owners(value):
    owned = {}
    parent = ""
    for line in value.splitlines():
        if line.startswith("F:"):
            parent = line[2:]
        elif line.startswith("R:"):
            path = (parent + "/" if parent else "") + line[2:]
            owned[path] = True
    return owned

def _fields(record):
    return {key: values[0] for key, values in record["fields"].items()}

def _source_name(record):
    return "%s-%s.apk" % (record["name"], record["version"])

def _package_catalog(iso, repo, community):
    catalog = {}
    if community != None:
        for record in read_index(community, None):
            catalog[record["name"]] = dict(record, repository = "community")
    for record in read_index(repo, None):
        catalog[record["name"]] = dict(record, repository = "main")
    index = iso["/apks/x86_64/APKINDEX.tar.gz"]
    internal = read_index(index, None)
    catalog.update({record["name"]: dict(record, repository = "iso") for record in internal})
    return catalog

def _selection(catalog, base, world):
    selected = [name + "=" + catalog[name]["version"] for name in world]
    wanted = archive.apk_resolve([_fields(r) for r in catalog.values()], _base_records(base), selected)
    return [catalog[identity.split("=", 1)[0]] for identity in wanted]

def _release(iso, root):
    version = root["/etc/alpine-release"].read().strip()
    parts = version.split(".")
    if len(parts) < 2 or not all([part.isdigit() for part in parts]):
        fail("Alpine miniroot must identify a stable release series")
    series = ".".join(parts[:2])
    label = iso["/.alpine-release"].read().split()
    if not label or not label[0].startswith("alpine-virt-" + series + "."):
        fail("Alpine virt ISO and miniroot must be from the same stable release series")
    return (version, series)

def alpine_repository_plan(boot_media, miniroot, repository, community = None, extra_packages = ()):
    """List the external repository and filename of each selected package."""
    iso = filesystem.iso9660(boot_media)
    root = archive.tar(archive.gzip(miniroot))
    _release(iso, root)
    selection = _selection(_package_catalog(iso, repository, community), root["/" + _INSTALLED].read(), _WORLD + list(extra_packages))
    return [(r["repository"], _source_name(r)) for r in selection if r["repository"] != "iso"]

def _place(entries, entry, owned):
    path = entry["path"]
    existing = entries.get(path)
    if existing != None and existing["mode"] & 0o170000 == 0o040000 and entry["mode"] & 0o170000 == 0o040000:
        return
    busybox_alias = existing != None and existing["mode"] & 0o170000 == 0o120000 and existing["target"] == "/bin/busybox" and path not in owned
    if existing != None and not busybox_alias:
        fail("Alpine package path collision at " + path)
    entries[path] = entry
    owned[path] = True

def _file(path, data, mode = 0o644):
    return {"path": path, "mode": 0o100000 | mode, "data": data}

def _early_boot(entries, kernel):
    busybox = entries["bin/busybox"]["data"]
    libc = entries["lib/ld-musl-x86_64.so.1"]["data"]
    ram = [
        _file("bin/busybox", busybox, 0o755),
        _file("lib/ld-musl-x86_64.so.1", libc, 0o755),
        {"path": "bin/sh", "mode": 0o120777, "target": "busybox"},
        {"path": "newroot", "mode": 0o040755},
    ]
    commands = ["""#!/bin/sh
set -eu
B=/bin/busybox
$B mount -t proc proc /proc
$B mount -t sysfs sysfs /sys
$B mount -t devtmpfs devtmpfs /dev
"""]
    for module in modules(kernel, ["nvme", "ext4"], aliases = {"crc32c": "crc32c_generic"}):
        mod = dict(module)
        if mod["path"].endswith(".gz"):
            mod.update(path = mod["path"][:-3], data = archive.gzip(mod["data"], maximum_bytes = 8 << 20))
        if mod["path"].endswith(".xz") or mod["path"].endswith(".zst"):
            fail("unsupported early boot module compression " + mod["path"])
        ram.append(mod)
        commands.append("$B insmod /" + mod["path"] + "\n")
    commands.append("""
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    [ -b ROOT_DEVICE ] && break
    $B sleep 1
done
$B mount -t ext4 -o rw ROOT_DEVICE /newroot
$B mount -o move /dev /newroot/dev
$B mount -o move /proc /newroot/proc
$B mount -o move /sys /newroot/sys
exec $B switch_root /newroot /sbin/init
""".replace("ROOT_DEVICE", _ROOT_PATH))
    return initramfs(ram, init = "".join(commands))

def _openrc(entries):
    for level, services in [
        ("sysinit", ["devfs", "dmesg", "mdev"]),
        ("boot", ["bootmisc", "hostname", "hwclock", "modules", "sysctl"]),
        ("shutdown", ["killprocs", "mount-ro", "savecache"]),
    ]:
        for name in services:
            script = "etc/init.d/" + name
            if script not in entries:
                fail("missing Alpine OpenRC service " + script)
            path = "etc/runlevels/" + level + "/" + name
            entries[path] = {"path": path, "mode": 0o120777, "target": "/" + script}

def alpine_disk(boot_media, miniroot, repository, sources, smoke = None, community = None, extra_packages = (), configure = None, package_effects = None):
    """Return a bootable disk assembled entirely from input readers."""
    iso = filesystem.iso9660(boot_media)
    root = archive.tar(archive.gzip(miniroot))
    version, series = _release(iso, root)
    image_id = "alpine-" + version + "-x86_64"
    entries = {item.path.lstrip("/") or ".": _tar_entry(item) for item in root.entries}
    installed = root["/" + _INSTALLED]
    installed_text = installed.read()
    owned = _base_owners(installed_text)
    records = []
    scripts = []
    world = _WORLD + list(extra_packages)
    catalog = _package_catalog(iso, repository, community)
    for record in _selection(catalog, installed_text, world):
        name = _source_name(record)
        source = iso.find("/apks/x86_64/" + name) or sources.get(name)
        if source == None:
            fail("missing original Alpine package " + name)
        package = read_package(source, None, expected = record, cache_payload = bool(extra_packages))
        # The source index validates the compressed control member, which
        # contains the original package's SHA-256 for its data member.
        for effect in package["effects"]:
            if effect in _UPGRADE_EFFECTS:
                continue
            if effect == ".post-install" and package["name"] == "openrc" and not any([p.startswith("etc/rcS.d/") or p.startswith("etc/rcL.d/") for p in entries]):
                continue
            if effect == ".post-install" and package["name"] == "mkinitfs":
                continue
            if effect == ".trigger" and package["name"] in ["kmod", "mkinitfs"]:
                continue
            if package_effects != None and package_effects(package, effect):
                continue
            fail("unmodeled Alpine installation effect " + package["name"] + ":" + effect)
        for entry in package["entries"]:
            _place(entries, entry, owned)
        fields = _fields(record)
        for metadata, key in [("replaces", "r"), ("replaces_priority", "q")]:
            if metadata in package["metadata"]:
                fields[key] = " ".join(package["metadata"][metadata])
        records.append((fields, package["entries"]))
        if package["effects"]:
            paths = " ".join(package["metadata"].get("triggers", [])).split()
            scripts.append((package["name"], package["version"], record["checksum"], package["effects"], paths))
    entries[_INSTALLED] = _file(_INSTALLED, binary.concat([installed, archive.apk_installed(records)]))
    hooks = archive.apk_script_database(root["/" + _SCRIPTS], root["/" + _TRIGGERS].read(), scripts)
    entries[_SCRIPTS] = _file(_SCRIPTS, hooks.scripts)
    entries[_TRIGGERS] = _file(_TRIGGERS, hooks.triggers)
    entries["etc/apk/world"] = _file("etc/apk/world", "\n".join(world) + "\n")
    entries["etc/hostname"] = _file("etc/hostname", "alpine\n")
    entries["etc/fstab"] = _file("etc/fstab", "PARTUUID=" + root_partition_id(image_id) + " / ext4 defaults 0 1\n")
    repository_url = "https://dl-cdn.alpinelinux.org/alpine/v" + series
    repositories = [repository_url + "/main"]
    if community != None:
        repositories.append(repository_url + "/community")
    entries["etc/apk/repositories"] = _file("etc/apk/repositories", "\n".join(repositories) + "\n")
    _openrc(entries)
    tab = entries["etc/inittab"]["data"].read()
    if smoke == None:
        tab += "\nttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100\n"
    else:
        entries["usr/libexec/trex-smoke"] = _file("usr/libexec/trex-smoke", smoke, 0o755)
        tab += "\nttyS0::once:/usr/libexec/trex-smoke\n"
    entries["etc/inittab"] = _file("etc/inittab", tab)
    kernel = select(entries.values())
    initfs_feature = "etc/mkinitfs/features.d/base.files"
    paths = entries[initfs_feature]["data"].read()
    if "/sbin/nlplug-findfs" not in paths.splitlines():
        entries[initfs_feature] = _file(initfs_feature, paths.rstrip("\n") + "\n/sbin/nlplug-findfs\n")
    suffix_path = "lib/modules/" + kernel["release"] + "/initramfs-suffix"
    entries[suffix_path] = _file(suffix_path, "-virt\n")
    entries["boot/boot"] = {"path": "boot/boot", "mode": 0o120777, "target": "."}
    early_boot = _early_boot(entries, kernel)
    entries["boot/initramfs-virt"] = _file("boot/initramfs-virt", early_boot)
    if configure != None:
        configure(entries)
    volume = filesystem.ext4_build(entries.values(), size = (4 if extra_packages else 1) << 30, label = "Alpine")
    cmdline = "root=PARTUUID=" + root_partition_id(image_id) + " rw console=ttyS0,115200 nokaslr panic=-1"
    return disk_image(image_id, iso["/efi/boot/bootx64.efi"], kernel["file"], cmdline, initramfs = early_boot, root = volume)

def alpine_sources(boot_iso, minirootfs, main_index, package_dir, community_index = None, extra_packages = (), list_only = False):
    """Open caller-supplied media and locate the selected packages."""
    boot_media = open(boot_iso)
    miniroot = open(minirootfs)
    repository = open(main_index)
    community = open(community_index) if community_index != None else None
    media_plan = alpine_repository_plan(boot_media, miniroot, repository, community, extra_packages)
    if list_only:
        return media_plan
    sources = {name: open(package_dir.rstrip("/") + "/" + name) for _, name in media_plan}
    return (boot_media, miniroot, repository, sources, community)
