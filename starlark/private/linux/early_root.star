"""Build a Linux installed-root initramfs for the CC disk profile."""

load("@stdlib//unix:initramfs.star", initramfs = "build")
load("@stdlib//unix:kernel.star", "modules")
load(":tree.star", "file_entry", "symlink_entry")

def early_root(miniroot, kernel, installed_init = "/sbin/init", module_aliases = {}, mount_run = False):
    """Use original early userspace and the installed kernel's module dependencies."""
    root = archive.tar(archive.gzip(miniroot))
    ram = [
        file_entry("bin/busybox", root["/bin/busybox"], 0o755),
        file_entry("lib/ld-musl-x86_64.so.1", root["/lib/ld-musl-x86_64.so.1"], 0o755),
        symlink_entry("bin/sh", "busybox"),
        {"path": "newroot", "mode": 0o040755},
    ]
    script = ["""#!/bin/sh
set -eu
B=/bin/busybox
$B mount -t proc proc /proc
$B mount -t sysfs sysfs /sys
$B mount -t devtmpfs devtmpfs /dev
"""]
    for entry in modules(kernel, ["nvme", "ext4"], aliases = module_aliases):
        mod = dict(entry)
        if mod["path"].endswith(".gz"):
            mod.update(path = mod["path"][:-3], data = archive.gzip(mod["data"], maximum_bytes = 8 << 20))
        elif mod["path"].endswith(".xz"):
            mod.update(path = mod["path"][:-3], data = archive.xz(mod["data"]))
        elif mod["path"].endswith(".zst"):
            mod.update(path = mod["path"][:-4], data = archive.zstd(mod["data"]))
        ram.append(mod)
        script.append("$B insmod /" + mod["path"] + "\n")
    script.append("""
root=/dev/nvme0n1p2
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    [ -b "$root" ] && break
    $B sleep 1
done
$B mount -t ext4 -o rw "$root" /newroot
$B mount -o move /dev /newroot/dev
$B mount -o move /proc /newroot/proc
$B mount -o move /sys /newroot/sys
""")
    if mount_run:
        script.append("$B mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /newroot/run\n")
    script.append("exec $B switch_root /newroot " + installed_init + "\n")
    return initramfs(ram, init = "".join(script))

def installed_kernel(file, release, entries, modules_path = "usr/lib/modules"):
    """Describe a kernel with module data from its installed filesystem."""
    source = modules_path + "/" + release + "/"
    assets = []
    for name, entry in entries.items():
        if name.startswith(source) and "data" in entry:
            asset = dict(entry)
            asset["path"] = "lib/modules/" + release + "/" + name[len(source):]
            assets.append(asset)
    return {"file": file, "release": release, "entries": assets}
