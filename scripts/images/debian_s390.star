"""Pinned Debian 5.0 (lenny) 31-bit s390 kernel and BusyBox initramfs.

The pins establish byte identity of archived packages, not Debian signature
authentication. Construction is native and in memory: the .deb members are
read in place and the newc initramfs is built from their entries. The result
is a kernel image and initramfs for a storage load on `emulator.s390`, not an
installed Debian system.
"""

load("@stdlib//unix:initramfs.star", initramfs = "build")

_POOL = "https://archive.debian.org/debian/pool/main/"

PACKAGES = {
    "kernel": ("l/linux-2.6/linux-image-2.6.26-2-s390_2.6.26-29_s390.deb", 7547198, "b33ae6921c4dec9c63e8c890bb3ecd8762526c659c67a39c6a319cece62d94da"),
    "busybox": ("b/busybox/busybox-static_1.10.2-2_s390.deb", 965524, "eba77da994fc29256db8bb69d61340c0e464bfe44f858db32884cc31dfb2107f"),
    # Debian 7 (wheezy) s390, still 31-bit: its BusyBox has insmod and
    # switch_root, which the lenny build lacks.
    "busybox-1.20": ("b/busybox/busybox-static_1.20.0-7_s390.deb", 949464, "59006628d84908518d7a4d04d47c55c3fe56de9af067223fa47509164edf7a0c"),
}

RELEASE = "2.6.26-2-s390"

# Linux/390 storage-load layout (arch/s390 head.S parameter area).
KERNEL_ADDRESS = 0x00000000
INITRD_ADDRESS = 0x00800000
INITRD_START = 0x00010408  # 64-bit start and size fields
COMMAND_LINE = 0x00010480

def _deb_data(name):
    path, size, sha = PACKAGES[name]
    source = http_file([_POOL + path], size = size, cache_bytes = 16 << 20)
    if binary.hex(digest(source)) != sha:
        fail("debian_s390: SHA-256 mismatch for " + path)
    package = archive.ar(source)
    member = package.find("data.tar.gz")
    if member != None:
        return archive.tar(archive.gzip(member))
    member = package.find("data.tar.xz")
    if member == None:
        fail("debian_s390: no data member in " + path)
    return archive.tar(archive.xz(member))

def _file(tar, path):
    entry = tar.find(path)
    if entry == None or entry.entry_type != "file":
        fail("debian_s390: missing " + path)
    return entry

INIT = """#!/bin/busybox sh
B=/bin/busybox
$B mount -t proc proc /proc
$B mount -t sysfs sysfs /sys
echo TREX_LINUX_READY $($B uname -m) $($B uname -r)
exec $B sh
"""

def _u64(value):
    return binary.concat([binary.u32be(value >> 32), binary.u32be(value & 0xffffffff)])

def image(init = INIT, command_line = "rdinit=/init"):
    """Return the storage images for m.storage_load() and their components."""
    kernel = _file(_deb_data("kernel"), "./boot/vmlinuz-" + RELEASE)
    busybox = _file(_deb_data("busybox"), "./bin/busybox")
    entries = [
        {"path": "bin", "mode": 0o040755},
        {"path": "bin/busybox", "mode": 0o100755, "data": busybox},
        {"path": "bin/sh", "mode": 0o120777, "target": "busybox"},
    ]
    initrd = initramfs(entries, init = init)
    images = [
        (KERNEL_ADDRESS, kernel),
        (INITRD_START, binary.concat([_u64(INITRD_ADDRESS), _u64(initrd.size)])),
        (COMMAND_LINE, command_line + "\0"),
        (INITRD_ADDRESS, initrd),
    ]
    return {"images": images, "kernel": kernel, "initramfs": initrd, "release": RELEASE}

def symbols():
    """Return the kernel's System.map as a sorted list of (address, name)."""
    text = binary.text(_file(_deb_data("kernel"), "./boot/System.map-" + RELEASE).read())
    out = []
    for line in text.split("\n"):
        f = line.split(" ")
        if len(f) == 3 and len(f[0]) == 8:
            out.append((int(f[0], 16), f[2]))
    return sorted(out)

_MODULES = "./lib/modules/" + RELEASE + "/kernel/"

# Loaded in dependency order: the DASD driver and its ECKD discipline, then
# ext2 with the shared metadata cache.
DASD_MODULES = [
    ("dasd_mod.ko", "drivers/s390/block/dasd_mod.ko", "dasd=0200"),
    ("dasd_eckd_mod.ko", "drivers/s390/block/dasd_eckd_mod.ko", ""),
    ("mbcache.ko", "fs/mbcache.ko", ""),
    ("ext2.ko", "fs/ext2/ext2.ko", ""),
]

DASD_INIT = """#!/bin/busybox sh
B=/bin/busybox
$B mount -t proc proc /proc
$B mount -t sysfs sysfs /sys
for m in %s; do $B insmod /lib/$m || echo TREX_FAIL insmod $m; done
$B mknod /dev/dasda b 94 0
$B mknod /dev/dasda1 b 94 1
if ! $B mount -t ext2 /dev/dasda1 /root; then
    echo TREX_FAIL mount
    exec $B sh
fi
exec $B switch_root /root /sbin/init
"""

ROOT_INIT = """#!/bin/busybox sh
B=/bin/busybox
$B mount -t proc proc /proc
echo TREX_DASD_ROOT $($B grep '^/dev/dasda1 / ' /proc/mounts | $B cut -d' ' -f1-3)
echo TREX_IDENTITY $($B cat /etc/trex-identity)
exec $B sh
"""

def dasd_image(cylinders = 100):
    """Return storage images and a root file system for a Linux disk-layout
    3390: the initramfs loads the DASD driver and switches root to it."""
    kernel_tar = _deb_data("kernel")
    kernel = _file(kernel_tar, "./boot/vmlinuz-" + RELEASE)
    busybox = _file(_deb_data("busybox-1.20"), "./bin/busybox")
    entries = [
        {"path": "bin", "mode": 0o040755},
        {"path": "bin/busybox", "mode": 0o100755, "data": busybox},
        {"path": "bin/sh", "mode": 0o120777, "target": "busybox"},
        {"path": "lib", "mode": 0o040755},
        {"path": "root", "mode": 0o040755},
    ]
    for name, path, _ in DASD_MODULES:
        entries.append({"path": "lib/" + name, "mode": 0o100644, "data": _file(kernel_tar, _MODULES + path)})
    # insmod takes the module and its parameters as separate words.
    init = DASD_INIT % " ".join([n for n, _, _ in DASD_MODULES])
    init = init.replace("$B insmod /lib/$m ", "$B insmod /lib/$m $([ $m = dasd_mod.ko ] && echo dasd=0200) ")
    initrd = initramfs(entries, init = init)
    root = filesystem.ext4_build([
        {"path": "bin", "mode": 0o040755},
        {"path": "bin/busybox", "mode": 0o100755, "data": busybox},
        {"path": "bin/sh", "mode": 0o120777, "target": "busybox"},
        {"path": "sbin", "mode": 0o040755},
        {"path": "sbin/init", "mode": 0o100755, "data": ROOT_INIT},
        {"path": "etc", "mode": 0o040755},
        {"path": "etc/trex-identity", "mode": 0o100644, "data": "native-ext2-on-3390\n"},
        {"path": "proc", "mode": 0o040755},
        {"path": "dev", "mode": 0o040755},
        {"path": "dev/console", "mode": 0o020600, "major": 5, "minor": 1},
    ], size = 32 << 20, label = "trexroot", ext2 = True)
    images = [
        (KERNEL_ADDRESS, kernel),
        (INITRD_START, binary.concat([_u64(INITRD_ADDRESS), _u64(initrd.size)])),
        (COMMAND_LINE, "rdinit=/init\0"),
        (INITRD_ADDRESS, initrd),
    ]
    return {"images": images, "root": root, "cylinders": cylinders, "release": RELEASE}
