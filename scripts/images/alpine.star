"""Pinned Alpine boot image policy; construction stays native and in memory.

The pins establish regression byte identity, not APK signature authentication.
This minimal image deliberately replaces BusyBox install-link effects with
explicit entries and the initramfs-generator capability with native construction.
It is not an installed apk database or a general Alpine service installation.
"""

load("@stdlib//unix:alpine.star", "read_package", "install_plan")
load("@stdlib//unix:kernel.star", "select", "modules")
load("@stdlib//unix:initramfs.star", initramfs = "build")

PACKAGES = [
    ("busybox-1.37.0-r20", 506116, "7cc34c2dda2520b456ab4a55abc37fe245ac90f98ab9f1c7a9be3aec035df48e"),
    ("musl-1.2.5-r12", 412252, "4990a5e0ba312e478f94cfe431a70efef1538004eb361c8ae424516848be45bb"),
    ("linux-virt-6.12.112-r0", 40705466, "6694e66849759265135a930306452c944bf2159f259b8c8f1c8731e474f2830b"),
]

def packages():
    base = "https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/"
    out = []
    for name, size, sha in PACKAGES:
        source = http_file([base + name + ".apk"], size = size, cache_bytes = 64 << 20)
        out.append(read_package(source, sha))
    return out

_PREAMBLE = """#!/bin/sh
B=/bin/busybox
export PATH=/bin:/sbin
exec </dev/console >/dev/console 2>&1
fail() { echo "TREX_FAIL:$*"; while :; do $B sleep 1; done; }
"""

def _probe(mode, release):
    lines = [
        'test "$$" = 1 || fail pid1',
        'test "$(%s uname -r)" = "%s" || fail kernel-release' % ("$B", release),
    ]
    if mode == "ext4":
        lines += [
            '$B grep -q " / ext4 " /proc/mounts || fail root-not-ext4',
            'test "$(%s cat /etc/trex-identity)" = native-alpine-ext4 || fail root-identity' % "$B",
            'test "$(%s stat -c %%u /var/metadata)" = 123456 || fail uid' % "$B",
            'test "$(%s stat -c %%g /var/metadata)" = 654321 || fail gid' % "$B",
            'test "$(%s stat -c %%h /var/metadata)" = 2 || fail hardlinks' % "$B",
            'test "$(%s readlink /var/link)" = metadata || fail symlink' % "$B",
            'printf "guest-ext4-write\n" >/var/boot-proof || fail write',
            '$B sync',
            'test "$(%s cat /var/boot-proof)" = guest-ext4-write || fail readback' % "$B",
        ]
    lines += ['echo TREX_READY_' + mode, 'exec $B sh -i']
    return "\n".join(lines) + "\n"

def image(package_records, mode = "ext4"):
    if mode not in ["initramfs", "ext4"]:
        fail("Alpine boot mode must be initramfs or ext4")
    base = install_plan(package_records, external = ["initramfs-generator"])
    kernel = select(base["entries"])
    modifications = [
        {"path": "bin/sh", "mode": 0o120777, "target": "busybox"},
        {"path": "etc/trex-identity", "mode": 0o100644, "data": "native-alpine-ext4\n"},
        {"path": "sbin/trex-init", "mode": 0o100755, "data": _PREAMBLE + _probe("ext4", kernel["release"])},
        {"path": "var/metadata", "mode": 0o100640, "uid": 123456, "gid": 654321, "data": "native metadata\n"},
        {"path": "var/hardlink", "mode": 0o100640, "uid": 123456, "gid": 654321, "target": "var/metadata", "hardlink": True},
        {"path": "var/link", "mode": 0o120777, "target": "metadata"},
    ] + [{"path": name, "mode": 0o040755} for name in ["dev", "proc", "sys"]]
    plan = install_plan(package_records, modifications = modifications, external = ["initramfs-generator"])
    userspace = [e for e in plan["entries"] if not e["path"].startswith("lib/modules/") and not e["path"].startswith("boot/")]
    init = _PREAMBLE + """echo TREX_INITRAMFS
$B mount -t proc proc /proc || fail proc
$B mount -t sysfs sysfs /sys || fail sys
$B mount -t devtmpfs devtmpfs /dev || fail dev
"""
    module_files = []
    if mode == "ext4":
        for entry in modules(kernel, ["virtio_blk", "virtio_pci", "ext4"], aliases = {"crc32c": "crc32c_generic"}):
            e = dict(entry)
            # Decode gzip modules natively, before boot. insmod never stands in
            # for missing archive construction or decompression capability.
            if e["path"].endswith(".gz"):
                e["path"] = e["path"][:-3]
                e["data"] = archive.gzip(e["data"], maximum_bytes = 32 << 20)
            if not e["path"].endswith(".ko"):
                fail("Alpine boot: unsupported module encoding " + e["path"])
            module_files.append(e)
            init += '$B insmod /' + e["path"] + ' || fail module:' + e["path"] + '\n'
        init += """echo TREX_MODULES
$B mkdir -p /newroot
$B mount -t ext4 -o rw /dev/vda /newroot || fail ext4-mount
echo TREX_EXT4_MOUNTED
$B mount --move /dev /newroot/dev || fail move-dev
$B mount --move /proc /newroot/proc || fail move-proc
$B mount --move /sys /newroot/sys || fail move-sys
exec $B switch_root /newroot /sbin/trex-init
"""
    else:
        init += _probe(mode, kernel["release"])
    return {
        "kernel": kernel,
        "initramfs": initramfs(userspace + module_files, init = init),
        "rootfs": filesystem.ext4_build(plan["entries"], size = 256 << 20, label = "alpine"),
        "plan": plan,
    }
