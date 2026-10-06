"""Optional NETWORK construction smoke using fixed Alpine v3.22 APK bytes.

Run: go run ./cmd/trex scripts/smoke/alpine_formats.star
Hashes record regression content identity, NOT APK signature authentication.
No files are extracted/written, no install effects executed and no VM started.
This is deliberately excluded from the offline test.star suite.
"""

load("@stdlib//unix:alpine.star", "read_package")
load("//scripts/examples:linux_image.star", "construct")

_PACKAGES = [
    ("busybox-1.37.0-r20", 506116, "7cc34c2dda2520b456ab4a55abc37fe245ac90f98ab9f1c7a9be3aec035df48e"),
    ("musl-1.2.5-r12", 412252, "4990a5e0ba312e478f94cfe431a70efef1538004eb361c8ae424516848be45bb"),
    ("linux-virt-6.12.112-r0", 40705466, "6694e66849759265135a930306452c944bf2159f259b8c8f1c8731e474f2830b"),
]

def main(args):
    if args:
        fail("alpine_formats.star takes no arguments")
    base = "https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/"
    packages = []
    for name, size, sha in _PACKAGES:
        source = http_file([base + name + ".apk"], size = size, cache_bytes = 64 << 20)
        packages.append(read_package(source, sha))
    result = construct(
        packages,
        init = "#!/bin/sh\nexec /bin/busybox sh\n",
        modifications = [{"path": "bin/sh", "mode": 0o120777, "target": "busybox"}],
        requested_modules = ["virtio_blk", "virtio_pci", "ext4"],
        module_aliases = {"crc32c": "crc32c_generic"},
        # Native initramfs construction replaces this package capability for
        # this experiment; it does not claim to install Alpine's generator.
        external = ["initramfs-generator"],
    )
    disk = {e.path: e for e in filesystem.ext4(result["rootfs"]).entries}
    initrd = {e["path"]: e for e in archive.cpio(result["initramfs"])}
    checked = 0
    for package in packages:
        for entry in package["entries"]:
            if entry["mode"] & 0o170000 != 0o100000 or entry.get("hardlink", False):
                continue
            path = entry["path"]
            if digest(entry["data"]) != digest(disk[path].data):
                fail("ext4 payload identity mismatch: " + path)
            if path in initrd and digest(entry["data"]) != digest(initrd[path]["data"]):
                fail("CPIO payload identity mismatch: " + path)
            checked += 1
    print("PASS Alpine formats:", checked, "file hashes; release", result["kernel"]["release"], "initramfs bytes", result["initramfs"].size, "ext4 bytes", result["rootfs"].size, "effects retained", len(result["plan"]["effects"]))
