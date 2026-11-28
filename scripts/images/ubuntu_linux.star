"""Construct the Ubuntu Noble desktop from original layered media."""

load("//starlark/private/linux:disk.star", "disk_image", "root_partition_id")
load("//starlark/private/linux:tree.star", "file_entry", "filesystem_entry", "filesystem_tree", "install_systemd_smoke")

_STATUS = "var/lib/dpkg/status"
_INFO = "var/lib/dpkg/info"

def _installed(fs):
    result = {}
    for paragraph in archive.debian_control(fs.find(_STATUS).file):
        key = (paragraph.fields["package"], paragraph.fields["architecture"])
        if key in result:
            fail("duplicate dpkg status entry " + repr(key))
        result[key] = paragraph
    return result

def _canonical(path):
    path = path.lstrip("/")
    for prefix in ["lib", "lib64", "bin", "sbin"]:
        if path == prefix or path.startswith(prefix + "/"):
            return "usr/" + path
    return path

def _kernel_packages(entries, minimum, source, release):
    """Restore kernel-package payloads, dpkg list files, and exact status stanzas."""
    status = _installed(minimum)
    additional = _installed(source)
    info = source.find(_INFO)
    links = {}
    for name in ["linux-image-" + release, "linux-modules-" + release]:
        key = (name, "amd64")
        if key in status or key not in additional or additional[key].fields["status"] != "install ok installed":
            fail("unexpected kernel package state in Ubuntu media for " + name)
        status[key] = additional[key]
        paths = info.find(name + ".list")
        if paths == None:
            fail("missing Ubuntu kernel package file list for " + name)
        for path in paths.file.read().splitlines():
            name_on_disk = _canonical(path)
            if name_on_disk in ["", "."]:
                continue
            member = source.find(name_on_disk)
            if member == None:
                # Layered filesystems omit unchanged directories from later layers.
                if name_on_disk not in entries or entries[name_on_disk]["mode"] & 0o170000 != 0o040000:
                    fail("file listed by " + name + " is absent in Ubuntu media: " + path)
            elif name_on_disk not in entries or member.summary["kind"] != "directory":
                entries[name_on_disk] = filesystem_entry(member, name_on_disk, links)
        for member in info.files:
            if member.name.startswith(name + "."):
                path = _INFO + "/" + member.name
                entries[path] = filesystem_entry(member, path, links)
    entries[_STATUS] = file_entry(_STATUS, "\n\n".join([status[key].raw for key in sorted(status)]) + "\n\n")

def ubuntu_disk(media, loader, smoke = None, configure = None):
    """Return a lazy GPT disk from a compatible Ubuntu Noble Desktop ISO."""
    iso = filesystem.iso9660(media)
    if not iso["/.disk/info"].read().startswith(("Ubuntu 24.04.", "Ubuntu 24.04 ")):
        fail("Ubuntu 24.04 LTS Desktop media required")
    kernel = iso["/casper/vmlinuz"]
    release = binary.bzimage_release(kernel)
    image_id = "ubuntu-noble-" + release + "-x86_64"
    minimal = auto(iso["/casper/minimal.squashfs"], maximum_entries = 500000, literal_backslash = True)
    live = auto(iso["/casper/minimal.standard.live.squashfs"], maximum_entries = 500000, literal_backslash = True)
    entries = filesystem_tree(minimal)
    _kernel_packages(entries, minimal, live, release)
    boot_kernel = entries["boot/vmlinuz-" + release]["data"]
    if digest(kernel) != digest(boot_kernel):
        fail("Ubuntu's ISO and installed kernel package disagree")
    ram = iso["/casper/initrd"]
    entries["boot/initrd.img-" + release] = file_entry("boot/initrd.img-" + release, ram, 0o600)
    entries["etc/fstab"] = file_entry("etc/fstab", "PARTUUID=" + root_partition_id(image_id) + " / ext4 defaults 0 1\n")
    entries["etc/hostname"] = file_entry("etc/hostname", "ubuntu\n")
    if smoke != None:
        install_systemd_smoke(entries, smoke)
    if configure != None:
        configure(entries)
    root = filesystem.ext4_build(entries.values(), size = 10 << 30, label = "Ubuntu", inode_count = 240000)
    cmdline = "boot=local root=PARTUUID=" + root_partition_id(image_id) + " rootfstype=ext4 rw console=ttyS0,115200 nokaslr panic=-1"
    return disk_image(image_id, loader, kernel, cmdline, initramfs = ram, root = root)
