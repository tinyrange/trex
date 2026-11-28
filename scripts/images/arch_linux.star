"""Construct a persistent Arch Linux installation from official Arch media."""

load("//starlark/private/linux:early_root.star", "early_root", "installed_kernel")
load("//starlark/private/linux:installed.star", "build_installed_disk", "lock_root_password", "root_configuration")
load("//starlark/private/linux:tree.star", "file_entry", "filesystem_tree", "install_systemd_smoke")

_LIVE_NAMES = [
    "autovt@.service",
    "choose-mirror.service",
    "etc-pacman.d-gnupg.mount",
    "livecd-alsa-unmuter.service",
    "livecd-talk.service",
    "pacman-init.service",
]

def arch_disk(media, loader, early_userspace, smoke = None, configure = None):
    iso = filesystem.iso9660(media)
    source = auto(iso["/arch/x86_64/airootfs.sfs"], maximum_entries = 500000, literal_backslash = True)
    entries = filesystem_tree(source)
    kernel = iso["/arch/boot/x86_64/vmlinuz-linux"]
    release = binary.bzimage_release(kernel)
    image_id = "arch-" + release + "-x86_64"
    if "usr/lib/modules/" + release + "/modules.dep" not in entries:
        fail("Arch media has no modules for kernel " + release)
    for path in list(entries):
        unit = path.rsplit("/", 1)[-1]
        if ((path.startswith("etc/systemd/system/") and unit in _LIVE_NAMES) or
            path.startswith("etc/systemd/system/getty@tty1.service.d/") or
            path.startswith("etc/systemd/system/cloud-init.target.wants/") or
            path in ["root/.automated_script.sh", "root/.zlogin"]):
            entries.pop(path)
    root_configuration(entries, image_id, "archlinux")
    lock_root_password(entries)
    ram = early_root(early_userspace, installed_kernel(kernel, release, entries), module_aliases = {"crc32c": "crc32c_generic"})
    entries["boot/vmlinuz-linux"] = file_entry("boot/vmlinuz-linux", kernel)
    entries["boot/initramfs-linux.img"] = file_entry("boot/initramfs-linux.img", ram, 0o600)
    if smoke != None:
        install_systemd_smoke(entries, smoke)
    if configure != None:
        configure(entries)
    return build_installed_disk(image_id, loader, kernel, ram, entries, 8 << 30, "Arch Linux", extra_cmdline = "efi=noruntime earlycon=uart8250,io,0x3f8,115200n8")
