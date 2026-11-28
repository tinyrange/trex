"""Install an official Gentoo amd64 OpenRC stage3 with its original media kernel."""

load("//starlark/private/linux:early_root.star", "early_root", "installed_kernel")
load("//starlark/private/linux:installed.star", "build_installed_disk", "lock_root_password", "root_configuration")
load("//starlark/private/linux:tree.star", "file_entry", "filesystem_tree", "tar_tree")

def gentoo_disk(stage3, install_media, loader, early_userspace, smoke = None):
    stage = archive.tar(archive.xz(stage3), maximum_entries = 500000)
    entries = tar_tree(stage)
    iso = filesystem.iso9660(install_media)
    source = auto(iso["/image.squashfs"], maximum_entries = 500000, literal_backslash = True)
    kernel = iso["/boot/gentoo"]
    release = binary.bzimage_release(kernel)
    image_id = "gentoo-openrc-" + release + "-amd64"
    modules = "usr/lib/modules/" + release
    directory = source.find(modules)
    if directory == None or directory.find("modules.dep") == None or "etc/inittab" not in entries:
        fail("Gentoo requires the matching amd64 OpenRC stage3 and minimal install ISO")
    entries.update(filesystem_tree(directory, prefix = modules + "/"))
    root_configuration(entries, image_id, "gentoo")
    ram = early_root(early_userspace, installed_kernel(kernel, release, entries), module_aliases = {"crc32c": "crc32c_generic"})
    for path, data in [
        ("boot/vmlinuz-" + release, kernel),
        ("boot/initramfs-" + release + ".img", ram),
        ("boot/config-" + release, iso["/boot/gentoo-config"]),
        ("boot/System.map-" + release, iso["/boot/System-gentoo.map"]),
    ]:
        entries[path] = file_entry(path, data)
    if smoke != None:
        path = "usr/libexec/trex-smoke"
        entries[path] = file_entry(path, smoke, 0o755)
        inittab = entries["etc/inittab"]["data"].read()
        entries["etc/inittab"] = file_entry("etc/inittab", inittab + "\ntr:3:once:/" + path + "\n")
    return build_installed_disk(image_id, loader, kernel, ram, entries, 8 << 30, "Gentoo")

def gentoo_graphical_disk(media, loader, early_userspace, desktop_proof):
    """Use the Gentoo LiveGUI package set as the installed graphical root."""
    iso = filesystem.iso9660(media)
    source = auto(iso["/image.squashfs"], maximum_entries = 500000, literal_backslash = True)
    entries = filesystem_tree(source)
    kernel = iso["/boot/gentoo"]
    release = binary.bzimage_release(kernel)
    image_id = "gentoo-livegui-" + release + "-amd64"
    if "usr/bin/plasmashell" not in entries or "usr/lib/modules/" + release + "/modules.dep" not in entries:
        fail("Gentoo LiveGUI media with Plasma and modules for " + release + " is required")
    root_configuration(entries, image_id, "gentoo")
    lock_root_password(entries)
    for name in ["autoconfig", "fixinittab"]:
        entries.pop("etc/runlevels/default/" + name, None)
    path = "etc/conf.d/modules"
    entries[path] = file_entry(path, entries[path]["data"].read() + '\nmodules="virtio_mmio virtio_gpu"\n')
    path = "usr/libexec/trex-desktop-observer"
    entries[path] = file_entry(path, desktop_proof, 0o755)
    inittab = entries["etc/inittab"]["data"].read()
    entries["etc/inittab"] = file_entry("etc/inittab", inittab + "\ntd:3:once:/" + path + "\n")
    initrd = early_root(early_userspace, installed_kernel(kernel, release, entries), module_aliases = {"crc32c": "crc32c_generic"})
    entries["boot/vmlinuz-" + release] = file_entry("boot/vmlinuz-" + release, kernel)
    entries["boot/initramfs-" + release + ".img"] = file_entry("boot/initramfs-" + release + ".img", initrd)
    return build_installed_disk(image_id, loader, kernel, initrd, entries, 16 << 30, "Gentoo", extra_cmdline = "efi=noruntime")
