"""Construct a Void Linux x86_64 installation from its original base ISO."""

load("//starlark/private/linux:installed.star", "build_installed_disk", "lock_root_password", "root_configuration")
load("//starlark/private/linux:tree.star", "file_entry", "filesystem_tree", "symlink_entry")

def void_disk(media, loader, smoke = None, configure = None):
    iso = filesystem.iso9660(media)
    outer = auto(iso["/LiveOS/squashfs.img"])
    source = auto(outer.find("LiveOS/ext3fs.img").file, maximum_entries = 500000, literal_backslash = True)
    entries = filesystem_tree(source)
    prefix = "boot/vmlinuz-"
    releases = [path[len(prefix):] for path in entries if path.startswith(prefix) and "data" in entries[path]]
    if len(releases) != 1 or "boot/initramfs-" + releases[0] + ".img" not in entries:
        fail("Void media must contain one installed kernel and its initramfs")
    release = releases[0]
    kernel = entries[prefix + release]["data"]
    initrd = entries["boot/initramfs-" + release + ".img"]["data"]
    image_id = "void-" + release + "-x86_64"
    root_configuration(entries, image_id, "void")
    lock_root_password(entries)
    entries.pop("etc/runit/runsvdir/default/sshd", None)
    entries.pop("etc/runit/core-services/99-live-audio.sh", None)
    if smoke != None:
        service = "etc/sv/trex-smoke/run"
        entries[service] = file_entry(service, smoke, 0o755)
        link = "etc/runit/runsvdir/default/trex-smoke"
        entries[link] = symlink_entry(link, "/etc/sv/trex-smoke")
    if configure != None:
        configure(entries)
    return build_installed_disk(image_id, loader, kernel, initrd, entries, (8 if configure != None else 6) << 30, "Void Linux")
