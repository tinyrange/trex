"""Construct a persistent Solus system from its original live filesystem."""

load("//starlark/private/linux:installed.star", "build_installed_disk", "lock_root_password", "root_configuration")
load("//starlark/private/linux:tree.star", "file_entry", "filesystem_tree", "install_systemd_smoke")

def solus_disk(media, loader, smoke = None, configure = None, graphical = False, edition = "budgie"):
    iso = filesystem.iso9660(media)
    outer = auto(iso["/LiveOS/squashfs.img"])
    source = auto(outer.find("LiveOS/rootfs.img").file, maximum_entries = 500000, literal_backslash = True)
    entries = filesystem_tree(source)
    prefix = "usr/lib64/kernel/"
    kernels = [
        path for path in entries
        if path.startswith(prefix + "com.solus-project.current.") and "data" in entries[path] and
        prefix + "initrd-" + path[len(prefix):] in entries
    ]
    if len(kernels) != 1:
        fail("Solus media must contain one Current kernel and its initrd")
    kernel_path = kernels[0]
    stem = kernel_path[len(prefix):]
    kernel = entries[kernel_path]["data"]
    initrd = entries[prefix + "initrd-" + stem]["data"]
    image_id = "solus-" + edition + "-" + stem + "-x86_64"
    root_configuration(entries, image_id, "solus")
    lock_root_password(entries)
    for path in list(entries):
        name = path.rsplit("/", 1)[-1]
        if path.startswith("etc/systemd/system/") and (name.startswith("solus-live") or name.startswith("livesys")):
            entries.pop(path)
    if smoke != None:
        install_systemd_smoke(entries, smoke)
    if configure != None:
        configure(entries)
    entries["boot/vmlinuz-current"] = file_entry("boot/vmlinuz-current", kernel)
    entries["boot/initrd-current"] = file_entry("boot/initrd-current", initrd, 0o600)
    cmdline = "efi=noruntime earlycon=uart8250,io,0x3f8,115200n8 earlyprintk=serial,ttyS0,115200,keep keep_bootcon ignore_loglevel"
    if graphical:
        cmdline += " systemd.unit=graphical.target systemd.mask=plymouth-start.service systemd.mask=plymouth-quit.service systemd.mask=plymouth-quit-wait.service"
    return build_installed_disk(image_id, loader, kernel, initrd, entries, 16 << 30, "Solus", extra_cmdline = cmdline)
