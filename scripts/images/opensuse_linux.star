"""Construct an installed openSUSE Tumbleweed system in memory."""

load("//starlark/private/linux:early_root.star", "early_root", "installed_kernel")
load("//starlark/private/linux:installed.star", "build_installed_disk", "lock_root_password", "root_configuration")
load("//starlark/private/linux:tree.star", "file_entry", "filesystem_tree", "install_systemd_smoke")

def opensuse_disk(media, loader, early_userspace, smoke = None, configure = None):
    iso = filesystem.iso9660(media)
    source = auto(iso["/LiveOS/squashfs.img"], maximum_entries = 500000, literal_backslash = True)
    entries = filesystem_tree(source)
    release = entries["usr/lib/os-release"]["data"].read()
    records = dict([line.split("=", 1) for line in release.splitlines() if "=" in line and not line.startswith("#")])
    snapshot = records.get("VERSION_ID", "").strip('"')
    if records.get("ID", "").strip('"') != "opensuse-tumbleweed" or not snapshot:
        fail("openSUSE Tumbleweed media required")
    image_id = "opensuse-tumbleweed-" + snapshot + "-x86_64"
    root_configuration(entries, image_id, "opensuse")
    lock_root_password(entries)
    for path in list(entries):
        name = path.rsplit("/", 1)[-1]
        if path.startswith("etc/systemd/system/") and (name.startswith("livesys") or name.startswith("liveinst")):
            entries.pop(path)
    kernels = [path for path in entries if path.startswith("usr/lib/modules/") and path.endswith("/vmlinuz") and "data" in entries[path]]
    if len(kernels) != 1:
        fail("openSUSE media must contain one installed kernel")
    kernel = entries[kernels[0]]["data"]
    version = kernels[0].split("/")[3]
    initrd = early_root(early_userspace, installed_kernel(kernel, version, entries), module_aliases = {"crc32c": "crc32c_generic"})
    entries["boot/initrd-" + version] = file_entry("boot/initrd-" + version, initrd, 0o600)
    if smoke != None:
        install_systemd_smoke(entries, smoke)
    if configure != None:
        configure(entries)
    return build_installed_disk(image_id, loader, kernel, initrd, entries, 10 << 30, "openSUSE")
