"""Construct Fedora from its original EROFS system payload."""

load("//starlark/private/linux:early_root.star", "early_root", "installed_kernel")
load("//starlark/private/linux:installed.star", "build_installed_disk", "lock_root_password", "root_configuration")
load("//starlark/private/linux:tree.star", "file_entry", "filesystem_tree", "install_systemd_smoke")

def fedora_disk(media, loader, smoke = None, configure = None, early_userspace = None, variant = "workstation", cache_payload = False):
    iso = filesystem.iso9660(media)
    payload = iso["/LiveOS/squashfs.img"]
    if cache_payload:
        payload = binary.snapshot(payload, maximum = 4 << 30, cache_bytes = 16 << 20, fast = True)
    source = auto(payload, maximum_entries = 500000, literal_backslash = True)
    release = source.find("usr/lib/os-release").file.read()
    records = dict([line.split("=", 1) for line in release.splitlines() if "=" in line and not line.startswith("#")])
    version = records.get("VERSION_ID", "").strip('"')
    if records.get("ID", "").strip('"') != "fedora" or not version or records.get("VARIANT_ID", "").strip('"') != variant:
        fail("Fedora " + variant + " media required")
    image_id = "fedora-" + variant + "-" + version + "-x86_64"
    entries = filesystem_tree(source)
    root_attrs = source.metadata["attributes"].get("root_xattrs")
    if root_attrs:
        entries["."] = {"path": ".", "mode": 0o040755, "xattrs": {name: binary.decode(value, "base64") for name, value in root_attrs.items()}}
    for path in list(entries):
        name = path.rsplit("/", 1)[-1]
        if path.startswith("etc/systemd/system/") and (name.startswith("livesys") or name.startswith("liveinst")):
            entries.pop(path)
    root_configuration(entries, image_id, "fedora")
    lock_root_password(entries)
    original = entries.get("etc/machine-id", {}).get("xattrs")
    entries["etc/machine-id"] = file_entry("etc/machine-id", "")
    if original != None:
        entries["etc/machine-id"]["xattrs"] = original
    kernels = [path for path in entries if path.startswith("usr/lib/modules/") and path.endswith("/vmlinuz")]
    if len(kernels) != 1:
        fail("Fedora media must contain one kernel")
    kernel = entries[kernels[0]]["data"]
    suffix = kernels[0].split("/")[3]
    initrd = iso["/boot/x86_64/loader/initrd"]
    if early_userspace != None:
        initrd = early_root(early_userspace, installed_kernel(kernel, suffix, entries), module_aliases = {"crc32c": "crc32c_generic"})
    entries["boot/vmlinuz-" + suffix] = file_entry("boot/vmlinuz-" + suffix, kernel)
    entries["boot/initramfs-" + suffix + ".img"] = file_entry("boot/initramfs-" + suffix + ".img", initrd, 0o600)
    if smoke != None:
        install_systemd_smoke(entries, smoke)
    if configure != None:
        configure(entries)
    return build_installed_disk(image_id, loader, kernel, initrd, entries, 14 << 30, "Fedora")
