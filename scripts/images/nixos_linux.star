"""Construct a persistent NixOS system from an official installer closure."""

load("//starlark/private/linux:early_root.star", "early_root", "installed_kernel")
load("//starlark/private/linux:installed.star", "build_installed_disk", "root_configuration")
load("//starlark/private/linux:tree.star", "file_entry", "filesystem_tree", "symlink_entry")

_STORE = "nix/store/"

def _boot_paths(iso, graphical):
    label = "Installer Plasma (Linux LTS)" if graphical else "Installer (Linux LTS)"
    selected = False
    for line in iso["/EFI/BOOT/grub.cfg"].read().splitlines():
        line = line.strip()
        if line.startswith("menuentry "):
            selected = label in line
        args = line.split()
        if not selected or len(args) < 2 or args[0] != "linux" or not args[1].endswith("/bzImage"):
            continue
        kernel = args[1].replace("/boot//nix/store/", "/boot/nix/store/", 1)
        inits = [arg[len("init="):] for arg in args[2:] if arg.startswith("init=/" + _STORE) and arg.endswith("/init")]
        if kernel.startswith("/boot/" + _STORE) and len(inits) == 1:
            return (kernel, inits[0])
    fail("missing the NixOS " + label + " boot entry")

def nixos_disk(media, loader, early_userspace, smoke = None, graphical = False):
    iso = filesystem.iso9660(media)
    version = iso["/version.txt"].read().strip()
    if not version:
        fail("NixOS installer version is missing")
    image_id = "nixos-" + version + "-x86_64"
    kernel_path, init = _boot_paths(iso, graphical)
    kernel = iso[kernel_path]
    release = binary.bzimage_release(kernel)
    source = auto(iso["/nix-store.squashfs"], maximum_entries = 500000, literal_backslash = True)
    system = init[:-len("/init")]
    manifest = source.find("nix-path-registration").file
    if graphical:
        closure = database.nix_store_closure(manifest, [system])
        entries = filesystem_tree(source, prefix = _STORE, names = [path[len(_STORE) + 1:] for path in closure.paths])
        registered = closure.database
    else:
        entries = filesystem_tree(source, prefix = _STORE)
        entries.pop(_STORE + "nix-path-registration")
        registered = database.nix_store(manifest)
    prepare_root = system + "/prepare-root"
    if init[1:] not in entries or prepare_root[1:] not in entries:
        fail("missing the stock NixOS system init")
    module_suffix = "/lib/modules/" + release + "/modules.dep"
    module_roots = sorted([path[:-len(module_suffix)] for path in entries if path.endswith(module_suffix) and "data" in entries[path]])
    if not module_roots:
        fail("missing module dependencies for the NixOS LTS kernel")
    assets = installed_kernel(kernel, release, entries, modules_path = module_roots[0] + "/lib/modules")
    # Invoke the closure's normal stage-2 activation before it starts systemd.
    initrd = early_root(early_userspace, assets, installed_init = prepare_root, module_aliases = {"crc32c": "crc32c_generic"}, mount_run = True)
    for path, mode, gid in [
        ("dev", 0o755, 0), ("proc", 0o555, 0), ("sys", 0o555, 0),
        ("run", 0o755, 0), ("tmp", 0o1777, 0), ("root", 0o700, 0),
        ("nix/store", 0o1775, 30000), ("nix/var/nix/db", 0o755, 0),
    ]:
        entries[path] = {"path": path, "mode": 0o040000 | mode, "gid": gid}
    root_configuration(entries, image_id, "nixos")
    for path, data, mode in [
        ("boot/bzImage", kernel, 0o644),
        ("boot/initrd", initrd, 0o600),
        ("etc/NIXOS", "", 0o644),
        ("nix/var/nix/db/db.sqlite", registered, 0o644),
        ("nix/var/nix/db/schema", "10", 0o644),
    ]:
        entries[path] = file_entry(path, data, mode)
    profile = "nix/var/nix/profiles/system"
    entries[profile] = symlink_entry(profile, "system-1-link")
    entries[profile + "-1-link"] = symlink_entry(profile + "-1-link", system)
    # Stage 1 mounts the installed root. The media's fstab and registration
    # service refer to mounts and a registration file found only on the ISO.
    cmdline = "efi=noruntime fstab=no systemd.mask=register-nix-paths.service init=" + init
    if graphical:
        cmdline += " systemd.unit=graphical.target"
    if smoke != None:
        program = "etc/trex/nixos-smoke"
        unit = "usr/local/lib/systemd/system/trex-smoke.service"
        entries[program] = file_entry(program, smoke, 0o755)
        entries[unit] = file_entry(unit, """[Unit]
Description=Trex installed NixOS smoke
After=nix-daemon.socket systemd-user-sessions.service

[Service]
Type=exec
ExecStart=/run/current-system/sw/bin/bash /etc/trex/nixos-smoke
StandardOutput=journal+console
StandardError=journal+console
""")
        cmdline += " systemd.wants=trex-smoke.service"
    return build_installed_disk(image_id, loader, kernel, initrd, entries, (24 if graphical else 12) << 30, "NixOS", extra_cmdline = cmdline)
