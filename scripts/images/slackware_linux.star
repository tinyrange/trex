"""Construct a Slackware 15.0 base installation from the original package sets."""

load("//starlark/private/linux:installed.star", "build_installed_disk", "lock_root_password", "root_configuration")
load("//starlark/private/linux:tree.star", "file_entry", "symlink_entry", "tar_tree")

_PACKAGES = {
    "a": [
        "aaa_base", "aaa_glibc-solibs", "aaa_libraries", "acl", "attr", "bash", "bin",
        "coreutils", "devs", "dialog", "e2fsprogs", "elogind", "etc", "findutils",
        "gawk", "grep", "gzip", "hostname", "kbd", "kernel-huge", "kmod",
        "less", "pkgtools", "procps-ng", "sed", "shadow", "sysvinit",
        "sysvinit-functions", "sysvinit-scripts", "tar", "util-linux", "which", "xz",
    ],
    "ap": ["diffutils", "slackpkg"],
    "l": ["gmp", "libcap", "libseccomp", "ncurses", "pcre", "zstd"],
    "n": ["wget"],
}

def _archive_paths(iso, desktop):
    selected = []
    packages = dict(_PACKAGES)
    if desktop:
        packages["a"] = packages["a"] + ["bzip2", "dbus", "eudev", "kernel-modules", "libgudev", "openssl-solibs", "pam", "udisks2"]
        packages.update(d = ["gcc-g++"], l = None, x = None, xfce = None, n = packages["n"] + [
            "curl", "cyrus-sasl", "gnutls", "krb5", "libgcrypt", "libgpg-error", "nettle", "nghttp2", "p11-kit",
        ])
        driver = "xf86-video-fbdev"
        selected.append((driver, _package_path(iso.find("/extra/" + driver).files, driver)))
    for series, names in packages.items():
        paths = iso.find("/slackware64/" + series).files
        if names == None:
            selected.extend([(path.rsplit("/", 1)[-1].rsplit("-", 3)[0], path) for path in paths if path.endswith(".txz")])
            continue
        for name in names:
            selected.append((name, _package_path(paths, name)))
    return selected

def _package_path(paths, name):
    candidates = [path for path in paths if path.endswith(".txz") and path.rsplit("/", 1)[-1].rsplit("-", 3)[0] == name]
    if len(candidates) != 1:
        fail("Slackware package must appear once: " + name)
    return candidates[0]

def _move(entries, old, new):
    entry = entries.pop(old)
    entry["path"] = new
    entries[new] = entry

def _links(entries, script):
    # makepkg emits these pairs to restore symlinks, using literal words.
    # The remaining fresh-install actions belong to the package policy below.
    for line in script.splitlines():
        words = line.strip().split()
        if len(words) != 9 or words[:2] != ["(", "cd"] or words[3:6] != [";", "ln", "-sf"] or words[-1] != ")":
            continue
        directory, target, name = words[2], words[6], words[7]
        if "$" in directory or "$" in target or "$" in name or name in [".", ".."] or "/" in name:
            continue
        directory = directory[2:] if directory.startswith("./") else directory
        if directory.startswith("/") or ".." in directory.split("/"):
            continue
        path = directory + "/" + name if directory != "." else name
        entries[path] = symlink_entry(path, target)

def _load_package(entries, iso, package, path, desktop):
    file = iso[path]
    contents = archive.xz(file)
    if desktop:
        contents = binary.snapshot(contents, maximum = 1 << 30, fast = True)
    tar = archive.tar(contents)
    payload = tar_tree(tar)
    install = tar.find("/install/doinst.sh")
    shortname = path.rsplit("/", 1)[-1][:-4]
    for member, entry in payload.items():
        if member == "." or member == "install" or member.startswith("install/"):
            continue
        if member not in entries or entry["mode"] & 0o170000 != 0o040000:
            entries[member] = entry
    if install != None:
        _links(entries, install.read())
        log_script = "var/lib/pkgtools/scripts/" + shortname
        entries[log_script] = file_entry(log_script, install, 0o755)
    if package == "aaa_glibc-solibs":
        for member in list(entries):
            prefix = "lib64/incoming/"
            if member.startswith(prefix):
                _move(entries, member, "lib64/" + member[len(prefix):])
        entries.pop("lib64/incoming", None)
    elif package == "bash":
        _move(entries, "bin/bash5.new", "bin/bash")
    elif package == "sysvinit":
        _move(entries, "sbin/init.new", "sbin/init")
    description = tar.find("/install/slack-desc")
    text = description.read() if description != None else ""
    text = "\n".join([line for line in text.splitlines() if line.startswith(package + ":")])
    record = "PACKAGE NAME:     %s\nCOMPRESSED PACKAGE SIZE:     %sK\nUNCOMPRESSED PACKAGE SIZE:     %sK\nPACKAGE LOCATION: %s\nPACKAGE DESCRIPTION:\n%s\nFILE LIST:\n" % (
        shortname,
        (file.size + 1023) // 1024,
        (contents.size + 1023) // 1024,
        path.lstrip("/"),
        text,
    )
    names = [member.name for member in tar.entries if member.path != "/install" and not member.path.startswith("/install/")]
    log = "var/lib/pkgtools/packages/" + shortname
    entries[log] = file_entry(log, record + "\n".join(names) + "\n")

def _fresh_install(entries):
    for path in list(entries):
        if path.endswith(".new") and (path.startswith("etc/") or path.startswith("var/log/") or path == "var/run/utmp.new") and path[:-4] not in entries:
            _move(entries, path, path[:-4])
    groups = {line.split(":")[0]: int(line.split(":")[2]) for line in entries["etc/group"]["data"].read().splitlines() if ":" in line}
    for path, group, mode in [("etc/shadow", "shadow", 0o640), ("etc/gshadow", "shadow", 0o640), ("var/log/wtmp", "utmp", 0o664), ("var/run/utmp", "utmp", 0o664)]:
        entries[path]["gid"] = groups[group]
        entries[path]["mode"] = 0o100000 | mode
    if "var/log/btmp" not in entries:
        entries["var/log/btmp"] = file_entry("var/log/btmp", "", 0o600)
    for name in ["packages", "scripts", "setup"]:
        path = "var/log/" + name
        target = "var/lib/pkgtools/" + name
        for member in [p for p in entries if p.startswith(path + "/")]:
            installed = target + member[len(path):]
            if installed in entries and entries[member]["mode"] & 0o170000 == 0o040000:
                entries.pop(member)
            else:
                _move(entries, member, installed)
        entries[path] = symlink_entry(path, "../lib/pkgtools/" + name)
    for name in ["removed_packages", "removed_scripts"]:
        target = "var/log/pkgtools/" + name
        entries[target] = {"path": target, "mode": 0o040755}
        path = "var/log/" + name
        entries[path] = symlink_entry(path, "pkgtools/" + name)
        path = "var/lib/pkgtools/" + name
        entries[path] = symlink_entry(path, "../../log/pkgtools/" + name)
    shells = entries["etc/shells"]["data"].read()
    if "/bin/bash" not in shells.splitlines():
        entries["etc/shells"] = file_entry("etc/shells", shells + "\n/bin/bash\n")

def slackware_disk(media, loader, smoke = None, desktop = None):
    iso = filesystem.iso9660(media)
    entries = {}
    for name, path in _archive_paths(iso, desktop != None):
        _load_package(entries, iso, name, path, desktop != None)
    _fresh_install(entries)
    kernels = [name for name, entry in entries.items() if name.startswith("boot/vmlinuz-huge-") and "data" in entry]
    if len(kernels) != 1:
        fail("Slackware media must contain one installed huge kernel")
    kernel = entries[kernels[0]]["data"]
    release = binary.bzimage_release(kernel)
    image_id = "slackware64-" + release
    root_configuration(entries, image_id, "slackware")
    lock_root_password(entries)
    entries["etc/HOSTNAME"] = file_entry("etc/HOSTNAME", "slackware\n")
    if smoke != None:
        path = "usr/libexec/trex-smoke"
        entries[path] = file_entry(path, smoke, 0o755)
        inittab = entries["etc/inittab"]["data"].read()
        entries["etc/inittab"] = file_entry("etc/inittab", inittab + "\ntr:3:once:/" + path + "\n")
    if desktop != None:
        desktop(entries)
    config = entries["boot/config-huge-" + release + ".x64"]["data"].read().splitlines()
    for feature in ["CONFIG_EXT4_FS", "CONFIG_BLK_DEV_NVME", "CONFIG_DEVTMPFS_MOUNT"]:
        if feature + "=y" not in config:
            fail("Slackware huge kernel lacks built-in " + feature)
    return build_installed_disk(image_id, loader, kernel, None, entries, (16 if desktop else 4) << 30, "Slackware", root_read_only = desktop != None)
