"""Slipstream Xfce into the installed Arch Linux disk."""

load("//scripts/images:arch_linux.star", "arch_disk")
load("//starlark/private/linux:desktop.star", "add_desktop_account", "add_login_group", "configure_desktop_console", "configure_lightdm_desktop", "install_shared_mime", "verify_desktop_cc")
load("//starlark/private/linux:installed.star", "inspect_root")
load("//starlark/private/linux:pacman.star", "pacman_add", "pacman_plan")
load("//starlark/private/linux:tree.star", "symlink_entry")

_MARKER = "ARCH_DESKTOP_OK xfce4-panel xfdesktop xfwm4"
_CONSOLE_CHECK = ("TREX_DESKTOP_CONSOLE", " ".join([
    'uid=$(id -u); for attempt in $(seq 1 90); do',
    'if pgrep -u "$uid" -x xfce4-panel >/dev/null && pgrep -u "$uid" -x xfdesktop >/dev/null && pgrep -u "$uid" -x xfwm4 >/dev/null; then',
    'if [ "$(pacman -Qoq /usr/bin/xfce4-panel)" = xfce4-panel ]; then',
    "printf '\\n%s\\n' '" + _MARKER + "';",
    "else printf '\\n%s\\n' DESKTOP_PACKAGE_CHECK_FAILED; fi; break;",
    "fi; sleep 2; done",
]))
_PACKAGES = [
    "xfce4-session", "xfce4-panel", "xfwm4", "xfdesktop", "xfce4-settings",
    "xfce4-appfinder", "thunar", "xorg-server", "xorg-xinit", "xf86-video-fbdev",
    "xf86-input-libinput", "xorg-xprop", "xorg-xauth", "ttf-dejavu", "lightdm",
    "lightdm-gtk-greeter",
]
def _plan(media, packages):
    iso = filesystem.iso9660(media)
    root = auto(iso["/arch/x86_64/airootfs.sfs"], maximum_entries = 500000, literal_backslash = True)
    records = [archive.pacman_metadata(p.find("desc").file) for p in root.find("var/lib/pacman/local").files if p.summary["kind"] == "directory"]
    repositories = [(repo, open(packages + "/" + repo + ".db")) for repo in ["core", "extra"]]
    return pacman_plan(records, repositories, _PACKAGES)

def _configure_installed(entries, plan, sources):
    pacman_add(entries, plan, sources, _PACKAGES, permit_hook = _known_hook)
    prefix = "usr/share/fontconfig/conf.default/"
    for path in list(entries):
        if path.startswith(prefix) and "/" not in path[len(prefix):]:
            link = "etc/fonts/conf.d/" + path[len(prefix):]
            if link not in entries:
                entries[link] = symlink_entry(link, "/" + path)
    install_shared_mime(entries)
    lightdm_uid = 626
    add_desktop_account(entries, "lightdm", lightdm_uid, home = "/var/lib/lightdm", shell = "/usr/bin/nologin")
    for path, mode, uid in [
        ("var/cache/lightdm", 0o711, 0),
        ("var/lib/lightdm", 0o1770, lightdm_uid),
        ("var/lib/lightdm-data", 0o1770, lightdm_uid),
        ("var/log/lightdm", 0o711, 0),
    ]:
        entries[path] = {"path": path, "mode": 0o040000 | mode, "uid": uid, "gid": lightdm_uid}
    configure_lightdm_desktop(entries, "xfce")
    add_login_group(entries, "autologin", number = 1638)

def _known_hook(name, script):
    source = script.read()
    if name == "xorg-server":
        return "Old behavior can be restored through Xorg.wrap" in source
    # The links are declared above. Fontconfig can read fonts directly with
    # an empty disposable cache.
    return name == "fontconfig" and "/usr/share/libalpm/scripts/40-fontconfig-config /etc/fonts/conf.d" in source and "/usr/bin/fc-cache -rs" in source

def arch_desktop_disk(media, loader, early_userspace, packages, configure = None):
    plan = _plan(media, packages)
    sources = {record["fields"]["FILENAME"][0]: open(packages + "/" + record["fields"]["FILENAME"][0]) for record in plan}

    def configure_image(entries):
        _configure_installed(entries, plan, sources)
        if configure != None:
            configure(entries)

    return arch_disk(media, loader, early_userspace, configure = configure_image)

def main(args):
    if len(args) not in [4, 5] or len(args) == 5 and args[4] != "--media-plan":
        fail("usage: scripts/smoke/arch_desktop.star <Arch ISO> <package directory> <Alpine virt ISO> <Alpine minirootfs> [--media-plan]")
    media = open(args[0])
    packages = args[1].rstrip("/")
    if len(args) == 5:
        for record in _plan(media, packages):
            print(record["repo"] + " " + record["fields"]["FILENAME"][0])
        return
    loader = filesystem.iso9660(open(args[2]))["/efi/boot/bootx64.efi"]
    disk = arch_desktop_disk(media, loader, open(args[3]), packages, configure = configure_desktop_console)
    root = inspect_root(disk, ["usr/bin/xfce4-panel", "usr/bin/Xorg", "var/lib/pacman/local"])
    records = [p for p in root.find("var/lib/pacman/local").files if p.name.startswith("xfce4-panel-")]
    if len(records) != 1 or "usr/bin/xfce4-panel" not in records[0].find("files").file.read().splitlines():
        fail("the installed Pacman database did not register Xfce")
    verify_desktop_cc(disk, _MARKER, timeout = 270, virtio_gpu = True, console_check = _CONSOLE_CHECK)
