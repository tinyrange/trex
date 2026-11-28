"""Boot installed graphical sessions in fresh CrumbleCracker VMs."""

load("//scripts/images:fedora_linux.star", "fedora_disk")
load("//scripts/images:gentoo_linux.star", "gentoo_graphical_disk")
load("//scripts/images:nixos_linux.star", "nixos_disk")
load("//scripts/images:opensuse_linux.star", "opensuse_disk")
load("//scripts/images:solus_linux.star", "solus_disk")
load("//scripts/images:ubuntu_linux.star", "ubuntu_disk")
load("//scripts/images:void_linux.star", "void_disk")
load("//scripts/smoke:alpine_desktop.star", alpine = "main")
load("//scripts/smoke:arch_desktop.star", arch = "main")
load("//scripts/smoke:slackware_desktop.star", slackware = "main")
load("//starlark/private/linux:desktop.star", "add_login_group", "configure_gdm_desktop", "configure_lightdm_desktop", "configure_lightdm_login", "verify_desktop_cc")
load("//starlark/private/linux:dpkg.star", "dpkg_add")
load("//starlark/private/linux:installed.star", "inspect_root")
load("//starlark/private/linux:media.star", "media_paths", "read_media")
load("//starlark/private/linux:tree.star", "file_entry", "symlink_entry")

_FEDORA = "FEDORA_DESKTOP_OK Xfce"
_GENTOO = "GENTOO_DESKTOP_OK Plasma"
_NIXOS = "NIXOS_DESKTOP_OK Plasma"
_OPENSUSE = "OPENSUSE_DESKTOP_OK Xfce"
_SOLUS = "SOLUS_DESKTOP_OK Xfce"
_UBUNTU = "UBUNTU_DESKTOP_OK GNOME"
_VOID = "VOID_DESKTOP_OK xfce4-panel xfdesktop xfwm4"
_XFCE_PROCESSES = ["xfce4-panel", "xfdesktop", "xfwm4"]
_RPM_XFCE_OWNER = """[ "$(rpm -qf --qf '%{NAME}' /usr/bin/xfce4-panel)" = xfce4-panel ]"""
_NIXOS_CONSOLE_CHECK = ("nixos@nixos", " ".join([
    "for attempt in $(seq 1 90); do",
    "if systemctl --user is-active --quiet plasma-plasmashell.service && pgrep -u nixos -x '[.]?kwin_(wayland(-w)?|x11)' >/dev/null; then",
    'profile=$(readlink -f /nix/var/nix/profiles/system);',
    'if timeout 15 nix-store --query --references "$profile" >/dev/null; then',
    "printf '\\n%s\\n' '" + _NIXOS + "';",
    "else printf '\\n%s\\n' DESKTOP_PACKAGE_CHECK_FAILED; fi; break;",
    "fi; sleep 2; done",
]))
_VOID_SMOKE = """#!/bin/sh
exec >/dev/ttyS0 2>&1
for attempt in $(seq 1 75); do
    if pgrep -u 1637 -x xfce4-panel >/dev/null &&
       pgrep -u 1637 -x xfdesktop >/dev/null &&
       pgrep -u 1637 -x xfwm4 >/dev/null; then
        xbps-query -o /usr/bin/xfce4-panel | grep -q '^xfce4-panel-' || exit 1
        printf '\n%s\n' '""" + _VOID + """'
        exec pause
    fi
    sleep 2
done
tail -n 35 /var/log/lightdm/lightdm.log
ls /sys/class/drm
echo DESKTOP_FAILED_SESSION
exec pause
"""
_GENTOO_SMOKE = """#!/bin/sh
exec >/dev/ttyS0 2>&1
for attempt in $(seq 1 80); do
    if pgrep -u gentoo -x plasmashell >/dev/null &&
       { pgrep -u gentoo -x kwin_wayland >/dev/null || pgrep -u gentoo -x kwin_x11 >/dev/null; }; then
        grep -q 'obj /usr/bin/plasmashell ' /var/db/pkg/kde-plasma/plasma-workspace-*/CONTENTS || exit 1
        printf '\n%s\n' '""" + _GENTOO + """'
        exit 0
    fi
    sleep 2
done
ls /sys/class/drm
rc-status default
echo DESKTOP_FAILED_SESSION
"""

def _fedora(entries):
    configure_lightdm_desktop(entries, "xfce", _XFCE_PROCESSES, _FEDORA, ownership_check = _RPM_XFCE_OWNER)
    for unit in ["plymouth-start.service", "plymouth-quit.service", "plymouth-quit-wait.service"]:
        path = "etc/systemd/system/" + unit
        entries[path] = symlink_entry(path, "/dev/null")

def _opensuse(entries):
    config = entries["etc/sysconfig/displaymanager"]["data"].read()
    settings = dict([line.split("=", 1) for line in config.splitlines() if "=" in line and not line.startswith("#")])
    user = settings.get("DISPLAYMANAGER_AUTOLOGIN", "").strip('"')
    accounts = [line.split(":") for line in entries["etc/passwd"]["data"].read().splitlines()]
    uids = [int(account[2]) for account in accounts if len(account) == 7 and account[0] == user]
    if len(uids) != 1 or uids[0] == 0:
        fail("openSUSE live media must configure an unprivileged LightDM login")
    configure_lightdm_desktop(entries, "xfce", _XFCE_PROCESSES, _OPENSUSE, user = user, uid = uids[0], ownership_check = _RPM_XFCE_OWNER)

def _ubuntu(entries, hello):
    dpkg_add(entries, hello, None, _validate_hello)
    configure_gdm_desktop(entries, "gdm.service", "etc/gdm3/custom.conf", _UBUNTU, session = "ubuntu", ownership_check = """[ "$(dpkg-query -S /usr/bin/hello)" = "hello: /usr/bin/hello" ] && [ "$(LC_ALL=C /usr/bin/hello)" = "Hello, world!" ]""")

def _libc_version(value):
    parts = value.split(".")
    if len(parts) != 2 or not all([part.isdigit() for part in parts]):
        fail("unsupported libc6 version " + value)
    return (int(parts[0]), int(parts[1]))

def _validate_hello(fields, installed):
    dependency = fields.get("depends", "")
    prefix = "libc6 (>= "
    if fields["package"] != "hello" or fields["architecture"] != "amd64" or fields.get("pre-depends") or not dependency.startswith(prefix) or not dependency.endswith(")"):
        fail("an amd64 Hello package with a single minimum libc6 dependency is required")
    required = _libc_version(dependency[len(prefix):-1])
    for record in installed:
        package = record.fields
        if package["package"] == "libc6" and package["architecture"] == "amd64" and package["status"] == "install ok installed":
            if _libc_version(package["version"].split("-", 1)[0]) >= required:
                return
    fail("the installed Ubuntu libc6 does not satisfy " + dependency)

def _solus(entries):
    configure_lightdm_desktop(entries, "xfce", _XFCE_PROCESSES, _SOLUS, ownership_check = """eopkg search-file /usr/bin/xfce4-panel | grep -q 'xfce4-panel'""")
    # Solus's packaged LightDM PAM profile permits autologin for this group.
    add_login_group(entries, "users")

def _void(entries):
    configure_lightdm_login(entries, "xfce")
    modules = "etc/modules-load.d/trex-display.conf"
    entries[modules] = file_entry(modules, "virtio_mmio\nvirtio_gpu\n")

_DISTROS = ["alpine", "arch", "fedora", "gentoo", "nixos", "opensuse", "slackware", "solus", "ubuntu", "void"]

def main(args):
    media, base, names = read_media(args, _DISTROS, "scripts/smoke/linux_desktops_cc.star")
    failed = []
    for name in names:
        result = testing.attempt(_smoke, args = [name, media, base])
        if not result.ok:
            print(name, result.error)
            failed.append(name)
    if failed:
        fail("desktop smokes failed for " + ", ".join(failed))

def _smoke(name, media, base):
    alpine_iso = media_paths(media, base, ("shared", "loader_iso"))[0]
    if name == "alpine":
        paths = media_paths(media, base, ("shared", "minirootfs"), ("alpine", "main_index"), ("alpine", "packages"), ("alpine", "community_index"))
        alpine([alpine_iso] + paths)
        return
    if name == "arch":
        paths = media_paths(media, base, ("arch", "iso"), ("arch", "packages"))
        early_userspace = media_paths(media, base, ("shared", "minirootfs"))[0]
        arch(paths + [alpine_iso, early_userspace])
        return
    field = "iso" if name in ["slackware", "ubuntu"] else "desktop_iso"
    iso = media_paths(media, base, (name, field))[0]
    if name == "slackware":
        slackware([iso, alpine_iso])
        return
    loader = filesystem.iso9660(open(alpine_iso))["/efi/boot/bootx64.efi"]
    early_userspace = None
    if name in ["gentoo", "nixos", "fedora", "opensuse"]:
        early_userspace = open(media_paths(media, base, ("shared", "minirootfs"))[0])
    if name == "gentoo":
        disk = gentoo_graphical_disk(open(iso), loader, early_userspace, _GENTOO_SMOKE)
        inspect_root(disk, ["usr/bin/plasmashell", "usr/bin/kwin_wayland", "var/db/pkg/kde-plasma"])
        verify_desktop_cc(disk, _GENTOO, memory = 3072 << 20, timeout = 260, virtio_gpu = True)
        return
    if name == "void":
        disk = void_disk(open(iso), loader, smoke = _VOID_SMOKE, configure = _void)
        inspect_root(disk, ["usr/bin/xfce4-panel", "usr/share/xsessions/xfce.desktop", "var/db/xbps"])
        verify_desktop_cc(disk, _VOID, memory = 2048 << 20, timeout = 190, virtio_gpu = True)
        return
    if name == "nixos":
        disk = nixos_disk(open(iso), loader, early_userspace, graphical = True)
        inspect_root(disk, ["nix/var/nix/db/db.sqlite", "nix/var/nix/profiles/system"])
        verify_desktop_cc(disk, _NIXOS, memory = 3072 << 20, timeout = 330, console_check = _NIXOS_CONSOLE_CHECK)
        return
    if name == "fedora":
        disk = fedora_disk(open(iso), loader, configure = _fedora, early_userspace = early_userspace, variant = "xfce", cache_payload = True)
        inspect_root(disk, ["usr/bin/xfce4-panel", "usr/share/xsessions/xfce.desktop", "home/trex-desktop", "etc/systemd/system/display-manager.service"])
        verify_desktop_cc(disk, _FEDORA, memory = 3072 << 20, timeout = 540, virtio_gpu = True)
        return
    elif name == "opensuse":
        disk = opensuse_disk(open(iso), loader, early_userspace, configure = _opensuse)
        inspect_root(disk, ["usr/bin/xfce4-panel", "usr/share/xsessions/xfce.desktop", "home/linux", "etc/systemd/system/display-manager.service"])
        verify_desktop_cc(disk, _OPENSUSE, memory = 3072 << 20, timeout = 390, cpus = 2)
        return
    elif name == "solus":
        disk = solus_disk(open(iso), loader, configure = _solus, graphical = True, edition = "xfce")
        inspect_root(disk, ["usr/bin/xfce4-panel", "usr/share/xsessions/xfce.desktop", "home/trex-desktop", "etc/systemd/system/display-manager.service"])
        verify_desktop_cc(disk, _SOLUS, memory = 3072 << 20, timeout = 390, cpus = 2, virtio_gpu = True)
        return
    elif name == "ubuntu":
        hello = open(media_paths(media, base, ("ubuntu", "hello_deb"))[0])
        disk = ubuntu_disk(open(iso), loader, configure = lambda entries: _ubuntu(entries, hello))
        inspect_root(disk, ["usr/bin/hello", "var/lib/dpkg/info/hello.list"])
        inspect_root(disk, ["usr/bin/gnome-shell", "home/trex-desktop", "etc/systemd/system/display-manager.service"])
        verify_desktop_cc(disk, _UBUNTU, memory = 3072 << 20, timeout = 390, virtio_gpu = True, serial = False)
