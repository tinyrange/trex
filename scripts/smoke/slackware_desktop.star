"""Slipstream the Slackware DVD's Xfce package sets and boot their desktop."""

load("//scripts/images:slackware_linux.star", "slackware_disk")
load("//starlark/private/linux:desktop.star", "configure_xfce_x11", "install_shared_mime", "verify_desktop_cc")
load("//starlark/private/linux:installed.star", "inspect_root")

_PROOF = "SLACKWARE_DESKTOP_OK xfce4-panel xfdesktop xfwm4"

def _configure(entries):
    fstab = "etc/fstab"
    entries[fstab]["data"] += "tmpfs /dev/shm tmpfs nosuid,nodev 0 0\n"
    install_shared_mime(entries)
    configure_xfce_x11(entries, "sysv", _PROOF, "grep -qx usr/bin/xfce4-panel /var/lib/pkgtools/packages/xfce4-panel-*")

def main(args):
    if len(args) != 2:
        fail("usage: scripts/smoke/slackware_desktop.star <Slackware DVD> <Alpine virt ISO>")
    loader = filesystem.iso9660(open(args[1]))["/efi/boot/bootx64.efi"]
    disk = slackware_disk(open(args[0]), loader, desktop = _configure)
    inspect_root(disk, ["usr/bin/Xorg", "usr/bin/xfce4-panel", "var/lib/pkgtools/packages/xfce4-panel-4.16.3-x86_64-1"])
    verify_desktop_cc(disk, _PROOF, timeout = 230)
