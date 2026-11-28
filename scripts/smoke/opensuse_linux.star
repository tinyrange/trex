"""Verify openSUSE's installed RPM, Zypper and bash on a fresh CC disk."""

load("//scripts/images:opensuse_linux.star", "opensuse_disk")
load("//starlark/private/linux:installed.star", "inspect_root", "verify_cc")

_MARKER = "OPENSUSE_INSTALLED_SMOKE_OK root=/dev/nvme0n1p2 owner=bash output=42"
_SMOKE = """#!/bin/bash
set -eu
exec >/dev/ttyS0 2>&1
check=root
trap 'rc=$?; [ "$rc" = 0 ] || echo "OPENSUSE_INSTALLED_SMOKE_FAILED check=$check rc=$rc"; systemctl --force --no-block poweroff' EXIT
[ "$(findmnt -no SOURCE,FSTYPE /)" = '/dev/nvme0n1p2 ext4' ]
. /etc/os-release
[ "$ID" = opensuse-tumbleweed ]
check=ownership
[ "$(rpm -qf --qf '%{NAME}' /usr/bin/bash)" = bash ]
zypper --version
check=execution
[ "$(/usr/bin/bash -c 'echo "$((6*7))"')" = 42 ]
echo '""" + _MARKER + """'
"""

def main(args):
    if len(args) != 3:
        fail("usage: scripts/smoke/opensuse_linux.star <openSUSE GNOME ISO> <Alpine virt ISO> <Alpine minirootfs>")
    loader = filesystem.iso9660(open(args[1]))["/efi/boot/bootx64.efi"]
    disk = opensuse_disk(open(args[0]), loader, open(args[2]), smoke = _SMOKE)
    root = inspect_root(disk, ["usr/bin/rpm", "usr/bin/zypper", "usr/bin/bash", "usr/lib/sysimage/rpm/Packages.db"])
    if root.find("usr/lib/sysimage/rpm/Packages.db").file.size == 0:
        fail("openSUSE media did not provide an installed RPM database")
    verify_cc(disk, _MARKER, memory = 2048 << 20, overlay_limit = 768 << 20, timeout = 150)
