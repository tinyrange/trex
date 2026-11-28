"""Verify installed Fedora Workstation RPM ownership and DNF in CC."""

load("//scripts/images:fedora_linux.star", "fedora_disk")
load("//starlark/private/linux:installed.star", "inspect_root", "verify_cc")

_MARKER = "FEDORA_INSTALLED_SMOKE_OK root=/dev/nvme0n1p2 owner=bash output=42"
_SMOKE = """#!/bin/bash
set -eu
exec >/dev/ttyS0 2>&1
check=root
trap 'rc=$?; [ "$rc" = 0 ] || echo "FEDORA_INSTALLED_SMOKE_FAILED check=$check rc=$rc"; systemctl --force --no-block poweroff' EXIT
echo FEDORA_INSTALLED_SMOKE_STARTED
[ "$(findmnt -no SOURCE,FSTYPE /)" = '/dev/nvme0n1p2 ext4' ]
[ "$(cat /proc/1/comm)" = systemd ]
. /etc/os-release
[ "$ID" = fedora ]
[ "$VARIANT_ID" = workstation ]
check=ownership
[ "$(rpm -qf --qf '%{NAME}' /usr/bin/bash)" = bash ]
echo FEDORA_INSTALLED_SMOKE_RPM_OK
check=dnf
dnf --version >/dev/null
check=execution
[ "$(/usr/bin/bash -c 'echo "$((6*7))"')" = 42 ]
echo '""" + _MARKER + """'
"""

def main(args):
    if len(args) != 2:
        fail("usage: scripts/smoke/fedora_linux.star <Fedora Workstation ISO> <Alpine virt ISO>")
    loader = filesystem.iso9660(open(args[1]))["/efi/boot/bootx64.efi"]
    disk = fedora_disk(open(args[0]), loader, smoke = _SMOKE)
    root = inspect_root(disk, ["usr/bin/rpm", "usr/bin/dnf", "usr/bin/bash", "usr/lib/sysimage/rpm/rpmdb.sqlite"])
    if root.find("usr/lib/sysimage/rpm/rpmdb.sqlite").file.slice(0, 16).read() != "SQLite format 3\x00":
        fail("missing Fedora's installed RPM SQLite database header")
    verify_cc(disk, _MARKER, memory = 3072 << 20, overlay_limit = 768 << 20, timeout = 150)
