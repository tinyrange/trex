"""Verify pacman ownership and execution on a freshly installed CC disk."""

load("//scripts/images:arch_linux.star", "arch_disk")
load("//starlark/private/linux:installed.star", "inspect_root", "verify_cc")

_MARKER = "ARCH_INSTALLED_SMOKE_OK root=/dev/nvme0n1p2 owner=bash output=42"
_SMOKE = """#!/bin/sh
set -eu
exec >/dev/ttyS0 2>&1
check=root
trap 'rc=$?; [ "$rc" = 0 ] || echo "ARCH_INSTALLED_SMOKE_FAILED check=$check rc=$rc"; systemctl --force --no-block poweroff' EXIT
[ "$(findmnt -no SOURCE,FSTYPE /)" = '/dev/nvme0n1p2 ext4' ]
[ "$(cat /proc/1/comm)" = systemd ]
. /etc/os-release
[ "$ID" = arch ]
check=ownership
[ "$(pacman -Qoq /usr/bin/bash)" = bash ]
check=execution
[ "$(/usr/bin/bash -c 'echo "$((6*7))"')" = 42 ]
echo '""" + _MARKER + """'
"""

def main(args):
    if len(args) != 3:
        fail("usage: scripts/smoke/arch_linux.star <Arch ISO> <Alpine virt ISO> <Alpine minirootfs>")
    loader = filesystem.iso9660(open(args[1]))["/efi/boot/bootx64.efi"]
    disk = arch_disk(open(args[0]), loader, open(args[2]), smoke = _SMOKE)
    root = inspect_root(disk, ["etc/os-release", "usr/bin/pacman", "usr/bin/bash", "var/lib/pacman/local"])
    database = root.find("var/lib/pacman/local")
    owners = [d for d in database.files if d.name.startswith("bash-") and d.find("files") != None and "usr/bin/bash" in d.find("files").file.read().splitlines()]
    if len(owners) != 1:
        fail("expected one installed Arch bash package")
    verify_cc(disk, _MARKER, memory = 1536 << 20)
