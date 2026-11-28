"""Verify XBPS ownership, runit and an installed program in CC."""

load("//scripts/images:void_linux.star", "void_disk")
load("//starlark/private/linux:installed.star", "inspect_root", "verify_cc")

_MARKER = "VOID_INSTALLED_SMOKE_OK root=/dev/nvme0n1p2 owner=bash output=42"
_SMOKE = """#!/bin/sh
set -eu
exec >/dev/ttyS0 2>&1
check=root
trap 'rc=$?; [ "$rc" = 0 ] || echo "VOID_INSTALLED_SMOKE_FAILED check=$check rc=$rc"; shutdown -P now' EXIT
[ "$(findmnt -no SOURCE,FSTYPE /)" = '/dev/nvme0n1p2 ext4' ]
[ "$(cat /proc/1/comm)" = runit ]
. /etc/os-release
[ "$ID" = void ]
check=ownership
owner="$(xbps-query -o /usr/bin/bash)"
case "$owner" in
    bash-[0-9]*) ;;
    *) echo "$owner"; exit 1 ;;
esac
check=execution
[ "$(/usr/bin/bash -c 'echo "$((6*7))"')" = 42 ]
echo '""" + _MARKER + """'
"""

def main(args):
    if len(args) != 2:
        fail("usage: scripts/smoke/void_linux.star <Void base ISO> <Alpine virt ISO>")
    loader = filesystem.iso9660(open(args[1]))["/efi/boot/bootx64.efi"]
    disk = void_disk(open(args[0]), loader, smoke = _SMOKE)
    root = inspect_root(disk, ["usr/bin/xbps-query", "usr/bin/bash", "var/db/xbps"])
    xbps = root.find("var/db/xbps")
    if not any([file.name.startswith("pkgdb-") and file.name.endswith(".plist") for file in xbps.files]):
        fail("the installed XBPS database is missing")
    verify_cc(disk, _MARKER, memory = 1536 << 20)
