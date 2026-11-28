"""Verify the installed Gentoo stage and its Portage database in CC."""

load("//scripts/images:gentoo_linux.star", "gentoo_disk")
load("//starlark/private/linux:installed.star", "inspect_root", "verify_cc")

_MARKER = "GENTOO_INSTALLED_SMOKE_OK root=/dev/nvme0n1p2 owner=app-shells/bash output=42"
_SMOKE = """#!/bin/sh
set -eu
exec >/dev/ttyS0 2>&1
check=root
trap 'rc=$?; [ "$rc" = 0 ] || echo "GENTOO_INSTALLED_SMOKE_FAILED check=$check rc=$rc"; poweroff' EXIT
[ "$(findmnt -no SOURCE,FSTYPE /)" = '/dev/nvme0n1p2 ext4' ]
[ "$(cat /proc/1/comm)" = init ]
. /etc/os-release
[ "$ID" = gentoo ]
check=ownership
pkg="$(portageq match / app-shells/bash)"
case "$pkg" in
    app-shells/bash-*) ;;
    *) echo "$pkg"; exit 1 ;;
esac
grep -Eq '^obj /(usr/)?bin/bash ' "/var/db/pkg/$pkg/CONTENTS"
check=execution
[ "$(/bin/bash -c 'echo "$((6*7))"')" = 42 ]
echo '""" + _MARKER + """'
"""

def main(args):
    if len(args) != 4:
        fail("usage: scripts/smoke/gentoo_linux.star <stage3 tar.xz> <Gentoo install ISO> <Alpine virt ISO> <Alpine minirootfs>")
    loader = filesystem.iso9660(open(args[2]))["/efi/boot/bootx64.efi"]
    disk = gentoo_disk(open(args[0]), open(args[1]), loader, open(args[3]), smoke = _SMOKE)
    root = inspect_root(disk, ["usr/bin/portageq", "usr/bin/bash", "var/db/pkg/app-shells"])
    if not any([node.name.startswith("bash-") and node.find("CONTENTS") != None for node in root.find("var/db/pkg/app-shells").files]):
        fail("Gentoo VDB is missing the installed bash record")
    verify_cc(disk, _MARKER, memory = 1536 << 20)
