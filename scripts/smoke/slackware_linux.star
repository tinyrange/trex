"""Verify Slackware pkgtools records and installed bash in CrumbleCracker."""

load("//scripts/images:slackware_linux.star", "slackware_disk")
load("//starlark/private/linux:installed.star", "inspect_root", "verify_cc")

_MARKER = "SLACKWARE_INSTALLED_SMOKE_OK root=/dev/nvme0n1p2 owner=bash output=42"
_SMOKE = """#!/bin/sh
set -eu
exec >/dev/ttyS0 2>&1
check=root
trap 'rc=$?; [ "$rc" = 0 ] || echo "SLACKWARE_INSTALLED_SMOKE_FAILED check=$check rc=$rc"; poweroff' EXIT
[ "$(findmnt -no SOURCE,FSTYPE /)" = '/dev/nvme0n1p2 ext4' ]
grep -q '^Slackware ' /etc/slackware-version
check=ownership
set -- /var/lib/pkgtools/packages/bash-*
[ "$#" = 1 ] && [ -f "$1" ]
record=$1
package=${record##*/}
grep '^PACKAGE NAME:' "$record" | grep -Fq " $package"
grep -Eq '^bin/bash[0-9]*[.]new$|^bin/bash$' "$record"
if ! grep -Fxq 'bin/bash' "$record"; then
    grep -Eq 'mv bin/bash[0-9]*[.]new bin/bash' "/var/lib/pkgtools/scripts/$package"
fi
test -x /sbin/pkgtool && test -x /usr/sbin/slackpkg
check=execution
[ "$(/bin/bash -c 'echo "$((6*7))"')" = 42 ]
printf '\n%s\n' '""" + _MARKER + """'
"""

def main(args):
    if len(args) != 2:
        fail("usage: scripts/smoke/slackware_linux.star <Slackware DVD> <Alpine virt ISO>")
    loader = filesystem.iso9660(open(args[1]))["/efi/boot/bootx64.efi"]
    disk = slackware_disk(open(args[0]), loader, smoke = _SMOKE)
    root = inspect_root(disk, ["bin/bash", "sbin/pkgtool", "usr/sbin/slackpkg", "var/lib/pkgtools/packages"])
    if len([file for file in root.find("var/lib/pkgtools/packages").files if file.name.startswith("bash-")]) != 1:
        fail("Slackware must contain one installed Bash package")
    verify_cc(disk, _MARKER)
