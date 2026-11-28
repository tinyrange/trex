"""Verify installed eopkg ownership and program execution in CrumbleCracker."""

load("//scripts/images:solus_linux.star", "solus_disk")
load("//starlark/private/linux:installed.star", "inspect_root", "verify_cc")

_MARKER = "SOLUS_INSTALLED_SMOKE_OK root=/dev/nvme0n1p2 owner=bash output=42"
_SMOKE = """#!/bin/bash
set -eu
exec >/dev/ttyS0 2>&1
check=root
trap 'rc=$?; [ "$rc" = 0 ] || echo "SOLUS_INSTALLED_SMOKE_FAILED check=$check rc=$rc"; systemctl --force --no-block poweroff' EXIT
[ "$(findmnt -no SOURCE,FSTYPE /)" = '/dev/nvme0n1p2 ext4' ]
. /etc/os-release
[ "$ID" = solus ]
check=ownership
eopkg list-installed bash | grep -Eq '^bash[[:space:]]'
eopkg search-file /usr/bin/bash | grep -Eq '(^|[[:space:]])bash([[:space:]:]|$)'
check=execution
[ "$(/usr/bin/bash -c 'echo "$((6*7))"')" = 42 ]
echo '""" + _MARKER + """'
"""

def main(args):
    if len(args) != 2:
        fail("usage: scripts/smoke/solus_linux.star <Solus Budgie ISO> <Alpine virt ISO>")
    loader = filesystem.iso9660(open(args[1]))["/efi/boot/bootx64.efi"]
    disk = solus_disk(open(args[0]), loader, smoke = _SMOKE)
    root = inspect_root(disk, ["usr/bin/eopkg", "usr/bin/bash", "var/lib/eopkg/package"])
    owners = []
    for node in root.find("var/lib/eopkg/package").files:
        if node.name.startswith("bash-"):
            files = node.find("files.xml")
            if files != None and "<Path>usr/bin/bash</Path>" in files.file.read():
                owners.append(node.name)
    if len(owners) != 1:
        fail("Solus media did not provide an installed eopkg bash file record")
    verify_cc(disk, _MARKER, memory = 2048 << 20, overlay_limit = 768 << 20, timeout = 150)
