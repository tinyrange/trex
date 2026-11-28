"""Verify the original NixOS Bash store path on a fresh installed CC disk."""

load("//scripts/images:nixos_linux.star", "nixos_disk")
load("//starlark/private/linux:installed.star", "inspect_root", "verify_cc")

_MARKER = "NIXOS_INSTALLED_SMOKE_OK root=/dev/nvme0n1p2 provenance=nix-store output=42"
_SMOKE = """set -eu
export PATH=/run/current-system/sw/bin
exec >/dev/ttyS0 2>&1
check=root
trap 'rc=$?; [ "$rc" = 0 ] || echo "NIXOS_INSTALLED_SMOKE_FAILED check=$check rc=$rc"; systemctl --force --no-block poweroff' EXIT
[ "$(findmnt -no SOURCE,FSTYPE /)" = '/dev/nvme0n1p2 ext4' ]
[ "$(cat /proc/1/comm)" = systemd ]
. /etc/os-release
[ "$ID" = nixos ]
check=profile
[ "$(readlink -f /nix/var/nix/profiles/system)" = "$(readlink -f /run/current-system)" ]
check=bash_path
bash=$(readlink -f /run/current-system/sw/bin/bash)
case "$bash" in /nix/store/*-bash-*/bin/bash|/nix/store/*-bash-interactive-*/bin/bash) ;; *) echo "bash resolved to $bash"; exit 1 ;; esac
check=bash_hash
hash=$(nix-store --query --hash "${bash%/bin/bash}")
echo "Nix store path ${bash%/bin/bash} nar hash $hash"
printf '%s\n' "$hash" | grep -Eq '^sha256:([[:alnum:]]{52}|[[:xdigit:]]{64})$'
check=execution
[ "$("$bash" -c 'echo "$((6*7))"')" = 42 ]
echo '""" + _MARKER + """'
"""

def main(args):
    if len(args) != 3:
        fail("usage: scripts/smoke/nixos_linux.star <NixOS minimal ISO> <Alpine virt ISO> <Alpine minirootfs>")
    loader = filesystem.iso9660(open(args[1]))["/efi/boot/bootx64.efi"]
    disk = nixos_disk(open(args[0]), loader, open(args[2]), smoke = _SMOKE)
    root = inspect_root(disk, ["boot/bzImage", "etc/NIXOS", "nix/store", "nix/var/nix/db/db.sqlite", "nix/var/nix/profiles/system"])
    store = database.sqlite(root.find("nix/var/nix/db/db.sqlite").file)
    paths = [row["values"][1] for row in store.rows("ValidPaths")]
    if not any([root.find(path[1:] + "/bin/bash") != None for path in paths if "-bash-" in path]):
        fail("the installed Nix database does not register a Bash payload")
    verify_cc(disk, _MARKER, memory = 1536 << 20, overlay_limit = 512 << 20, timeout = 135)
