"""Build and verify a fresh Alpine installation under CrumbleCracker."""

load("//scripts/images:alpine_linux.star", "alpine_disk", "alpine_sources")
load("//starlark/private/linux:installed.star", "verify_cc")

_SMOKE = """#!/bin/sh
set -eu
exec >/dev/ttyS0 2>&1
mount_source="$(awk '$2 == "/" && $3 == "ext4" {print $1}' /proc/mounts)"
[ "$mount_source" = /dev/nvme0n1p2 ]
[ -s /etc/alpine-release ]
[ "$(cat /proc/1/comm)" = init ]
apk info -e alpine-base openrc linux-virt jq >/dev/null
owner="$(apk info --who-owns /usr/bin/jq)"
case "$owner" in '/usr/bin/jq is owned by jq-'*) ;; *) exit 1 ;; esac
result="$(printf '%s\\n' '{"a":[2,40]}' | /usr/bin/jq -cer '.a | add')"
[ "$result" = 42 ]
printf 'ALPINE_INSTALLED_SMOKE_OK root=%s owner=jq output=%s\\n' "$mount_source" "$result"
poweroff
"""

def _inspect(disk):
    partitions = filesystem.gpt(disk).partitions
    if len(partitions) != 2:
        fail("Alpine image must have an EFI partition and an installed root")
    volume = filesystem.ext4(partitions[1]["file"])
    files = {entry.path: entry.data for entry in volume.entries if entry.data != None}
    for path in ["sbin/apk", "sbin/openrc", "usr/bin/jq", "etc/alpine-release", "lib/apk/db/installed"]:
        if path not in files:
            fail("missing Alpine installed file " + path)
    database = files["lib/apk/db/installed"].read()
    jq = [record for record in database.split("\n\n") if "\nP:jq\n" in record]
    if len(jq) != 1 or "\nF:usr/bin\nR:jq\n" not in jq[0]:
        fail("APK installed database does not own usr/bin/jq")

def main(args):
    if len(args) != 4:
        fail("usage: scripts/smoke/alpine_linux.star <Alpine virt ISO> <Alpine minirootfs> <main APKINDEX> <package directory>")
    boot_media, miniroot, repository, sources, _ = alpine_sources(*args)
    disk = alpine_disk(boot_media, miniroot, repository, sources, smoke = _SMOKE)
    _inspect(disk)
    marker = "ALPINE_INSTALLED_SMOKE_OK root=/dev/nvme0n1p2 owner=jq output=42"
    verify_cc(disk, marker, memory = 512 << 20, overlay_limit = 256 << 20, timeout = 60)
