"""Boot and verify the native Ubuntu installation under CrumbleCracker."""

load("//scripts/images:ubuntu_linux.star", "ubuntu_disk")
load("//starlark/private/linux:disk.star", "launch_cc")

_MARKER = "UBUNTU_INSTALLED_SMOKE_OK root=/dev/nvme0n1p2 owner=jq output=42 cap_net_raw=ep"
_SMOKE = """#!/bin/sh
say() { printf '%s\\n' "$*" >/dev/ttyS0; }
proof() {
    check=root
    say "UBUNTU_INSTALLED_SMOKE_CHECK $check"
    awk '$1 == "/dev/nvme0n1p2" && $2 == "/" && $3 == "ext4" { found=1 } END { exit !found }' /proc/mounts || return
    check=release
    [ "$(cat /proc/1/comm)" = systemd ] || return
    . /etc/os-release
    [ "$ID" = ubuntu ] && [ "$VERSION_ID" = 24.04 ] || return
    check=jq-ownership
    say "UBUNTU_INSTALLED_SMOKE_CHECK $check"
    [ "$(dpkg-query -S /usr/bin/jq)" = 'jq: /usr/bin/jq' ] || return
    check=kernel-ownership
    [ "$(dpkg-query -W -f='${db:Status-Status}' "linux-image-$(uname -r)")" = installed ] || return
    check=jq-execution
    say "UBUNTU_INSTALLED_SMOKE_CHECK $check"
    result="$(printf '%s\\n' '{"a":[2,40]}' | /usr/bin/jq -cer '.a | add')"
    [ "$result" = 42 ] || return
    check=capability
    [ "$(getcap /usr/bin/ping)" = '/usr/bin/ping cap_net_raw=ep' ]
}
if proof; then
    say '""" + _MARKER + """'
else
    say "UBUNTU_INSTALLED_SMOKE_FAILED check=$check"
fi
systemctl --force --no-block poweroff
"""

def _inspect(disk):
    volume = auto(filesystem.gpt(disk).partitions[1]["file"], maximum_entries = 300000, literal_backslash = True)
    for path in ["usr/bin/dpkg-query", "usr/bin/jq", "usr/lib/systemd/systemd", "var/lib/dpkg/info/jq.list"]:
        if volume.find(path) == None:
            fail("missing installed Ubuntu file " + path)
    status = archive.debian_control(volume.find("var/lib/dpkg/status").file)
    installed = [p.fields["package"] for p in status if p.fields["status"] == "install ok installed"]
    if "jq" not in installed or not any([name.startswith("linux-image-") for name in installed]):
        fail("missing installed Ubuntu jq or kernel package record")
    if "security.capability" not in volume.find("usr/bin/ping").summary["attributes"].get("xattrs", {}):
        fail("Ubuntu ping lost its extended attribute in the installed disk")

def main(args):
    if len(args) != 2:
        fail("usage: scripts/smoke/ubuntu_linux.star <Ubuntu Desktop ISO> <Alpine virt ISO supplying GRUB>")
    loader = filesystem.iso9660(open(args[1]))["/efi/boot/bootx64.efi"]
    disk = ubuntu_disk(open(args[0]), loader, smoke = _SMOKE)
    _inspect(disk)
    vm = launch_cc(disk, memory = 3072 << 20, overlay_limit = 768 << 20, run_timeout = 150)
    result = testing.attempt(vm.wait, kwargs = {"timeout": 152})
    state = testing.attempt(vm.extension("cc.v1").state)
    vm.close()
    if not state.ok:
        fail(state.error)
    output = state.value["console"].replace("\r", "")
    if not result.ok or result.value.reason != "shutdown" or not any([line.endswith(_MARKER) for line in output.splitlines()]):
        reason = (result.value.reason + ": " + result.value.detail) if result.ok else result.error
        checks = [line for line in output.splitlines() if "UBUNTU_INSTALLED_SMOKE_" in line or "trex-smoke.service" in line]
        fail("Ubuntu CC smoke failed: " + reason + "\n" + "\n".join(checks) + "\n" + output[-7000:])
    print(_MARKER)
