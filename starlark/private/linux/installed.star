"""Common filesystem and smoke policy for Linux installed disks."""

load(":disk.star", "disk_image", "launch_cc", "root_partition_id")
load(":tree.star", "file_entry")

def root_configuration(entries, image_id, hostname):
    for path, data in [
        ("etc/fstab", "PARTUUID=" + root_partition_id(image_id) + " / ext4 defaults 0 1\n"),
        ("etc/hostname", hostname + "\n"),
    ]:
        previous = entries.get(path, {})
        entry = file_entry(path, data)
        if previous.get("xattrs"):
            entry["xattrs"] = previous["xattrs"]
        entries[path] = entry

def lock_root_password(entries):
    shadow = entries["etc/shadow"]
    lines = []
    for line in shadow["data"].read().splitlines():
        if line.startswith("root:"):
            account = line.split(":")
            account[1] = "!"
            line = ":".join(account)
        lines.append(line)
    entry = dict(shadow)
    entry["data"] = "\n".join(lines) + "\n"
    entries["etc/shadow"] = entry

def build_installed_disk(image_id, loader, kernel, initrd, entries, size, label, extra_cmdline = "", root_read_only = False):
    root = filesystem.ext4_build(entries.values(), size = size, label = label)
    mount = "ro" if root_read_only else "rw"
    args = "root=PARTUUID=" + root_partition_id(image_id) + " rootfstype=ext4 " + mount + " console=ttyS0,115200 nokaslr panic=-1"
    if extra_cmdline:
        args += " " + extra_cmdline
    return disk_image(image_id, loader, kernel, args, initramfs = initrd, root = root)

def inspect_root(disk, paths):
    partitions = filesystem.gpt(disk).partitions
    if len(partitions) != 2:
        fail("installed Linux disk needs an EFI partition and a root partition")
    root = auto(partitions[1]["file"], maximum_entries = 500000, literal_backslash = True)
    if root.metadata["format"] != "ext4":
        fail("expected native ext4 in the installed root partition")
    for path in paths:
        if root.find(path) == None:
            fail("missing installed file " + path)
    return root

def verify_cc(disk, marker, memory = 1024 << 20, overlay_limit = 384 << 20, timeout = 90):
    vm = launch_cc(disk, memory = memory, overlay_limit = overlay_limit, run_timeout = timeout)
    result = testing.attempt(vm.wait, kwargs = {"timeout": timeout + 2})
    state = testing.attempt(vm.extension("cc.v1").state)
    vm.close()
    if not state.ok:
        fail(state.error)
    output = state.value["console"].replace("\r", "")
    if not result.ok or result.value.reason != "shutdown" or result.value.detail != "ACPI S5" or marker not in output.splitlines():
        reason = (result.value.reason + ": " + result.value.detail) if result.ok else result.error
        nvme = state.value["nvme"]
        storage_errors = "\nNVMe: " + repr(nvme["backing_failures"][-3:]) if nvme and nvme["backing_failure_count"] else ""
        fail("installed CC smoke failed: " + reason + " at PC 0x%x\n" % (state.value["pc"] & ((1 << 64) - 1)) + output[-7500:] + storage_errors + "\nEFI: " + repr(state.value["efi"][-3:]))
    print(marker)
