"""Opens installed Windows 9x disks for native filesystem and CREG inspection."""

def _open_disk(name):
    disk = open(name)
    table = filesystem.mbr(disk)
    if len(table.partitions) != 1:
        fail(name + " does not contain exactly one MBR partition")
    return disk, table, filesystem.fat(table.partitions[0].file)

def main(args):
    if len(args) < 1 or len(args) > 2:
        fail("usage: scripts/inspect/windows_9x_disk_repl.star DISK.raw [REFERENCE.raw]")
    disk, table, volume = _open_disk(args[0])
    system = volume["/WINDOWS/SYSTEM.DAT"]
    user = volume["/WINDOWS/USER.DAT"]
    print("disk, table, volume, system, and user are available")
    print("system/user values:", len(windows.creg_patches(system)), len(windows.creg_patches(user)))
    if len(args) == 2:
        reference_disk, reference_table, reference_volume = _open_disk(args[1])
        reference_system = reference_volume["/WINDOWS/SYSTEM.DAT"]
        reference_user = reference_volume["/WINDOWS/USER.DAT"]
        print("reference_disk, reference_table, reference_volume, reference_system, and reference_user are available")
        print("reference system/user values:", len(windows.creg_patches(reference_system)), len(windows.creg_patches(reference_user)))
    repl()
