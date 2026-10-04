"""Builds a fully installed MS-DOS 6.22 disk from its three setup floppies."""

PARTITION_LBA = 63
IMAGE_SIZE = 32 * 1024 * 1024
DISK_SIGNATURE = 0x54524436
VOLUME_LABEL = "MSDOS622"
BIOS_CHS = (66, 16, 63)
HELLO_MESSAGE = "*** Hello from TinyRangeX on MS-DOS 6.22! ***"

_SYSTEM_FILES = ["IO.SYS", "MSDOS.SYS", "COMMAND.COM"]
_SETUP_METADATA = ["AUTOEXEC.BAT", "CONFIG.SYS"]

def _open_setup_disk(source, number):
    if source.size != 1440 * 1024:
        fail("MS-DOS 6.22 setup disk %d must be a 1.44 MiB image" % number)
    volume = filesystem.fat(source)
    markers = {
        1: ["/IO.SYS", "/MSDOS.SYS", "/COMMAND.COM", "/PACKING.LST"],
        2: ["/HIMEM.SY_", "/DRVSPACE.EXE"],
        3: ["/MSAV.EXE", "/UNDELETE.EXE"],
    }[number]
    missing = [name for name in markers if name not in volume]
    if missing:
        fail("MS-DOS 6.22 setup disk %d is missing: %s" % (number, ", ".join(missing)))
    return volume

def _source_files(volumes):
    files = {}
    for volume in volumes:
        for source_path in volume["/"].files:
            if source_path == "/$metadata":
                continue
            name = path.base(source_path).upper()
            if name in files:
                fail("duplicate MS-DOS setup member " + name)
            files[name] = volume[source_path]
    return files

def _packing_plan(disk1, files):
    plan = []
    destinations = {}
    text = disk1["/PACKING.LST"].read().replace("\r", "")
    for line in text.split("\n"):
        fields = line.split()
        if len(fields) != 2:
            continue
        source = fields[0].upper()
        destination = fields[1].upper()
        if source not in files:
            continue
        if destination in destinations:
            fail("duplicate installed MS-DOS file " + destination)
        destinations[destination] = source
        plan.append((source, destination))
    missing = [name for name in files if name not in [item[0] for item in plan]]
    if missing:
        fail("PACKING.LST does not describe setup members: " + ", ".join(sorted(missing)))
    return plan

def _installed_file(source_name, source):
    return archive.kwaj(source) if source_name.endswith("_") else source

def _installed_tree(volumes):
    files = _source_files(volumes)
    plan = _packing_plan(volumes[0], files)
    root = directory()
    root.mkdir("/DOS")
    root.mkdir("/TEMP")

    for name in _SYSTEM_FILES:
        root.write("/" + name, files[name])
    for name in ["/IO.SYS", "/MSDOS.SYS"]:
        root.set_attributes(name, readonly = True, hidden = True, system = True)

    installed = 0
    for source_name, destination in plan:
        if source_name in _SYSTEM_FILES or source_name in _SETUP_METADATA:
            continue
        root.write("/DOS/" + destination, _installed_file(source_name, files[source_name]))
        installed += 1

    # MS-DOS Setup places the compression driver at the root as a protected
    # boot-time file in addition to the utility set under C:\DOS.
    root.write("/DRVSPACE.BIN", files["DRVSPACE.BIN"])
    root.set_attributes("/DRVSPACE.BIN", readonly = True, hidden = True, system = True)
    root.write("/CONFIG.SYS", "FILES=30\r\nBUFFERS=20\r\nLASTDRIVE=Z\r\n")
    root.write("/AUTOEXEC.BAT", "@ECHO OFF\r\nPROMPT $P$G\r\nPATH C:\\DOS\r\nSET TEMP=C:\\TEMP\r\nCALL C:\\HELLO.BAT\r\n")
    root.write("/HELLO.BAT", "@ECHO OFF\r\nECHO.\r\nECHO " + HELLO_MESSAGE + "\r\nECHO The complete DOS 6.22 toolset is installed in C:\\DOS.\r\nECHO.\r\n")
    print("modeled MS-DOS 6.22 installation files:", installed)
    return root

def msdos_622_directory(disk1, disk2, disk3):
    """Returns the complete installed MS-DOS 6.22 directory tree."""
    volumes = [
        _open_setup_disk(disk1, 1),
        _open_setup_disk(disk2, 2),
        _open_setup_disk(disk3, 3),
    ]
    return _installed_tree(volumes)

def msdos_622_disk(disk1, disk2, disk3):
    """Returns a lazy installed MS-DOS 6.22 FAT16 hard-disk image."""
    volumes = [
        _open_setup_disk(disk1, 1),
        _open_setup_disk(disk2, 2),
        _open_setup_disk(disk3, 3),
    ]
    root = _installed_tree(volumes)
    boot_sector = volumes[0]["/$metadata/boot_sector.bin"]
    filesystem_image = filesystem.fat16(
        root,
        size = IMAGE_SIZE,
        boot_code = boot_sector,
        hidden_sectors = PARTITION_LBA,
        label = VOLUME_LABEL,
        file_order = ["/IO.SYS", "/MSDOS.SYS", "/COMMAND.COM"],
        directory_label = False,
    )
    return filesystem.mbr(
        IMAGE_SIZE + PARTITION_LBA * 512,
        disk_signature = DISK_SIGNATURE,
    ).partition(
        filesystem_image,
        bootable = True,
        type = 0x06,
        start_lba = PARTITION_LBA,
    )

def main(args):
    if len(args) != 4:
        error("Usage: scripts/images/msdos_622.star <setup-disk-1.img> <setup-disk-2.img> <setup-disk-3.img> <output.raw>")
    disk = msdos_622_disk(open(args[0]), open(args[1]), open(args[2]))
    print("writing installed MS-DOS 6.22 disk image")
    write(args[3], disk)
    return disk
