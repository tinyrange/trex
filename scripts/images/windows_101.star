"""Builds a fully installed Microsoft Windows 1.01 disk on MS-DOS 6.22."""

load("//scripts/images:msdos_622.star", "msdos_622_directory")

PARTITION_LBA = 63
IMAGE_SIZE = 32 * 1024 * 1024
DISK_SIGNATURE = 0x31575254
VOLUME_LABEL = "WIN101"
BIOS_CHS = (66, 16, 63)
HELLO_TITLE = "Hello from Windows 1.01"

_MEDIA_SIZE = 360 * 1024
_FONT_CONFIGURATION = """
[fonts]
Courier 8,10,12 (Set #3)=COURB
Helv 8,10,12 (Set #3)=HELVB
Tms Rmn 8,10,12 (Set #3)=TMSRB
System, Terminal (Set #3)=HIFONTS
Courier 8,10,12 (Set #2)=COURA
Helv 8,10,12 (Set #2)=HELVA
Tms Rmn 8,10,12 (Set #2)=TMSRA
Roman (Set #1)=ROMAN
Script (Set #1)=SCRIPT
Modern (Set #1)=MODERN
System, Terminal (Set #2)=LOFONTS
"""

def _open_windows_disk(source, number):
    if source.size != _MEDIA_SIZE:
        fail("Windows 1.01 disk %d must be a 360 KiB image" % number)
    volume = filesystem.fat(source)
    markers = {
        1: ["/SETUP.EXE", "/KERNEL.EXE", "/PIF"],
        2: ["/BUILD.LBL", "/GDI.EXE", "/USER.EXE", "/WIN.CNF"],
        3: ["/UTILITY.LBL", "/COURA.FON", "/EPSON.DRV"],
        4: ["/CALC.EXE", "/NOTEPAD.EXE", "/PAINT.EXE"],
        5: ["/WRITE.EXE", "/PRACTICE.DOC", "/README.DOC"],
    }[number]
    missing = [name for name in markers if name not in volume]
    if missing:
        fail("Windows 1.01 disk %d is missing: %s" % (number, ", ".join(missing)))
    return volume

def _copy_directory(volume, source, destination, target):
    for source_path in source.files:
        if source_path == "/$metadata":
            continue
        member = volume[source_path]
        output = target + "/" + path.base(source_path)
        if type(member) == "directory":
            if output not in destination.files:
                destination.mkdir(output)
            _copy_directory(volume, member, destination, output)
        elif output not in destination.files:
            destination.write(output, member)

def _installed_windows_tree(root, volumes, startup):
    root.mkdir("/WINDOWS")
    for volume in volumes:
        _copy_directory(volume, volume["/"], root, "/WINDOWS")

    setup, build = volumes[0], volumes[1]
    fastboot = windows.ne_fastboot([
        setup["/KERNEL.EXE"],
        setup["/SYSTEM.DRV"],
        setup["/KEYBUS.DRV"],
        setup["/NOMOUSE.DRV"],
        setup["/EGAHIRES.DRV"],
        setup["/SOUND.DRV"],
        setup["/COMM.DRV"],
        setup["/HIFONTS.FON"],
        build["/GDI.EXE"],
        build["/USER.EXE"],
        build["/MSDOSD.EXE"],
        build["/MSDOS.EXE"],
    ])
    root.write("/WINDOWS/WIN.COM", binary.concat([build["/WIN.CNF"], build["/CGA.LGO"]]))
    root.write("/WINDOWS/WIN100.BIN", fastboot["bin"])
    root.write("/WINDOWS/WIN100.OVL", fastboot["overlay"])
    root.write("/WINDOWS/WINOLDAP.GRB", build["/EGALORES.GRB"])
    # The real-mode DOS support module has been bound into WIN100.BIN.  Setup
    # leaves this one-byte return stub in its place in the installed tree.
    root.write("/WINDOWS/MSDOS.EXE", b"\xc3")

    ini = build["/WIN.INI"].read().replace("    ", "").replace(" = ", "=")
    ini = ini.replace("run=\r\n", "run=" + startup + "\r\n") + _FONT_CONFIGURATION.replace("\n", "\r\n")
    root.write("/WINDOWS/WIN.INI", ini)
    root.write("/HELLO.TXT", HELLO_TITLE + "\r\n\r\nThis complete image was assembled natively by TinyRangeX.\r\n")

def windows_101_disk(dos_disk1, dos_disk2, dos_disk3, setup_disk, build_disk, utility_disk, applications_disk, write_disk, modifications = [], startup = "c:\\hello.txt"):
    """Returns a fully installed Windows 1.01 FAT16 hard-disk image."""
    root = msdos_622_directory(dos_disk1, dos_disk2, dos_disk3)
    volumes = [
        _open_windows_disk(setup_disk, 1),
        _open_windows_disk(build_disk, 2),
        _open_windows_disk(utility_disk, 3),
        _open_windows_disk(applications_disk, 4),
        _open_windows_disk(write_disk, 5),
    ]
    _installed_windows_tree(root, volumes, startup)

    setver = archive.kwaj(filesystem.fat(dos_disk2)["/SETVER.EX_"])
    root.write("/DOS/SETVER.EXE", windows.setver(setver, "WIN100.BIN", 3, 30))
    root.write("/CONFIG.SYS", "DEVICE=C:\\DOS\\SETVER.EXE\r\nFILES=30\r\nBUFFERS=20\r\nLASTDRIVE=Z\r\n")
    root.write("/AUTOEXEC.BAT", "@ECHO OFF\r\nPROMPT $P$G\r\nPATH C:\\DOS;C:\\WINDOWS\r\nSET TEMP=C:\\TEMP\r\nCD \\WINDOWS\r\nWIN\r\n")

    for modification in modifications:
        root.write(modification["path"], modification["file"])

    boot_volume = filesystem.fat(dos_disk1)
    filesystem_image = filesystem.fat16(
        root,
        size = IMAGE_SIZE,
        boot_code = boot_volume["/$metadata/boot_sector.bin"],
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
    if len(args) != 9:
        error("Usage: scripts/images/windows_101.star <dos-1.img> <dos-2.img> <dos-3.img> <setup.img> <build.img> <utility.img> <applications.img> <write.img> <output.raw>")
    disk = windows_101_disk(
        open(args[0]), open(args[1]), open(args[2]),
        open(args[3]), open(args[4]), open(args[5]), open(args[6]), open(args[7]),
    )
    print("writing fully installed Windows 1.01 disk image")
    write(args[8], disk)
    return disk
