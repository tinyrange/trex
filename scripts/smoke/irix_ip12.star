"""Boot the IRIX 3.3.2 installer miniroot through the first /etc/init instruction."""

def prepare(source, options = [], system = None):
    """Open the original miniroot, attach its disk, and load its kernel."""
    archive_file = archive.sevenzip(source)
    support = [f for f in archive_file.entries if f.path.endswith("/4D35-support-1.0-tape1/sa")]
    if len(support) != 1:
        fail("expected the Personal IRIS 4D/35 support tape")
    tape = archive.irix_tape(binary.view(support[0].bytes()))
    roots = [entry.data for entry in tape.entries if entry.path == "mr"]
    if len(roots) != 1:
        fail("expected one miniroot on the support tape")
    root = filesystem.efs(roots[0])
    kernel = root.find("/unix.IP12")
    init_file = root.find("/etc/init")
    if kernel == None or init_file == None:
        fail("miniroot is missing unix.IP12 or /etc/init")

    # The miniroot mounts partition 1 and also uses it for swap starting at
    # block 30000. EFS data includes the omitted, proved-free filesystem tail.
    blank = block.view(block.blank(16 << 20))
    swap_partition = binary.concat([root.data, blank])
    image = filesystem.sgi_build([(1, 3, swap_partition), (0, 7, system if system != None else blank)], bootfile = "unix.IP12")
    disk = block.observe(block.overlay(block.device(image)))

    machine = emulator.ip12()
    machine.attach_disk(1, disk)
    devices = ["root=dks0d1s1", "swap=dks0d1s1"]
    machine.load_executable(
        kernel.data,
        args = ["dksc(0,1,1)unix.IP12"] + devices + options,
        env = ["console=d", "cpufreq=36", "dbaud=9600", "rbaud=9600"] + devices + options,
    )
    return machine, disk, root

def main(args):
    if len(args) != 1:
        fail("usage: irix_ip12.star IRIX_3.3_ARCHIVE.7z")
    machine, disk, root = prepare(open(args[0]))
    console = machine.serial()
    init = binary.irix_executable(root.find("/etc/init").data)
    text = [section for section in init.sections if section.name == ".text"][0]
    entry_bytes = text.data.bytes(init.entry - text.address, 32)

    # Stop after the first instruction so the user text page has translated.
    machine.break_at(init.entry + 4)
    stop = machine.run(30000000)
    transcript = console.read_available()
    banner = b"IRIX System V Release 3.3.2 IP12 Version 03141619"
    if transcript == None or banner not in transcript or b"PANIC:" in transcript:
        fail("IRIX serial boot output:", repr(transcript))
    if stop.kind != "breakpoint" or machine.read_effective(init.entry, len(entry_bytes)) != entry_bytes:
        fail("IRIX did not execute the original /etc/init entry:", stop.kind, hex(stop.pc))
    if disk.stats.read_bytes == 0:
        fail("IRIX did not read the miniroot disk")

    print("IRIX System V Release 3.3.2 IP12 Version 03141619")
    print("Executed /etc/init from the EFS miniroot after", stop.cycles, "CPU cycles")
    print("SCSI disk bytes read:", disk.stats.read_bytes)
    machine.close()
