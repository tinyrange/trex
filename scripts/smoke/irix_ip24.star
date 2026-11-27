"""Boot archived IRIX 6.5.22 on the native SGI Indy and query its guest release."""

def _partition(volume, index):
    matches = [p.data for p in volume.partitions if p.index == index]
    if len(matches) != 1:
        fail("SGI volume has no partition", index)
    return matches[0]

def _installed(source):
    image = filesystem.chd(source)
    root = _partition(filesystem.sgi(image), 0)
    kernel = filesystem.xfs_lookup(root, "/unix")
    if kernel == None or kernel.entry_type != "file":
        fail("Missing /unix in the installed XFS root")
    init = filesystem.xfs_lookup(root, "/sbin/init")
    if init == None or init.entry_type != "file":
        fail("Missing /sbin/init in the installed XFS root")
    return image, kernel.data, "dksc(0,1,0)"

def _miniroot(source):
    members = [entry for entry in archive.sevenzip(source).entries if entry.entry_type == "file" and entry.path.endswith(".iso")]
    if len(members) != 1:
        fail("Expected the IRIX 6.5.22 Overlay 1 CD")
    # Decode the solid archive sequentially before seeking in the filesystem.
    volume = filesystem.sgi(binary.view(members[0].bytes()))
    distribution = filesystem.efs(_partition(volume, 7))
    kernel = distribution.find("/dist/miniroot/unix.IP22")
    files = [item.data for item in volume.files if item.name == "mr"]
    if kernel == None or len(files) != 1:
        fail("Missing the IP22 kernel or XFS miniroot")
    if filesystem.xfs_lookup(files[0], "/sbin/init") == None:
        fail("Missing /sbin/init in the XFS miniroot")
    blank = block.view(block.blank(64 << 20))
    # Put the original XFS on partition 1, leaving room for paging after it.
    swap = binary.concat([files[0], blank])
    image = filesystem.sgi_build([(0, 10, blank), (1, 3, swap)], bootfile = "unix")
    return image, kernel.data, "dksc(0,1,1)"

def prepare(source, mode, rom = None, newport = False, single_user = True):
    """Attach a private writable overlay and start the original kernel."""
    if mode == "system":
        image, kernel, partition = _installed(source)
        return prepare_disk(image, kernel, partition, rom = rom, newport = newport, single_user = single_user)
    elif mode == "miniroot":
        image, kernel, partition = _miniroot(source)
        return prepare_disk(image, kernel, partition, rom = rom, newport = newport, single_user = False, load_options = "mr")
    else:
        fail("Expected system or miniroot")

def prepare_disk(image, kernel, partition, rom = None, newport = False, single_user = True, load_options = "auto", kernel_options = []):
    """Start an original IRIX kernel with a prepared SGI disk."""
    options = (["initstate=s"] if single_user else []) + kernel_options
    # Guest swap and application caches can dirty more than the generic
    # overlay limit. Chunks still allocate only when written.
    disk = block.observe(block.overlay(block.device(image), max_dirty_bytes = image.size))
    machine = emulator.ip24(rom = rom, newport = newport) if rom != None else emulator.ip24(newport = newport)
    machine.attach_disk(1, disk)
    args = [partition + "unix", "OSLoadOptions=" + load_options] + options
    env = [
        "console=d", "dbaud=9600", "rbaud=9600", "cpufreq=150",
        "scsihostid=7", "eaddr=08:00:69:00:00:01",
        "SystemPartition=dksc(0,1,8)", "OSLoadPartition=" + partition,
        "OSLoadFilename=unix", "OSLoadOptions=" + load_options,
    ] + options
    if newport:
        env.append("monitor=h")
    machine.load_executable(kernel, args = args, env = env)
    return machine, disk

def main(args):
    if len(args) not in [2, 3]:
        fail("usage: irix_ip24.star system|miniroot IRIX_6.5.22_MEDIA [INDY_PROM]")
    mode = args[0]
    rom = open(args[2]) if len(args) == 3 else None
    machine, disk = prepare(open(args[1]), mode, rom)
    release = "6.5.22f" if mode == "system" else "6.5.22m"
    version = "6.5 " + release + " 10070055 IP22"
    console = machine.serial()
    transcript = ""
    selected_shell, selected_term, queried = False, False, False
    for _ in range(180):
        stop = machine.run(10000000)
        data = console.read_available()
        if data:
            transcript = (transcript + str(data))[-16384:]
        if stop.kind != "budget" or "PANIC:" in transcript:
            fault = machine.registers().last_fault
            fail("IRIX boot stopped", stop.kind, hex(stop.pc), stop.service, hex(fault.pc), repr(transcript[-1600:]))
        if mode == "miniroot" and not selected_shell and "Make new file system on /dev/dsk/realroot [yes/no/sh/help]:" in transcript:
            console.write(b"sh\r")
            selected_shell = True
        if mode == "system" and not selected_shell and "(or give root password for Single User Mode): " in transcript:
            console.write(b"\r")
            selected_shell = True
        if mode == "system" and not selected_term and transcript.endswith("TERM = (iris-tp) "):
            console.write(b"vt100\r")
            selected_term = True
        if not queried and transcript.endswith("# "):
            console.write(b"uname -aR\r" if mode == "miniroot" else b"uname -aR; id\r")
            queried = True
        if queried and version in transcript and (mode == "miniroot" or "uid=0(root)" in transcript):
            if disk.stats.read_bytes == 0:
                fail("IRIX did not read its SCSI disk")
            print("Booted IRIX " + release + " on the emulated Indy")
            for line in transcript.splitlines():
                if version in line or "uid=0(root)" in line:
                    print(line.strip())
            print("SCSI disk bytes read", disk.stats.read_bytes)
            machine.close()
            return
    fail("IRIX guest command did not complete", mode, repr(transcript[-1600:]))
