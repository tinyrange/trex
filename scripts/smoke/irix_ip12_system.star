"""Boot the IRIX 3.3.2 distribution userland from an in-memory EFS disk."""

_TAPES = [
    ("4d1-3.3-eoe-tape1", "eoe1", ["unix"]),
    ("4d1-3.3-eoe-tape2", "eoe2", ["NeWS", "demos", "envm", "gltools", "moregltools", "editors", "tcp", "usrenv", "optfonts"]),
    ("4D35-support-1.0-tape1", "4D35", ["unix", "moregltools"]),
]

_TYPES = {
    "directory": 0o040000,
    "file": 0o100000,
    "symlink": 0o120000,
    "character_device": 0o020000,
    "block_device": 0o060000,
    "fifo": 0o010000,
}

# These are the known actions and overlaps in the 3.3 distribution. This
# recipe applies the stock device numbers and first matches from the media.
_EXPECTED_ISSUES = {
    "descriptor_extension": ["eoe1.sw.unix"],
    "destination_conflict": ["/usr/NeWS/lib/NeWS/cursor.ps", "/usr/NeWS/lib/NeWS/icon.ps", "/usr/lib/winattr.o"],
    "install_action": [
        "/dev/MAKEDEV", "/etc/init.d/network", "/stand", "/stand/ide", "/stand/sash",
        "/usr/NeWS/bin", "/usr/NeWS/fonts", "/usr/lib/filetype/Makefile",
        "/usr/lib/filetype/install", "/usr/lib/filetype/system/mailbox.ftr", "/usr/lib/filetype/tagscript",
    ],
}

def _ids(file):
    ids = {}
    for line in file.read().splitlines():
        fields = line.split(":")
        if len(fields) >= 3 and fields[2].isdigit():
            ids[fields[0]] = int(fields[2])
    return ids

def _system_files(source):
    tapes = {name: {} for name, _, _ in _TAPES}
    for member in archive.sevenzip(source).entries:
        if type(member) != "file":
            continue
        parts = member.path.rsplit("/", 2)
        if len(parts) >= 2 and parts[-2] in tapes:
            tapes[parts[-2]][parts[-1]] = member

    standalone = archive.irix_tape(binary.view(tapes[_TAPES[-1][0]]["sa"].bytes()))
    roots = [entry.data for entry in standalone.entries if entry.path == "mr"]
    if len(roots) != 1:
        fail("expected the original IP12 miniroot")
    miniroot = filesystem.efs(roots[0])
    kernel = miniroot.find("/unix.IP12").data

    operations = {}
    for tape_name, product, subsystems in _TAPES:
        tape = tapes[tape_name]
        plan = archive.irix_plan(
            [tape[product]],
            [product + ".sw." + subsystem for subsystem in subsystems],
            machine = {"CPUBOARD": "IP12", "GFXBOARD": "ECLIPSE", "SUBGR": "", "MACHINE": "4D35"},
            indexes = {product: tape[product + ".idb"]},
            images = {product + ".sw": binary.view(tape[product + ".sw"].bytes())},
        )
        for issue in plan.issues:
            if issue.subject not in _EXPECTED_ISSUES.get(issue.kind, []):
                fail("unresolved distribution item", issue.kind, issue.subject, issue.detail)
        for op in plan.operations:
            operations[op.path] = op

    uid = _ids(operations["/etc/passwd"].data)
    gid = _ids(operations["/etc/group"].data)
    rows = {}
    # Preserve the miniroot's stock console and null device inodes.
    for entry in miniroot.entries:
        if entry.path.startswith("/dev/") and entry.entry_type in ["character_device", "block_device"]:
            path = entry.path[1:]
            rows[path] = {
                "path": path, "mode": entry.mode, "uid": entry.uid, "gid": entry.gid,
                "mtime": entry.modified, "major": entry.major, "minor": entry.minor,
            }

    links = []
    for path, op in operations.items():
        path = path[1:] or "."
        if op.kind == "hardlink":
            links.append((path, op.target[1:]))
            continue
        row = {"path": path, "mode": (op.mode & 0o7777) | _TYPES[op.kind], "uid": uid[op.owner], "gid": gid[op.group]}
        if op.data != None:
            row["data"] = op.data
        elif op.kind == "symlink":
            row["target"] = op.target
        elif op.kind in ["character_device", "block_device"]:
            row.update(major = op.major, minor = op.minor)
        rows[path] = row

    # Device entries normally created by the distribution MAKEDEV script.
    for name, major, minor, perm in [
        ("mem", 1, 0, 0o640), ("kmem", 1, 1, 0o640),
        ("ttyd1", 0, 1, 0o622), ("keybd", 0, 30, 0o666), ("mouse", 0, 31, 0o600),
        ("tty", 2, 0, 0o666), ("queue", 9, 0, 0o666), ("zero", 37, 0, 0o666),
    ]:
        path = "dev/" + name
        rows[path] = {"path": path, "mode": 0o020000 | perm, "major": major, "minor": minor, "gid": gid["sys"]}
    for directory, major in [("gro", 12), ("grin", 13)]:
        for minor in range(64):
            name = "admin" if minor == 0 else str(minor)
            path = "dev/" + directory + "/" + name
            rows[path] = {"path": path, "mode": 0o020666, "major": major, "minor": minor, "gid": gid["sys"]}
    rows["dev/ptc"] = {"path": "dev/ptc", "mode": 0o020666, "major": 10, "minor": 14, "gid": gid["sys"]}
    for minor in range(1, 64):
        path = "dev/ttyq%d" % minor
        rows[path] = {"path": path, "mode": 0o020666, "major": 15, "minor": minor, "gid": gid["sys"]}
    for partition in range(2):
        path = "dev/dsk/dks0d1s%d" % partition
        rows[path] = {"path": path, "mode": 0o060600, "major": 22, "minor": 32 + partition, "gid": gid["sys"]}
        alias = "dev/swap" if partition == 0 else "dev/root"
        rows[alias] = dict(rows[path], path = alias)
        raw = "dev/rdsk/dks0d1s%d" % partition
        rows[raw] = dict(rows[path], path = raw, mode = 0o020600)
    for dest, target in links:
        row = dict(rows[target])
        row.pop("data", None)
        row.update(path = dest, target = target, hardlink = True)
        rows[dest] = row
    rows["tmp"] = {"path": "tmp", "mode": 0o041777}
    rows["unix"] = {"path": "unix", "mode": 0o100755, "data": kernel}
    return filesystem.efs_build(rows.values(), 192 << 20, label = "root", modified = 670608000), kernel

def prepare(source):
    """Start the stock support kernel with the installed userland on SCSI."""
    root, kernel = _system_files(source)
    blank = block.view(block.blank(64 << 20))
    # The stock support kernel uses partition 1 as root. Give its paging
    # area a separate partition, with space above its 30,000-block offset.
    image = filesystem.sgi_build([(0, 3, blank), (1, 7, root)], root = 1, swap = 0, bootfile = "unix")
    disk = block.observe(block.overlay(block.device(image), max_dirty_bytes = 128 << 20))
    machine = emulator.ip12()
    machine.attach_disk(1, disk)
    devices = ["root=dks0d1s1", "swap=dks0d1s0"]
    machine.load_executable(
        kernel,
        args = ["dksc(0,1,1)unix"] + devices,
        env = ["console=d", "dbaud=9600", "rbaud=9600", "cpufreq=36"] + devices,
    )
    return machine, disk, filesystem.efs(root)

def main(args):
    if len(args) != 1:
        fail("usage: irix_ip12_system.star IRIX_3.3_ARCHIVE.7z")
    machine, disk, root = prepare(open(args[0]))
    for path in ["/etc/init", "/etc/gl/grcond", "/usr/sbin/workspace", "/usr/sbin/clock", "/usr/sbin/ical"]:
        if root.find(path) == None:
            fail("missing distribution file", path)

    console = machine.serial()
    replies = {
        "Automatically reconfigure the operating system": b"n\r",
        "IRIS console login:": b"root\r",
        "TERM = (vt100)": b"\r",
        "# ": b"uname -a; id\r",
    }
    transcript = ""
    for _ in range(64):
        stop = machine.run(9000000)
        data = console.read_available()
        if data != None:
            transcript += str(data)
        if stop.kind != "budget" or "PANIC:" in transcript:
            fail("IRIX boot stopped", stop.kind, hex(stop.pc), repr(transcript[-1200:]))
        for prompt in list(replies):
            if prompt in transcript:
                console.write(replies.pop(prompt))
        if "IRIS IRIS 3.3.2 03141619 IP12" in transcript and "uid=0(root) gid=0(sys)" in transcript:
            if "root on dev 0x1621, swap on dev 0x1620" not in transcript or disk.stats.read_bytes == 0:
                fail("IRIX did not use the constructed disk geometry")
            print("Booted and logged into IRIX 3.3.2 on IP12")
            print("IRIS IRIS 3.3.2 03141619 IP12")
            print("uid=0(root) gid=0(sys)")
            machine.close()
            return
    fail("IRIX interactive login did not complete", repr(transcript[-1200:]))
