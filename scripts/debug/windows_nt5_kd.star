"""Boots an NT5 disk and reports native serial KD events and module locations."""

load("@stdlib//qemu:profiles.star", "nt5")
load("@stdlib//windows:symbols.star", "add_pdb", "locate", "state", "update")

def _boot_partition(disk):
    mbr = filesystem.mbr(disk)
    for partition in mbr.partitions:
        if partition.sectors:
            return partition
    fail("disk has no populated MBR partition")

def _validate_debug_boot(disk):
    partition = _boot_partition(disk)
    partition_file = disk.slice(partition["offset"])
    if partition["type"] == 0x07:
        volume = filesystem.ntfs(partition_file)
    elif partition["type"] in [0x01, 0x04, 0x06, 0x0b, 0x0c, 0x0e]:
        volume = filesystem.fat(partition_file)
    else:
        fail("unsupported NT5 boot partition type " + hex(partition["type"]))
    boot_ini = binary.text(volume["/boot.ini"], encoding = "ascii").lower()
    configured = False
    for line in boot_ini.split("\n"):
        line = line.strip()
        if line and not line.startswith("[") and "=" in line and "/debug" in line:
            configured = True
            if "/debugport=com1" not in line:
                fail("BOOT.INI enables KD but does not select COM1")
            break
    if not configured:
        fail("BOOT.INI does not enable kernel debugging; build the image with the debug option")

def main(args):
    if len(args) < 1 or len(args) > 6:
        error("Usage: scripts/debug/windows_nt5_kd.star <disk.raw> [seconds] [display] [module:pdb] [screenshot.png] [hold]")
    seconds = int(args[1]) if len(args) > 1 else 30
    display = args[2] if len(args) > 2 else "none"
    symbol_spec = args[3] if len(args) > 3 else ""
    screenshot = args[4] if len(args) > 4 else ""
    hold = len(args) > 5 and args[5] == "hold"
    disk = open(args[0])
    _validate_debug_boot(disk)

    machine = vmm.machine(
        architecture = "i386",
        memory = 512 << 20,
        disks = [vmm.disk(disk, bus = "ide", snapshot = True)],
        networks = [vmm.network("nat")],
        display = vmm.display("interactive" if display != "none" else "capturable"),
        channels = [vmm.channel("serial", "kd")],
        start_paused = True,
        required_capabilities = ["disk.snapshot", "channel.serial", "screenshot"],
    )
    vm = vmm.start(machine, backend = nt5(display_frontend = display, audio = False))
    kd = windows.kd(vm.channel("kd"), architecture = "i386")
    symbols = state()
    if symbol_spec:
        parts = symbol_spec.split(":", 1)
        if len(parts) != 2:
            fail("symbol input must be module:pdb-path")
        add_pdb(symbols, parts[0], windows.pdb(open(parts[1])))
    vm.resume()

    deadline = clock.monotonic() + seconds
    saw_packet = False
    while vm.running and clock.monotonic() < deadline:
        ready = debug.select([kd, vm], timeout = max(0, deadline - clock.monotonic()))
        if ready == None:
            break
        if ready == vm:
            print("VM", vm.next_event(timeout = 0).kind)
            continue
        event = kd.next_event(timeout = 0)
        saw_packet = True
        if event.kind == "control":
            continue
        if event.kind == "debug_io":
            print("KD debug", event.data)
            continue
        if event.kind == "exception":
            print("KD", event.kind, "code", hex(event.code), "parameters", event.parameters, "pc", hex(event.program_counter))
        else:
            print("KD", event.kind, event)
        update(symbols, event)
        if event.kind == "load_symbols":
            print("module", event.path, "at", hex(event.base), "size", hex(event.size))
        address = getattr(event, "program_counter", 0) if event.kind == "exception" else 0
        location = locate(symbols, address) if address else None
        if location != None and event.kind == "exception":
            nearest = location.get("nearest")
            if nearest == None:
                print("location", location["module"]["name"], "+", hex(location["rva"]))
            else:
                print("location", location["module"]["name"], nearest.name, "+", hex(location["rva"] - nearest.rva))
        if event.kind in ["exception", "load_symbols", "command_string", "state"]:
            if event.kind == "exception":
                break
            getattr(kd, "continue")()
    if not saw_packet:
        fail("NT5 guest did not produce a KD packet before the deadline")
    if screenshot:
        write(screenshot, vm.screenshot())
    if hold:
        vm.wait()
    else:
        kd.close()
        vm.stop()
        vm.wait(timeout = 10)
