"""Boots ReactOS and reports a symbolized kernel stop through a VMM debugger."""

load("@stdlib//qemu:profiles.star", "reactos")
load("@stdlib//debug:gdb.star", "read_u32")
load("@stdlib//windows:symbols.star", "add_pe", "locate", "state")

PARTITION_LBA = 2048

def _kernel(disk):
    partition = disk.slice(PARTITION_LBA * 512)
    return filesystem.fat(partition)["/ReactOS/system32/ntoskrnl.exe"]

def _kernel_base(gdb, pc):
    # A running kernel stop is inside ntoskrnl's contiguous image. Walking
    # mapped pages backward avoids probing unmapped kernel address ranges.
    address = pc & ~0xfff
    pages = 0
    while pages < 4096:
        if gdb.read_memory(address, 2) == b"MZ":
            pe_offset = read_u32(gdb, address + 0x3c)
            if pe_offset >= 0x40 and pe_offset <= 0x1000:
                if gdb.read_memory(address + pe_offset, 4) == b"PE\x00\x00":
                    return address
        address -= 0x1000
        pages += 1
    fail("ReactOS kernel image was not found near stopped PC " + str(hex(pc)))

def main(args):
    if len(args) < 1 or len(args) > 5:
        error("Usage: scripts/debug/reactos_kernel.star <disk.raw> [seconds] [display] [screenshot.png] [hold]")
    seconds = int(args[1]) if len(args) > 1 else 30
    display = args[2] if len(args) > 2 else "none"
    screenshot = args[3] if len(args) > 3 else ""
    hold = len(args) > 4 and args[4] == "hold"

    source = open(args[0])
    machine = vmm.machine(
        architecture = "i386",
        memory = 512 << 20,
        disks = [vmm.disk(source, bus = "ide", snapshot = True)],
        networks = [vmm.network("nat")],
        display = vmm.display("interactive" if display != "none" else "capturable"),
        start_paused = True,
        required_capabilities = ["disk.snapshot", "debugger.gdb", "screenshot"],
    )
    vm = vmm.start(machine, backend = reactos(display_frontend = display))
    gdb = debug.gdb(vm.debugger("gdb", create = True))
    getattr(gdb, "continue")()

    deadline = clock.monotonic() + seconds
    while vm.running and clock.monotonic() < deadline:
        ready = debug.select([vm], timeout = min(1, deadline - clock.monotonic()))
        if ready == vm:
            print("VM", vm.next_event(timeout = 0).kind)
    if not vm.running:
        fail("ReactOS VM exited before the debugger snapshot")

    gdb.interrupt()
    stop = gdb.wait(timeout = 10)
    symbols = state()
    add_pe(symbols, "ntoskrnl.exe", _kernel(source), base = _kernel_base(gdb, stop.pc))
    location = locate(symbols, stop.pc)
    if location == None or location.get("nearest") == None:
        fail("stopped address did not resolve inside ReactOS ntoskrnl.exe")
    nearest = location["nearest"]
    print("GDB", stop.kind, "ntoskrnl.exe!" + nearest["name"], "+", hex(location["rva"] - nearest["rva"]))

    if screenshot:
        write(screenshot, vm.screenshot())
    if hold:
        vm.wait()
    else:
        gdb.close()
        vm.stop()
        vm.wait(timeout = 10)
