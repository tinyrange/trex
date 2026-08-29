"""Boots a Windows XP disk with native GDB, input, and screenshot support."""

load("@stdlib//debug:trace.star", "delayed_snapshot")
load("@stdlib//qemu:profiles.star", "nt5")

def main(args):
    if len(args) < 1 or len(args) > 6:
        error("Usage: scripts/debug/windows_xp_boot.star <disk.raw> [snapshot-delay] [display] [breakpoint] [screenshot.png] [continue]")
    delay = int(args[1]) if len(args) > 1 else 10
    display = args[2] if len(args) > 2 else "none"
    breakpoint = int(args[3], 0) if len(args) > 3 and args[3] else 0
    screenshot = args[4] if len(args) > 4 else ""
    continue_after = len(args) > 5 and args[5] == "continue"

    machine = vmm.machine(
        architecture = "i386",
        memory = 512 << 20,
        disks = [vmm.disk(open(args[0]), bus = "ide", snapshot = True)],
        networks = [vmm.network("nat")],
        display = vmm.display("interactive" if display != "none" else "capturable"),
        start_paused = True,
        required_capabilities = ["disk.snapshot", "debugger.gdb", "screenshot"],
    )
    vm = vmm.start(machine, backend = nt5(display_frontend = display, audio = False))
    gdb = debug.gdb(vm.debugger("gdb"))
    point = gdb.breakpoint(breakpoint) if breakpoint else None
    getattr(gdb, "continue")()
    if point != None:
        stop = gdb.wait(timeout = max(30, delay))
        point.remove()
        print("GDB breakpoint", stop)
        if continue_after:
            getattr(gdb, "continue")()
    else:
        print("GDB snapshot", delayed_snapshot(gdb, delay, continue_after = continue_after))
    if screenshot:
        write(screenshot, vm.screenshot())
    if continue_after:
        vm.powerdown()
        vm.wait(timeout = 30)
    else:
        vm.stop()
        vm.wait(timeout = 10)
