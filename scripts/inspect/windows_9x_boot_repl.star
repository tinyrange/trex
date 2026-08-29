"""Boots a Windows 9x disk in a writable trex overlay for inspection."""

load("@stdlib//qemu:profiles.star", "dos")

def main(args):
    if len(args) not in [2, 3]:
        fail("usage: scripts/inspect/windows_9x_boot_repl.star DISK.raw OUTPUT.raw [CYLINDERS,HEADS,SECTORS]")
    disk = open(args[0])
    storage = block.overlay(block.device(disk), max_dirty_bytes = disk.size)
    system_disk = vmm.disk(storage, name = "windows9x-inspect", bus = "ide", unit = 0, snapshot = False)
    if len(args) == 3:
        geometry = [int(value) for value in args[2].split(",")]
        if len(geometry) != 3 or any([value <= 0 for value in geometry]):
            fail("CHS must contain three positive integers")
        system_disk = vmm.disk(storage, name = "windows9x-inspect", bus = "ide", unit = 0, chs = (geometry[0], geometry[1], geometry[2]), snapshot = False)
    machine = vmm.machine(
        architecture = "i386",
        memory = 64 << 20,
        disks = [system_disk],
        display = vmm.display("capturable"),
        required_capabilities = ["disk.snapshot", "input.key", "input.text", "screenshot"],
    )
    backend = dos(display_frontend = "none", cpu = "486", boot_order = "c", no_reboot = False)
    vm = vmm.start(machine, backend)
    print("vm, storage, machine, backend, and disk are available; end input to save the writable disk")
    repl()
    write(args[1], storage.snapshot())
    if vm.running:
        vm.stop()
    vm.wait(timeout = 10)
