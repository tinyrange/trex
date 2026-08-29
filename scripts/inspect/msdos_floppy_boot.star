"""Boots one floppy image directly from 7z media for native-media diagnosis."""

load("@stdlib//qemu:profiles.star", "dos")
load("@stdlib//vmm:automation.star", "wait_duration")

def main(args):
    if len(args) != 3:
        error("Usage: scripts/inspect/msdos_floppy_boot.star <media.7z> <image-basename> <screenshot.png>")
    sevenzip = archive.sevenzip(open(args[0]))
    selected = None
    for member_path in sevenzip.files:
        if path.base(member_path).lower() == args[1].lower():
            selected = sevenzip[member_path]
    if selected == None:
        fail("floppy image not found: " + args[1])
    machine = vmm.machine(
        architecture = "i386",
        memory = 16 << 20,
        disks = [vmm.disk(selected, name = "source-floppy", bus = "floppy", media = "floppy", unit = 0, snapshot = True)],
        display = vmm.display("capturable"),
        required_capabilities = ["disk.snapshot", "screenshot"],
    )
    vm = vmm.start(machine, dos())
    wait_duration(vm, 5)
    write(args[2], vm.screenshot())
    print("source floppy boot screenshot", args[2])
    vm.stop()
    vm.wait(timeout = 10)
