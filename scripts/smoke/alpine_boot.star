"""Fresh Linux boots from native-built newc and ext4, with serial evidence.

Run: go run ./cmd/trex scripts/smoke/alpine_boot.star [initramfs|ext4|both] [tcg|kvm]
Needs QEMU on a Linux host and the pinned network APKs; no extracted host files.
Guest tools only exercise already constructed images, never build/install them.
"""

load("//scripts/images:alpine.star", "image", "packages")
load("@stdlib//block:devices.star", "cached_working_copy")

def _await(vm, serial, marker, timeout = 90):
    deadline = clock.monotonic() + timeout
    output = ""
    while marker not in output:
        remaining = deadline - clock.monotonic()
        if remaining <= 0 or debug.select([serial], timeout = remaining) == None:
            vm.close()
            fail("Alpine serial timeout: " + marker + "\n" + output[-12000:])
        chunk = serial.read_some(maximum = 16384, timeout = min(remaining, 5))
        if not chunk:
            result = vm.wait(timeout = 5)
            vm.close()
            fail("Alpine exited before " + marker + ": " + result.detail + "\n" + output[-12000:])
        output += binary.text(chunk)
        if len(output) > 256 << 10 or "Kernel panic" in output or "TREX_FAIL:" in output:
            vm.close()
            fail("Alpine boot failed or exceeded output bound\n" + output[-16000:])
    return output

def smoke(package_records, mode, accelerator = "tcg"):
    built = image(package_records, mode = mode)
    disk = cached_working_copy(built["rootfs"], dirty_bytes = 64 << 20)
    machine = vmm.machine(
        architecture = "x86_64", memory = 512 << 20,
        boot = vmm.linux_boot(built["kernel"]["file"], initramfs = built["initramfs"], command_line = "console=ttyS0,115200 rdinit=/init panic=-1"),
        channels = [vmm.channel("serial", name = "console")],
        disks = [vmm.disk(disk, bus = "virtio")],
    )
    backend = qemu.backend(
        accelerator = accelerator, block_transport = "nbd", display_frontend = "none",
        options = [qemu.option("-nodefaults"), qemu.option("-cpu", "max" if accelerator == "tcg" else "host"), qemu.option("-no-reboot")],
    )
    vm = vmm.start(machine, backend)
    serial = vm.channel("console")
    output = _await(vm, serial, "TREX_READY_" + mode)
    # The exact expected response is NOT in the command/terminal echo.
    serial.write("printf 'TREX_%s_%s\\n' SHELL " + mode + "; /bin/busybox sync; /bin/busybox poweroff -f\n")
    output += _await(vm, serial, "TREX_SHELL_" + mode, timeout = 15)
    result = vm.wait(timeout = 15)
    vm.close()
    if not result.clean or result.code != 0:
        fail("Alpine shutdown failed: " + result.detail)
    if mode == "ext4":
        changed = {e.path: e for e in filesystem.ext4(disk.commit()).entries}
        if changed["var/boot-proof"].data.read() != "guest-ext4-write\n":
            fail("native readback of guest-written ext4 failed")
        if "var/boot-proof" in filesystem.ext4(built["rootfs"]).files:
            fail("guest mutated immutable base image")
    print(output[-6000:])
    print("PASS Alpine boot:", mode, built["kernel"]["release"], "interactive shell; clean poweroff;" + (" native guest-write readback" if mode == "ext4" else " initramfs PID1"))
    return output

def main(args):
    mode = args[0] if args else "both"
    accelerator = args[1] if len(args) > 1 else "tcg"
    if len(args) > 2 or mode not in ["both", "initramfs", "ext4"] or accelerator not in ["tcg", "kvm"]:
        fail("Usage: alpine_boot.star [initramfs|ext4|both] [tcg|kvm]")
    records = packages()
    for selected in (["initramfs", "ext4"] if mode == "both" else [mode]):
        smoke(records, selected, accelerator = accelerator)
