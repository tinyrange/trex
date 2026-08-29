"""Boots a generated BIOS sector through the in-process NBD transport."""

def _serial_boot_disk():
    """Returns a 1 MiB sparse disk whose MBR prints a serial marker."""
    code = binary.decode(
        "fa31c08ed8fbb8e30031d2cd14be207cac84c07408b40131d2cd14ebf3f4ebfd" +
        "5452582d4e42442d4f4b0d0a00",
        encoding = "hex",
    )
    sector = binary.builder(capacity = 512)
    sector.append(code)
    sector.reserve(510 - sector.size)
    sector.append(b"\x55\xaa")
    return binary.extents(1 << 20, [(0, sector.file())])

def main(args):
    if args:
        error("Usage: scripts/debug/nbd_boot_smoke.star")
    profile = clock.profiler()
    boot_span = profile.span("build_and_boot")
    disk = _serial_boot_disk()
    working = block.overlay(block.device(disk), max_dirty_bytes = 1 << 20, chunk_size = 4096)
    profile.counter("generated_bytes", disk.size)
    machine = vmm.machine(
        architecture = "i386",
        memory = 64 << 20,
        disks = [vmm.disk(working, bus = "ide", unit = 0)],
        channels = [vmm.channel("serial", "boot", required = True)],
        display = vmm.display("none"),
    )
    backend = qemu.backend(
        machine = "pc",
        accelerator = "kvm",
        display_frontend = "none",
        options = [qemu.option("-no-reboot"), qemu.option("-no-shutdown")],
    )
    vm = vmm.start(machine, backend)
    serial = vm.channel("boot", timeout = 10)
    marker = b""
    deadline = clock.monotonic() + 10
    while b"TRX-NBD-OK" not in marker:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            fail("timed out waiting for generated boot sector")
        marker = bytes_concat([marker, serial.read_some(maximum = 128, timeout = remaining)])
    transport = qemu.extension(vm).block_stats()[0]
    vm.stop(timeout = 10)
    vm.wait(timeout = 10)
    boot_span.end()
    report = profile.report()
    print("serial", marker)
    print("coverage_ppm", report.coverage_ppm)
    print("source_read_bytes", report.runtime.source_read_bytes)
    print("streamed_bytes", report.runtime.streamed_bytes)
    print("nbd_read_bytes", report.runtime.nbd_read_bytes)
    print("transport_reads", transport.reads, "transport_read_bytes", transport.read_bytes)
    if b"TRX-NBD-OK" not in marker:
        fail("generated boot sector did not execute")
    if report.runtime.streamed_bytes != 0 or transport.read_bytes == 0 or report.runtime.nbd_read_bytes != transport.read_bytes:
        fail("boot did not remain on the direct NBD path")
