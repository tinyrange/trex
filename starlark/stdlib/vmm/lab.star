"""Small helpers for focused VM work in a Starlark REPL.

The values returned here are ordinary block devices, machines, VMs, and files.
This module deliberately does not track experiment history or hide lifecycle
operations from the caller.
"""

load(":automation.star", "release_modifiers", "wait_duration")

def working_copy(disk, max_dirty_bytes = 1 << 30, trace_operations = 0):
    """Returns a bounded in-memory copy-on-write block device."""
    if max_dirty_bytes < 1:
        fail("working-copy dirty-byte limit must be positive")
    if trace_operations < 0:
        fail("working-copy trace-operation limit must be non-negative")
    source = disk if type(disk) == "block_device" else block.device(disk)
    return block.overlay(
        source,
        max_dirty_bytes = max_dirty_bytes,
        trace_operations = trace_operations,
    )

def start(
        disk,
        backend,
        architecture = "i386",
        memory = 1 << 30,
        cpus = 1,
        bus = "ide",
        unit = 0,
        snapshot = True,
        display = "capturable",
        start_paused = False,
        channels = [],
        required_capabilities = ["input.key", "input.text", "screenshot"]):
    """Starts one explicit single-disk machine for focused investigation."""
    if memory < 1 or cpus < 1:
        fail("VM memory and CPU count must be positive")
    machine = vmm.machine(
        architecture = architecture,
        memory = memory,
        cpus = cpus,
        disks = [vmm.disk(disk, bus = bus, unit = unit, snapshot = snapshot)],
        display = vmm.display(display),
        channels = channels,
        start_paused = start_paused,
        required_capabilities = required_capabilities,
    )
    return vmm.start(machine, backend)

def capture_after(vm, seconds):
    """Drains VM events for a bounded duration and returns an in-memory PNG."""
    wait_duration(vm, seconds)
    return vm.screenshot()

def stop(vm, stop_timeout = 10, wait_timeout = 120):
    """Stops a VM if needed and returns its final backend result."""
    if stop_timeout <= 0 or wait_timeout <= 0:
        fail("VM stop and wait timeouts must be positive")
    if vm.running:
        release_modifiers(vm)
    if vm.status != "stopped":
        vm.stop(timeout = stop_timeout)
    result = vm.wait(timeout = wait_timeout)
    vm.close()
    return result
