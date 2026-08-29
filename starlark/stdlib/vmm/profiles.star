"""Portable machine-profile helpers shared by VMM backends."""

def pc(
        architecture,
        memory,
        disk,
        cpus = 1,
        networks = [],
        display = None,
        channels = [],
        start_paused = False,
        required_capabilities = []):
    """Builds a portable PC request without selecting a VMM backend."""
    if display == None:
        display = vmm.display("none")
    return vmm.machine(
        architecture = architecture,
        memory = memory,
        cpus = cpus,
        disks = [disk],
        networks = networks,
        display = display,
        channels = channels,
        start_paused = start_paused,
        required_capabilities = required_capabilities,
    )
