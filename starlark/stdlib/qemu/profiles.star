"""Typed QEMU profiles; exact device policy stays out of the VMM core."""

def dos(
        accelerator = "tcg",
        display_frontend = "auto",
        machine = "pc-i440fx-5.1",
        cpu = "486",
        display_device = "VGA",
        no_reboot = True,
        boot_order = "c",
        block_transport = "auto",
        overlay_limit = 256 << 20,
        debug_events = [],
        icount = "",
        no_acpi = False):
    """Returns a minimal legacy PC profile for an installed DOS system."""
    if boot_order not in ["a", "c", "d"]:
        fail("DOS boot_order must be a, c, or d")
    options = [
        qemu.option("-nodefaults"),
        qemu.option("-cpu", cpu),
        qemu.option("-boot", "order=" + boot_order),
        qemu.option("-no-shutdown"),
        qemu.option("-parallel", "none"),
    ]
    if no_reboot:
        options.append(qemu.option("-no-reboot"))
    if debug_events:
        options.append(qemu.option("-d", debug_events))
    if icount:
        options.append(qemu.option("-icount", icount))
    if no_acpi:
        options.append(qemu.option("-no-acpi"))
    return qemu.backend(
        machine = machine,
        accelerator = accelerator,
        display_frontend = display_frontend,
        block_transport = block_transport,
        overlay_limit = overlay_limit,
        devices = [qemu.device(display_device)],
        options = options,
    )

def nt351(
        accelerator = "auto",
        display_frontend = "auto",
        machine = "pc-i440fx-5.1",
        network = True,
        no_reboot = True,
        block_transport = "auto"):
    """Returns a QEMU profile compatible with Windows NT 3.51 x86."""
    devices = [qemu.device("isa-cirrus-vga")]
    netdevs = []
    options = [
        qemu.option("-nodefaults"),
        qemu.option("-cpu", "pentium"),
        qemu.option("-no-shutdown"),
        qemu.option("-parallel", "none"),
    ]
    if no_reboot:
        options.append(qemu.option("-no-reboot"))
    if network:
        netdevs.append(qemu.netdev("user", id = "net0"))
        devices.append(qemu.device("pcnet", netdev = "net0"))
    return qemu.backend(
        machine = machine,
        accelerator = accelerator,
        display_frontend = display_frontend,
        block_transport = block_transport,
        devices = devices,
        netdevs = netdevs,
        options = options,
    )

def nt4(
        accelerator = "tcg",
        display_frontend = "auto",
        machine = "pc-i440fx-5.1",
        network = True,
        no_reboot = True,
        block_transport = "auto"):
    """Returns a QEMU profile compatible with Windows NT 4.0 x86.

    Current KVM exposes a legacy-CPU execution path on which NT4 can stall
    before Winlogon initializes, even with the Pentium CPUID model. TCG
    preserves the execution semantics NT4 expects. Callers may still override
    this when their hypervisor has independently verified NT4 compatibility.
    """
    devices = [qemu.device("cirrus-vga")]
    netdevs = []
    options = [
        qemu.option("-nodefaults"),
        qemu.option("-cpu", "pentium"),
        qemu.option("-no-shutdown"),
        qemu.option("-parallel", "none"),
    ]
    if no_reboot:
        options.append(qemu.option("-no-reboot"))
    if network:
        netdevs.append(qemu.netdev("user", id = "net0"))
        devices.append(qemu.device("pcnet", netdev = "net0"))
    return qemu.backend(
        machine = machine,
        accelerator = accelerator,
        display_frontend = display_frontend,
        block_transport = block_transport,
        devices = devices,
        netdevs = netdevs,
        options = options,
    )

def nt5(
        accelerator = "auto",
        display_frontend = "auto",
        machine = "pc-i440fx-5.1",
        audio = True,
        network = True,
        no_reboot = True,
        block_transport = "auto"):
    """Returns the QEMU hardware profile used by NT5 image recipes."""
    devices = [qemu.device("cirrus-vga"), qemu.device("ide-cd")]
    netdevs = []
    audiodevs = []
    options = [
        qemu.option("-nodefaults"),
        qemu.option("-no-shutdown"),
        # The NT5 image recipe only installs devices represented by this
        # profile. Parallel channels are not part of the portable VMM model.
        qemu.option("-parallel", "none"),
    ]
    if no_reboot:
        options.append(qemu.option("-no-reboot"))
    if network:
        netdevs.append(qemu.netdev("user", id = "net0"))
        devices.append(qemu.device("pcnet", netdev = "net0"))
    if audio:
        audiodevs.append(qemu.audiodev("pipewire", id = "audio0"))
        devices.append(qemu.device("AC97", audiodev = "audio0"))
    return qemu.backend(
        machine = machine,
        accelerator = accelerator,
        display_frontend = display_frontend,
        block_transport = block_transport,
        devices = devices,
        netdevs = netdevs,
        audiodevs = audiodevs,
        options = options,
    )

def nt6(
        accelerator = "auto",
        display_frontend = "auto",
        machine = "pc-i440fx-5.1",
        network = True,
        no_reboot = True,
        block_transport = "auto"):
    """Returns the QEMU hardware profile used by 32-bit NT6 image recipes."""
    devices = [qemu.device("cirrus-vga"), qemu.device("ide-cd")]
    netdevs = []
    options = [
        qemu.option("-nodefaults"),
        qemu.option("-no-shutdown"),
        qemu.option("-parallel", "none"),
    ]
    if no_reboot:
        options.append(qemu.option("-no-reboot"))
    if network:
        netdevs.append(qemu.netdev("user", id = "net0"))
        devices.append(qemu.device("e1000", netdev = "net0"))
    return qemu.backend(
        machine = machine,
        accelerator = accelerator,
        display_frontend = display_frontend,
        block_transport = block_transport,
        devices = devices,
        netdevs = netdevs,
        options = options,
    )

def modern_windows(
        accelerator = "auto",
        display_frontend = "auto",
        machine = "pc-q35-9.2",
        cpu = "max",
        network = False,
        no_reboot = True,
        block_transport = "auto"):
    """Returns a UEFI/Q35 profile with a contemporary x86-64 CPU baseline."""
    devices = [qemu.device("VGA")]
    netdevs = []
    options = [
        qemu.option("-nodefaults"),
        qemu.option("-cpu", cpu),
        qemu.option("-no-shutdown"),
        qemu.option("-parallel", "none"),
    ]
    if no_reboot:
        options.append(qemu.option("-no-reboot"))
    if network:
        netdevs.append(qemu.netdev("user", id = "net0"))
        devices.append(qemu.device("e1000e", netdev = "net0"))
    return qemu.backend(
        machine = machine,
        accelerator = accelerator,
        display_frontend = display_frontend,
        block_transport = block_transport,
        firmware = "uefi",
        devices = devices,
        netdevs = netdevs,
        options = options,
    )

def reactos(
        accelerator = "auto",
        display_frontend = "auto",
        machine = "pc-i440fx-5.1",
        network = True,
        no_reboot = True,
        block_transport = "auto"):
    """Returns QEMU policy matching the devices in the ReactOS image recipe."""
    devices = [qemu.device("VGA")]
    netdevs = []
    if network:
        netdevs.append(qemu.netdev("user", id = "net0"))
        devices.append(qemu.device("e1000", netdev = "net0"))
    return qemu.backend(
        machine = machine,
        accelerator = accelerator,
        display_frontend = display_frontend,
        block_transport = block_transport,
        devices = devices,
        netdevs = netdevs,
        options = [qemu.option("-nodefaults"), qemu.option("-no-shutdown")] + ([qemu.option("-no-reboot")] if no_reboot else []),
    )
