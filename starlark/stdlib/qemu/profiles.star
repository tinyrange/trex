"""Typed QEMU profiles; exact device policy stays out of the VMM core."""

def dos(
        accelerator = "tcg",
        display_frontend = "auto",
        machine = "pc-i440fx-5.2",
        cpu = "486",
        display_device = "VGA",
        no_reboot = True,
        boot_order = "c",
        boot_menu = False,
        block_transport = "auto",
        overlay_limit = 256 << 20,
        debug_events = [],
        icount = "",
        no_acpi = False,
        rtc = ""):
    """Returns a minimal legacy PC profile for an installed DOS system."""
    if boot_order not in ["a", "c", "d"]:
        fail("DOS boot_order must be a, c, or d")
    options = [
        qemu.option("-nodefaults"),
        qemu.option("-cpu", cpu),
        qemu.option("-boot", ["order=" + boot_order] + (["menu=on"] if boot_menu else [])),
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
    if rtc:
        options.append(qemu.option("-rtc", "base=" + rtc))
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
        machine = "pc-i440fx-5.2",
        cpu = "pentium",
        network = True,
        no_reboot = True,
        block_transport = "auto"):
    """Returns a QEMU profile compatible with Windows NT 3.51 x86."""
    devices = [qemu.device("isa-cirrus-vga")]
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
        machine = "pc-i440fx-5.2",
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
        machine = "pc-i440fx-5.2",
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
        machine = "pc-i440fx-5.2",
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

def windows_arm64(
        accelerator = "hvf",
        display_frontend = "auto",
        cpu = "host",
        network = False,
        no_reboot = True,
        block_transport = "nbd",
        zoom_to_fit = True):
    """ARM64 UEFI machine with inbox NVMe storage and USB input policy.

    Attach the system disk with bus="nvme". HVF uses the host ARM CPU;
    emulated runs may select accelerator="tcg", cpu="max".
    """
    if network:
        error("windows_arm64 has no validated network device")
    return qemu.backend(
        machine = "virt",
        # Keep ITS enabled: QEMU 10.2.1 emits a malformed IORT without it,
        # and Windows 11 build 26100 loops while scanning that table.
        machine_properties = {"gic-version": 3, "its": True},
        accelerator = accelerator,
        firmware = "uefi",
        display_frontend = display_frontend,
        display_zoom_to_fit = zoom_to_fit and display_frontend in ["cocoa", "gtk"],
        block_transport = block_transport,
        devices = [
            qemu.device("ramfb"),
            qemu.device("qemu-xhci", id = "usb"),
            qemu.device("usb-kbd", bus = "usb.0"),
            qemu.device("usb-tablet", bus = "usb.0"),
        ],
        options = [
            qemu.option("-nodefaults"),
            qemu.option("-cpu", cpu),
            qemu.option("-no-shutdown"),
        ] + ([qemu.option("-no-reboot")] if no_reboot else []),
    )

def reactos(
        accelerator = "auto",
        display_frontend = "auto",
        machine = "pc-i440fx-5.2",
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
