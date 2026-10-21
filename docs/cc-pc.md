# CrumbleCracker PC backend

`cc.backend()` implements `vmm.Backend` in process on Linux/amd64 with KVM.
It runs a caller-supplied boot disk through the VMM block interface, using
BIOS by default or native Go UEFI with `cc.backend(uefi=True)`.
Guest image construction and operating-system setup belong to the caller.
Go constructs the BIOS data areas and supplies interrupt services through
small real-mode firmware entrypoints. Video calls exchange register values
through I/O packets, including when a guest interprets the BIOS ROM. No external firmware binary or process
is used.

UEFI requires `x86_64` and enables ACPI. Storage defaults to PCI IDE;
`vmm.disk(..., bus="nvme")` selects the shared NVMe controller instead. It reads the GPT and FAT
EFI System Partition through native parsers, loads `EFI/Boot/BootX64.efi`,
and executes the original AMD64 image. Its firmware services share the
portable `emulator/uefi` implementation and the selected device's disk overlay.
The graphics output protocol exposes a 1280×720 BGRX framebuffer with a
hardware device path. Guest page tables translate firmware-call arguments;
runtime address mapping updates the firmware tables and their checksums.
Usable low RAM remains available for Windows startup stubs; VGA and firmware
ranges are reserved. BIOS and direct-Darwin x86_64 machines accept 16 MiB–8 GiB RAM; i386 accepts up to 3 GiB and native x86_64 UEFI accepts up to 16 GiB. Low RAM ends at the PCI MMIO window (0xc0000000). Additional RAM is mapped above 4 GiB, with compact host backing. BIOS E820 and the Darwin/native UEFI maps describe both ranges; E801 reports only low RAM. Native memory inspection and DMA reject the PCI hole rather than aliasing it to RAM.
The `efi` inspection field contains the last 32 firmware calls and statuses.
Unsupported firmware services stop execution with their name and arguments.


### Native UEFI multicore

Use `vmm.machine(architecture="x86_64", cpus=4, ...)` with
`cc.backend(uefi=True, ...)` for four cores. The UEFI PC accepts one through
four CPUs; legacy BIOS, direct Darwin and ARM64 profiles retain their existing
single-CPU limits. The default remains one CPU.

Multicore CPUID describes one package, one hardware thread per core, and local
APIC IDs matching the ACPI MADT and AML processors. It adds sanitized cache and
extended topology enumeration without enabling XSAVE/AVX. Each CPU executes
concurrently through KVM, including architectural INIT/SIPI startup. A single
coordinator serializes device exits and polls timers independently of CPU0.
Pause, stop, inspection and capture join every CPU; close also joins storage
before releasing shared RAM. Machine-wide A20 changes run at an all-CPU stop.

`vm.extension("cc.v1").cpus()` returns a bounded list of per-CPU register
summaries (`id`, `rip`, `rsp`, `cr0`, `cr3`, `cr4`, `efer`) from one all-CPU stop.
Existing `state()` and virtual-address inspection use CPU0. Execution breakpoints
and instruction stepping are explicitly unavailable on multicore machines.

Windows 11 build 26300 has been verified from a fresh in-memory image through
the Trex REPL with four cores, 16 GiB RAM, USB input, per-core affinity workloads,
all-core pause/resume, and clean ACPI S5 shutdown. This does not change the
standalone desktop application's CPU default or establish a performance speedup.

Fixed-disk BIOS services include EDD probing, extended reads/writes, verification,
seek and drive parameters. Larger disks use translated BIOS CHS independently
of ATA's 16-head task-file geometry. Explicit caller-supplied CHS remains intact.
The single-CPU model exposes basic CPUID leaves through 3 with supported legacy
features, without SMT or XSAVE/AVX enumeration. CPUID policy uses the portable
accelerator interface rather than patching guest instructions. The vendor is
GenuineIntel, the signature is family 6/model 6/stepping 3, and the extended
brand is TinyRangeX Virtual CPU, independent of the accelerator host.
The `x86_64` target also exposes supported long-mode, SYSCALL, NX and
CMPXCHG16B, SSE3, SSSE3, SSE4.1, SSE4.2 and POPCNT features when supported
by the accelerator.

The PC defaults to one CPU and contains KVM PIC/PIT, a CMOS RTC with periodic IRQ8, one primary
ATA PIO disk, standard planar VGA and i8042 keyboard/mouse. The disk uses the
portable block interface; snapshot attachments use bounded memory overlays.
`cc.backend(overlay_limit=...)` sets the dirty-memory bound in bytes; the
default is 256 MiB. Larger Windows images can require a larger limit during
first logon. The limit reserves no memory until the guest writes.
The VGA aperture is unmapped RAM and generates MMIO exits. Win9x alias probes
may read past installed low RAM: the conventional gap below the PCI aperture
returns zero on reads and ignores writes, matching the QEMU control. Real RAM
and device apertures are not converted to this unassigned bus range; wrapping
MMIO accesses are rejected. Guest RAM, disk
and firmware are never transferred through temporary host files.
The E820 memory map omits the VGA device aperture while reserving ROM and
firmware memory. Advertising VGA as firmware-owned memory conflicts with
NT 3.51's video resource allocation.

RTC periodic interrupts raise IRQ8 without cancelling native execution.
Register C latches the interrupt until the guest acknowledges it. Native
execution slices allow progress through host split-lock mitigation delays;
repeated millisecond cancellation can otherwise starve NT10 x86 atomic
operations that cross cache-line boundaries.

An `x86_64` machine enables ACPI automatically; `cc.backend(acpi=True)` also
enables it for an i386 machine. Go builds the RSDP, RSDT/XSDT, FADT, FACS, MADT
and DSDT in reserved guest firmware memory. Fixed devices are children of the
PCI root so its interrupt-routing interface is initialized before their
resources are assigned. The root supplies PCI configuration mechanism 1.
The ACPI fixed registers provide a 24-bit
3.579545 MHz timer, SCI events, a power button and S5 shutdown.

`cc.backend(hpet=True)` adds an ACPI-described HPET at `0xfed00000`. Its
100 MHz main counter and three 64-bit comparators support one-shot, periodic,
32-bit wrap, and edge or level interrupts through IOAPIC inputs 20–23. Legacy
replacement and FSB delivery are not advertised. HPET and RTC deadlines share
asynchronous IRQ delivery, with register state serialized before guest access.
`cc.v1.state().hpet` reports the counter, configuration and comparators.

`cc.backend(pci_ide=True, ide_dma=False)` retains the PCI controller and
selects a PIO-only disk. This allows a guest profile to choose the transfer
mode independently of its bus topology.

`cc.backend(pci_ide=True)` enables ACPI and a generic PCI IDE controller at
00:01.0 (1234:cc01). It retains compatibility-mode ports and IRQ14/15 and
provides the standard 16-byte bus-master register block in BAR4. PIO and
multiword DMA use the portable block device. DMA validates guest physical
region descriptors before transferring, including RAM bounds, 64 KiB windows,
direction, and the PCI bus-master enable bit. The ATA disk advertises only the
implemented transfer modes. The ACPI namespace omits the separate legacy IDE
device when PCI owns the controller.
Inspection exposes the bus-master registers and the last eight ATA failures,
including the command, task file, and DMA validation or block-device error.

```starlark
vm = vmm.start(vmm.machine(
    architecture = "i386",
    memory = 64 << 20,
    disks = [vmm.disk(disk, bus = "ide", unit = 0,
                      chs = (520, 16, 63), snapshot = True)],
    display = vmm.display("capturable"),
    start_paused = True,
), cc.backend())
vm.resume()
# Use @stdlib//vmm:automation.star wait_duration for bounded event waits.
vm.pause()
frame = vm.screenshot()
vm.resume()
vm.chord(["control", "alt", "delete"])
vm.stop()
result = vm.wait(timeout = 2)
vm.close()
```

TinyRangeX supplies the NT 3.1 image recipes, guest drivers and integration
smokes in [tinyrangex](https://github.com/tinyrange/tinyrangex). Those are
consumer-level validation of this backend, not image-building features of trex.

## DOS and Win16 firmware

Legacy POST enables IRQ1 and installs a firmware keyboard handler. Translated
set-1 key events feed the standard BDA ring buffer. INT16 supports blocking
reads, non-consuming status queries, shift-state queries and buffered key
insertion. Blocking reads sleep in guest ROM with interrupts enabled; they do
not terminate the VM or block the host input loop. Protected-mode guest drivers
can replace IRQ1 and continue using the i8042 directly. The firmware translation
is a US-layout subset, not a complete international/enhanced keyboard BIOS.

Text mode starts with readable 8×16 ASCII cells padded from Go's BSD-licensed
basicfont (derived from public-domain X11 misc-fixed). Guest font uploads remain
authoritative; the screenshot renderer does not replace uploaded glyphs. Full
CP437 coverage is not supplied. CGA mode 06h uses 640×200 monochrome pixels in
the two alternating 8 KiB banks at B8000. BIOS EGA palette-table services and
six-bit EGA color decoding are implemented, including the 64-entry DAC colors.
VGA BIOS DAC services 1010/1012/1015/1017 program or read single entries and
RGB blocks through paged guest buffers. Screenshot DAC expansion matches the
QEMU comparison surface; the Windows 95 smoke checks exact UI color samples,
not only glyph silhouettes.

System-control port 61h exposes clock-driven AT refresh transitions on bit 4.
Its writable low bits are independent of refresh status. On Linux/amd64, the
8042 output-port and fast-A20 controls drive actual native RAM aliases with
physical address bit 20 cleared while disabled. Enabling the gate restores the
original high-memory backing without copying or overwriting it. VGA holes stay
unmapped and their MMIO aliases are decoded by the PC layer. BIOS INT15 A20
control/status services use the same gate. Unowned software-interrupt vectors use inert `IRET` entries, not host services
or null targets. CPU exceptions and implemented BIOS vectors retain their
explicit traps. No optional software-provider signature is supplied.

Consumer smokes build DOS 6.22 and Windows 2.03 from original media. They check
shell commands or exact Notepad title/document glyphs, real key chords, and
files saved by the guest through a native FAT disk snapshot. The separate DOS
HIMEM variant verifies a resident XMS driver and nonzero free extended memory;
the stock DOS recipe's configuration remains unchanged. Windows 95 RTM also
passes the exact original Notepad title/document glyphs and keyboard edit/save
proof from a fresh image. Its first-run mouse-detection warning is recorded
and explicitly acknowledged; pointer input is not part of that proof.

BIOS stack frames, CHS/EDD buffers and firmware output packets use guest
linear addresses. Firmware walks the current guest page tables for paged
virtual-8086 calls, including noncontiguous physical pages. Physical disk DMA
is kept separate. The disk-call inspection tail reports linear and translated
buffer addresses, CR0/CR3 and returned status; a successful disk status must
not conceal data written to the wrong RAM backing.

## Inspection and limitations

`vm.extension("cc.v1").state()` returns a serialized observation containing
PC, CR0/CR3, last BIOS service, ATA task registers and command count, VGA
access count, PIC/PIT state, and bounded keyboard/CMOS transaction tails.
PCI inspection includes the configuration-address latch, controller header,
and bitmaps of configuration dwords read and written.
It also exposes integer registers, CR2/CR4, the IDT base, CS/DS/ES/SS selectors
and bases, `a20_enabled`, VGA register/palette snapshots, and the last 16
`bios_calls` with arguments, caller addresses and returned AX/flags.
`bios_counts` records per-vector totals and `bios_disk_calls` retains the last
eight disk calls independently of keyboard polling. `read_physical(address,
size)` returns an owned snapshot of at most 64 KiB of RAM, including the display
aperture. `breakpoint(address)` replaces the single debugger-owned execution breakpoint;
zero disables it. `breakpoint(address, skip=N)` skips only the first N hits.
A hit pauses execution and `resume()` skips that occurrence. `step(count=1,
stop_below=0)` performs bounded native debug observations on a paused VM
(up to 4096 observations and five seconds), replacing the execution breakpoint.
Its structured result retains the trace on a guest fault rather than treating
the fault as success; `reason` distinguishes a limit, address bound, timeout
and guest failure. Devices use the same bus routing as ordinary execution.
Reading a screenshot or state serializes with execution. Closing the VM
releases KVM and RAM and is idempotent; stopping preserves inspection until
close. Events support `debug.select` and the portable automation helpers.

This platform supports one IDE disk (or one NVMe disk with x86_64 UEFI), BIOS modes 03h/06h/10h/12h, UEFI GOP, PNG capture,
keyboard transitions, chords and relative PS/2 pointer input. Text injection,
interactive host windows, reset, guest snapshots and debugger
channels are not advertised capabilities. ARM64 UEFI continuation remains
available through its existing emulator interface. Other host platforms return
an explicit unsupported-backend error for cc PC execution.

An optional ISA NE2000 at I/O 300h and IRQ 9 connects to an in-memory Ethernet
switch. Create one `lan = vmm.switch()` and attach each guest with
`vmm.network("ethernet", switch=lan, mac="02:00:00:00:00:01")`, using a distinct
MAC for each guest. The switch learns unicast destinations, floods broadcasts
and multicasts, and bounds each port's receive queue. It requires no host
network configuration. Guest NIC drivers and protocol bindings belong to the
image recipe. `cc.v1.state().network` reports device state and frame counts.
The ACPI platform currently rejects this NIC attachment because its SCI also
uses IRQ9.

`vm.extension("cc.v1").disk()` takes an immutable, in-memory snapshot of a
snapshot-attached disk for inspection with trex filesystem readers. It preserves
the blocks at that instant; it does not quiesce guest filesystem transactions or
capture CPU/RAM state. This allows guest crash logs to be inspected without
extracting a disk image to a host file.

## Native execution contract

CC's `hypervisor.X86` accepts architectural state and RAM mappings, with no
host paths or image-building policy. `MapRAMRegions` allows one RAM backing
allocation to leave MMIO holes. Calls are serialized except for `Cancel` and `SetIRQ`. Pending IRQ callbacks
are joined before closing the accelerator.
`CompleteIO` completes the pending operation without executing a further
instruction before the firmware reads or modifies CPU state. This follows the
[KVM I/O completion contract](https://docs.kernel.org/virt/kvm/api.html#the-kvm-run-structure).

Two firmware details are required by NT 3.1 and covered by regression tests:

- IRQ0 must invoke the INT 1Ch user timer hook; NTLDR uses it for calibration.
- The AT CMOS configuration checksum covers bytes 10h–2Dh and is stored
  big-endian at 2Eh–2Fh. NT's HAL uses its validity to choose century register
  32h; an invalid checksum selects 37h and produces an invalid system time.

NTDETECT also needs INT 15h C2h mouse reset/identification services to discover
the PS/2 auxiliary device. Without them, the kernel leaves IRQ12 masked and the
mouse disabled even though the BIOS equipment word advertises a pointing device.
The BIOS detection regression and PS/2 packet tests cover this path. See
[browser display](vnc.md) for the WebSocket/VNC frontend.

### VGA performance

KVM executes ordinary guest instructions in hardware, but the planar VGA
aperture generates device exits. NT 3.1 uses masked set/reset write mode 3
extensively (about 245,000 writes in one interactive-logon boot); these writes
combine CPU-supplied masks, VGA registers and read latches. Mapping the aperture
as ordinary RAM would lose those semantics. A RAM-backed linear framebuffer
needs a matching guest display driver.

The native x86 run path uses cancellation callbacks instead of starting and
joining a goroutine at every IO/MMIO exit. On an i7-1165G7, the isolated exit
benchmark improved from 8.6–8.9 microseconds to 3.7–3.8 microseconds. Four fresh
NT desktop dialog measurements, without a browser, improved from 2.1–2.4 seconds
to 1.0–1.1 seconds for roughly 305,000 VGA byte accesses. These timings include
input and screenshot caption checks, and are not general application speedups.

`go test ./vmm/cc -run '^$' -bench BenchmarkVGAExit` exercises the native
aperture path. VGA tests cover masked writes and latches; native CPU tests check
repeated cancellation followed by resumed IO.

### Shared-memory byte channel

`vmm.channel("shared-memory", name="agent")` attaches one optional 4 KiB
aperture at physical `0xe1000000`, outside BIOS-advertised RAM. Open the host
endpoint using `vm.channel("agent")`; it implements the ordinary byte-channel
read/write/deadline contract. Closing a handle leaves the VM running.

The guest maps this aperture using its own OS driver/API. Bytes 0–3 contain
`TRCH`, followed by little-endian version 1. Host-to-guest producer/consumer
counters are at offsets 32/36, with a 1024-byte ring at offset 64. Guest-to-host
counters are at 40/44, with its ring at 1088. Counters are monotonically
increasing uint32 values; unsigned producer-minus-consumer must be at most
1024. Index the payload modulo 1024. Each producer writes payload before
publishing its counter; each consumer advances its own counter after reading.
Host operations run with the vCPU stopped and preserve the other side's
counters. Backpressure and deadlines bound host operations. Guest provisioning
protocols remain in their owning recipes.

### RAM framebuffer protocol

The host maps an additional 8 MiB of ordinary RAM at physical `0xe0000000`,
outside the RAM advertised by the BIOS. Six little-endian words describe the
TRF1 protocol: magic `0x31465254`, active, width, height, stride, and format
(`1` = BGRX). Pixels begin at offset 4096. A guest driver activates a mode
and renders into this allocation. Captures validate its dimensions and stride,
copy pixels while the guest CPU is stopped, and fall back to emulated VGA
before mode activation. The protocol and decoder live in `vmm/ramfb`.

Guest-specific driver implementations and installation policy belong to the
image recipe. TinyRangeX provides the NT 3.1 implementation. Trex supplies
`windows.pe32_link` for in-memory i386 object linking and stdcall adapters,
and `windows.pe(...).with_resources` for PE resource construction.

### Virtio absolute pointer

A modern virtio-MMIO input device occupies `0xe2000000..0xe2000fff`, IRQ10,
separate from the shared-memory byte channel. It advertises device type18,
VIRTIO_F_VERSION_1, absolute X/Y axes spanning0..65535, left/right/middle
buttons, and a vertical wheel. Two split queues accept up to128 descriptors
each. Events are delivered as complete SYN_REPORT batches; malformed rings
or DMA ranges set DEVICE_NEEDS_RESET. DMA cannot access the VGA/firmware hole,
device apertures, or memory outside guest RAM.

`vmm.Input` uses absolute coordinates0..32767; the backend scales these to the
virtio axes. `vmm.AbsolutePointerSource` reports when the guest has enabled the
device. RFB advertises that transition using Pointer Motion Change (-257),
and the JavaScript client maps CSS canvas positions to framebuffer pixels.
Relative mode uses the extension's0x7fff-biased deltas. Clients without the
extension retain the existing accumulated-coordinate input behavior.

`cc.v1.state().virtio_input` exposes negotiated status, queue addresses,
completion count, pending reports, and delivered report count. Windows-specific
driver source and installation policy live in TinyRangeX; no guest-driver
code is embedded in the backend or compiler.

## USB desktop input

`cc.backend(usb=True)` on x86_64 adds the UHCI PCI controller and native
USB HID keyboard/absolute pointer (including wheel), using guest inbox drivers.
Keyboard input falls back to PS/2 until the USB keyboard is configured.
`AbsolutePointer` reports availability only after the guest configures the HID
pointer, so frontends can release relative capture and switch coordinates safely.
Native Windows 11 build 26300 has been boot-tested with 16 GiB, USB keyboard,
absolute pointer, and wheel scrolling. This does not add SMP or an NVMe device.

## Native x86 NVMe

Use `vmm.disk(device, bus="nvme", unit=0)` with `cc.backend(uefi=True)`.
Do not also enable `pci_ide`, PIO-only mode, an alternate IDE model, or CHS
geometry. Legacy BIOS and `bus="auto"` retain IDE behavior.

The PC reuses cc's transport-independent NVMe controller at PCI 00:01.0
(1b36:0010, class 010802), with a relocatable 16-KiB MMIO BAR, namespace 1,
64-bit queue/DMA addresses and one I/O queue pair. PCI MSI is advertised when
supported by the accelerator, with INTx/GSI16 fallback. ACPI routing and the EFI
namespace device path match the controller; no IDE function or legacy ATA ports
are exposed for this profile. The existing snapshot/read-only disk policy is
preserved. `cc.v1.state().nvme` reports PCI configuration and controller registers.

This is a synchronous emulated block controller, not physical NVMe passthrough
or a multiqueue throughput promise. Guest boot policy must install an NVMe driver;
changing the VM bus alone does not make an IDE-specific image bootable.


## Hyper-V clock and timer enlightenments

The x86_64 machine enables a bounded Hyper-V interface when the accelerator
reports the required features. Legacy BIOS CPUID policy is unchanged. On Linux,
`KVM_GET_SUPPORTED_HV_CPUID` (system capability 191) is queried separately from
ordinary supported CPUID; kernels without it keep the existing hardware clocks.
The machine advertises `Hv#1`, reference-time counter and reference-TSC page,
and the guest-OS-ID/hypercall MSRs. It exposes SynIC, synthetic timers and VP
index only after `KVM_CAP_HYPERV_SYNIC` activation succeeds on each vCPU's
lifetime owner thread. Direct timers are exposed only if KVM reports support.
Clock-only support remains usable if SynIC activation is unavailable; ioctl
errors fail construction rather than claiming a feature that was not enabled.

Timer delivery and clock MSRs stay kernel-owned. SynIC configuration exits need
no userspace device routing in this machine. There is no VMBus implementation:
userspace hypercalls, including Windows' extended-capabilities query, receive
`HV_STATUS_INVALID_HYPERCALL_CODE`; unhandled Hyper-V exit kinds remain fatal.
Reset, crash, nested virtualization, TLB/IPI and APIC-assist enlightenments are
not advertised. This is not a claim of complete Hyper-V compatibility.

Paused `cc.v1.state().interrupts` includes bounded `hypervN.*` clock/timer MSR
values and rejected-hypercall count/last input. All CPU-local ioctls use the
same lifetime owner as execution. The usual pause/join requirement applies.
Native tests execute guest MSR instructions, validate the reference-TSC page,
and verify both SynIC message delivery and direct timer interrupts. Policy
coverage checks prerequisites, unavailable capability, activation errors and
legacy exclusion. ABI coverage verifies rejected-hypercall completion.

Specification references: Linux KVM API sections `KVM_GET_SUPPORTED_HV_CPUID`
and `KVM_CAP_HYPERV_SYNIC`; Hyper-V TLFS feature/MSR definitions; QEMU's
`docs/system/i386/hyperv.rst` describes the clock/timer dependencies. No QEMU
process is involved in this implementation.
