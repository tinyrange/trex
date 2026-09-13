# CrumbleCracker PC backend

`cc.backend()` implements `vmm.Backend` in process on Linux/amd64 with KVM.
It runs an existing BIOS-bootable disk supplied through the VMM block interface.
Guest image construction and operating-system setup belong to the caller.
Go constructs the BIOS data areas and supplies interrupt services through
small OUT/IRET firmware entrypoints. No firmware binary or external process
is used.

The PC contains one CPU, KVM PIC/PIT, a CMOS RTC with periodic IRQ8, one primary
ATA PIO disk, standard planar VGA and i8042 keyboard/mouse. The disk uses the
portable block interface; snapshot attachments use bounded memory overlays.
The VGA aperture is unmapped RAM and generates MMIO exits. Guest RAM, disk
and firmware are never transferred through temporary host files.

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

## Inspection and limitations

`vm.extension("cc.v1").state()` returns a serialized observation containing
PC, CR0/CR3, last BIOS service, ATA task registers and command count, VGA
access count, PIC/PIT state, and bounded keyboard/CMOS transaction tails.
It also exposes integer registers and the IDT base. `read_physical(address,
size)` returns an owned snapshot of at most 64 KiB of RAM, including the display
aperture. `breakpoint(address)` installs a debugger-owned execution breakpoint;
zero disables it. A hit pauses execution and `resume()` skips that occurrence.
Reading a screenshot or state serializes with execution. Closing the VM
releases KVM and RAM and is idempotent; stopping preserves inspection until
close. Events support `debug.select` and the portable automation helpers.

This initial platform supports one IDE disk, BIOS modes 03h/12h, PNG capture,
keyboard transitions, chords and relative PS/2 pointer input. Text injection,
interactive host windows, ACPI powerdown, reset, guest snapshots and debugger
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

`vm.extension("cc.v1").disk()` takes an immutable, in-memory snapshot of a
snapshot-attached disk for inspection with trex filesystem readers. It preserves
the blocks at that instant; it does not quiesce guest filesystem transactions or
capture CPU/RAM state. This allows guest crash logs to be inspected without
extracting a disk image to a host file.

## Native execution contract

CC's `hypervisor.X86` accepts architectural state and RAM mappings, with no
host paths or image-building policy. `MapRAMRegions` allows one RAM backing
allocation to leave MMIO holes. Calls are serialized except for `Cancel`.
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
