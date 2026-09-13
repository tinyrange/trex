# CrumbleCracker PC backend

`cc.backend()` implements `vmm.Backend` in process on Linux/amd64 with KVM.
The initial supported guest is x86 Windows NT 3.1 build 511. Its original MBR,
volume boot sector, NTLDR, NTDETECT and kernel execute on the native CPU.
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

The enclosing TinyRangeX recipe `scripts/smoke/windows_cc.star` constructs a
fresh NT 3.1 image from original media, boots to Program Manager and checks
the Windows NT Security caption after Ctrl+Alt+Del. It writes both PNGs and
requires a clean lifecycle stop. Caption glyph comparisons identify the actual
successful surfaces instead of accepting an arbitrary framebuffer change.
It uses interactive Administrator logon to avoid the observed automatic-logon
startup race described in [browser display](vnc.md).

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
keyboard transitions, chords and relative PS/2 pointer input. Network, text injection,
interactive host windows, ACPI powerdown, reset, guest snapshots and debugger
channels are not advertised capabilities. ARM64 UEFI continuation remains
available through its existing emulator interface. Other host platforms return
an explicit unsupported-backend error for cc PC execution.

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

`go test ./trex/vmm/cc -run '^$' -bench BenchmarkVGAExit` exercises the native
aperture path. VGA tests cover masked writes and latches; native CPU tests check
repeated cancellation followed by resumed IO.

### Renvo NT 3.1 display driver

The browser recipe compiles `vmm/ramfb/driver/display.go` and `miniport.go`
using unmodified Renvo's existing `linux/386` relocatable-object output.
This supplies cdecl machine code, not a Linux process or runtime.
`windows.pe32_link` then constructs the PE image using trex's Go PE builder,
resolves ELF relocations, and emits stdcall import/export/callback adapters.
The recipe declares the NT ABI's DLL names and argument counts. There is no
NT-specific Renvo target or compiler modification, and all stages stay in memory.

The host maps an additional 8 MiB of ordinary RAM at physical `0xe0000000`,
outside the RAM advertised by the BIOS. Six little-endian words describe the
TRF1 protocol: magic `0x31465254`, active, width, height, stride, and format
(`1` = BGRX). Pixels begin at offset 4096. The miniport verifies the magic,
selects 1024×768×32, and maps the aperture into CSRSS. GDI renders directly into
an unhooked engine bitmap over this allocation. Captures copy it while the
guest CPU is stopped, falling back to emulated VGA before mode activation.

NT 3.1 hosts the graphics engine in WINSRV and requires both DrvEnableDriver
and DrvDisableDriver exports. It also loads desktop metrics and OEM images
from the display DLL. The recipe builds a resource section from the original
media's VGA resources, excluding VGA version metadata; all executable code
in the custom driver remains Renvo-generated. `windows.pe(...).with_resources`
performs the portable PE resource construction and updates its checksum.

NTVDM needs a separate `VgaCompatible` video device even for windowed Win16
applications. The recipe retains the original VGA miniport but deletes its
`InstalledDisplayDrivers` value, leaving the Renvo driver as the desktop
display. An empty multi-string is insufficient: NT 3.1 attempts to load an
empty DLL name. Disabling VGA instead makes `RegisterConsoleVDM` fail with
error 6 (`ERROR_INVALID_HANDLE`). Legacy VGA accesses during initialization
are expected; desktop rendering still uses the RAM aperture.

The NT 3.1 image also applies INITIAL.INF's x86 WOW setup step: select
`krnl386` in `Control/WOW/wowcmdline`. The seed hive names `krnl286`, which
the setup script selects only for MIPS. Keeping that default prevents Write
from reaching the Win16 desktop. `scripts/smoke/nt31_write.star` verifies a
fresh Write title and typed document text, with no VGA accesses during typing.

The fresh `scripts/smoke/nt31_framebuffer.star` smoke verifies Notepad text and
the Security dialog, at 1024×768, with zero VGA accesses during desktop redraw.
The Security caption appeared in 51 ms on the i7-1165G7 host, including the
50 ms chord hold. This check reads the RAM caption directly; the older VGA
timing above also included repeated PNG decoding. It is not a general CPU or
application speedup measurement. Mouse input remains relative PS/2, with a
GDI software cursor; absolute pointer support is separate work.
