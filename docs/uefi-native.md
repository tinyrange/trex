# ARM64 native UEFI execution

`emulator.uefi` can start an independent native machine at the EFI entry point,
or continue a suspended software boot. The native backend is Crumblecracker, checked out
as the `cc` submodule. Apple Silicon hosts use Hypervisor.framework through
purego and a small ARM64 SIMD-register ABI bridge. Build with `CGO_ENABLED=0`.
The executable needs the `com.apple.security.hypervisor` entitlement; the
entitlements file is `cc/tools/entitlements.xml`.

The handoff copies RAM, general/SIMD registers and EL1 translation state.
File inputs get an independent memory-overlay copy; explicitly supplied block
devices retain the same caller-owned backing. Firmware entrypoints become identified HVC calls.
Boot services use the shared Go firmware implementation; runtime services handle
virtual-address conversion, time and variables.
Unexpected firmware services, exceptions and MMIO accesses remain explicit
stops. Software accelerators do not patch the Windows kernel.

## Starlark lifecycle

Configure ACPI and firmware block devices, then start native execution directly
without calling `vm.run`. Boot Manager, winload and the kernel execute on HVF:

```starlark
vm.native_start(disk_handle = disk_handle, gop = True, input = True)
stop = vm.native_run(timeout = 30.0, windows_debug = True, mmio_trace = 64)
print(stop)
print(vm.native_console())
print(vm.native_mmio())
screenshot = vm.native_screenshot()
disk_snapshot = vm.native_disk()
vm.native_close()
```

`native_start` creates one native execution. Calling it twice is an error.
`trap_debug=False` leaves debug exceptions and debug-register accesses to the
guest. This avoids a host exit on Windows' frequent MDSCR accesses during
syscalls and page faults. Choose this at creation for ordinary desktop runs;
the default `True` retains debugger stops and Windows debug-service observations.
`windows_debug=True` requires debug trapping. The policy remains fixed for the
execution, so switching cannot mix emulated and native debug-register state.
`gop=True` provides a 1280×720 BGRX firmware framebuffer in reserved guest
RAM for the OS's built-in display driver. It is mutually exclusive with
`ramfb_base`, which exposes the fw_cfg device for a guest RAMFB driver.
`native_close` releases only the native execution and is idempotent; another
`native_start` can reuse the original software state. `vm.close()` closes both.
Software `checkpoint`/`restore` affect only software state, never the running
native machine. Native snapshots/restore are not exposed by this adapter.

`emulator.uefi(..., memory=4<<30)` supports 4 GiB of guest RAM. The physical
range starts at 1 GiB, so its upper GiB is above physical address 4 GiB.
Guest RAM is additional to image construction and software/native handoff memory.

For disposable sparse backing without a changed-data quota, create the device
before the VM and pass it directly to `vm.block_device`:

```starlark
working = block.temporary_overlay(block.device(disk), directory="local")
vm = emulator.uefi(boot, memory=4<<30)
disk_handle = vm.block_device(working, device_path=disk_path)
```

The native frontend owns the temporary backing file and removes it at script
exit, including script failures. UEFI machines are also runtime-owned and close
before backing created earlier. Explicit `vm.close()` stops the VM immediately;
the backing remains available until script exit. There is no memory fallback or
dirty-byte quota: available host filesystem space bounds writes. A backing I/O
failure stops native execution. Abrupt process termination can leave an orphan.
The immutable base image is never modified or materialized in this file.
Caller-owned devices cannot be checkpointed; file inputs retain bounded memory
overlays for independent software experiments.

`native_start` accepts an optional whole-disk firmware handle and these native
PCI parameters. ACPI must describe the same topology:

| Argument | Default |
| --- | --- |
| `config_base`, `config_size` | `0x20000000`, `0x1000000` |
| `window_base`, `window_size` | `0x21000000`, `0x1000000` |
| `nvme_bar`, `nvme_device` | `0x21000000`, `1` |
| `nvme_interrupt` | `78` (GIC interrupt ID, including the SPI offset) |
| `ramfb_base` | `0` (disabled) |
| `input` | `False`; enables virtio PCI keyboard (device 2, GSI 79) and absolute pointer (device 3, GSI 80) |

The platform uses CC's native GIC distributor at `0x08000000` and redistributor
at `0x080a0000`. Its GTDT declares physical timer PPI 30 and virtual timer PPI 27.
The PCI root exposes ECAM, a memory window and INTx routing. RAMFB implements
the fw_cfg DMA protocol used by the TinyRangeX Windows miniport.

`native_run` requires a started native machine and a timeout in `(0,3600]`
seconds. Reason `0` means the caller's deadline expired. Internal device
interrupt wakeups are resumed automatically. Reason `1` is an unhandled
architectural exception; `syndrome`, `pc`, `virtual_address` and
`physical_address` identify it. Non-exception exits have zeroed syndrome/address
fields. Native timers continue advancing while stopped for inspection.

Reason `4` is a terminal PSCI power-off request; reason `5` is a terminal reset
request. Repeated runs return that result without resuming guest execution.
The native window closes normally on power-off. Reset remains an explicit stop;
automatic reboot is not implemented.

The backend implements PSCI 1.1 and SMCCC 1.1 discovery. Validation OS 26100's
PSCI 1.0 platform table disables SYSTEM_OFF and SYSTEM_RESET without querying
their features; its 1.1 table enables both. The desktop shutdown path was
verified with `shutdown /s /t 0`, reaching SYSTEM_OFF and closing the window.

With `windows_debug=True`, the adapter recognizes the Windows ARM64 debug
service ABI, captures symbol load/unload notifications and debug printing, and
delivers intentional divide breakpoints to the guest's exception vector. An
ordinary debugger breakpoint still stops. Debug output is bounded at 64 KiB,
individual messages at 4096 bytes and module observations at 4096 entries.

Symbol unloads do not require a name. An unload notification with an all-ones
image base clears module observations; it does not itself stop execution.

`mmio_trace` is the maximum retained tail of successful MMIO transactions, from
0 (disabled) through 4096. Each run clears that tail. `native_mmio()` returns
address, access size, value and write direction. `native_modules()` returns
module names, bases and sizes. `native_stats()` reports cumulative exit/MMIO
counts and a stopped GIC/timer state observation. Its counter uses
`mach_absolute_time() - vtimer_offset`, the HVF clock domain.

`firmware_trace` similarly retains up to 4096 completed firmware calls per run.
`native_firmware()` returns service names, argument values, EFI status and the
protocol GUID for protocol lookup/open/close calls. The GUID is captured at the
call, before the guest can reuse its buffer. Both traces default to disabled.

Use `vm.register(name, native=True)`, `vm.memory(address, size, native=True)` and
`vm.disassemble(address, count=..., native=True)` to inspect native execution.
Memory/disassembly accept `physical=True`; otherwise they walk the native
guest's current translation tables. Native register writes are not exposed.

`native_screenshot()` returns a PNG file abstraction, copied from the configured
GOP framebuffer or RAMFB while the guest is stopped. `native_disk()` returns an immutable in-memory
overlay snapshot. Neither operation creates a host file. Guest filesystem
caches must be flushed before treating that snapshot as a report of guest
writes. Caller-owned backing does not offer immutable snapshots: request
`native_disk(snapshot=False)` for a live file view while execution is stopped.
That view remains valid only while its backing is open and must not be mistaken
for a filesystem-consistent snapshot.

With `input=True`, the two input BARs start at `0x21004000` and `0x21008000`.
ACPI must route their INTx interrupts. The guest needs a modern virtio PCI input
driver. `native_key(code, down)` accepts Linux input-event key codes;
`native_pointer(x, y, buttons=0, previous=0)` accepts absolute guest pixel
coordinates and the CC display button mask (left 1, middle 2, right 4).
These operations submit real virtqueue events and hardware interrupts.
`native_stats()` includes each input device's status, queue readiness, used
event index, pending event count and interrupt status.

`native_window(title="Validation OS")` opens a cgo-free Gowin window until
closed. It presents RAMFB and forwards physical key transitions, mouse buttons,
absolute movement and wheel events. Rendering preserves the guest aspect ratio;
host coordinates map through the displayed rectangle, including Retina scaling.
Ordinary movement outside that rectangle is ignored. Focus loss releases held
keys and buttons. On macOS the host cursor is hidden over the active guest
display and restored when leaving it or closing the window. Windows handles
key repeat and keyboard layout.

The display runner executes the VM independently of OpenGL presentation,
interrupting it briefly to submit input or copy a framebuffer. Captures reuse
storage and return only changed rows, with owned pixel bytes. All VM and device
access stays serialized; rendering never reads live guest RAM. Clipboard and
guest resolution changes are not exposed by this RAMFB frontend.

The Windows RAMFB miniport allocates coherent cached framebuffer RAM and uses
the kernel's bulk memory copy for each dirty row, including console scrolling.
The fw_cfg device registers retain their device-memory mapping.

## TinyRangeX recipes

From the enclosing TinyRangeX checkout, the inspection recipe accepts `hvf`
for native storage or `ramfb` for native storage plus the display miniport:

```sh
CGO_ENABLED=0 go build -o local/trex-hvf ./trex/cmd/trex
codesign -f -s - --entitlements trex/cc/tools/entitlements.xml local/trex-hvf
local/trex-hvf scripts/inspect/uefi_arm64_repl.star validationos-arm64.iso ramfb repl
```

The scripted display smoke constructs a fresh image, boots it through software
UEFI and native HVF, and launches the existing guest display probe at login:

```sh
local/trex-hvf scripts/smoke/windows_hvf.star validationos-arm64.iso screenshot.png
```

For an interactive native window, supply the original virtio-win 0.1.285 ISO:

```sh
local/trex-hvf scripts/run/windows_hvf.star validationos-arm64.iso virtio-win-0.1.285.iso
```

The native run and smoke scripts use 4 GiB guest RAM and disposable sparse
overlays in the enclosing checkout's `local/` directory, using the same backing
implementation as `cmd/windows11`. These settings do not establish full Windows
11 client boot support; that image recipe still needs ARM64 provisioning.

The recipe constructs both the driver files and PnP registry database in memory,
using the ARM64 input package's INF declarations and a development signing
identity. Append `repl` to boot for 40 seconds and retain the stopped VM for
inspection; call `vm.native_window()` from that REPL to open it.

The display smoke also exercises hardware input when given a fourth argument:

```sh
local/trex-hvf scripts/smoke/windows_hvf.star validationos-arm64.iso screenshot.png 40 virtio-win-0.1.285.iso
```

It drags the console with pointer events and types the probe command through
the keyboard device. The guest probe verifies the resulting console and cursor
positions as well as the display configuration, then flushes its report.

Its optional third argument is the bounded native duration (default 40 seconds).
The probe verifies 2560×1664, 192 DPI and Tahoma caption metrics. The supported
recipe was exercised with ARM64 Validation OS build 26100.9278. This is an
initial single-vCPU Windows boot platform, not a general live-migration API:
additional firmware runtime services, devices and native checkpoint support
remain explicit extension points.
