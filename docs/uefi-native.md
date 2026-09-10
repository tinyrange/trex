# ARM64 UEFI continuation

`emulator.uefi` can seed an independent native machine after a successful,
validated `ExitBootServices`. The native backend is Crumblecracker, checked out
as the `cc` submodule. Apple Silicon hosts use Hypervisor.framework through
purego and a small ARM64 SIMD-register ABI bridge. Build with `CGO_ENABLED=0`.
The executable needs the `com.apple.security.hypervisor` entitlement; the
entitlements file is `cc/tools/entitlements.xml`.

The handoff copies RAM, general/SIMD registers, EL1 translation state and the
disk overlay. Firmware runtime entrypoints become identified HVC calls. The
runtime adapter handles virtual-address conversion, time and variable services.
Unexpected firmware services, exceptions and MMIO accesses remain explicit
stops. Software accelerators do not patch the Windows kernel.

## Starlark lifecycle

Configure ACPI and firmware block devices before the software boot. After
`vm.run(...)` returns `reason == "exit_boot_services"`:

```starlark
vm.native_start(disk_handle = disk_handle, ramfb_base = 0x09020000)
stop = vm.native_run(timeout = 30.0, windows_debug = True, mmio_trace = 64)
print(stop)
print(vm.native_console())
print(vm.native_mmio())
screenshot = vm.native_screenshot()
disk_snapshot = vm.native_disk()
vm.native_close()
```

`native_start` creates one native execution. Calling it twice is an error.
`native_close` releases only the native execution and is idempotent; another
`native_start` can reuse the software EBS state. `vm.close()` closes both.
Software `checkpoint`/`restore` affect only software state, never the running
native machine. Native snapshots/restore are not exposed by this adapter.

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

With `windows_debug=True`, the adapter recognizes the Windows ARM64 debug
service ABI, captures symbol load/unload notifications and debug printing, and
delivers intentional divide breakpoints to the guest's exception vector. An
ordinary debugger breakpoint still stops. Debug output is bounded at 64 KiB,
individual messages at 4096 bytes and module observations at 4096 entries.

`mmio_trace` is the maximum retained tail of successful MMIO transactions, from
0 (disabled) through 4096. Each run clears that tail. `native_mmio()` returns
address, access size, value and write direction. `native_modules()` returns
module names, bases and sizes. `native_stats()` reports cumulative exit/MMIO
counts and a stopped GIC/timer state observation. Its counter uses
`mach_absolute_time() - vtimer_offset`, the HVF clock domain.

Use `vm.register(name, native=True)`, `vm.memory(address, size, native=True)` and
`vm.disassemble(address, count=..., native=True)` to inspect native execution.
Memory/disassembly accept `physical=True`; otherwise they walk the native
guest's current translation tables. Native register writes are not exposed.

`native_screenshot()` returns a PNG file abstraction, copied from the configured
RAMFB while the guest is stopped. `native_disk()` returns an immutable in-memory
overlay snapshot. Neither operation creates a host file. Guest filesystem
caches must be flushed before treating that snapshot as a report of guest
writes.

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
