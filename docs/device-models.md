# Native experimental PCI device models

Use an explicit attachment list rather than adding another device flag or
`if p.myDevice != nil` case to the emulator:

```python
# cc and vmm are native trex namespaces.
backend = cc.backend(devices=[
    cc.p390(name="p390", slot=5, s370=True,
            start="2003-01-01T08:00:00Z"),
])
vm = vmm.start(machine, backend)  # caller-supplied i386 BIOS machine and disk
```

This constructs **configuration**, not a running coprocessor. Each VM start
calls a fresh native factory. Reusing `backend` must not share device memory,
interrupt state, clocks, or diagnostic buffers between VMs. `name` is the
inspection key; `slot` is a bus-0 device number, function 0. Slot 5 preserves
the original P/390 recipe's placement, but is not baked into dispatch.
`cc.backend(p390=True, p390_s370=True, p390_start=...)` remains a compatibility
shortcut producing the same named attachment. Do not combine it with an
explicit attachment having the same name or BDF.

The attachment extension currently supports **single-CPU x86 BIOS PCs**, not
UEFI, direct Darwin boot, or ARM64. P/390 further requires `i386`. The core
model and bus are portable Go; that does not mean that QEMU, HVF ARM64, or an
arbitrary emulator already exposes this attachment API. Another backend must
implement the small adapter contract below. Existing unrelated planar devices
remain on their established paths; this is not a wholesale chipset rewrite.

## Three boundaries

1. **Hardware/model:** `vmm/device.PCI` plus optional capabilities. Owns PCI
   identity, configuration masks, BAR decoding, register semantics, internal
   processors, and device-local state. Imports no hypervisor or CPU engine.
2. **Attachment/bus:** `device.Spec` and `device.Bus`. Own names/BDFs, independent
   construction, configuration routing, access shape/boundaries, ambiguous BAR
   detection, attached interrupt aggregation, polling/deadlines, inspection,
   construction rollback, and optional `io.Closer` teardown.
3. **Emulator adapter:** `vmm/cc/devices.go`, the generic I/O/MMIO exit paths and
   scheduler. Translate CPU exits to byte transfers, complete MMIO reads, wire
   IRQs, reserve platform resources and wake a CPU at a model's deadline. No
   P/390 type assertion or device-specific dispatch case is needed.

`emulator/s390/P390PCI` is the concrete example. It wraps the existing portable
P/390 HLE/architectural machine. The original OS/2 device-manager channel path
is unchanged; the PCI transport has moved out of `vmm/cc`. Only the convenience
constructor/legacy configuration translation knows that this model is P/390.

## Adding another native model

Implement the four-method interface in a model package:

```go
// Methods of device.PCI:
ReadConfig(offset uint16) byte
WriteConfig(offset uint16, value byte)
Regions() []device.Region
Access(device.Access) error
```

- Config offsets are bytes in conventional 256-byte PCI configuration space.
  The model owns read-only identity, command bits, BAR masks/probes, alignment,
  and interrupt routing registers. The bus does not guess a generic PCI ABI.
- `Regions` reports current decoded BARs, including `BAR`, `Space` (`IO` or
  `Memory`), `Base` and `Size`. Omit disabled decoders and probes that are not
  valid parent-bus addresses. Returned descriptors must remain consistent until
  the next owner-serialized mutation. Do not cache bases in the emulator.
- `Access` receives a **BAR-relative** offset, a byte slice, and read/write
  direction. Reads fill the slice. Each call is one little-endian bus element:
  widths 1/2/4 for I/O and 1/2/4/8 for memory; models may reject widths they do
  not implement. The bus handles REP I/O by repeating the *same* port, not by
  incrementing the BAR offset. It checks the complete shape before side effects.
  Do not retain the slice. Unsupported commands must fail, not synthesize success.
- `Access.Position` is an optional lazy diagnostic callback. Do not require it
  for hardware behavior or expose accelerator register objects to a model.

Describe caller placement and immutable options with a factory:

```go
spec := device.Spec{
    Name: "experiment",
    BDF:  7 << 3, // bus 0, device 7, function 0
    New: func() (device.PCI, error) {
        return newExperiment(copiedOptions) // independently allocated each time
    },
    Check: func(p device.Profile) error {
        // Optional model-specific architecture/CPU/firmware constraints.
        return validateExperimentProfile(p)
    },
}
backend := &cc.Backend{Devices: []device.Spec{spec}}
```

No live hardware is allocated in `Check`. `device.Validate` checks identity,
placement and profile policy without calling factories; an empty architecture
performs structural checks only (Starlark construction does not yet have a VM).
Fixed PC function-0 BDFs for slots 0–4 are reserved even when their built-in
function is absent. Duplicate names/BDFs and out-of-bus-0 placement fail before
construction. If a factory fails, the bus closes models made by that attachment
attempt, including a nonnil partially constructed model returned with an error.
A factory should clean its own allocations when returning a nil model/error.

For a new native Starlark constructor, return `cc.NewPCIDeviceValue(spec)` or
implement `cc.PCIDeviceValue`. `cc.backend(devices=[...])` consumes that interface;
it does not need another type switch or backend option. The wrapper contains
immutable construction policy, not Starlark callbacks or a mutable live device.
Do not mutate captured option slices/maps after publishing the specification.

## Optional capabilities

| Interface | Contract |
|---|---|
| `device.Poller` | `Poll(now) error` advances bounded work on the device owner; `Deadline() time.Time` gives the next required wake, or zero for none. Use the supplied clock, not a hidden wall-clock loop. |
| `device.Interrupt` | `Interrupt() (line uint32, asserted bool)` exposes the current level. The bus ORs attached sources on a shared line and lowers the old line on relocation. |
| `device.Inspector` | `State() any` returns bounded model diagnostics suitable for immediate native-to-Starlark conversion. |
| `device.MemoryReader` | `ReadMemory(space, address, data)` reads a model-defined observational space. Validate unknown spaces and bounds; do not simulate guest writes or mutate storage keys/descriptors. |
| `device.BARReader` | `ReadBAR(bar, offset, data)` optionally supports read-only physical aperture inspection without guest MMIO side effects. |
| `io.Closer` | Releases model-owned resources after guest execution is joined, before CPU/RAM teardown. Construction rollback uses the same hook. |

The CC owner polls models and synchronizes interrupts before resuming execution.
A deadline's concurrent timer **only wakes/cancels native CPU execution**; model
mutation and IRQ synchronization happen on the owner after execution returns.
All access, inspection, poll and close calls are serialized with guest execution.
Models must not start unsynchronized workers mutating their state or guest RAM.
This API deliberately does **not** promise hotplug, migration/snapshot, generic
DMA, MSI, a new guest-memory loan mechanism, or arbitrary guest callbacks. Add
such a capability only with an explicit ownership contract and a real consumer.

## Resource conflicts and failure behavior

The generic bus rejects wrapping/straddling accesses, overlapping attached BARs,
and attachment BARs overlapping the adapter's reserved platform resources before
delivering a routed transfer. Relocating a BAR updates routing immediately;
disabled decoders no longer claim a range. Unclaimed traffic falls back to the
existing platform path. This is decode validation, not a PCI resource allocator:
configuration probing may temporarily change BAR values, and the adapter does
not unmap RAM to honor a bad BAR. Keep experimental apertures in free device
space rather than relying on accesses to mapped RAM to produce MMIO exits.

The CC adapter reserves planar/ISA/BIOS/config ports below `0x1000`, low physical
space below `0xc0000000`, framebuffer/input/channel ranges, high RAM, and enabled
built-in PCI IDE/UHCI/Ethernet BARs and HPET. Attached level IRQs may share with
**other attachments**, but not existing chipset interrupt owners. The current
PC adapter accepts free legacy IRQs below 16; reserved or unsupported asserted
lines fail explicitly. There is no global chipset-wide interrupt rewiring.
Errors from access/poll/IRQ wiring propagate to the VM rather than looking like
successful hardware. Model inspection is bounded by the frontend (64 KiB per
memory read) as well as model-specific bounds.

## Inspection and tests

```python
ext = vm.extension("cc.v1")
state = ext.state()["devices"]["p390"]
main = ext.device_read(name="p390", space="main", address=0, size=64)
aperture = ext.device_read(name="p390", space="aperture", address=0x20000, size=64)
```

P/390 also retains `state()["p390"]` and `p390_read(address, size)` aliases for the
attachment named `p390`. Renaming it deliberately uses generic inspection.
`read_physical` observes a currently decoded BAR through `BARReader`; it does
not execute MMIO register reads with side effects.

Portable external-package tests (`vmm/device/pci_test.go`) use non-P/390 register
models to exercise multiple instances, relocated/disabled BARs, REP shape,
conflicts, IRQ sharing/relocation, deadlines, errors and teardown/rollback.
`vmm/cc/experimental_devices_test.go` attaches an unrelated doorbell device at
slot 7 through the same PCI BIOS, CF8, I/O, MMIO, scheduler and IRQ paths, and
checks Starlark configuration/factory isolation. These tests require no IBM
media or running guest. Concrete transport tests live beside `P390PCI`; the
original-media OS/2 CPU/channel and full MVS/TSO smokes validate the complete
consumer through the explicit attachment API.
