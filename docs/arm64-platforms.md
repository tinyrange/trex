# ARM64 boot and platform composition

CPU handoff and hardware composition are separate portable values:

```python
def create_devices(ctx):
    value = [0]
    def read(offset, size):
        return value[0]
    def write(offset, size, data):
        value[0] = data
    return {"devices": [vmm.mmio(0x1000000, 4096, read, write, widths=[4])]}

boot = vmm.arm64_boot(image, address=0x40000000, memory_base=0x40000000)
platform = vmm.arm64_platform(create_devices)
machine = vmm.machine(architecture="arm64", memory=64<<20, boot=boot, platform=platform)
```

`arm64_boot` supplies the immutable image, physical load/entry addresses and
optional X0–X30/system registers. It does not select a board. Generic bounds
checks impose instruction alignment and nonoverlapping load ranges; the native
backend separately checks host-page alignment. Native cc currently executes
one CPU at EL1, with headless output. Unsupported operations fail explicitly.

`darwin_arm64_boot(kernel, device_tree, memory, memory_base, virtual_base, ...)`
constructs XNU's revision-2 handoff and returns a generic boot value. Both bases
are explicit. Its `nvram`, `read_only_address` and `read_only_size` attributes
expose handoff metadata for the recipe to wire into hardware if needed. XNU's
32 MiB RAM-base/size and 16 KiB payload-placement requirements belong to that
handoff ABI. No hardware platform is selected. `darwin_nvram(values)` separately
encodes an 8 KiB CHRP bank into immutable bytes; neither API accesses host NVRAM.

## Platform factory and MMIO

`arm64_platform(create, gic_distributor=0, gic_redistributor=0)` accepts explicit
GIC placement. Nonzero GIC addresses must be distinct and 64 KiB aligned. The
factory runs once per VM and must create fresh mutable state. It returns:

```python
{"devices": [device, ...], "hvc": optional_hvc_callback}
```

Devices are ordered: the first device claiming an address handles the access.
This permits a specific PCI function ahead of a broad absent-ECAM fallback.
Unknown addresses remain unsupported, rather than implicitly reading zero.

`mmio(address, size, read=None, write=None, widths=[1,2,4,8])` creates a region.
Callbacks receive region-relative offsets: `read(offset,size)` returns an
unsigned value fitting the access width; `write(offset,size,value)` returns
`None`. Accesses must be aligned and fit wholly inside the region. Missing
callbacks fail. Region callbacks and native protocol callbacks execute serially
on one VM-owned Starlark thread; VM cancellation interrupts Starlark execution.
Create mutable callback state inside the factory, rather than sharing it between
VMs. Native device values are bound to their creating VM and cannot be reused.
Unused native devices and those created by a failed factory are closed.

An optional `hvc(immediate,function)` returns `True` only for services it handles.
It can inspect/update X0–X30 through the runtime. HVC dispatch precedes the
backend's architectural PSCI handling. With HVF, PC has already advanced past
HVC; callbacks must not advance it again. An absent callback supplies no OEM
services. The optional private Apple ISA setting remains an explicit native
Hypervisor.framework host capability, independent of the chosen guest board.

## Runtime resources

The factory's `ctx` exposes:

| Operation | Contract |
| --- | --- |
| `memory_base`, `memory_size`, `disks` | Supplied guest resources; disk values expose their actual overlay-backed block device. |
| `read_memory(address,size)` | Immutable bytes; at most 8 MiB per call. |
| `write_memory(address,data)` | Bounded bytes/file input; enforces guest memory write permissions. |
| `protect_memory(address,size,read=True,write=False,execute=True)` | Applies native CPU permissions and the corresponding emulated-DMA restrictions. Host-page alignment is checked by the backend. |
| `counter()` | Architectural counter ticks and frequency. |
| `epoch_microseconds` | Epoch supplied by the native backend for this VM. |
| `irq(id,level)` | Drives a GIC SPI; wiring and MSI interpretation belong to the platform. |
| `read_register(id)`, `write_register(id,value)` | X0–X30 only. |
| `emit(kind,payload=None)` | Portable structured event. |
| `device(kind,options)` | Creates a native protocol device with explicit placement/backing/wiring. |

Runtime operations are restricted to the platform callback thread, preventing
escaped contexts from racing a running VM. Operations are revoked when the VM
stops. The runtime exposes no host paths, processes or sockets. Native protocol DMA uses the same memory-permission checks
as runtime writes. Memory protection updates preserve unaffected subranges.
Only asynchronous protocols are polled; synchronous block requests complete
through their notifications. Device polling and final evidence flushing use
generic lifecycle hooks. Devices close before CPU resources are released.

## Native protocol primitives

The cc implementation registers the following protocols. Addresses have no
board-specific defaults. Options not listed for a kind are rejected.

| Kind | Options |
| --- | --- |
| `pl011` | `address`, `channel` (a named machine byte channel). Buffered serial evidence is emitted on stop; byte-channel traffic remains live. |
| `pl031` | `address`; counter/epoch come from the runtime. |
| `pl061` | `address`; static eight-pin GPIO register semantics. |
| `apple-aes` | `address`, optional `irq`; software-key FIFO/DMA protocol only. |
| `apple-rtc` | `address`; microsecond counter and host-change controls. |
| `apple-ctrr` | `address`, optional `seed_bank`, `seed_address`, `seed_size`; version-1 register protocol. Lockdown enforces CPU and DMA permissions. |
| `virtio-block` | `config_base`, `bar`, `disk`, optional `msi(address,data)` callback. Standard modern VirtIO block, including writable backing and flush. |
| `apple-storage-pci` | Same placement/backing/MSI options plus required `role` byte; Apple storage role/capability protocol. |
| `apple-usb-pci` | `config_base`, `bar`, `channel`, optional `msi`; framed Apple USB over modern split queues. |
| `apple-simple-storage` | `address`, `disk`, optional `version=1`, `device_id=0`, `page_size=4096`; sequential-descriptor firmware transport. |
| `apple-simple-usb` | `address`, `channel` (empty means disconnected), optional version/device/page fields as above. |

PCI configuration bases require 4 KiB alignment and BARs 64 KiB alignment.
Storage protocols require 512-byte sectors. Native channel protocols require
nonblocking read/write operations, supplied by cc's in-memory channel endpoints.
An MSI callback returns `None`; the platform chooses interrupt decoding and
whether to pulse or hold the line. Protocol constants are implemented in Go;
board identity, placement, firmware registers, policy and composition belong to
the recipe repository.
