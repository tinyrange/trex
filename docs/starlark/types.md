# trex Starlark value types

trex APIs exchange capability-bearing values instead of host paths and
processes. This keeps image construction portable and permits files to remain
lazy through archives, filesystems, block devices, NBD, and QEMU.

## Binary and file values

| Type | Purpose | Mutability and ownership |
| --- | --- | --- |
| `bytes` | Small immutable byte string already materialized in memory. | Immutable Starlark value. |
| `file` | Random-access byte source with a 64-bit logical size. | Usually lazy; write support is capability-dependent. |
| `byte_view` | Immutable bounded window over a file or bytes value. | Zero-copy over its source where possible. |
| `binary.cursor` | Stateful sequential decoder over a byte source. | Advances on reads; not safe to share as immutable state. |
| `binary.builder` | Bounded in-memory sequential encoder and patch target. | Mutable until frozen; `bytes()` and `file()` return snapshots. |
| `binary.layout` | Reusable fixed-record decoder and encoder. | Immutable compiled layout. |

Use a cursor for sequential records and `binary.read_u32le(source, offset)` for
isolated random fields. Builders are for small metadata and executable records,
not multi-gigabyte images. Filesystem and partition builders return lazy files.

## Trees and filesystems

A directory is an in-memory logical tree. Archive and filesystem mounts expose
read-only directory trees backed by their source file. Filesystem builders take
a directory and return a lazy generated image. Mount values retain format
metadata and virtual files such as boot sectors where supported.

Paths inside these values are logical paths. They are not permission to create
an extracted host tree. Windows path policy belongs in Starlark modules; format
parsing and construction belong in Go implementations.

## Block values

| Type | Purpose |
| --- | --- |
| `block_device` | Sector-oriented random-access device with geometry and capabilities. |
| cached device | Bounded read cache over another device. |
| overlay device | Writable copy-on-write working state over an immutable base. |
| block view | Live read-only file view of a block device. |
| NBD server | Runtime-owned export of a block device over a byte channel. |

An overlay owns dirty chunks and may hold an active lease while a VM uses it.
Respect its configured byte limit. `snapshot()` returns an immutable live view
using generation-based copy-on-write; `commit()` seals an overlay and requires
all leases to end. Exporting a complete image is an explicit final-output
operation, not a required processing stage.

## Events, clocks, and channels

A byte channel is a bounded bidirectional byte stream used by native backends,
NBD, debugger protocols, and VM channels. Events are immutable notifications
from VMs and protocols. `debug.select` waits across event sources without
requiring host socket access in Starlark.

`clock.monotonic()` provides high-resolution elapsed seconds through an
injectable runtime clock. A profiler records nested spans and counters and
returns structured nanosecond snapshots. `report()` rejects incomplete span
coverage by default and includes runtime source-read, decompression, final
streaming, NBD, and bounded-cache metrics. Use monotonic deadlines and timeout
helpers rather than polling wall time. Long-lived channels and protocol
sessions are registered with the current runtime and close in reverse creation
order when that runtime exits.

`runtime.stats()` reports source reads, decompression, streamed output, NBD
traffic, bounded decompression-cache use, and Go runtime memory counters. Image
recipes do not cache derived stages; use these counters and profiler spans to
make cold operations faster instead of hiding them behind retained results.

## VMM values

VMM machine, disk, network, display, and channel values describe a VM without
assuming QEMU command-line syntax. A backend validates this description and
returns a VM session. The session exposes lifecycle, input, screenshot, channel,
and debugger capabilities. Test capabilities instead of assuming a particular
backend or display frontend.

QEMU is currently the production backend. Its native process and sockets remain
behind the backend boundary; stable Starlark recipes use VMM values.

## Emulator values

`emulator.machine(image=...)` selects the execution architecture from the PE
header. Raw code accepts `architecture="x86"` or `architecture="amd64"` (the
default is x86). Both expose `architecture`, `pointer_size`, `read_pointer`, and
`write_pointer`; pointer operations use guest width, not host width. The AMD64
backend retains 64-bit virtual addresses and marshals integer/pointer calls
using the Windows x64 register, shadow-space, and stack-argument convention.
Unsupported instructions produce a structured stop rather than being skipped.

AMD64 modules keep their preferred PE base when available. Colliding modules
are placed in a free 64-KiB-aligned range and rebased using their native PE
relocation records before TLS pointers are interpreted. A collision without
valid relocation records fails the load; source file bytes remain unchanged.

The AMD64 `mappings` view returns named, sorted address ranges with their
allocation bases and effective read/write/execute permissions. Protection
changes can split a single allocation into multiple records. The view exposes
no guest bytes and modifying returned records does not alter guest mappings.
The `mxcsr` register preserves SSE control/status state across native save/load
instructions and snapshots; this does not imply floating-point execution support.

The AMD64 backend is under development; it does not yet provide the complete
x86 debugging/checkpoint API or floating-point/aggregate call marshaling.
It provides bounded PC-only traces, sampled hotspot profiles, native-width
static TLS metadata, and CPU/memory snapshots. Snapshots retain semantic
callback bindings; they do not independently clone mutable plugin state.
`local_unwind(frame, target)` executes native C termination handlers when
leaving scopes in the current AMD64 frame, then resumes the requested target.
It validates the PE function and C scope tables; cross-frame, chained, and
frame-pointer unwinds remain explicit unsupported cases. General AMD64
exception dispatch is not yet implemented. `transfer(address, stack_pointer=...)`
lets a semantic callback resume a guest continuation without performing its
ordinary function return.
`stop(reason, detail="", value=None)` is also available to active AMD64 hooks.
It returns a structured stop without returning from the guest call; `value`,
when supplied, sets the full 64-bit RAX. Resuming re-enters the stopped hook.
Empty reasons and `return`, `plugin`, and `exception` are reserved.
`arguments(count)` reads integer/pointer arguments at the current native call
boundary, combining AMD64 registers and stack slots. This supports semantic
variadic callbacks whose required argument count comes from a format string.
For bounded investigation, `run(instruction_limit=N, until=address)` stops
before the requested instruction with reason `breakpoint`, without executing
that instruction or mutating guest state. The temporary instruction limit
cannot exceed the constructor budget. Omit `until` to continue normally.

`emulator.x86` is an in-process bounded machine used for low-level executable
behavior with pluggable semantic APIs. Raw `read` and `write` transfer byte
ranges. Typed methods such as `read_u32le` and `write_u32le` access scalar guest
memory without constructing intermediate Starlark bytes. Mappings, instruction
budgets, call depth, and allocation bytes are bounded.

On the x86 backend, `machine.checkpoint()` captures CPU and mapped-memory state together with the
mutable state of installed semantic plugins and their suspended executions.
`machine.restore(checkpoint)` rewinds the same machine between calls. A
checkpoint is reusable and machine-local; restoring it preserves the identities
of plugin dictionaries and lists so installed callbacks continue to observe the
restored state. Use `snapshot()` only when an independent machine clone is
needed and no mutable plugin callback state will be resumed.
