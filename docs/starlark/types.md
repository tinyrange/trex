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

`runtime.stage_cache()` owns immutable stage records for one Starlark runtime.
Its keys combine a source object's identity, a stage name, and explicit
hashable options. A cache hit returns the same frozen result without rerunning
the callable. No cache directory or host intermediate file is involved.

## VMM values

VMM machine, disk, network, display, and channel values describe a VM without
assuming QEMU command-line syntax. A backend validates this description and
returns a VM session. The session exposes lifecycle, input, screenshot, channel,
and debugger capabilities. Test capabilities instead of assuming a particular
backend or display frontend.

QEMU is currently the production backend. Its native process and sockets remain
behind the backend boundary; stable Starlark recipes use VMM values.

## Emulator values

`emulator.x86` is an in-process bounded machine used for low-level executable
behavior with pluggable semantic APIs. Raw `read` and `write` transfer byte
ranges. Typed methods such as `read_u32le` and `write_u32le` access scalar guest
memory without constructing intermediate Starlark bytes. Mappings, instruction
budgets, call depth, and allocation bytes are bounded.

`machine.checkpoint()` captures CPU and mapped-memory state together with the
mutable state of installed semantic plugins and their suspended executions.
`machine.restore(checkpoint)` rewinds the same machine between calls. A
checkpoint is reusable and machine-local; restoring it preserves the identities
of plugin dictionaries and lists so installed callbacks continue to observe the
restored state. Use `snapshot()` only when an independent machine clone is
needed and no mutable plugin callback state will be resumed.
