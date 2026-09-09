# ARM64 UEFI inspection

`emulator.uefi(image, ...)` loads and relocates an ARM64 EFI PE image into an
in-process AArch64 interpreter. All image and disk inputs are TinyRangeX files;
guest memory, firmware state and disk overlays stay in memory.

This is an inspection environment under development. Instruction and firmware
coverage is incomplete. Unsupported operations stop explicitly. Native HVF
continuation, full hardware emulation and a complete firmware implementation are
not provided.

## Configuration

```python
vm = emulator.uefi(
    image,
    memory = 256 * 1024 * 1024,
    memory_base = 0x40000000,
    stack_size = 1024 * 1024,
    image_path = "\\EFI\\Boot\\BootAA64.efi",
    time_unix = 0,
    registers = {"cntfrq_el0": 1000000},
    device_path = volume_device_path,
    observe = observe,
)
```

`image_base` optionally overrides PE placement. RAM must be page aligned and
between 16 MiB and 2 GiB. The default CPU enters EL1 with an identity-mapped,
4 KiB-granule MMU, X0 containing the image handle and X1 the EFI system table.
Register overrides apply after initialization. Identification registers describe
a baseline ARMv8 CPU without optional crypto, LSE or pointer authentication.
Changing feature advertisements does not add instruction implementations.

The virtual generic counter advances once per completed instruction. `time_unix`
is its wall-clock epoch; supply `clock.unix()` explicitly for current time.

`vm.addresses` exposes RAM, image, system-table, boot-services and handle addresses.
Attach inputs with:

* `block_device(source, device_path=b"", handle=0, read_only=False,
  block_size=512, overlay_bytes=128*1024*1024)` returns a handle.
* `block_partition(parent, offset, size, device_path, handle=0)` shares the parent's
  overlay. Offsets and sizes are bytes. Attach the loaded volume using
  `handle=vm.addresses.device_handle`.
* `configuration_table(guid, data, memory_type=9)` installs a table and returns its
  guest address. Populate internal pointers using `write_memory`.
* `install_protocol(guid, data, handle=0)` installs protocol bytes and returns the
  handle. Service pointers must refer to implemented gates or guest code.
* `set_variable(name, guid, attributes, data)` configures EFI variables.

Device paths are serialized EFI device-path nodes including their end node.
ACPI tables, boot policy and hardware declarations belong to the caller.

## Execution and observation

```python
result = vm.run(
    steps = 1000000,
    stop_pcs = [],
    stop_services = ["ExitBootServices"],
    watch = [],
    trace = 32,
    timeout = 5.0,
)
print(result.reason, result.pc, result.service, result.args)
```

Step budgets apply to each call; `result.steps` is cumulative. `timeout` is in
seconds and uses the runtime's monotonic clock. Trace retains the last N executed
addresses, with a maximum of 100000. Watches are `(physical_address, byte_size,
"rwx")` tuples; any nonempty subset of access flags is accepted. A watch stops
after the instruction or firmware operation completes. Address and service stops
occur before execution. Remove the matching stop to resume.

`sample_interval=N` emits a `sample` event before every Nth execution unit,
starting with the first unit in each run. Zero disables it. Sampling retains
native rewrites, so samples describe execution units rather than the guest
instructions omitted by a rewrite. Use a bounded histogram in `plugin` for hot
addresses; `sample=4093` enables this in the inspection script. A prime interval
helps avoid aliasing short loops; this is statistical evidence, not an exact
instruction count or a wall-clock profile.

`run(translation_cache=False, decode_cache=False)` disables the two interpreter
caches independently of native rewrites. Translation results are invalidated by
guest or debugger writes to any page-table page used by a cached walk, changes
to mappings or permissions, translation-control registers and TLBI. Observing
memory adapters always walk the tables. Decode entries match the complete newly
fetched instruction word; they never replace instruction fetch or its access
checks. CPU clones discard translation dependencies.

The constructor accepts `event_kinds=["service", "console", "memory"]` to filter
events before allocating Starlark records. Omitting it observes every kind;
an empty list observes none. Filtering events does not disable watches or their
stop conditions. The inspection script keeps service, console, memory and sample
events by default; `all-events` also includes accelerator and disk events.

Results distinguish budget, timeout, cancellation, address/service stops, memory
watches, image return, unsupported services and instruction or memory faults.
`exit_boot_services` means the image called ExitBootServices with the correct
image handle and current memory-map key. The retained PC is the return address
and X0 is EFI_SUCCESS. A pre-dispatch `service_stop` alone does not prove this
transition. Further runs preserve the completed-transition result.

```python
print(vm.register("pc"))
vm.register("x0", 42)
print(vm.vector(0))                 # 16 bytes; optional second argument sets it
print(repr(vm.memory(address, 64))) # virtual addresses by default
vm.write_memory(address, data, physical=True)
print(vm.disassemble(address, 8))
vm.copy_memory(destination, source, size) # overlap-safe virtual memory move
vm.fill_memory(destination, size, 0)      # repeated byte, default zero
```

Memory reads are limited to 1 MiB and disassembly to 256 instructions per call.
Both accept `physical=True` to inspect RAM independently of guest translation.
The Go API additionally exposes address translation and typed execution options.
Bulk copy/fill validate complete ranges before writing and use bounded 64 KiB
scratch space in Go. Transfers are limited to the configured RAM size. This avoids
converting large temporary buffers through Starlark inside native callbacks.

The observer receives records containing `machine`, `kind`, `name`, `pc`,
`args`, `text`, `address`, `size`, `access` and `data`. Firmware calls, console
output, disk operations and watched accesses use this channel. Keep observations
bounded and keep mutable callback state in `event.machine.plugin`.

## Native routine rewrites

`vm.rewrite(address, size, digest, callback, name="native routine")` follows the
x86 emulator's digest-checked rewrite pattern. `digest` is the SHA-256 of the
entire routine's executable bytes. Registration rejects mismatches, and every
invocation rechecks those bytes. Changed code automatically uses the interpreter.
The callback receives the machine and returns the next guest PC; it must implement
the routine's ABI, including output memory and preserved registers. A function
rewrite can return `vm.register("lr")` after calculating its outputs with APIs
such as `crypto.hash_blocks`. Version-specific signatures belong in recipes.
Return `None` without changing guest state to decline an invocation and execute
it in the interpreter, for example when flags select an unverified variant.

Rewrites emit `accelerator` events. `run(accelerate=False)`, tracing, memory watches
and interior PC stops disable them. Each callback counts as one execution step
and virtual clock tick, so accelerated timing and instruction counts differ from
the interpreter. Callback failures stop explicitly; mutations already made remain
inspectable. Callbacks must keep their work bounded and put mutable state in
`vm.plugin`. They must also guard any algorithm tables outside the matched code.

Function-level rewrites preserve ABI-observable results rather than discarded
stack scratch or caller-saved register values. Use interpreter mode to inspect
those details. Validate rewrites against the interpreter from a shared checkpoint
before using them for boot proofs.

The Validation OS recipe supplies independently matched boot-manager and loader
SHA-256 and image-checksum rewrites using
`crypto.checksum("sum16le", data, initial=seed)`. SHA state and remainder were
compared against the real ARM64 routines for empty, partial, single and multiple
blocks; checksum comparisons covered odd/even lengths and multiple initial sums.
The checksum rewrite declines alternate flags and nonzero yield intervals.

The recipe also recognizes byte-zeroing loops, overlap-safe memory moves and
SymCrypt integer multiplication, squaring, division and Montgomery reduction.
All arithmetic is calculated using Go-backed integer operations. Montgomery
reduction preserves its in/out operand as well as the reduced output; its
constant cache lives in `plugin` and is bounded to 64 moduli. These replacements
were compared with the real ARM64 routines using 54 zero-loop, 78 memory-move,
60 Montgomery, 40 multiplication/square and 27 division cases. Comparisons cover
carry boundaries, overlap, page/chunk boundaries and preserved registers.
Both image-checksum routines were checked on 21 odd/even-length and seed cases.
Version and layout guards decline unmatched invocations. `interpreter` disables
native rewrites; `uncached` disables both interpreter caches in the script.

## Repeatable experiments

```python
vm.plugin["events"] = []
checkpoint = vm.checkpoint()
result = vm.run(steps=10000, watch=[(address, 4, "w")])
vm.restore(checkpoint)
result = vm.run(steps=10000, stop_services=["GetMemoryMap"])
vm.close()
```

Checkpoints capture CPU and SIMD/system registers, RAM, firmware allocations,
variables, protocols and shared disk overlays. Starlark checkpoints also restore
nested dictionary/list/tuple state in `plugin`, preserving container identities.
Other mutable objects and closure-hidden state are not captured. A checkpoint
belongs to its creating machine. Recreate it after changing code, inputs or
initialization. Checkpoints copy RAM, so retain only the variants needed.

The future HVF handoff must preserve CPU, page tables, RAM and device state and
provide a runtime-services bridge. Current synthetic firmware gate addresses are
interpreter dispatch points, not executable native firmware stubs.
