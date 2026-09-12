# trex Starlark Standard Library

## `block/devices.star`

Composable block-device policies for VMM storage and protocol exports.

### `cached`

Adds a bounded read-through cache below a writable overlay.

### `cached_working_copy`

Builds a lazy, cached, bounded writable view suitable for VM boot.

### `readonly`

Returns a read-only logical block device backed lazily by file.

### `working_copy`

Returns a bounded copy-on-write device that never changes base.

## `debug/gdb.star`

Reusable GDB inspection helpers built on the native session primitives.

### `break_on_return`

Installs a temporary breakpoint at the current stack return address.

### `breakpoints_all`

Installs corresponding points on every advertised remote thread.

### `continue_to`

Continues to one installed point and returns its self-consistent stop.

### `follow_caller_return`

Continues to the return address in the current frame-pointer chain.

### `follow_register`

Continues to an address derived from a stopped register.

### `follow_return`

Continues to the current function's stack return address plus offset.

### `follow_return_pattern`

Finds a pattern near the return PC and breaks at its selected occurrence.

### `follow_stack_read`

Reads a target relative to the stack pointer and continues to it.

### `frame_argument_value`

Reads a pointer-sized argument from the current frame pointer.

### `frame_backtrace`

Walks a bounded frame-pointer chain into address records.

### `inferior_call`

Calls a stopped inferior function and restores its registers and stack.

    Integer arguments are passed by value. Byte arguments are copied into
    temporary target stack storage and passed by pointer. The returned mapping
    contains the integer return value, stop record, scratch addresses, and the
    scratch bytes captured before restoration.

### `inspect_in_address_space`

Runs an inspection callback under a temporary CR3 value.

### `kernel_address_space`

Returns a checked kernel address-space handle.

### `pointer_chain`

Follows a pointer through a sequence of signed offsets.

### `process_address_space`

Returns a checked user address-space handle for a process record.

### `read_c_string`

Reads a bounded NUL-terminated target string.

### `read_int`

Reads one bounded integer from target memory.

### `read_process_memory`

Reads memory through a checked process directory-table base.

### `read_u16`

Reads a little-endian unsigned 16-bit integer.

### `read_u32`

Reads a little-endian unsigned 32-bit integer.

### `read_u64`

Reads a little-endian unsigned 64-bit integer.

### `read_u8`

Reads a little-endian unsigned 8-bit integer.

### `read_unicode_string`

Reads a Windows UNICODE_STRING from target memory.

### `read_utf16_c_string`

Reads a bounded NUL-terminated UTF-16LE target string.

### `read_utf16_string`

Reads a bounded UTF-16LE string with an explicit byte length.

### `remove_points_all`

Removes per-thread points and restores the selected remote thread.

### `run_to`

Continues to one temporary breakpoint, ignoring unrelated stops.

### `stack_argument`

Returns the address of a stack argument at a stop.

### `stack_argument_value`

Reads a pointer-sized stack argument at a stop.

### `step_over`

Steps one instruction, running over calls except selected direct targets.

### `step_over_many`

Selectively steps over instructions and returns accepted stop records.

### `wait_for_pc`

Waits for one exact program counter while ignoring unrelated stops.

### `wait_for_pcs`

Waits for one of several exact PCs while ignoring unrelated stops.

    `resume` controls whether the target is resumed before the first wait.  Each
    rejected stop is resumed automatically.  The stop budget prevents a noisy
    target from turning a diagnostic mistake into an unbounded trace.

### `watch_from_argument`

Installs a watchpoint relative to a pointer-valued entry argument.

### `watchpoints_all`

Installs a distinct per-thread watchpoint and restores selection.

    QEMU models hardware debug registers per vCPU. Adjacent byte addresses keep
    each remote thread's point distinct while still detecting a write to the
    watched field covered by the first `size` bytes.

### `with_address_space`

Runs callback with a temporary address-space register and restores it.

## `debug/trace.star`

Breakpoint and watchpoint orchestration expressed as session-local policy.

### `chained_return_search_watch`

Follows a return-side pattern and then collects writes at an address.

### `delayed_snapshot`

Interrupts after a selectable delay and captures a structured stop.

### `filtered_breakpoint_hits`

Collects repeated breakpoint stops accepted by a Starlark predicate.

### `follow_write`

Collects stops from a temporary data watchpoint.

### `ordered_breakpoints`

Visits addresses in order using only one active point at a time.

### `repeated_breakpoint`

Collects repeated filtered hits at one execution address.

    A raw GDB execution breakpoint stops before its instruction. Re-arm it
    after each stop so continuing cannot immediately report the same hit.

### `run_window`

Runs through incidental stops for a duration, then captures a stop.

    This is intended for noisy whole-system targets where an ordinary delayed
    snapshot would return early on the first unrelated exception.  A predicate
    can accept a stop early, and inspect_interval creates periodic stopped-state
    observations even when the target emits no events.  The stop budget bounds
    pathological targets and the result reports how many stops were resumed.

### `selective_step_trace`

Steps over calls selectively while collecting filtered stop records.

### `step_many`

Single-steps count instructions and returns every stop.

### `wait_hits`

Collects count matching stops for an installed point.

## `doc.star`

Shared documentation fixture for the embedded trex standard library.

### `identity`

Returns value unchanged; useful in module-loader examples and tests.

## `firmware/acpi.star`

Portable ACPI table construction helpers returning trex files.

### `compatible_id`

Builds an SSDT that assigns _CID on an absolute ACPI device path.

### `table`

Builds a checksummed ACPI table around a caller-supplied binary body.

## `inspect/memory.star`

Declarative, bounded structure readers over a memory image or address space.

Layouts map field names to (offset, kind, size). Kinds are uint, bytes,
cstring and unicode (a 32-bit Windows UNICODE_STRING descriptor, size 8).
Results retain only fully decoded fields/entries and an explicit fault.
Pointers are uint fields: callers choose whether and when to dereference them.

### `read_list`

Combines walk_list with a caller-supplied structure layout.

### `read_structure`

Reads named fields; never fills missing bytes or follows arbitrary pointers.

    Offsets and sizes are validated before reading. unicode validates length,
    capacity and pointer bounds, then reads precisely Length bytes as UTF-16LE.
    A partial result contains preceding complete fields, not a fabricated value.

### `walk_list`

Returns containing-object addresses from a circular doubly linked list.

    Checks reciprocal links, alignment, cycles and a hard entry bound. The head
    is a sentinel, not an object; link_offset locates its embedded LIST_ENTRY.
    Incomplete results are checked prefixes, never a claim of complete inventory.

## `inspect/snapshot.star`

Bounded filesystem and registry snapshots for focused comparisons.

### `file_snapshot`

Returns path and size facts for files below selected volume prefixes.

### `registry_snapshot`

Returns bounded raw registry state below selected roots in one hive.

### `snapshot_delta`

Returns sorted added, changed, and removed values from keyed snapshots.

## `predeclared.star`

Declares optional embedded extensions to predeclared Go namespaces.

## `qemu/profiles.star`

Typed QEMU profiles; exact device policy stays out of the VMM core.

### `dos`

Returns a minimal legacy PC profile for an installed DOS system.

### `modern_windows`

Returns a UEFI/Q35 profile with a contemporary x86-64 CPU baseline.

### `nt351`

Returns a QEMU profile compatible with Windows NT 3.51 x86.

### `nt4`

Returns a QEMU profile compatible with Windows NT 4.0 x86.

    Current KVM exposes a legacy-CPU execution path on which NT4 can stall
    before Winlogon initializes, even with the Pentium CPUID model. TCG
    preserves the execution semantics NT4 expects. Callers may still override
    this when their hypervisor has independently verified NT4 compatibility.

### `nt5`

Returns the QEMU hardware profile used by NT5 image recipes.

### `nt6`

Returns the QEMU hardware profile used by 32-bit NT6 image recipes.

### `reactos`

Returns QEMU policy matching the devices in the ReactOS image recipe.

### `windows_arm64`

ARM64 UEFI machine with inbox NVMe storage and USB input policy.

    Attach the system disk with bus="nvme". HVF uses the host ARM CPU;
    emulated runs may select accelerator="tcg", cpu="max".

## `vmm/automation.star`

Event-driven portable VM automation without implicit sleeps.

### `checkpoint`

Returns an in-memory framebuffer checkpoint as a file value.

### `click`

Sends one portable pointer click at the selected position.

### `paced_chord`

Sends a chord with explicit key transitions for legacy guest loops.

### `paced_tap`

Presses and releases one key with a guest-visible hold interval.

### `pump_events`

Dispatches VM/debugger events until a predicate accepts one.

    Each handler is selected by event kind and receives `(source, event)`.
    `until`, when supplied, receives the same pair after dispatch. The returned
    record preserves the selected source, event, and total dispatch count.

### `release_modifiers`

Idempotently releases every modifier used by the automation helpers.

### `repeat_ui`

Runs a guest UI procedure repeatedly and returns framebuffer checkpoints.

### `wait_duration`

Waits using selectable VM events while draining them deterministically.

### `wait_for_event`

Returns the first event whose kind is in kinds before timeout.

### `wait_until`

Evaluates predicate after each VM event until it returns a value.

## `vmm/lab.star`

Small helpers for focused VM work in a Starlark REPL.

The values returned here are ordinary block devices, machines, VMs, and files.
This module deliberately does not track experiment history or hide lifecycle
operations from the caller.

### `capture_after`

Drains VM events for a bounded duration and returns an in-memory PNG.

### `start`

Starts one explicit single-disk machine for focused investigation.

### `stop`

Stops a VM if needed and returns its final backend result.

### `working_copy`

Returns a bounded in-memory copy-on-write block device.

## `vmm/profiles.star`

Portable machine-profile helpers shared by VMM backends.

### `pc`

Builds a portable PC request without selecting a VMM backend.

## `vmm/smoke.star`

Framebuffer-based guest smoke automation for unmodified disk recipes.

### `case`

Returns validated, ordinary case data for a smoke suite.

### `check`

Returns one portable smoke assertion and optional evidence reference.

### `close_and_verify`

Closes the active guest window and verifies continued UI responsiveness.

### `encode_suite`

Encodes the authoritative suite model as deterministic indented JSON.

### `enter_command`

Enters a command through a supported guest shell surface.

### `frame_delta`

Returns bounded pixel-difference metrics for two framebuffer captures.

### `launch_and_capture`

Launches one guest command and captures its settled visual result.

### `media`

Declares one caller-supplied smoke input without opening it.

### `parse_suite_options`

Parses one shared name=value surface and validates selected case inputs.

### `phase`

Returns one measured phase using the caller's portable clock values.

### `render_suite`

Renders the authoritative suite value as a self-contained HTML report.

### `result`

Returns one complete case result in the authoritative schema.

### `run`

Runs selected case functions and incrementally writes JSON and HTML.

### `suite`

Validates and returns one authoritative multi-case smoke result.

### `wait_for_command_surface`

Waits for a stable guest frame, then submits the probe exactly once.

    Opening an empty command surface can be retried when it produces no visual
    response. Smoke automation never repeats the command itself after an
    ambiguous response.

### `wait_for_display_mode`

Waits for a framebuffer large enough to represent the guest UI mode.

### `wait_for_frame_match`

Waits until the framebuffer returns close to an expected frame.

### `wait_for_material_change`

Waits for a material framebuffer change which remains after settling.

    The returned dictionary always contains `passed`, `image`, `comparison`,
    and `detail`. Cursor blinking and tiny animation changes remain below the
    default changed-pixel threshold.

### `wait_for_stable_frame`

Returns after the framebuffer remains materially stable for several samples.

## `windows/certstore.star`

Native Windows SystemCertificates registry record construction.

### `certificate_store_patch`

Builds one machine SystemCertificates patch from a certificate record.

## `windows/command_line.star`

Microsoft command-line parsing shared by Windows process models.

### `command_line_arguments`

Splits a Microsoft CRT command line, including backslash-quote runs.

## `windows/emulation/abi.star`

Native-width layouts shared by Windows execution plugins.

### `counted_string_layout`

Returns native STRING/UNICODE_STRING field offsets and total size.

### `object_attributes_layout`

Returns the native OBJECT_ATTRIBUTES layout, including alignment.

### `pointer_array`

Allocates an array of guest pointers without host-width assumptions.

### `process_layout`

Returns named offsets for the modeled PEB and process-parameter prefix.

### `security_descriptor_layout`

Returns absolute native-pointer or fixed-width self-relative SD fields.

### `system_info_layout`

Returns SYSTEM_INFO fields with native pointer and affinity-mask widths.

### `teb_layout`

Returns the common NT_TIB and initial TEB pointer-field offsets.

## `windows/emulation/conformance.star`

Bounded conformance calls into Windows PE32 implementations.

This module is intentionally smaller than the Windows execution environment.
It maps target modules, installs only explicitly declared semantic imports, and
leaves every other import as the emulator's fail-on-call stub.  Callers can use
exports, ordinals, image-relative RVAs, or absolute addresses without teaching
the stable API about a particular Windows release.

### `buffer`

Describes one zero-initialized bounded call buffer.

    `value` is copied at offset zero.  `size` may reserve writable tail space.
    `expected`, when supplied, is compared with the complete buffer after the
    call.  Captured bytes are returned by `call` under the descriptor's key.

### `c_memory_bindings`

Returns declared cdecl bindings for memcpy, memmove, and memset.

    These leaf operations are useful when validating otherwise self-contained
    target algorithms.  No allocation, I/O, locale, or process behavior is
    implied, and all other C runtime imports remain fail-on-call stubs.

### `call`

Invokes one target with bounded named buffers and captures post-state.

    Pass a positional `target` address or exactly one of `name`, `ordinal`,
    `rva`, or `address`; `module` selects a mapped or semantic module.
    Arguments may contain raw integers, `pointer(name)`, or `size_of(name)`
    references. `inspect`, when
    supplied, runs before allocations are released and may return additional
    caller-defined facts.  CPU state outside the invocation is preserved.

### `output`

Describes one bounded zero-initialized output buffer.

### `pointer`

Returns an argument reference to a named call buffer and byte offset.

### `resolve`

Resolves exactly one absolute, RVA, named-export, or ordinal target.

### `run`

Runs named zero-argument conformance cases and returns their results.

### `sequence`

Invokes an ordered target sequence over shared bounded buffers.

    Each step contains `target` and optional arguments, registers,
    expected_reason, and expected_return fields.  Argument references use
    `pointer` and `size_of`.  All CPU invocations are isolated while their
    explicitly allocated memory remains shared for the complete sequence.

### `session`

Creates an isolated PE32 or raw-x86 conformance session.

    `bindings` contains mappings accepted by `emulator.x86.provide_export`:
    module plus exactly one of name/ordinal and exactly one of callback/value.
    Unbound PE imports remain lazy error stubs and therefore fail only if target
    execution calls them.  Additional PE images are mapped from `modules`.

### `size_of`

Returns an argument reference to a named call buffer's capacity.

## `windows/emulation/patterns.star`

Compact, validated executable signatures and emulator transformations.

### `code_signature`

Describes code using a short anchor and a full-region SHA-256 digest.

    Relative call and branch operands may be normalized before hashing. This
    keeps generated-code signatures stable across allocator addresses without
    weakening validation of opcodes, registers, constants, or layout.

### `executable_signature_rva`

Validates one signature match and converts it to an image RVA.

### `install_function`

Hooks one uniquely located, digest-validated executable function.

### `install_loop`

Installs one digest-validated, bounded x86 loop.

### `install_region`

Batches a digest-validated code region while preserving x86 behavior.

    Unlike a loop accelerator, a region may contain indirect internal control
    flow. Execution yields when it leaves the region or reaches its bound.

### `install_relocated_region`

Batches source-validated code after applying PE base relocations.

    The complete on-disk region is first identified by its declared digest.
    The emulator then validates the complete mapped region against a runtime
    digest derived from that trusted source mapping. No relocated code bytes
    are retained in Starlark or committed as an alternate payload.

### `install_rewrite`

Installs one digest-validated inline rewrite.

### `install_runtime_region`

Batches a digest-validated region when generated code materializes.

### `install_transform`

Installs a validated transformation for generated executable code.

### `module_base`

Finds one mapped module base by case-insensitive name.

### `module_source`

Finds one module image by case-insensitive basename.

### `unique_executable_signature_rva`

Returns the RVA of exactly one validated executable match, or `None`.

## `windows/emulation/rpc.star`

In-memory Windows RPC runtime and semantic proxy registration.

This module models the public NdrDllRegisterProxy contract. It parses the
MIDL-generated ProxyFileInfo tables already mapped in the target DLL and emits
registry operations; RPCRT4 itself is never loaded or executed.

### `rpc_plugin`

Provides semantic NdrDllRegisterProxy registration.

    The limits bound pointer-table traversal independently of emulator memory
    permissions. Malformed target structures fail closed through machine.read.

### `rpc_proxy_plugin`

Provides semantic NdrDllRegisterProxy registration.

    The limits bound pointer-table traversal independently of emulator memory
    permissions. Malformed target structures fail closed through machine.read.

## `windows/emulation/runner.star`

Composable execution of Windows PE modules with semantic system APIs.

### `run`

Runs one target export or executable using semantic system-DLL plugins.

    `prepare(machine)` may allocate target memory and return the integer
    arguments passed to one export. `execute(machine)` may instead make a
    stateful sequence of calls on the configured machine. These keep
    command-specific marshaling in Starlark while preserving the bounded
    emulator and plugin policy here. `files` supplies memory-backed guest
    paths to target file APIs; no host staging is performed. Modules named in
    `deferred_modules` are mapped but skip eager process attach. Their private
    import graph is initialized lazily if COM or SCM activates the module.
    Set `executable` when the primary image is a process: dependency DLLs still
    receive process attach, but the PE entry point is not called as DllMain.
    `command_line` is returned by both GetCommandLine variants. `environment`
    augments a minimal standard Windows process environment and may override
    any of its values. Each `plugin_factories` callback runs after the core
    runtime plugins are constructed and receives a record containing `crt` and
    `module_files`; it must return one emulator plugin. This lets callers add
    semantic system APIs without coupling the public runner to target policy.
    `generated_entries` retains newly created or changed files and directories
    as path-keyed records with `directory`, file `data`, and optional DOS
    `attributes` and owned self-relative `security` bytes. `generated_files`
    is the content-only compatibility view; use entries to preserve metadata.

## `windows/identity.star`

Generic Windows machine identity policy composed from crypto primitives.

### `machine_identity`

Builds a deterministic Windows machine SID and identity hive patches.

## `windows/installer.star`

Portable analysis of Windows installer plans and packaged PE side effects.

### `analyze`

Analyzes script, driver, custom-DLL, and self-registration effects.

    Every input and dependency remains a trex file. Registration exports
    run in the bounded in-memory x86 emulator with semantic Win32 APIs; no
    payload is staged on the host and no native installer code is launched.

### `installer`

Returns declarative modifications and requirements for one installer.

    The result contains no host paths or staged files. Package members remain
    trex files and can be applied directly while an image is assembled.

## `windows/kd.star`

Windows KD event and inspection policy over the native transport session.

### `break_on_module`

Installs a breakpoint relative to one load-symbols event.

### `continue_until`

Continues state changes until predicate accepts an event.

### `delayed_breakin`

Requests a KD break-in after a selectable delay unless an event arrives first.

### `pointer_chain`

Follows kernel pointers through signed offsets.

### `read_int`

Reads a little-endian integer from kernel virtual memory.

### `read_u32`

Reads a little-endian kernel uint32.

### `wait_for`

Returns the next KD event whose kind is selected.

### `wait_for_exception`

Waits for a kernel exception state change.

## `windows/memory.star`

Read-only NT x86 inventories with caller-supplied, build-qualified layouts.

All results use {value, complete, fault}; incomplete values are checked prefixes.
No offsets are guessed, and no absent pages are synthesized. Layouts are the
same field dictionaries used by inspect/memory.star. See docs/starlark/memory.md.

### `read_drivers`

Reads the kernel loader list (including kernel/HAL, not just .sys files).

    Required fields: base and size (uint). Names/paths are caller layout fields.
    By default adds per-entry pe results for resident DOS/PE32 headers and size,
    accepting exact or page-rounded loader sizes. Top-level complete describes
    the loader inventory; pe.complete separately describes header checks, not file hashes,
    signatures or module trust. A mapped image is not an on-disk PE file.

### `read_file_handles`

Filters handle records by object type name File before reading FILE_OBJECT.

    header_layout needs uint field type; type_layout needs unicode field name;
    file_layout needs uint field type (IO_TYPE_FILE=5), and may include name,
    device, related_file, flags and size. Names are raw FILE_OBJECT names, not
    canonical DOS paths; unnamed files and device/relative names are preserved.
    Access masks stay raw. No file contents or credential material is read.

### `read_handle_table`

Reads XP-style 0/1/2-level handle tables, preserving handle aliases.

    Required uint fields: table_code, next_handle, count. TableCode uses its low
    two bits as level, 4 KiB pages, 4-byte directory pointers and 8-byte entries.
    Handles have stride four; zero is reserved. Free entries have a zero object
    word. Object-header pointers mask the low three attribute/lock bits. This
    encoding is not the encoded handle representation of newer Windows kernels.
    maximum bounds examined slots, including free entries, not just live handles.

### `read_threads`

Reads an ETHREAD list and checks owner IDs, unique TIDs and optional count.

    Required uint fields: pid, tid. Extra caller fields such as start_address,
    state or TEB are retained without interpreting build-specific enums.

### `read_vads`

Walks an NT x86 VAD binary tree, returning half-open byte ranges.

    Required uint fields: left, right, parent, start_vpn, end_vpn. Additional
    caller fields (for example raw flags) are retained. Parent pointers must be
    untagged, the root parent zero, and VPN intervals ordered and nonoverlapping.
    This reads the XP-style tree, not later balanced-root sentinel structures.

## `windows/memory_context.star`

Context and content recovery from NT x86 memory, with explicit layouts.

These readers preserve per-artifact faults. Offsets, flag encodings, roots and
context seeds must come from the captured build, not a guessed Windows version.

### `describe_vad`

Adds private/mapped, protection and backing-file evidence to one VAD.

    flags supplies private_bit, protection_shift, protection_mask, protections
    (numeric-code to descriptive value), and control_area_offset. Private VADs
    never read a long-VAD control-area field. control_layout requires file;
    file_layout describes FILE_OBJECT fields, conventionally type and name.
    Region permissions are allocation metadata, not CPU page-table permissions.

### `module_at`

Returns every covering module and RVA; overlapping evidence is not hidden.

    modules is a list of dictionaries with base, size and optional name/path.
    An empty list means unattributed, not proof of suspicious executable memory.

### `read_cache_views`

Reads a flat XP VACB pointer array into file-offset/memory mappings.

    Shared-cache fields: file_size (uint64), vacbs (pointer). VACB fields: base,
    owner, offset (uint64); low view-size bits of offset include active-count
    metadata and are masked. Owner and slot offset must agree. Null VACBs are
    explicit uncached ranges. Caller must select a verified flat-array layout;
    multi-level VACB trees are not interpreted by this reader.

### `read_endpoints`

Reads an explicitly rooted IPv4 endpoint hash table with singly linked buckets.

    Layout requires next, pid (uint), local_address (4 bytes), local_port
    (2 network-order bytes); optional remote fields use the same encodings.
    Protocol/state fields are retained raw. This is a table reader, not a pool
    signature scan or automatic tcpip.sys version detector. Zero buckets with
    a null root describe an uninitialized table, not proof of no network use.

### `read_key_path`

Reads registry KCB ancestors and compressed/uncompressed name blocks.

    layout requires parent and name pointers. name_layout requires compressed
    and length; name_offset locates inline bytes. No registry values are read.
    Returned components are leaf-to-root so a partial path cannot look absolute.

### `read_object_handles`

Reads all handle types with optional named, type-specific body fields.

    Header fields: type and name_offset (backward offset to optional name info).
    Type fields: name. Name-info layout normally includes unicode name and
    directory pointer. Names are object-manager components, not full paths.
    body_layouts maps exact type names to declarative fields; unknown types
    remain in the inventory. Each name/body has its own result and fault.
    Registry keys need their KCB path, not just an object-manager name. Named
    pipes are File objects; retain device/name evidence, not a guessed subtype.

### `read_object_path`

Walks named object-manager directories, returning leaf-to-root components.

    header_layout requires name_offset; name_layout requires directory and name.
    Directory pointers address object bodies. An unnamed object or missing
    ancestor returns a partial result, never an invented absolute path. Useful
    for events, sections and file device names such as Device/NamedPipe.

### `read_process_context`

Reads parent/create-time metadata and PEB process parameters separately.

    process_layout requires peb; other fields such as parent_pid/created are
    caller-defined. peb_layout requires parameters. parameter_layout requires
    flags and may contain unicode command_line, image_path and directory fields.
    FILETIME values remain raw 100 ns ticks. PIDs are not durable identities.
    Relative UNICODE_STRING buffers are resolved for unnormalized parameters.

### `read_relative_unicode`

Decodes a 32-bit UNICODE_STRING with an explicit buffer-pointer bias.

### `read_thread_context`

Reads thread state/start attribution and a bounded trap-seeded EBP chain.

    Thread fields: state, start, trap, teb, stack_limit, stack_base; optional
    win32_start is also attributed. Trap fields: eip, ebp, cs, esp. TEB fields:
    stack_limit/stack_base. User-mode traps select process memory and TEB bounds;
    kernel traps select kernel memory and KTHREAD bounds. A saved trap context
    is not necessarily the running thread's current CPU state. Stack failure
    leaves readable thread metadata intact with its own result.

### `recover_cached_file`

Returns resident bytes as offset-tagged extents plus explicit missing ranges.

    Never fills gaps with zeros or falls back to disk. Reading is page-bounded
    so later resident pages survive an earlier fault. Only complete contiguous
    recovery returns file bytes; partial recovery returns data=None and extents.
    This is a current memory view, not necessarily the durable on-disk version.

### `walk_frames`

Walks a conventional x86 EBP chain within caller-proven stack bounds.

    Records saved return addresses, not arbitrary stack words. This is not an
    FPO/optimized-code unwinder. Null ends the chain; bounds, nonmonotonic links,
    missing pages or the frame limit stop it explicitly. Unmapped module names
    do not erase frames. A complete chain is not proof of a complete call stack.

## `windows/process.star`

Offset-driven Windows process and PEB traversal for debugger scripts.

### `amd64_physical_address`

Translates one canonical amd64 address through target page tables.

### `eprocesses`

Reads EPROCESS facts through KD or GDB using supplied offsets.

### `find_eprocess`

Finds one process by image name or PID in a bounded EPROCESS walk.

### `find_process_module`

Finds one case-insensitive module name in a process PEB loader list.

### `find_process_module_amd64`

Finds one case-insensitive module in an amd64 process loader list.

### `i386_physical_address`

Translates one bounded i386 virtual address through target page tables.

### `install_amd64_process_breakpoint`

Installs one debugger-owned INT3 in a selected amd64 process.

### `install_process_breakpoint`

Installs one debugger-owned INT3 in a selected i386 process.

### `nt61_x86_eprocess_offsets`

Returns the checked Windows 7 SP1 x86 EPROCESS layout.

    The layout is deliberately build-qualified.  Callers inspecting another
    kernel must supply offsets derived from that kernel instead of silently
    reusing this profile.

### `nt_x86_debugger_state`

Reads the x86 KPCR debugger-version record from a stopped target.

    NT keeps a pointer to DBGKD_GET_VERSION64 at KPCR offset 0x34 even for an
    x86 kernel.  The record is a stable source of the ASLR kernel base and the
    two debugger-owned kernel lists; unlike an interrupted PC, it is not
    affected by which driver happened to be executing when the VM stopped.

### `pe_export_rva`

Resolves one named PE export RVA, rejecting absent or duplicate names.

### `peb_modules`

Reads a user PEB loader list while restoring the debugger's CR3.

### `process_image_base`

Reads PEB.ImageBaseAddress in an EPROCESS address space.

### `process_list_head`

Derives PsActiveProcessHead from PsInitialSystemProcess and a layout.

### `process_list_head_from_kernel`

Derives PsActiveProcessHead using the boot kernel's actual PE exports.

### `process_modules`

Reads one process's bounded PEB loader list through KD physical memory.

### `process_modules_amd64`

Reads one amd64 process's bounded PEB loader list through page tables.

### `read_amd64_process_virtual`

Reads one amd64 process using an EPROCESS-derived page-map base.

### `read_amd64_virtual`

Reads one amd64 process address space through KD physical memory.

### `read_i386_virtual`

Reads one i386 process address space through KD physical memory.

### `read_process_virtual`

Reads i386 user memory using an EPROCESS-derived address space.

### `rearm_process_breakpoint`

Reinstalls a previously restored debugger-owned process breakpoint.

### `restore_process_breakpoint`

Restores a process breakpoint's original instruction byte once.

### `wait_for_eprocess_insertion`

Waits for a process-list insertion and returns the selected EPROCESS.

    The active process list's tail pointer changes while a process is inserted,
    before its initial user thread can execute.  Watching that pointer avoids
    races inherent in periodically interrupting a fast whole-system target.

### `wait_for_process_peb`

Waits until a newly inserted EPROCESS receives a non-NULL PEB.

### `walk_linked_list`

Walks a bounded circular LIST_ENTRY and returns containing addresses.

### `write_amd64_process_virtual`

Writes one amd64 process using an EPROCESS-derived page-map base.

### `write_amd64_virtual`

Writes one amd64 address space through KD physical-memory operations.

### `write_i386_virtual`

Writes one i386 address space through KD physical-memory operations.

### `write_process_virtual`

Writes bounded i386 user memory using an EPROCESS address space.

## `windows/reactos/image.star`

Constructs a complete ReactOS image in memory from original media.

### `reactos_disk`

Builds a lazy installed ReactOS disk from its ISO, ZIP or 7z media.

## `windows/reactos/media.star`

Original-media discovery and installed-file destinations.

### `base_name`

Returns the final slash-separated media filename.

### `copy_cab_from_inf`

Populates installed files and their declared directories from a CAB.

### `copy_iso_files`

Copies the selected setup directory, excluding explicitly skipped names.

### `destination_map`

One authoritative INF destination map for copying and registration.

### `installed_files`

Maps installed image paths to lazy CAB files using the INF destinations.

### `reactos_media`

Selects the unique ISO from original ZIP/7z media or accepts a raw ISO.

## `windows/reactos/profiles.star`

User-profile layout and locale defaults.

### `add_profile_skeleton`

Builds each declared profile from one directory and hive specification.

### `international_profile_patches`

Returns the default English locale and keyboard preferences.

### `mkdir_tree`

Ensures all ancestors of an image directory exist.

### `profile_hive`

Builds a user hive with profile-relative shell folders and locale policy.

## `windows/reactos/registry.star`

ReactOS registry, hardware and offline registration policy.

### `add_txtsetup_services`

Appends boot-driver service policy from one TXTSETUP section.

### `font_file_registry_patches`

Registers the installed font filenames and decoded font names.

### `mirror_numbered_control_sets`

Returns patches mirrored into inactive, physically stored control sets.

    CurrentControlSet is a runtime registry symbolic link and must never be
    materialized in a SYSTEM hive. The kernel creates it from the Select key
    after mounting the selected numbered control set.

### `network_system_patches`

Returns the tested QEMU adapter and TCP/IP registry policy.

### `reactos_base_patches`

Returns explicit boot and machine-identity policy for generated hives.

### `register_shell`

Executes media exports in-process and applies their effects before boot.

### `selfreg_software_patches`

Applies static registration resources selected by INF registration bits.

### `setup_shell_namespace_patches`

Returns the desktop namespace policy needed by the ReactOS shell.

### `shell_registration_actions`

Selects the shell registrations needed in addition to static resources.

### `software_build_patches`

Combines static registration, font and workstation SOFTWARE policy.

### `software_patches`

Returns workstation shell, autologon and standard-profile defaults.

### `txtsetup_system_patches`

Derives boot services and hardware matches from the setup media.

### `video_system_patches`

Describes the tested QEMU Bochs graphics device and driver.

## `windows/reactos/security.star`

Declarative ReactOS account and local-security policy, without hive templates.

### `security_database`

Builds SAM/SECURITY from account records; no host paths or seed templates.

### `workstation_security`

Returns mutable, explicit defaults; customize this record before building.

## `windows/reactos/shortcuts.star`

INF-declared shortcuts and installed-file lookup.

### `add_shortcuts_from_inf`

Constructs shell links from media declarations for the selected user.

### `expand_shortcut_path`

Expands the media shortcut variables for the selected user.

### `installed_file_size`

Returns the size of a CAB-backed installed file, or zero if absent.

### `installed_windows_path`

Looks up the first installed Windows path for a media filename.

### `safe_shortcut_name`

Replaces characters that cannot occur in a Windows shortcut filename.

### `shortcut_folder_path`

Resolves an INF shortcut folder ID for the selected user.

### `shortcut_int`

Decodes the small icon-index range used by the media shortcut policy.

### `shortcut_rows`

Normalizes repeated INF shortcut rows without losing their order.

### `windows_base_name`

Returns the final backslash-separated filename.

## `windows/security.star`

Windows registry-key, SID, ACL, ACE, and security-descriptor primitives.

### `access_allowed_ace`

Returns an ACCESS_ALLOWED_ACE for principal.

### `acl`

Returns an ACL containing aces.

### `des_56_key`

Expands seven key bytes into a DES key with odd parity.

### `legacy_lsa_secret_crypt`

Applies the legacy LSA rolling-DES transform to whole blocks.

### `mandatory_label_ace`

Returns a SYSTEM_MANDATORY_LABEL_ACE for an integrity-level SID.

### `registry_boot_key`

Decodes the four obfuscated LSA registry classes into a boot key.

### `registry_boot_key_classes`

Encodes a 16-byte boot key into its four obfuscated registry classes.

### `sddl_security_descriptor`

Encodes an SDDL security descriptor without host operating-system APIs.

### `security_descriptor`

Returns a revision-1 self-relative security descriptor.

### `security_descriptor_components`

Returns the components of a self-relative security descriptor.

### `sid`

Returns a revision-1 SID.

## `windows/selfreg/advpack.star`

Semantic ADVPack registration services for embedded REGINST resources.

### `advpack_plugin`

Implements RegInstall directly from a loaded module's REGINST data.

    The embedded INF stays in memory throughout parsing, substitution, and
    registry application. This avoids running ADVPack as an image-building
    helper while preserving the selected section and caller-supplied string
    table semantics.

## `windows/selfreg/appmodel.star`

Windows application-model identity semantics for unpackaged processes.

### `appmodel_plugin`

Reports the ordinary absence of package identity for desktop binaries.

## `windows/selfreg/cabinet.star`

In-memory Cabinet.dll extraction services for setup-time execution.

### `cabinet_plugin`

Provides FDI extraction over native CAB files in the virtual file view.

## `windows/selfreg/comcat.star`

Semantic Component Categories Manager used by setup-time registrars.

### `component_categories_provider`

Returns a native ICatRegister provider backed by the live registry.

## `windows/selfreg/common.star`

Shared registry-patch and Windows path helpers for self-registration.

### `coalesce`

Keeps only the final registry operation for each hive, key, and value.

### `deduplicate`

Removes byte-for-byte equivalent registry operations while preserving order.

### `expand`

Expands percent-delimited registration variables to a fixed point.

### `expand_environment`

Expands case-insensitive percent-delimited process environment names.

### `module_parts`

Returns the normalized module path, directory, basename, and stem.

### `module_replacements`

Returns conventional registration-resource substitutions for a module.

### `patch`

Builds one registry patch in the format accepted by windows.hive().

## `windows/selfreg/crypto.star`

Semantic CryptoAPI and WinTrust registration contracts.

The plugin consumes public registration structures passed by a target export.
It does not execute CRYPT32 or WINTRUST implementation DLLs.

### `crypto_registration_plugin`

Models WinTrust action, default-usage, SIP, and OID registration.

### `cryptoapi_plugin`

Models bounded legacy CryptoAPI provider contexts.

    Verification contexts are process-local handles. Random output is derived
    deterministically from the provider facts and a monotonic counter so
    emulation remains reproducible; it is not exposed as a cryptographic host
    randomness service.

    RC4 key derivation supports explicit 40–128-bit lengths and the exportable
    flag, using the leading hash bytes and finalizing the hash. Provider-default
    lengths, salt policies, and other derived ciphers fail explicitly.

    Process-local RtlEncryptMemory/RtlDecryptMemory use an opaque, per-plugin
    128-bit key and XTEA blocks. This models their in-process reversible-memory
    contract, not interoperability with a Windows kernel's private ciphertext.
    The default key is random; tests may supply a 16-byte key. Cross-process,
    logon-session and system-only protection require an execution-domain model
    and currently return STATUS_NOT_SUPPORTED, never successful plaintext.

## `windows/selfreg/exception.star`

Compiler exception and local-unwind semantics for bounded execution.

### `exception_plugin`

Dispatches RaiseException through active compiler SEH3 scope tables.

    x86 uses the registration-chain contract. AMD64 supports same-frame local
    C-scope unwinds, including native termination calls; general exception
    dispatch and unsupported frame layouts fail closed.

## `windows/selfreg/facts.star`

Static COM facts derived from generic PE, binary, and x86 primitives.

### `class_ids`

Finds classes served by a 32-bit PE's DllGetClassObject implementation.

    This mirrors common compiler output without interpreting the function: the
    generic disassembler identifies direct factory calls and immediate GUID
    references, while all COM knowledge stays here.

### `export_rva`

Returns a named export RVA, or zero when it is absent.

### `guid`

Formats a 16-byte little-endian Windows GUID.

### `guid_bytes`

Encodes a canonical textual GUID as its 16-byte Windows representation.

### `pointer_string_table`

Returns the longest aligned PE pointer table naming bounded ASCII strings.

    The suffix is a caller-owned policy filter. Pointers and strings must both
    resolve inside raw PE sections, and path-like values are rejected so a DLL
    dependency table cannot be confused with arbitrary text.

## `windows/selfreg/loadperf.star`

Performance counter registration backed by generated in-memory files.

### `loadperf_plugin`

Models LoadPerf registration without a host filesystem or process.

## `windows/selfreg/mmc.star`

Static MMC snap-in registration derived from console and PE facts.

### `mmc_registration_patches`

Registers candidate snap-ins whose class GUIDs occur in the target PE.

## `windows/selfreg/msxml.star`

Bounded semantic MSXML DOM interfaces backed by `binary.xml`.

### `msxml_dom_provider`

Returns a pluggable COM provider for MSXML DOM document classes.

## `windows/selfreg/plugins.star`

Composable import-hook plugins for Windows self-registration emulation.

This module defines composition and calling-convention policy in Starlark. The
x86 execution loop, PE mapping, memory safety, and budgets remain generic Go.

### `import_plugin`

Builds a plugin from declarative import bindings.

    Each binding is a dict containing callback and optional module, name,
    ordinal, argc, and convention fields accepted by emulator.x86.hook().

### `override_plugin`

Replaces or wraps installed semantic methods without repeating their ABI.

    Install after the base plugins. Each binding supplies callback, module,
    exactly one name/ordinal, and optional wrap. Wrappers receive
    (event, previous), where previous(event) calls the preceding callback.
    Put mutable callback state in state for checkpoint/restore.

### `successful_imports`

Builds a deterministic plugin whose selected imports return success.

## `windows/selfreg/policy.star`

High-level, data-first Windows self-registration policy.

### `registration_patches`

Returns registry patches for one PE without loading system DLL images.

    Structured resources and static PE facts are preferred. The bounded native-architecture
    runner fills missing behavior and resolves Active Scripting language aliases
    and primary classes. Its writes require success, except for
    completed HKCR writes guarded by static class metadata when a registrar
    reports the aggregate SELFREG_E_CLASS result.

## `windows/selfreg/reginst.star`

Registration policy for PE REGINST resources.

### `reginst_registration_patches`

Parses install-style AddReg sections embedded in REGINST resources.

### `reginst_resource_patches`

Parses one textual REGINST resource into registry operations.

## `windows/selfreg/registry.star`

Registry API plugin for deterministic Windows self-registration emulation.

### `registry_plugin`

Returns a registry plugin initialized from hive-style dictionaries.

    Initial values are queryable but are not reported as writes. Each value uses
    the same `hive`, `key`, `name`, `type`, and `value` fields as a hive patch.
    Initial keys use `hive` and `key`; they make empty setup-created namespaces
    observable without being reported as writes. `hives` may map hive names to
    parsed `windows.hive` objects; these are consulted lazily and overridden by
    explicit keys, values, and subsequent writes.

## `windows/selfreg/rpcrt.star`

Compatibility facade for the neutral Windows RPC emulator.

### `rpc_plugin`

Provides semantic NdrDllRegisterProxy registration.

    The limits bound pointer-table traversal independently of emulator memory
    permissions. Malformed target structures fail closed through machine.read.

### `rpc_proxy_plugin`

Provides semantic NdrDllRegisterProxy registration.

    The limits bound pointer-table traversal independently of emulator memory
    permissions. Malformed target structures fail closed through machine.read.

## `windows/selfreg/runner.star`

Compatibility facade for the neutral Windows PE execution environment.

### `run`

Runs one target export or executable using semantic system-DLL plugins.

    `prepare(machine)` may allocate target memory and return the integer
    arguments passed to one export. `execute(machine)` may instead make a
    stateful sequence of calls on the configured machine. These keep
    command-specific marshaling in Starlark while preserving the bounded
    emulator and plugin policy here. `files` supplies memory-backed guest
    paths to target file APIs; no host staging is performed. Modules named in
    `deferred_modules` are mapped but skip eager process attach. Their private
    import graph is initialized lazily if COM or SCM activates the module.
    Set `executable` when the primary image is a process: dependency DLLs still
    receive process attach, but the PE entry point is not called as DllMain.
    `command_line` is returned by both GetCommandLine variants. `environment`
    augments a minimal standard Windows process environment and may override
    any of its values. Each `plugin_factories` callback runs after the core
    runtime plugins are constructed and receives a record containing `crt` and
    `module_files`; it must return one emulator plugin. This lets callers add
    semantic system APIs without coupling the public runner to target policy.
    `generated_entries` retains newly created or changed files and directories
    as path-keyed records with `directory`, file `data`, and optional DOS
    `attributes` and owned self-relative `security` bytes. `generated_files`
    is the content-only compatibility view; use entries to preserve metadata.

## `windows/selfreg/script.star`

Static Active Scripting COM registration policy.

### `script_engine_patches`

Returns static COM registration for an Active Scripting engine PE.

### `script_engine_registry_patches`

Builds Active Scripting registry policy from already-derived facts.

## `windows/selfreg/script_component.star`

Declarative registration for Windows Script Component (WSC) files.

### `script_component_registration_patches`

Returns COM registration declared by every component in a WSC package.

    The output mirrors the script-component registrar while keeping the XML
    payload and registry construction in memory. `module` and `server` are
    absolute guest paths to the WSC file and script component runtime.

## `windows/selfreg/service.star`

Service Control Manager semantics for setup-time PE execution.

### `service_manager_plugin`

Models SCM configuration and registry-directed service activation.

    Local COM servers hosted by a service are resolved through CLSID/AppID and
    the service's `ServiceDll`/`ServiceMain` values. The selected target module
    remains an in-memory PE mapped by the caller; no host process is launched.

## `windows/selfreg/setupapi.star`

SetupAPI services used by setup-time module execution.

### `setupapi_plugin`

Models INF access, install sections, queues, and process-local logging.

    `infs` maps explicit integer HINF values to parsed `windows.inf` objects.
    File operations stay inside the supplied virtual kernel backend and
    registry sections are applied through the live registration model.

## `windows/selfreg/typelib.star`

Registry policy for MSFT type libraries exposed by windows.pe().

### `typelib_patches`

Builds registry operations from parsed type-library facts.

### `typelib_registration_patches`

Registers referenced or self-registering embedded MSFT type libraries.

## `windows/selfreg/wer.star`

Process-local Windows Error Reporting registration semantics.

### `wer_plugin`

Models WER's in-process registration surface without reporting externally.

## `windows/selfreg/win32.star`

Small composable Win32 API models used by registration-time execution.

### `com_plugin`

Models COM registration APIs as explicit registry writes.

### `common_controls_plugin`

Models registration-time COMCTL32 controls and headless property sheets.

### `environment_plugin`

Models a mutable Win32 environment.

    `system_time` is a portable Unix timestamp used to initialize the
    KUSER_SHARED_DATA wall clock visible to native code.

### `event_log_plugin`

Models registration-time Event Log and disabled ETW providers.

### `gdi32_plugin`

Models registration-visible GDI stock objects without a host display.

### `kernel32_plugin`

Models deterministic allocation, strings, paths, files, and OS facts.

    `files` maps guest paths to bytes or trex files. They are made
    available directly to target file APIs without host filesystem staging.
    `directories` supplies empty or otherwise implicit guest directories.
    `on_thread_create(event, thread)` may schedule the captured start routine
    using emulator control APIs; no host thread is created implicitly.
    `on_system_query(machine, query)` may inspect one live, bounded diagnostic
    query and return a compact observation for the plugin state.
    `system_query_provider(machine, query)` may return a response containing
    `status`, `required_length`, optional `short_status`, and optional `data`.
    Returning `None` delegates to the built-in deterministic system facts.
    `system_time` is a portable Unix timestamp used by the Windows wall-clock
    APIs. Its default preserves the historic deterministic 2000-01-01 value.

### `lz32_plugin`

Models the memory-backed LZ file-handle APIs used by setup helpers.

### `msvcrt_plugin`

Models CRT memory, strings, locale data, and guest-backed streams.

### `netapi_plugin`

Models local group membership over the emulated account database.

### `ole32_plugin`

Models allocation, initialization, GUIDs, and class factories.

    `on_class_registration(event, registration)` may inspect a service class
    registration and use the emulator control APIs to delimit service startup.

### `oleaut_plugin`

Models bounded Automation values and explicit type-library actions.

    `type_libraries` maps installed Windows paths to in-memory files. Loading a
    type library not present in that mapping fails closed.
    `registered_type_libraries` contains parsed `library` facts and their
    installed `path`, allowing LoadRegTypeLib to resolve without a host registry.

### `permissive_import_plugin`

Returns zero from explicitly declared imports; undeclared calls fail closed.

### `resource_plugin`

Exposes immutable PE resources, selected by live module handles.

    `module_files` may be extended after plugin installation when the emulated
    loader maps a DLL lazily. Resource tables are parsed on first use so a
    LoadLibrary/FindResource sequence observes the same module state as NT
    without eagerly parsing every DLL available to the process.

### `security_plugin`

Models an elevated interactive token for setup-time Win32 checks.

### `shell32_plugin`

Models the process-local shell change-notification registrations.

### `shell_plugin`

Models the bounded SHLWAPI compatibility wrappers used by registrars.

### `user32_plugin`

Models resources, bounded formatting, and a deterministic message queue.

    String-table resources follow the live loader state. `module_files` may be
    extended after installation when LoadLibrary maps a DLL lazily.

### `userenv_plugin`

Models portable user-profile directory and environment APIs.

### `version_plugin`

Serves immutable PE version resources through the Win32 version API.

### `virtual_file_entries`

Prepares immutable guest file metadata for repeated process models.

### `winsock_helper_plugin`

Models opaque Winsock handle-context tables used by ws2_32.

### `winsock_plugin`

Models stable Winsock 1.1 ordinals shared by wsock32 and ws2_32.

## `windows/symbols.star`

Module tracking and PDB resolution policy for Windows debugger scripts.

### `add_pdb`

Associates a parsed PDB with a module basename.

### `add_pe`

Adds a loaded PE image and its exports to resolver state.

### `canonical_address`

Collapses a KD sign-extended 32-bit address without changing 64-bit addresses.

### `kernel_module`

Returns the first loaded preferred kernel module.

### `locate`

Returns module and nearest-symbol facts for a virtual address.

### `module_name`

Returns a lowercase basename for a Windows module path.

### `state`

Creates mutable resolver state owned by one script/session.

### `update`

Applies one KD load/unload event to resolver state.

## Native namespaces and values

### `auto`

`auto(source, name='', maximum=512MiB, maximum_entries=100000, maximum_depth=32) -> auto`

Wraps a byte view, file, bytes value or existing filesystem in a lazy standardized Go node view. Registered format detectors inspect a bounded prefix and confirm the format through native parsers. Container paths resolve recursively while file preserves the original bytes.

### `bytes_concat`

`bytes_concat(parts) -> bytes`

Materializes a list of binary values into one bytes value, preserving order. Use binary.concat when a lazy file composition is preferable.

### `digest`

`digest(value, algorithm='sha256') -> bytes`

Hashes a file, string or bytes value and returns raw digest bytes, not hexadecimal text. The default algorithm is SHA-256.

### `directory`

`directory() -> directory`

Creates an empty, mutable in-memory directory tree. Add files and metadata to it before passing it to a filesystem image builder.

### `error`

`error(message)`

Stops evaluation with the supplied error message. Use testing.attempt when a caller needs to inspect an expected failure.

### `help`

`help(value=None) -> None`

Prints runtime help for a value, or an overview of available globals when no value is supplied. Returns None and does not modify the inspected value.

### `hex`

`hex(value, width=0) -> string`

Formats an integer as signed, 0x-prefixed hexadecimal text with optional digit padding. For file, string or bytes input, returns the raw bytes as unprefixed hexadecimal text; width applies only to integers.

### `mirror_file`

`mirror_file(urls, cache, key, sha256='', size=-1, maximum=64GiB, timeout=3600, retries=0) -> file`

Opens a cached download or tries the supplied mirror URLs, checking the requested size and SHA-256 when supplied. The cache and key identify persistent native-backend storage; the result is a file, not extracted contents.

### `open`

`open(name) -> file`

Opens a host-backed file for reading through the native storage backend. This is an explicit host-path boundary; portable format APIs consume the returned file.

### `repl`

`repl() -> None`

Enters the interactive Starlark prompt using the current runtime. Useful for retaining parsed inputs or a VM while running bounded experiments.

### `stdout`

`stdout(value) -> None`

Writes the supplied value to the runtime's standard output and returns None. It does not create a named file.

### `write`

`write(name, value, max_bytes=64GiB) -> None`

Writes a binary value to the named host output file, subject to max_bytes. This materializes an explicit output; use in-memory files to connect construction stages.

### `archive.adcr`

`archive.adcr(file, dictionary=None, maximum_decoded_bytes=256MiB) -> file`

Decodes Aladdin ADCR01 and ADCR03 resources to in-memory files. Both validate the header, 24-bit decoded size, copy ranges and complete compressed-byte consumption. Version1 validates its additional stored-length framing and decodes control words with a 4096-entry phrase table and rolling insertion counter. Its optional dictionary supplies the first 18 bytes as an initial seed phrase; unobserved framing flags are rejected. Version3 validates recursively encoded Huffman tables and uses the last 65535 dictionary bytes as preceding history. Missing referenced history is always an error, never zero-filled. maximum_decoded_bytes bounds output and stored payload bytes. These wrappers have no checksum; verify decoded structures or independent hashes. The decoder never locates or executes loader code or selects an installation variant. Other ADCR versions remain unsupported.

### `archive.ar`

`archive.ar(file, maximum_entries=1M, maximum_metadata=64MiB) -> ar`

Parses a Unix ar archive and returns ordered member metadata and file views. find(name, occurrence) distinguishes duplicate member names.

### `archive.arsenic`

`archive.arsenic(file, maximum_decoded_bytes=256MiB, maximum_block_bytes=16MiB) -> file`

Decodes one raw StuffIt method-15 fork, not a StuffIt container. Reconstructs adaptive arithmetic-coded MTF tokens, reverses BWT and optional block randomization, expands final runs, and validates the in-stream IEEE CRC32 for nonempty streams before returning an immutable in-memory file. maximum_decoded_bytes bounds logical output and stored input; maximum_block_bytes bounds each intermediate BWT block. Truncated input, invalid indices and exceeded limits fail explicitly. Use the enclosing container's declared fork length as an additional check; resource maps and nested archives require separate decoders.

### `archive.aws`

`archive.aws(file, maximum_records=1M) -> record`

Reads an AWS tape image into logical records and tape marks, checking block framing and previous-length links. Each record exposes data, original offset, physical block count and tape_mark; data is None for marks. Does not interpret record payloads such as DDR disk dumps.

### `archive.bru`

`archive.bru(file, maximum_entries=1M) -> record`

Reads classic uncompressed BRU backups, validating each 2 KiB record's signed-byte checksum, archive identity, sequence and member name. Returns ordered entries with type, mode, ownership, link target and data file views assembled across record headers. Checks the end record and trailing buffer padding, including padding-block checksums. Compressed/extended members and incomplete multivolume inputs fail explicitly; no restore commands are executed.

### `archive.bsd_dump`

`archive.bsd_dump(file, maximum_entries=1M, maximum_decoded_bytes=256MiB) -> record`

Reads full, single-volume historical BSD dumps with 1024-byte records, magic60012 and old 128-byte UFS inodes, in either byte order. Validates header checksums, tape positions, record identity, address flags, complete inode payloads and directory structure. Returns entries, paths in files, find(path), dump date and raw allocated_map/dumped_map file views. Entries expose the same inode metadata and data views as filesystem.ufs; holes read as zeroes, hard links share data, symlinks are not followed and device nodes are metadata only. maximum_entries bounds both inode records and reachable paths; maximum_decoded_bytes bounds input size and cumulative logical inode bytes. Incremental dumps require a base image and are rejected, as are other dump generations and multi-volume streams. Dumped inode bitmap membership is checked against recovered records and the allocation map. Nested payloads require separate decoders.

### `archive.bzip2`

`archive.bzip2(file, maximum_bytes=2GiB) -> file`

Decodes all concatenated bzip2 streams, including legacy randomized blocks, into an immutable in-memory file. Validates block and stream checksums and enforces maximum_bytes on decoded output. Randomization is reversed after inverse BWT and before run expansion, with independent state per block. Does not interpret a filesystem or archive inside the stream.

### `archive.cab`

`archive.cab(file, cache=True) -> cab`

Parses a Microsoft Cabinet file and exposes its members as file views. Folder decompression is shared when caching is enabled, so several entries in one compressed folder need not decode it repeatedly.

### `archive.cab_set`

`archive.cab_set(files, cache=True) -> cab`

Opens related Cabinet files as one set, resolving files and compressed data that span cabinet boundaries. The caller supplies the cabinet files; the parser does not search host directories.

### `archive.cfb`

`archive.cfb(file) -> cfb`

Reads an OLE compound file through bounded FAT, DIFAT, and mini-stream chains, exposing member file views without host extraction.

### `archive.compactpro`

`archive.compactpro(file, maximum_entries=1M, maximum_decoded_bytes=256MiB) -> record`

Decodes a single-volume CompactPro archive, including self-extractors whose data fork contains the archive. Validates catalog CRC, directory descendant counts, payload ranges and the combined CRC of each file's decoded resource and data forks. Supports RLE and block-based LZH followed by RLE, retaining both forks and their stored views. Returns entries with reversible percent-escaped paths, raw name bytes, file type/creator, Finder flags, Mac-epoch dates, compression flags, CRC, data/resource and their sizes. maximum_decoded_bytes bounds total decoded fork bytes and each stored fork. Encrypted and multi-volume archives fail explicitly; no self-extractor code runs. Nested archives and resource payload formats remain separate layers.

### `archive.compress`

`archive.compress(file, maximum_bytes=2GiB, zero_padding=False) -> file`

Decodes a UNIX compress (.Z) stream with 9–16-bit LZW codes, legacy or block mode and packing realignment at width changes or resets. Enforces maximum_bytes; the format has no checksum, so enclosing size/checksum metadata should be validated separately. zero_padding=True explicitly accepts a final incomplete all-zero code after at least one decoded literal, for fixed-block media packages such as Ultrix setld subsets. It does not trim input bytes, suppress nonzero truncated codes or strip decoded zeroes. Use this option only with independent container and inventory validation; the default retains strict incomplete-code checks.

### `archive.gzip`

`archive.gzip(file, maximum_bytes=2GiB) -> file`

Decodes all concatenated gzip streams into an immutable in-memory file, validating checksums and enforcing maximum_bytes on decoded output. Does not interpret an archive inside the stream.

### `archive.hunk_load`

`archive.hunk_load(file, maximum_records=1M) -> record`

Reads one non-overlaid Amiga HUNK_HEADER load module without loading or executing its code. Returns header (raw bytes, padded resident library name views, table_size, first, last and allocation sizes in bytes), one unnamed element in units containing the record stream, and entries for code/data/debug payloads. Uses the same record fields as hunk_objects. Checks header ranges, section count, section payload bounds and declared allocation capacity; BSS remains metadata. maximum_records bounds header items, blocks, symbols and relocation groups. Only ordinary longword RELOC32 load relocations are accepted; compact encodings, overlays and extended memory attributes remain explicit gaps. Resident libraries are listed, not resolved; no relocation is applied and no guest memory is allocated.

### `archive.hunk_objects`

`archive.hunk_objects(file, maximum_records=1M) -> record`

Reads concatenated classic Amiga and EHF HUNK_UNIT object libraries, preserving unit names and complete raw unit views in units. The entries list exposes code, data and debug payloads under unique unit/record paths for nested inspection. Each unit's records expose tag, flags, absolute offset, raw bytes, optional payload, memory_size, symbols and relocations. Names retain longword padding. Code, data, debug bytes and big-endian relocation offset arrays remain borrowed files; BSS has a declared memory_size and no payload. Checks record boundaries, section ordering and END markers. maximum_records bounds blocks, symbols and relocation groups together. Does not link, apply relocations, resolve symbols or allocate BSS; reference targets and offsets are metadata, not a validated linked program. Supports EHF PPC_CODE, RELRELOC26 and EXT_RELREF26 framing without applying relocations. Load modules require hunk_load; indexed libraries and overlays remain rejected rather than silently skipped.

### `archive.installer`

`archive.installer(file, maximum_scan=256MiB, cache=True) -> installer`

Recognizes a supported installer container, including supported embedded payloads, and returns an inspection object with files and a declarative installation plan. It does not run the installer or apply that plan.

### `archive.installer_media`

`archive.installer_media(files) -> installer`

Discovers InstallShield packages, including nested packages, from a dictionary mapping portable relative media names to files.

### `archive.installer_probe`

`archive.installer_probe(file, maximum_scan=256MiB, cache=True) -> dict`

Inspects a candidate installer and returns detection details and diagnostics as a dictionary. Use it to distinguish unsupported packaging from a recognized payload before requesting a full plan.

### `archive.installscript`

`archive.installscript(file) -> installscript`

Parses compiled InstallShield InstallScript into functions, callbacks, calls and effects. The result supports bounded evaluation of the modeled script semantics; parsing does not execute a host installer.

### `archive.installshield`

`archive.installshield(header, cabinets, external={}) -> installshield`

Combines an InstallShield header, cabinet files and optional externally supplied files into an archive view. Exposes file groups, components and shortcuts needed for installation planning.

### `archive.irix_idb`

`archive.irix_idb(file, maximum_entries=1M) -> record`

Parses an IRIX installation database into ordered items, preserving duplicates and non-file records. Each item exposes kind, path, source, mode, owner, group and attributes. Use the logical subsystem attributes to pair renamed overlay images with archive.irix_image; inspecting an index does not select a machine variant or execute installation actions. Validates quoting, numeric modes, entry limits and zero tape padding.

### `archive.irix_image`

`archive.irix_image(file, idb, image_name, maximum_entries=1M) -> record`

Opens an IRIX inst software image with its IDB index and explicit image name, such as 4Dwm.sw. Returns files in physical record order, retaining duplicate paths, source names, IDB attributes, modes, owners and groups. Reads unwrap indexed .Z payloads and validate decoded sizes and BSD checksums. Supports headerless tape images and indexes without offsets, matching repeated names by IDB occurrence order; explicit offsets take precedence. Checks all tape padding is zero and block-aligned. Does not select subsystems or execute installation actions.

### `archive.irix_tape`

`archive.irix_tape(file) -> record`

Reads an SGI standalone tape directory after checking its header checksum and member ranges. Returns entries with path, size, offset and data file views; use filesystem.efs on an mr member to inspect the nested miniroot. This is the standalone archive format, not an inst software image or raw tape-record framing.

### `archive.kwaj`

`archive.kwaj(file, maximum=512MiB) -> file`

Decodes a Microsoft KWAJ-compressed input into a file, enforcing the decoded-size bound. Use kwaj_info when the header's original name and compression method are also needed.

### `archive.kwaj_info`

`archive.kwaj_info(file, maximum=512MiB) -> record(file, name, method, decoded_size, compressed_size)`

Returns the decoded KWAJ file together with its original name, method and compressed/decoded sizes. This preserves wrapper metadata that archive.kwaj omits.

### `archive.lha`

`archive.lha(file, maximum_entries=1M, maximum_decoded_bytes=256MiB) -> record`

Reads level-0 LHA headers and stored lh0 or Huffman/LZSS lh5 payloads. Checks header byte sums, file CRC-16, declared sizes, terminal marker, path components and duplicate paths. Returns entries, files and find(path). Entries preserve raw name/header bytes, the packed DOS timestamp, DOS attributes, method, CRC, decoded data and a borrowed stored view. Backslashes become path separators; parent traversal and empty components are rejected. maximum_entries bounds records; maximum_decoded_bytes bounds total decoded bytes and each stored payload. Other header levels, directory records, compression methods and self-extractors are explicit gaps. Nested containers are not automatically decoded.

### `archive.mac_resource`

`archive.mac_resource(file, maximum_entries=1M, maximum_decoded_bytes=256MiB) -> record`

Parses a classic Macintosh resource fork, checking map, reference, name and payload bounds and repeated type groups. Duplicate IDs retain every record in map order; duplicate_ids reports collisions, occurrence is one-based, and later occurrences have ordinal path suffixes. Returns fork attributes and entries with resource_type (four raw bytes), signed id, name (raw bytes or None), attributes, offset, size and data. Uncompressed data is a borrowed view; supported Apple dcmp 0/1/2/3 compressed resources are decoded and validated in memory. Compression requires both attribute bit0 and the a89f6572 payload tag, matching Resource Manager; raw attributes remain available when the bit is set on ordinary data. compressed reports actual decoding, while stored_data and stored_size preserve the original representation. maximum_decoded_bytes bounds total decoded compressed payload bytes and each stored compressed input. Unknown codecs and unsupported token variants fail explicitly. The synthetic path uses hexadecimal type and signed ID without interpreting names as host paths. Payload-specific formats remain separate layers.

### `archive.pack`

`archive.pack(file, maximum_bytes=2GiB) -> file`

Decodes a UNIX pack (1f1e) Huffman stream, checking its symbol tree, end marker, padding and declared output size. Enforces maximum_bytes and returns a file; useful for compressed IRIX manual pages nested inside inst images.

### `archive.rms_variable`

`archive.rms_variable(file, attributes, maximum_records=1M) -> record`

Decodes sequential RMS variable-length (VAR) and variable-with-fixed-control (VFC) records using the 32-byte attributes from an ODS-2 header or BACKUP attribute52. Returns records with original offset and borrowed control/data file views. Removes length words, odd-length alignment bytes and FFFF end-of-block padding from those views, but does not translate text or interpret printer controls. Validates EOF, control size, declared maximum data length and no-span block boundaries; rejects indexed/relative organizations, other record formats and extended record flags. maximum_records bounds returned records. Metadata alone is not proof that arbitrary file bytes actually use RMS framing; mismatches remain errors.

### `archive.sevenzip`

`archive.sevenzip(file, maximum_entries=1M, maximum_metadata=64MiB, max_dictionary=256MiB) -> sevenzip`

Parses a 7-Zip archive into member file views with bounded entry count, metadata and decoder dictionary size. Unsupported compression methods fail explicitly.

### `archive.sfp`

`archive.sfp(file, maximum_entries=1M, maximum_metadata=64MiB) -> sfp`

Parses an SFP installer archive and exposes member paths, timestamps, stored sizes and payload file views. It does not install the contents.

### `archive.stuffit`

`archive.stuffit(file, maximum_entries=1M, maximum_decoded_bytes=256MiB) -> record`

Reads the classic 22-byte/112-byte StuffIt archive generation, including self-extractors with an archive data fork. Validates declared archive size, header CRC-16/ARC, nested directory markers and each decoded fork CRC. Classic top-level counts are checked; STi2/ST46/ST50/ST60/ST65 installer counts are preserved separately as declared_count/top_level_count with root_count_verified=False because their selection semantics are not interpreted. STi2 repeated directory records remain in order. ST46 preserves repeated STcp/STde/STal/DIFF records with creator STin, exposing installer_record, one-based occurrence and raw declared fork sizes; copy/delete/alias metadata bytes are retained even when their logical data size is zero. ST60/ST65 additionally preserve STda/STmv metadata, including metadata naming existing directories without replacing them. No installation operations or patches are applied. ST60 alternative ordinary files are also retained as separate occurrences; other variants reject ordinary duplicate files, and ordinary file/directory conflicts still fail. Supports stored forks, method13 LZSS/Huffman with embedded or predefined tables, and method14 installer blocks with recursive Huffman tables and retained 256KiB history. Method14 validates block framing, decoded sizes and final fork CRCs; unavailable history is never invented. Returns version and entries preserving raw name bytes, reversible percent-escaped paths, file type/creator, Finder flags, Mac-epoch dates, resource/data methods and CRCs, separate data/resource files and original stored views. maximum_decoded_bytes bounds total decoded fork bytes and each stored fork. Also reads the StuffIt5 banner container with method15 (Arsenic) forks, validating the global, record and metadata CRC16 fields, parent/previous/file-next links, directory child counts and in-stream fork CRC32. StuffIt5 fork CRC16 attributes are None because integrity comes from the method15 stream. Other StuffIt5 fork methods, other compression methods, encryption and StuffItX remain explicit gaps; executable self-extractor code never runs. Nested containers and resource payloads require their own decoders.

### `archive.szdd`

`archive.szdd(file, maximum=512MiB) -> file`

Decodes the legacy Microsoft SZDD single-file compression format and returns a file. maximum bounds decoded output rather than the compressed input alone.

### `archive.tar`

`archive.tar(directory, compress='') -> bytes; archive.tar(file, maximum_entries=1M) -> tar`

With a directory, serializes its entries into tar bytes, optionally compressed. With a file, parses a tar archive and preserves ordered entries, metadata and duplicate-name occurrences.

### `archive.tome`

`archive.tome(file, maximum_entries=1M, maximum_decoded_bytes=256MiB) -> record`

Reads classic kc0001 Apple installer Tome catalogs and decodes both forks using chunked InstaCompOne in memory. Validates catalog counts, unique IDs, payload ranges, nonoverlap, exact fork sizes, both decoded-fork checksums and complete compressed-input consumption. Returns entries with ID, raw name bytes, reversible ID-qualified paths, file type/creator, Finder flags, version, Mac-epoch dates, decoded data/resource files and original stored views. maximum_decoded_bytes bounds total decoded output and each stored fork. Catalog checksum values are preserved as data_checksum and resource_checksum; checksums_verified is True after validation. Supports the observed 00010000 binary and 00000000 seven-bit-text chunk framing, plus stored chunks selected by a leading 01 byte, with retained 32KiB history and command-aligned 64KiB blocks; other encodings fail explicitly. Resource maps and nested archives require separate decoders. Installer code never runs. catalog_kind distinguishes file catalogs (1) from individual-resource catalogs (2). Kind2 exposes resource_type and signed resource_id, with the decoded resource payload in data and an empty resource fork; file-only metadata is omitted. Unknown catalog kinds are rejected.

### `archive.vmsbackup`

`archive.vmsbackup(file, maximum_blocks=1M, maximum_records=1M, maximum_block_size=16MiB, maximum_files=1M, maximum_attributes=256) -> record`

Reconstructs VMS BACKUP file-data chains after the same block, CRC and redundancy validation as vmsbackup_blocks. Returns entries with raw name bytes, flags, declared logical size, stored_size, attributes (kind/data records), missing_contents and data. Data borrows source ranges, excludes allocation slack, and is None when a nonempty file has metadata but no stored payload bytes. missing_contents reports absence without inferring its cause or accepting a partially stored file. Empty files have an empty data view. Rejects discontinuous virtual block addresses, partial data, missing or duplicate name/RMS fields and unsupported record kinds. Retains file attributes without translating RMS records or applying host path rules. Volume/file-ID record interpretation remains outside this API; inspect them with vmsbackup_blocks. Source bytes must remain unchanged while data views are used.

### `archive.vmsbackup_blocks`

`archive.vmsbackup_blocks(file, maximum_blocks=1M, maximum_records=1M, maximum_block_size=16MiB) -> record`

Reads a complete single-volume VMS BACKUP block stream, validating header CRC-16, whole-block CRC-32, sequence numbers, record boundaries and each encountered XOR redundancy payload. Returns blocks with offset, sequence, raw header, parity and records. Records expose offset, kind, flags, address, reserved and a borrowed data file. Unknown record kinds and flags are preserved. Does not repair damaged blocks, require final-group redundancy, join file data records, interpret RMS attributes, or decode nested file contents. The source must remain unchanged while borrowed views are used. Limits independently bound block count, total record count and block size before allocation.

### `archive.wim`

`archive.wim(file) -> wim`

Parses a Windows Imaging Format archive and exposes its image contents through file views. The archive reader handles its supported compression internally without mounting an image.

### `archive.xz`

`archive.xz(file, max_dictionary=64MiB) -> file`

Decodes an XZ stream into a file, rejecting decoder dictionaries above max_dictionary. This unwraps compression; it does not interpret an archive contained in the decoded bytes.

### `archive.zip`

`archive.zip(file) -> zip`

Parses a ZIP archive and exposes member files through files or entries. Members expose name/path and entry_type; complete reads validate decoded size and CRC, including exact-sized reads. Call entry.verify() to force complete validation, including empty entries. Data stays in memory rather than being extracted into a host directory.

### `binary.annotate`

`binary.annotate(file, attrs) -> file`

Wraps a file with caller-supplied attributes while retaining its bytes. Use this to attach construction metadata without rebuilding the file's contents.

### `binary.base64`

`binary.base64(value, url=False, padding=True, maximum=512MiB)`

Encodes binary input as a Base64 string. url selects the URL-safe alphabet, padding controls trailing equals signs, and maximum bounds encoded output.

### `binary.bits`

`binary.bits(value, order='msb') -> bit reader`

Creates a stateful bit reader over binary input. Its read, peek, drop and align operations consume or inspect bits in the selected bit order.

### `binary.builder`

`binary.builder(capacity=0, limit=512MiB) -> binary.builder`

Creates a bounded mutable byte builder. Append encoded values, reserve or patch regions, then obtain bytes or a file; capacity is an allocation hint and limit bounds growth.

### `binary.concat`

`binary.concat(parts) -> file`

Returns a lazy file formed by concatenating binary parts in order. Unlike bytes_concat, it need not materialize the complete result at construction time.

### `binary.cursor`

`binary.cursor(value, offset=0) -> binary.cursor`

Creates a sequential byte reader at the selected offset. Scalar reads and bytes(size) advance its position; seek, skip and align change that position explicitly.

### `binary.decode`

`binary.decode(value, encoding, maximum=512MiB) -> bytes`

Decodes a hex, Base64 or unpadded URL-safe Base64 string into bytes. This is the inverse of binary.hex/base64, not a character-set decoder; use binary.text for text.

### `binary.encode`

`binary.encode(value, encoding='utf8', nul=False) -> bytes`

Encodes a string into bytes using the selected character encoding. nul appends an encoding-appropriate terminator; binary.text performs the reverse conversion.

### `binary.extents`

`binary.extents(size, extents) -> file`

Constructs a file of the requested logical size from supplied byte extents. Unpopulated ranges read as zero, allowing sparse image layouts without allocating every logical byte.

### `binary.f32be`

`binary.f32be(value) -> bytes`

Encodes a 32-bit IEEE-754 floating-point value as 4 bytes in big-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.f32le`

`binary.f32le(value) -> bytes`

Encodes a 32-bit IEEE-754 floating-point value as 4 bytes in little-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.f64be`

`binary.f64be(value) -> bytes`

Encodes a 64-bit IEEE-754 floating-point value as 8 bytes in big-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.f64le`

`binary.f64le(value) -> bytes`

Encodes a 64-bit IEEE-754 floating-point value as 8 bytes in little-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.hex`

`binary.hex(value, maximum=512MiB)`

Encodes binary input as lowercase hexadecimal text, with two characters per input byte. maximum bounds the encoded result; use top-level hex to format an integer.

### `binary.i16be`

`binary.i16be(value) -> bytes`

Encodes a 16-bit signed integer as 2 bytes in big-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.i16le`

`binary.i16le(value) -> bytes`

Encodes a 16-bit signed integer as 2 bytes in little-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.i32be`

`binary.i32be(value) -> bytes`

Encodes a 32-bit signed integer as 4 bytes in big-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.i32le`

`binary.i32le(value) -> bytes`

Encodes a 32-bit signed integer as 4 bytes in little-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.i64be`

`binary.i64be(value) -> bytes`

Encodes a 64-bit signed integer as 8 bytes in big-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.i64le`

`binary.i64le(value) -> bytes`

Encodes a 64-bit signed integer as 8 bytes in little-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.i8`

`binary.i8(value) -> bytes`

Encodes a 8-bit signed integer as 1 bytes in single-byte order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.layout`

`binary.layout(format, names=None) -> binary.layout`

Compiles a fixed-size binary layout from a format string and optional field names. The returned value encodes records or decodes a source at a byte offset.

### `binary.read_f32be`

`binary.read_f32be(source, offset=0) -> float`

Reads a 32-bit IEEE-754 floating-point value from source at the byte offset, using big-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_f32le`

`binary.read_f32le(source, offset=0) -> float`

Reads a 32-bit IEEE-754 floating-point value from source at the byte offset, using little-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_f64be`

`binary.read_f64be(source, offset=0) -> float`

Reads a 64-bit IEEE-754 floating-point value from source at the byte offset, using big-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_f64le`

`binary.read_f64le(source, offset=0) -> float`

Reads a 64-bit IEEE-754 floating-point value from source at the byte offset, using little-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_i16be`

`binary.read_i16be(source, offset=0) -> int`

Reads a 16-bit signed integer from source at the byte offset, using big-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_i16le`

`binary.read_i16le(source, offset=0) -> int`

Reads a 16-bit signed integer from source at the byte offset, using little-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_i32be`

`binary.read_i32be(source, offset=0) -> int`

Reads a 32-bit signed integer from source at the byte offset, using big-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_i32le`

`binary.read_i32le(source, offset=0) -> int`

Reads a 32-bit signed integer from source at the byte offset, using little-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_i64be`

`binary.read_i64be(source, offset=0) -> int`

Reads a 64-bit signed integer from source at the byte offset, using big-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_i64le`

`binary.read_i64le(source, offset=0) -> int`

Reads a 64-bit signed integer from source at the byte offset, using little-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_i8`

`binary.read_i8(source, offset=0) -> int`

Reads a 8-bit signed integer from source at the byte offset, using single-byte encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_u16be`

`binary.read_u16be(source, offset=0) -> int`

Reads a 16-bit unsigned integer from source at the byte offset, using big-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_u16le`

`binary.read_u16le(source, offset=0) -> int`

Reads a 16-bit unsigned integer from source at the byte offset, using little-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_u32be`

`binary.read_u32be(source, offset=0) -> int`

Reads a 32-bit unsigned integer from source at the byte offset, using big-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_u32le`

`binary.read_u32le(source, offset=0) -> int`

Reads a 32-bit unsigned integer from source at the byte offset, using little-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_u64be`

`binary.read_u64be(source, offset=0) -> int`

Reads a 64-bit unsigned integer from source at the byte offset, using big-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_u64le`

`binary.read_u64le(source, offset=0) -> int`

Reads a 64-bit unsigned integer from source at the byte offset, using little-endian encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.read_u8`

`binary.read_u8(source, offset=0) -> int`

Reads a 8-bit unsigned integer from source at the byte offset, using single-byte encoding. Returns the decoded scalar without advancing a cursor; a truncated read fails.

### `binary.replace`

`binary.replace(value, old, new, count=-1, maximum=512MiB) -> bytes`

Returns bytes with up to count non-overlapping occurrences of old replaced by new; count=-1 replaces all. old must be nonempty and maximum bounds the result.

### `binary.strings`

`binary.strings(value, encoding='ascii', minimum=4, maximum=64MiB) -> list[string]`

Scans binary input for printable ASCII or UTF-16LE strings of at least minimum characters. Returns string values, not offsets or a decoded version of the entire file.

### `binary.text`

`binary.text(value, encoding='utf8', nul=False, maximum=16MiB) -> string`

Decodes binary input into a string using the selected character encoding. nul requests terminator-aware decoding; maximum bounds input size.

### `binary.u16be`

`binary.u16be(value) -> bytes`

Encodes a 16-bit unsigned integer as 2 bytes in big-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.u16le`

`binary.u16le(value) -> bytes`

Encodes a 16-bit unsigned integer as 2 bytes in little-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.u32be`

`binary.u32be(value) -> bytes`

Encodes a 32-bit unsigned integer as 4 bytes in big-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.u32le`

`binary.u32le(value) -> bytes`

Encodes a 32-bit unsigned integer as 4 bytes in little-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.u64be`

`binary.u64be(value) -> bytes`

Encodes a 64-bit unsigned integer as 8 bytes in big-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.u64le`

`binary.u64le(value) -> bytes`

Encodes a 64-bit unsigned integer as 8 bytes in little-endian order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.u8`

`binary.u8(value) -> bytes`

Encodes a 8-bit unsigned integer as 1 bytes in single-byte order. Returns new bytes; integer inputs outside the codec's range fail rather than silently truncating.

### `binary.view`

`binary.view(value, offset=0, size=None) -> byte_view`

Creates a bounded random-access byte view, optionally over a source slice. It supports byte search, comparisons and further slicing without requiring the entire source to be copied.

### `binary.xml`

`binary.xml(value, maximum=16MiB, max_depth=256, max_nodes=1M)`

Parses XML into namespace-aware immutable document and node values. Size, depth and node-count limits bound parsing; with_root/with_children/with_text create edited values for serialization.

### `block.cache`

`block.cache(base, max_bytes=32MiB, chunk_size=64KiB)`

Adds a bounded read-through chunk cache to a block device. It speeds repeated reads but is not a writable overlay or a persistent image cache.

### `block.device`

`block.device(file, format='raw', logical_block_size=512, physical_block_size=logical, writable=False)`

Wraps a file as a block device with declared logical and physical block geometry. Writable mode requires a source that supports writes; it does not implicitly add copy-on-write storage.

### `block.nbd`

`block.nbd(device, export_name='', max_request=8MiB, structured=True, handshake_timeout=10, request_timeout=30, workers=4)`

Creates an NBD protocol server for a block device. serve(channel) processes requests over a supplied byte channel; constructing the server does not open a listening socket.

### `block.overlay`

`block.overlay(base, max_dirty_bytes=128MiB, chunk_size=64KiB, trace_operations=0)`

Creates a bounded writable copy-on-write layer over a base block device. Writes affect the overlay, leaving the base unchanged; max_dirty_bytes bounds retained changes.

### `block.view`

`block.view(device) -> live read-only file view`

Returns a read-only file view of a live block device. Later device changes remain visible through the view; it is not an immutable snapshot.

### `clock.monotonic`

`clock.monotonic() -> elapsed seconds`

Returns seconds from the runtime's monotonic clock. Subtract readings to time work; the value is not a calendar timestamp.

### `clock.profiler`

`clock.profiler() -> clock.profiler`

Creates a profiler for named spans, counters and measured calls. Its snapshots and reports summarize work explicitly recorded through this profiler.

### `clock.unix`

`clock.unix() -> int`

Returns the runtime clock's current Unix timestamp in seconds. Use clock.monotonic rather than calendar time to measure durations.

### `clock.utc`

`clock.utc(timestamp) -> dict`

Converts an integer Unix timestamp into a dictionary of UTC year, month, weekday, day, hour, minute, second and millisecond fields. Weekday uses Sunday=0; this converts a supplied time rather than reading the current clock.

### `crypto.aes`

`crypto.aes(key, value, decrypt=False, mode='cbc', iv=None) -> bytes`

Encrypts or decrypts complete 16-byte AES blocks in CBC or ECB mode, returning bytes without adding or removing padding. CBC uses a zero IV when none is supplied; callers implementing a protocol must provide its required IV and authentication.

### `crypto.checksum`

`crypto.checksum(algorithm, value, initial=0) -> int`

Returns Adler-32, a supported CRC-32, or sum16le for binary input. sum16le adds little-endian 16-bit words with end-around carry and no complement; an odd final byte is a low byte. Its optional initial accumulator must fit 16 bits. Continue using even-sized chunks; nonzero initial is rejected for other algorithms. These checksums are not cryptographic authentication.

### `crypto.constant_time_equal`

`crypto.constant_time_equal(left, right) -> bool`

Compares two binary values using a constant-time comparison for equal-length inputs. Returns a boolean; differing lengths are not hidden.

### `crypto.des`

`crypto.des(key, value, decrypt=False, iv=None) -> bytes`

Encrypts or decrypts complete 8-byte blocks with an 8-byte DES key. Supplying an IV selects CBC; otherwise blocks are processed independently. This legacy compatibility primitive adds no padding or authentication.

### `crypto.deterministic`

`crypto.deterministic(seed, size, algorithm='sha256') -> bytes`

Derives a reproducible byte sequence from a seed using domain-separated counter hashes. Equal seed, algorithm and size produce equal output; it is not an entropy source.

### `crypto.hash`

`crypto.hash(algorithm, value) -> bytes`

Returns raw digest bytes for binary input using MD4, MD5, SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512. Legacy algorithms are provided for format compatibility, not as recommendations for new security protocols.

### `crypto.hash_blocks`

`crypto.hash_blocks(algorithm, state, blocks) -> bytes`

Advances a supplied SHA-1 or SHA-256 compression state over complete blocks and returns the updated state. It does not perform message padding or finalization; use crypto.hash for a complete digest.

### `crypto.hasher`

`crypto.hasher(algorithm) -> crypto.hasher`

Creates a mutable incremental hash state. update(value) feeds input, sum() reads the current digest without resetting, and reset() starts a new message.

### `crypto.hmac`

`crypto.hmac(algorithm, key, value) -> bytes`

Computes an HMAC over binary input using the supplied key and hash algorithm. Returns raw authentication bytes rather than hexadecimal text.

### `crypto.mod_exp`

`crypto.mod_exp(base, exponent, modulus, byte_order='big') -> bytes`

Computes base raised to exponent modulo modulus from byte-encoded nonnegative operands. byte_order applies to inputs and output; the result is padded to the modulus byte width.

### `crypto.mod_inverse`

`crypto.mod_inverse(value, modulus) -> int|None`

Returns the multiplicative inverse of an integer modulo a positive modulus, or None when no inverse exists. Operands are bounded to 16384 bits; this arithmetic operation is not a constant-time cryptographic protocol.

### `crypto.mod_mul`

`crypto.mod_mul(left, right, modulus, byte_order='big') -> bytes`

Multiplies byte-encoded nonnegative operands modulo a byte-encoded modulus. The selected byte order is preserved and the result has the modulus's byte width.

### `crypto.random`

`crypto.random(size) -> bytes`

Returns the requested number of bytes from the runtime's cryptographic randomness source. Unlike crypto.deterministic, repeated calls are not reproducible.

### `crypto.rc4`

`crypto.rc4(key, value) -> bytes`

Applies the RC4 stream cipher to binary input using a fresh state initialized from key. Encryption and decryption use the same operation; this unauthenticated legacy primitive is for compatibility.

### `crypto.xtea`

`crypto.xtea(key, value, decrypt=False, byte_order='big') -> bytes`

Encrypts or decrypts complete 8-byte XTEA blocks with a 16-byte key and the selected word byte order. Returns bytes without padding or authentication.

### `database.ese`

`database.ese(file) -> ESE database`

Parses an Extensible Storage Engine database into inspectable tables and records. It is a file-format reader, not a host ESE engine or SQL connection.

### `database.ese_build`

`database.ese_build(tables, database_pages=0, sort_data=None) -> file`

Builds an ESE database file from declarative tables, optionally controlling database page allocation and sort data. Construction stays in memory.

### `database.msi`

`database.msi(file) -> msi`

Reads a Windows Installer database and its embedded streams. plan resolves static payloads and table effects for supplied target properties, retaining custom actions and runtime dependencies without execution.

### `database.sqlite`

`database.sqlite(file, wal=None) -> SQLite database`

Parses a SQLite database, optionally applying a supplied WAL view, and exposes schema and table rows. It does not execute arbitrary SQL through a host SQLite process.

### `database.sqlite_build`

`database.sqlite_build(objects, page_size=4096, encoding=1, user_version=0, application_id=0) -> file`

Builds a SQLite database file from declarative schema and row data. The output can be embedded in an image without invoking a host database engine.

### `debug.disassemble`

`debug.disassemble(data, address=0, architecture='i386', maximum=64MiB, count=-1); architectures: i8086/x86-16, i386/x86, amd64/x86_64`

Decodes machine-code bytes into instruction records at a supplied base address. Supports the listed 16-, 32- and 64-bit x86 modes; count bounds returned instructions.

### `debug.gdb`

`debug.gdb(channel, memory_limit=64MiB, stop_queue=256, timeout=15)`

Connects a GDB remote-protocol session over an existing byte channel. The returned session controls the target and reads structured stops, registers and memory without launching a host debugger.

### `debug.select`

`debug.select(values, timeout=-1)`

Waits until one of the supplied selectable values is ready, returning that value, or None on timeout. Read the event from the returned source separately; selection itself does not consume the event.

### `emulator.machine`

`emulator.machine(image|code, architecture='auto', **architecture_options) -> emulator`

Creates an in-process machine for the input's supported architecture, using native instruction execution and modeled Windows API callbacks. Instruction and memory limits bound execution; this is not a QEMU VM.

### `emulator.plugin`

`emulator.plugin(install, name='plugin', state=None, attrs=None) -> plugin`

Wraps explicit mutable plugin state and its installation callback for emulator use. Keep checkpointed callback state here rather than hiding it in closures.

### `emulator.uefi`

`emulator.uefi(image, memory=256MiB, memory_base=0x40000000, image_base=0, stack_size=1MiB, time_unix=0, image_path='\\EFI\\Boot\\BootAA64.efi', registers={}, observe=None, device_path=b'', event_kinds=None)`

Loads an ARM64 EFI image into a configurable in-process interpreter. Runs stop at budgets, watches, explicit breakpoints, unsupported operations or validated ExitBootServices. CPU, RAM, firmware and disk overlays support checkpoints; digest-checked rewrites accelerate recognized routines. See the [UEFI inspection API](../../../emulator/uefi/README.md) for configuration and limitations. Native HVF continuation is not implemented.

### `emulator.x86`

`emulator.x86(image|code, base=0x1000, entry=None, instruction_limit=2M, memory_limit=32MiB, stack_size=1MiB, call_depth_limit=1024, trace=False, trace_limit=4096, profile=False, profile_interval=256, profile_limit=16384, image_name='main', fs_base=0, segment_size=4096)`

Creates a bounded 32-bit x86 execution context from a PE image or raw code. Exposes guest registers, memory, hooks and snapshots; unsupported behavior returns structured stops rather than executing host code.

### `filesystem.apm`

`filesystem.apm(file, block_size=512, maximum_entries=1M) -> record`

Reads an Apple Partition Map as portable partition file views. block_size explicitly selects the 512-, 1024- or 2048-byte logical map; device_block_size and device_blocks retain independent driver-descriptor geometry. This distinction matters for CDs containing overlapping maps. Each partition exposes its effective block_size: a CDvr-tagged Apple_Driver43_CD record with a matching block-zero driver descriptor uses 2048-byte device units even in a 512-byte map; other records use the selected map units. Validates ER/PM signatures, consistent entry counts, allocated-partition bounds and nonoverlap. Returns partitions with index, raw name/type/processor bytes, start_block, blocks, logical data-range fields, status and boot metadata. data is the complete physical partition view; no inner filesystem is inferred. An out-of-image Apple_Free descriptor retains its declared geometry with data=None and complete=False; allocated partitions must fit fully. Boot metadata is not executed and boot checksums are not verified.

### `filesystem.efs`

`filesystem.efs(file, maximum_entries=1M) -> record`

Reads an IRIX EFS volume into entries and case-sensitive paths, resolving direct and indirect extents without mounting. find(path) returns an entry or None; entries expose data, entry_type, size, inode, mode, uid, gid and modified. Accepts a trimmed free tail only when the allocation bitmap proves the omitted region is free and all referenced extents fit the original input. Symlink data remains the link target and is never followed; device entries have no data.

### `filesystem.fat`

`filesystem.fat(file) -> FAT filesystem`

Parses an existing FAT volume into a filesystem view. Use fat12, fat16 or fat32 with a directory to construct a new volume.

### `filesystem.fat12`

`filesystem.fat12(directory, size, boot_code=None, hidden_sectors=0, label='NO NAME', file_order=[], directory_label=True, extended_bpb=False, chs=None) -> file`

Builds a FAT12 volume from a directory with the requested size, boot metadata and file order. The returned file is an in-memory image, not a mounted filesystem.

### `filesystem.fat16`

`filesystem.fat16(directory, size, boot_code=None, hidden_sectors=0, label='NO NAME', file_order=[], directory_label=True, extended_bpb=True, chs=None) -> file`

Builds a FAT16 volume from a directory, preserving supported attributes and requested boot metadata. Geometry and hidden-sector fields must match the surrounding disk layout.

### `filesystem.fat32`

`filesystem.fat32(directory, size, boot_code=None, hidden_sectors=0, label='NO NAME', boot_stage_sector=14, file_order=[], directory_label=True, chs=None) -> file`

Builds a FAT32 volume from a directory and requested layout options. It produces a volume file for composition into a disk rather than writing or formatting a host device.

### `filesystem.gpt`

`filesystem.gpt(file) -> parsed GPT; filesystem.gpt(size, disk_guid=...) -> builder`

With a file, parses GPT partition metadata; with a size, creates a partition-table builder. Populate the builder with partition contents to produce a complete disk layout.

### `filesystem.hfs`

`filesystem.hfs(file, maximum_entries=1M) -> record`

Reads a classic HFS volume's catalog and extent-overflow records without mounting. Returns raw volume name, entries, paths and exact find(path) lookup. Every regular entry exposes separate data and resource fork views, their sizes, raw name bytes, catalog/parent IDs, Finder information, flags and Mac-epoch timestamps. Path components percent-escape non-ASCII/control bytes, slash and percent, keeping legacy names reversible without assuming a script encoding. HFS Plus and fragmented extents-file bootstrap are not yet supported; compressed resources require a separate resource decoder. Aliases are not followed.

### `filesystem.host`

`filesystem.host(root, lazy=False) -> host filesystem`

Exposes a host directory through the native filesystem backend. This is a host-path boundary, not an image parser or a portable replacement for an in-memory directory.

### `filesystem.iso9660`

`filesystem.iso9660(file) -> ISO filesystem`

Parses an ISO 9660 filesystem and exposes its directory tree and file views. It does not mount the image or copy its contents to the host.

### `filesystem.mbr`

`filesystem.mbr(file) -> parsed MBR; filesystem.mbr(size, boot_code=None, disk_signature=0, chs=None) -> builder`

With a file, parses the MBR and partitions; with a disk size, creates a builder with optional boot code, signature and CHS geometry. Partition payloads remain caller-supplied.

### `filesystem.ntfs`

`filesystem.ntfs(source, size=None, boot_code=None, hidden_sectors=0, label='NO NAME', version='1.1', log_file=None, upcase=None, upcase_profile='default')`

Parses an NTFS volume when given a file, or builds one from a directory and size. Construction accepts explicit NTFS generation, boot metadata, log and upcase data so older NT layouts need not inherit modern defaults.

### `filesystem.ods2`

`filesystem.ods2(file, maximum_entries=1M, maximum_depth=64) -> record`

Reads Files-11 ODS-2 version1 home blocks, index headers and versioned directory trees. Verifies home/header checksums, primary and backup index maps, file identities, allocation bounds, EOF fields, directory records and traversal limits. Returns entries, files, exact-path find(path), raw home bytes and padded volume_name. Entries retain raw names, version, file_number, sequence, header, record_attributes, characteristics, data and size. Names include ;version, with unsafe bytes percent-escaped; the root self-reference is a directory_link and is not followed. Data is a borrowed read-only extent view; RMS records are not translated and allocation slack is excluded. Supports retrieval formats1/2/3. Extension chains, placement-control pointers, alternate-volume resolution and other ODS generations remain explicit gaps. Opening an ODS-2 view does not validate any enclosing CD-image trailer or decode nested backup savesets.

### `filesystem.sgi`

`filesystem.sgi(file) -> record`

Validates an SGI volume-header checksum and returns partition and boot-directory file views. Partitions expose index, partition_type, start_block, blocks, data and complete; addresses are 512-byte basic blocks. A whole-volume descriptor may exceed a CD image: its declared blocks are retained, data covers only available bytes, and complete is false. Filesystem partitions and boot files must fit in full. Does not infer an inner filesystem from a filename.

### `filesystem.udf`

`filesystem.udf(file) -> UDF filesystem`

Parses a UDF filesystem into directory and file views. Reads resolve the filesystem's on-disk structures without mounting it.

### `filesystem.ufs`

`filesystem.ufs(file, maximum_entries=1M, maximum_blocks=1M) -> record`

Reads the historical UFS1 filesystem layout used by Ultrix, with a superblock at byte8192 and either byte order. Checks fragment/cylinder-group geometry, inode and data ranges, 512-byte directory records, dot entries, duplicate names and directory cycles. Returns entries, paths, find(path), block_size, fragment_size and groups. Entries preserve inode identity, mode, link count, old 16-bit uid/gid, timestamps, flags, device number and borrowed data views. Reads 12 direct blocks and single/double/triple indirect pointers; zero pointers remain sparse zeroes. maximum_blocks bounds total mapping work, including indirect pointers; maximum_entries bounds reachable paths. Hard-linked files share inode data, symlinks are exposed but not followed, and no device nodes are created. This is the old directory/inode layout, not UFS2 or modern UFS1 extensions; inline symlinks, extended attributes and journal replay are not implemented. Nested archives require separate decoders.

### `filesystem.ultrix_label`

`filesystem.ultrix_label(file) -> record`

Reads the eight-slot DEC/Ultrix disk label at byte16312, validating magic, active-table flag, signed 512-byte sector geometry and nonempty partition bounds. Returns block_size=512 and partitions with index, conventional a-h name, start_block, blocks and borrowed data. Empty slots remain present with data=None. Overlaps are preserved because the whole-disk slot overlaps individual filesystems; no partition is silently selected or treated as a duplicate. The label has no checksum or filesystem-type field, so inspect each selected partition with its own format reader. Does not scan for alternate labels, mount filesystems or execute boot code.

### `filesystem.vhdx`

`filesystem.vhdx(file) -> VHDX disk`

Parses a VHDX container and exposes its logical disk contents. This unwraps the virtual-disk format; parse the returned disk's partitions/filesystems separately.

### `filesystem.xfs`

`filesystem.xfs(file, maximum_entries=1M) -> record`

Reads a legacy version-4 XFS directory tree using borrowed file extents, without mounting or replaying the journal. Returns entries and paths; find(path) returns an entry or None. Entries expose data, entry_type, inode, mode, uid, gid, modified and size. Supports local forks and inode-resident extent lists, sparse and unwritten data, and version-1/version-2 directories (including version-1 directory btrees). Symlinks are not followed. Version-5 metadata, extent btrees, realtime data and file-type directory extensions are currently rejected explicitly.

### `firmware.acpi_compatible_id`

`firmware.acpi_compatible_id(device, compatible_id)`

Builds a complete SSDT file that assigns an ACPI compatible ID to the selected device. The output includes the ACPI header and checksum and can be supplied directly to qemu.acpi_table.

### `firmware.acpi_fadt_arm64`

`firmware.acpi_fadt_arm64(dsdt, psci=False, hvc=False)`

Builds a hardware-reduced ARM64 FADT with an explicit DSDT guest address and PSCI conduit declarations. HVC requires PSCI; the caller supplies the declared platform.

### `firmware.acpi_gtdt_arm64`

`firmware.acpi_gtdt_arm64(physical_interrupt, virtual_interrupt)`

Builds an ARM64 Generic Timer Description Table with distinct physical and virtual timer PPI interrupt IDs.

### `firmware.acpi_madt_arm64`

`firmware.acpi_madt_arm64(distributor, redistributor, mpidrs, performance_interrupt=0, maintenance_interrupt=0)`

Builds a GICv3 MADT with enabled CPU interfaces for the supplied MPIDRs, a distributor, and an always-on redistributor range with one 128 KiB frame per CPU. Addresses and interrupt IDs are explicit platform inputs.

### `firmware.acpi_mcfg`

`firmware.acpi_mcfg(base, first_bus, last_bus, segment=0)`

Builds a PCI ECAM allocation table for the supplied base address, segment, and inclusive bus range.

### `firmware.acpi_pci_root`

`firmware.acpi_pci_root(memory_base, memory_size, routes, first_bus=0, last_bus=0, segment=0)`

Builds AML for a PCI root with a fixed memory window and INTx routes. Routes are (device, pin, interrupt) tuples; pins use ACPI numbering 0 through 3.

### `firmware.acpi_rsdp`

`firmware.acpi_rsdp(xsdt, oem_id='TREXOS')`

Builds an ACPI 2.0+ root pointer with both checksums and an explicit guest XSDT address. Returns a file containing the serialized structure.

### `firmware.acpi_table`

`firmware.acpi_table(signature, body, revision=2, oem_id='TREXOS', oem_table_id='TREXACPI', oem_revision=1, creator_id='TREX', creator_revision=1)`

Wraps an ACPI table body with the requested signature, revision and OEM/creator identifiers, computing its checksum. Returns a table file for use by a VM backend.

### `html.escape`

`html.escape(value) -> string`

Escapes special characters in text for HTML output. This is text escaping, not sanitization of an existing HTML document.

### `html.unescape`

`html.unescape(value) -> string`

Decodes HTML character references in a string. It does not parse or validate markup.

### `image.compare`

`image.compare(left, right, threshold=8, maximum=128MiB, max_pixels=16MiP) -> record`

Compares decoded images and returns difference measurements using the specified per-pixel threshold. Pixel differences alone are not proof that a guest application launched successfully.

### `image.info`

`image.info(source, maximum=128MiB, max_pixels=16MiP) -> record`

Decodes image metadata and returns dimensions and format information within input and pixel-count bounds.

### `image.pixel`

`image.pixel(source, x, y, maximum=128MiB, max_pixels=16MiP) -> record`

Returns the color of one decoded image pixel at x,y. Coordinates must be inside the image; input size and decoded pixel limits apply.

### `json.decode`

`json.decode(value, maximum=64MiB) -> value`

Parses bounded JSON input into Starlark dictionaries, lists and scalar values. Invalid JSON produces an error.

### `json.encode`

`json.encode(value, indent=None) -> string`

Serializes a supported Starlark value as JSON text. Values that have no JSON representation fail rather than being stringified implicitly.

### `path.base`

`path.base(path) -> string`

Returns the last component of a logical path. It operates on path text and does not access the filesystem.

### `path.clean`

`path.clean(path) -> logical absolute path`

Normalizes a logical path, resolving separators and dot components into the library's absolute-path form. It does not resolve symlinks or check host existence.

### `path.dir`

`path.dir(path) -> logical directory path`

Returns the containing directory of a logical path. This is lexical path manipulation, not a filesystem lookup.

### `path.ext`

`path.ext(path) -> extension`

Returns the final filename extension, including its leading dot, or an empty string when none exists.

### `path.from_windows`

`path.from_windows(path) -> string`

Converts a Windows-style path into the library's logical slash-separated path representation. It does not translate it into a host path or access a drive.

### `path.join`

`path.join(*parts) -> string`

Joins logical path components and normalizes the result. The operation is independent of the host operating system's path rules.

### `qemu.acpi_table`

`qemu.acpi_table(file)`

Creates a QEMU backend descriptor for an ACPI table file. The table is supplied through the backend when the VM starts.

### `qemu.audiodev`

`qemu.audiodev(name, **properties) -> qemu_audiodev`

Creates a QEMU audio-backend descriptor from its name and properties. It is configuration data; creating it does not start audio or launch QEMU.

### `qemu.backend`

`qemu.backend(binary='', machine='pc', machine_properties={}, accelerator='auto', firmware='bios', display_frontend='auto', display_zoom_to_fit=False, block_transport='auto', overlay_limit=256MiB, stderr_limit=1MiB, devices=[], netdevs=[], chardevs=[], options=[], acpi_tables=[])`

Creates a QEMU implementation of the portable VMM backend with selected machine, acceleration, devices and transport policies. A separate vmm.start call launches the guest.

### `qemu.chardev`

`qemu.chardev(name, **properties)`

Creates a QEMU character-device backend descriptor from a backend name and properties. Use it in qemu.backend configuration.

### `qemu.device`

`qemu.device(name, **properties)`

Creates a QEMU device descriptor from a device model and properties. This is backend-specific configuration, not an already-running device.

### `qemu.extension`

`qemu.extension(vm)`

Returns the QEMU-specific control extension for an existing VM, including QMP/HMP and block statistics. Use portable VM methods when backend-specific control is unnecessary.

### `qemu.netdev`

`qemu.netdev(name, **properties)`

Creates a QEMU network-backend descriptor with the supplied properties. It does not independently create a host network interface.

### `qemu.option`

`qemu.option(name, value=None); -d accepts a list of debug event names`

Creates a supported QEMU command-line option descriptor. The backend validates and translates it at launch; it is not a shell command.

### `regexp.compile`

`regexp.compile(pattern) -> regexp`

Compiles a regular expression into a reusable matching object. Invalid patterns fail at compilation rather than at the first match.

### `renvo.cc`

`renvo.cc(source, input, target, flags=[], arena_size=32MiB) -> compiledModule; input is a virtual source path or list of paths`

Compiles virtual C/C++ sources with the in-process Renvo toolchain for the selected target. Returns a compiledModule containing success/diagnostic information and virtual output bytes.

### `renvo.go`

`renvo.go(source, input, target, arena_size=32MiB) -> compiledModule`

Compiles a virtual Go source tree with Renvo for the selected target. Returns compilation status and outputs without invoking a host Go compiler.

### `renvo.make`

`renvo.make(source, target, input='Makefile', targets=[], output='', arena_size=32MiB) -> compiledModule; rebuilds Renvo recipes in memory; output selects the binary by virtual path relative to the Makefile`

Evaluates supported Renvo make recipes against a virtual source tree and rebuilds their outputs in memory. output selects the desired binary relative to the Makefile; no host make process is launched.

### `runtime.stats`

`runtime.stats() -> record`

Returns a snapshot of runtime resource statistics for diagnostics and benchmarking. Counters describe the running runtime, not just one image recipe.

### `testing.attempt`

`testing.attempt(callback, args=None, kwargs=None) -> record(ok, value, error)`

Calls a function with supplied positional and keyword arguments and captures success or failure in an ok/value/error record. It does not roll back side effects performed before an error.

### `testing.module`

`testing.module(label) -> dict`

Loads a module label and returns its globals as a dictionary. Used by the portable test runner to discover tests through the normal module loader.

### `url.path_escape`

`url.path_escape(value) -> string`

Percent-encodes text for use as one URL path segment. It is not query-string encoding or whole-URL normalization.

### `url.path_unescape`

`url.path_unescape(value) -> string`

Decodes percent escapes in URL path text. Malformed escape sequences produce an error.

### `vmm.backends`

`vmm.backends()`

Lists the VMM backends registered in this runtime and their advertised capabilities. Availability depends on the runtime's backend implementations.

### `vmm.channel`

`vmm.channel(kind, name, required=True)`

Describes a named VM byte channel of the requested kind. required determines whether lack of backend support is a validation failure.

### `vmm.disk`

`vmm.disk(source, name='disk0', bus='auto', media='disk', unit=-1, chs=None, read_only=None, snapshot=False, required=True)`

Describes a guest disk or optical medium backed by a file or block device, including bus, unit and write/snapshot policy. It does not boot or materialize the source.

### `vmm.display`

`vmm.display(mode, required=True)`

Describes the requested guest display mode and whether support is mandatory. This is part of a portable machine specification.

### `vmm.machine`

`vmm.machine(architecture, memory, cpus=1, disks=[], networks=[], display=vmm.display('none'), channels=[], start_paused=False, required_capabilities=[])`

Creates a portable machine specification from architecture, memory, CPUs, storage, networking and channels. It does not start a VM.

### `vmm.network`

`vmm.network(kind, name='net0', required=True)`

Describes a named guest network connection and whether its requested kind is required. The selected backend implements the transport.

### `vmm.start`

`vmm.start(machine, backend)`

Validates a machine specification against a backend and starts a VM. Returns the live VM handle used for input, screenshots, events and lifecycle control.

### `vmm.validate`

`vmm.validate(machine, backend)`

Checks whether a backend can implement a machine specification and its required capabilities without launching it. Use this before committing to a boot experiment.

### `web.browse`

`web.browse(root, request) -> response`

Resolves a recursive path against an auto view. json=1 returns entry metadata and paginated children; raw responses use the existing file range handling. Returns structured HTTP errors for missing, malformed and bounded-out inputs.

### `web.file`

`web.file(file, name='download', status=200, headers={}) -> response`

Builds an HTTP response that serves a file, optionally with a download name, status and headers. Constructing the response does not start a web server.

### `web.redirect`

`web.redirect(location, status=303) -> response`

Builds an HTTP redirect response with a Location header and selected redirect status. It does not follow the redirect.

### `web.response`

`web.response(body='', status=200, headers={}) -> response`

Builds an HTTP response from body, status and headers for the web runtime to send.

### `web.zip`

`web.zip(filesystem, path, name='download.zip') -> response`

Builds a downloadable ZIP response for a directory in a supplied virtual filesystem. Packaging is handled in-process rather than by a host archiver.

### `windows.acme_plan`

`windows.acme_plan(table, inf, media, target="", system_root="C:\\WINDOWS", root="", predicates=None) -> dict`

Joins an ACME STF object graph with its INF file catalogue and portable media files. Unknown choices and runtime destinations remain explicit; no installer code is executed.

### `windows.acme_table`

`windows.acme_table(file) -> dict`

Parses an ACME setup table into headers, objects, arguments, annotations, and source provenance.

### `windows.assembly_manifest`

`windows.assembly_manifest(value) -> record(identity, files)`

Parses an assembly manifest XML value into identity attribute records and declared file records, including hashes and hash algorithms. It does not install a side-by-side assembly or verify those hashes.

### `windows.batch_plan`

`windows.batch_plan(script, media, variables=None) -> dict`

Inspects DOS batch commands and COPY source declarations using portable media files. Labels, branches, media selection, and external commands remain explicit runtime dependencies; it does not execute the script.

### `windows.catalog_hash`

`windows.catalog_hash(file, algorithm='sha1')`

Computes the Windows catalog membership hash of a file. For PE inputs this uses the format's Authenticode hashing rules rather than a plain whole-file digest.

### `windows.catalog_members`

`windows.catalog_members(value)`

Reads a PKCS#7 catalog and returns its member digest byte strings. Extracting membership does not verify the catalog signature or establish certificate trust.

### `windows.certificate`

`windows.certificate(value) -> certificate record`

Parses one DER X.509 certificate and returns its DER bytes, subject, issuer, SHA-1 fingerprint and a subject/issuer-equality flag named self_signed. That flag is not cryptographic signature verification.

### `windows.clone_file_entries`

`windows.clone_file_entries(entries) -> dict`

Copies a path-to-metadata dictionary and each entry dictionary, preserving insertion order. The two dictionary layers are independently mutable; file sources and other field values remain shared and are not read.

### `windows.creg_compare`

`windows.creg_compare(left, right) -> structural difference report`

Compares two Windows 9x CREG registry files structurally and returns a difference report. This avoids treating different physical record layouts as necessarily different registry contents.

### `windows.creg_from_patches`

`windows.creg_from_patches(name, patches, keys=[], state=1, generation='windows95') -> file`

Constructs a Windows 9x CREG registry file from a name, value patches and optional key records. generation selects the intended Windows 9x layout; this is not an NT REGF hive writer.

### `windows.creg_keys`

`windows.creg_keys(file) -> list[list[string]]`

Returns the key paths represented by a Windows 9x CREG registry file as lists of path components. Empty keys can therefore be preserved independently of value patches.

### `windows.creg_patches`

`windows.creg_patches(file) -> list[dict]`

Converts values in a Windows 9x CREG registry file into declarative registry patch dictionaries. Use creg_keys as well when reconstructing empty keys.

### `windows.csp_registrations`

`windows.csp_registrations(file, strict=True)`

Derives CryptoAPI provider-registration arguments from a 32-bit provider DLL without assigning registry paths or defaults. strict=False returns an empty list for unrecognized registration code; malformed input still fails. The provider is not executed.

### `windows.empty_event_log`

`windows.empty_event_log(size=5MiB) -> file`

Constructs a valid empty legacy Windows event-log file of the requested size. This creates an EVT-format starting state, not an EVTX log.

### `windows.event_log`

`windows.event_log(file) -> list[dict]`

Parses legacy EVT or supported EVTX event-log input into event records. The format is detected from the file; this does not query the host's event-log service.

### `windows.font_names`

`windows.font_names(file) -> list[string]`

Extracts full font-name strings from supported OpenType/TrueType files, including collections. Returns a list of names without installing or rendering the font.

### `windows.hive`

`windows.hive(file) -> registry hive`

Parses an NT REGF registry hive and returns a read-only key/value inspection object. Use hive_from_patches to construct a hive and patch_hive to produce an edited copy.

### `windows.hive_from_patches`

`windows.hive_from_patches(name, patches, keys=None, format=None) -> file`

Builds an NT registry hive from declarative value patches and optional key records. format controls the supported on-disk generation; security and key metadata remain caller-supplied policy.

### `windows.hive_keys`

`windows.hive_keys(file, metadata=False) -> list`

Enumerates an NT hive's key paths, optionally including key metadata. This preserves keys that have no values when exporting a hive for reconstruction.

### `windows.hive_log`

`windows.hive_log(file) -> file`

Constructs the transaction-log companion for the supplied NT hive. The result is a new file; it does not replay a host registry log.

### `windows.hive_patches`

`windows.hive_patches(file, raw=False) -> list[dict]`

Exports an NT hive's values as declarative patches. raw requests raw value representations, useful when preserving types or bytes that should not be interpreted as text.

### `windows.hives_from_inf`

`windows.hives_from_inf(inf, txtsetup=None, extra=None, patches=None, format=None) -> dict`

Builds registry hives from setup INF data with optional TXTSETUP context, extra inputs and patches. format selects the hive generation; the function does not boot Windows or execute setup.

### `windows.icon`

`windows.icon(file, index=0, width=32, height=32)`

Selects an icon image from an ICO, PE or NE file using its index and requested dimensions. Returns image bytes with actual dimensions, bit depth and resource identity; it does not launch or render the executable.

### `windows.inf`

`windows.inf(file) -> INF`

Parses a Windows INF file into section and entry data, with helpers for install sections and registry patches. This is declarative inspection, not execution of every installer directive.

### `windows.inf_patches`

`windows.inf_patches(inf, hive, section='AddReg') -> list[dict]`

Converts a selected INF registry section into patches for the named hive. Returns modifications for later construction rather than changing an existing hive.

### `windows.internet_shortcut`

`windows.internet_shortcut(url, icon_location='', icon_index=0) -> bytes`

Builds InternetShortcut (.url) bytes for a URL with optional icon location and index. It creates the shortcut contents but does not fetch or open the URL.

### `windows.kd`

`windows.kd(channel, architecture='i386', packet_limit=65535, memory_limit=64MiB, event_queue=512)`

Creates a Windows kernel-debugging protocol session over an existing byte channel. The session exposes packets, events, context and memory operations, bounded by the configured protocol limits.

### `windows.memory_image`

`windows.memory_image(file, ranges=None) -> windows.memory_image`

Borrows a file as a read-only physical capture. Optional ranges map (physical_start, file_offset, size); omitted ranges cover the whole file, while an empty list captures nothing. Gaps remain unavailable, not zero-filled. Keep the source unchanged while views exist; this does not parse crash dumps or discover RAM ranges.

### `windows.minidump`

`windows.minidump(file) -> minidump`

Parses a Windows minidump into inspectable dump streams and associated metadata. It operates on the supplied file and does not attach to a live process.

### `windows.module_sources`

`windows.module_sources(files, exclude=[]) -> dict`

Indexes a path-to-source dictionary by normalized DLL basename without reading sources. Matching is case-insensitive, both slash styles are accepted, extensionless basenames gain .dll, and the first non-excluded match wins.

### `windows.mof`

`windows.mof(value) -> MOF document`

Parses Managed Object Format source into a structured document containing its declarations. Pass documents to wmi_repository to construct repository files; parsing alone does not register classes with a running service.

### `windows.msc_snapins`

`windows.msc_snapins(file) -> list[string]`

Extracts snap-in identifiers referenced by an MMC console file. Use the identifiers to select registration metadata; the function does not launch MMC.

### `windows.ne_fastboot`

`windows.ne_fastboot(modules, overlay_path='C:\\WINDOWS\\WIN100.OVL', maximum=64MiB) -> {bin, overlay}`

Constructs the Windows NE fast-boot binary and overlay from supplied modules, returning bin and overlay files. overlay_path is the guest-visible location to encode, not a host output path.

### `windows.patch_hive`

`windows.patch_hive(file, patches, root_name='', keys=[]) -> file`

Applies declarative registry patches to an NT hive and returns a new file, optionally replacing the root name. `keys` lists registry paths to create without adding values; existing keys and their values remain intact. This preserves the source hive's layout, including legacy REGF 1.1 cells. The input hive is not edited in place.

### `windows.pdb`

`windows.pdb(file, stream_limit=256MiB)`

Parses a PDB symbol file with bounded stream sizes. Exposes identity and symbols, including lookup of the nearest symbol to an RVA; symbol parsing does not download files automatically.

### `windows.pe`

`windows.pe(file) -> windows.pe`

Creates a lazy inspection object for a PE32 or PE32+ file. Metadata and data share an owned immutable snapshot; read uses RVAs, while patch returns a separate modified file.

### `windows.pe32_executable`

`windows.pe32_executable(section, labels, fixups, imports=None, entry='entry', image_base=0x400000) -> bytes`

Links a labeled section, fixups and optional imports into a minimal PE32 executable. The caller supplies instruction bytes and policy; the builder lays out headers, RVAs and imports and checks fixup bounds.

### `windows.pe_sign`

`windows.pe_sign(file, identity, replace=False, page_hashes=False) -> bytes`

Signs a PE32 or PE32+ file with RSA/SHA-256 Authenticode entirely in memory and returns new bytes with an aligned WIN_CERTIFICATE and updated checksum. Preserves sections and overlay data. Existing certificate tables require replace=True. Optional page_hashes=True embeds SHA-256 page hashes. No timestamp, nested signatures, or trust-store changes are generated. See docs/pe-signing.md.

### `windows.pkcs7_certificates`

`windows.pkcs7_certificates(value) -> list[certificate record]`

Extracts distinct embedded DER certificates from PKCS#7/CMS input, including legacy catalogs. Returns certificate records; extraction is deliberately separate from signature or trust verification.

### `windows.press_setup_plan`

`windows.press_setup_plan(inf, media, target="") -> dict`

Plans Microsoft Press SETUP.INI media trees and retains companion SETUP.CMD actions and shortcut dependencies. It does not run the setup executable.

### `windows.reactos_record`

`windows.reactos_record(kind, fields) -> bytes`

Encodes a named ReactOS binary-record kind from declarative fields. Layout and field validation stay in Go while values and operating-system policy remain with the caller.

### `windows.registration_expand`

`windows.registration_expand(value, replacements) -> value`

Expands percent-delimited registration variables in replacement-dictionary order, uppercase token then lowercase token, for at most four passes. Unknown tokens remain unchanged and non-string inputs pass through; this is not general case-insensitive environment expansion.

### `windows.registry_children`

`windows.registry_children(entries, hive, key, values=False) -> dict`

Selects direct children from a self-registration registry-state dictionary. values=True selects direct values; otherwise it derives immediate subkeys, without changing the input or recursively returning descendants.

### `windows.registry_partition`

`windows.registry_partition(entries, hive, key, values=False) -> tuple(selected, retained)`

Splits a self-registration registry-state dictionary into selected and retained dictionaries for a hive subtree. values selects the value-identity layout; ordering and payload identity are preserved, and neither result aliases the input dictionary.

### `windows.sdk_inf_plan`

`windows.sdk_inf_plan(inf, media, target="", sections=None, locations=None) -> dict`

Plans Windows 3.x SDK disk catalogues from INF declarations, retaining group and environment actions. Sources are decoded natively from supplied media handles.

### `windows.selfreg_patches`

`windows.selfreg_patches(file, module) -> list[dict]`

Derives registry patches from supported self-registration resources in a PE file or windows.pe object, using module for path substitutions. It does not emulate DllRegisterServer; use the self-registration policy/runner for runtime effects.

### `windows.setup_inf`

`windows.setup_inf(file) -> setup_inf`

Parses command-oriented Microsoft setup INF sections with source locations. plan expands known copy catalogues and branches while retaining runtime queries and unknown loops.

### `windows.setver`

`windows.setver(source, name, major, minor, maximum=16MiB) -> file`

Returns a SETVER driver image with the named executable's reported DOS version added or updated. The original source remains unchanged and maximum bounds the processed image.

### `windows.shortcut`

`windows.shortcut(target, short_target='', description='', arguments='', working_dir='', icon_location='', icon_index=0, target_size=0, system_root='') -> bytes`

Builds Windows Shell Link (.lnk) bytes for a target with optional arguments, working directory, description and icon metadata. It serializes a shortcut; it does not resolve or launch its target on the host.

### `windows.signing_identity`

`windows.signing_identity(certificate, private_key, chain=[]) -> signing identity`

Loads a DER or PEM X.509 certificate and matching unencrypted PKCS#1/PKCS#8 RSA private key for in-memory PE signing. Optional chain certificates are embedded without establishing trust. The identity exposes only its public certificate; private key material is not printable or exportable.

### `windows.symbol_server`

`windows.symbol_server(base_url, name, key, guid=None, age=None, maximum=256MiB, timeout=45)`

Retrieves a symbol file from a symbol-server layout using its name and identity key, with optional PDB GUID/age validation. maximum and timeout bound the download; windows.pdb parses the result.

### `windows.test_signing_identity`

`windows.test_signing_identity(subject, not_before, not_after) -> signing identity`

Generates an ephemeral RSA-2048 key and self-signed code-signing certificate. not_before and not_after are explicit Unix seconds supplied by the caller. Returns an opaque identity with a public certificate attribute; does not install trust or change driver-signing policy.

### `windows.utf16_strings`

`windows.utf16_strings(file, minimum=4) -> list[string]`

Scans a file for printable UTF-16LE strings meeting the minimum length. Returns extracted strings rather than decoding the entire file as text.

### `windows.win9x_vxd_library`

`windows.win9x_vxd_library(base, members, exclude=[]) -> file`

Builds a Windows 9x VxD library from a base and supplied members, excluding requested names. Returns the constructed file rather than installing drivers.

### `windows.win9x_vxd_library_members`

`windows.win9x_vxd_library_members(file) -> list[string]`

Lists the member names contained in a Windows 9x VxD library. It provides inventory without writing member files to the host.

### `windows.win9x_vxd_unpack`

`windows.win9x_vxd_unpack(file) -> file`

Decodes the supported compressed Windows 9x VxD container into an unpacked file. The result can be inspected or rebuilt without a host conversion tool.

### `windows.wmi_repository`

`windows.wmi_repository(files=None, documents=None, default_namespace='root\cimv2', server_name='')`

Either parses supplied repository files or constructs repository files from parsed MOF documents; exactly one input mode is required. Construction uses default_namespace and server_name to resolve repository identities without running WMI.

### `ar` value

An ordered ar member inventory. entries/files expose member records and file views; find(name, occurrence=0) selects a particular occurrence when an archive repeats a member name.

Methods and attributes: `entries`, `files`, `find(name, occurrence=0)`.

### `ar_entry` value

One ar member, combining ownership, mode and timestamp metadata with a file view of its payload. Byte reads and slices operate on this member, not on the enclosing archive.

Methods and attributes: `binary`, `bytes`, `gid`, `hex`, `mode`, `mtime`, `name`, `read`, `size`, `slice`, `uid`.

### `auto` value

A lazy standardized file or directory node. metadata describes the selected source, files lists immediate children, and indexed paths or find recursively enter nested containers. file retains the original bytes; compressed containers expose their decoded children without an extra path component.

Methods and attributes: `bytes(offset=0, size=remaining)`, `file`, `files`, `find(path)`, `metadata`, `name`, `slice(offset=0, size=remaining)`.

### `binary.builder` value

A mutable, bounded byte buffer. append and scalar methods grow it; reserve adds filled space, align adds padding, and patch methods replace existing ranges. bytes() materializes the result and file() exposes it as a file.

Methods and attributes: `align(alignment, fill=0)`, `append(value)`, `bytes()`, `f32be(value)`, `f32le(value)`, `f64be(value)`, `f64le(value)`, `file()`, `i16be(value)`, `i16le(value)`, `i32be(value)`, `i32le(value)`, `i64be(value)`, `i64le(value)`, `i8(value)`, `patch(offset, value)`, `patch_f32be(offset, value)`, `patch_f32le(offset, value)`, `patch_f64be(offset, value)`, `patch_f64le(offset, value)`, `patch_i16be(offset, value)`, `patch_i16le(offset, value)`, `patch_i32be(offset, value)`, `patch_i32le(offset, value)`, `patch_i64be(offset, value)`, `patch_i64le(offset, value)`, `patch_i8(offset, value)`, `patch_u16be(offset, value)`, `patch_u16le(offset, value)`, `patch_u32be(offset, value)`, `patch_u32le(offset, value)`, `patch_u64be(offset, value)`, `patch_u64le(offset, value)`, `patch_u8(offset, value)`, `reserve(size, fill=0)`, `size`, `u16be(value)`, `u16le(value)`, `u32be(value)`, `u32le(value)`, `u64be(value)`, `u64le(value)`, `u8(value)`.

### `binary.cursor` value

A sequential reader with an explicit byte offset. Scalar methods and bytes(size) advance the cursor; seek sets an absolute position, skip moves relatively, and align advances to an alignment boundary. remaining reports unread bytes.

Methods and attributes: `align(alignment)`, `bytes(size)`, `f32be()`, `f32le()`, `f64be()`, `f64le()`, `i16be()`, `i16le()`, `i32be()`, `i32le()`, `i64be()`, `i64le()`, `i8()`, `offset`, `remaining`, `seek(offset)`, `skip(size)`, `u16be()`, `u16le()`, `u32be()`, `u32le()`, `u64be()`, `u64le()`, `u8()`.

### `binary.layout` value

A fixed-size binary record layout. decode reads a record from a source offset; encode serializes supplied field values using the same layout. size is the encoded byte width.

Methods and attributes: `decode(source, offset=0)`, `encode(values)`, `size`.

### `binary.xml_document` value

An immutable parsed XML document. root exposes its element tree; with_root returns a new document and bytes serializes it within an output bound.

Methods and attributes: `bytes(maximum=16MiB)`, `root`, `with_root(root)`.

### `binary.xml_node` value

An immutable namespace-aware element. child/children_named select direct children and attribute performs a named lookup; direct_text excludes descendants while text includes their text. with_children and with_text return edited nodes without changing the original.

Methods and attributes: `attribute(name, default=None, namespace='')`, `attributes`, `bytes(maximum=16MiB)`, `child(name, namespace='')`, `children`, `children_named(name, namespace='')`, `direct_text`, `name`, `namespace`, `prefix`, `qualified_name`, `text`, `with_children(children)`, `with_text(text)`.

### `block_device` value

A random-access block device with declared geometry and capabilities. read/write, zero and trim address byte ranges; extents reports range layout, flush requests durability, and snapshot/commit are available only where supported. stats exposes backend counters.

Methods and attributes: `capabilities`, `commit()`, `extents(offset, length)`, `flush()`, `geometry`, `read(offset, size)`, `size`, `snapshot()`, `stats`, `trim(offset, length)`, `write(offset, value)`, `zero(offset, length)`.

### `byte_channel` value

An owned bidirectional byte transport. read requests a specified amount, read_some returns available bytes within its bound/timeout, write sends bytes, and close releases the endpoint. Channel operations do not imply any particular wire protocol.

Methods and attributes: `close()`, `name`, `read(size, maximum=8MiB)`, `read_some(maximum=64KiB, timeout=30)`, `write(value)`.

### `byte_view` value

A bounded random-access view of binary data. slice derives a subview, bytes reads a range, find returns a match position, find_all collects bounded matches, and find_indices searches several needles. compare performs the requested binary comparison without advancing a cursor.

Methods and attributes: `bytes(offset=0, size=remaining)`, `compare(other, signed=False, exact=False)`, `find(needle, start=0, end=size)`, `find_all(needle, start=0, end=size, limit=1M)`, `find_indices(needles, start=0, end=size)`, `size`, `slice(offset=0, size=remaining)`.

### `clock.profiler` value

An explicit instrumentation collector. span/end time a region, measure wraps a call and counter adds a named quantity. snapshot exposes current measurements and report applies the requested coverage criterion.

Methods and attributes: `counter(name, amount=1)`, `measure(name, function, *args, **kwargs)`, `report(minimum_coverage=0.95)`, `snapshot()`, `span(name)`.

### `clock.span` value

An open timed region belonging to a profiler. end() closes the region and returns its elapsed duration in seconds.

Methods and attributes: `end() -> elapsed seconds`.

### `compiledModule` value

A compilation result rather than an automatically executed program. Check ok and diagnostic before using binary; outputs maps virtual output names to immutable bytes.

Methods and attributes: `binary`, `diagnostic`, `ok`, `outputs (immutable dict of virtual output names to bytes)`.

### `crypto.hasher` value

A mutable incremental digest. update feeds binary input, sum returns the current digest without clearing state, and reset discards accumulated input. Frozen hashers cannot be updated or reset.

Methods and attributes: `reset()`, `sum()`, `update(value)`.

### `directory` value

A mutable in-memory directory tree. write adds file content, mkdir creates directories, find retrieves an entry and remove deletes one. Attributes and security descriptors are stored as image-construction metadata; fat_short_path reports the FAT-compatible short-name path.

Methods and attributes: `fat_short_path(name)`, `files`, `find(path)`, `mkdir(name)`, `remove(name)`, `set_attributes(name, readonly=False, hidden=False, system=False, archive=False)`, `set_security(name, descriptor)`, `write(name, value)`.

### `emulator.execution` value

A retained in-process execution that can be advanced with a bounded run. done distinguishes completed execution from a suspended one; close releases it and closed records that lifecycle state. It is not a QEMU snapshot.

Methods and attributes: `close()`, `closed`, `done`, `run(instruction_limit=0)`.

### `emulator.machine` value

The AMD64 execution context returned by emulator.machine for a 64-bit target; x86 targets use the emulator.x86 value. Calls marshal Windows x64 integer arguments, while hooks and provided exports model APIs. imports_named filters import records and provide_exports binds an ordered name-to-argument-count table. Memory/register methods affect guest state; snapshot copies the context, but callback closure state is not independently forked. See [emulation](../emulation.md) for architecture-specific behavior.

Methods and attributes: `allocate(size=0, value=None, address=None, alignment=16, name='allocation', readable=True, writable=True, executable=False)`, `architecture`, `arguments(count)`, `call(address, args=[])`, `call_export(name, args=[])`, `entry`, `free(address)`, `get_register(name)`, `hook(callback, module='', name='', ordinal=0, address=0, argc=0, convention='win64')`, `imports`, `imports_named(names)`, `invoke(address, args=[])`, `load_module(image, name)`, `local_unwind(frame, target)`, `mappings`, `modules`, `pointer_size`, `profile(limit=256, reset=False)`, `protect(address, size, readable=True, writable=False, executable=False)`, `provide_export(callback=None, module, name|ordinal, argc=0, convention='win64', value=None, writable=True)`, `provide_exports(callback, module, signatures, convention='stdcall')`, `read(address, size)`, `read_cbytes(address, maximum=32KiB, require_terminator=True, unit_width=1)`, `read_cstring(address, maximum=32KiB, encoding='ascii')`, `read_f32be(address)`, `read_f32le(address)`, `read_f64be(address)`, `read_f64le(address)`, `read_i16be(address)`, `read_i16le(address)`, `read_i32be(address)`, `read_i32le(address)`, `read_i64be(address)`, `read_i64le(address)`, `read_i8(address)`, `read_pointer(address)`, `read_u16be(address)`, `read_u16le(address)`, `read_u32be(address)`, `read_u32le(address)`, `read_u64be(address)`, `read_u64le(address)`, `read_u8(address)`, `resolve_export(module, name='', ordinal=0)`, `run(entry=None, instruction_limit=current, until=None)`, `segment_base(segment)`, `set_register(name, value)`, `snapshot()`, `stack`, `stop(reason, detail='', value=None)`, `transfer(address, stack_pointer=current_rsp)`, `use(plugins)`, `write(address, value)`, `write_f32be(address, value)`, `write_f32le(address, value)`, `write_f64be(address, value)`, `write_f64le(address, value)`, `write_i16be(address, value)`, `write_i16le(address, value)`, `write_i32be(address, value)`, `write_i32le(address, value)`, `write_i64be(address, value)`, `write_i64le(address, value)`, `write_i8(address, value)`, `write_pointer(address, value)`, `write_u16be(address, value)`, `write_u16le(address, value)`, `write_u32be(address, value)`, `write_u32le(address, value)`, `write_u64be(address, value)`, `write_u64le(address, value)`, `write_u8(address, value)`.

### `emulator.plugin` value

A named installation callback with explicit mutable state and optional caller-defined attributes. The emulator calls install(machine) when attaching the plugin; state makes checkpoint participation explicit instead of relying on closure-hidden mutations.

Methods and attributes: `install(machine)`, `name`, `state`.

### `emulator.x86` value

A bounded 32-bit guest execution context. run/call/invoke execute modeled instructions; hooks and provided exports bind guest API calls to callbacks. Read/write and register methods inspect or change guest state. checkpoint/restore and snapshot support controlled variants; tracing, watches and profiles provide bounded observations. Acceleration/rewrite/transform operations require their documented code-identity checks; see [emulation](../emulation.md) for their contracts and checkpoint limitations.

Methods and attributes: `accelerate_loop(address, pattern=None, size=0, digest=None, normalize_relative=False, maximum_instructions=1Mi)`, `accelerate_region(entry, start, size, digest, reenter=False, maximum_instructions=1Mi)`, `accelerate_runtime_region(anchor, size, digest, entry_offset=0, anchor_mask=None, name='runtime executable region', normalize_relative=True, reenter=False, maximum_instructions=1Mi)`, `allocate(size=0, value=None, address=None, alignment=16, name='plugin', readable=True, writable=True, executable=False)`, `call(address, args=[], registers={})`, `call_export(name, args=[], registers={})`, `call_trace(reset=False)`, `checkpoint()`, `code_trace(watch, reset=False)`, `configure_call_trace(enabled=True, limit=unchanged, start=0, size=0, reset=True)`, `configure_trace(enabled=True, limit=unchanged, reset=True)`, `entry`, `free(address)`, `get_register(name)`, `hook(...) and use(plugins)`, `imports`, `imports_named(names)`, `invoke(address, args=[], registers={})`, `load_module(image, name)`, `mappings`, `memory_writes(watch, reset=False)`, `modules`, `override(callback, module, name|ordinal, wrap=False)`, `profile(limit=256, reset=False)`, `protect(address, size, readable=True, writable=False, executable=False)`, `provide_export(callback=None, module, name|ordinal, argc=0, convention='stdcall', value=None, writable=True)`, `provide_exports(callback, module, signatures, convention='stdcall')`, `read_cbytes(address, maximum=32KiB, require_terminator=True, unit_width=1)`, `read_f32be(address)`, `read_f32le(address)`, `read_f64be(address)`, `read_f64le(address)`, `read_i16be(address)`, `read_i16le(address)`, `read_i32be(address)`, `read_i32le(address)`, `read_i64be(address)`, `read_i64le(address)`, `read_i8(address)`, `read_u16be(address)`, `read_u16le(address)`, `read_u32be(address)`, `read_u32le(address)`, `read_u64be(address)`, `read_u64le(address)`, `read_u8(address)`, `restore(checkpoint)`, `rewrite(address, pattern=None, size=0, digest=None, callback, name='inline rewrite', normalize_relative=False)`, `run()`, `set_register(name, value)`, `snapshot()`, `spawn(address, args=[], registers={})`, `stack`, `stop(reason, detail='')`, `transfer(address, esp=None, ebp=None, return_address=None)`, `transform(anchor, size, digest, callback, anchor_mask=None, name='runtime transformation', normalize_relative=True)`, `u32_multiply_accumulate(destination, source, count, scalar, carry=0, subtract=False)`, `watch_code(address, size, limit=4096, stack_bytes=0, captures={})`, `watch_memory(address, size, limit=4096)`, `write_f32be(address, value)`, `write_f32le(address, value)`, `write_f64be(address, value)`, `write_f64le(address, value)`, `write_i16be(address, value)`, `write_i16le(address, value)`, `write_i32be(address, value)`, `write_i32le(address, value)`, `write_i64be(address, value)`, `write_i64le(address, value)`, `write_i8(address, value)`, `write_u16be(address, value)`, `write_u16le(address, value)`, `write_u32be(address, value)`, `write_u32le(address, value)`, `write_u64be(address, value)`, `write_u64le(address, value)`, `write_u8(address, value)`.

### `gdb` value

A live remote-debugging session. continue, step, interrupt and wait change or observe target execution; register and memory operations use the selected thread/context. Breakpoints and watchpoints return removable handles. with_state/with_register temporarily modify target state around a callback; packet and monitor expose protocol-specific control.

Methods and attributes: `address_space(page_table, kind='user')`, `architecture`, `breakpoint(address, kind='hardware', size=1, timeout=30)`, `close()`, `continue(timeout=30)`, `current_thread(timeout=30)`, `features`, `generation`, `interrupt(timeout=30)`, `monitor(command, timeout=30)`, `packet(payload, timeout=30)`, `read_memory(address, size, timeout=30)`, `read_register(name, timeout=30)`, `registers(timeout=30)`, `running`, `search_memory(address, size, pattern, limit=256, timeout=30)`, `select_thread(thread, general=True, execution=True, timeout=30)`, `step(timeout=30)`, `threads(timeout=30)`, `wait(timeout=30)`, `watchpoint(address, size, access='write', timeout=30)`, `with_register(name, value, callback)`, `with_state(registers, memory, callback, timeout=30)`, `write_memory(address, data, timeout=30)`, `write_register(name, value, timeout=30)`.

### `gdb_address_space` value

A checked page-table context for reading target virtual memory. page_table and kind identify the address space; generation ties it to the debugger's observed state so stale handles can be rejected.

Methods and attributes: `generation`, `kind`, `page_table`, `read_memory(address, size, timeout=30)`.

### `gdb_point` value

A breakpoint or watchpoint installed in a GDB target. remove deletes it and removed reports that state; with_disabled runs a callback while the point is temporarily disabled.

Methods and attributes: `address`, `kind`, `remove(timeout=30)`, `removed`, `size`, `with_disabled(callback, timeout=30)`.

### `installer` value

A recognized installer container with payload files and detection metadata. plan returns declarative modifications using caller-supplied locations, variables and component selection. It does not apply the plan or run a host installer.

Methods and attributes: `container`, `files`, `find(path)`, `format`, `installscript`, `offset`, `payload`, `plan(locations={}, variables={}, components=None)`, `size`.

### `installscript` value

A parsed InstallShield script with functions, callbacks, calls and effects. find_function locates a declaration; evaluate interprets the supported subset using explicit state and step/depth bounds, returning analysis rather than running a host executable.

Methods and attributes: `blocks`, `callbacks`, `calls`, `effects`, `evaluate(entry='application', strings={}, numbers={}, profiles={}, maximum_steps=200000, maximum_depth=64)`, `find_function(name)`, `functions`, `strings`.

### `installshield` value

An InstallShield cabinet view. Files, groups, components and shortcuts preserve package organization; find selects a member path. version identifies the parsed package generation.

Methods and attributes: `components`, `entries`, `files`, `find(path)`, `groups`, `shortcuts`, `version`.

### `nbd_server` value

An NBD export bound to a block device. serve processes protocol requests on a supplied byte channel, stats exposes activity and close ends service. It does not own an implicit host listening socket.

Methods and attributes: `close()`, `export_name`, `serve(channel)`, `stats`.

### `qemu.v1` value

The backend-specific extension of a running QEMU VM. qmp sends structured monitor requests, qmp_schema inspects available commands, hmp uses the human monitor and block_stats reports storage activity. process exposes backend lifecycle state; these operations are not portable to every VMM.

Methods and attributes: `block_stats()`, `capabilities`, `hmp(command, timeout=30)`, `process`, `qmp(command, arguments={}, timeout=30)`, `qmp_schema(timeout=30)`.

### `qemu_acpi_table` value

A launch descriptor carrying an ACPI table file and its QEMU properties. It is configuration data consumed by the backend, not a running guest object.

Methods and attributes: `file`, `name`, `properties`.

### `qemu_chardev` value

A named QEMU character-backend descriptor. properties are passed through the backend's supported configuration handling when a VM is launched.

Methods and attributes: `name`, `properties`.

### `qemu_device` value

A QEMU device-model descriptor with named properties. Adding the descriptor to a backend configuration selects guest hardware at launch.

Methods and attributes: `name`, `properties`.

### `qemu_netdev` value

A QEMU network-backend descriptor. name identifies the backend kind and properties configure it; the object itself does not start networking.

Methods and attributes: `name`, `properties`.

### `qemu_option` value

A validated QEMU option descriptor with its value/properties. It is interpreted by the backend at launch, not executed by a shell.

Methods and attributes: `name`, `properties`.

### `sfp` value

A parsed SFP package inventory. entries/files expose member metadata and content, find selects a path, and package_label/version identify the package. archive_size/data_offset describe the enclosing container.

Methods and attributes: `archive_size`, `data_offset`, `entries`, `files`, `find(path)`, `package_label`, `version`.

### `sfp_entry` value

An SFP member with its logical path, entry type, timestamps and stored/unpacked lengths. Its read/bytes/slice operations expose decoded member content while payload_offset/record_offset locate its archive records.

Methods and attributes: `binary`, `bytes`, `created_time`, `entry_type`, `file_length`, `flags`, `hex`, `modified_time`, `name`, `parent`, `path`, `payload_offset`, `read`, `record_offset`, `size`, `slice`, `stored_size`.

### `tar` value

An ordered tar archive view. entries/files retain metadata and payload views; find(path, occurrence=0) selects repeated paths without losing earlier archive entries.

Methods and attributes: `entries`, `files`, `find(path, occurrence=0)`.

### `tar_entry` value

A tar member with path, type, ownership, permissions, timestamp and link target. Payload reads are relative to the member; entry_type and link distinguish regular content from directories and links.

Methods and attributes: `binary`, `bytes`, `entry_type`, `gid`, `gname`, `hex`, `link`, `mode`, `mtime`, `name`, `path`, `read`, `size`, `slice`, `stored_size`, `uid`, `uname`.

### `vm` value

A live virtual machine. Input helpers send guest keys, text or pointer events; screenshot captures the display. pause/resume/reset/powerdown/shutdown/stop control lifecycle, wait observes completion and next_event consumes events. channel and debugger open declared guest endpoints; extensions expose backend-specific features. Check capabilities before using optional operations.

Methods and attributes: `backend_id`, `capabilities`, `channel(name, timeout=30)`, `chord(keys)`, `debugger(protocol, create=False, paused=False, timeout=30)`, `detach()`, `extension(name)`, `has_capability(name)`, `key(key, down=True)`, `next_event(timeout=-1)`, `pause(timeout=30)`, `pointer(x=0, y=0, absolute=False, buttons=[], wheel=0)`, `powerdown(timeout=30)`, `reset(timeout=30)`, `result`, `resume(timeout=30)`, `running`, `screenshot(format='png', timeout=30)`, `send_keys(keys)`, `send_text(text)`, `shutdown(timeout=30, force=True, force_timeout=10)`, `status`, `stop(timeout=30)`, `tap(key)`, `type_and_enter(text, enter='enter')`, `wait(timeout=-1)`.

### `vmm_backend` value

A backend configuration and its advertised capabilities. id identifies the implementation; machine, accelerator and block_transport describe backend choices used during validation and startup.

Methods and attributes: `accelerator`, `block_transport`, `capabilities`, `id`, `machine`.

### `vmm_channel` value

A portable request for a named guest communication channel. kind selects its purpose and required controls whether unsupported channels make validation fail.

Methods and attributes: `kind`, `name`, `required`.

### `vmm_disk` value

A guest storage attachment specification. device supplies bytes, bus/unit choose placement, media distinguishes disk from optical media, and read_only/snapshot specify write policy. CHS is optional legacy geometry.

Methods and attributes: `bus`, `chs`, `device`, `media`, `name`, `read_only`, `required`, `snapshot`, `unit`.

### `vmm_display` value

A guest display requirement. mode selects the requested display arrangement and required distinguishes a mandatory capability from an optional preference.

Methods and attributes: `mode`, `required`.

### `vmm_machine` value

A portable VM specification, not a live VM. It records architecture, resources, disks, networks, channels, display and required capabilities for backend validation and vmm.start.

Methods and attributes: `architecture`, `channels`, `cpus`, `disks`, `display`, `memory`, `networks`, `required_capabilities`, `start_paused`.

### `vmm_network` value

A named portable guest-network request. kind selects networking behavior; required controls whether a backend may omit unsupported networking.

Methods and attributes: `kind`, `name`, `required`.

### `windows.address_space` value

An i386 virtual-memory view with explicit CR3 and PAE mode. read/probe/view share physical capture semantics and never substitute zeros for absent data. translate returns mapped, physical_address, page_size, raw entries and fault; a present translation does not guarantee its payload was captured. Faults identify the virtual address, physical address and paging stage. Supports present 4 KiB, non-PAE 4 MiB and PAE 2 MiB mappings; not-present software PTEs, PSE-36 and x64 paging are not recovered. No CPU permission validation is implied. Structure interpretation lives in @stdlib//inspect:memory.star.

Methods and attributes: `directory_table_base`, `pae`, `probe(address, size)`, `read(address, size)`, `translate(address)`, `view(address, size)`.

### `windows.kd` value

A Windows kernel-debugging session over a byte channel. breakin/continue control execution, next_event observes notifications, context/set_context access registers and read/write methods access virtual or physical memory. request/packet expose lower-level protocol operations; file_io installs a handler for guest debugger file requests.

Methods and attributes: `breakin()`, `breakpoint(address, timeout=30)`, `close()`, `context(timeout=30)`, `continue(status=0x10002, timeout=30)`, `file_io(handler=None)`, `next_event(timeout=-1)`, `packet(kind, payload, packet_id=None, timeout=30)`, `read_physical(address, size, timeout=30)`, `read_virtual(address, size, timeout=30)`, `request(api, processor=-1, arguments={}, data=b'', timeout=30)`, `set_context(raw, edi=None, esi=None, ebx=None, edx=None, ecx=None, eax=None, ebp=None, eip=None, eflags=None, esp=None, timeout=30)`, `write_physical(address, data, timeout=30)`, `write_virtual(address, data, timeout=30)`.

### `windows.kd_breakpoint` value

A breakpoint installed through the Windows KD protocol. handle identifies the remote breakpoint; remove deletes it and removed reports the local handle state.

Methods and attributes: `address`, `handle`, `remove(timeout=30)`, `removed`.

### `windows.memory_image` value

A borrowed physical capture. read requires all bytes; probe returns data (the valid prefix), complete and fault. Fault kinds distinguish not-captured bytes from source-error failures. view returns a bounded, lazy read-only file for existing binary readers. Reads/views are limited to 64 MiB each. ranges returns an independent mapping list. address_space constructs an i386 paging view from an explicit CR3 and PAE mode without altering the source.

Methods and attributes: `address_space(directory_table_base, pae=False)`, `probe(address, size)`, `ranges`, `read(address, size)`, `view(address, size)`.

### `windows.pdb` value

A parsed PDB identity and symbol index. GUID/age or signature identify its build; symbols exposes entries and nearest(rva) finds the nearest applicable symbol for address annotation.

Methods and attributes: `age`, `guid`, `nearest(rva)`, `signature`, `symbols`.

### `windows.pdb_symbol` value

One PDB symbol record containing its name, kind and relative virtual address. It identifies metadata in the parsed module, not an automatically resolved live-process address.

Methods and attributes: `kind`, `name`, `rva`.

### `windows.pe` value

A lazy PE32/PE32+ inspection value. Metadata attributes expose headers, sections, imports, exports, resources, strings and debug/type-library data from an owned snapshot. read/disasm use RVAs; patch returns modified file bytes without changing the original. data provides the shared immutable source snapshot.

Methods and attributes: `codeview`, `data`, `disasm(rva, size=256)`, `exports`, `imports`, `info`, `messages`, `patch(rva, data, update_checksum=True)`, `pointer_string_tables(suffix='', minimum=2, maximum=260)`, `read(rva, size)`, `resources`, `sections`, `typelibs`, `version`.

### `windows.signing_identity` value

Opaque RSA code-signing identity. certificate contains the public DER X.509 certificate; private-key material is not exposed by attributes or representations.

Methods and attributes: `certificate (DER bytes; private key is not exposed)`.
