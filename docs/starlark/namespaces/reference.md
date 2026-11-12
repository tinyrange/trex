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

## `macos/softwareupdate.star`

Discover macOS full installers from explicit Apple software-update catalogs.

Discovery reads metadata only; cache_packages acquires complete original sources.
Does not emulate softwareupdate's
machine eligibility rules, execute Distribution scripts, or infer Intel support.

### `cache_packages`

Acquire every original package before parsing or guest execution.

    Returns URL -> complete local file, using the native persistent mirror
    cache by default. No decompression or installer execution occurs here.
    Sizes, duplicate URLs and the aggregate budget are checked before fetching.
    A failed acquisition returns no partial mapping; completed source objects
    remain reusable and interrupted downloads remain resumable in the cache.

    Size is verified; catalog Digest is an opaque cache-identity component,
    not a claim of signature or cryptographic verification. Alternate backends
    may supply fetch(package, cache), returning a complete random-access file
    with no later network dependency. Cache configuration belongs to that
    backend; paths never enter the returned file interface.

### `installers`

Fetch a catalog and one Distribution per installer, returning manifests.

    catalog_url is explicit. languages is an ordered list of exact Distribution
    keys; absence is an error, not a silent omission. fetch(url, maximum) can
    supply an alternative byte transport or offline fixture. Results preserve
    product IDs, versions/builds, package dictionaries (including sizes, URLs
    and digests), all original product metadata, and parsed Distribution data.
    No payload is downloaded, no version is deduplicated, and no host/model
    eligibility filter is applied. Missing version/build metadata is an error.

### `products`

Return installer product dictionaries from a plain/gzip catalog file.

    Results are ordered by product ID. Each has id and the complete original
    metadata dictionary; ordinary updates are excluded. No network requests.

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

## `unix/alpine.star`

Basic Alpine APK v2 handling. Policy stays in Starlark, formats in Go.

Inputs are caller-pinned: read_package requires an independently trusted full
APK SHA-256. Embedded signatures are retained for inspection, not interpreted
as authentication. This is image construction, not an apk-tools replacement:
install scripts/triggers are returned and never silently executed or discarded.

### `install_plan`

Return dependency-ordered payloads and explicit install-effect records.

    Inspired by pkg2's declarative package plans, not its guest script runner.
    No effect is executed. Each record retains its original script file and
    trigger patterns; unknown control effects are retained as phase "other".
    A consumer must implement or explicitly replace every relevant effect.
    Dependency cycles and ambiguous virtual providers require caller policy.

### `merge`

Merge package payloads; conflicting files/effects require explicit policy.

### `parse_index`

Parse APKINDEX text, retaining dependency/provides/checksum fields.

### `read_index`

Read a trusted pinned APKINDEX.tar.gz; package signatures are not trust.

### `read_package`

Validate pinned APK v2 and return metadata, entries and install effects.

### `select`

Select exact name -> version pins, never whichever release is newest.

    Dependency resolution is deliberately separate: pins must include the
    desired closure; validate_dependencies checks it after reading packages.

### `validate_dependencies`

Check bare/exact dependencies, virtual provides and conflicts.

    Range/tilde constraints fail explicitly: this basic pinned policy does not
    implement apk version ordering or silently relax unsupported constraints.
    External capabilities must be explicitly named by the caller.

## `unix/build.star`

In-memory Unix build policy. The engine supplies mechanisms, not a tool image.

### `check`

Require a successful command status and retain bounded failure output.

### `install`

Install a selected tool set; return its inspectable path -> action table.

    No hidden marker interpretation: only this table binds executable paths to
    native capabilities. Files remain in the caller-owned Unix namespace.

### `mkdirs`

Create parents once while constructing a fresh tree.

### `run`

Run a build step with an explicit Linux action and C-locale environment.

### `unpack`

Populate tar entries through portable files, preserving regular-file modes and times.

## `unix/initramfs.star`

Declarative Linux initramfs construction using native newc file views.

### `build`

Build an uncompressed initramfs; supplied /init must be executable.

    Entries use Unix on-disk mode bits. Parent directories are supplied by
    the native builder. No payload is extracted or mounted on the host.

## `unix/kernel.star`

Distribution kernel selection and initramfs module policy; no host modprobe.

### `build_initramfs`

Build a caller-defined initramfs with a validated module closure.

    Firmware, decompression/insmod, and init policy remain explicit caller
    inputs; resolving dependencies does not execute or autoload the modules.

### `modules`

Resolve modules.dep and softdep in dependency-before-dependent order.

    Only selected softdeps are interpreted; malformed records for selected
    modules fail. Repeated softdep records accumulate. Builtins need no payload.
    Crypto/device aliases are not guessed: aliases pins alias -> module name
    (e.g. crc32c -> crc32c_generic), avoiding hardware-dependent provider choice.
    Unknown dependencies and cycles fail; this does not execute modprobe.

### `select`

Select one Alpine vmlinuz and its exact lib/modules release directory.

### `x86_header`

Inspect Linux x86 boot protocol 2.04+; return the borrowed kernel.

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
    ambiguous response. confirm_launcher additionally requires an empty modal
    launcher to close back to the baseline and reopen consistently, preventing
    a coincident desktop transition from being accepted as an input surface.

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

## `windows/emulation/iphlpapi.star`

Explicit adapter inventory for a machine with no IPv4 network adapters.

### `no_ipv4_adapters_plugin`

Models GetAdaptersInfo for an explicitly empty IPv4 adapter inventory.

    This API excludes loopback. It returns ERROR_NO_DATA, never a fabricated
    adapter or successful empty linked list. It is not installed by default;
    disconnected but configured adapters require a different inventory model.

## `windows/emulation/native_exceptions.star`

Execute AMD64 language-specific exception handling in explicit native DLLs.

This bridge marshals RaiseException and binds public runtime exports. Native
NTDLL walks PE unwind tables; native MSVCRT runs matching, cleanup, and catch
funclets. No private installer address or canned exception outcome is used.

### `native_exceptions_plugin`

Bind explicitly loaded AMD64 runtime images; no implicit DLL loading.

    Install after the shared Windows process semantics. `finish(machine)` frees
    owned exception records only after the caller has completed all native calls
    and teardown; it closes this bridge to subsequent raises. `state.raises`
    records requested exceptions, not an assertion that each was handled.
    Hardware exceptions, dynamic function tables and nonlocal transfers across
    an embedding `machine.invoke` boundary are not supplied by this bridge.

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
    `redirection_trust_policy` declares initial policy-16 flags for the modeled
    process. It admits get/set only in a junction-free virtual namespace and
    is not evidence of a real service process mitigation configuration.
    `maximum_file_size` explicitly bounds virtual file writes (16 MiB by default,
    at most 512 MiB); increasing it does not relax the emulator memory limit.
    `command_line` is returned by both GetCommandLine variants. `environment`
    augments a minimal standard Windows process environment and may override
    any of its values. `process_create_provider(machine, request)` supplies a
    bounded semantic result for child-process creation. Each `plugin_factories`
    callback runs after the core
    runtime plugins are constructed and receives a record containing `crt`,
    `cryptoapi`, `bcrypt`, `kernel`, `registry`, and `module_files`; it must return
    one emulator plugin. Registry security changes must use the registry plugin
    so subsequent operations and returned effects share the same state. This lets callers add
    semantic system APIs without coupling the public runner to target policy.
    `object_directories` maps exact NT directory names to explicit allowed access
    masks (or records with access and explicit self-relative security bytes).
    Queries execute RtlQuerySecurityObject in the explicit `object_security_module`.
    This grants no host namespace access or synthetic security descriptors.
    `module_paths` supplies explicit guest filenames for module-handle filename
    queries; it does not load images or infer paths from host file objects.
    `virtual_modules` explicitly adds semantic DLL names to LoadLibrary lookup;
    callers must supply their exports through plugins. No native DLL is loaded. Keys
    missing from those plugins still fail on resolution or invocation.
    `api_set_namespace` supplies the parsed target Windows API-set schema to
    loader lookup, including importer-specific hosts. It neither admits host
    modules nor supplies exports: use explicit virtual_modules or actual module
    sources. `loader_lookup_observer(machine, query)` observes module/procedure
    lookup before return, and may stop a missing required capability before a
    native delay-loader exception. No exception is suppressed or handled for it.
    `token_privileges` is an explicit LUID-to-attribute inventory for the
    modeled caller's primary token (enabled bit 2, enabled-by-default bit 1).
    Native backup/restore registry opens consult the current effective token,
    including subsequent privilege changes and thread impersonation.
    It defaults empty: AdjustTokenPrivileges cannot grant an unowned privilege.
    This is emulator caller policy, not a change to the offline target image.
    `registry_key_deletions` retains successful key-removal events, including
    empty keys and names later recreated. Reconcile them with final registry
    keys and value patches; they are effects, not a committed hive image.
    `registry_effects` additionally captures only surviving touched value bytes,
    final key metadata and removals. Use it rather than replaying historical
    sets after key deletion. Missing key-creation security remains explicit.
    `registry_hive_mounts` supplies explicit static source-hive namespace mounts
    to registry_plugin. It does not emulate hive loading or infer user profiles;
    effects preserve namespace paths for caller-directed hive publication.
    `registry_creation_provider(machine, request)` is passed to registry_plugin's
    on_create_key boundary, including the exact view's existing parent security.
    It must supply all missing descriptors before any key mutation; the runner
    never infers inheritance policy or falls back to copying a parent ACL.
    `generated_entries` retains newly created or changed files and directories
    as path-keyed records with `directory`, file `data`, and optional DOS
    `attributes`, raw file times, `extended_attributes` name/flags/value dictionaries,
    and owned self-relative `security` bytes. EA records are copied, not shared
    with mutable execution state. `generated_files`
    is the content-only compatibility view; use entries to preserve metadata.
    A `hardlink_to` entry names the canonical generated path of the same file
    object. Content-only consumers deliberately lose this identity information.

## `windows/emulation/urlmon.star`

Explicit disconnected URLMon policy for offline installer execution.

### `offline_urlmon_plugin`

Rejects HTTP(S) stream binding when the modeled machine has no network.

    This must be selected explicitly by the image/probe, not installed as a
    default fallback for a missing network implementation. No request is sent,
    no completion callback is invented, and no content is returned.

## `windows/emulation/wininet.star`

Explicit disconnected WinINet session model; no network access.

### `disconnected_wininet_plugin`

Creates local Internet sessions, but never fabricates network content.

    Only direct/preconfigured sessions and their owned lifetime are
    currently modeled. Other operations remain missing rather than succeeding.

## `windows/emulation/winrt.star`

Bounded Windows Runtime string-reference semantics.

### `disconnected_network_information_plugin`

Exposes only the no-Internet-profile NetworkInformation static query.

    This explicitly selected machine has no connected network. No activation
    or networking fallback is installed for other classes or methods.

### `string_reference_plugin`

Provides caller-owned UTF-16 HSTRING references, not runtime activation.

    Headers and source buffers remain caller-owned and immutable until their
    last use. Deleting a reference never frees either. Owned/duplicated strings
    and other Windows Runtime APIs are deliberately not supplied.

## `windows/emulation/wintrust.star`

Bounded Authenticode verification for an explicitly disconnected machine.

### `offline_wintrust_plugin`

Verify embedded signatures using explicit media roots, time and policy.

    Models generic verify-v2 FILE/VERIFY/CLOSE, no UI, chain revocation and
    cache-only retrieval (0x1440), with an empty revocation cache. The supported
    Windows policy 0x23c00 permits offline revocation for individual/commercial
    publishers and ignores timestamp revocation. Both chains still undergo
    signature, time, purpose and explicit-root validation. No host trust/clock
    or network is consulted. Disallowed certificates are never accepted.

    Unsupported formats, policies and invalid cryptographic inputs stop
    execution, rather than falsely reporting successful trust. Provider-state
    inspection is limited to borrowed signer/chain/DER views (no CERT_INFO or
    CMSG_SIGNER_INFO). This is not a general WinTrust provider.

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

Extract single cabinets from owned files or caller-supplied FDI streams.

    Callback input is bounded at 256 MiB; decoded output at 512 MiB. Real native
    read/write/notification callbacks execute in-process, including pointer-sized
    FDINOTIFICATION fields and raw CAB timestamp/attribute metadata. No child
    process or completion marker is implied by extraction.

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

### `bcrypt_hash_plugin`

CNG SHA-1/SHA-256 pseudo-algorithm handles and owned ordinary hashes.

    Uses the documented Windows 10 SHA pseudo handles. Unkeyed non-reusable hashes use an owned opaque object. The 256-byte
    caller-object footprint matches measured target primitive-provider queries
    and successful native creation; no private Microsoft object layout is exposed. Other algorithms and flags stop explicitly;
    hashing never establishes certificate, catalog or signature trust.

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

Finds classes served by an x86 or AMD64 DllGetClassObject implementation.

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

## `windows/selfreg/objects.star`

Explicit object-manager directory facts, independent of the host namespace.

### `object_directories_plugin`

Open declared absolute directories with caller-supplied allowed access.

    `directories` maps exact NT names to allowed specific/standard access masks.
    Values may also be records with `access` and explicit self-relative `security`
    bytes. NtQuerySecurityObject checks owned-handle rights and delegates projection
    to the real mapped target NTDLL RtlQuerySecurityObject. `security_module` may
    name a separately admitted native implementation image, without exposing its
    unrelated optional exports to the target loader. Missing security facts
    or native implementation fail closed. These are admission facts, not an ACL
    access evaluator. No default objects, host namespace, enumeration, mutation, generic access,
    inheritance or symbolic links are supplied. Relative opens require an owned
    directory root. Unknown names in this closed namespace return not-found.

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

### `registry_handles_plugin`

Connect owned registry keys to same-process kernel handle operations.

### `registry_plugin`

Returns a registry plugin initialized from hive-style dictionaries.

    Initial values are queryable but are not reported as writes. Each value uses
    the same `hive`, `key`, `name`, `type`, and `value` fields as a hive patch.
    Initial keys use `hive` and `key`; they make empty setup-created namespaces
    observable without being reported as writes. `hives` may map hive names to
    parsed `windows.hive` objects; these are consulted lazily and overridden by
    explicit keys, values, and subsequent writes. Static `mounts` entries
    contain hive, key (encoded non-root namespace path), and parsed source hive.
    Mounts are nonoverlapping immutable inputs, not RegLoadKey/NtLoadKey emulation.
    Their metadata and values remain source-backed; effects retain mounted
    namespace paths for caller-directed publication. Removing a mount or an
    ancestor is unsupported, rather than deleting across hive boundaries.
    RegDeleteKey(A/W/Ex) deletes only leaves, including lazy source values;
    open references remain owned and cannot alias a recreated name. Ex accepts
    default/native views only. Alternate views, empty-name self-deletion and
    complete NT ACL authorization are not modeled. key_deletions() reports
    successful key removals, including empty source keys and names later
    recreated; callers must reconcile those events with final keys/values.
    effects() captures surviving owned value bytes, final key metadata and
    removals before hive teardown; unlike patches(), it cannot resurrect a
    write made to an earlier deleted key object. Neither report supplies
    missing key-creation security or implies a committed hive image.
    on_create_key(machine, request) may supply exact final descriptors for
    every missing key in one native create request. It runs before mutation
    and must return an encoded-key-to-bytes dictionary covering missing_keys.
    Request metadata includes API, creator descriptor address, class/options
    and access. parent_key and parent_security identify the nearest existing
    ancestor in this exact view, including transacted security; an unknown
    descriptor stays None. Caller-specific inheritance/identity policy stays outside this
    registry namespace model. Without a provider, creation security is unknown.
    on_open_key(machine, request) optionally resolves existing-key opens against
    the exact overlay/source descriptor. Return concrete granted rights or None
    for access denied. Unknown descriptors remain None, never a null DACL.
    This callback does not establish new-key authorization or inheritance.
    effective_token_privileges() supplies a fresh LUID-to-attributes mapping for
    backup/restore opens of existing keys. No provider fails closed; no enabled
    backup/restore privilege returns access denied. New backup/restore keys
    remain unsupported rather than inventing privileged creation security.

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
    `redirection_trust_policy` declares initial policy-16 flags for the modeled
    process. It admits get/set only in a junction-free virtual namespace and
    is not evidence of a real service process mitigation configuration.
    `maximum_file_size` explicitly bounds virtual file writes (16 MiB by default,
    at most 512 MiB); increasing it does not relax the emulator memory limit.
    `command_line` is returned by both GetCommandLine variants. `environment`
    augments a minimal standard Windows process environment and may override
    any of its values. `process_create_provider(machine, request)` supplies a
    bounded semantic result for child-process creation. Each `plugin_factories`
    callback runs after the core
    runtime plugins are constructed and receives a record containing `crt`,
    `cryptoapi`, `bcrypt`, `kernel`, `registry`, and `module_files`; it must return
    one emulator plugin. Registry security changes must use the registry plugin
    so subsequent operations and returned effects share the same state. This lets callers add
    semantic system APIs without coupling the public runner to target policy.
    `object_directories` maps exact NT directory names to explicit allowed access
    masks (or records with access and explicit self-relative security bytes).
    Queries execute RtlQuerySecurityObject in the explicit `object_security_module`.
    This grants no host namespace access or synthetic security descriptors.
    `module_paths` supplies explicit guest filenames for module-handle filename
    queries; it does not load images or infer paths from host file objects.
    `virtual_modules` explicitly adds semantic DLL names to LoadLibrary lookup;
    callers must supply their exports through plugins. No native DLL is loaded. Keys
    missing from those plugins still fail on resolution or invocation.
    `api_set_namespace` supplies the parsed target Windows API-set schema to
    loader lookup, including importer-specific hosts. It neither admits host
    modules nor supplies exports: use explicit virtual_modules or actual module
    sources. `loader_lookup_observer(machine, query)` observes module/procedure
    lookup before return, and may stop a missing required capability before a
    native delay-loader exception. No exception is suppressed or handled for it.
    `token_privileges` is an explicit LUID-to-attribute inventory for the
    modeled caller's primary token (enabled bit 2, enabled-by-default bit 1).
    Native backup/restore registry opens consult the current effective token,
    including subsequent privilege changes and thread impersonation.
    It defaults empty: AdjustTokenPrivileges cannot grant an unowned privilege.
    This is emulator caller policy, not a change to the offline target image.
    `registry_key_deletions` retains successful key-removal events, including
    empty keys and names later recreated. Reconcile them with final registry
    keys and value patches; they are effects, not a committed hive image.
    `registry_effects` additionally captures only surviving touched value bytes,
    final key metadata and removals. Use it rather than replaying historical
    sets after key deletion. Missing key-creation security remains explicit.
    `registry_hive_mounts` supplies explicit static source-hive namespace mounts
    to registry_plugin. It does not emulate hive loading or infer user profiles;
    effects preserve namespace paths for caller-directed hive publication.
    `registry_creation_provider(machine, request)` is passed to registry_plugin's
    on_create_key boundary, including the exact view's existing parent security.
    It must supply all missing descriptors before any key mutation; the runner
    never infers inheritance policy or falls back to copying a parent ACL.
    `generated_entries` retains newly created or changed files and directories
    as path-keyed records with `directory`, file `data`, and optional DOS
    `attributes`, raw file times, `extended_attributes` name/flags/value dictionaries,
    and owned self-relative `security` bytes. EA records are copied, not shared
    with mutable execution state. `generated_files`
    is the content-only compatibility view; use entries to preserve metadata.
    A `hardlink_to` entry names the canonical generated path of the same file
    object. Content-only consumers deliberately lose this identity information.

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

## `windows/selfreg/transactions.star`

Bounded, isolated KTM registry transactions for native installer calls.

### `registry_transactions_plugin`

Model unnamed local transactions with synchronous commit and rollback.

    Registry operations through transacted handles use private overlays. Ordinary
    handles continue seeing committed state. Commit publishes only after checking
    that the parent overlay has not changed; concurrent writers are unsupported,
    never silently overwritten. Rollback and closing an active transaction discard
    its overlay. Named/distributed transactions, timeouts, notifications, alternate
    registry views, and non-close use of terminal transacted keys fail closed.

## `windows/selfreg/typelib.star`

Registry policy for MSFT and SLTG type libraries exposed by windows.pe().

### `typelib_patches`

Builds registry operations from parsed type-library facts.

### `typelib_registration_patches`

Registers referenced or self-registering embedded MSFT and SLTG type libraries.

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
    KUSER_SHARED_DATA wall clock visible to native code. Its read-only
    NtSystemRoot is initialized from SystemRoot (or windir, then C:\Windows);
    later process-environment changes do not change that boot-time fact.

### `event_log_plugin`

Models registration-time Event Log and disabled ETW providers.

### `gdi32_plugin`

Models registration-visible GDI stock objects without a host display.

### `kernel32_plugin`

Models deterministic allocation, strings, paths, files, and OS facts.

    `module_paths` maps module names to explicit guest filenames, preserving
    their spelling. GetModuleFileName uses the requested HMODULE, not the
    primary filename for every image. An unspecified dependency keeps its
    loader name; no host path or guessed system directory is substituted.
    `api_set_namespace` is an optional parsed target namespace from
    windows.api_set_namespace. API-set loads and handle lookup resolve its actual
    host using the native caller's mapped module as importer. Host admission and
    exports remain explicit: a namespace does not supply missing DLLs or APIs.
    `on_loader_lookup(machine, query)` observes module/procedure lookups before
    their return; queries include kind, module and found, plus procedure or API
    fields. A capability guard may raise there; machine.run can retry the same
    pending lookup after the required implementation has been installed.
    `version.native_machine` may explicitly select IMAGE_FILE_MACHINE_I386
    (0x14c) or AMD64 (0x8664) for native-system/WOW64 queries. Omission preserves
    a native process of the emulated image architecture; it never uses the host.
    `files` maps guest paths to bytes or trex files. They are made
    available directly to target file APIs without host filesystem staging.
    `directories` supplies empty or otherwise implicit guest directories.
    `prepared_file_entries` is cloned; names sharing an entry retain their
    alias relationship without sharing mutable metadata with the caller.
    File handles and mappings retain that object across rename/recreation.
    CreateHardLinkA/W requires explicit local NTFS `volumes` facts; distinct
    declared drives reject cross-volume links. Links share content, security,
    file IDs, and sharing checks. Delete-pending names are removed after the
    last modeled handle/view releases the object. CreateFileA/W DELETE_ON_CLOSE
    retains the requesting open object across DuplicateHandle and rename; it
    requires delete sharing and does not delete a later path occupant. The
    distinct NtCreateFile FILE_DELETE_ON_CLOSE option remains unsupported.
    Reparse links, drive aliases,
    full NT authorization, and resizing live mapped views are not modeled.
    `redirection_trust_policy` explicitly supplies initial RedirectionGuard
    flags (0..3) for this modeled process, not facts about a host or booted guest.
    Only policy 16 get/set and a junction-free namespace are admitted; omitted
    policy facts, other policies and reparse inputs fail closed. No junction
    traversal, trust classification or audit-log implementation is implied.
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

    wcstok_s uses caller-owned continuation pointers and UTF-16 code-unit
    offsets, retaining the terminator address after exhaustion. Its invalid
    arguments set the modeled per-thread errno to EINVAL and stop explicitly:
    the secure CRT invalid-parameter handler/fail-fast policy is not simulated.

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

    Native ACE append and absolute/self-relative descriptor validation support
    bounded simple ACEs, real SID/mask bytes, NT statuses and failure atomicity.
    Descriptor conversion preserves native component order and sizing behavior;
    it is serialization, not access authorization. Self-impersonation and bounded
    native token duplication/thread attachment retain owned token objects and
    independent privilege attributes. Native privilege adjustment reports real
    changes and STATUS_NOT_ALL_ASSIGNED; it cannot invent unowned privileges. Existing non-simple ACE
    validation remains an explicit gap. None of these changes image ACL policy.

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

Models Winsock with explicit DNS data and exclusively in-memory connections.

    connect(address_bytes, port, server_channel) returns True to accept a
    connection. The provider receives the server end of a memory pair; there
    is no native networking fallback. Retain mutable server state in a plugin.

## `windows/servicing/appx_native.star`

Publish AppxReg's native queued user-registration invalidations atomically.

Manifest registry declarations constrain package names only. The real AppxReg
Commit and WCP primitive executor decide which existing user records to remove.
This is not AppX deployment, provisioning, or a CBS completion declaration.

### `apply_native_appx`

Run the qualified native AppX queue and publish authorized deletions on root; reject missing hives, incomplete queues and stale sources.

### `appx_package_authority`

Derive deletion authority from bounded, explicitly selected AppX jobs.

### `plan_native_appx`

Validate deletion-only AppX effects against job authority and the exact source hive; return registry plans without publication.

## `windows/servicing/backup.star`

BootRecovery backups selected from admitted component transitions.

WCP 9703 ContainsBackup (113310) selects the exact category identity.
FormatBackupFileNameWithReallocate (26c05c) uses the low 32 bits of
RtlHashEncodedLBlob, lowercase, plus the sanitized component filename.
Backups are independent files, not aliases of the protected source object.

### `apply_update_backups`

Preflight the complete backup plan, then publish independent copies and retirements on root; return selected/written/retired counts.

### `plan_update_backups`

Select BootRecovery copies and retirements with source/destination epochs.

    Audit mode checks payload bytes, including obsolete backups before removal.
    Non-audit mode uses admitted source identities and declaration-selected
    retirements; it does not claim to verify the removed bytes.

## `windows/servicing/boot_installers.star`

Native offline FVE/SecureBoot admission; not firmware or CBS completion.

### `apply_update_boot_installers`

Execute bounded offline boot-installer jobs and publish checked effects; online firmware and CBS lifecycle remain separate.

### `boot_installer_jobs`

Collect supported offline FVE and SecureBoot jobs from admitted runtime transitions; reject unsupported declarations.

### `publish_secureboot_effects`

Validate and publish the qualified SecureBoot value on root; return emitted patches, not firmware-update completion.

### `validate_secureboot_effects`

Require the single supported native AvailableUpdates write and return its selected SYSTEM key.

## `windows/servicing/catalog_hints.star`

Publish catalog lookup hints, never cached signing levels or trust verdicts.

The admitted DriverStore path writes v1 hints for each non-catalog member of
an explicitly cataloged INF repository. Verify the exact source bytes, nested
catalog signature, timestamp chains and each member before any EA mutation.

### `apply_catalog_hints`

Validate catalog and metadata bindings, optionally rehash payloads, then publish hint EAs. Audit mode rejects plans without payload proof.

### `audit_catalog_hints`

Verify emitted hints against the actual registered catalog tree.

    This is read-only and independent of the publication planner. A different
    catalog leaf is not automatically equivalent: it must exist in CatRoot,
    have an authenticated signing timestamp and chains, and cover the member's
    logical bytes. Duplicate catalog leaves must contain identical bytes.
    No reference-image catalogs or filesystem objects participate.

### `catalog_hint_name`

Decode a v1 lookup hint without treating it as a trust decision.

### `package_hint_paths`

Read exact signed SPC Hint attributes, never infer eligibility from PE type.

    CBS9703 CipSetEasForEachHint (6b90c) skips short v2 subject IDs,
    selects OID 1.3.6.1.4.1.311.12.2.1, flags&10001==10001 and Hint.
    Its offline path is Windows/WinSxS/<NUL-terminated UTF16 value>.

### `plan_driver_catalog_hints`

Plan signed driver catalog hints for explicit amd64 host jobs and repository bindings; do not modify root.

### `plan_package_catalog_hints`

Verify actual catalogs and members in execution order, retaining last writer.

    Absent signed paths are not installed by this operation. Native tries the
    open and reports failure; we record absent paths without creating files.
    Audit mode verifies catalog signatures/chains and present files against
    signed catalog members, including
    retained compressed base content. Non-audit mode publishes declared hints
    without eagerly reconstructing every payload. Neither mode fabricates a
    cached signing level. Publication still checks namespace/object metadata.

## `windows/servicing/catalogs.star`

Package catalog preparation and candidate publication.

Optional signature auditing qualifies trust against unchanged ROOT anchors.
MUM membership is always checked; neither mode fabricates a trust verdict.

### `apply_package_catalogs`

Publish checked MUM/CAT bytes and CatRoot aliases on a candidate tree.

    prepared must be the unchanged result of prepare_package_catalogs against
    this baseline. If omitted, preparation runs first. This mutates root and
    preserves existing file security; the caller owns cross-phase rollback.
    Native trust-provider policy and catalog database rebuilding are separate.

### `prepare_package_catalogs`

Capture catalog/MUM bytes and membership without changing the tree.

    Signature/timestamp-chain auditing defaults on. Explicit non-audit mode
    requires caller-admitted transport sources and never asserts trust.

## `windows/servicing/components.star`

Exact CSI composition, installed-mark and winner analysis. No state writes.

The result is not complete servicing: driver operations, payload/effect
materialization, catalog verification and transaction persistence are separate.

### `analyze_servicing_components`

Count complete installed ownership and project changed compositions.

    Unchanged deployments use persisted c! membership, not guessed dispositions.
    Every changed/staged deployment still follows its complete manifest graph.
    audit_baseline additionally recomputes and checks every unchanged graph.

### `bind_servicing_runtime_sources`

Bind exact versioned runtime sources to staged/resident store entries.

    This does not stage files or authorize activation. Family keys are never
    used as payload identities. Hash-derived paths must be unique, and each
    exact identity must have been resolved by component analysis or staging.
    Returned lazy references retain provenance; callers still need content,
    security, attributes, compression and transaction policy before writing.

### `open_servicing_runtime_source`

Open and revalidate one exact runtime source; never mutate an image.

    DCS is a resident storage container, not the projected file's byte stream.
    The bounded native Identity/SHA256 policy must agree after expansion.

### `plan_servicing_payloads`

Join exact staging compositions to store-file plans, not runtime effects.

    Resident manifests are classified for subsequent payload verification, not
    treated as evidence of completed staging. New plans contain every selected
    component's manifest and declared files; package catalogs remain separate.

### `project_servicing_sources`

Project source edits for successful staging then ordinary installation.

    This is conditional construction analysis, NOT evidence that those phases
    succeeded. Pin edits require staged manifests; staged-source edits require
    completed payload staging. Pending-content staging is not modeled here.
    Driver references still require their separate operation queue. No writes
    are applied and no composition/status/payload completion is inferred.

### `verify_resident_payloads`

Verify exact resident store files after DCS expansion; no catalog trust.

    Nested Identity SHA-1/SHA-256 and legacy SHA-1 ImageDigest declarations
    are checked independently. Unsupported hash policies fail, never bypass.
    COMPONENTS-backed manifest resolution has already validated full identities;
    reject path-hash collisions rather than selecting a filename by version.

### `verify_servicing_catalogs`

Check staged-source catalog integrity, complete membership and X.509 paths.

    Anchors come only from the unchanged base ROOT registry store. Code-signing
    and timestamping paths are checked at each authenticated timestamp. This is
    NOT Windows trust-provider policy: root-store property policy, revocation,
    disallowed CTLs and CBS publisher policy still require separate validation.
    Nothing is installed, staged or marked by this content inspection.

### `verify_servicing_payloads`

Force native reconstruction and reads; no installed-state claims/writes.

    This verifies new component content against available graph/manifest hashes.
    It does not establish catalog trust or validate the resident content reused.
    The result retains plans rather than all decoded file bytes in memory.

## `windows/servicing/csi.star`

Value-scoped CSI publication for a caller-owned candidate directory.

Not a complete CBS transaction or package-completion writer.

### `apply_csi_state`

Build COMPONENTS/SOFTWARE changes, optionally auditing serialized output; preserve unrelated values and return CSI effects, not package completion.

### `inspect_native_package_context`

Inspect the exact 9703 CBS metadata prefix; no image writes or commit.

    Runs the real serviced CRT, MUM parser, WCP identity factory, constructors
    and package population against caller-supplied parsed hive sources. These
    are function-level controls, NOT a fully initialized servicing session or a
    completed stage/install. Only ordinary object inputs are linked manually:
    the native identity authority and the constructed store-parameter object.
    No package/session/CSI success, Active or completion flag is supplied.

    Version-gated private addresses come from the exact matching public PDBs.
    Returns the runner's effects/stop evidence; result retains machine, pointers
    and bounded steps for follow-up in the inspection REPL. Do not infer success
    from a returned dictionary: require each native step's return/value. A fresh
    run is needed after contributing code/input changes; snapshots share plugin
    state and must not be treated as independent registry/filesystem variants.

## `windows/servicing/driver_apply.star`

Ordered driver/ownership/file construction; CBS finalization remains separate.

### `finish_update_driver_file_tree`

Publish a completed native session, then apply files WITHOUT restaging.

    The session checks actual phase returns, array guards, closed references,
    backing-hive bytes and complete native file objects before yielding a clone.
    Original COMPONENTS must still match the owner's source inventory. Changes
    stay on that independent tree until the entire function returns successfully.

### `prepare_update_driver_file_tree`

Build an independent direct-replacement candidate and file report. This uses qualified equivalent-INF replacement, not the separate native-session API; version is retained for caller compatibility.

### `prepare_update_native_driver_file_tree`

Execute the native transaction on staged sources, then finish once.

    Neither target mutations nor partial phase output escape on failure. In
    particular, do not restage after native driver installation: that would
    overwrite native security, aliases and deletions before qualification.

## `windows/servicing/driver_catalogs.star`

Bounded readonly catalog metadata for the observed offline-driver path.

Does not implement WinVerifyTrust, catalog installation or publisher policy.
Unknown APIs stop at their native call boundary without returning success.

### `update_driver_catalogs`

Create an emulator plugin for catalog enumeration and metadata, with explicit kernel and CryptoAPI state.

## `windows/servicing/driver_cleanup.star`

Retire one completed native driver host; never complete a driver phase for it.

CloseContext and DLL detach do not close every process-owned registry handle.
The isolated host is no longer used after this boundary. Release those references
through RegCloseKey and unload its owned mounts through the existing provider,
which serializes actual final effects before removing the namespace. No pending
mount, live reference, hive edit or phase result is discarded or fabricated.

### `retire_update_driver_process`

Retire a completed native driver host once, only after all phases including Close; reject live or already-retired sessions.

## `windows/servicing/driver_destinations.star`

Independently qualify native driver projections outside its source inventory.

The host input inventory includes selected source objects, not every runtime
alias. Authorize replacement only by the admitted manifest's exact after hash,
an entirely unchanged resident dependency, or an exact staged driver catalog.
These checks authorize content construction, not CBS package completion.

### `prepare_update_driver_destination_authority`

Keep only actual native output leaves, releasing the large full hierarchy.

### `qualify_update_driver_destinations`

Bind generated driver destinations to admitted payload and prepared path authority; return qualified paths and counts.

## `windows/servicing/driver_direct.star`

Direct equivalent-INF replacement; one staged payload and one file pass.

No native installer execution, guest-side repair, or prepared-image cache. The
caller still owns catalog trust, CSI/CBS lifecycle and non-driver installers.

### `finish_update_direct_driver_tree`

Continue a staged candidate without replaying recovery generation.

### `prepare_update_direct_driver_tree`

Clone root, stage payloads once and apply qualified direct driver/file changes; return the independent candidate and phase report.

## `windows/servicing/driver_eas.star`

Persist the measured offline DriverStore catalog-hint EA operation.

This is not a general protected-EA, catalog-trust or access-check implementation.
Only an actual owned FILE_WRITE_EA handle to the explicit offline repository and
one structurally valid v1 $CI.CatalogHint update are admitted. Other policy stops
before returning to native code. Existing unrelated EAs and hardlinks survive.

### `update_driver_eas`

Create an emulator EA plugin that validates and records native writes against the supplied kernel file objects.

## `windows/servicing/driver_files.star`

Apply the final native driver's file objects, not content-only copies.

Requires closed native file/mapping references and no pending deletions. Native
hive writes are verified against the mount provider's already-built backing
files. Unknown target paths, missing final file security and unobserved directory
creation policy fail before changing the image.

### `apply_update_driver_file_effects`

Recheck all native file-plan guards, then publish files, metadata, links and deletions to root; return effect counts.

### `collect_update_driver_entries`

Snapshot changed native file entries and link targets from the supplied kernel state.

### `plan_update_driver_file_effects`

Plan native file-object publication only after handles, views and pending deletes are closed; return guarded file/directory effects.

### `prepare_update_driver_transaction`

Return a fully verified independent tree; never partially publish effects.

    The native mount provider must have closed every hive epoch. Its independently
    committed backing hives and the final kernel file objects describe one native
    execution. Callers publish only the returned root after this function succeeds.

## `windows/servicing/driver_hives.star`

Bounded native offline-driver hive mount provider.

Models the observed successful-buffer/owned-reference SSU path, not a general
kernel hive lifecycle or authorization model. A successful ordinary unload first
constructs actual backing-hive effects, as does an owned native flush while
references remain open; pending/busy mounts never fake success.
Namespace teardown is kept outside the next captured native mutation epoch.

### `update_driver_hive_mounts`

Create an emulator plugin for explicit offline hive mounts and flush epochs; host mount namespaces are not published target keys.

## `windows/servicing/driver_inputs.star`

Reconstruct the exact immutable file inputs of the pinned driver host.

### `build_update_driver_input_entries`

Build native virtual-file inputs from explicit driver jobs and the actual INF/DriverStore namespace, retaining file metadata.

## `windows/servicing/driver_owners.star`

Ordinary CBS driver owner mutations, independently verified against native CBS.

The pinned 26100.9703 Add/RemoveDriver owner controls (RVAs 10f9d4/10a234)
establish first/last owner results and zero-valued additions. All 1,648 update
operations were compared to native output. This constructs those same physical
keys, preserving literal Base64 components and unrelated values/security.
It is NOT driver installation: callers publish only with the completed matching
driver-store transaction. No package state, privileges or completion flags change.

### `apply_update_driver_owners`

Require the original COMPONENTS digest before publishing the prepared owner hive; return owner-change counts.

### `order_update_driver_owner_operations`

Ordinary forward DOQ execution, not queue registration order.

    CBS9703 DoqExecuteImmediate 10dfed..10e06e installs noncritical then
    critical groups before either uninstall pass. DoqIsCritical 10bb98
    groups every case-insensitive INF match with a CRITDOQ- update; the
    update prefix comparison at 12b892 is case-sensitive wcsncmp.
    Input is the already reduced, uncompleted queue in sequence order.

### `plan_update_driver_owners`

Apply owner primitives in the supplied execution order, without sorting.

## `windows/servicing/driver_random.star`

Execute the source NTDLL's self-initializing RtlRandomEx for offline drivers.

The process cookie is an explicit virtual-process input, not an observed target
OS cookie, trust verdict, privilege or servicing state. No initialization flag or
random table is patched. The source routine initializes its own state. Its only
admitted process query is ProcessCookie for the current virtual process. This
bounded AMD64 path does not implement arbitrary NTDLL syscalls or initialization.

### `update_driver_native_random`

Create a qualified native random/process-cookie plugin; require an explicit ULONG cookie and the expected native exports.

## `windows/servicing/driver_replace_hives.star`

Construct paired, equivalent-INF DriverDatabase replacements without x86.

Preserve installed configuration and physical hive placement. The caller supplies
complete new repositories, not templates' INF-only FileSize values. Nothing is
published until all hives have been built and read back successfully.

### `apply_version_only_driver_hives`

Preflight every source hive before publishing version-only driver replacements; return the number of written hives.

### `plan_version_only_driver_hives`

replacements carry exact before/after names, version, size and INF name.

    Each replacement must already have passed the ordered-INF equality guard.
    This routine requires an actual old package; absent or multiple bindings
    are not silently repaired from a manifest template.

## `windows/servicing/driver_replacements.star`

Plan version-only replacements from actual driver inputs, without emulation.

This is deliberately not a general INF installer. A matching CBS first/last
owner pair, exact manifest hashes, and unchanged INF instructions are required.
The plan does not itself publish files, invent package state, or run a guest.

### `plan_version_only_driver_replacements`

Bind before/after driver sources and owner operations, accepting only supported equivalent-INF version transitions.

### `require_version_only_driver_inf`

Reject changed instructions, including ordering and duplicate directives.

## `windows/servicing/driver_repositories.star`

Complete native DriverStore layouts for admitted version-only replacements.

CSI runtime projections are not repository inventory (including WOW64 drivers).
Authorize every relative name against both the installed layout and the new
manifest, verify all logical source bytes before writing, then link exact store
objects. No native installer execution or architecture-wide path rewriting.

### `apply_direct_driver_repositories`

Re-resolve and verify repository source epochs before publication; optionally audit payload bytes and return file/directory counts.

### `plan_direct_driver_repositories`

Plan repository files/directories from explicit replacement jobs and manifests, retaining source epochs for publication.

## `windows/servicing/driver_retire.star`

Retire repository directories only for admitted last-owner replacements.

Called after replacement files, registry bindings and CSI owners are published
on the private candidate. Retained source packages and WinSxS files are untouched.

### `apply_direct_driver_retirement`

Reject stale files or extra namespace entries before deleting planned predecessor repositories; return removal counts.

### `plan_direct_driver_retirement`

Plan removal of unretained predecessor repositories, capturing their complete namespace and file epochs.

## `windows/servicing/driver_runtime.star`

Refresh installed runtime aliases of admitted equivalent-INF replacements.

The installed file object, not a filename or matching bytes, establishes the
binding. No INF execution, new runtime destination, generic CSI projection or
FileMap ownership is inferred. Repository planning has already bound each new
source to an unchanged installed layout and a manifest hash.

### `apply_direct_driver_runtime`

Preflight runtime alias authority before replacing links; preserve independently selected winners and return replacement counts.

### `plan_direct_driver_runtime`

Select installed runtime aliases for explicitly bound driver repository replacements.

## `windows/servicing/driver_session.star`

Pinned native driver transaction for the offline update construction.

One retained session owns all three phases and Close. Instruction-limit stops
resume the same call, never recreate a phase. publish() returns an independently
verified filesystem tree, not a CBS completion flag. Payloads must already be
staged; do not replay staging after publishing native file objects.

### `prepare_update_driver_session`

Prepare start/advance/finish/publish callbacks for the exact qualified native driver ABI. The current SSU and DLL identity guards are intentional support limits, not a general Windows driver transaction.

## `windows/servicing/drivers.star`

Ordinary empty-queue driver planning, not driver-store/CBS completion.

Keep MUM declaration provenance, exact INF digest, and each package/update owner.
Planning neither installs drivers nor authorizes package completion or file removal.

### `plan_update_driver_operations`

Bind admitted ordinary actions to declared INF metadata and manifest hash.

    manifests is an exact canonical CSI identity (casefolded) to decoded manifest
    map, including resident declarations. Only normal/force ranking declarations
    are retained; this does not map them to native driver-store flags. Payload
    verification, staging, new-owner key security, driver-store effects and queue
    execution remain mandatory separate phases. No image mutations occur here.

### `reduce_update_driver_queue`

Reduce new, uncompleted operations using the observed native queue rules.

    The caller must supply an explicit persisted-queue inventory. Nonempty queues
    require native load/recovery policy and are rejected. Records require exact
    identity text and owner (package~update); comparisons are CASE SENSITIVE.
    Conflicting duplicate metadata fails rather than relying on native first-win.
    Native completed-state reversal is deliberately outside this empty-queue path.

### `select_update_driver_source_paths`

Select actual descendants of already-bound component source roots.

    INF SourceDisks paths can name nested architecture directories. Selection
    retains that existing hierarchy, not a flattened list or synthetic aliases.
    Binding roots to admitted manifests/driver jobs remains the caller's duty.

## `windows/servicing/events.star`

Native offline event publisher/channel and shared-autologger registration.

This models shared Admin/Operational and new disabled System Debug channels,
not the whole
advanced-installer queue. Event definitions remain in hash-qualified PE payloads.
No host wevtutil invocation or installer emulator participates in construction.

### `plan_update_event_registry`

Construct exact bounded publisher/channel/shared-session hive effects.

    Preexisting changed publishers must match the old declared registration.
    Unknown extra child state is not destroyed. Changed channel modes, custom
    access/logging/publishing, external user configuration and unestablished
    key-creation security fail before any hive publication.

### `prepare_update_event_registration`

Reduce registration fields globally by GUID before deciding removals.

    Event/task/template definitions are intentionally not treated as registry
    data. Unsupported changed channel configuration is rejected by the planner.
    Equal shared GUID declarations must agree, including channel order.

### `validate_update_event_resources`

Validate newly registered GUIDs in the actual final projected PE bytes.

## `windows/servicing/events_native.star`

Validate and atomically publish real Events-installer hive effects.

Jobs must already come from native queue admission. This module does not infer
jobs from XML, execute online phases, or declare CBS package completion.

### `apply_native_events`

Execute all explicit jobs before committing any native registry effect.

### `events_jobs_from_queue`

Use the common native smart-installer job mapping for Events.

### `plan_native_events`

Build all target hive bytes; no image mutation occurs on any rejection.

## `windows/servicing/file_apply.star`

Bounded file/FileMap phase orchestration; not complete CBS servicing.

### `apply_update_directory_removals`

Remove changed empty directories bottom-up only when no FileMap ownership remains; return removed and retained-owned paths.

### `prepare_and_apply_staged_update_file_effects`

Commit existing hash-qualified sources without recreating their objects.

    Native driver staging may already own links, EAs and final file metadata.
    Replaying payload staging here would unlink those real objects. This entry
    plans from the actual current tree; source bindings/security and mutable
    projections are checked without eagerly reading every payload.

### `prepare_and_apply_update_file_effects`

Plan hierarchy and directories, stage payloads, and apply ordered file/FileMap effects on root; this is a mutating phase, not complete servicing.

## `windows/servicing/file_commit.star`

Apply bounded native CSI file effects, never package lifecycle shortcuts.

Inputs are the full hierarchy and already-staged, hash-qualified WinSxS sources.
Planning reads the image but does not modify it. It rejects absent source
security instead of silently preserving the destination's old WIM descriptor.

### `apply_update_directories`

Preflight directory existence/security before creating directories and applying planned descriptors; return effect counts.

### `apply_update_file_commits`

Apply one native pass: 1 before LUA maps, 2 after LUA maps.

    The caller preserves the hierarchy's directory-security and LUA ordering.
    This applies portable object effects; it neither completes driver queues nor
    advances CBS package/component lifecycle or pretends to execute a session.

### `image_path_names`

Return the case-folded file-derived namespace, excluding empty directories; mutable=False requests a read-only index.

### `plan_update_directories`

Construct effective ancestor security before any file/map mutation.

    Directory child-enumeration propagation must be disabled by actual native
    configuration. Missing implicit ancestors use the bounded SYSTEM creation
    policy, not WRP permissions copied from a nearby directory.

### `plan_update_file_commits`

Plan all dirty primary/link/removal effects against unchanged paths.

    source_paths maps the native FileInfo key to its exact staged store path.
    Validate source metadata, security, link prerequisites and writable
    decisions before any mutation. Exhaustive byte verification is opt-in. User-modified writable files preserve bytes
    AND metadata. Old-only immutable projections are unlinked without hashing.

## `windows/servicing/file_stage.star`

Store-file preparation for the bounded offline update construction.

This implements source-folder and component-file ACL effects, manifest creation
security, logical payloads and exact source joins. Driver queues and component/
CBS lifecycle finalization remain separate.

### `build_update_source_folder_security`

Derive the established native source-folder descriptor from the actual parent security; return descriptor bytes.

### `resolve_update_source_paths`

Bind prepared source identities to exact staged or resident paths in root; reject missing or ambiguous sources.

### `stage_update_payload_files`

Materialize admitted payload sources and their security/metadata on root; do not replay this after native driver publication.

## `windows/servicing/filemap_security.star`

Final FileMap security from the observed native WCP default pair.

This is a final metadata constructor, not token acquisition or a shortcut that
copies a resident map's permissions. Creation's default DACL is overwritten by
this complete setter; the bounded new-map path establishes absence of labels.

### `prepare_update_filemap_security`

Prepare FileMap descriptors from the actual parent and planned records, preserving native audit and integrity-label semantics.

## `windows/servicing/files.star`

Native path/FileMap construction for caller-owned offline images.

Planning is separate from applying effects. In particular a complete map plan
is not permission to mark a package installed or discard driver-store state.

### `apply_update_filemaps`

Apply a validated LUA plan with explicit final map descriptors.

    Security is keyed by the plan's exact output path; it must come from the
    native security constructor, not default filesystem inheritance. The entire
    plan's source digests and descriptors are checked before any mutation.
    This does not apply the final file/directory pass or commit package state.

### `plan_update_filemaps`

Plan the complete LUA pass against unchanged baseline maps.

    The caller must complete the preliminary boot-critical file pass first.
    Only its already-state-2 immutable shape is supported here; accepting a
    writable/link state without the real pass would manufacture post-pass state.
    Directory collisions retain resident ownership and obey the actual hive's
    native strict-directory policy. Any file-owner conflict fails before writes.

### `prepare_update_file_hierarchy`

Resolve amd64 runtime paths, hashes and security against explicit baseline hives; return reduced hierarchy, sources and collision policy.

## `windows/servicing/gac.star`

Guarded refresh of existing legacy/CLR4 GAC assemblies from CSI declarations.

This is not Fusion registration or NGEN completion. New cache directories,
assembly identity changes and removals require their own installer phases and
are rejected. New companion files may be linked into an existing cache identity
only when absent and backed by an exact declared staged hash. No oracle paths, hashes or registry results enter this planner.

### `apply_update_gac`

Validate the full GAC batch before refreshing files; runtime Fusion/NGen validation is not implied.

### `apply_update_gac_notifications`

Check file epochs/timestamps before publishing prepared Fusion counters and notifications.

### `plan_update_gac`

Plan Fusion cache refreshes with namespace guards and optional payload auditing.

    Non-audit mode does not verify baseline or source bytes. The caller must
    supply admitted sources; publication binds their captured write epochs.
    fileCopy=false requires pre-published content or the exact staged file
    object; shared hardlink identity avoids decoding the same object twice.

### `plan_update_gac_notifications`

Notify Fusion using the installed assembly's last-write FILETIME.

    This is NOT a wall clock and must agree with the file Fusion will inspect.
    Optional audit verifies the declared payload hash; epochs and timestamps
    are always checked before publication.
    Existing cache identities only: lifecycle changes are rejected by the same
    guarded cache planner. Reference counting is unchanged for these replacements.

## `windows/servicing/http.star`

Execute the admitted HTTPAI queue through the native CSI harness.

The XML reader supplies CDF input, not predicted registry effects. The actual
DLL decides which writes to make; publication is bounded and atomic.

### `apply_update_http`

Execute the qualified native HTTP installer and publish checked offline reservations; return phase evidence, not CBS completion.

### `http_installer_jobs`

Select bounded HTTP installer jobs and reservations from runtime transitions without mutating the image.

### `http_reservations`

Parse the supported HTTPAI declaration shape into reservations; reject unsupported attributes or structure.

### `publish_http_effects`

Validate native HTTP writes against reservation authority and the selected SYSTEM control set before publication.

## `windows/servicing/http_native.star`

Execute native HTTP queue phases against a private hive, then publish once.

### `apply_native_http`

Run both native phases in order; a late failure publishes neither phase.

### `plan_native_http_effects`

Check exact per-call URL authority before building any new hive bytes.

## `windows/servicing/installer.star`

Bounded native CSI basic-installer execution against an offline registry.

This is an explicit, narrow CSI ABI adapter, not an implementation of an
installer's decisions. Unsupported methods stop execution without publication.

### `basic_jobs_from_queue`

Bind native phase-8 removal and phase-10 installation entries to inputs.

    This preserves native queue order and both identity references. It does not
    infer executor eligibility, inspect smart installers or declare a phase done.

### `expand_csi_windows_path`

Expand the explicit target Windows-root token, rejecting other namespaces.

### `run_basic_installer`

Execute an identity-qualified basic installer for supported install/uninstall phases under explicit instruction limits; return native outcomes and effects.

### `run_http_installer`

Run the bounded native HTTP profile with explicit SYSTEM bytes, rows, operation and phase; return captured effects.

### `select_basic_installer`

Select one present, hash-qualified source; never guess between versions.

## `windows/servicing/key_flags.star`

Bounded CSI registry-key flags bridge, backed by explicit offline hives.

The native installer chooses keys, recursion and flags. This bridge records
uncommitted metadata edits; it neither creates keys nor publishes a hive.

Pinned target-kernel evidence: CmQueryKey 0x85878a returns class-5's three
DWORDs (UserFlags, key flags, virtualization flags). CmSetKeyFlags 0x9af0fb
sets nk+0x34 bits20..23; disable bit2 also clears nk.Flags bit0x80. The native
luainstall ApplyRegistryKeyRecurse reads the third DWORD, ORs its selected
policy, and calls IRtlKey slot27/class2. Enumeration names remain borrowed
until the next batch or enumerator release; LBLOBs use WCP's own allocator.

### `create_key_flags_registry`

Allocate native key-flags registry interfaces using explicit SOFTWARE/SYSTEM hives and caller-owned allocation callbacks.

## `windows/servicing/media_categories.star`

Construct the MediaCategories subset of admitted KS registration.

This does not claim all Include/Needs or RunOnce work is complete. Existing
values survive unless the exact KS declaration replaces them. Newly created
keys use the explicit target administrator subject, never an oracle host SID.

### `apply_update_media_categories`

Recheck the source hive and INF proofs before publishing MediaCategories; None represents an empty plan.

### `plan_update_media_categories`

Plan supported amd64 MediaCategories updates from driver jobs, exact ks.inf bytes and an explicit subject group.

## `windows/servicing/migration.star`

Maintain migration manifest membership from admitted component transitions.

Retain unaffected entries in order, then append new declarations in transition
order. This is a membership index; reference transaction enumeration order is
not an input to construction.

### `apply_update_migration`

Validate the migration plan source/epoch and proofs before writing its replacement index; return membership counts.

### `plan_update_migration`

Plan migration-index membership from admitted payloads and baseline components, preserving source and manifest proofs.

## `windows/servicing/native_configuration.star`

Pinned native store-option interpretation against explicit hive snapshots.

### `query_native_installer_options`

Read native HKCU service options, not transaction admission or SKU state.

    Native code owns policy precedence, value decoding, defaults and lifetime.
    MobileStore is compared with 1, not interpreted as a generic Boolean;
    MobileStoreVersion is compared with 4 by the actual executor caller.
    No POQ disposition or transaction identity is inferred from these values.

### `query_native_mobile_store_version`

Resolve executor +0x41; transaction-derived +0x40 remains unknown.

## `windows/servicing/native_eligibility.star`

Pinned native executor eligibility probe, not a complete execution planner.

### `determine_per_user_eligibility`

Run DetermineIfHKCUShouldRun against explicit target inputs.

    The two booleans are CQueueExecutor fields +0x40 (Initialize flags bit 2)
    and +0x41 (store option equals 4). Neither is inferred here. Callers must
    establish them for the actual transaction before applying these results.
    A True result only passes this gate; it does not prove complete eligibility,
    execution, an installed inventory, or a committed CBS transaction.

## `windows/servicing/native_inventory.star`

Read-only native CSI install-map inputs for complete inspection inventory.

### `build_native_inspection_inventory`

Query every target candidate before returning an unchanged inventory.

### `inspection_candidates`

Read every persisted component and sum all installed-source backlinks.

### `query_native_install_map`

Query native winning versions and identity kinds, without guessing inventory.

    This does not itself count installed ownership or exclude changed identities.
    Callers supply complete candidates and validated reference counts separately.

### `resolve_inspection_manifests`

Bind selected native identities to exact decoded manifests and CSI hashes.

    Analysis intentionally preloads only changed compositions. Complete native
    inspection also needs unchanged components outside those compositions. Read
    those through the exact resident source, never a guessed stem or reference
    image. A missing or mismatched manifest rejects the entire input batch.

### `select_inspection_inventory`

Select the native Fetch(flags=40h) inventory, minus both changed sides.

    native_rows must come from query_native_install_map against the exact target
    SOFTWARE hive. Complete row coverage is mandatory, including unowned staged
    components. The optional expected_marks independently reconciles population
    analysis against persisted source counts; it cannot supply missing counts.

## `windows/servicing/native_lsa.star`

Read-only LSA identity boundary for the pinned offline servicing process.

Only SECURITY/Policy domain identity records are read; secrets, authentication,
account mutations and remote machines are outside this adapter. The explicit
query_access is an isolated process capability, not an inferred policy DACL or
a claim about a booted host. Native WCP owns SID cache interpretation.

### `read_servicing_policy`

Read the bounded servicing policy from explicit native inputs; reject unsupported source layout rather than synthesizing policy.

### `servicing_lsa_plugin`

Serve classes 5 and 12 from explicit immutable target policy records.

    query_access must be an explicit bool. False denies POLICY_VIEW_LOCAL_INFORMATION;
    True permits that one right only. No MAXIMUM_ALLOWED or generic-access grant.
    Handles and result allocations are independent, owned and checkpointed.
    NTSTATUS failures preserve outputs and the Win32 thread last-error slot.

## `windows/servicing/native_midground.star`

Execute the pinned native service-category merger on explicit queue inputs.

This does not execute online ServicesSmartInstaller or publish any effects.

### `run_native_service_category`

Run the qualified native service-category implementation with explicit hives, jobs and token privileges under an instruction bound.

### `service_category_jobs`

Bind native service-category queue entries to explicit changed and inspection manifests, preserving queue order.

## `windows/servicing/native_queue.star`

Derive phase 3..12 AI entries with the pinned native WCP implementation.

This returns an execution plan, not committed servicing state. It deliberately
uses the ordinary non-repair/non-debug flags (0) and no external transforms.
Explicit source/target hives permit bounded read-only transformer-state queries;
all other native environment operations stop execution.

### `derive_offline_queue`

Return native finalized entries for explicit (old, new) manifest pairs.

    Omitted inspect_manifests explicitly leaves the installed inventory unknown.
    The returned inspection_required flag must not be treated as satisfied.
    Entry operation numbers belong to ExecutionQueueEntry, NOT the smart
    installer interface. Identity references are (input-index, side) pairs.
    Caller must still supply the complete inspection inventory, dispatch the
    native operation and execute/commit every applicable phase. Phases 60/61
    are outside this adapter. Inspection references index inspect_manifests.
    registry_snapshots is an explicit (before, after) pair of COMPONENTS/SYSTEM
    hive maps for native transformer admission; omission fails on any SIL read.
    progress, when supplied, receives bounded completed-input counts (every
    progress_interval inputs and at each stage end), not mutable emulator state
    or a partial queue. This interval does not change native queue decisions.
    Individual manifests are limited to 16 MiB, the total to 512 MiB, and each
    native call to the explicit instruction_limit (at most two billion).

## `windows/servicing/native_runtime.star`

Pinned servicing runtime boundary, not a replacement for native installer logic.

Map the target NTDLL under native-ntdll.dll. Only explicitly admitted public
exports are visible through ntdll.dll; native internal heap/token boundaries
use the emulator's owned process state. Optional feature-query status remains
the native result, not proof of the target system's effective feature policy.

### `native_registry_creation_provider`

Assign NULL-creator registry security with the pinned target kernel.

    This isolated, non-restricted SYSTEM subject uses the same explicit owner,
    group, default DACL and integrity facts as the network process. Native
    CmpCreateChild calls SeAssignSecurity(container=1, registry mapping, pool=1).
    No installer HRESULT, ACL inheritance decision or descriptor is synthesized.
    Explicit creators, class names and special create options remain unsupported.

### `ntdll_runtime_plugin`

Create the qualified native ntdll runtime plugin for emulation; this is not a host or booted-guest execution API.

### `prepare_network_runtime`

Construct the isolated setup process's RPC directory, not a host ACL snapshot.

    SMSS supplies native creation security. Native NTDLL assigns an independent
    directory with no parent and default inheritance flags, using the target's
    directory generic mapping and verified SYSTEM token defaults. The resulting
    self-relative descriptor is queried by real RPC/NTDLL; it is never published
    into image registry security. This model does not claim the token or object
    namespace of a booted servicing process, nor effective feature-policy state.

## `windows/servicing/ngen.star`

Manifest-owned deferred NGEN commands. Never runs ngen or marks it complete.

### `apply_update_ngen`

Preflight queue inputs and publish prepared deferred NGEN registry effects; return publication evidence, not completed compilation.

### `collect_update_ngen`

Collect supported NGEN declarations from runtime transitions, retaining architecture and native ordering.

### `plan_update_ngen`

Plan deferred native-image queue entries from admitted runtime declarations without compiling managed code.

## `windows/servicing/package_audit.star`

Read-only package-state provenance audit; never repair or downgrade state.

### `audit_package_states`

Account for EVERY final package, including native non-installed entries.

    State provenance is not independent payload/installer validation. Report
    concrete metadata contradictions separately; never infer missing effects
    from a missing timestamp, an unrun check or a constructed state value.

## `windows/servicing/package_indexes.star`

CBS package metadata indexes, independent of package lifecycle state.

These are MUM-derived lookup/dependency records. Planning them does not prove
manifest resolution, payload staging, installation, owner state or completion.
No CurrentState, Owners, session, Active or completion records are produced.

### `plan_servicing_package_indexes`

Derive value-scoped native indexes from one exact package MUM.

    PackageDetect stores the parent-integration enum, not a state. Standalone
    blocks omit their own identities but still recurse into nested blocks.
    UpdateDetect records parent update references only, never local ones.
    ComponentDetect retains every applicable updateComponent target and source,
    with the base elevation (not the source payload's alternative-target bit).
    No applicability pruning.
    Returned patches are not authorization to apply or to register a package.

## `windows/servicing/package_security.star`

Protection for newly published CBS package manifests and catalogs.

CBS package publication is not WCP payload staging: the former keeps the
protected resource ACL and audit policy, including auto-inheritance controls.
Catalogs with installed deployments take WCP staging protection instead.
Neither constructor replaces the security of already resident objects.

### `new_package_catalog_security`

Derive the native staged catalog descriptor from the actual destination parent.

### `new_package_manifest_security`

Derive the native staged package-manifest descriptor from the actual destination parent.

## `windows/servicing/package_store.star`

Publish admitted package dispositions after constructing their effects.

CBS state is consumed by Windows servicing, not an internal confidence flag.
Never cap installed packages or owner requests at Resolved because validation
is outstanding. See docs/windows-package-state-policy.md.

### `package_metadata_executions`

Select admitted metadata, not merely the last population action.

    Merge can converge a previously processed stage/install to ActionNone.
    MUMPopulated records that admission; the final target still limits lifetime.
    This selects metadata; final state publication follows the applied effects.

### `plan_resident_package_dispositions`

Persist explicit resident execution transitions after construction effects.

    FinalCommitPackagesState retains 0x50; dirty/action normalization to 0x40
    does not apply to persistence. Owner overlays retain unmentioned owners.
    Only the observed installed-to-superseded transition is supported here;
    removal/reinstallation requires its own effects and must fail closed.

### `publish_package_metadata`

Publish new packages with their admitted stage/install dispositions.

    Called after file, registry, installer and CSI effects have been applied.
    Exact signed MUM membership is mandatory. Optional audit mode also reads
    back emitted composition, payload bytes and serialized dispositions.
    Unchanged native packages are preserved; explicit resident transitions
    are persisted alongside new packages. Unsupported dispositions fail
    without writing a conservative placeholder into Windows' registry.

## `windows/servicing/plan.star`

Plan package phases without mutating an image or selecting product policy.

The caller supplies one immutable baseline and explicit metadata closure.
A successful plan is admission evidence, NOT a completed CBS transaction.

### `plan_package_phases`

Return install population and a compact, independently owned closure.

    StageChain ordering is captured before install planning. Both phases use
    the same baseline and complete closure; only afterward are unused MUMs and
    decoded XML released from the returned record. The input closure is not
    modified. Equal-state admitted wrappers remain present even when their
    final action is a no-op. Missing closed metadata fails rather than silently
    manufacturing a package disposition.

    No payload staging, registry publication, emulation, VM boot, network
    selection, or host output occurs here. Source objects may retain lazy
    readers; keep their backing capabilities alive through construction.

## `windows/servicing/population.star`

Offline servicing construction policy. No guest or host servicing tools.

Metadata availability, package admission, and image mutation are distinct phases.
This module must not turn an incomplete analysis into bootable update media.

### `collect_servicing_metadata`

Close exact package references over raw/express MUMs and the base store.

    Optional hives are the exact recipe baseline, before update writes. Use the
    same baseline for population, composition, source and winner analysis.
    Roots and features are explicit caller policy, not inferred from preliminary
    payload selection. All registered store packages seed the closure, including
    staged and absent registrations. Parent applicability and XML contained flags
    NEVER prune metadata. Missing references are returned, not authorized to skip.

### `plan_servicing_population`

Plan one independent phase from a complete immutable baseline.

### `prepare_servicing_population`

Plan ordinary package admission; reject unsupported or unresolved policy.

    This does not apply a CSI transaction or authorize boot. Unknown nonzero
    references fail: the metadata closure is not an omission allowlist.

## `windows/servicing/print_queue.star`

Queue admitted native-architecture printer replacements for first boot.

Records come from exact installed replacement INF inputs, never a reference
hive. Queue presence means pending work, not successful printer installation.
Opaque entry IDs are deterministic; Windows' incidental random IDs are not an
image-construction requirement.

### `apply_direct_print_queue`

Validate the pending print plan input epochs and publish its registry effects.

### `plan_direct_print_queue`

Plan supported print-driver pending operations from explicit driver jobs and repository bindings.

## `windows/servicing/queue_registry.star`

Read-only IRtl SIL bridge for native queue transformer-state queries.

The pinned WCP code owns all interpretation and queue decisions. This bridge
supplies bytes from explicit source/target hives, including genuine not-found
results. It cannot create keys, write values, or consult the host registry.

### `create_configuration_registry`

Return (SIL, optional SideBySide/Configuration key) for native options.

### `create_executor_registry`

Read only the native executor's HKCU eligibility policy path.

### `create_install_map_registry`

Read only SOFTWARE's native Winners map; return (SIL, map root key).

### `create_queue_registry`

Read only the native queue transformer's established registry paths.

## `windows/servicing/recovery.star`

Verified recovery publication; generated metadata policy remains explicit.

The production generator binds every record to an admitted forward edge.
WCP supplies a fixed reverse-target timestamp, independent of payload times.
File security uses component-staging policy, including driver ACLs.

### `apply_generated_recovery`

Check the complete generated-recovery batch before writing records or CSI markers; return emitted markers.

### `apply_inherited_recovery`

Validate and publish planned inherited recovery records and metadata on root.

### `plan_generated_recovery`

Plan generated recovery records with an explicit target FILETIME; do not infer timestamps from wall-clock or reference output.

### `plan_inherited_recovery`

Plan inherited recovery records from explicit root/payload state without treating missing evidence as a recovery marker.

### `retained_recovery_flags`

Read retained recovery flags from established image records; do not invent recovery state for absent records.

## `windows/servicing/registry.star`

Native ordinary registry planning, separate from hive publication.

A complete before/after contribution inventory is required even when only a
small subtree changes. Provider disposition and security assignment happen
later against the actual candidate hives, never against a declaration count.

### `changed_update_registry_values`

Retain only unequal complete value multisets, excluding provenance alone.

    Call only after collecting and validating every admitted declaration. Keep
    all contributors of changed values for later family arbitration; equal raw
    bytes with different types, multiplicity, mutability, hints or unquoted-empty
    semantics are NOT equal. This does not retire keys or suppress security work.
    The detailed collector remains unchanged for inspection consumers.

### `plan_update_ordinary_registry`

Plan complete ordinary keys/values against the actual constructed image.

    Audit mode reads back every serialized target; normal mode keeps source
    and planning guards without that redundant decoding pass. Unchanged
    user-profile trees require no binding. Changed profiles require explicit
    hive paths and support existing-key value changes only: profile key creation,
    security assignment and cleanup remain fail-closed. The caller owns complete
    profile enumeration; HKCU is never substituted with HKU/.DEFAULT. Atomic
    mutable trees and nonempty retired-security cleanup also remain fail-closed. Literal key components are retained, including dot and slash.

### `prepare_update_registry_keys`

Reduce exact admitted keys in family order, retaining separate profiles.

    `buckets` must come from the complete affected install-closure capacity.
    Equal-bucket contributions are allowed only when ordering cannot alter
    descriptor selection. The native reducer preserves first ownership and
    last nonempty security independently; dictionary iteration is not priority.

## `windows/servicing/registry_access.star`

Bounded existing-key access policy for the declared offline driver subject.

This is not a general Windows token/authorization service. The driver session
uses a non-restricted SYSTEM subject, enabled BA/WD/AU groups, high integrity,
and no privilege-based ordinary-open grants. Unknown ACEs or higher-integrity
objects stop construction rather than silently relaxing access.

### `update_driver_key_open_access`

Evaluate driver registry access against an established descriptor and request; return granted access or denial.

## `windows/servicing/registry_effects.star`

Commit captured native registry effects, not historical sets or CBS success.

Bindings identify an exact source hive and an optional encoded emulator mount
prefix. Capture registry.effects() while each hive is mounted, before teardown.
All newly materialized keys require separately established final security; the
writer's parent-copy fallback is deliberately not used as native creation policy.

### `apply_update_registry_effects`

Recheck all source-hive digests before publishing the prepared registry batch; return hive/value/key effect counts.

### `build_update_driver_key_security`

Measured NULL-creator SYSTEM key policy for this exact driver database.

    Original kernel CmpCreateChild -> SeAssignSecurity, legacy parent control
    8004, either the three-ACE DriverDatabase policy or the independently
    captured seven-ACE COMPONENTS policy. The latter is a fixed point
    under actual native creation at INF/hash depth and for new CSI component,
    deployment and catalog keys. Unlike NTFS, no 4000
    normalization or AI flags are added. Child owner/group come from the
    declared subject, not arbitrary parent principals. The independently measured Print PackagesToAdd parent also produces the
    seven-ACE child. Other ACLs/controls require their own evidence.

### `build_update_driver_property_key_security`

Require the established native property creator and parent descriptor before returning protected device-property security.

### `plan_update_registry_effects`

Build and read back all final hive bytes before modifying the image.

### `update_driver_key_creation_provider`

Bind only the explicitly declared SYSTEM subject, not arbitrary tokens.

## `windows/servicing/runtime.star`

Exact winner-transition runtime analysis, not an installer queue or application.

Primitive file/registry effects, dual-mode driver operations and advanced
installer phase/inspection policy remain separate from equivalence predicates.
Record identity is the stable transition label; component_identity is the exact
side-specific source identity, or None for incomplete inspection-only fixtures.
Only the latter identifies exact payloads; native FileInfo interning has its
own servicing-family comparison for supported version scopes.

### `analyze_servicing_directories`

Read ordered directory declarations, never infer creation or ownership.

    Only direct assembly/directories/directory nodes participate. Retain raw
    attributes (including owner and compression) for native operation policy.
    A repeated destination is not collapsed, and each side resolves security
    definitions in its own manifest. Implicit file parents are not declarations.

### `analyze_servicing_file_paths`

Select native directory IDs, not resolved paths or authorized effects.

    Only direct assembly files with a leading directory macro are decomposed.
    Missing destinationPath remains explicit; driver projection policy is not
    inferred from its absence. Profile lookup and offline root mapping must
    resolve every directory ID before any filesystem changes can be planned.

### `analyze_servicing_file_security`

Resolve manifest-local declarations, not effective object permissions.

    Missing references, the CSI (inherit) marker, and explicit SDDL remain
    distinct. Neither operationHint nor SDDL is interpreted as permission to
    change an object; native defaulting, inheritance and commit policy are
    separate from this analysis. Preserve attributes for that later policy.

### `analyze_servicing_registry_declarations`

Collect admitted primitive declarations, not an ordered registry plan.

    Native 26100.9441 ProcessChange bypasses registry and later primitives for
    exact Type=dualModeDriver unless the existing-store ConfigOptions has all
    bits 0x33. Earlier file processing and separate CBS driver operations are
    NOT bypassed. Excluded transitions remain explicit for those consumers.
    Case folding Type here would disagree with native identity classification.

    Keys include their complete XML node (including security/empty keys), and
    values retain unexpanded attributes and side-specific source identity.
    Nothing is decoded, reduced, ordered, rooted, authorized or applied.

### `analyze_servicing_runtime`

Capture manifest-bound component transitions and declaration inventories from composition analysis; MOF equivalence is not an installer queue.

### `assign_servicing_directory_security`

Assign the bounded directory request's metadata, not token authority.

    Native SeSetSecurityDescriptorInfoEx preserves bounded audit components,
    clears AR controls, retains AI and makes absent audit SACLs present-NULL.
    Existing mandatory labels are retained by the common category selection.
    Owner authorization must have been established separately; SYSTEM alone
    cannot assign the TrustedInstaller owner used by the conditional forms.

### `assign_servicing_file_security`

Construct the bounded kernel-assigned descriptor, without applying it.

    This models the observed NTFS SeSetSecurityDescriptorInfoEx flags-0x4000
    metadata transformation for the ordinary file request above. It is not a
    token authorization check or an NTFS transaction. The caller must supply
    the actual current descriptor, including labels shared by hardlinks.
    Audit updates preserve existing mandatory labels; other SACL categories
    require their own information-mask policy and fail closed here.

### `assign_servicing_staged_file_security`

Apply the bounded staging metadata transformation, without authorization.

    Native staging updates labels as well as audit security. The observed
    request has a present-NULL SACL and clears existing labels, unlike the
    runtime hardlink setter. Non-NULL requested SACLs require separate label
    validation policy and are deliberately unsupported by this entry point.
    The native comparison declares a SYSTEM-integrity servicing subject with
    an owner-capable TrustedInstaller group; this does not grant that access.

### `build_servicing_created_security`

Build the bounded SYSTEM creation descriptor before WCP's setter.

    Models NULL file creator security, or directory creator O:SYG:SY, with
    SYSTEM owner/primary group and SYSTEM integrity. This is not a general
    token-dependent SeAssignSecurityEx implementation. The native NTFS path
    takes auto-DACL inheritance only when the parent has DACL_AUTO_INHERITED.
    Ordinary audit ACEs inherit when the parent SACL is auto-inherited;
    noninheritable parent audit ACEs do not propagate. If no DACL
    inherits, the caller must explicitly supply the subject token default DACL.
    Only nonpropagating allow ACEs with mapped file rights are supported there;
    legacy propagating SACL inheritance and other token/SACL policies
    remain fail-closed.

### `build_servicing_directory_security_request`

Build a bounded explicit or selected-default directory request.

    This is WCP's directory setter input, not creation-time inheritance or
    authorization. Covers protected DACLs, explicit unprotected DACLs and
    ordinary audit SACLs, including OI/CI/NP/IO/ID inheritance flags.
    Other control/SACL forms fail closed until separately established.

### `build_servicing_file_security_request`

Construct the bounded WCP ordinary-file request, not an NTFS effect.

    The caller selects the child descriptor and supplies the actual parent.
    This composes the proven defaulting, native-RTL inheritance and WCP final
    file-control policies. It does not select commit flags, authorize a write,
    set kernel security, handle directories or model token-dependent defaults.
    Present-NULL/defaulted child ACLs remain rejected by preparation.

### `build_servicing_immutable_file_security_request`

Select the proven ordinary immutable-file request from native flags.

    The supplied parent is the effective destination parent at commit time,
    not necessarily its base-image descriptor. These added/paired state-2
    cases set security on the linked source object. Source staging metadata,
    hardlink mutation, authorization and ordering remain caller obligations.

### `build_servicing_registry_security_request`

Build the bounded explicit WCP key setter request, not a hive effect.

    Missing principals default to SYSTEM; key rights use container inheritance.
    Empty unprotected audit ACLs disappear, protected empty ACLs survive.
    A selected explicit label suppresses parent labels and requests LABEL_SECURITY
    information; a merely inherited label does not request that category.
    Audit entries precede the label regardless of selected input order.
    default=True selects the observed GetRegistryDefaultSecurity descriptor,
    with no explicit declaration. defer_inheritance=True models the separate
    setter flag: no parent query, no generic-rights/creator transformation,
    and original ACE ordering retained for later propagation.
    No kernel assignment, token ownership authorization, key creation, or
    transaction ordering is implied. Absent/NULL child DACLs and
    protected NULL SACLs remain outside this explicit-declaration path.

### `build_servicing_staged_file_security_request`

Construct the observed component-file staging request, not its effect.

    The caller must determine driverUpdate/dualModeDriver identity semantics
    and supply the effective component-store parent. This models the ACL part
    of ApplyAclsAndWofCompressIfNecessary with compression disabled, not the
    staging dispatch, source attributes, owner authorization or kernel update.
    Unlike runtime hardlink security, this request also updates integrity
    labels. The ordinary assignment helper deliberately rejects that mask.

### `collect_servicing_registry_contributions`

Decode admitted values in native loops; do not select or apply winners.

    Admission, version-specific path rules, macro roots and key capture policy
    remain explicit recipe inputs. All contributors survive, including equal
    before/after declarations and duplicates. There is no unsupported fallback.

### `compile_servicing_file_security`

Compile declaration bytes, retaining absent and CSI inherit separately.

    This does not map generic rights, supply defaults, inherit parent ACEs or
    authorize a filesystem mutation. Cache by exact SDDL, not definition name:
    names are local to each side of each manifest transition.

### `expand_servicing_environment_path`

Expand only the three variables installed by the native offline provider.

    ProfileList and ProgramFiles values use this provider, not the host user's
    environment. Unknown variables fail closed rather than being substituted
    with guessed user/profile paths. Expansion is a single pass.

### `expand_servicing_registry_string`

Expand a registry string/name against explicitly resolved DOS paths.

    source_roots is the source_roots map from the offline path policy, NOT its
    image-relative roots map. Registry data remains DOS syntax, not NT device
    syntax or image paths. Environment references remain literal. The observed
    unresolved build.PackageMoniker is also literal; other unknown macros fail
    closed. This helper does not decide which registry data types expand text.

### `map_servicing_offline_path`

Map an already expanded DOS path; never infer another volume's mount.

### `offline_servicing_path_context`

Validate this recipe's one-volume, image-relative path mapping.

    SystemRoot is read from the offline SOFTWARE hive, not the host environment.
    windows_directory is an explicit absolute virtual path within that image.
    It must retain the recorded Windows directory's spelling (ignoring case),
    because the native drive mapping targets the offline Windows parent.
    This is deliberately narrower than native arbitrary provider mappings.

### `plan_servicing_filemap`

Build one native FileMap action without applying filesystem effects.

    The caller must select a dirty directory and supply immediate children with
    POST-preliminary-file-pass state. None means the map did not exist; an empty
    resident map is not a supported substitute. This composes the bounded native
    transition, path metadata and encoder. It does not validate transaction-wide
    collision policy, authorize paths, choose traversal order, apply security or
    commit a servicing transaction. A remove action removes the map, NOT its
    directory. No-op and removal have no content and are never encoded.

### `prepare_servicing_file_security`

Build the bounded ordinary-file setter input, not an applied descriptor.

    WCP ApplySecurityToObjectWithDefaults supplies System for each missing
    principal and empty unprotected ACLs for absent ACLs. CFile's option-4 path
    conveys protection separately and does not preserve input AI/AR bits.
    Generic rights are mapped by the native format API, which also validates
    all component extents before these fixed-header patches. The existing
    ACE bytes/order (including ID) otherwise survive until RTL inheritance.

    The caller must first select a descriptor. None/(inherit)/absent references
    are dispatch decisions, not descriptors. Present-NULL and defaulted controls
    remain unsupported here; they require the separate provider/current-object
    paths. No parent query, inheritance, final control pass or mutation occurs.

### `prepare_servicing_projected_files`

Prepare bounded ordinary ProcessFile inputs, retaining unresolved work.

    This is not a full file plan. The unresolved list is carried forward and
    must be discharged before a complete hierarchy/commit can be claimed.
    External-source cases remain unsupported. Compression flags reflect the
    explicitly selected native mode, not a file compression effect. The selected
    policy must be for the ordinary direct transaction, not HKCU or repair.

### `prepare_servicing_registry_value_data`

Decode one ordinary modern registry declaration, not its commit policy.

    The pinned native modern-profile path selects value, not IEDownlevelValue.
    Options are retained verbatim for the reducer; decoding does not authorize
    mutable writes, replace/merge behavior, priorities, or overlapping owners.
    MULTI_SZ entries and unquoted-empty provenance must survive even though
    their canonical raw encoding can coincide. No profile/key binding occurs.

### `prepare_servicing_unprojected_files`

Prepare source-only native inputs without dropping unprojected work.

### `preprocess_servicing_directory_declarations`

Compute each explicit directory's own change bits, not subtree skips.

    This consumes ordered reduction, retaining all collisions and source
    contributions for later policy validation. It does not include file work,
    implicit ancestors, discovered children, inheritance, or commit effects.
    An unchanged directory here must never suppress changed descendants.

### `preprocess_servicing_file_declarations`

Native own-change bits after all primary/link source contributions.

    State differences alone are NOT file changes (unlike directories).
    FileInfo equality uses the native interning key; hash presence, digest method,
    transform and bytes are compared separately. This pass never reads or
    modifies the image and does not authorize copy, removal or security work.

### `preprocess_servicing_path_hierarchy`

Propagate already-proven own changes through the complete path graph.

    Both inputs must contain fully reduced and own-preprocessed records. Files
    include extra link destinations. Omitting file work is NOT a supported way
    to produce a directory-only commit plan. This pass adds implicit ancestors
    and native unchanged-subtree bits, without querying or changing the image.
    It does not authorize collisions, removals, phase selection or propagation
    to filesystem children discovered during commit.

### `preprocess_servicing_registry_keys`

Compute ordinary key flags after independent complete value reduction.

    value_changes maps EVERY explicit reduced key to its manifest-value change
    boolean, even keys with no values. It is not a comparison against live hive
    data. compiled_security maps exact SDDL to bytes compiled with the target's
    identity context. Native pointer interning preserves equal-text equality;
    different texts use the asymmetric registry-rights comparison.
    The returned mapping does not authorize traversal order or hive mutation.

### `redirect_servicing_machine_registry_path`

Map a canonical NT machine-hive path for the pinned amd64 profile.

    This is the observed 26100.9441 WCP rule set, not generic Windows version
    policy. amd64 leaves paths unchanged; x86/wow64 use the native machine
    rules. One explicit WOW6432Node at Software or Software/Classes is handled;
    deeper/multiple explicit nodes fail closed. USER roots, root aliases,
    provider mounts and value macro expansion are outside this helper.

### `reduce_servicing_directory_declarations`

Reduce ordered declarations, not filesystem effects or commit authority.

    Models the bounded install/remove ProcessDirectory path: no repair,
    filter-list exclusions, implicit ancestors, compression effects or native
    collision-policy authorization. Repeated owned additions are recorded for
    that later policy decision, not silently accepted as authorized writes.
    Descriptor references remain manifest-local opaque definitions here.
    Preprocessing must compare selected descriptor *semantics* and propagate
    changed descendants before any unchanged-subtree optimization is valid.

### `reduce_servicing_file_declarations`

Reduce explicit native ProcessFile inputs; do not infer installer flags.

    Each input must supply process_flags and source_hash (None or a native
    digest_method/transform/digest record). This supports ordinary primary/link calls
    with flags 1, 2, 8, 10, 20 and 40 only, not repair, filters, external
    sources. With an explicit non-strict ownership policy, ordinary primary
    overlaps with identical metadata reduce in call order, as native ProcessFile
    does. Mixed metadata, writable/link overlaps, strict-policy overlaps and
    repeated primary sources remain unsupported. Hashes live on interned sources,
    so links use their primary's hashes even at another destination.

### `reduce_servicing_registry_keys`

Reduce a bounded ordered set of resolved ordinary keys in one pass.

    Input records carry path, side, identity, descriptor and key_attributes.
    Paths are already macro-expanded, rooted and view-redirected. This models
    native last-nonempty descriptor selection separately from first-owner
    retention. Overlapping owned additions are counted, not authorized. Either
    side can arrive first; the caller supplies the native contribution order.
    Implicit ancestors are retained, but namespace/profile anchors are provider-
    owned. System and per-user passes must never share one reduction mapping.
    No value reduction, exclusion authorization or hive writes happen here.

### `reduce_servicing_unprojected_files`

Retain native ProcessUnprojectedFile source/hash contributions.

    Native 282f10 interns the same FileInfo table as projected files but makes
    no runtime destination record. Flags20 and new-only1 select compression
    and the component-wide GAC/NGEn marker, not projected immutable state.

### `resolve_servicing_directory_paths`

Resolve declared directories only; unknown roots fail, not guess.

### `resolve_servicing_file_paths`

Resolve explicit paths and retain bounded native unprojected work.
    Ordinary identities without destinationPath use ProcessUnprojectedFile.
    In the ordinary transaction (no 0x400 driver override), native
    DoComponentOperation also forces dual-mode drivers down that source-only
    path, even with destinationPath. Their runtime projection belongs to the
    driver installer, not the generic file installer. Unprojected records still
    require source/hash processing; incomplete identities remain unresolved.

    driver_projection_candidates is only for independently checking actual
    driver-installer outputs against declared hashes. It is not permission to
    feed driver files into the ordinary file/FileMap installer.

### `resolve_servicing_machine_registry_key`

Resolve verified HKLM/HKCR root aliases and the pinned registry view.

    Keys must already have macros expanded. HKCU/HKU, provider hive mounts,
    CurrentControlSet resolution, virtualization and key security are separate.
    Returned paths are canonical NT paths without a trailing separator.

### `resolve_servicing_registry_key_pass`

Map a manifest registry key to its architecture-qualified pass using the compiled native path mapper.

### `select_servicing_file_commit_paths`

Select native file-loop candidates, not an execution schedule.

    Requires the complete own/subtree-preprocessed hierarchy. Phase 1 selects
    boot-critical flag0x10 files; phase 2 selects its complement; phase 0
    selects both. Clean bit4 and directories are excluded in every phase.
    This models only the ordinary CommitDirectoryChanges file loop. Security-
    only/external-store flags, ancestor opens, recursion order, global enable
    gates and actual effects remain caller obligations. Returned sorted paths
    are for selection/comparison, never authorization to reorder native work.

### `select_servicing_file_hash`

Bounded CmsGetFileHashInformation projection, not payload verification.

    Select the nested SHA256 Identity digest for file projection. .NET may
    additionally retain an obsolete build-time SHA1 attribute. Its syntax is
    checked, but the nested digest is binding; native readers verify SHA256.
    Other algorithms/transforms remain unsupported.

### `select_servicing_new_registry_multi_action`

Select a new-only nonempty MULTI_SZ contribution's observed effect.

    Missing manifest hint is append in the pinned native ProcessValue path.
    Existing strings survive append/prepend; an already present new entry is
    not moved. New-only replace overwrites without mutable preservation.
    Empty/unquoted-empty contributions and overlapping owners need separate
    reduction, and must not be collapsed into this bounded single-owner case.

### `select_servicing_paired_registry_dword_action`

DWORD-only compatibility entry point for the paired value selector.

### `select_servicing_paired_registry_multi_action`

Return the observed ordinary MULTI_SZ merge effect, without applying it.

    before/after are ordered contribution lists of nonempty strings from one
    owner with ordinary priority and no override. Both sides must use the same
    operation_hint and mutable setting. The caller must resolve the hint;
    the default here explicitly selects append, not manifest default parsing.
    An empty list means no entries (e.g. quoted empty declaration), not
    the distinct unquoted empty-string contribution. Append/prepend merge
    regardless of mutable; replace uses exact old-value preservation.
    Current is a typed raw record or None. Only canonical
    terminated current MULTI_SZ data is accepted; malformed data fails closed.
    The caller establishes reduction/root/key policy. No hive is modified.

### `select_servicing_paired_registry_value_action`

Select the observed single-owner paired ordinary-value commit action.

    Inputs are decoded typed raw records (type=int, raw=bytes), not XML text.
    Supported types are NONE, SZ, EXPAND_SZ, BINARY, DWORD, QWORD and raw
    numeric types greater than 11 (all 32 bits preserved). Both sides
    must have ordinary priority, no override or operation hint, and the same
    effective mutable flag. The caller establishes those
    preconditions; this is not registry manifest arbitration. MULTI_SZ uses
    different native merge behavior and must not enter this selector.
    None means a missing current value, not an unreadable key. No registry
    roots, security, ownership, key creation or effects are handled here.

### `select_servicing_registry_empty_delete`

Evaluate a queued key AFTER descendants and values have been processed.

    Counts must come from the current physical key, including undeclared
    contents; declaration counts cannot establish emptiness. Nonempty-key
    security reset/propagation requires a separate configured policy.

### `select_servicing_registry_key_commit`

Select ordinary CreateKeysInKey work from a preprocessed native node.

    This is not declaration reduction or permission to mutate a hive. The
    caller must establish ordering, overlap/exclusion policy and parent state
    first. `created` is the actual create disposition, not an existence guess.
    Removal only queues an emptiness check AFTER value and descendant work;
    implicit ancestors participate too. Missing removal keys are tolerated by
    the provider. Mutable/protected-subtree and special auxiliary policies
    deliberately remain outside this bounded selector.

### `select_servicing_registry_value_action`

Select a bounded ordinary single-owner registry value action.

    Uses the paired ordinary-value selector's types and reduction preconditions.
    None on one declaration side means that side has no contribution. Unlike
    paired mutable updates, a new-only value overwrites without querying and
    an old-only value deletes without checking whether it was user-modified.
    A missing value during deletion is tolerated by the native commit path.
    MULTI_SZ contributions require their separate merge/replace policy.

### `select_servicing_writable_file_action`

Select copy versus preservation for supported paired/new writable shapes.

    This reads the current projected file, not its possibly DCS-encoded WinSxS
    counterpart. It neither applies effects nor verifies the replacement source,
    security authorization, FileMaps or transaction ordering. Missing paired
    projections, existing new destinations, different flags/states and
    non-identity hashes require separate native policy.

### `servicing_directory_propagation_policy`

Select the ordinary direct-transaction enumeration gate, not effects.

    WCP raw layout +2c is MobileStore == 1. AnalyzePrimitiveInstallers maps
    that byte to primitive flag 10, then PerformPrimitiveInstallation maps it
    to coordinator flag 80. This is not equivalent to offline mode. The
    coordinator also ORs the numeric SmiHiveUpdates configuration result into
    its flags; retain that override rather than assuming it is a boolean.
    This covers ordinary direct transactions only, not HKCU or repair setup.
    The ordinary primitive flag mapping never supplies 20000; only the raw
    SmiHiveUpdates override can set that bit here and suppress the primary
    immutable flag. No full coordinator flag word is inferred from this subset.
    A false enumeration gate does NOT suppress explicitly declared children,
    their own security work, or inherited security on newly created objects.

### `servicing_file_compression_policy`

Select native CFileInstaller compression mode from SYSTEM/Setup.

    IsCompactOSEnabled accepts only an exact DWORD and treats any nonzero
    value as true. Missing/malformed values select noncompact mode. This
    describes ProcessFile inputs, not authorization to compress file data.

### `servicing_file_path_roots`

Resolve the observed amd64 offline directory IDs; no file effects.

### `servicing_file_security_matches_manifest`

Compare independent descriptors with native WCP flags 2 (file rights).

### `servicing_file_source_key`

Bounded native FileInfo key, NOT an exact payload/store identity.

    InsertFileInfo ignores all version fields for nonSxS scope, but retains
    major/minor for absent scope. The source filename is independently case-folded.
    Preserve the full component_identity on declarations for payload lookup;
    neither a transition label nor this intern key authorizes source bytes.
    Other scopes and non-ASCII comparison require additional native evidence.

### `servicing_filemap_collision_policy`

Select the ordinary direct transaction's ownership strictness gate.

    Coordinator initialization ORs 0x4800 for SingleResourceOwnership and the
    raw SmiHiveUpdates DWORD into its flags. InitializeCFileInstaller copies
    bit 0x800 to the ownership byte (also used by ReportFileCollision).
    The historical strict_directories key names this shared gate. Primitive flags cannot
    supply that bit. This is not a repair/custom-coordinator policy.

### `servicing_filemap_collision_status`

Return the native final collision HRESULT, not transaction success.

    Directory dot-entry collisions retain the resident owner. Tolerating them
    does not authorize ordinary file collisions or any other commit effects.
    Other native final checks and all earlier failures remain independent.

### `servicing_manifest_boot_critical`

Bounded WcpManifest::IsBootCritical category membership predicate.

### `servicing_primitive_family_capacity`

Bound the native table capacity from complete affected TLC closures.

    GenerateServicingFamilies inserts only install/uninstall operations (0/1),
    and all members of their complete compositional closures. Stage, unstage,
    pin and unpin operations do not add entries. The caller must supply the
    identities from the verified complete affected install-mark analysis,
    not merely changed winners.

    Version-independent hashes give a lower bound on native family count;
    distinct full identities give an upper bound, covering version-scoped
    families without assuming their hash policy. Both bounds must imply the
    same capacity. This does not resolve within-bucket insertion order.

### `servicing_registry_driver_options`

Read the pinned existing-store configuration, without changing store mode.

    A missing/malformed value is outside this bounded recipe; it is not an
    instruction to create a driver database or enable the offline-new-store
    override. SYSTEM and DRIVERS are separate logical hives.

### `servicing_registry_overlap_policy`

Select ordinary direct-transaction overlap gates, not authorization.

    CRegistryInstaller::Initialize copies coordinator bit 0x800 to both its
    strict-key and strict-value bytes. The coordinator sets it from boolean
    SingleResourceOwnership or the raw SmiHiveUpdates flag override. Other
    coordinator modes and critical/state-separation/HKCU counters remain
    independent obligations.

### `servicing_registry_overlap_status`

Return native DoesOverlapExist status from complete classified counts.

    A total owner collision is not automatically a critical collision. Callers
    must separately establish all six counters; absence cannot mean zero.
    This does not classify contributions, authorize mutation, or replace
    earlier parser/override/security failures.

### `servicing_registry_path_roots`

Resolve registry-backed roots for a no-SID offline servicing profile.

    The caller supplies the image's SOFTWARE hive. No host registry, mounted
    volume, current-user profile, or hardcoded Default directory participates.
    Other special-directory IDs remain absent until separately resolved.

### `servicing_registry_security_matches_manifest`

Compare independent descriptors with native WCP flags 1 (key rights).

    This is the asymmetric comparator used by ArbitrateKeySecurity, not the
    entire arbitration or an applied-key security decision. Interned identical
    descriptors use a separate native pointer-equality fast path; independent
    descriptors with inherited ACEs must not be conflated with that case.

### `servicing_runtime_manifest_root`

Return the captured immutable XML root only while its transition source binding matches; otherwise parse the replacement.

## `windows/servicing/services_direct.star`

Apply declared service deltas without running the service installer.

Unchanged settings (including image policy) are preserved. This handles explicit
SCM configuration and SvcHost membership; it neither starts services nor invents
an advanced-installer completion record.

### `apply_direct_services`

Plan and publish supported direct service effects on root; return service/group and registry publication counts.

### `collect_direct_services`

Collect before/after service and group contributions from manifest-bound runtime transitions.

### `plan_direct_services`

Plan qualified service/group changes against actual SYSTEM and SOFTWARE state, preserving unrelated configuration and security.

## `windows/servicing/services_native.star`

Publish native phase-three service-category effects, never predicted merges.

XML limits which SvcHost values the admitted native jobs may touch. Native WCP
alone decides list contents, ordering, and deletions. Online service creation
and CBS transaction completion are not covered by this adapter.

### `apply_native_service_category`

Run native service jobs with explicit privileges, validate their effects and publish only authorized hive changes.

### `plan_native_service_category`

Require the execution's exact SOFTWARE epoch and validate before writes.

### `service_category_authority`

Read declared group names only; this is not a replacement merger.

## `windows/servicing/settings.star`

Publish settings manifests from exact admitted component declarations.

WCP 9703 ShouldManifestBeSettingsManifestLinked (11be48) tests configuration
or RegistryKey.overridable count, not the presence of migration rules. The
original encoded manifest is hardlinked; existing older versions are retained.

### `apply_update_settings_manifests`

Preflight settings source/destination objects before publishing manifest hardlinks; return selection/link counts.

### `plan_update_settings_manifests`

Select admitted settings manifests and bind exact source objects, security and destination epochs.

## `windows/servicing/smart_installer.star`

Execute pinned native CSI smart-installer jobs, without publishing effects.

The real WCP parser constructs manifest objects; each real installer DLL owns all
queue/commit decisions. This is not queue derivation or a CBS completion claim.

### `run_appx_installer`

Execute the bounded qualified AppX smart-installer profile with explicit token privileges and return native effects.

### `run_events_installer`

Execute the bounded qualified Events smart-installer profile against explicit hives and jobs; return native effects.

### `run_network_drivers_installer`

Run the qualified network-driver smart profile with explicit NetSetup modules, hives, jobs and optional native runtime context.

### `run_smart_installer`

Run explicit (operation, manifest-file) jobs and return uncommitted effects.

    Operations are native Install=1, Uninstall=2, Inspect=3. Callers must derive
    eligible jobs and offline phases independently. For per-user registry, the
    caller must supply the exact profile SID (empty for the default template),
    source-backed static mounts, local-policy read capability and caller token
    privileges. This executes one admitted profile; it does not enumerate users,
    establish phase eligibility or infer whether transaction POQs ran inline.
    No registry changes escape
    if initialization, parsing, queueing, commit, release or unload fails.

### `run_system_protection_installer`

Execute the bounded qualified System Protection smart-installer profile and capture key-flag effects.

### `smart_jobs_from_queue`

Translate native phase-9 entries for an admitted smart-installer profile.

    WCP ExecuteSingle queues the new manifest as Install=1 first, then the old
    manifest as Uninstall=2. Commit resolves that aggregate; these calls are
    not immediate registry writes. Inspection uses its exact retained identity.

## `windows/servicing/system_protection_native.star`

Publish native System Protection key metadata only after complete execution.

### `apply_native_system_protection`

Run qualified System Protection jobs and publish validated key flags; return queue/parse/commit evidence.

### `plan_native_key_flags`

Build and verify existing-key flag edits without changing values/security.

## `windows/servicing/timezone.star`

Native offline timezone installer admission and atomic effect publication.

### `apply_update_timezone`

Execute qualified offline timezone resource handlers and publish checked effects; return resource/native-write evidence.

### `publish_timezone_effects`

Validate timezone writes against actual SOFTWARE/SYSTEM and the selected control set before publishing patches.

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

`auto(source, name='', maximum=<default>, maximum_entries=100000, maximum_depth=32, tree=None, path='') -> auto`

Wraps a byte view, file, bytes value or existing filesystem in a lazy standardized Go node view. Registered format detectors inspect a bounded prefix and confirm the format through native parsers. Native EROFS supports compact/extended inodes, flat/inline data and LZ4 full/compact indexes including 2-byte packs and big physical clusters. EROFS views verify superblock CRC32C and reject unsupported incompatible features; source bytes must remain unchanged while views are used. summary returns current entry metadata without detecting or reading its payload; metadata additionally detects the payload format. Use summary for directory inventories. By default eager decoding is limited to 512 MiB while bounded gzip, bzip2 and XZ streams have no total-length ceiling; an explicit positive maximum bounds both kinds. Container paths resolve recursively while file preserves the original bytes. Detectors receive containing-tree context for companion files across directories. For an isolated file, tree and its tree-relative path attach that context explicitly. Companion lookup reads raw entries within the supplied tree without following links or recursively detecting files; dot segments and host paths are not accepted.

### `auto_plan`

`auto_plan(source, name='', maximum=512MiB, maximum_entries=100000, maximum_depth=32, tree=None, path='') -> auto`

Like auto, but also proposes named virtual filesystems from directory listings. The plans attribute returns id, title, description and a relative path under $plans. Following that path constructs the selected read-only view on demand; discovery does not read member payloads. Ordinary files remain accessible, plain auto is unchanged, and a real $plans entry takes precedence. Plans preserve input provenance and distinguish variants rather than overwriting duplicate objects. A proposal is a candidate: content validation can report unsupported or malformed inputs when opened.

### `bytes_concat`

`bytes_concat(parts) -> bytes`

Materializes a list of binary values into one bytes value, preserving order. Use binary.concat when a lazy file composition is preferable.

### `digest`

`digest(value, algorithm='sha256') -> bytes`

Hashes a file, string or bytes value and returns raw digest bytes, not hexadecimal text. The default algorithm is SHA-256. Content-addressed immutable readers may reuse a SHA-256 digest only after complete byte verification; a cached identity is not a backing-store availability check.

### `digest_many`

`digest_many(values, algorithm='sha256', workers=4, while_running=None) -> list[bytes]`

Hashes up to 65536 file, string or bytes inputs in input order using 1..8 parallel native readers (default 4). Reads and hashes each input (or reuses a previously byte-verified immutable SHA-256 identity), rejects short files and propagates read errors without returning partial results. Optional while_running is called once with no arguments on the caller interpreter thread while native readers run; its return value is ignored and an error aborts the batch only after joining every worker. Input membership is captured before the callback, but it must not mutate underlying bytes. No Starlark callbacks run in workers; source readers must support concurrent reads and remain unchanged until return.

### `directory`

`directory() -> directory`

A mutable in-memory directory tree. write adds file content, mkdir creates directories, find retrieves an entry and remove deletes one. list_dir(path) returns sorted absolute paths of immediate files and directories (including empty directories); missing paths return an empty list. Paths are normalized but case-sensitive. Listings reflect mutations and are independent mutable lists. path_names(lower=False, include_empty=True) returns an independent dictionary of all file and directory paths (including root and empty directories), without reading file contents. Values retain exact spelling; lower=True lowercases lookup keys and rejects colliding file names. Directory spelling follows the first sorted descendant file; empty directories fill remaining names in sorted order. include_empty=False returns only files and their ancestors. path_index(lower=False, include_empty=True) provides the same namespace as an immutable native mapping with string keys, get, keys, values and items; enumeration is sorted and returned lists are independent. It avoids dictionary construction for lookup-only callers. Later namespace changes do not alter the snapshot. Attributes and security descriptors are stored as image-construction metadata; fat_short_path reports the FAT-compatible short-name path.

`get_security(name)` returns the existing path's self-relative Windows security descriptor as immutable bytes, or `None` when no descriptor is assigned. Missing paths are errors. It does not synthesize inherited permissions or modify the tree.

`set_security(name, descriptor)` updates the existing file or directory's security. For a hardlinked file, every alias receives the same descriptor; link-local metadata such as short names is preserved.

`set_reparse(name, tag, data)` attaches an opaque Microsoft reparse payload to an existing file or directory for image construction. `tag` is an unsigned 32-bit Microsoft tag (bit 31 set; reserved low values 0 and 1 are rejected). `data` is immutable bytes, at most 16376 bytes, excluding the eight-byte REPARSE_DATA_BUFFER header. The payload is copied; existing metadata is preserved. No target is followed and no host filesystem object is created. Missing paths, non-Microsoft GUID buffers, and multiply-linked files are rejected. NTFS writes both the payload and its reparse index entry.

### `error`

`error(message)`

Stops evaluation with the supplied error message. Use testing.attempt when a caller needs to inspect an expected failure.

### `help`

`help(value=None) -> None`

Prints runtime help for a value, or an overview of available globals when no value is supplied. Returns None and does not modify the inspected value.

### `hex`

`hex(value, width=0) -> string`

Formats an integer as signed, 0x-prefixed hexadecimal text with optional digit padding. For file, string or bytes input, returns the raw bytes as unprefixed hexadecimal text; width applies only to integers.

### `http_file`

`http_file(urls, size=None, name='HTTP range file', chunk_bytes=4MiB, cache_bytes=256MiB) -> file; omitted size uses HEAD discovery`

Creates a lazy random-access file over HTTP byte ranges with a bounded in-memory chunk cache. urls supplies alternative source locations; omitted size uses HEAD discovery. This does not extract or convert the remote content.

### `http_get`

`http_get(url, maximum=64MiB, timeout=60) -> file`

Performs one sequential HTTP(S) GET into an in-memory file, with normal redirect handling and HTTP gzip decoding. No HEAD/range requests, retries, disk cache or host intermediate files. Requires status200 and bounds response bytes after HTTP decompression to maximum (1..128MiB); timeout is 1..3600 seconds and lifecycle cancellation is honored. This is for bounded metadata; use http_file for large lazy payloads. It does not validate package signatures or digests.

### `http_post_json`

`http_post_json(url, body, maximum=8MiB, timeout=60, tls_roots=None, response=False, headers=None, http_version='auto') -> file or response dict`

Sends a UTF-8 JSON string (or empty body) as application/json, returning a bounded in-memory file. Request body is limited to 1MiB; response maximum is 1..128MiB after transfer decompression. By default requires HTTP 200 and rejects oversized responses. response=True instead returns a frozen dictionary for any HTTP status with status, status_code, protocol, headers, trailers, content_length, transfer_encoding, uncompressed, body (file), body_truncated, read_error and complete. Header/trailer values are lists, preserving repeated fields. It reads at most maximum+1 decoded body bytes and retains a maximum-byte prefix; complete is false on truncation or read failure. Trailers may be incomplete unless complete is true. TLS responses additionally expose tls_alpn, tls_version and tls_server_name. http_version defaults to auto; 1.1 creates an isolated HTTP/1-only transport with HTTP/2 disabled and hostname/certificate verification unchanged. The returned protocol and TLS ALPN expose what was actually used. Transport/TLS failures still raise. Never follows redirects or retries; honors lifecycle cancellation and a 1..3600 second deadline. Response bodies may be gzip-decoded by HTTP; uncompressed identifies that transformation. headers optionally supplies at most 64 string-to-string fields, bounded to 64KiB. Names/control characters and case-insensitive duplicates are checked; Host, Content-Length, Transfer-Encoding, Connection, Content-Type and idempotency-key overrides are rejected. Empty User-Agent suppresses the generated header entirely rather than sending an empty value. No token acquisition or credential lookup is performed. tls_roots optionally supplies 1..16 DER/PEM CA files or bytes (up to 1MiB each); an isolated per-request root pool replaces system roots while preserving hostname, validity and chain verification. No global trust changes, implicit certificate fetching or insecure fallback. Intended for metadata; payloads should use file APIs.

### `mirror_file`

`mirror_file(urls, cache, key, sha256='', size=-1, maximum=64GiB, timeout=3600, retries=0, validate=None) -> file`

Opens a cached download or tries the supplied mirror URLs, checking the requested size and SHA-256 when supplied. The cache and key identify persistent native-backend storage; cache='' uses the native user cache directory's trex folder. An optional validate(file) callback runs synchronously before publication and on cache hits: it must return None to accept or raise an error to reject. The borrowed read-only file is usable only during the callback; do not retain it or derived views. Failed validation prevents publication; invalid cached objects are downloaded again. The result is a file, not extracted contents.

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

### `archive.aea`

`archive.aea(file, key=None, maximum_bytes=4GiB) -> record`

Opens a symmetric profile-1 AEA1 archive natively. key is 32 raw bytes; None selects the explicit hex encryption_key metadata field. Returns a lazy plaintext file, encrypted_size, segment_size, segments_per_cluster, compression, checksum and verify(). Authenticates root/cluster/segment HMACs and optional padding; verifies plaintext SHA256 or Murmur checksums. Supports stored, LZFSE, LZVN and zlib segments with bounded allocations and a one-segment cache. maximum_bytes bounds declared decoded size. verify() reads the entire archive. Rejects other profiles/strengths and unavailable keys; never fetches keys, launches tools or writes intermediate files.

### `archive.aea_metadata`

`archive.aea_metadata(file) -> record`

Reads bounded AEA1 header metadata without decrypting or authenticating it. Returns profile, scrypt_strength, borrowed auth_data and values (key to binary bytes). Rejects malformed or duplicate records. Metadata may contain encryption keys; inspect names before printing values. Never contacts a key service.

### `archive.apple_archive`

`archive.apple_archive(file, maximum_entries=100000) -> entries`

Reads bounded AA01 Apple Archive records. Returns path, kind, borrowed data and fields keyed by the original three-letter names. Supports unsigned integer, path, timestamp and blob fields; timestamps contain seconds and nanoseconds. Rejects unknown encodings and malformed extents. Does not unpack to a host directory or infer archive authentication.

### `archive.appx`

`archive.appx(file) -> {kind, identity, full_name, family_name, entries, files, packages}`

Reads unencrypted APPX/MSIX packages and bundles through portable files. identity exposes name, publisher, version, architecture and resource_id. full_name and family_name use the Windows SHA-256/UTF-16LE publisher identity hash; these names do not authenticate the publisher. entries/files are lazy ZIP file views; complete reads or entry.verify() check CRC. Entry name/path is the once-decoded UTF-8 OPC path, archive_name is the original ZIP name; do not unescape paths again. Unsafe and colliding decoded paths are rejected. Bundle packages expose name, type, architecture, version, size, is_stub and file. Member names normalize Windows separators to slashes; full installations should skip stub alternatives; call archive.appx(member.file) to read a child. Rejects unsafe paths, duplicate/colliding names, oversized manifests and absent or size-mismatched embedded members. verify_block_map(maximum=8589934592) checks SHA256 decoded blocks, sizes and complete payload coverage under a decoded byte budget; bundle members require separate calls. This checks an unauthenticated map, not publisher trust or ZIP container signature digests. Does not authenticate signatures, decrypt packages, resolve flat bundles, or install/register software. Keep the source open while reading entries.

### `archive.ar`

`archive.ar(file, maximum_entries=1M, maximum_metadata=64MiB) -> ar`

Parses Unix ar (including Microsoft COFF-library NUL-terminated long names) or AIX small indexed ar into ordered member metadata and borrowed file views. find(name, occurrence) distinguishes duplicate names. AIX archives follow double-linked member order rather than physical order, validating first/last endpoints, member-table names and offsets, optional symbol references, free-list links and non-overlapping ranges. Deleted members are not active files. maximum_entries and maximum_metadata bound indexing; no linking, object loading or installation is performed. AIX big indexed archives remain unsupported.

### `archive.arsenic`

`archive.arsenic(file, maximum_decoded_bytes=256MiB, maximum_block_bytes=16MiB) -> file`

Decodes one raw StuffIt method-15 fork, not a StuffIt container. Reconstructs adaptive arithmetic-coded MTF tokens, reverses BWT and optional block randomization, expands final runs, and validates the in-stream IEEE CRC32 for nonempty streams before returning an immutable in-memory file. maximum_decoded_bytes bounds logical output and stored input; maximum_block_bytes bounds each intermediate BWT block. Truncated input, invalid indices and exceeded limits fail explicitly. Use the enclosing container's declared fork length as an additional check; resource maps and nested archives require separate decoders.

### `archive.aws`

`archive.aws(file, maximum_records=1M) -> record`

Reads an AWS tape image into logical records and tape marks, checking block framing and previous-length links. Each record exposes data, original offset, physical block count and tape_mark; data is None for marks. Does not interpret record payloads such as DDR disk dumps.

### `archive.bff`

`archive.bff(file, maximum_entries=1M, maximum_decoded_bytes=512MiB) -> record`

Reads single-volume AIX by-name backup archives with extended name records (FS_NAME_X=11), checking every header checksum, record and security bounds, declared sizes and end framing. Stored payloads, raw headers and ACL/PCL bytes remain borrowed file views; packed Huffman bodies decode natively using the enclosing logical size and a cumulative decoded-byte limit. Entries preserve original names, paths, modes, inode/link identity, owners, device numbers and timestamps without applying them. The returned trailer retains final unused distribution-block bytes, which may be nonzero. This initial generation handles exact-end or 1KiB-rounded distribution archives; other record generations, continuation volumes and larger physical tails fail explicitly. It does not run scripts, plan installation, interpret XCOFF or validate uncompressed file contents with a nonexistent payload checksum.

### `archive.bom`

`archive.bom(file, maximum_entries=1M) -> list[record]`

Returns every flat Apple BOMStore path-inventory record, including architecture variants sharing a path and trailing leaf-chain nodes missing from branch indexes. Records preserve kind, BOM ID, mode, uid/gid, mtime, declared size, architecture, checksum or link target/device number. BOM describes metadata only and has no file contents. maximum_entries bounds indexing. The auto tree preserves duplicate variants under %00bom-variants with bom_path metadata.

### `archive.bru`

`archive.bru(file, maximum_entries=1M) -> record`

Reads classic uncompressed BRU backups, validating each 2 KiB record's signed-byte checksum, archive identity, sequence and member name. Returns ordered entries with type, mode, ownership, link target and data file views assembled across record headers. Checks the end record and trailing buffer padding, including padding-block checksums. Compressed/extended members and incomplete multivolume inputs fail explicitly; no restore commands are executed.

### `archive.bsd_dump`

`archive.bsd_dump(file, maximum_entries=1M, maximum_decoded_bytes=256MiB) -> record`

Reads full, single-volume historical BSD dumps with 1024-byte records, magic60012 and old 128-byte UFS inodes, in either byte order. Validates header checksums, tape positions, record identity, address flags, complete inode payloads and directory structure. Returns entries, paths in files, find(path), dump date and raw allocated_map/dumped_map file views. Entries expose the same inode metadata and data views as filesystem.ufs; holes read as zeroes, hard links share data, symlinks are not followed and device nodes are metadata only. maximum_entries bounds both inode records and reachable paths; maximum_decoded_bytes bounds input size and cumulative logical inode bytes. Incremental dumps require a base image and are rejected, as are other dump generations and multi-volume streams. Dumped inode bitmap membership is checked against recovered records and the allocation map. Nested payloads require separate decoders.

### `archive.burn_containers`

`archive.burn_containers(file) -> list[file]`

Reads WiX v3 Burn attached CAB container boundaries from PE metadata, returning portable file slices in UX-first order. Rejects unsupported, detached, or truncated layouts without executing the bootstrapper.

### `archive.bzip2`

`archive.bzip2(file, maximum_bytes=<unlimited>, cache=False) -> file`

Opens concatenated bzip2 streams, including legacy randomized blocks, as a lazy read-only file with a bounded decoded block cache. Block and stream checksums are checked during reads; size scans the complete stream. Omitted maximum_bytes has no decoded-length ceiling; an explicit positive maximum is enforced. cache=True requires explicit positive maximum_bytes, eagerly validates every member to EOF, and returns an immutable paged RAM snapshot supporting random access without replay or host files; integrity or overflow failures return no partial result. Does not interpret an archive inside the stream.

### `archive.c2r`

`archive.c2r(database, stream) -> entries/find`

Indexes an Office Click-to-Run full stream using a schema-5 UnityDB. Entries expose package-relative path, size, packages, data and verify(); find is case-insensitive. Lazy reads verify stored-block SHA256 and bounded zlib decoding. verify() also checks the complete logical-file SHA256. Metadata references, block coverage, source extents and paths are validated before returning. Uses one shared decoded-block cache; keep both sources unchanged. Does not apply deltas, install Office, interpret App-V manifests, activate products, or authenticate catalog signatures. Pin or authenticate metadata separately.

### `archive.c2r_database`

`archive.c2r_database(file) -> frozen dict[str, list[tuple]]`

Decodes a bounded version-0x30 Office UnityDB into frozen literal tables. Checks declared extents, zlib framing and decoded SQL SHA-256; SQL statements are never executed. Supports the emitted integer/string INSERT subset, not arbitrary SQLite. Integrity checks do not authenticate the publisher.

### `archive.cab`

`archive.cab(file, cache=True, lzx_checkpoint_bytes=0) -> cab`

Parses a Microsoft Cabinet file and exposes its members as file views. Folder decompression is shared when caching is enabled, so several entries in one compressed folder need not decode it repeatedly. Optional lzx_checkpoint_bytes (2..64 MiB, requires cache=True; zero disables) uses source-backed LZX block-boundary history checkpoints rather than a retained whole folder. First access decodes a complete folder, retaining compressed histories and SHA-256 hashes that bind future decoded frames to those initial bytes. It is not signature/trust verification. Sources must remain stable for member lifetimes. Checkpoint spacing is a target: a 24-bit LZX block can extend it; interleaved random access may cost more decoding than ordinary caching. Each member exposes frozen cab_metadata containing raw DOS date/time, attributes, folder index, set_id and cabinet index; reading metadata does not decompress the member.

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

### `archive.cpio`

`archive.cpio(file, maximum_entries=100000, apple_double=False) -> list[dict]`

Indexes ASCII CPIO directly into flat metadata dictionaries using bounded forward metadata reads, without following links or instantiating special files. Supports newc, CRC newc, odc and concatenated archives; maximum_entries bounds original records, with contextual limit errors. Regular data is borrowed. archive identifies the trailer-delimited hardlink namespace. apple_double=True explicitly folds ._ sidecars into finder_info, resource and named xattrs using bounded ATTR decoding; malformed metadata and missing targets fail rather than discarding data.

### `archive.cpio_build`

`archive.cpio_build(entries) -> file`

Constructs a deterministic Linux-compatible newc archive from Unix entry dictionaries. Preserves modes, ownership, timestamps, symbolic links, hardlinks and device numbers. Synthesizes missing parent directories, rejects duplicate or unsafe paths, and borrows payload readers without extracting them.

### `archive.crx`

`archive.crx(file) -> record(id, version, files, entries)`

Verifies a CRX3 envelope and returns its developer ID, format version and ZIP entries as portable files without extraction. Checks all RSA/SHA-256 and P-256 ECDSA/SHA-256 signatures and requires a matching developer key. Header decoding is bounded to 1MiB. Does not pin a Chrome Web Store publisher key or parse legacy CRX2 packages. The source must remain open while reading entries.

### `archive.dcs`

`archive.dcs(file, maximum_bytes=512MiB) -> file`

Expands a DCS v1 CBS component-store container to an in-memory read-only file using native LZMS decoding. maximum_bytes (1..512MiB) bounds both stored and expanded sizes; framing, block counts, lengths and trailing data are checked before returning content. This is separate from WIM resource compression and does not verify manifest hashes or catalog trust.

### `archive.gzip`

`archive.gzip(file, maximum_bytes=<unlimited>, cache=False) -> file`

Opens concatenated gzip streams as a lazy read-only file with a 1 MiB decoded cache. Forward reads reuse the decoder; backward reads outside the cache replay it. Checksums are validated as data is consumed; size scans the complete stream without retaining it. Omitted maximum_bytes has no decoded-length ceiling; an explicit positive maximum is enforced. cache=True requires explicit positive maximum_bytes, eagerly validates every member to EOF, and returns an immutable paged RAM snapshot supporting random access without replay or host files; integrity or overflow failures return no partial result. Does not interpret an archive inside the stream.

### `archive.gzip_members`

`archive.gzip_members(file, maximum_bytes=512MiB, maximum_members=1024) -> list[file]`

Validates individual gzip members and returns exact compressed-member file views. CRC and size checks cover every member; maximum_bytes bounds total expanded data and maximum_members bounds indexing. No expanded payload is retained. Trailing junk is rejected.

### `archive.hunk_load`

`archive.hunk_load(file, maximum_records=1M) -> record`

Reads one non-overlaid Amiga HUNK_HEADER load module without loading or executing its code. Returns header (raw bytes, padded resident library name views, table_size, first, last and allocation sizes in bytes), one unnamed element in units containing the record stream, and entries for code/data/debug payloads. Uses the same record fields as hunk_objects. Checks header ranges, section count, section payload bounds and declared allocation capacity; BSS remains metadata. maximum_records bounds header items, blocks, symbols and relocation groups. Only ordinary longword RELOC32 load relocations are accepted; compact encodings, overlays and extended memory attributes remain explicit gaps. Resident libraries are listed, not resolved; no relocation is applied and no guest memory is allocated.

### `archive.hunk_objects`

`archive.hunk_objects(file, maximum_records=1M) -> record`

Reads concatenated classic Amiga and EHF HUNK_UNIT object libraries, preserving unit names and complete raw unit views in units. The entries list exposes code, data and debug payloads under unique unit/record paths for nested inspection. Each unit's records expose tag, flags, absolute offset, raw bytes, optional payload, memory_size, symbols and relocations. Names retain longword padding. Code, data, debug bytes and big-endian relocation offset arrays remain borrowed files; BSS has a declared memory_size and no payload. Checks record boundaries, section ordering and END markers. maximum_records bounds blocks, symbols and relocation groups together. Does not link, apply relocations, resolve symbols or allocate BSS; reference targets and offsets are metadata, not a validated linked program. Supports EHF PPC_CODE, RELRELOC26 and EXT_RELREF26 framing without applying relocations. Load modules require hunk_load; indexed libraries and overlays remain rejected rather than silently skipped.

### `archive.ibmi_save`

`archive.ibmi_save(file, maximum_entries=100000, profile="catalog") -> record`

Reads qualified IBM i optical descriptors, catalogs and stored sections. Supported release/target pairs are 4705/4705, 4705/3905, 4600/4600 and older 3400/3400 font descriptors. The default catalog profile requires a save catalog; profile=boot750 permits only the qualified QGENESIST or QINTAPE catalog-free starts. Auto additionally expands codec-02 LD_TRS into lazy logical-prefix views while retaining unknown LD_LZ1 tails and physical/logical provenance. Logical section views fail on unstored bytes, never zero-fill. Explicit IBM037 text rendering is not detected saved CCSID. Standalone 528-byte SAVF, unqualified generations and full object restoration remain unsupported.

### `archive.im4p`

`archive.im4p(file) -> record`

Parses an ASN.1 IM4P firmware envelope with bounded DER depth/node counts, including canonical high-tag-number private properties. Returns payload_type, description, borrowed payload, extras (original optional DER records) and expected_size (LZFSE metadata when present, otherwise zero). Does not decrypt, decompress, authenticate signatures or infer a filesystem; pass payload explicitly to archive.lzfse or the appropriate format reader.

### `archive.img4`

`archive.img4(payload, manifest=None) -> file`

Constructs an IMG4 DER wrapper around a validated complete IM4P file and optional IM4M manifest. Borrows source records without changing payload or metadata; the manifest uses explicit context tag zero. Does not create a ticket, sign or authenticate the image. Omitting the manifest does not bypass firmware authentication.

### `archive.installer`

`archive.installer(file, maximum_scan=256MiB, cache=True, maximum_bytes=512MiB) -> installer`

Recognizes a supported installer container, including supported embedded payloads, and returns an inspection object with files and a declarative installation plan. It does not run the installer or apply that plan.

### `archive.installer_media`

`archive.installer_media(files) -> installer`

Discovers InstallShield packages, including nested packages, from a dictionary mapping portable relative media names to files.

### `archive.installer_probe`

`archive.installer_probe(file, maximum_scan=256MiB, cache=True, maximum_bytes=512MiB) -> dict`

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

### `archive.irix_plan`

`archive.irix_plan(descriptors, selected, machine={}, installed={}, versions={}, indexes={}, images={}, existing={}, previous={}) -> record`

Plans explicitly selected subsystem patterns (or declared defaults when selected is empty), choosing the newest supplied version unless versions pins an exact subsystem. Reports unsatisfied prerequisite alternatives, explicit machine facts, ambiguous destinations, missing payloads and unexecuted preop/postop/exitop hooks. indexes uses product@version keys; images uses product.image@version keys. installed maps subsystem names to versions. existing is the caller's complete current regular-file map, and previous maps paths to prior BSD checksums for config(update/suggest/noupdate) decisions. Returns ordered selections, declarative borrowed-file/node/link operations, removed subsystem names, hooks and issues. resolved only means no known planning issue: payload checksums are validated when read, and this is not installation or boot proof. Unknown policy remains an explicit issue; scripts are never executed.

### `archive.irix_product`

`archive.irix_product(file, maximum_entries=1M) -> record`

Reads IRIX pd001 product descriptors into products, images and subsystems with versions, flags, build-selection expressions, replacement ranges and grouped prerequisites. Preserves alternate descriptions and extended attributes. Checks field bounds, entry limits and zero block padding; it neither executes expressions nor installs software.

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

### `archive.lzfse`

`archive.lzfse(file, maximum_bytes=<unlimited>) -> file`

Opens Apple LZFSE v1/v2, LZVN and stored-block streams as a read-only file. Bounds block size/count and retains a 64 MiB decoded cache plus 256 KiB match history. Backward reads outside cache replay preceding dependent blocks. Validates entropy states, source/output lengths, match distances and end marker; LZFSE has no content checksum. Explicit maximum_bytes bounds total decoded bytes. No host or C decoder is used.

### `archive.lzma`

`archive.lzma(file, maximum_bytes=512MiB, max_dictionary=64MiB) -> file`

Decodes one standalone LZMA stream into a bounded in-memory file. Checks header size, dictionary limit, decoded length, stream termination and trailing data. LZMA has no checksum; callers must authenticate the enclosing payload. This does not interpret the decoded archive.

### `archive.mac_resource`

`archive.mac_resource(file, maximum_entries=1M, maximum_decoded_bytes=256MiB) -> record`

Parses a classic Macintosh resource fork, checking map, reference, name and payload bounds and repeated type groups. Duplicate IDs retain every record in map order; duplicate_ids reports collisions, occurrence is one-based, and later occurrences have ordinal path suffixes. Returns fork attributes and entries with resource_type (four raw bytes), signed id, name (raw bytes or None), attributes, offset, size and data. Uncompressed data is a borrowed view; supported Apple dcmp 0/1/2/3 compressed resources are decoded and validated in memory. Compression requires both attribute bit0 and the a89f6572 payload tag, matching Resource Manager; raw attributes remain available when the bit is set on ordinary data. compressed reports actual decoding, while stored_data and stored_size preserve the original representation. maximum_decoded_bytes bounds total decoded compressed payload bytes and each stored compressed input. Unknown codecs and unsupported token variants fail explicitly. The synthetic path uses hexadecimal type and signed ID without interpreting names as host paths. Payload-specific formats remain separate layers.

### `archive.nsis`

`archive.nsis(file, maximum_bytes=512MiB, maximum_scan=16MiB, maximum_metadata=64MiB, maximum_instructions=1000000) -> nsis`

Decodes NSIS 2 ANSI non-solid stored/DEFLATE metadata and file payloads natively, without running installer code or extracting host files. Stable /files/NNNNNN names identify File instruction indices, preserving duplicate filenames and shared payloads. files lists names; find and indexing return readable files; entries retain name, instruction, source, file and output_directory_hint; instructions, sections and string(offset) expose symbolic metadata for inspection. Directory hints are not resolved destinations. maximum_bytes bounds cumulative unique decoded payload bytes (512 MiB default). Other limits match nsis_list. The same payload is recognized by archive.installer and auto. installer.plan supports selected-section straight-line effects and stops at unresolved control flow; explicit half-open ranges select audited product-policy regions and are reported as explicit_ranges=True. Supported effects include file writes, directories, attributes, string assignments, planned-file copy/deletion, registry values and native WriteUninstaller reconstruction. This is not a general NSIS script VM; callers must reject unresolved plans and supply explicit variables. Solid streams, other codecs, Unicode strings and modified opcode tables are unsupported.

### `archive.nsis_list`

`archive.nsis_list(file, maximum_scan=16MiB, maximum_metadata=64MiB, maximum_instructions=1000000) -> record`

Lists File instructions from the NSIS 2 ANSI non-solid stored/NSIS-DEFLATE metadata layout without executing the installer or reading member contents. Returns format, header_offset, data_offset, header_size, header_compression, instruction_count and ordered entries. Entries retain name, raw_name bytes, instruction index, output_directory_hint, directory_instruction, relative data_offset, absolute offset of the member length word, packed_size, compressed and filetime. Repeated names and payload references are preserved. Directory hints are only the nearest preceding SetOutPath in bytecode order, not resolved installation destinations; variables, shell folders and language references remain symbolic, and literal dollars are doubled. Version-dependent variables remain numeric. This is a listing, not an installation plan or readable file view: no decoded sizes, CRC verification or extraction are claimed. Solid streams, other codecs and Unicode metadata are not supported. Zero limits select defaults; limits bound signature scanning, packed/decoded metadata, rendered text and instruction count.

### `archive.omaha_payload`

`archive.omaha_payload(file, maximum_bytes=512MiB, max_dictionary=64MiB) -> file`

Decodes an Omaha metainstaller LZMA/BCJ2 payload resource into a portable file, normally a tar archive. Bounds both expanded stages, validates all four stream extents and complete BCJ2 termination. Does not select PE resources, execute installer code, authenticate publishers or apply installation effects.

### `archive.pack`

`archive.pack(file, maximum_bytes=2GiB) -> file`

Decodes a UNIX pack (1f1e) Huffman stream, checking its symbol tree, end marker, padding and declared output size. Enforces maximum_bytes and returns a file; useful for compressed IRIX manual pages nested inside inst images.

### `archive.pbze`

`archive.pbze(file, maximum_bytes=<unlimited>) -> file`

Opens a bounded Apple pbze chunk stream as a lazy read-only file using native LZFSE decoding. Validates chunk framing and decoded lengths; maximum_bytes bounds total decoded size. Uses a 64 MiB decoded cache and a 64 MiB per-chunk bound. No host decoder or intermediate files are used.

### `archive.pbzx`

`archive.pbzx(file, maximum_bytes=<unlimited>, replay_cache_bytes=0) -> file`

Opens chunked Apple installer payloads as a lazy read-only concatenated file. Validates decoded/stored chunk lengths, XZ indexes and final short-chunk framing; stored chunks are borrowed. Uses a 64 MiB decoded cache and 64 MiB per-chunk bound. Optional nonnegative replay_cache_bytes adds a byte-bounded volatile indexed S2 cache of verified decoded chunks. Replay and decoded retention use independent 64 KiB blocks, avoiding whole-chunk work on small reads; first XZ verification still covers the complete original chunk. No eager reads or host intermediates. The returned file.stats dictionary separates cumulative successful xz_chunks/xz_bytes from replay_blocks/replay_bytes and includes decoded_cache/replay_cache counters; snapshots under concurrent reads are observational, not transactional. The budget charges exact retained encoded allocations; transient decode buffers are additional. Zero disables it. Omitted maximum_bytes has no total decoded ceiling; explicit positive limits are enforced. Read complete contents to force XZ checksums. Parse the resulting CPIO separately.

### `archive.rar`

`archive.rar(file, maximum_entries=100000) -> RAR archive`

Opens RAR4 and RAR5 archives using bounded-memory native readers, including solid compression, PPMd and executable filters. Files are decoded on demand; complete reads verify checksums. Password-protected and split-volume members require capabilities not exposed by this API.

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

### `archive.udif`

`archive.udif(file) -> record`

Opens XML-backed, single-segment UDIF v4 disk images. Returns disk (complete logical disk), original xml and trailer, BLKX tables (name, offset, size, raw), and verify(). Raw, zero-fill, ignored, zlib and bzip2 chunks use bounded caches. verify() reads stored data and checks declared data-fork, table and master CRC32s; ignored sectors are excluded from table checksums. Rejects encryption, segmented images, unsupported codecs and overlapping/gapped maps. Does not authenticate signatures or infer filesystems.

### `archive.vmsbackup`

`archive.vmsbackup(file, maximum_blocks=1M, maximum_records=1M, maximum_block_size=16MiB, maximum_files=1M, maximum_attributes=256) -> record`

Reconstructs VMS BACKUP file-data chains after the same block, CRC and redundancy validation as vmsbackup_blocks. Returns entries with raw name bytes, flags, declared logical size, stored_size, attributes (kind/data records), missing_contents and data. Data borrows source ranges, excludes allocation slack, and is None when a nonempty file has metadata but no stored payload bytes. missing_contents reports absence without inferring its cause or accepting a partially stored file. Empty files have an empty data view. Rejects discontinuous virtual block addresses, partial data, missing or duplicate name/RMS fields and unsupported record kinds. Retains file attributes without translating RMS records or applying host path rules. Volume/file-ID record interpretation remains outside this API; inspect them with vmsbackup_blocks. Source bytes must remain unchanged while data views are used.

### `archive.vmsbackup_blocks`

`archive.vmsbackup_blocks(file, maximum_blocks=1M, maximum_records=1M, maximum_block_size=16MiB) -> record`

Reads a complete single-volume VMS BACKUP block stream, validating header CRC-16, whole-block CRC-32, sequence numbers, record boundaries and each encountered XOR redundancy payload. Returns blocks with offset, sequence, raw header, parity and records. Records expose offset, kind, flags, address, reserved and a borrowed data file. Unknown record kinds and flags are preserved. Does not repair damaged blocks, require final-group redundancy, join file data records, interpret RMS attributes, or decode nested file contents. The source must remain unchanged while borrowed views are used. Limits independently bound block count, total record count and block size before allocation.

### `archive.wim`

`archive.wim(file, references=[], cache_bytes=384MiB) -> wim`

Parses a Windows Imaging Format archive and exposes its image contents through file views. The archive reader handles its supported compression internally without mounting an image. Nonnegative cache_bytes bounds retained buffers shared with reference archives; zero disables retention. Large solid LZMS archives split that same budget between decoded chunks, a small decoded hot-file tier and compressed in-memory blobs (whole small files and at most 32MiB per segment of large files), keyed by the complete WIM SHA-1 and segment ordinal. No decoded data is persisted. cache_stats.bytes/entries/peak_bytes aggregate these tiers; blob_bytes counts encoded retained bytes, blob_hits/blob_loads count compressed-tier accesses, and recent_files is a bounded chronological window of the last 64 cold file reads. prefetch(paths) validates at most 200000 explicit file paths before payload reads, deduplicates content, and prepares eligible solid files in physical chunk order with at most four joined workers; returns the unique source byte count. Prefetch does not pin entries or exceed the cache budget, and ordinary non-solid files are not eagerly read. Large multi-chunk reads use bounded parallel decoding and join all workers before returning. Entry and file metadata expose tagged_items as ordered tag/data records, retaining unknown extensions. apply preserves Windows tag-2 extended attributes (names, flags and value bytes) for supporting filesystem builders; it does not synthesize trust verdicts or apply unknown tags.

### `archive.xar`

`archive.xar(file, maximum_entries=100000) -> record`

Indexes XAR v1 without extraction. Returns entries, files, original decoded toc, raw heap and find(path). Entries preserve path, kind, ID, mode, uid/gid, link target, encoding, raw/data file views, size and verify(). Verifies declared compressed-TOC checksum on open; member verify() checks archived/extracted checksums and exact decoded lengths. Supports stored, zlib and bzip2 members. Safe paths, XML depth/size, heap extents and index sizes are bounded. Signature metadata remains in TOC/heap but signatures are not authenticated.

### `archive.xz`

`archive.xz(file, max_dictionary=64MiB) -> file`

Decodes an XZ stream into a file, rejecting decoder dictionaries above max_dictionary. This unwraps compression; it does not interpret an archive contained in the decoded bytes.

### `archive.zip`

`archive.zip(file) -> zip`

Parses a ZIP archive and exposes member files through files or entries. Members expose name/path, entry_type, compressed_size and compression_method. Complete reads validate decoded size and CRC; entry.verify() forces complete validation, including empty entries. Each member retains a bounded 8 MiB decoded window; backward reads outside it restart decompression. No host extraction occurs.

### `archive.zstd`

`archive.zstd(file) -> file`

Opens a Zstandard stream as a portable file with a 64 MiB decoder window limit. Frame headers provide decoded sizes when available; streams without content sizes require a counting pass. Reads and seeks replay decompression without extracting host files.

### `binary.android_boot`

`binary.android_boot(file) -> record`

Reads Android boot and vendor_boot v3/v4 headers, exposing bounded section files, command_line, version and page_size. Vendor v4 includes ramdisk fragments with type and board identifiers, plus a bootconfig section. Validates section/table bounds; does not decompress ramdisks or authenticate AVB signatures.

### `binary.annotate`

`binary.annotate(file, attrs) -> file`

Wraps a file with caller-supplied attributes while retaining its bytes. Use this to attach construction metadata without rebuilding the file's contents.

### `binary.apple_device_tree`

`binary.apple_device_tree(file) -> record`

Decodes an Apple flattened device tree into recursive properties, property_flags and children records. Preserves template flag bits without resolving bindings. Bounds input to 1 MiB, depth to 32 and nodes to 4096; rejects malformed names, duplicate properties, truncation and trailing bytes.

### `binary.appledouble`

`binary.appledouble(file) -> dict[int,file]`

Parses AppleDouble version 2 headers and returns an integer-entry-ID dictionary of borrowed files. Validates table bounds, duplicate IDs and non-overlapping extents. Preserves unknown entries without interpreting them. FinderInfo (9), resource fork (2) and any ATTR extension remain raw bytes; does not apply metadata or modify files.

### `binary.appledouble_metadata`

`binary.appledouble_metadata(file) -> dict(finder_info, resource, xattrs, other)`

Decodes FinderInfo, resource forks and macOS ATTR named attributes as separate borrowed views. Absolute ATTR offsets, 64 KiB header/table bound, names, duplicate attributes and overlapping data extents are checked. Unknown entry IDs are retained in other. Does not apply metadata or follow links.

### `binary.arm64_disassemble`

`binary.arm64_disassemble(source, offset=0, address=0, count=32) -> list`

Decodes 1 through 4096 ARM64 instructions from a portable file or byte view. Returns records with address, bytes, instruction and target for PC-relative operands. Unknown instructions retain their original bytes and report unknown. Offset and caller-supplied address are independent; no host disassembler is used.

### `binary.base64`

`binary.base64(value, url=False, padding=True, maximum=512MiB)`

Encodes binary input as a Base64 string. url selects the URL-safe alphabet, padding controls trailing equals signs, and maximum bounds encoded output.

### `binary.berkeley_db`

`binary.berkeley_db(file, maximum_entries=1000000) -> record`

Reads BSD Berkeley DB version-3 B-trees with inline keys and values in either byte order. Returns page_size, little_endian and entries with borrowed key/value file views, preserving on-disk comparator order. Validates root traversal, page bounds, overlapping records, cycles and leaf sibling links. Rejects overflow records, recno databases and newer formats explicitly; does not execute or infer a database-specific comparator.

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

### `binary.elf_symbols`

`binary.elf_symbols(file, maximum_symbols=1000000, maximum_string_bytes=16MiB)`

Reads bounded ELF64 static/dynamic symbols and load segments from a portable file, in either byte order. Returns type, machine, entry, little_endian, symbols (name, address, size, section, binding, type, visibility, dynamic), and segments (address, offset, file_size, memory_size, flags). Addresses are ELF values, not runtime-relocated addresses; callers supply mapping/load bias. Zero-sized/undefined symbols are preserved, not assigned inferred extents. Rejects extended numbering, duplicate symbol-table kinds, compressed symbol/string metadata, malformed extents/names and resource-limit violations. Does not read host symbols or load code.

### `binary.encode`

`binary.encode(value, encoding='utf8', nul=False) -> bytes`

Encodes a string into bytes using the selected character encoding, including explicit IBM037/cp037. Unrepresentable characters fail. nul appends an encoding-appropriate terminator; binary.text performs the reverse conversion.

### `binary.encode_apple_device_tree`

`binary.encode_apple_device_tree(tree) -> file`

Encodes an Apple flattened device tree from recursive records or dictionaries with properties (string-to-bytes), optional property_flags, and children lists. Uses the same bounded layout and validation as binary.apple_device_tree, preserves explicit flags, and creates a portable in-memory file. Template expressions require caller policy before kernel handoff.

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

### `binary.irix_executable`

`binary.irix_executable(file) -> record`

Inspects MIPS ELF32/ELF64 and ECOFF32 files natively, returning byte order, o32/n32/n64 ABI and ISA flags, entry/GP, borrowed sections and segments, symbols, relocations, dynamic tags and needed libraries. MIPS64 relocations preserve all three operation types and the special-symbol byte; MIPS option/ABI-flag records expose compiler metadata and the GP value. ECOFF symbolic tables retain local/external names and storage classes. Tables, counts, names, ranges and references are bounded and checked. It does not apply relocations, load executable code, interpret all debug records or emulate IRIX syscalls.

### `binary.layout`

`binary.layout(format, names=None) -> binary.layout`

Compiles a fixed-size binary layout from a format string and optional field names. The returned value encodes records or decodes a source at a byte offset.

### `binary.macho`

`binary.macho(file, architecture="x86_64", cpu_subtype=None) -> record`

Inspects a bounded little-endian Mach-O64 image (architecture x86_64 or arm64), optionally selected from a big-endian fat32/fat64 universal container. cpu_subtype optionally selects an exact uint32 subtype (including arm64e capability bits) and validates the thin header; omitted selection rejects ambiguous CPU matches. Exposes the selected cpu_subtype, initial thread entry PC (zero when absent), borrowed file, segments (name, address, size, file_offset, file_size, flags), original symbols (name, address, type, section, description), dyld exports (name, address, flags, resolver, reexport_ordinal, import_name), indirect imports (name, kind stub/pointer, address, size), and fileset_entries (name, address, file_offset) for MH_FILESET kernel collections. fileset(name) opens an embedded Mach-O through the same reader, preserving collection-relative segment and linkedit offsets. Bound filesets with stripped symbol tables may contain zero indirect-symbol placeholders; these expose no named imports. Fileset offsets refer to the containing image; entries are not independent extracted binaries. at(address, size) returns borrowed file-backed virtual bytes; zero-fill, unmapped, ambiguous and overflowing ranges fail. Header, command, string, symbol and export-trie traversal bounds and aggregate name/prefix allocations are enforced. Export trie support includes ordinary, absolute, weak, thread-local, reexport and stub/resolver terminals; it does not resolve reexport dependencies. Does not relocate, link or execute the image.

### `binary.perf`

`binary.perf(file, maximum_records=1000000, maximum_samples=1000000, maximum_string_bytes=1MiB) -> record`

Reads finalized little-endian Linux PERFILE2 perf.data directly from a file. Returns attributes, samples, mappings, comms, lost, total_lost, unknown_records (record type to count), records and little_endian. Samples expose ip, pid, tid, time, address, id, stream_id, cpu, period, identifier and a present bit mask; absent fields are None. Each record retains its file offset and raw misc bits, so streams can be ordered and CPU modes distinguished. MMAP/MMAP2 records expose address, length, page_offset, filename and available inode/build-ID/protection metadata. Mapping, COMM and loss records include a sample_id trailer record. Attributes retain sample_type, read_format, flags, IDs, sample_id_all, use_clock_id and clock_id (None unless explicitly selected). Times retain the recorded clock domain; no symbols, paths or clock conversion are inferred. Rejects pipe/unfinalized input, unsupported sample layouts, heterogeneous attribute layouts, compression and AUX streams. All limits must be positive. Records and samples are each capped at 10 million; maximum_string_bytes bounds aggregate decoded names and is capped at 64 MiB. Limits and malformed records fail explicitly rather than returning a truncated profile.

### `binary.plist`

`binary.plist(source) -> value`

Decodes bounded XML 1.0 or bplist00 property lists into dict/list, bytes, string, bool, int64, float and opaque round-trippable plist_date values. Binary null becomes None; unsupported UID and 16-byte integers fail explicitly. Enforces 64MiB input/decoded data, 100000 visited values and depth128, validates reference/offset bounds, rejects cycles, duplicate keys and invalid Unicode. Does not follow XML external entities.

### `binary.plist_encode`

`binary.plist_encode(value) -> file`

Encodes supported plist values as deterministic XML1.0 in an in-memory file. Preserves plist_date values from decoding. Enforces aggregate conversion/output byte, node and depth limits, including dictionary keys. Rejects None, non-finite floats, non-string keys, invalid XML characters and integers outside int64.

### `binary.ppc_instructions`

`binary.ppc_instructions(source, offset=0, size=256, address=0, byte_order="big", maximum=4096) -> list[record]`

Inspects a four-byte-aligned POWER instruction range without execution. Accepts source, offset=0, size=256, address=0, byte_order=big and maximum=4096. Reads at most 64KiB, returns offset/address/length/word/opcode/GNU text/typed operands, resolved 64-bit branch target and explicit decode errors. Absolute branch labels are sign-extended for target; upstream GNU display uses 32-bit label spelling. Prefixed instructions consume eight bytes; unknown words consume four and are not proof of executable code. Maximum is at most 16384; source bounds, alignment, address overflow and instruction budget fail explicitly.

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

### `binary.rpm_metadata`

`binary.rpm_metadata(file, maximum_entries=65536, maximum_bytes=16MiB) -> record`

Reads RPM package metadata with a version-3/4 lead and v1 headers, without executing scripts, decompressing payloads or authenticating signatures. Returns fields (named stored tags), tags and signature_tags (numeric keys with type/count/value), source_package, payload_offset and a borrowed payload file. STRING is a string; numeric values and STRING_ARRAY/I18NSTRING are lists; BIN is bytes. Missing fields are absent; localized strings are not selected. Unknown tags are retained; unknown types, duplicate tags, unsupported leads, invalid offsets/counts/alignment and unterminated strings fail. Entry/byte limits cover both headers; decoded values are also bounded against alias amplification. Maximum entries is 1M and maximum bytes is 256MiB. No digest, immutable-region or signature verification is performed; this is inspection, not package validation or an RPM database reader.

### `binary.snapshot`

`binary.snapshot(file, maximum=512MiB, cache_bytes=64KiB) -> file`

Copies a stable source file into an independent immutable in-memory snapshot, using 64KiB compressed chunks (raw when compression would expand them). Reads the complete source sequentially within maximum; no host intermediates or source references remain. cache_bytes bounds the per-snapshot decoded read cache, not encoded storage or transient decoder memory. Source must not change during copying. This preserves bytes, not authenticity: retain source hash and format validation. Returned file supports ordinary random access, not a serialized archive format.

### `binary.snapshot_many`

`binary.snapshot_many(files, maximum=512MiB, cache_bytes=1MiB) -> list`

Copies at most 65536 stable files into independent immutable in-memory snapshots in input order. maximum bounds their aggregate size, checked before reading; cache_bytes is one shared decoded-byte budget for the whole batch. Uses compressed 64KiB chunks with deduplication within the batch; returned files retain neither sources nor encoder. Encoded bytes and transient memory are outside the decoded cache budget. Sources must remain unchanged during copying. Preserves bytes, not authenticity; retain source and format validation.

### `binary.software_update_catalog`

`binary.software_update_catalog(source) -> list`

Reads plain or gzip Apple software-update catalogs and returns installer products as id/metadata dictionaries in ID order. Selects OSInstall or SharedSupport InstallAssistant identifiers, preserving original package URLs, int64 sizes, digests, dates and Distribution locations. Does not fetch URLs or filter host compatibility. XML is decoded per product, bounded to 128MiB stored/expanded input, 8MiB per product, 4M XML tokens and depth128; each product retains plist value limits. Binary catalogs use the existing stricter plist limits. Rejects duplicate product/catalog keys, malformed XML/plists and corrupt gzip.

### `binary.software_update_distribution`

`binary.software_update_distribution(source) -> dict`

Reads bounded installer-gui-script XML (8MiB, 4M tokens, depth128). Returns title, raw_title, version, build, auxinfo, options, scripts and localizations. Prefers macOSProductVersion/macOSProductBuildVersion to VERSION/BUILD. Resolves observed double-quoted localization title assignments; unsupported localization grammar remains in raw_title/localizations. Scripts are retained as text, never executed, and external entities are not followed. This is metadata, not an eligibility decision.

### `binary.strings`

`binary.strings(value, encoding='ascii', minimum=4, maximum=64MiB) -> list[string]`

Scans bounded binary input for printable ASCII, UTF-16LE or explicitly rendered IBM037 strings of at least minimum characters. IBM037 is a selected rendering, not saved-CCSID detection. Returns strings, not offsets or a decoded file.

### `binary.text`

`binary.text(value, encoding='utf8', nul=False, maximum=16MiB) -> string`

Decodes bounded binary input using the selected character encoding, including explicit IBM037/cp037 (not CCSID detection). nul requests terminator-aware decoding; maximum bounds input size.

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

`binary.xml(value, maximum=16MiB, max_depth=256, max_nodes=1M, discard_whitespace=False)`

Parses XML into namespace-aware immutable document and node values. Size, depth and node-count limits bound parsing; with_root/with_children/with_text create edited values for serialization. Optional discard_whitespace removes whitespace-only XML character-data tokens (space, tab, CR, LF) unless inherited xml:space requests preservation; xml:space=default resets preservation and unknown values preserve conservatively. Other text, attributes, comments and processing instructions remain unchanged. Default parsing retains all whitespace. This option is for structural analysis, not lossless editing or signed serialization. Nodes expose attribute_map(namespace='', strict=False), an independent name-to-value dictionary for one exact attribute namespace. Namespace declarations are ignored, duplicates in the selected namespace are rejected, and strict=True rejects attributes from any other namespace. Default element namespaces do not apply to unprefixed attributes.

### `binary.xml_many`

`binary.xml_many(values, workers=4, maximum=16MiB, max_depth=256, max_nodes=1M, discard_whitespace=False, total_maximum=256MiB)`

Parses a list of at most 4096 XML inputs with 1..8 native workers (default 4), preserving input order and duplicates as independent immutable documents. XML options and per-document validation match binary.xml. Input/file conversion runs on the caller thread before parsing; workers receive owned byte snapshots and never call Starlark. total_maximum bounds aggregate input bytes (default and maximum 256 MiB). Input conversion errors precede parsing; otherwise the lowest failing input index determines the error after all workers join, with no partial result.

### `binary.zlib`

`binary.zlib(source, maximum=16MiB)`

Decodes one complete RFC 1950 zlib stream from bytes or a file. Returns bytes; verifies the checksum and rejects truncation, trailing data and output beyond maximum (0..512MiB). No host extraction or intermediate files.

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

### `block.temporary_overlay`

`block.temporary_overlay(base, directory) -> disposable sparse block device`

Creates disposable native sparse backing in the explicit host directory, with no changed-data quota or memory fallback. The immutable base remains unchanged. Create it before its VM; runtime cleanup closes users before removing the backing at script exit. Available host disk space bounds writes; backing I/O errors are terminal. It is not a snapshot or reusable disk image.

### `block.view`

`block.view(device) -> live read-only file view`

Returns a read-only file view of a live block device. Later device changes remain visible through the view; it is not an immutable snapshot.

### `cc.backend`

`cc.backend(acpi=False, pci_ide=False, pci_display=False, hpet=False, uefi=False, usb=False, ide_model='synthetic', ide_dma=True, overlay_limit=268435456, run_timeout=30.0, private_apple_isa=False) -> vmm_backend`

Creates an in-process CrumbleCracker backend for Linux/amd64 KVM or native macOS ARM64 HVF. ARM64 uses explicit CPU/load state and an optional caller-composed vmm.arm64_platform. The native loop dispatches MMIO, optional polling/lifecycle hooks and platform HVC before PSCI; it has no board map or OEM service policy. Native protocol devices receive placement, backing and wiring from the platform factory. run_timeout bounds ARM64 execution in seconds (default 30). private_apple_isa=True selects HVF private ISA level 3 before VM creation and requires com.apple.private.hypervisor on a configured host; this host option is independent of board selection and nested EL2. ARM64 is headless and supports one CPU, named byte channels and snapshot-backed block resources. RAM must align to host pages; memory protection applies to both guest CPU access and emulated DMA. PC devices and Intel symbol/disassembly helpers below apply to x86 guests. The i386 and x86_64 platforms provide Go BIOS services, one ATA disk, VGA capture and PS/2 input. ACPI is automatic for x86_64 and optional for i386. uefi=True selects native Go UEFI for x86_64 GPT disks, enables PCI IDE, and provides a 1280x720 GOP framebuffer. Native UEFI PCs accept cpus=1..4 as one package without SMT; other PC profiles remain single-CPU. All-core pause/stop/capture barriers precede inspection and teardown. cc.v1.cpus() returns per-core register summaries; state/read_virtual use CPU0, and breakpoint/step require one CPU. RAM supports 16 MiB through 8 GiB for x86_64 BIOS/direct Darwin, 3 GiB for i386, or 16 GiB with uefi=True. usb=True on x86_64 enables a UHCI keyboard and absolute pointer with wheel; PS/2 keyboard fallback remains until USB enumeration. RAM beyond 3 GiB is mapped above 4 GiB, leaving the PCI MMIO window unmapped as RAM. hpet=True adds a 100 MHz HPET with three comparators and enables ACPI. pci_display=True exposes the 1234:cc02 TRF1 PCI framebuffer at bus 0 device 2, with an 8 MiB BAR at 0xe0000000; it requires a compatible guest display driver. pci_ide enables ACPI and a generic PCI IDE controller with PIO and bus-master DMA; ide_dma=False selects a PIO-only disk. ide_model='synthetic' preserves the generic compatibility controller; 'ich7-pata' requires PCI IDE and selects the 8086:27df profile with one primary disk, compatibility IRQ14 and native INTA routed to GSI16. The secondary channel has no disk. Timing registers are recorded; electrical cable timing is not simulated. The cc.v1 extension provides bounded read_virtual, original kernel symbol lookup and read-only disassemble observations for direct Darwin boot. overlay_limit bounds dirty snapshot memory in bytes (default 256 MiB). vmm.start creates the guest from portable memory and disk intent.

### `cc.boot_bsd`

`cc.boot_bsd(os, kernel, marker, root=None, memory_mb=1024, timeout=60, console=None, overlay_limit=64MiB) -> result`

Directly boots an original amd64 OpenBSD, FreeBSD or NetBSD kernel in Linux/amd64 KVM with optional borrowed NVMe root backing. Stops at an explicit serial marker, timeout or failure and closes the VM. Returns success, serial, error and a read-only post-boot root snapshot (None without a root). The snapshot is available on failure too; FreeBSD timeout errors include bounded architectural observations. Output is capped at 1 MiB, kernel at 256 MiB, memory at 64..8192 MiB and timeout at 600 seconds. Console is at most 64 ordered (wait, send) string tuples; root writes use a bounded in-memory overlay, never alter the source. This is a bounded serial boot primitive, not a persistent desktop or managed-agent session.

### `cc.kernel_symbol`

`cc.kernel_symbol(kernel, address) -> symbol or None`

Read-only nearest original executable-section ELF symbol lookup for a stopped kernel address. Returns name, address, size and offset, or None when no preceding symbol exists. A nonzero offset is a nearest-symbol observation, not an exact call-site assertion. Input is bounded to 256 MiB and symbol/string sections to 32 MiB. Does not relocate, execute or patch bytes.

### `channel.expose_tcp`

`channel.expose_tcp(channel, port=0) -> tcp_bridge`

Native-only IPv4 loopback bridge for one trusted TCP client. Port zero selects a free port, returned as port. Takes exclusive ownership of the byte channel on success; do not read or write it elsewhere. The listener closes after the first connection; disconnect closes both streams without reconnect or replay. Uses bounded copy buffers. close() interrupts and joins workers; runtime teardown also closes it. The channel must unblock reads and writes on close. TCP is plaintext and has no authentication; other local processes can connect.

### `channel.extension`

`channel.extension(channel, timeout=5) -> extension`

Discovers a synchronous v1 device over an exclusively owned byte channel with deadlines. Exposes manifest-declared methods with positional/keyword arguments and type checks. close() closes the channel. No host SDK, sockets, futures, retry or reconnect. Malformed replies, transport errors and timeout close it with outcome uncertain; ordinary device ERR leaves it usable. help(device) shows the manifest. For complete framing, discovery, value grammar, bounds and native input examples: print(channel.extension_protocol()).

### `channel.extension_protocol`

`channel.extension_protocol() -> string`

Returns the complete offline synchronous v1 wire specification, including the Windows 1.01 native input payload. Print it in the REPL; no connection or I/O required.

### `channel.memory_pair`

`channel.memory_pair(maximum=1MiB) -> (byte_channel, byte_channel)`

Creates two connected, bounded byte channels entirely in memory, without host sockets or DNS. maximum limits each incoming queue (default 1 MiB, at most 64 MiB). read_available returns None when the peer has no data yet, bytes when data is ready, and empty bytes after the peer closes and its data is drained. write_available returns the byte count, None when capacity is insufficient, or -1 for a closed endpoint; writes are all-or-nothing. write instead raises an error when delivery is unavailable. Emulator checkpoints restore queued data and closed state when endpoints are retained in plugin state.

### `clock.monotonic`

`clock.monotonic() -> elapsed seconds`

Returns seconds from the runtime's monotonic clock. Subtract readings to time work; the value is not a calendar timestamp.

### `clock.profiler`

`clock.profiler() -> clock.profiler`

Creates a profiler for named spans, counters and measured calls. Its snapshots and reports summarize work explicitly recorded through this profiler.

### `clock.read_profiler`

`clock.read_profiler(max_files=16384, max_events=1024, min_seconds=0.01) -> clock.read_profiler`

Measures completed reads from labeled file views with bounded per-file aggregates and slowest-call samples. Uses the runtime monotonic clock without executing callbacks on I/O threads.

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

`database.ese_build(tables, database_pages=0, sort_data=None, page_size=32768, revision=0) -> file`

Builds an ESE database in memory from declarative tables. Supports Windows 2000 revision 2 with page_size=8192 and Windows 8 revision 0x14 with page_size=32768; revision=0 selects the matching default. sort_data accepts base US-English sortkey.nls for Windows 2000 or SortDefault.nls for Windows 8. An empty indexes list creates a heap table. Revision 2 tagged columns accept lists of values; columns may preserve raw catalog defaults with default bytes.

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

Waits until one of the supplied selectable values is ready, returning that value, or None on timeout. Read the event from the returned source separately; selection itself does not consume the event. For byte channels, readiness includes data, stream closure, or a spurious change notification (such as checkpoint restoration): retry the read to distinguish them. A closed debugger/event session still reports EOF.

### `emulator.linux`

`emulator.linux(max_instructions=10000000) -> shell_command`

Creates an ELF execution capability for shell.run(executable=...). Recognizes static Linux/amd64 ELF images, preserves argv[0] independently of the resolved guest path, and uses the same virtual filesystem and inherited streams. Non-ELF input falls back to the shell script loader.

### `emulator.machine`

`emulator.machine(image|code, architecture='auto', **architecture_options) -> emulator`

Creates an in-process machine for the input's supported architecture, using native instruction execution and modeled Windows API callbacks. Instruction and memory limits bound execution; this is not a QEMU VM.

### `emulator.plugin`

`emulator.plugin(install, name='plugin', state=None, attrs=None) -> plugin`

Wraps explicit mutable plugin state and its installation callback for emulator use. Keep checkpointed callback state here rather than hiding it in closures.

### `emulator.processor`

`emulator.processor(architecture='arm64', memory=64MiB) -> processor`

Creates a portable in-process ARM64 or AMD64 instruction context independently of executable formats and OS APIs. map(address,size,data=None,access=rw) copies bounded bytes/files into owned sparse memory; read/write, get_register/set_register and plugin expose explicit experiment state. run(maximum_steps,stop_at=[]) stops before address breakpoints and returns reason, detail, steps and PC for breakpoint, halt, budget or fault. ARM64 uses the existing baseline ARMv8-A processor without optional PAuth. No code is implicitly loaded or executed. close() releases the context.

### `emulator.uefi`

`emulator.uefi(image, memory=256MiB, memory_base=0x40000000, image_base=0, stack_size=1MiB, time_unix=0, image_path='\\EFI\\Boot\\BootAA64.efi', registers={}, observe=None, device_path=b'', event_kinds=None)`

Loads an ARM64 EFI image into a configurable in-process interpreter. Runs stop at budgets, watches, explicit breakpoints, unsupported operations or validated ExitBootServices. CPU, RAM, firmware and disk overlays support checkpoints; digest-checked rewrites accelerate recognized routines. See the [UEFI inspection API](../../../emulator/uefi/README.md) for configuration and limitations. Native HVF can execute directly from the EFI entry point or continue suspended firmware state; see the [native UEFI API](../../../docs/uefi-native.md).

### `emulator.x86`

`emulator.x86(image|code, base=0x1000, entry=None, instruction_limit=2M, memory_limit=32MiB, stack_size=1MiB, call_depth_limit=1024, trace=False, trace_limit=4096, profile=False, profile_interval=256, profile_limit=16384, image_name='main', fs_base=0, segment_size=4096)`

Creates a bounded 32-bit x86 execution context from a PE image or raw code. Exposes guest registers, memory, hooks and snapshots; unsupported behavior returns structured stops rather than executing host code.

### `filesystem.android_super`

`filesystem.android_super(file, slot=0, devices={}) -> record`

Reads raw Android super-partition metadata versions 10.0–10.2 with geometry/header/table SHA256 validation and backup fallback. Exposes groups, physical devices and logical partition files composed from linear/zero extents. slot chooses a metadata slot; devices supplies additional physical files by name. Views borrow their inputs; sparse wrappers and EROFS traversal are separate formats.

### `filesystem.apfs`

`filesystem.apfs(file) -> record`

Inspects a raw APFS container natively. Returns the selected container superblock byte view, block_size, blocks, transaction, allocation() and volumes with name, canonical UUID string, ID, role, flags, tree metadata, snapshot_count, snapshot_tree, snapshot_tree_type and browse(raw=False), plus the selected volume superblock byte view. snapshots() validates snapshot metadata and name records; snapshot(name) opens that immutable filesystem through its physical superblock and historical object-map versions, exposing the same read APIs. browse reconstructs entries, paths and exact find(path) from ordinary unencrypted filesystem trees; each entry exposes entry_type, ID/private_id, mode/uid/gid, target, size, data, raw_data, compression_type, xattrs and xattr_streams (nonresident attribute stream IDs). allocation() validates the selected checkpoint maps, space manager, chunk bitmaps and free counts, returning bounded free_ranges and metadata summaries; it does not allocate or modify blocks. Supports sparse files, regular hardlinks, embedded/streamed xattrs and shared decmpfs types 3/4/9. raw=True retains compression metadata and physical streams with data=None for compressed files. Checks object checksums, object-map versions, tree and extent bounds. Symlinks remain entries. Sealed volumes support headerless hashed metadata trees and separate file-extent trees. seal_info() returns integrity version/flags/hash type, advertised root hash and original root node. verify_seal(expected=None) validates all metadata node hashes, optionally against external trusted root bytes; it counts file-data hash records but does not read or verify file contents. records() copies bounded (key,value) metadata byte tuples in APFS traversal order. object(id) returns the selected virtual object mapping and borrowed bytes. canonical_records(time_ns, hashes) normalizes inode/directory/stream metadata, omits physical extents and merges APFS file-info hash tuples. seal_image(records, expected, snapshot_name='', snapshot_time_ns=0, companions=[]) constructs an immutable standalone single-checkpoint container with these records, a mandatory matching external SHA-256 root, preserved file data, updated maps and allocation accounting; it requires an unencrypted snapshot-free volume and a single-block internal-pool bitmap. A nonempty snapshot_name and explicit positive snapshot_time_ns additionally construct a named boot snapshot, its physical superblock, object-map snapshot index and extended metadata, while moving the extent-reference tree into the snapshot and starting an empty live extent-reference tree. companions accepts up to 16 dictionaries with name, role, created_ns, optional directories and optional entries. Entry dictionaries supply path, entry_type (directory/file/symlink), mode, optional uid/gid, file data and symlink target. Native construction copies plaintext into new blocks, builds bounded mutable virtual filesystem trees, physical extent references and data-stream refcounts, creates missing directory parents and synthetic root entries, expands the container volume slots, and assigns deterministic UUIDs. Data shares an existing system volume group; ungrouped sources remain ungrouped. Bounds include 128 directories, 1024 explicit entries, 8 MiB per file and 32 MiB aggregate data, with a single bounded extent-reference leaf. Existing source IDs, compression and xattrs are not copied. Native directory, mapping, allocation and seal checks run before returning. The result includes snapshot_name, snapshot_transaction and deterministic snapshot_uuid. It retires historical checkpoints and is not a live-disk journal operation. File-content hash verification remains the caller’s responsibility. Encrypted and fusion volumes and ephemeral filesystem trees are unsupported; no mounting, repair or execution is performed.

### `filesystem.apfs_sealed_tree`

`filesystem.apfs_sealed_tree(records, block_size=4096, hash_type=1) -> record`

Constructs a packed headerless APFS filesystem metadata B-tree in memory from (key,value) byte tuples already in APFS traversal order. Returns file, root_hash, nodes and records. Supports power-of-two node sizes 4096 through 65536 and SHA256, SHA512/256, SHA384 or SHA512. Reproduces sequential node splitting, relative node identifiers, conservative index preflight, freed separator bytes and child hashes for the observed PCC generation. Bounds records and tree storage; does not install the tree into a container, create integrity metadata or snapshots, supply file extents, or claim authentication without a trusted matching root seal.

### `filesystem.apm`

`filesystem.apm(file, block_size=512, maximum_entries=1M) -> record`

Reads an Apple Partition Map as portable partition file views. block_size explicitly selects the 512-, 1024- or 2048-byte logical map; device_block_size and device_blocks retain independent driver-descriptor geometry. This distinction matters for CDs containing overlapping maps. Each partition exposes its effective block_size: a CDvr-tagged Apple_Driver43_CD record with a matching block-zero driver descriptor uses 2048-byte device units even in a 512-byte map; other records use the selected map units. Validates ER/PM signatures, consistent entry counts, allocated-partition bounds and nonoverlap. Returns partitions with index, raw name/type/processor bytes, start_block, blocks, logical data-range fields, status and boot metadata. data is the complete physical partition view; no inner filesystem is inferred. An out-of-image Apple_Free descriptor retains its declared geometry with data=None and complete=False; allocated partitions must fit fully. Boot metadata is not executed and boot checksums are not verified.

### `filesystem.ckd_attribute_page`

`filesystem.ckd_attribute_page(data) -> record`

Parses one 4096-byte IGW AD page, returning level and cells with decompressed 20-byte key, uninterpreted flags and value bytes. Observed cell flags, including 0xc0, 0xd5, 0xe5 and 0xec, are preserved, not interpreted as liveness. Validates page framing, live-region bounds, group/cell lengths, anchored prefix compression, trailing zero suppression and leaf key ordering. Internal namespace separators may be shortened; full traversal validates actual leaf order. Does not resolve internal child identifiers, traverse a dataset, or decode PDSE members or HFS files.

### `filesystem.ckd_catalog_record`

`filesystem.ckd_catalog_record(data) -> record`

Parses an observed BCS record into kind, name, raw key, ordered type-03 relationship references and nested cells. Data/index component cells expose their names and children; other attributes retain raw bytes. Validates record length, key header, component lengths and subtree bounds.

### `filesystem.ckd_control_interval`

`filesystem.ckd_control_interval(data) -> record`

Decodes one explicitly selected VSAM data control interval (512 to 32768 bytes, multiple of 512). Returns eof, free_offset, free_length and records in data order. A zero CIDF is a software EOF marker; callers must establish the input is a VSAM data CI. Validates CIDF and backwards RDF boundaries, including repeated equal-length records. Rejects unsupported flags and spanning. Does not interpret indexes, RRDS slots, catalog relationships or high-used RBA; not a complete VSAM dataset reader.

### `filesystem.ckd_igw_attributes`

`filesystem.ckd_igw_attributes(data, max_cells=100000) -> list`

Enumerates the bounded active IGW attribute tree of an allocated-page file through native map-chain and child-link validation. Returns exact 20-byte keys, flags and uninterpreted values. Does not carve inactive pages or decode file payloads.

### `filesystem.ckd_scan`

`filesystem.ckd_scan(file, max_tracks=16777216, max_errors=0) -> record`

Validates every physical CKD track and exact cylinder-aligned EOF through a portable file. Returns tracks, records, data_bytes, key_bytes and image_bytes; max_tracks bounds the scan. Reads free space and record zero too, and propagates source checksum errors. Accepts uncompressed CKD_P370 and compressed CKD_C370 base images. With max_errors > 0 (at most 1M), every track implied by the cylinder-aligned image size is parsed and per-track failures are returned as errors (track, error) instead of stopping, failing only beyond max_errors; tracks counts successful tracks. Does not claim logical dataset decoding.

### `filesystem.ckd_vsam_records`

`filesystem.ckd_vsam_records(data, organization, ci_bytes, used_bytes, cis_per_ca, key_offset=0, key_length=0, index=None, index_ci_bytes=4096, index_used_bytes=0, index_root_rba=0, max_records=100000, max_record_bytes=16777216, max_intervals=1000000, max_bytes=67108864) -> list`

Reads a resolved immutable VSAM data component through portable files. ESDS preserves physical record order; fixed RRDS preserves record numbers across vacant slots; KSDS follows the supplied active index root and verifies strictly increasing keys. Assembles spanned records only within a control area and matching update generation. Returns record number, RBA and unconverted data bytes. Explicit high-used bounds, CI/CA geometry and key metadata are required; allocation size is not substituted for high-used RBA. The optional index is traversed natively using header/section/key compression and active child pointers, excluding free intervals. Enforces interval, record-count, per-record and total-byte budgets. Does not infer catalog metadata, index roots, variable RRDS or extended-address formats.

### `filesystem.ckd_vvr`

`filesystem.ckd_vvr(data) -> record`

Parses an observed primary Z VVDS volume record, returning component, cluster and catalog names, index/data flags, index root RBA, CI size, high-used and allocated byte bounds, control-area geometry, maximum record length and key position/length. Reports ci_addressed and converts qualified extended data-component CI counts to 64-bit byte bounds. Rejects incompatible headers, cell bounds and geometry; extended index roots and multivolume layout remain unsupported.

### `filesystem.cms`

`filesystem.cms(file, cylinder, cylinders=0, directory_origin=0, max_files=100000) -> record`

Opens the CMS EDF minidisk whose CMS1 label is record 3 of the given cylinder's first track in a CKD_P370/CKD_C370 image. cylinders, when nonzero, is the authoritative extent (for example from a CP directory MDISK statement); the label must fit it, so stale or overlapping labels fail. directory_origin selects an alternate directory block. Returns id, block_size, blocks, used_blocks, cylinders, maximum_cylinders, blocks_per_track, directory_origin, created (YYMMDDHHMMSS), label, files and the methods read(index, max_bytes=64MiB) -> file and verify(max_bytes=64MiB) -> record(files, bytes, errors). files entries expose name, type, mode, record_format (F or V), record_length, records, data_blocks, origin, levels, flags, date, century and fst. read returns EBCDIC content unchanged: fixed files are records*record_length bytes with unallocated blocks as zeros; variable files are the 2-byte length-prefixed record stream. Pointer-tree record counts and displacements are verified. Minidisk discovery, CP directory parsing and code page conversion stay in Starlark.

### `filesystem.cms_csllib`

`filesystem.cms_csllib(file, max_entries=16000000, max_bytes=512MiB) -> record`

Decodes a CMS callable services library (CSLLIB). Returns name, date, time, identifiers, header and segments (one module segment per routine, in the cms_module segment shape; each Extra holds the routine's descriptor record, and the final one also holds the library index).

### `filesystem.cms_library`

`filesystem.cms_library(file, max_entries=1000000, max_bytes=512MiB) -> record`

Decodes a CMS LIBPDS library (MACLIB, TXTLIB and other F 80 libraries) from its fixed-format content, such as cms(...).read(index). Returns format, directory_bytes, directory_record, reserved (two header words kept uninterpreted) and entries with name, raw_name, flags, record, records and data. Several entries may name one member (for example TXTLIB entry points); a member ends before the next record beginning with X'61FFFF61'. Member data stays EBCDIC card images. DMSLIB-format TXTLIBs, LOADLIBs and CSLLIBs are rejected.

### `filesystem.cms_loadlib`

`filesystem.cms_loadlib(file, max_entries=1000000, max_bytes=512MiB) -> record`

Decodes a variable-format CMS LOADLIB (OS PDS simulation). Returns directory_bytes, directory_record, header and entries with name, raw_name, alias, record, records, user_data (OS load module attributes) and data (the member's load module records as a 2-byte length-prefixed stream). The directory is read from its own records; record 1's truncated copy is ignored. Members end before the X'61FFFF61' delimiter.

### `filesystem.cms_module`

`filesystem.cms_module(file, record_format='V', max_entries=16000000, max_bytes=512MiB) -> record`

Decodes CMS MODULE content such as cms(...).read(index). Fixed modules are one headerless image. Variable modules return segments, each with header, entry, origin, end, end2, image, loader_table (name, raw_name, words), relocation_count, relocation_width (0, 4 or 5), relocation_data (raw entries), extra (records after the relocation list such as service history, or trailer bytes when there is none), program_object (raw IEWPLMH trailer or None) and trailer. Core-image records must sum exactly to end-origin; further segments (as in CP's CPLOAD) are found structurally. Loader entry size (20 or 24) is chosen by validation and ambiguity is rejected.

### `filesystem.cms_unpack`

`filesystem.cms_unpack(file, record_format='F', max_bytes=256MiB) -> record`

Decodes CMS packed (COPYFILE PACK) content, such as cms(...).read(index), from F 1024 container records (record_format='F') or variable container records (record_format='V'). Returns record_format (F or V), record_length, records, maximum_record and data: fixed records concatenated, or the 2-byte length-prefixed variable stream used by cms read. Verifies the end marker, whole fixed records, LRECL-bounded variable records and that the final container record's tail is blank or repeats the stream 1024 bytes earlier. Unobserved codes are rejected.

### `filesystem.cp_directory`

`filesystem.cp_directory(file, root=0, max_users=100000) -> record`

Reads the z/VM CP object directory (DIRECTXA output) of a CKD volume, by default the active one selected by the VOL1 label (root overrides it with a page pointer: 2-byte cylinder, record, zero). Returns root, header, users, profiles (from the directory header; their devices are owned by SYSTEM) and groups (POSIX GID, name). Each user has name, flags, word (POSIX UID), device_count, block, devices (own), configuration (resolved chain: own then INCLUDEd profile devices), iucv (target, resource, message_limit, priority, ident_flags), namesave, distribution, account, acigroup, include, ipl, password_date, autolog, machine (XA, ESA, XC), nolog, classes (bit 31 = class A), storage_kb, maximum_storage_kb, maxconn, share_absolute, share_relative, posix_uid, posix_gid, posix_group and options (only option bits verified on media). Devices have address, type (X'80' MDISK, X'40' LINK, X'08' unit record, X'10' DEDICATE), owner, start, end, volume, mode, mode_code, password_flags, target_user, target_address, link_mode, device_type, spool_class, real_address and raw. Passwords stay encoded. The root's leaf chain, high keys, device counts, block owners and configuration order are verified; a superseded generation whose pages were reused fails. This is the directory CP runs with, which may differ from USER DIRECT source.

### `filesystem.diskdupe`

`filesystem.diskdupe(file) -> file`

Decodes DiskDupe DDI track maps into a read-only logical disk. Omitted tracks remain unreadable, never zero-filled.

### `filesystem.duplicator`

`filesystem.duplicator(file) -> file`

Decodes version 1 The Duplicator images, including explicit cylinder filler. Cylinder checksums are not verified.

### `filesystem.efs`

`filesystem.efs(file, maximum_entries=1M) -> record`

Reads an IRIX EFS volume into entries and case-sensitive paths, resolving direct and indirect extents without mounting. find(path) returns an entry or None; entries expose data, entry_type, size, inode, mode, uid, gid and modified. Accepts a trimmed free tail only when the allocation bitmap proves the omitted region is free and all referenced extents fit the original input. Symlink data remains the link target and is never followed; device entries have no data.

### `filesystem.ext4`

`filesystem.ext4(file, maximum_entries=100000, maximum_depth=32) -> record`

Reads a clean ext2/3/4 image without mounting. Returns flat entry records with Unix metadata and lazy file data; symbolic links and device nodes are metadata, never followed. Handles multi-level extents, sparse/unwritten ranges, indirect blocks, indexed directories, 64-bit descriptors and metadata checksums. Rejects unsupported incompatible features and images requiring journal replay. Positive entry/depth limits bound traversal.

### `filesystem.ext4_build`

`filesystem.ext4_build(entries, size, label='', uuid='', inode_count=0) -> file`

Builds a sparse ext4 image from Unix entry dictionaries using native 4096-byte blocks, extents and linear directories. Size is explicit and block-aligned; metadata is bounded at 256 MiB. inode_count optionally sets minimum total inode capacity, including reserved inodes, rounded up to block-group geometry; zero sizes from input entries. Larger values reserve free inodes for later guest writes, subject to the metadata and disk-size bounds. Preserves ownership, permissions, links and devices. Images have no journal; file payloads are borrowed immutable readers. UUID is 32 hexadecimal digits; label is at most 16 bytes.

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

### `filesystem.ffs_build`

`filesystem.ffs_build(entries, size=0, extra=0, layout='raw', timestamp=1700000000) -> file`

Builds a sparse FFS1 root from Unix entry dictionaries, preserving ownership, special permissions, symlinks, hardlinks and BSD device numbers. Payload readers are borrowed. Raw layout is for FreeBSD/NetBSD; openbsd adds an MBR and disklabel. Size is filesystem capacity excluding the OpenBSD prefix; zero estimates capacity. Capacity and total file payload are bounded to 32 GiB. No host extraction, mounting or mkfs.

### `filesystem.gpt`

`filesystem.gpt(file) -> parsed GPT; filesystem.gpt(size, disk_guid=...) -> builder`

With a file, parses GPT partition metadata; with a size, creates a partition-table builder. Populate the builder with partition contents to produce a complete disk layout.

### `filesystem.hdcopy`

`filesystem.hdcopy(file) -> file`

Decodes standard and extended HD-Copy images in memory with strict RLE validation. Omitted tracks remain unreadable.

### `filesystem.hfs`

`filesystem.hfs(file, maximum_entries=1M, raw_forks=False) -> record`

Reads classic HFS, HFS+/HFSX and embedded HFS+ volumes without mounting. Returns raw volume name, entries, paths and exact find(path). Entries expose distinct data/resource forks, xattrs, reversible escaped paths, Finder/catalog metadata, Unix modes/uid/gid and link targets. Hardlink inode aliases share decoded inode contents while raw_data/raw_resource retain physical alias forks. Symlinks are not followed. Inline and fork-backed attributes have independent extent-overflow support. Shared decmpfs types 3/4 (inline/resource zlib with stored-block escape) and 9 (stored inline) decode lazily with exact logical lengths and checksums; resource zlib allocations may have unused trailing bytes. Other compression types fail unless raw_forks=True explicitly requests physical forensic forks. compression_type identifies decoded files. Does not mount, repair or execute filesystem contents.

### `filesystem.hfs_build`

`filesystem.hfs_build(entries, size, label="Untitled") -> file`

Builds a bounded unjournaled case-sensitive HFSX version-5 volume natively in memory from UNIX entry dictionaries. size is the volume byte length; payloads are borrowed file/string/bytes values. Entries support path, mode, uid, gid, mtime, data, target, hardlink, major, minor, finder_info (32 bytes), resource, xattrs (name to file/bytes), owner_flags and admin_flags. Preserves regular-file hardlinks through native private inodes; directory hardlinks are unsupported. Paths use POSIX components (colon becomes catalog slash); names use HFS canonical decomposition. Allocation, catalog and attribute trees include free growth nodes with bounded metadata. Does not build partitions, journal, execute guest tools or write intermediate host files.

### `filesystem.host`

`filesystem.host(root, lazy=False) -> host filesystem`

Exposes a host directory through the native filesystem backend. This is a host-path boundary, not an image parser or a portable replacement for an in-memory directory.

### `filesystem.iso9660`

`filesystem.iso9660(file) -> ISO filesystem`

Parses an ISO 9660 or High Sierra filesystem and exposes directory and lazy file views. High Sierra uses case-insensitive names and validates descriptor addresses, both-endian fields and extent bounds. Validated Rock Ridge takes precedence over Joliet, preserving case-sensitive names, POSIX metadata and symbolic-link targets without following links. Joliet and basic ISO names remain available when Rock Ridge is absent. It does not mount or copy the image.

### `filesystem.mbr`

`filesystem.mbr(file) -> parsed MBR; filesystem.mbr(size, boot_code=None, disk_signature=0, chs=None) -> builder`

With a file, parses the MBR and partitions; with a disk size, creates a builder with optional boot code, signature and CHS geometry. Partition payloads remain caller-supplied.

### `filesystem.mds`

`filesystem.mds(file, images={}) -> mds`

Reads Alcohol MDS v1 descriptor metadata, including sessions, track geometry, pregaps, TOC and companion filenames. Optional images maps declared names (including *.mdf) to portable files. Bound tracks expose raw sectors, logical data or audio, and interleaved P-W subchannels without conversion or copying. auto resolves MDF companions from its source tree. The sessions attribute contains tracks and their byte views.

### `filesystem.mtree`

`filesystem.mtree(file, maximum_entries=100000) -> list[record]`

Reads a bounded BSD mtree metadata manifest natively, including /set and /unset defaults, directory descent and parent navigation, full ./ paths, line continuations, comments and octal or common escaped characters. Returns path/attributes records with metadata values preserved as strings, including Apple extensions. Bounds input, logical lines, records, expanded attributes and paths; rejects duplicates, malformed escapes and parent traversal. Does not read the described files, follow links or mutate a filesystem.

### `filesystem.ntfs`

`filesystem.ntfs(source, size=None, boot_code=None, hidden_sectors=0, label='NO NAME', version='1.1', log_file=None, upcase=None, upcase_profile='default')`

Parses an NTFS volume when given a file, or builds one from a directory and size. Construction accepts explicit NTFS generation, boot metadata, log and upcase data so older NT layouts need not inherit modern defaults.

Read-only mounts resolve extension attributes through the base record's
`$ATTRIBUTE_LIST`, matching record sequences, stream names and starting VCNs.
An extension backlink alone does not make its data current. Conflicting
referenced extents remain errors; unreferenced stale records are not merged.

Read-only `volume.metadata(path)` returns `path`, `directory`, `record_number`,
`sequence`, `security_id` and `security_descriptor`. Use the record number with
`filesystem.ntfs_record` to inspect the corresponding base FILE record. Metadata
reads do not flush guest writes or make a paused live volume coherent.

### `filesystem.ntfs_record`

`filesystem.ntfs_record(source, number)`

Inspect one FILE record in a volume file without enumerating its namespace.
The native reader validates volume geometry, MFT bounds, sector fixups and
attribute headers. It does not repair malformed attribute values or follow
extension records. The result exposes `number`, `sequence`, `base_reference`,
`flags`, `cluster_size`, `record_size`, fixed-up `raw` bytes, and `attributes`.
Each attribute has `type`, `name`, `instance`, `flags`, `nonresident`, `size`,
`first_vcn` and `header` bytes. Resident attributes expose `value`; nonresident
ones expose `allocated_size`, `initialized_size` and `runs` containing
`cluster`, `count` and `sparse`. These are individual attribute extents, not
automatically reconstructed streams. This inspection remains usable when an
unrelated invalid attribute list prevents a complete namespace read.

### `filesystem.object_deck`

`filesystem.object_deck(file, max_cards=10000000, max_bytes=256MiB) -> record`

Decodes F 80 object card content (TEXT files, TXTLIB members). Returns symbols (module, name, raw_name, type, id, owner, address, value, flags, extended, kind) from ESD and XSD cards, ends, sections (SD/PC/CM sections assembled from TXT data with a symbol and data file), text_cards, relocations and other_cards (SYM, loader and control cards). TXT and RLD ESDIDs must be defined; ESDIDs restart after each END; XSD long names may span cards.

### `filesystem.ods2`

`filesystem.ods2(file, maximum_entries=1M, maximum_depth=64) -> record`

Reads Files-11 ODS-2 version1 home blocks, index headers and versioned directory trees. Verifies home/header checksums, primary and backup index maps, file identities, allocation bounds, EOF fields, directory records and traversal limits. Returns entries, files, exact-path find(path), raw home bytes and padded volume_name. Entries retain raw names, version, file_number, sequence, header, record_attributes, characteristics, data and size. Names include ;version, with unsafe bytes percent-escaped; the root self-reference is a directory_link and is not followed. Data is a borrowed read-only extent view; RMS records are not translated and allocation slack is excluded. Supports retrieval formats1/2/3. Extension chains, placement-control pointers, alternate-volume resolution and other ODS generations remain explicit gaps. Opening an ODS-2 view does not validate any enclosing CD-image trailer or decode nested backup savesets.

### `filesystem.openbsd_label`

`filesystem.openbsd_label(file, label_offset=512) -> record`

Reads a version-1 OpenBSD or legacy version-0 BSD disklabel at label_offset, an explicit byte offset in the complete disk. The default 512 is the common standalone amd64 label location; for an MBR image pass the OpenBSD partition offset plus 512. Validates both magic values, XOR checksum, partition count, 48-bit sector addresses, declared disk/partition bounds and FFS geometry. Legacy labels use 32-bit sector addresses and explicit fragment geometry rather than the OpenBSD packed fields. Sector size is declared by the label, including 4096-byte sectors. Returns sector_size, total_sectors, bound_start, bound_end, uid, type_name, pack_name and partitions. Partitions preserve index, a-z/A-Z name, absolute start_sector, sectors, type, block_size, fragment_size, cylinders_per_group and borrowed read-only data. Empty slots have data=None; overlapping raw c remains present. Requires the complete declared disk; does not guess offsets, mount, repair, construct images or accept other disklabel versions.

### `filesystem.program_object`

`filesystem.program_object(file) -> file`

Validates a stored binder program object (IEWPLMH versions 2-5), such as a CMS module segment's program_object, and returns it as a file. Version 1 objects are rejected.

### `filesystem.raw_cd`

`filesystem.raw_cd(file) -> file`

Views a single-track 2352-byte or 2448-byte raw CD as logical 2048-byte sectors. Supports ISO9660 and High Sierra in Mode 1 and Mode 2 Form 1, preserving the source without conversion or mounting.

### `filesystem.sgi`

`filesystem.sgi(file) -> record`

Validates an SGI volume-header checksum and returns partition and boot-directory file views. Partitions expose index, partition_type, start_block, blocks, data and complete; addresses are 512-byte basic blocks. A whole-volume descriptor may exceed a CD image: its declared blocks are retained, data covers only available bytes, and complete is false. Filesystem partitions and boot files must fit in full. Does not infer an inner filesystem from a filename.

### `filesystem.udf`

`filesystem.udf(file) -> UDF filesystem`

Parses a UDF filesystem into directory and file views. Symbolic links expose decoded targets and metadata rather than encoded payloads; they are not followed. Reads resolve the filesystem's on-disk structures without mounting it.

### `filesystem.ufs`

`filesystem.ufs(file, maximum_entries=1M, maximum_blocks=1M) -> record`

Reads historical and 4.4BSD UFS1, UFS2 and NetBSD UFS2EA in either byte order, checking superblocks at byte8192 or byte65536. UFS2 uses 256-byte inodes and 64-bit pointers; UFS1 uses 128-byte inodes and 32-bit pointers. The declared inode format selects old 16-bit ownership/16-bit directory name lengths or modern 32-bit ownership/typed directories and inline symlinks. Checks fragment/cylinder-group geometry, inode and data ranges, 512-byte directory records, dot entries, directory type/inode agreement, duplicate names and directory cycles. Returns entries, paths, find(path), block_size, fragment_size, groups and inode_format. Entries preserve inode identity, mode, link count, ownership, timestamps, flags, device number and borrowed data views. Reads 12 direct blocks and single/double/triple indirect pointers; zero pointers remain sparse zeroes. maximum_blocks bounds mapping work; maximum_entries bounds reachable paths. Hard-linked files share data, symlinks are not followed and device nodes are metadata only. Unknown inode formats, extended-attribute enumeration and journal replay remain unsupported. filesystem.ffs_build separately constructs FFS1 roots. Nested archives require separate decoders.

### `filesystem.ultrix_label`

`filesystem.ultrix_label(file) -> record`

Reads the eight-slot DEC/Ultrix disk label at byte16312, validating magic, active-table flag, signed 512-byte sector geometry and nonempty partition bounds. Returns block_size=512 and partitions with index, conventional a-h name, start_block, blocks and borrowed data. Empty slots remain present with data=None. Overlaps are preserved because the whole-disk slot overlaps individual filesystems; no partition is silently selected or treated as a duplicate. The label has no checksum or filesystem-type field, so inspect each selected partition with its own format reader. Does not scan for alternate labels, mount filesystems or execute boot code.

### `filesystem.vhdx`

`filesystem.vhdx(file) -> VHDX disk`

Parses a VHDX container and exposes its logical disk contents. This unwraps the virtual-disk format; parse the returned disk's partitions/filesystems separately.

### `filesystem.xfs`

`filesystem.xfs(file, maximum_entries=1M, realtime_file=None) -> record`

Reads version-4 and checksum-protected version-5 XFS directory trees using borrowed local, extent-list and multi-level bmap-btree views. Checks levels, key ranges, sibling links, cycles and extent counts; sparse and unwritten data reads as zeros. Version-5 superblocks, v3 inodes, BMA3 trees and directory blocks validate CRC32C, metadata UUID, owner and physical address. Supports directory formats 1/2/3 and file-type extensions. realtime_file explicitly supplies the separate realtime device. Returns entries, paths and find(path); symlinks are never followed. Does not mount, replay logs, repair or build filesystems, decode attribute forks, or accept unsupported incompatible features such as bigtime and large-extent-count layouts.

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

### `image.decode`

`image.decode(source, maximum=128MiB, max_pixels=16MiP) -> record`

Decodes one bounded immutable image snapshot with width, height, pixels, format and pixel(x,y). Repeated snapshot pixel reads never reopen or redecode the source. Useful for glyph and framebuffer probes; encoded input and decoded pixel limits apply.

### `image.info`

`image.info(source, maximum=128MiB, max_pixels=16MiP) -> record`

Decodes image metadata and returns dimensions and format information within input and pixel-count bounds.

### `image.pixel`

`image.pixel(source, x, y, maximum=128MiB, max_pixels=16MiP) -> record`

Returns the color of one decoded image pixel at x,y. Coordinates must be inside the image; input size and decoded pixel limits apply.

### `image.sample`

`image.sample(source, points, maximum=128MiB, max_pixels=16MiP) -> list[record]`

Decodes the source once per call and returns r/g/b/a color records in point order, using the same 8-bit alpha-premultiplied channels as image.pixel. points must be a list or tuple of (x,y) lists or tuples with integer coordinates inside the image; duplicate points are preserved. maximum bounds encoded bytes; max_pixels bounds both decoded image pixels and point count. An empty selection returns an empty list after validating the image. No decoded image is cached between calls.

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

### `renvo.archiver`

`renvo.archiver(index=False) -> shell_command`

Creates an in-process archive command capability. index=True supplies ranlib-style arguments; index=False accepts ar-style arguments. Inputs and outputs remain in the invoking Unix filesystem.

### `renvo.cc`

`renvo.cc(source, input, target, flags=[], arena_size=32MiB) -> compiledModule; input is a virtual source path or list of paths`

Compiles virtual C/C++ sources with the in-process Renvo toolchain for the selected target. Returns a compiledModule containing success/diagnostic information and virtual output bytes.

### `renvo.compiler`

`renvo.compiler(target, arena_size=32MiB) -> shell_command`

Creates an in-process C compiler command capability. The recipe installs and binds its guest path. Invocation arguments, working directory, input and output all use the shell-owned Unix filesystem and streams; no host compiler is invoked.

### `renvo.go`

`renvo.go(source, input, target, arena_size=32MiB) -> compiledModule`

Compiles a virtual Go source tree with Renvo for the selected target. Returns compilation status and outputs without invoking a host Go compiler.

### `renvo.headers`

`renvo.headers() -> directory`

Exposes bundled libc headers as portable directory files. Requires renvo_bundle; does not install or overwrite files. The recipe chooses where and with which modes to provision them.

### `renvo.linker`

`renvo.linker(target, arena_size=32MiB) -> shell_command`

Creates a portable Renvo linker command capability, without installing an executable or choosing its guest path. Writes outputs into the invoking shell filesystem.

### `renvo.make`

`renvo.make(source, target, input='Makefile', targets=[], output='', arena_size=32MiB) -> compiledModule; rebuilds Renvo recipes in memory; output selects the binary by virtual path relative to the Makefile`

Evaluates supported Renvo make recipes against a virtual source tree and rebuilds their outputs in memory. output selects the desired binary relative to the Makefile; no host make process is launched.

### `rfe.backend`

`rfe.backend(overlay_limit=268435456) -> vmm_backend`

Creates an experimental in-process software x86 PC backend from Renvo x86.rfe. JIT-compiles hot 16-, 32- and 64-bit code using Renvo native blocks, without KVM or QEMU. Requires a supported 64-bit native-JIT host; unavailable executable memory is an error. Privileged/device/unsupported instructions use precise architectural slow paths. Shares BIOS, IDE, VGA, input and overlays with cc. MS-DOS 6.22 startup, Windows 3.11 standard/enhanced-mode Notepad, and Windows 98 SE Explorer/Notepad are verified. The graphical smokes verify keyboard input, PS/2 mouse-selected Save and changed bytes on the guest disk. Enhanced-mode paging and actual native-tier retirement are explicitly asserted. Implements basic x87, string port I/O, paging and protected/v8086 gates; parts of x87 and other legacy CPU/device features remain incomplete. overlay_limit bounds dirty snapshot memory in bytes. Inspect with vm.extension("rfe.v1").state().

### `runtime.heap_profile`

`runtime.heap_profile(limit=20, order_by='sampled_bytes') -> record`

Returns a bounded read-only snapshot of the running Go allocation sampler, not a per-recipe ownership graph. limit defaults to 20 and must be 1..100. Returns sample_rate_bytes, total sampled_bytes/sampled_objects, stack_count, and entries ordered by retained sampled bytes. Each entry has sampled_bytes, sampled_objects and stack frames (function, line); paths and addresses are omitted. Raw counts are unscaled samples. Additional estimated_bytes/estimated_objects fields on entries and totals apply the inverse sampling probability from mean sampled object size; these are statistical estimates, not exact ownership measurements. order_by accepts sampled_bytes (default) or estimated_bytes. Counts and estimates may lag up to two GC cycles. Does not force collection or change sampling, GC policy, memory limits or guest timing. Bounds stack inventory to 1048576 and retries a changing inventory at most three times; failure returns no partial snapshot.

### `runtime.host_memory`

`runtime.host_memory(pid=current_process) -> record`

Read-only native host diagnostic snapshot: platform, pid, files and errors. On Linux reads fixed procfs status/stat/meminfo/vmstat/cgroup paths for the positive 32-bit pid (default this process) and memory counters at the mounted /sys/fs/cgroup root and up to 16 process-membership ancestors, bounded to 64 KiB per file; each failure is explicit. Raw texts permit bounded policy-side inspection without host tools. The mounted cgroup root need not be the process leaf; consult membership before interpreting scope. Samples are not atomic, PIDs may be reused, counters are cumulative, and an OOM increment alone does not identify its victim. Other platforms return empty files/errors. Does not change limits, collect garbage, reserve memory or launch processes.

### `runtime.release_memory`

`runtime.release_memory() -> None`

Explicitly runs a process-wide Go garbage collection and requests that unused heap pages be returned to the operating system. Drop unneeded construction references before calling it at a phase boundary. Reachable readers, caches and guest resources are not closed or evicted. Does not change GC policy or the memory limit and does not guarantee an RSS reduction or a hard memory bound. May pause concurrent work; include its elapsed time in end-to-end measurements.

### `runtime.set_memory_limit`

`runtime.set_memory_limit(bytes) -> int`

Explicitly sets the process-wide Go soft memory limit and returns the previous limit in bytes. The positive limit applies to Go-managed memory, not guest RAM mappings, other native allocations, or other processes. Set an appropriate budget at construction/boot phase boundaries; restore the returned value when done. This is not a reservation or hard RSS bound, cannot reclaim reachable data, and may cause severe GC overhead below the live working set. Affects concurrent work in the same process; use only when the caller owns process memory policy.

### `runtime.stats`

`runtime.stats() -> record`

Returns a snapshot of runtime resource statistics for diagnostics and benchmarking. Counters describe the running runtime, not just one image recipe. Includes heap allocation/goal, in-use/idle/released heap pages, stack and runtime metadata reservations, the configured soft memory limit, cumulative GC cycles and stop-the-world pause nanoseconds, and cumulative GC/runtime available CPU seconds. CPU seconds are runtime-wide capacity-accounting counters, not elapsed time or per-recipe work; compare snapshots rather than interpreting totals as a critical path. Observes configuration only; does not change GC policy, memory limits or guest clocks.

### `scs.create`

`scs.create(path) -> scs.repository`

Creates a new exclusively locked native SCSREPO3 repository file without overwriting existing data. File paths and durability are native backend authority; stored contents use the portable SCS engine. Repositories close at execution teardown or explicit close. See docs/scs.md for publication, Git cloning and limits.

### `scs.memory`

`scs.memory(file=None, max_bytes=512MiB) -> scs.repository`

Creates a bounded volatile SCSREPO3 repository, or reopens an existing portable repository file into independent paged memory. Defaults to 512 MiB of addressable storage, not a total-process memory quota. Published roots can be preserved as a standalone file via repository.file(); Sync does not make memory survive process exit.

### `scs.open`

`scs.open(path) -> scs.repository`

Opens a native SCSREPO2/3 repository with exclusive ownership. Paged indexes load lazily and are verified as accessed. Opening may repair an incomplete tail; it is not a forensic read-only operation. Complete corruption fails rather than being silently discarded.

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

### `vmm.arm64_boot`

`vmm.arm64_boot(image, address, memory_base, entry=None, registers=None, system=None) -> vmm_arm64_boot`

Creates a board-independent ARM64 handoff with explicit physical RAM base, image address, entry point and optional X0-X30/system registers. It contains no devices, firmware commands, NVRAM or board selection. Generic validation checks load ranges and instruction alignment; native backends separately enforce host-page constraints. Compose hardware with vmm.arm64_platform and pass it independently to vmm.machine. Native cc currently provides one CPU and headless execution; stopped cc.v1 exposes bounded read_physical and read_virtual until VM close.

### `vmm.arm64_platform`

`vmm.arm64_platform(create, gic_distributor=0, gic_redistributor=0) -> vmm_arm64_platform`

Composes ARM64 hardware independently of CPU/load state. create(ctx) runs once per VM and returns a dictionary with devices (ordered MMIO/native device values) and optional hvc(immediate,function)->bool. Each factory must create fresh mutable state. Earlier devices win overlapping address ranges; unknown MMIO and unhandled HVC remain unsupported exits. Optional GIC distributor/redistributor addresses are explicit and must be distinct 64 KiB-aligned values. Factory and MMIO/HVC callbacks run serially on one VM-owned Starlark thread, canceled when the VM stops. Runtime operations reject calls from any other Starlark thread. The runtime supplies bounded guest-memory access, permission-enforcing DMA, memory protection, registers, counter/epoch, IRQs, disk resources, events and native protocol construction. Native device instances cannot be shared across VMs; unused or failed-factory native devices are closed. No host paths, sockets or processes are exposed.

### `vmm.backends`

`vmm.backends()`

Lists the VMM backends registered in this runtime and their advertised capabilities. Availability depends on the runtime's backend implementations.

### `vmm.channel`

`vmm.channel(kind, name, required=True)`

Describes a named VM byte channel of the requested kind. required determines whether lack of backend support is a validation failure.

### `vmm.darwin_arm64_boot`

`vmm.darwin_arm64_boot(kernel, device_tree, memory, memory_base, virtual_base, command_line='-v', entropy=None, payloads=None, nvram=None) -> vmm_arm64_boot`

Constructs a board-independent unslid ARM64 executable/fileset handoff in memory from a decoded Mach-O kernel and flattened Apple device tree. Loads bounded nonoverlapping segments, zeroes BSS, appends ARM64 revision-2 bootargs, chosen DRAM ranges, a random-seed and device-tree memory-map ranges, and enters the original thread PC with X0 pointing to bootargs. Physical and virtual bases are required explicit arguments; RAM bases and size must be 32 MiB aligned. The machine memory must equal the encoded memory value. payloads maps memory-map names to immutable files loaded separately at 16 KiB aligned addresses and reserved through topOfKernelData. TrustCache is placed below the kernel inside its protected range; RAMDisk can contain an original APFS image. nvram optionally maps string variable names to string values in a fresh volatile CHRP bank; the bytes seed the chosen proxy and are returned as boot.nvram for explicit recipe-owned device backing. Unqualified names and the 7C436110-AB2A-4BBB-A880-FE41995C9F82: prefix select common; the 40A0DDD2-77F8-4392-B4A3-1E7304206516: prefix selects system and is needed for system variables such as boot-args. None preserves a supplied proxy with matching bank geometry or creates an empty bank. XNU performs its own fileset rebasing/signing. entropy=None generates 256 fresh cryptographic bytes for modern XNU; an explicit entropy value must be 64 bytes (earlier XNU) or 256 bytes with nonzero data. Returned read_only_address/read_only_size describe the immutable kernel prefix for optional platform protection configuration. No hardware platform is selected. Does not personalize IMG4 or imply a successful kernel boot. Public HVF rejects Apple PAC initialization; the native cc private_apple_isa option selects ISA level 3 with a separately entitled executable.

### `vmm.darwin_boot`

`vmm.darwin_boot(kernel, command_line='', smc_osk=b'') -> vmm_darwin_boot`

Creates an unslid amd64 XNU v2 direct handoff from an immutable original kernelcache or Mach-O executable. Supports amd64 fat slices and Apple comp/lzss caches with checksum validation. Native cc requires Linux/amd64 KVM, x86_64 and no UEFI image execution; QEMU rejects this intent. No guest bootloader is executed or kernel instructions patched. RAM disks are not supported. Optional smc_osk must be empty or exactly 64 bytes; it is explicit caller-supplied SMC material, never bundled or logged. Native cc exposes SMC APP0001/IRQ6 and omits OSK0/OSK1 when no material is supplied. Verified scope is Lion HFS-root boot to launchd and a visible single-user shell, not keyboard input, a desktop or a complete installation.

### `vmm.darwin_nvram`

`vmm.darwin_nvram(values) -> bytes`

Encodes string variable names/values into one volatile 8 KiB CHRP NVRAM bank. Unqualified names select Apple common; explicit Apple common/system GUID prefixes select their corresponding partitions. Returns immutable bytes for a caller-owned backing layout. This is format construction only and never accesses host firmware.

### `vmm.disk`

`vmm.disk(source, name='disk0', bus='auto', media='disk', unit=-1, chs=None, read_only=None, snapshot=False, required=True)`

Describes a guest disk or optical medium backed by a file or block device, including bus, unit and write/snapshot policy. It does not boot or materialize the source.

### `vmm.display`

`vmm.display(mode, required=True)`

Describes the requested guest display mode and whether support is mandatory. This is part of a portable machine specification.

### `vmm.linux_boot`

`vmm.linux_boot(kernel, initramfs=None, command_line='')`

Creates portable direct Linux boot intent from borrowed immutable kernel and optional initramfs files plus a command line. Requires backend boot.linux capability; QEMU supports Linux hosts and x86 guests using anonymous inherited descriptors.

### `vmm.machine`

`vmm.machine(architecture, memory, cpus=1, disks=[], networks=[], display=vmm.display('none'), channels=[], start_paused=False, required_capabilities=[], boot=None, platform=None)`

Creates a portable machine specification from architecture, memory, CPUs, storage, networking and channels. It does not start a VM.

### `vmm.mmio`

`vmm.mmio(address, size, read=None, write=None, widths=[1,2,4,8]) -> vmm_arm64_device`

Creates a guest MMIO region with explicit address/size, optional read(offset,size)->uint and write(offset,size,value)->None callbacks, and access widths (default 1,2,4,8). Reads/writes must be aligned to their width and fit entirely inside the region; read results must fit the requested width. Add the value to an ARM64 platform factory result. Mutable callback state should be created inside that factory. A missing callback fails explicitly. This primitive does not allocate RAM or select hardware.

### `vmm.network`

`vmm.network(kind, name='net0', required=True, switch=None, mac='')`

Describes a named guest network connection and whether its requested kind is required. The selected backend implements the transport.

### `vmm.start`

`vmm.start(machine, backend)`

Validates a machine specification against a backend and starts a VM. Returns the live VM handle used for input, screenshots, events and lifecycle control.

### `vmm.switch`

`vmm.switch()`

Creates an isolated in-memory Ethernet switch. internet=True explicitly requests a single-guest IPv4 TCP/DNS gateway and requires trex -allow-internet; mac defaults to 02:54:52:00:00:01 and must match the guest. Private/LAN destinations, IPv6 and general UDP are not forwarded. Attach guests with vmm.network('ethernet', switch=lan, mac='02:00:00:00:00:01'), using a distinct unicast MAC for each NIC. Ports have bounded receive queues and disconnect when their VM closes.

### `vmm.validate`

`vmm.validate(machine, backend)`

Checks whether a backend can implement a machine specification and its required capabilities without launching it. Use this before committing to a boot experiment.

### `vmm.workspace`

`vmm.workspace(vms, create=None)`

Groups a name-to-VM dictionary for the browser frontend; it may start empty. add(name, vm) registers a display and returns a never-reused ID; remove(id) unregisters without closing the VM. The optional zero-argument create callback returns (name, vm); calls are serialized and successful creations appear as new tabs. Switching tabs leaves every VM running. Guest construction and provisioning remain recipe-owned.

### `web.application`

`web.application(handler, consoles=None, public=[], origin='') -> application`

Composes a scripted request handler with optional dynamically registered VM consoles and native session authentication. Public GET/HEAD asset paths are explicit; other requests require a token, and mutations require same-origin checks. The HTTP listener permits loopback or an exact IP assigned to the local Tailscale tunnel; wildcard and LAN binds are rejected. An explicit HTTPS origin supports a trusted reverse proxy without trusting forwarded headers.

### `web.browse`

`web.browse(root, request, path='') -> response`

Resolves a recursive path against an auto view. Optional path mounts a tree under a script-owned route prefix. json=1 returns entry metadata and paginated children; raw responses use the existing file range handling. Returns structured HTTP errors for missing, malformed and bounded-out inputs.

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

### `windows.acl_entries`

`windows.acl_entries(source) -> dict`

Validates a complete revision-2/4 Windows ACL (at most 65,535 bytes), returning `revision` and `entries`. Every entry contains `type`, `flags` and its original `data` bytes. Simple allow, deny, audit, alarm, mandatory-label and callback-allow entries also contain a checked binary `sid` and numeric `mask`. Callback application bytes remain in `data` after the SID; other entry layouts retain opaque bytes with `sid` and `mask` set to `None`. Unused ACL allocation space is allowed. This inspects the format; it neither evaluates access nor resolves principals through the host.

### `windows.acme_plan`

`windows.acme_plan(table, inf, media, target="", system_root="C:\\WINDOWS", root="", predicates=None) -> dict`

Joins an ACME STF object graph with its INF file catalogue and portable media files. Unknown choices and runtime destinations remain explicit; no installer code is executed.

### `windows.acme_table`

`windows.acme_table(file) -> dict`

Parses an ACME setup table into headers, objects, arguments, annotations, and source provenance.

### `windows.ad_ancestors`

`windows.ad_ancestors(tags) -> bytes`

Encodes a root-to-object path of 1..1024 nonzero, distinct directory name tags as little-endian DWORDs.

### `windows.ad_legacy_dn_binary`

`windows.ad_legacy_dn_binary(tag, value) -> bytes`

Encodes a Windows 2000 non-linked DN-Binary value from a nonzero directory name tag and opaque binary payload.

### `windows.ad_legacy_pek_list`

`windows.ad_legacy_pek_list(boot_key, key, salt, generated) -> bytes`

Builds an encrypted revision-2 AD password encryption key list containing key zero. boot_key, key and salt are 16-byte values; generated is a Windows FILETIME. The caller supplies key and salt bytes.

### `windows.ad_legacy_secret`

`windows.ad_legacy_secret(secret, key, salt) -> bytes`

Wraps a nonempty secret with the Windows 2000 AD RC4-with-salt format using PEK zero. key and salt must each contain 16 bytes. Password hashes require RID-based DES protection before this outer layer.

### `windows.ad_replication_metadata`

`windows.ad_replication_metadata(attributes, invocation_id, changed, usn) -> bytes`

Builds initial version-one attribute replication metadata in attribute-ID order. invocation_id uses Windows GUID byte order; changed uses the target directory generation's persisted timestamp. Local and originating USNs equal usn. Duplicate attribute IDs are rejected.

### `windows.ad_replication_schedule`

`windows.ad_replication_schedule(hours) -> bytes`

Builds a SCHEDULE_INTERVAL record from 168 hourly bytes, starting Sunday at 00:00 UTC. Each byte contains four quarter-hour availability bits; upper bits must be zero.

### `windows.ad_stored_sid`

`windows.ad_stored_sid(sid) -> bytes`

Converts a wire-format SID to AD's stored form by reversing only the final subauthority's byte order.

### `windows.api_set_namespace`

`windows.api_set_namespace(data=None, file=None) -> namespace`

Decodes a raw v6 API-set namespace (.apiset section bytes or a file slice), limited to 16 MiB. Accepts exactly one positional/data or file argument. Also supports the immutable inspection mapping keys version, flags, hash_factor and contracts (with ordered alias/host dictionaries), and a contracts attribute. Returns version, flags, hash_factor, entries and resolve(contract, importer=""). Entries preserve flags, UTF-16 hashed_length and ordered importer/host records. resolve uses the validated hashed prefix excluding the final revision, then selects an exact importer override or value-zero fallback; it does not guess nearest versions. Names are bounded ASCII UTF-16 module basenames; unresolved or empty hosts return None. Rejects unsupported versions, malformed offsets/counts/names, duplicate contracts/importers and ambiguous or inconsistent hash indexes. The result owns its parsed data. Does not load DLLs, invent hosts, initialize modules, implement their exports or confer trust.

### `windows.appx_package_acl`

`windows.appx_package_acl(parent, family, kind='root', framework=False) -> bytes`

Constructs identity-scoped WindowsApps package DACLs from a native parent DACL. family is a package family name; kind is root, directory or file. By default adds conditional Users execute access bound to WIN://SYSAPPID, the derived family capability SID and Users read access. framework=True instead adds native shared-framework read/execute grants for both AppContainer groups and Users. Both policies inherit parent grants. Unsupported inheritable ACE types/flags and missing inherited grants fail closed. Does not construct an owner/SACL or register packages. No host security APIs.

### `windows.appx_signature`

`windows.appx_signature(file) -> record`

Verifies single-signer RSA/SHA-256 APPX/MSIX package integrity, all AXPC/AXCD/AXCT/AXBM and optional AXCI digest domains, and recognized RFC3161 timestamp integrity. Returns the same signature metadata as pe_signature. Supports bounded single-disk, comment-free ZIP/ZIP64 packages with a final signature entry; rejects unsupported layouts and bundles. Input limit 64 MiB, signature 4 MiB, footprint 16 MiB, 4096 entries. Does not establish publisher, chain, expiry or revocation trust. No host tools, roots, clock or network.

### `windows.assembly_declarations`

`windows.assembly_declarations(root) -> record`

Extracts ordered raw assembly declarations in one traversal of a binary.xml_node root. Returns a frozen record with architectures, files, directories, security_definitions, memberships and managed_assembly. Recognizes asm.v1/asm.v3 only and ignores foreign namespace nodes. Preserves duplicates, qualified attributes, absent versus empty values, unknown directory children, link content presence, and security references for caller validation. Bounds extraction to 1,048,576 visited nodes/attributes. This is not macro expansion, path validation, precedence, security resolution, installation policy or authenticity verification.

### `windows.assembly_manifest`

`windows.assembly_manifest(value) -> assembly_manifest`

Parses an assembly manifest XML value into identity attribute records and declared file records, including hashes and hash algorithms. Each file also has digest=None or the declared nested XMLDSIG record (algorithm, transforms, value); unsupported algorithms/transforms are retained for inspection, not treated as verified. The registry_keys list retains every declared key path, including empty CBS index keys, independently of values. References also retain dependency_type, resource_type, qualified attributes and binding_redirects. deployment is the root deployment attribute list, or None when absent; impact is preserved without inferring installation. top_level and file_elements are deduplicated local element names for conservative presence filtering (assembly children and direct file children respectively); namespace and attribute validation still belongs to the consumer. It does not install a side-by-side assembly or verify those hashes. Returns a lazy assembly_manifest view over an owned parse. Each call owns its projected mutable lists; fields materialize on first access. Freezing the view also freezes fields materialized later.

### `windows.assembly_registry_data`

`windows.assembly_registry_data(value_type, value, variables=None) -> value`

Decodes CBS manifest text into native hive-writer values. Multi-strings use strict comma-separated quoted fields when the first character
is a quote; otherwise the entire text is one string, including commas and whitespace.
There is no CSV quote escaping or separator whitespace trimming. Backslashes
are literal and empty quoted entries contribute no strings. This decodes data,
not registry contribution/merge operations. QWORDs accept either
eight little-endian hexadecimal bytes or a `0x` numeric literal. Binary and resource-list data remain bytes. REG_NONE declaration text is ignored
and decodes to empty bytes (including macro-like text). Eight-hex-digit numeric types (for example
`FFFF0012` or `00040007`) decode hexadecimal data to raw bytes; the native hive
writer accepts these type spellings and preserves all 32 type bits unchanged.
Optional string `variables` expand named
`$(name)` macros case-insensitively in one pass; unknown used macros are errors.
Environment-variable strings are unchanged. Runtime path policy is supplied
by the image recipe, not inferred from the host.

### `windows.assign_registry_security`

`windows.assign_registry_security(current, request, security_information) -> bytes`

Constructs the bounded registry setter result from current/request descriptor bytes and explicit security_information. Requires owner, group, DACL and audit SACL with matching protection flags; optional LABEL replaces mandatory labels, otherwise current labels survive. Maps effective key rights (kernel execute 0x20039), preserves inherit-only generics and duplicate ACEs, consumes AR, and emits a present-NULL empty SACL. Unsupported controls, ACE categories and multiple labels fail closed. Does not create keys, inherit from parents, authorize the subject, propagate to descendants or write hives.

### `windows.batch_plan`

`windows.batch_plan(script, media, variables=None) -> dict`

Inspects DOS batch commands and COPY source declarations using portable media files. Labels, branches, media selection, and external commands remain explicit runtime dependencies; it does not execute the script.

### `windows.bitmap_info`

`windows.bitmap_info(header) -> dict`

Parses the first 40 bytes of an uncompressed 24/32-bit RGB Windows BITMAPINFOHEADER. Returns width, absolute height, depth, DWORD-aligned stride, pixel size, and top_down. Does not allocate pixels or access a display.

### `windows.catalog`

`windows.catalog(file) -> file`

Owns at most 64 MiB of catalog bytes and parses its CTL index once, returning a read-only file. Reapplying catalog to that handle returns the same handle. catalog_index reuses the native index; catalog_signature lazily memoizes cryptographic content/signature/timestamp integrity on these exact bytes, returning independent projections. This is not certificate-chain, revocation, expiry, publisher or timestamp-authority trust. Callers must validate trust against the exact trust store and policy; no trust result is cached.

### `windows.catalog_attributes`

`windows.catalog_attributes(file) -> list`

Parses ordered catalog-level CTL extensions from PKCS#7/CMS catalogs (64 MiB limit). Returns oid, critical, name_value, name, flags and raw value bytes. SPC name/value names are BMPStrings; flags and value bytes are preserved. Unknown extension OIDs remain opaque, duplicates remain distinct, and member/signer attributes are not enumerated. This is neither signature verification nor a trust decision.

### `windows.catalog_entries`

`windows.catalog_entries(file, name_value=None) -> dict`

Returns version (1 or 2) and ordered CTL entries with subject, lookup digest and ordered attributes. SPC name/value attributes expose name, flags and exact value bytes; unknown values retain their DER. Member attributes are never taken from global extensions or signer metadata. name_value optionally selects SPC name/value attributes by lowercase name and omits entries without matches, preserving order and duplicates; the complete catalog is still parsed and validated before filtering. Bounded to 64 MiB; malformed input fails. Parsing is not signature verification, path validation or a trust verdict.

### `windows.catalog_hash`

`windows.catalog_hash(file, algorithm='sha1')`

Computes the Windows catalog membership hash of a file. For PE inputs this uses the format's Authenticode hashing rules rather than a plain whole-file digest.

### `windows.catalog_index`

`windows.catalog_index(file) -> dict`

Parses signed-catalog CTL lookup entries into `sha1` and `sha256` byte lists. Version 1 uses SPC indirect-data digests; version 2 uses subject identifiers. Unrelated certificate/attribute octet strings are not treated as entries. Input is bounded to 64 MiB and malformed catalogs fail. These are catalog lookup keys, not signature verification or trust decisions. No network access or Windows API is used. An input from windows.catalog reuses its owned parsed index, but every call returns independent mutable digest lists.

### `windows.catalog_members`

`windows.catalog_members(value)`

Reads a PKCS#7 catalog and returns its member digest byte strings. Extracting membership does not verify the catalog signature or establish certificate trust.

### `windows.catalog_sign`

`windows.catalog_sign(members, identity, created_at, os_attributes="") -> bytes`

Builds a native RSA/SHA-256 signed CTL catalog from a dictionary of simple filenames to files or bytes. PE members use the catalog image digest; ordinary files use their full byte digest. Includes File, SIP member information, and optional OSAttr attributes. Creation time is explicit Unix seconds. Supports 1–4096 members, at most 64 MiB each and 256 MiB total. Returns bytes; does not install trust or change guest signing policy.

### `windows.catalog_signature`

`windows.catalog_signature(file) -> record`

Verifies single-signer RSA/SHA-256 Windows catalog SignedData integrity and recognized Microsoft RFC3161 timestamps. Supports directly carried PKCS#7 CTLs and CMS OCTET STRING encapsulation with distinct signed hash domains. Returns the same signer, certificates, signature, unsigned_attributes, timestamp and digest_algorithm fields as pe_signature. Requires a parseable catalog membership index, bounds input to 64 MiB and certificate count to 32. Does not establish certificate-chain, revocation, publisher or Windows trust-provider policy. No host roots, clock or network are consulted.

### `windows.cbs_component_owners`

`windows.cbs_component_owners(installed, pinned, changes) -> record`

Reduces explicit component-analyzer owner changes for one resolved version. installed and pinned are lists of dict(source=string_or_None, elevation=int); changes adds action=pin, unpin, install or uninstall and requires a string source. None is a native RTM placeholder, distinct from an empty string. Source names are case-sensitive; elevation is part of owner identity. Pass the complete ordered transaction prefix against the original baseline: identical source/elevation/action events are deduplicated in first-seen order, not replayed. Additions preserve existing owners; removal requires the exact source/elevation or consumes one anonymous RTM placeholder, otherwise fails. Returns a record with installed and pinned lists of source/elevation dicts; only installed elevations feed cbs_update_index.with_components. No inventory loading, RTM synthesis, package scheduling, winner selection or registry writes. Bounds: 1048576 combined owners/events, 64 KiB per source and 64 MiB combined source text. Unknown actions/elevations, malformed text, or missing removals fail with no partial result.

### `windows.cbs_deployment_source`

`windows.cbs_deployment_source(data) -> record`

Decodes a bounded native two-length canonical CSI CBS source payload. Returns package, update, primary, opaque secondary bytes and source_key. Secondary data does not participate in source identity. Validates framing before slicing; inspection does not imply activation or interpret secondary bytes as an elevation.

### `windows.cbs_deployment_source_data`

`windows.cbs_deployment_source_data(manifest, update) -> bytes`

Serializes a native two-length CBS deployment source payload from an exact package manifest and update name. The manifest may be a file, string or bytes, bounded at 64 MiB. Preserves the declared update spelling. Secondary bytes encode the first applicable updateComponent analyzer flags as decimal: the elevation mask plus bit 0 for multiple assemblyIdentity targets; absent analyzer entries yield empty secondary data. Direct updateComponent declarations precede nested applicability groups, independently of XML interleaving. Selectability does not supply source flags. Unknown elevations and missing or ambiguous updates fail. This formats data only; it does not install, stage, write state or replace existing opaque source payloads.

### `windows.cbs_manifest`

`windows.cbs_manifest(manifest) -> immutable parsed CBS manifest`

Parses one CBS MUM into an immutable reusable value (32 MiB maximum). Accepted wherever CBS parent queries, update indexes, package-owner planning or deployment-source encoding accept a manifest. Reuses parsing only: comparison descriptors, candidates, intended states and aggregate byte bounds are still evaluated per call. Identity-validated update metadata files reuse their owned parse without rereading XML. No global cache, file writes or servicing effects.

### `windows.cbs_package_owners`

`windows.cbs_package_owners(packages, targets, editions=[]) -> list`

Plans package-reference owner intents without modifying an image. packages is a list of dicts with manifest (file or bytes), intended_state (0x40 staged, 0x50 superseded or 0x70 installed), optional parents (resolved canonical package identity strings) and choices (update-name to boolean selectable overrides). targets is an explicit list of selected canonical package identities; every target and parent needs a package context. Returns sorted records with package, owner, integration, state and value (integration shifted 16 bits plus state). Local update names and parent-package scopes remain separate; repeated detectors within one applicable block are conjunctive, while separate applicable blocks are alternatives. Failed detect applicability retains the detector state (including absent or superseded), not an implicit staged floor. Local detection uses uncapped update intent; parent detection and emitted owners apply the containing package cap. Unknown conditions, cycles and unresolved metadata raise errors, never partial records. Supports detectNone and scoped detectUpdate with staged/detect dispositions, plus absent selectable defaults for dependency queries and selected content; edition-gated selectability accepts up to two explicitly resolved current/target edition identity names in editions. A nonmatching edition disables the selector, not the child. Missing edition context, absent owner intents requiring removal, capability restrictions and component predicates remain unsupported. Intended state is supplied transaction intent, not a computed CurrentState. This does not select packages, resolve parent versions, infer permanence, supersede packages, verify signatures or complete a servicing transaction. Lists are bounded to 65536 items; manifest input is at most 32 MiB each and 256 MiB total. No host tools, registry writes or network access.

### `windows.cbs_parent_relationships`

`windows.cbs_parent_relationships(packages, candidates) -> list`

Tests native CBS IsParent relationships against explicit runtime version descriptors. Uses the same manifest/comparisons dicts and canonical candidate-name list as cbs_parent_update_scopes, but every root and nested rule participates, including nested-only families. EQ descriptors honor ignore_revision instead of performing exact lookup. Returns sorted unique matching candidate identities for each package. No state, disposition, standalone or Baseline relaxation is applied. This predicate does not reproduce reverse-index order, populate a watch list, authorize admission, or implement a servicing transaction. Bounds and all-or-error behavior match cbs_parent_update_scopes; no host tools or registry writes.

### `windows.cbs_parent_states`

`windows.cbs_parent_states(packages, candidates) -> list`

Evaluates CBS parent states without modifying an image. packages is a list of dicts with manifest (file or bytes), comparisons (one runtime descriptor per parsed parent block in preorder), and optional standalone_satisfied (default false; caller-resolved package/session bypass). Each descriptor requires major_minor, build and revision operators (EQ/NE/GE/GT/LE/LT) and an explicit ignore_revision boolean. candidates is an effective-intent snapshot of dicts with canonical package identity string in package, intended_state, and explicit baseline boolean from the CBS Baseline attribute. Pending/session overrides must already be resolved. Returns one integer parent state per input package; no-parent is the 0x1000 unspecified sentinel, not installed. Exact/range version lookup, staged-Baseline descending revision relaxation, and nested parent constraints are evaluated separately from owner intents. This does not populate runtime descriptors, infer installed state from MUM presence, compute final CurrentState, supersede packages, or write registry records. Lists are bounded to 65536 entries; manifests to 32 MiB each and 256 MiB total. Invalid inputs raise errors without partial results. No host tools, guest execution or network access.

### `windows.cbs_parent_update_scopes`

`windows.cbs_parent_update_scopes(packages, candidates) -> list`

Selects available parent packages for CBS update-name queries without modifying an image. packages is a list of dicts with manifest (file or bytes) and comparisons (one explicit runtime descriptor per parent block in preorder). Descriptors require major_minor, build, revision (EQ/NE/GE/GT/LE/LT) and ignore_revision. candidates is a list of canonical package identity strings. Returns one sorted, deduplicated list of matching package identities per input. Exact top-level references use exact lookup even when revision is ignored; ranged top-level references seed related families, then any root or nested rule can accept a candidate. Nested-only families do not seed candidates. Missing packages are skipped. This is not parent-state reduction: no state filter, disposition, standalone bypass or staged-Baseline revision relaxation applies. It does not enumerate updates, reproduce native release-type ordering, populate runtime descriptors, or perform a servicing transaction. Lists are bounded to 131072 inputs and 1048576 total results; manifests to 32 MiB each and 256 MiB total. Errors return no partial results. No host tools, registry writes or network access.

### `windows.cbs_update_index`

`windows.cbs_update_index(packages, editions=[]) -> cbs_update_index`

Builds a read-only immutable CBS update-state snapshot. packages and editions use the same explicit contexts as cbs_package_owners, but intended_state also accepts resolved absent (0), resolved (0x20) and permanent (0x80) states. Returns a record with state(package, update), yielding raw_state and intended_state (capped by the containing package), and with_states(states), yielding an independent snapshot after replacing the targets in a canonical-package-name to state dict. All dependency memo entries are invalidated in the new snapshot, including transitive detections; old snapshots remain unchanged. Parent scopes, editions, choices, explicitly published targets and parsed manifests are retained. with_updates(package, states) creates a new snapshot with explicit published update targets (update-name to resolved state dict); 0x1000 clears an override. state prefers these targets even when they carry an earlier containing-package cap. applicable(package, update) evaluates metadata for that update instead, while detectors still honor published dependency targets. Neither query publishes its result. with_components(components) replaces the effective component-analyzer snapshot for updateComponent predicates and invalidates derived applicability, preserving published targets. Each entry requires identity (canonical CSI UTF-8 bytes) and owners (effective installed-owner elevation DWORDs, not package states). Purely staged owners must be excluded and transaction overlays resolved by the caller. Missing snapshots fail; an explicit empty snapshot is distinct. Supported elevate values are revision, distribution, build, version and install. Same-family strictly older components supply evidence; architecture, culture, type and versionScope remain distinct. Only nonSxS families discard the entire version; other scopes retain major/minor, preventing activation from a different side-by-side version family. This does not load ownership from a hive, update analyzer execution overlays or choose CSI winners. Component inputs are bounded to 1048576 entries/owner words and 64 MiB identity bytes. This does not model the separate native applicability-result cache or its invalidation policy. Rebuild with cbs_update_index if parent/selection/edition policies change. Pending/unspecified targets, duplicate case-insensitive changes and unknown packages are rejected. package_states() returns an independent canonical-package-name to target dict, including unadmitted inventory. package_state(package) queries one exact target without copying the inventory; missing contexts are errors, not inferred absent states. ordinary_population(roots, store_owners, applicability, populate_mum, work_limit, omitted_references=[], watch=..., allow_absent_references=False, store_loaded_packages=[], lcu_session=False) evaluates only an explicitly selected ordinary population prefix. store_loaded_packages supplies exact contexts resolved from the installed store (native source kind -1); only their ordinary deployment references may ignore a not-found child at nonzero target. It does not permit missing roots/MUM requests or grant this policy to new sources merely sharing a family. lcu_session explicitly models native LCU task flags and requires a Package_for_RollupFix root requested installed or staged; only not-found deployment children become optional. The returned unresolved_references records parent, package identity, update, intended_state and reason for every optional not-found lookup; these records are not admissions or content-installation evidence. Each root/request is a dict(package, owner, state, integration, ceiling), optionally preserve_store_owner, bypass_owners and skip_mum; store owners are dict(package, owner, state, integration). applicability(package, snapshot) must return a resolved state. populate_mum(package, snapshot, action) must return dict(before_updates=[requests], deferred=[requests]); both callbacks must be pure and explicitly resolve missing policy. MUM actions 2/3 require supersedence policy; 4/5/6 require lower-version reinstall policy. Initial unchanged installed items select action 3. A merge uses the previous target after completed MUM processing, otherwise the original state, then clears the processed flag. MUM processing is not once per item; it rechecks reinstall after immediate supersedence recursion. Immediate MUM requests precede update publication; deferred requests follow all roots/children. Updates publish in manifest order before depth-first child admission. Named execution requests replace state and retain first integration; dirty normalizes only superseded to staged. Returns index, executions (package, intended_state, owners, updates, update_starts, action, mum_populated, mum_processed, mum_passes, dirty, dirty_updates, watch_processed), and admissions. Unknown referenced packages fail unless explicitly omitted. allow_absent_references=True permits an unavailable reference only when its containing update target is absent; nonzero targets still fail. This models the native target-zero optional resolve path, not the broader session-flag policy; work_limit is required in 1..4194304 and bounds queued requests and evaluations. Optional watch is dict(initial_update, dependents, satellites), with all three pure callbacks required. initial_update(package, update, target, snapshot) returns dict(state, has_deployments) using the resolved native start state; deployment-free updates are initially dirty even when unchanged. dependents(notifier, snapshot) returns ordered deduplicated requests. satellites(notifier, admitted_package, snapshot) returns requests after each dependent/satellite admission drains; recursion keeps the same notifier. Notifications scan execution insertion order, repeat after admissions, preserve package dirtiness, and clear update dirtiness/mark processed only after children return. Any ordinary merge resets processed, even with unchanged target. Records, dirty-update lists and update_starts are independent callback snapshots. update_starts maps each update name to its first resolved state/has_deployments record; merges and notifications preserve it. It is empty without watch and is not post-stage CSI state. The returned population exposes execution_count without materializing its full mutable executions inspection list. selected_executions(packages, actions=...) intersects up to 65536 nonempty package-name strings case-insensitively with native execution order, returning fresh independent execution records only for matches; duplicates collapse and missing packages are omitted. Optional actions is a list of at most seven integer MUM actions in 0..6; filtering occurs before record materialization, and an explicit empty list selects nothing. Omitting it preserves all matching executions. This view never consults edits to the full inspection list. The returned population can explicitly capture `deployment_plan()`: this validates the complete native deployment projection once and returns admissions, execution_count, selected_executions, executions, deployment_actions and install_marks without retaining the admission index or package manifests. Dropping the original population then permits that graph to be reclaimed. The captured action evidence is private; changing either inspection list cannot change later marks. This is an action plan, not completed servicing. The returned population also provides deployment_actions(changed_only=False), a read-only projection in execution/manifest order: records contain package, update (exact spelling), deployment (CSI identity record), driver, driver_attributes (independent namespace/name/value records from the containing MUM driver declaration, including inf/ranking/bootCritical when declared), stage and action. No driver metadata is inferred from a dual_* identity or an INF-looking component file. Stage is separate from Execute: stage-only sources have stage=True and action=0; action=3 installs and action=4 uninstalls. With changed_only=True only records with stage=True or action!=0 are materialized, in the same order, AFTER validating the entire native action set. Default inspection retains unchanged references; update starts rather than package last-action determine operations. Resolved starts from watch are required for every deployment. Unsupported restaging, removal below staged, pending/resolved-only source states and undrained notifications fail. The method retains the native snapshot independently of mutable inspection records and returns fresh lists. install_marks(inventory) uses that same immutable action snapshot to analyze exact installed-source counts. inventory is a list of dict(identity=canonical CSI bytes, composition=records from csi_composition, installed_sources=native i!CBS_ payload bytes). Supply every resident owner, including unchanged owners, and every changed deployment; changed resident compositions must match their c! backlinks. An unchanged deployment may replace composition with persisted_members, a list of canonical CSI identity bytes from its installed c! backlinks. These contribute all baseline source counts without recomputing manifest graphs or inventing dispositions. Supplying both forms, duplicate members, missing roots of nonempty/installed inventories, or using persisted membership for an install/uninstall action fails. Empty membership is allowed only for an unowned unchanged deployment. Returns component records with identity, initial/final counts, affected and impactful_install. Each installed source contributes a mark, not merely each active deployment; source conflicts and duplicate changes fail. Uninstall closures can set impactful_install even when another source keeps the component installed. Stage-only changes do not alter install marks. Input identity/source data is bounded to 64 MiB, entries to 4194304. This analysis does not persist sources, resolve non-CBS source policy or execute driver operations. Driver records additionally require native driver-store/DOQ operations; this projection neither executes them nor selects winners, materializes files or authorizes registry writes. These callbacks must explicitly resolve native indexes, child rules, pending/session state and satellite requests. Omit watch to stop before notifications; watch fields are then not evidence of notifications. Deferred MUM work during watching fails because transaction queue policy is not supplied. Inputs and retained snapshots are unchanged; any error returns no partial result. This prefix excludes force-state, pending resolution, CBSBLR owner clearing, capability wrappers, target-raise restrictions, feature-controlled staged restaging, automatic watch-index/initial-state resolution, component execution, permanence and final persistence. It is never a fallback for unsupported transaction policy or authorization to write CurrentState. Uses the same manifest/list bounds as cbs_package_owners; no registry writes, host tools or network access. Returns a native immutable cbs_update_index snapshot, bounded to 65,536 packages, with lazily bound methods. package_state_vector(packages) returns an ordered tuple of intended states for up to 65,536 package-name strings. It queries this exact snapshot; publication never reuses another snapshot's state memo. initial_component_states(deployments, packages) joins explicit canonical-deployment value dictionaries (appid and p!/s!/i! source bytes) to immutable component/driver references, returning independent package/update-to-state lists in manifest reference order. Missing bindings are zero; matching installed/staged/pinned sources yield 112/64/32 with that precedence. Identity matching retains architecture, normalized culture, version, versionScope and type; source primary names remain case-sensitive. Duplicate deployment identities/packages, malformed source data and bounded-input violations fail. It does not cap states by package intents, infer transaction completion, change the baseline or share stage/install execution state. Inputs are bounded to 1048576 deployments/sources, 64 KiB per identity/source, 256 MiB aggregate bytes and 1048576 projected references.

### `windows.cdf_decode`

`windows.cdf_decode(data) -> dict`

Parses version-one PcmH compiled data container bytes. Returns a mutable dictionary with flags, format (16 bytes), root, auxiliary_root, strings, identities, appids, guids, and blobs. The three ID indexes refer to zero-based blobs; GUIDs are inline 16-byte values; blobs are (kind, opaque bytes) tuples. 0xffffffff denotes an absent root. Validates the noncryptographic IHA8 checksum, extents and outer references; does not validate nested-table semantics, decode strings, authenticate contents, or decide FileMap ownership. Input/expanded payload bounded to 64 MiB and each record list to 1048576. No host parsing or writes.

### `windows.cdf_encode`

`windows.cdf_encode(document) -> bytes`

Serializes the exact nine-field dictionary returned by cdf_decode, preserving blob/index IDs and opaque data. Four-byte aligns payloads and recomputes IHA8; padding, physical ordering and shared extents need not match input. Validates integer ranges, extents and outer references, not nested payload semantics or FileMap servicing policy. Bounds match cdf_decode. Returns bytes without image mutation or host intermediates.

### `windows.cdf_filemap`

`windows.cdf_filemap(data) -> dict`

Decodes the observed version-one CSI FileMap no-hash schema from CDF bytes. Returns path, root_selector, identities (ordered lists of namespace/name/value tuples), and entries (name, display_name, flags, identity index). Validates container checksum, schema GUID, table framing, key hashes, string/blob/identity references and duplicate keys. Preserves native flags without authorizing filesystem effects. Unsupported compact tables, hashed records, unknown field bits, non-ASCII lookup keys or other schema variants fail closed. Bound to 64 MiB container/expanded payload, 1048576 records/total attributes, and 1024 attributes per identity. Does not decide ownership transitions, apply updates or authenticate contents.

### `windows.cdf_filemap_encode`

`windows.cdf_filemap_encode(document) -> bytes`

Rebuilds the supported no-hash FileMap dictionary returned by cdf_filemap. Interns UTF-8 strings, prunes unused identities and remaps references, preserves resolved flags/names/attributes, sorts native 32-bit name hashes while preserving equal-hash input order, and emits a checksummed CDF. IDs and physical bytes may differ from input. Uses the same bounds and rejected variants as cdf_filemap; empty maps fail rather than implying deletion. No ownership selection, root-path normalization, image mutation or authentication is performed; callers must supply the complete intended records and correct root selector.

### `windows.cdf_filemap_name`

`windows.cdf_filemap_name(path, windows_root="/Windows") -> string`

Derives the native CSI FileMaps leaf filename from a canonical absolute image path with slash separators. windows_root defaults to /Windows and must be a non-root canonical image directory. Supports printable ASCII paths of at most 32767 bytes; rejects drive prefixes, backslashes, empty/dot components, trailing separators and Unicode rather than approximating Windows folding. Uses the Windows-relative $$ prefix, native filtering/collapse and 100-character bound, and uppercase CSI hashing when required. Drive root maps to _0000000000000000.cdf-ms. Does not inspect the image, choose ownership or mutate any files.

### `windows.cdf_filemap_path`

`windows.cdf_filemap_path(path, volume, windows_root="/Windows") -> dict`

Computes native FileMap path/root_selector metadata for a canonical ASCII image path and an explicit drive designator such as C:. Windows-root matching uses the native case-insensitive literal prefix, not a path-component boundary. Image root emits an absolute NT path with selector 0; Windows-relative paths use 1 and other volume-relative paths use 2. Shares cdf_filemap_name path bounds and rejects noncanonical paths. Does not mutate a map or image.

### `windows.cdf_filemap_transition`

`windows.cdf_filemap_transition(document, nodes) -> dict`

Computes a bounded no-hash FileMap ownership transition without mutating inputs. document has the cdf_filemap schema (empty entries/identities represent a new map). Each node requires name, operation, state, directory_flags, file_flags, before_identity and after_identity; identities are None or lists of namespace/name/value tuples. Names are immediate ASCII leaves; dot denotes the directory. States must be post-preliminary-file-pass native states, not raw manifest declarations. Files compare existing ownership against the new family ignoring version; dot uses the old family. Unmentioned entries survive. Returns document and directory_collisions (retained_identity/requested_identity pairs). A duplicate dot retains the resident owner and is reported, not silently overwritten; transaction-level diagnostic handling remains separate. Unsupported identities and unresolved file-family conflicts fail closed. Empty documents do not authorize deletion and cannot be encoded. Does not select dirty directories, normalize root paths, mutate image files/security, authenticate packages or commit servicing.

### `windows.certificate`

`windows.certificate(value) -> certificate record`

Parses one DER X.509 certificate and returns its DER bytes, subject, issuer, SHA-1 and SHA-256 fingerprints and a subject/issuer-equality flag named self_signed. Also exposes exact subject_public_key_info DER, public_key_algorithm OID, public_key_parameters DER, public_key_bits and public_key_bit_length without re-encoding the signed key material. These fields and self_signed do not establish signature verification or trust.

### `windows.certificate_chain`

`windows.certificate_chain(certificate, roots, intermediates, unix_time, purpose) -> list[list[bytes]]`

Validates X.509 paths using only explicit roots (at most 64), intermediates (at most 32), unix_time and purpose (code_signing or timestamping). Timestamping additionally requires a critical, exclusive RFC3161 timestamping EKU on the leaf. Each DER/PEM input is bounded to 1 MiB. Returns lists of certificate DER from leaf through root; invalid time, usage or trust paths raise errors. This is not revocation checking, a trusted timestamp decision or Windows provider policy; it uses no host roots, clock or network.

### `windows.cli_inspect`

`windows.cli_inspect(value, method='') -> record`

Reads CLI metadata and selected managed method bodies without executing them. Accepts a portable file or bytes, at most 32 MiB. Returns runtime_version (metadata version string without trailing NUL padding), cor_flags (raw COR header flags), entry_point (raw COR header entry field), rows (token, columns in ECMA-335 table order), strings (user-string token to text), and methods (token, name, instructions). String/blob columns are decoded; coded references and table indexes become tokens, except null remains zero; list-end sentinels are preserved as token-shaped indexes. Other columns retain their integer value, including GUID heap indexes. method is a case-sensitive method-name substring; empty selects all IL bodies. Each instruction has offset relative to IL code, numeric opcode, raw operand bytes and token (zero for non-token operands). Bounds tables/heaps/bodies, limits rows to 100000, decoded row heaps to 64 MiB and instructions to 1000000, and rejects unknown opcodes. Does not verify IL stack/control flow, resolve external assemblies, decode signatures or exception clauses, evaluate feature gates, or claim observed runtime effects.

### `windows.clone_file_entries`

`windows.clone_file_entries(entries) -> dict`

Copies a path-to-metadata dictionary and each distinct entry dictionary, preserving insertion order and alias groups: names sharing one entry share one new entry in the clone. The cloned dictionaries are independently mutable from the source; equal-valued but distinct entries remain distinct. File sources and other field values remain shared and are not read.

### `windows.coff`

`windows.coff(source, maximum=64MiB) -> record`

Inspects a bounded standard COFF object in memory. Returns machine, sections (index, name, bytes data, size, characteristics, relocations) and primary symbols (index including auxiliary slots, name, value, section, type, storage_class, aux_count). Relocations retain offset, numeric type, symbol_index and resolved symbol. Rejects PE images, bigobj and overflow relocation tables. maximum defaults to 64MiB.

### `windows.compile_sddl`

`windows.compile_sddl(text, account_domain_sid=None) -> bytes`

Compiles a bounded SDDL subset to revision-1 self-relative descriptor bytes, without host identity lookup, defaulting, generic-right mapping or inheritance. Supports O/G/D/S sections; fixed SY, BA, BU, WD, AC, LU, AU, BO, CO, IU, LS, LW, ME, NO, NS, RC, SU, UD, AN, BG, CG, OW, SO and numeric revision-1 SIDs; P/AR/AI ACL flags; absent, empty and NO_ACCESS_CONTROL ACLs; A/D/AU ACEs, SACL mandatory-label ACEs with integrity SIDs and masks 0..7 (including NW/NR/NX policy tokens), and XA local-attribute Contains-string, exists, or parenthesized local-attribute NOT conditions. Optional account_domain_sid must be a canonical S-1-5-21-a-b-c SID and enables LA (RID 500); no account domain is guessed. Symbolic and base-zero numeric rights may be concatenated and are ORed; numeric overflow is rejected. Unsupported syntax (including CSI (inherit), other domain-relative aliases, object GUIDs, compound conditions and escaped literals) fails closed. This is format construction, not an access decision or a complete file-security policy.

### `windows.container_index`

`windows.container_index(value, names=None, source_type='', limit=20, target_hash='') -> record`

Returns compact CIX statistics and explicitly selected file records. Names and
source type select their union; optional `target_hash` (64 hexadecimal SHA-256
digits) narrows that selection, or selects equal-content aliases by itself.
At most `limit` records are returned (0–1000); input remains in memory.

### `windows.copy_explicit_file_acl`

`windows.copy_explicit_file_acl(source, owner, group, directory=False) -> bytes`

Constructs effective and propagation ACEs from an explicit file ACL under auto-inheritance. Source is a bounded ACL; owner and group are binary SIDs. Maps and clips file rights, substitutes creator owner/group, preserves callback data, and splits directory propagation when needed. Supports allow/deny/audit/alarm and callback-allow layouts; inherited ACEs, other creator identities, reserved flags and unsupported layouts fail closed. Does not select or merge parent ACLs, supply descriptor defaults, represent absent/NULL ACLs, or change a filesystem.

### `windows.creg_compare`

`windows.creg_compare(left, right) -> structural difference report`

Compares two Windows 9x CREG registry files structurally and returns a difference report. This avoids treating different physical record layouts as necessarily different registry contents.

### `windows.creg_from_patches`

`windows.creg_from_patches(name, patches, keys=[], state=1, generation='windows95') -> file`

Constructs a Windows 9x CREG registry file from a name, value patches and optional key records. generation selects windows95, windows95_rtm, windows_nashville, windows98_fe, windows98 (SE), or windowsme, including their navigation page and allocator layouts; this is not an NT REGF hive writer.

### `windows.creg_keys`

`windows.creg_keys(file) -> list[list[string]]`

Returns the key paths represented by a Windows 9x CREG registry file as lists of path components. Empty keys can therefore be preserved independently of value patches.

### `windows.creg_patches`

`windows.creg_patches(file) -> list[dict]`

Converts values in a Windows 9x CREG registry file into declarative registry patch dictionaries. Use creg_keys as well when reconstructing empty keys.

### `windows.csi_composition`

`windows.csi_composition(root, resolve, work_limit=1048576) -> list`

Calculates a bounded exact CSI composition, following only explicit install dependencies. resolve(identity_bytes) must return the exact decoded component manifest as a file, string, bytes or immutable cbs_manifest value; None or a foreign identity fails. Parsed values can be shared across compositions without bypassing identity, dependency or work-limit checks. Returns records with canonical identity bytes and disposition (1 patch, 2 install). Omitted dependency types, prerequisites and runtime bindings do not introduce owners. Preserves native breadth-first impact propagation and rejects missing install edges, cycles exceeding native depth 128 and work-limit exhaustion. Manifest reads are bounded at 64 MiB; work_limit ranges from 1 to 4194304. Does not decide package applicability, source activation, final installed marks, winners or driver-store effects, and does not write state.

### `windows.csi_deployment_key`

`windows.csi_deployment_key(data) -> string`

Encodes complete bounded CSI identity bytes as the native canonical COMPONENTS deployment key, preserving architecture, culture, type and version-scope hash distinctions. Not a WinSxS directory name; malformed or unsupported identities fail instead of approximating.

### `windows.csi_file_attributes`

`windows.csi_file_attributes(attributes=None) -> int`

Parses the native manifest file attribute mask. None retains the 0xa0 constructor default; an explicit value replaces it, including an empty string yielding zero. Accepts case-insensitive readOnly, hidden, system, archive, temporary, offline and notContentIndexed separated by XML whitespace. Rejects unsupported tokens. This is not the final commit-time filesystem mask.

### `windows.csi_file_destination_name`

`windows.csi_file_destination_name(name, destination_name=None) -> string`

Selects the shallow CSI destination name: an explicitly supplied destination_name (including an empty string) overrides name; otherwise selects the suffix after the last backslash, or the preceding path when the last backslash is trailing. Forward slashes are not separators here. None means no override. Does not expand macros, validate a final path or authorize a projection.

### `windows.csi_file_directory_macro`

`windows.csi_file_directory_macro(target, architecture, name) -> int`

Returns the WCP IRtlUserProfile directory identifier for an unwrapped runtime macro name. Only the observed amd64 target policy is supported. MSIL/data/absent component architecture use native directories; x86/wow64/amd64.x86 use redirected directories. ASCII macro names are case-insensitive. Unknown macros and unsupported architectures fail closed. The identifier is not a path: image registry/profile lookup, environment expansion and offline drive mapping remain caller responsibilities. This read-only lookup does not authorize or apply file effects.

### `windows.csi_file_source_key`

`windows.csi_file_source_key(identity, name) -> tuple`

Returns the ordinary CSI FileInfo intern key as (name, culture, architecture, token, type, version_scope, relative_name, version_family). Identity is canonical bytes bounded to 64 KiB; compared fields must be printable ASCII. Relative names may contain backslash-separated nonempty components, but not slash, colon, dot or dot-dot components. Absent versionScope retains major/minor; nonSxS ignores version; other scopes fail. This is not an exact payload identity, content hash or permission to publish a file.

### `windows.csi_identity`

`windows.csi_identity(data) -> record`

Decodes bounded canonical COMPONENTS identity/appid bytes, preserving name, version, language, processor_architecture, public_key_token, type and version_scope. Rejects malformed, unknown or repeated attributes; does not infer identity from a lossy registry key or activate components.

### `windows.csi_identity_hash`

`windows.csi_identity_hash(data, omit_version=False) -> int`

Hashes bounded full COMPONENTS identity/appid bytes using the native non-cryptographic CSI identity discriminator, returning an unsigned 64-bit integer. omit_version=True selects the version-independent family hash used by component-family and SOFTWARE winner key suffixes; type, versionScope, architecture and culture remain significant. This differs from CBS update-analyzer family matching. Only the validated ASCII identity alphabet is supported. Does not reconstruct an identity from an abbreviated path, select a winning version, infer activation or write registry state.

### `windows.csi_mof_equivalent`

`windows.csi_mof_equivalent(left, right) -> bool`

Compares ordered CSI MOF declarations and referenced primary-file hashes using the observed WCP MofDiffer predicate. Inputs are XML file/string/bytes, at most 16 MiB each. Supports ASCII file lookup, SHA1/SHA256 nested hashes with zero or one Identity transform and legacy SHA1; unsupported policy and ambiguous file names fail closed. Declaration strings are case-sensitive, file lookup is case-insensitive, and either comparable hash mismatch vetoes equality. The native uninstallmof branch compares its declaration string but rechecks the primary file hash. True is only predicate equivalence: it does not derive installer queue/inspection policy, execute MOF registration, verify payload authenticity or apply state.

### `windows.csi_source_plan`

`windows.csi_source_plan(before, changes) -> record`

Plans ordered value-only CBS p!/i!/s! source edits for one deployment. before is the complete source inventory as dicts (name, type, data); changes contains dicts (kind, delete, data), with native kind 1 pinned, 2 installed, or 4 staged. Data must be exact serialized bytes. Existing adds preserve their opaque payload even when the requested secondary differs; deletion requires presence. Returns edits (name, delete, type, data), before and after counts (pinned, installed, staged). Rejects non-CBS sources, mismatched names, malformed data and invalid masks atomically. Bounds: one million entries per list, 64 KiB per payload, 64 MiB total payload. Does not choose operations or apply writes: staged marks require successful staging or the separate native pending-content protocol, not merely a queued stage action. Counts do not authorize backlink deletion or activation.

### `windows.csi_winner_change`

`windows.csi_winner_change(identity, current, installed, changes) -> record`

Analyzes one exact CSI servicing family after installed-mark updates. identity is full canonical CSI bytes; current is the effective winning version or an empty string. installed is complete final installed version membership. changes is a list of dict(version, installed, impactful_install) for affected versions. Returns winner and shadowed strings; both empty means unchanged, an empty winner with a shadowed version means clear the effective winner. Preserves surviving winners unless a strictly higher impactful install replaces them, and falls back to the highest remaining installed member only on removal. Ordinary SxS identities are restricted to their major/minor branch; NonSxS and policy identities span branches. Does not rebuild untouched branch defaults or write state.

### `windows.csi_winner_family_key`

`windows.csi_winner_family_key(data) -> str`

Formats a SOFTWARE SideBySide/Winners family key from bounded full CSI identity bytes. Native abbreviation scans both ends; type and versionScope affect the hash but not the readable prefix. Validates ASCII identities, canonical named architectures and 16-hex-digit tokens; rejects unsupported typeName and Unicode rather than guessing. Does not choose winners or write state.

### `windows.csi_winner_plan`

`windows.csi_winner_plan(identity, current, before, changes) -> record`

Plans value-only SOFTWARE Winners edits from a full CSI identity, actual current winner, complete baseline membership before, and affected-version dicts (version, installed, impactful_install). Derives final membership and winner choice using native semantics. Returns family, winner, shadowed, edits; each edit has branch, name, delete, type and data. Empty branch means family root; empty name means default. Nondelete data is raw REG_SZ or REG_BINARY. Deletions remove individual values only, never keys or unrelated branch defaults. This is not complete servicing and applies no writes.

### `windows.csp_registrations`

`windows.csp_registrations(file, strict=True)`

Derives CryptoAPI provider-registration arguments from a 32-bit provider DLL without assigning registry paths or defaults. strict=False returns an empty list for unrecognized registration code; malformed input still fails. The provider is not executed.

### `windows.decode_file_eas`

`windows.decode_file_eas(data) -> list`

Decodes a bounded FILE_FULL_EA_INFORMATION chain (at most 64 KiB) to name/flags/value dictionaries. Validates lengths, alignment, terminators, supported flags and unique case-insensitive names. Values are opaque bytes; this is not a trust decision or WIM EA decoding.

### `windows.delta_apply`

`windows.delta_apply(source, delta, psf_record=False, maximum=64MiB) -> bytes`

Reconstructs native PA30/PA31 bytes with mandatory source and target hash
verification. `maximum` bounds each input and the decoded target; an explicit
value up to 128 MiB supports large Defender definition records without changing
the default 64 MiB bound.

### `windows.delta_info`

`windows.delta_info(value, psf_record=False, maximum=16MiB) -> record`

Inspects PA30/PA31 headers and bounded preprocessing data. `pe_preprocess`
contains native address maps and, when present, `managed`: CLI metadata extent,
streams (`#Strings`, `#US`, `#Blob`, `#GUID`, `#~`), table row counts, and
heap/table maps. Inspection does not imply that every recorded transform is
supported by apply. Managed apply supports metadata RVA/index normalization,
signature-token remapping and heap/table copy-coordinate maps. Nonidentity
method-body tokens are normalized in bounded tiny/fat IL bodies; metadata
column-width changes use source-cell copy mappings. `maximum` bounds the record
read and may be raised explicitly to 128 MiB for large records; it does not bypass
PSF framing checks.

### `windows.delta_trace`

`windows.delta_trace(source, delta, start, end, psf_record=False, pe_transforms=True, prepared_source_start=-1, prepared_source_end=-1, inspect_signatures=False) -> record`

Inspects the selected reconstructed byte range before PE restoration, without
enforcing the target digest. Source identity and input bounds remain checked.
This is a diagnostic API, not an image-construction replacement for
`windows.delta_apply`. LZMS-backed direct payloads report literal spans; nested binary deltas report
clipped `add` spans with signed source offsets and literal insertion spans.
Additive spans may reference bytes outside the source, which contribute zero.
These are binary-delta spans, not LZMS compression matches. Set
`pe_transforms=False` to omit PE normalization events for broad byte comparisons.
Supply both prepared-source bounds to also return `prepared_source`, a copy
of that source window after preprocessing and before patch matching, plus
`prepared_source_start`. The window must be nonempty and within the input
source; it is `None` when omitted. These bytes are diagnostic, not a verified
target.
With `inspect_signatures=True`, a prepared-source range is required and
`source_signatures` lists overlapping original CLI signature consumers in
normalization order, including shared blobs. Each record contains `table`,
one-based `row`, `blob_index`, and payload `offset`/`size` excluding the blob
length prefix. Without this option the list is empty.

### `windows.dmr_alternate_path`

`windows.dmr_alternate_path(value, first_package_family=False) -> file`

Encodes an alternate package path in a DMR section, optionally using the first-package-family form. Paths describe guest package state, not host output files.

### `windows.dmr_application_resources`

`windows.dmr_application_resources(index, display_name, description, square150x150_logo, square44x44_logo, start_page=None) -> file`

Serializes one indexed application's display, description, logo and optional start-page reference files into a DMR resource section. It does not infer resource choices.

### `windows.dmr_applications`

`windows.dmr_applications(applications, capabilities, source_flag) -> file`

Encodes declared application records, capabilities and a source flag into a DMR applications section. This serializes the supported application metadata without executing registration callbacks.

### `windows.dmr_container`

`windows.dmr_container(sections, max_bytes=64MiB) -> file`

Combines ordered section files into a bounded DMR envelope. Format and extent validation do not establish that the caller supplied every section required for a valid Windows package graph.

### `windows.dmr_globalization`

`windows.dmr_globalization(application_id, utf8=False, windows_display_language=False) -> file`

Encodes an application's UTF-8 and Windows-display-language settings into a DMR globalization section. The application identity and policy are supplied by the caller.

### `windows.dmr_graph`

`windows.dmr_graph(nodes) -> file`

Serializes an already selected, ordered package dependency graph into a DMR section with bounded node count. Package identity, paths and flags remain caller-supplied; it does not perform dependency resolution.

### `windows.dmr_mutable_paths`

`windows.dmr_mutable_paths(paths) -> file`

Encodes an ordered, bounded nonempty list of mutable package paths into a DMR section. It does not create directories or change permissions.

### `windows.dmr_package_resources`

`windows.dmr_package_resources(display_name, publisher_display_name, logo, description=None) -> file`

Serializes package resource references into a DMR section. Inputs are bounded encoded reference files; description=None preserves an absent description rather than an empty reference.

### `windows.dmr_package_security`

`windows.dmr_package_security(ari_flags, package_sid, is_inbox, capabilities) -> file | None`

Serializes declared package SID, ARI flags, inbox status and capabilities into a DMR security section. Encoding these fields neither verifies signatures nor establishes package trust.

### `windows.dmr_target_platform`

`windows.dmr_target_platform(target_device_family_name, minimum_version, maximum_version_tested) -> file`

Encodes a target-platform DMR section from a native device-family enum and version bounds. The family value is not a StateRepository database row ID; -1 represents the native unknown enum.

### `windows.dmr_trailer`

`windows.dmr_trailer() -> file`

Returns the fixed native DMR trailer section as an in-memory file for container composition.

### `windows.empty_event_log`

`windows.empty_event_log(size=5MiB) -> file`

Constructs a valid empty legacy Windows event-log file of the requested size. This creates an EVT-format starting state, not an EVTX log.

### `windows.etl_profile`

`windows.etl_profile(file) -> dict`

Native 64-bit kernel sampled-IP analysis with the ETL reader's bounded input
and event limits. Returns image identities, process lifetimes, aggregated
`points` (process/module indices, RVA, interrupt flag, sample count), loss
metadata and explicit unknown counts. Index -1 means unknown; an unmapped
RVA retains the absolute IP. Counts are self samples, not elapsed time or
inclusive stacks. Also returns timestamp-sorted `image_events` (tick, pid, opcode, base, path, size, timestamp, checksum) from native load/unload/rundown records for explicit cross-trace address correlation. Callers must compare trace clocks and boot identity, respect process/address reuse, and retain ambiguous mappings. End rundown is not treated as an earlier image load.
No symbols or network requests are implicit.

`windows.pe(file).symbolize(pdb, rvas, timestamp, image_size, checksum)` resolves
an AMD64 RVA list against `windows.pdb(file)`. Requires matching PE identity
and CodeView GUID/DBI age; returns name/RVA/displacement/match dictionaries
or None. Nearest public symbols cannot extend past their runtime-function
interval or explicit chained unwind owner; unnamed leaves/unlinked fragments remain unresolved.

### `windows.etl_report`

`windows.etl_report(file, max_events=4000000) -> dict`

Native offline analysis of finalized sequential, uncompressed kernel ETW `.etl`
files (not EVT/EVTX). Uses the portable file reader; no Windows API, external
parser, guest conversion tool, symbols or network access. Input is limited to
1 GiB, 1 MiB per buffer, 4096 schemas, one day of event timestamps, and the
configured event count (1..4000000). Unsupported framing/clock modes and
truncation are errors, not partial-success reports.

Returns `header` (clock, CPU count, loss counters), observed tick/time range,
scheduled/idle/unknown/uncovered CPU-seconds, switch discontinuities, per-process
lifetimes, command lines, scheduled CPU, matched ready/block thread-seconds,
wait reasons, disk bytes/counts/summed and maximum response times, DPC/ISR sums,
one-second `timeline`, `schemas` (group/opcode/version/header/count/decoded), and
`warnings`. Events are time-sorted before lifecycle attribution; PID/TID reuse
is not collapsed into one final ID map. Unsupported payloads remain in the schema
inventory rather than being guessed.

Times are relative to the first observed event, not firmware entry. Process start
is not a desktop-ready milestone. Scheduled CPU includes interruptions; DPC/ISR
sums can overlap each other and scheduled time. Ready/block/I/O sums across
concurrent work are **not** critical-path wall time. Boundary gaps, unknown
threads and losses are explicit. Reports include sensitive process arguments.
See `windows/etl/FORMAT.md` for format coverage and permissive reference licenses.

### `windows.etl_scheduler`

`windows.etl_scheduler(file, pid, max_events=4000000, max_records=200000) -> dict`

Returns timestamp-sorted scheduler observations for one PID from a finalized
kernel ETL file. Records contain `seconds` relative to `first_tick`, `kind`,
`tid`, `peer_tid`, `peer_pid`, `cpu`, `state`, and `reason`. Kinds are
`process_start`, `process_end`, `thread_start`, `thread_rundown`, `thread_end`,
`in`, `out`, and `ready`. State/reason describe the outgoing thread on a
context switch; they do not describe the incoming thread on an `in` record.

Ownership follows observed thread lifetimes; process boundaries expose PID
reuse, and end rundown never invents an earlier lifetime. A ready record's
peer is the last observed running thread on that CPU, not a proven waker:
interrupts/DPCs may be responsible. Zero peer IDs mean idle or unknown.

Includes `header` loss counters, `first_tick`, `last_tick`,
`switch_discontinuities`, and `unsupported_thread_events`. Unsupported process
schemas are not counted by the latter; use `etl_report` for a schema inventory.
Losses and incomplete ownership prevent reliable interval/causal conclusions.
No wait durations or critical path are inferred. Input/event limits match
`etl_report`; `max_records` must be 1..1000000. Limits and malformed framing
fail rather than silently truncating. No symbols or network access is implicit.

### `windows.etl_walk`

`windows.etl_walk(file, visit, group=-1, opcode=-1, min_tick=0, max_tick=0, max_events=4000000) -> dict`

Visits raw records from a finalized sequential uncompressed kernel ETL in file order, NOT timestamp order. Calls visit(record); callback return values are ignored and errors stop traversal. Records contain offset, tick, cpu, header_type, group, opcode, version, pid, tid and owned payload bytes. Also exposes marker, provider_id (16 GUID bytes in Windows byte order), event_id, message_flags, header_flags and activity_id (16 GUID bytes). Modern event extensions are separated from user payload: extensions contains type, linkage, owned data bytes, match_id, pointer_size and stack address values. Stack types 5/6 decode 32/64-bit addresses; unknown types remain opaque. Extension chains are limited to 128 items and malformed bounds fail. Supports bounded WPP TraceMessage framing (marker 0x9000); its optional timestamp/TID/PID fields follow message_flags. Missing timestamps are zero; payload schemas are not inferred. Unavailable PID/TID are 0xffffffff; non-kernel group is 255. Optional group/opcode (-1 or 0..255) and inclusive raw min_tick/max_tick filters select callbacks; max_tick=0 is unbounded. The entire file is still validated and all records count toward max_events (1..4000000); input is bounded to 1 GiB and buffers to 1 MiB. Returns logfile header and loss counters. Callers must check loss, interpret clocks and schemas, account for lifecycle reuse and sort selected records before scheduler attribution. A thread running on the ReadyThread CPU is not proof of the wake source: interrupts may intervene. No symbols, inferred dependency claims, guest execution or network access.

### `windows.event_log`

`windows.event_log(file) -> list[dict]`

Parses legacy EVT or supported EVTX event-log input into event records. The format is detected from the file; this does not query the host's event-log service.

### `windows.event_template_providers`

`windows.event_template_providers(source) -> list`

Reads a CRIM 5.1 WEVT_TEMPLATE resource (bytes/file, at most 16 MiB) and returns canonical lowercase braced provider GUIDs in directory order. Validates bounded directory counts, GUID uniqueness, WEVT block extents/non-overlap and up to three trailing zero bytes. Event schemas, message/channel metadata, resource trust and registration policy are not interpreted.

### `windows.font_names`

`windows.font_names(file) -> list[string]`

Extracts full font-name strings from supported OpenType/TrueType files, including collections. Returns a list of names without installing or rendering the font.

### `windows.guid_bytes`

`windows.guid_bytes(value) -> bytes`

Parses a textual GUID into the 16-byte mixed-endian representation used by Windows binary formats.

### `windows.hive`

`windows.hive(file, snapshot=False) -> registry hive`

Parses an NT REGF registry hive and returns a read-only key/value inspection object. Keys expose security as the bounded raw self-relative descriptor from their SK record, without walking descendants or inferring permissions. path_component_patches(replacements, exclude_keys=[]) returns planned key_parts/name/type/value/before records for REG_SZ, REG_EXPAND_SZ and REG_MULTI_SZ values. Matches complete backslash/NUL-delimited components case-insensitively, preserving all unmatched raw bytes. Excluded key subtrees use literal key parts. Traversal is bounded to 1,048,576 keys, 4,194,304 values, 1 GiB of string data and 65,536 output patches; errors return no partial plan. This never edits the hive. Use hive_from_patches to construct a hive and patch_hive to produce an edited copy.

Large registry values in hive format 1.4 and later use native `db` descriptors
and segment lists above 16,344 bytes. Every segment, including the final one,
has at least 16,344 bytes of capacity; unused capacity and alignment padding
are excluded from decoded values. Complete hive construction and mutable patches preserve
this representation; older hive formats retain direct large-value cells.
Malformed segment counts and truncated segments are rejected. snapshot=True captures at most 512 MiB in an immutable owned reader and lazily indexes decoded keys and case-insensitive children. Native hive_from_patches and patch_hive outputs already own immutable versions: their bytes, lazy indexes and verified SHA-256 are shared by subsequent hive views, without another copy. Patching creates a distinct version. Borrowed inputs are copied for snapshots; default False keeps their live-read behavior and never caches mutable-source metadata.

### `windows.hive_from_patches`

`windows.hive_from_patches(name, patches, keys=None, format=None, source=None, source_drive="", target_drive="", exclude_keys=None, exclude_values=None) -> file`

Builds an NT registry hive from declarative value patches and optional key records. With source, imports its raw value types/data, empty keys, security, class and flags natively before applying keys and patches; the source format is inherited unless format overrides it. Optional source_drive/target_drive (both ASCII drive letters with colons) relocate upper/lower drive spellings in key/value names and raw UTF-16 REG_SZ/REG_EXPAND_SZ/REG_MULTI_SZ data only. exclude_keys removes case-insensitive subtrees from the relocated source: legacy strings accept slash/backslash separators, while key/key_parts dictionaries support lossless literal components. exclude_values contains exact key/key_parts and name dictionaries. Component lists never split literal separators; matching occurs after relocation. Additions are applied after exclusions and are never relocated or filtered. Source options require source. Without source, format controls the generation and metadata is caller-supplied.

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

### `windows.image_digest`

`windows.image_digest(file, algorithm='sha1', maximum_bytes=512MiB) -> bytes`

Computes the CBS HashTransforms.ImageDigest hash, distinct from Authenticode/catalog hashing. Normalizes PE resource/debug layout and hashes the DOS prefix, fixed NT header, rewritten section table and section payloads in table order, excluding resource-directory bytes and .debug payloads. Non-images are hashed verbatim; recognizable malformed or unsupported images fail closed. maximum_bytes (1..512MiB) bounds input, and the transformed stream is capped at 512MiB. No signature or catalog trust is implied.

### `windows.inf`

`windows.inf(file) -> INF`

Parses a Windows INF file into section and entry data, with helpers for install sections and registry patches. directives preserves ordered (section, key, fields) logical rows before string expansion or duplicate grouping, including repeated directives; section markers have key/fields None. json remains the expanded section projection. This is declarative inspection, not execution of every installer directive.

### `windows.inf_patches`

`windows.inf_patches(inf, hive, section='AddReg') -> list[dict]`

Converts a selected INF registry section into patches for the named hive. Returns modifications for later construction rather than changing an existing hive.

### `windows.inherit_file_acl`

`windows.inherit_file_acl(parent, owner, group, directory=False) -> bytes`

Derives auto-inherited ACEs from a bounded parent file ACL and binary owner/group SIDs. Honors OI/CI/NP, adds ID, substitutes creator principals, and prunes ordinary ACEs covered by earlier inherited masks in each effective/object/container domain; callback ACEs are not deduplicated. Supports the layouts of copy_explicit_file_acl plus one mandatory-label ACE with an integrity SID and mask 0..7, preserving even zero policy masks. This does not authorize explicit label assignment or select token-default labels; whole-descriptor inheritance still rejects labels. An empty result means no inherited ACEs, not an instruction to install an empty ACL. Does not select defaults, apply protection, merge explicit ACLs, or construct a security descriptor.

### `windows.inherit_file_security`

`windows.inherit_file_security(source, parent=None, directory=False) -> bytes`

Constructs a bounded self-relative file descriptor with explicit owner/group and auto-inherited ACLs. Selects protected versus unprotected explicit entries, drops old unprotected ID entries, and appends parent inheritance. Preserves absent versus empty ACLs. Matches the token-free RTL flags-0x101b construction path, not access validation or WCP defaulting/final control policy. Source owner/group are required; child NULL ACLs, defaulted controls, unsupported controls and non-revision-2 ACLs fail closed. Parent NULL ACLs contribute no entries and do not create a child NULL ACL. Parent defaults to absent.

### `windows.inherit_registry_security`

`windows.inherit_registry_security(source, parent=None) -> bytes`

Constructs bounded registry-key security with explicit owner/group and container auto-inheritance. Uses key generic rights (read/execute 0x20019, write 0x20006, all 0xf003f), retains generic propagation ACEs, substitutes creator principals, and selects protected versus inherited entries. Shares the file-construction extent and syntax checks; child NULL ACLs, missing principals and unsupported layouts fail closed. Does not select WCP defaults, adjust final request controls, authorize ownership, or assign security to a hive. Parent defaults to absent.

### `windows.internet_shortcut`

`windows.internet_shortcut(url, icon_location='', icon_index=0) -> bytes`

Builds InternetShortcut (.url) bytes for a URL with optional icon location and index. It creates the shortcut contents but does not fetch or open the URL.

### `windows.kd`

`windows.kd(channel, architecture='i386', packet_limit=65535, memory_limit=64MiB, event_queue=512)`

Creates a Windows kernel-debugging protocol session over an existing byte channel. The session exposes packets, events, context and memory operations, bounded by the configured protocol limits.

### `windows.kernel_dump_header`

`windows.kernel_dump_header(file) -> record`

Reads only the fixed 8 KiB Windows PAGE/DU64 kernel dump header, including
one still stored at the start of a guest pagefile. Returns `bugcheck_code`,
`bugcheck_parameters`, `dump_type`, `required_size`, `writer_status`,
`major_version`, `minor_version`, `machine`, `processor_count`,
`directory_table_base`, `pfn_database`, `loaded_module_list`,
`active_process_head`, and `debugger_data_block`.
`extent_available` means the header-declared extent is at least 8 KiB and
fits inside the input; it does not validate the body or prove that the writer
completed. Other dump signatures are rejected. No guest execution or host
debugger is used. This is distinct from the MDMP user-mode minidump reader.

### `windows.kernel_triage_dump`

`windows.kernel_triage_dump(file) -> record`

Reads completed AMD64 PAGE/DU64 type-4 kernel triage dumps without a host debugger. Returns header, context (1232 AMD64 CONTEXT bytes), pc/sp/fp, stack (borrowed file), stack_address, modules (name/base/size/checksum/timestamp), and regions (virtual address plus borrowed file). Regions preserve captured ranges independently, including overlaps; this does not synthesize absent RAM or walk page tables. The triage directory and TRGD completion marker must fit the declared triage extent, itself bounded to 64 MiB and contained in RequiredDumpSpace and the input. Bounds counts before reading tables: at most 4096 drivers, 65536 memory blocks, 1 MiB stack and 32767 UTF-16 code units per name. Secondary streams after the triage extent are not interpreted. No symbol download, automatic stack unwinding or driver attribution is implied; stack words alone are not frames. Borrowed files require the input lifetime. Other dump types and malformed/incomplete ranges fail.

### `windows.map_file_security_rights`

`windows.map_file_security_rights(source) -> bytes`

Maps generic rights in a revision-1 self-relative security descriptor to file-specific masks, preserving all other bytes, ACL states and ordering. Accepts bytes or a file up to 1 MiB. Supports simple allow/deny/audit/alarm and callback-allow ACE layouts; unknown layouts and malformed or overlapping components fail closed. This does not default or inherit security, clear propagation flags, apply filesystem changes, or decide access.

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

### `windows.mrm_index_reference`

`windows.mrm_index_reference(index) -> file`

Encodes a supplied resource index as an MRM resource-reference file. The caller must resolve the correct index from package metadata.

### `windows.mrm_literal_reference`

`windows.mrm_literal_reference(value) -> file`

Encodes a literal string as a native MRM resource-reference file for composition into DMR resource sections.

### `windows.mrm_missing_file_reference`

`windows.mrm_missing_file_reference(package_path, value) -> file`

Encodes the native missing-file resource-reference form using a package path and value. It represents that condition without inventing or creating the referenced file.

### `windows.msc_snapins`

`windows.msc_snapins(file) -> list[string]`

Extracts snap-in identifiers referenced by an MMC console file. Use the identifiers to select registration metadata; the function does not launch MMC.

### `windows.ne_exports`

`windows.ne_exports(source, maximum=64MiB) -> list`

Inspects named and ordinal exports of a native Windows NE image through its existing bounded parser. Returns ordinal, names, segment, offset, file_offset, available bytes, entry flags, movable and constant metadata. Constant exports have no code bytes; unbacked or iterated segment storage is identified without inventing a file offset. maximum bounds input to 64MiB by default. Does not load or execute the module.

### `windows.ne_extend`

`windows.ne_extend(source, code, data, relocations, exports, aliases={}) -> file`

Extends a Windows NE module with fixed code and data segments while preserving original segment storage, imports, resources, and exports. exports maps ordinal to an offset in the new code. relocations contains (source_type, source_offset, target_segment, target_offset) tuples: type 2 is a selector and type 3 a far pointer; target 0 denotes new code, -1 new data, -2 a movable export ordinal in target_offset, and positive values existing segments. Movable export references retain the loader thunk needed when real-mode segments move or are discarded. Each source begins with the 0xffff chain terminator. aliases maps unused ordinals to original ordinals, retaining the original entries and Windows loader prologue patching when wrappers redirect them. Clears stale fast-load metadata. Returns an in-memory file.

### `windows.ne_fastboot`

`windows.ne_fastboot(modules, overlay_path='C:\\WINDOWS\\WIN100.OVL', maximum=64MiB) -> {bin, overlay}`

Constructs the Windows NE fast-boot binary and overlay from supplied modules, returning bin and overlay files. overlay_path is the guest-visible location to encode, not a host output path.

### `windows.ne_imports`

`windows.ne_imports(source, maximum=64MiB, maximum_imports=4096) -> list`

Inspects original imported relocation heads of a native Windows NE image. Each record identifies module, name or ordinal, source segment, offset, source_type and additive flag. Validates module/name tables, segment storage, relocation counts and import targets; maximum bounds input bytes and maximum_imports bounds returned records. Iterated segment relocations are explicitly unsupported. Does not apply relocations, follow loader-linked chains, load or execute the module.

### `windows.ne_internal_references`

`windows.ne_internal_references(source, maximum_references=65536) -> list`

Expands internal NE relocation chains without loading or modifying the image. Returns source segment/offset/type, resolved target segment/offset, original entry ordinal when used, and additive status. Validates chain bounds, cycles, targets, and maximum_references. Imported and operating-system fixups are outside this view; iterated relocation storage is rejected.

### `windows.object_ace`

`windows.object_ace(type, flags, mask, sid, object_type='', inherited_type='') -> bytes`

Builds an allow, deny, audit or alarm object ACE (types 5..8) from a wire SID, access mask, ACE flags and optional object/inherited-object GUID strings. The containing ACL must use revision 4.

### `windows.patch_hive`

`windows.patch_hive(file, patches, root_name='', keys=[], delete_keys=[], delete_values=[], key_flags=[], exclude_keys=[], exclude_values=[]) -> file`

Applies declarative registry patches to an NT hive and returns a new file, optionally replacing the root name. `keys` lists registry paths to create without adding values; existing keys and their values remain intact. This preserves the source hive's layout, including legacy REGF 1.1 cells. The input hive is not edited in place.

Each value patch has
`key` (normalized path) or `key_parts` (literal component list), plus `name`, `type`, and `value`. Literal components preserve slash and dot names and take precedence over `key`. `type` accepts a registry type name or a raw non-negative 32-bit integer for formats such as SAM indexes that encode counts in the type field. Optional `keys` contains registry key paths
to create, including missing parents; existing keys are preserved. Empty keys
remain truly empty, so registry indexes represented by child-key names do not
need placeholder values. New keys inherit their parent's security descriptor. keys also accepts key/key_parts dictionaries with optional raw self-relative security bytes; other key metadata is rejected. delete_keys removes strict existing subtrees; delete_values removes strict existing key/key_parts/name values. Alternatively, exclude_keys and exclude_values resolve a single source-epoch union before edits: duplicate and absent exclusions are harmless, ancestor removals subsume descendants, and recreated keys retain no excluded contents. Exclusions cannot be combined with ordered delete_keys/delete_values; excluding the root is rejected. Exclusion paths are bounded to 512 levels and 1,048,576 distinct trie nodes. Empty value names and (default) identify the default value. Deletions precede key creation and value patches. Optional key_flags records contain key/key_parts and user_flags and/or virtualization_flags (integers 0..15), applied last to strictly existing keys. Each replaces only its persistent nibble; virtualization_flags bit 2 also clears NK KEY_VIRTUAL_STORE, as native class-2 SetInformationKey does. No live cache or timestamp is synthesized. Child-index updates and native source imports preserve packed metadata. Hive keys expose raw NK flags, user_flags and virtualization_flags separately. Missing deletions, deleting the root, cyclic metadata or invalid security fail without changing the input. Each edit list is bounded to 1,048,576 entries. Deletion traversals are bounded to 512 levels and 1,048,576 keys. Updates maintain child indexes, segmented value cells and shared SK references; unrelated class/flags and value bytes are retained.

### `windows.patch_ini`

`windows.patch_ini(source, changes) -> file`

Merges literal section/key string settings into a Windows INI file, matching section and key names case-insensitively. Preserves unrelated lines, commas, and quotes; returns a new file. source=None creates a new INI file.

### `windows.pdb`

`windows.pdb(file, stream_limit=256MiB)`

Parses a PDB symbol file with bounded stream sizes. Exposes identity and symbols, including lookup of the nearest symbol to an RVA; symbol parsing does not download files automatically.

`guid` and `age` describe the PDB Info stream;
`dbi_age` is the independently stored symbol-record age in the DBI stream.
Post-link processing can advance `age` without advancing `dbi_age`.

### `windows.pe`

`windows.pe(file) -> windows.pe`

Creates a lazy inspection object for a PE32 or PE32+ file. Metadata and data share an owned immutable snapshot; read uses RVAs, while patch returns a separate modified file. The explicit resource_files() method instead indexes the ORIGINAL input without copying payload bodies, returning frozen rows with type, name, lang, size and a read-only file view. Unlike resources/data it borrows the input, which must stay stable for all returned file lifetimes; it does not use a previously materialized snapshot or verify hashes/trust. Resource metadata is bounded to 65536 visited entries and 16 nested directories; cyclic directories and out-of-file or out-of-section ranges fail.

### `windows.pe32_executable`

`windows.pe32_executable(section, labels, fixups, imports=None, entry='entry', image_base=0x400000) -> bytes`

Links a labeled section, fixups and optional imports into a minimal PE32 executable. The caller supplies instruction bytes and policy; the builder lays out headers, RVAs and imports and checks fixup bounds.

### `windows.pe32_link`

`windows.pe32_link(object, imports, exports, callbacks=None, import_abi=None, indirect_calls=None, entry='', subsystem=3, version_major=3, version_minor=10, image_base=0x62000000, executable=False, native_dll=False) -> bytes`

Links an in-memory ELF32/i386 cdecl object into a PE32 DLL, executable, or native driver. executable=True requires an entry point; subsystem=2 selects a GUI executable, subsystem=3 a console executable, and subsystem=1 a native driver. native_dll=True marks a subsystem=1 module as a DLL. Imports map DLLs to symbol/argument-word dictionaries; exports and callbacks map symbols to stack-word counts. import_abi optionally selects fastcall instead of stdcall for named imports. indirect_calls maps synthetic symbols to stdcall argument counts: the cdecl caller supplies a function pointer followed by those arguments. Supports R_386_32 and R_386_PC32 relocations; rejects unresolved symbols and unsupported relocations. No OS runtime is linked.

### `windows.pe_sign`

`windows.pe_sign(file, identity, replace=False, page_hashes=False) -> bytes`

Signs a PE32 or PE32+ file with RSA/SHA-256 Authenticode entirely in memory and returns new bytes with an aligned WIN_CERTIFICATE and updated checksum. Preserves sections and overlay data. Existing certificate tables require replace=True. Optional page_hashes=True embeds SHA-256 page hashes. No timestamp, nested signatures, or trust-store changes are generated. See docs/pe-signing.md.

### `windows.pe_signature`

`windows.pe_signature(file) -> record`

Verifies embedded single-signer RSA/SHA-256 Authenticode image integrity using bounded native PE and PKCS#7 parsing. Returns signer DER, embedded certificate DER list, signature bytes, raw unsigned attributes, digest_algorithm, timestamp and secondary_signature_count. The count describes advertised nested signatures, not verified secondary signatures. A recognized Microsoft RFC3161 SHA-256 timestamp is checked for signature integrity and binding to the primary signature; timestamp contains unix seconds, signer DER and certificates, or None when absent. Input is limited to 256 MiB, certificate table to 4 MiB and certificates to 32. Rejects unsigned images, unsupported signature forms and mismatched image/content/signature digests. This is NOT certificate-chain, timestamp-authority trust, expiry, revocation, publisher or Windows trust-policy validation. Other unsigned attributes and CMS v1 attribute certificates are not authenticated or used as trust material. No host roots, clock or network are consulted.

### `windows.pkcs7_certificates`

`windows.pkcs7_certificates(value) -> list[certificate record]`

Extracts distinct embedded DER certificates from PKCS#7/CMS input, including legacy catalogs. Returns certificate records; extraction is deliberately separate from signature or trust verification.

### `windows.press_setup_plan`

`windows.press_setup_plan(inf, media, target="") -> dict`

Plans Microsoft Press SETUP.INI media trees and retains companion SETUP.CMD actions and shortcut dependencies. It does not run the setup executable.

### `windows.pri_resource_candidates`

`windows.pri_resource_candidates(file, section_index, resource_indices, max_bytes=256MiB) -> list[dict]`

Returns structural candidate counts and schema information for selected resource indexes in a PRI resource-map section. It does not choose candidates or decode their values.

### `windows.pri_resource_values`

`windows.pri_resource_values(file, section_index, resource_indices, max_bytes=256MiB) -> list[dict|None]`

Returns a parallel list of sole neutral/default string candidates. Each decoded
entry has `value` (text) and `path` (boolean). Multiple candidates, a sole
non-default candidate, or binary data return `None`: retain the resource index
rather than choosing a locale. Absent resources, unsupported external-file
locators, invalid bounds and malformed encodings are errors. Supports bounded
internal/data-item values in UTF-16, ASCII and UTF-8. Path values are not opened
or trusted as filesystem paths; callers must validate package-relative paths.

### `windows.pri_schema`

`windows.pri_schema(file, section_index, max_bytes=256MiB) -> dict`

Parses a selected PRI schema section into its hierarchy and resource item names. The section index is explicit; parsing does not select locale-specific resource candidates.

### `windows.pri_sections`

`windows.pri_sections(file, max_bytes=256MiB) -> list[dict]`

Parses a bounded PRI container envelope and returns section identities, metadata and payload files. Section discovery alone does not resolve or render resources.

### `windows.reactos_record`

`windows.reactos_record(kind, fields) -> bytes`

Encodes a named ReactOS binary-record kind from declarative fields. Layout and field validation stay in Go while values and operating-system policy remain with the caller.

### `windows.registration_expand`

`windows.registration_expand(value, replacements) -> value`

Expands percent-delimited registration variables in replacement-dictionary order, uppercase token then lowercase token, for at most four passes. Unknown tokens remain unchanged and non-string inputs pass through; this is not general case-insensitive environment expansion.

### `windows.registry31`

`windows.registry31(entries, sources=[]) -> file`

Constructs a Windows 3.1 SHCC3.10 registry file from class-path string entries and optional REGEDIT text source files. Explicit entries override sources; keys match case-insensitively. Uses Windows-1252 strings and rejects output exceeding 64 KiB. Does not launch REGEDIT or modify a live registry.

### `windows.registry_children`

`windows.registry_children(entries, hive, key, values=False) -> dict`

Selects direct children from a self-registration registry-state dictionary. values=True selects direct values; otherwise it derives immediate subkeys, without changing the input or recursively returning descendants.

### `windows.registry_contributions`

`windows.registry_contributions(manifests, resolve_key, expand_string, key_prefix=None, max_records=1048576, max_bytes=268435456, capture_key_records=False, compact_key_records=False) -> dict`

Collects ordinary registry contributions from up to 65536 explicitly admitted manifest rows (dict(root=binary.xml_node, architecture=string, side=before/after, owner=integer 0..2^30)). Traverses asm.v1/v3 registryKeys and validates strict key/value attribute namespaces, keyName, value content, and local security definition/reference uniqueness and presence. Unknown key attributes and unrelated namespaces/children retain the inspection path semantics; this is not a complete manifest schema validator. Supports exact REG_NONE/SZ/EXPAND_SZ/BINARY/DWORD/MULTI_SZ/QWORD spellings, validates mutable/operationHint, ignores IEDownlevelValue data, and preserves raw UTF-16 and unquoted-empty MULTI_SZ provenance. resolve_key(key, architecture) supplies dict(scope, path); expand_string(text, architecture) is called only for macro-bearing names/string data. Both callbacks must be pure for one call, execute on the caller thread, and are memoized only within the call; input rows are captured before callbacks. Architecture policy is checked by the resolver when keys are encountered, not for empty managed assemblies. Returns dict(groups, keys), plus key_records when requested: groups maps (scope, lowercase NT path, lowercase name) to [before, after] lists of (owner, type, raw bytes, mutable, operationHint, unquoted_empty) tuples. Every contributor, duplicate and unchanged value survives in input order; no winner selection. key_prefix=None omits key capture; a string selects a case-insensitive literal NT prefix (empty selects all), with keys mapping (scope, lowercase path) to [first-spelled path, before_present, after_present]. The prefix filters only keys capture, never validation or values. capture_key_records=True separately retains all empty/nonempty key contributions grouped by owner, in input order, as (side, scope, resolved path, key-attribute dict, selected local SDDL or None) tuples. It does not select competing descriptors or interpret their policy. The default omits key_records. compact_key_records=True requires capture_key_records=True and returns immutable windows.registry_key_records instead of owner dictionaries; it validates supported key owner/virtualization/access attributes immediately and retains decoded path/side/owner/security fields without XML or attribute dictionaries. Use registry_key_plan for this representation; the default detailed inspection result is unchanged. max_records defaults/caps at 1048576 processed roots/keys/values/security-path records; max_bytes defaults/caps at 256 MiB of observed attribute/security text, resolved paths and decoded data (including expanded macro text). Each may be lowered, not disabled. Errors return no partial result. No hive/image writes, package admission, profile mounting, security assignment, trust verification, or CBS completion is implied.

### `windows.registry_key_plan`

`windows.registry_key_plan(records, families, value_changes, compile_security, security_matches) -> dict`

Reduces immutable compact registry_key_records into separate system/user dictionaries of immutable mapping-like windows.registry_key_plan_node values. families is a list indexed by transition owner, with (nonnegative family bucket, before identity, after identity) tuples; identities are strings/bytes or None for absent sides. Every recorded side requires an identity. Processes stable (bucket, transition, declaration) order, rejects unequal descriptors at the same path/side/bucket, retains first ownership and collision count separately from last nonempty security, and builds implicit ancestors. value_changes maps (scope, lowercase NT path) to booleans for explicit keys; omitted keys mean unchanged and unknown/implicit keys fail. compile_security(SDDL) must return bytes using the target identity context; security_matches(before bytes or None, after bytes or None) must return a boolean with the asymmetric registry semantics. Both callbacks must be pure; compilation is interned by exact text and comparisons are memoized by ordered text pair per call. Identical nonempty texts bypass comparison. Computes operation/security/auxiliary flags and bottom-up subtree skips; does not assign security or mutate hives. Nodes support string-key indexing for path, parent, before_present, after_present, explicit, hive_boundary, owner, owned_addition_collisions, operation, security_flags, auxiliary_flags, descriptor, old_descriptor, subtree_changed. No per-contribution history or copied dictionaries are retained; use the noncompact collector plus inspection reducers when history is needed. Input families cap at 65536; expanded hierarchy caps at 1048576 nodes and 256 MiB of path/parent text. Errors return no partial plan. All collection validation and full value comparison remain caller prerequisites.

### `windows.registry_partition`

`windows.registry_partition(entries, hive, key, values=False) -> tuple(selected, retained)`

Splits a self-registration registry-state dictionary into selected and retained dictionaries for a hive subtree. values selects the value-identity layout; ordering and payload identity are preserved, and neither result aliases the input dictionary.

### `windows.registry_path_mapper`

`windows.registry_path_mapper(rules) -> callable(key, architecture)`

Compiles an owned, immutable registry redirection table supplied by the recipe. `rules` contains at most 4096 `(canonical_nt_machine_prefix, flags)` tuples; prefixes are at most 32768 bytes, matched case-insensitively at component boundaries. Flags 1 selects redirection and 2 marks an insertion anchor; 0 selects sharing. Longest matching prefix wins, and later equal prefixes replace earlier entries. The returned callable `(key, architecture)` yields a fresh dict with `scope` and canonical NT `path`. Architectures are amd64, x86, wow64. HKLM/HKEY_LOCAL_MACHINE and HKCR/HKEY_CLASSES_ROOT use the table; amd64 preserves their physical paths. HKEY_CURRENT_USER is abstract user scope, not .DEFAULT; explicit HKEY_USERS/.DEFAULT is system scope. Other user roots, macros, NULs, empty interior components, and unsupported explicit WOW placements fail. Trailing declaration separators are removed. No host state or default OS rule table is used; hive mounting, CurrentControlSet resolution, virtualization, security and value expansion remain separate.

### `windows.sam_alias_members`

`windows.sam_alias_members(source) -> list`

Decodes the binary SID vector in an NT5 SAM alias C value supplied as bytes or a portable file, bounded to 16 MiB. Validates header and payload extents, SID encodings and member counts. Does not resolve host accounts or select membership policy.

### `windows.sam_alias_with_members`

`windows.sam_alias_with_members(source, members) -> bytes`

Returns an NT5 SAM alias C value with its member SID vector replaced, preserving unrelated record fields. Accepts a source value bounded to 16 MiB and a list of checked binary SIDs; rejects duplicates. The caller must update the SAM reverse-membership indexes and counts in the same hive construction operation.

### `windows.script_signature`

`windows.script_signature(file, format='powershell') -> record`

Verifies SHA-256 Authenticode PowerShell or CDXML script integrity and recognized RFC3161 timestamp integrity. format is powershell or xml. Accepts strict UTF-8 or BOM-marked UTF-16LE, CRLF signature framing, and no trailing unsigned data. Input limit 16 MiB. Returns pe_signature-compatible metadata, not a certificate-chain or publisher trust decision. No host roots, clock or network.

### `windows.sdk_inf_plan`

`windows.sdk_inf_plan(inf, media, target="", sections=None, locations=None) -> dict`

Plans Windows 3.x SDK disk catalogues from INF declarations, retaining group and environment actions. Sources are decoded natively from supplied media handles.

### `windows.security_descriptor_parts`

`windows.security_descriptor_parts(source) -> dict`

Validates a self-relative Windows security descriptor (at most 1 MiB), including aligned, non-overlapping component extents and ACL entries. Returns `control`, `resource_manager_control`, and binary `owner`, `group`, `sacl`, `dacl` components. Missing components are `None`; ACL presence bits distinguish absent from NULL. Exact same-kind aliases are allowed and unknown ACE bodies remain opaque. This is format inspection, not access checking, inheritance, default selection or a security equivalence predicate.

### `windows.selfreg_patches`

`windows.selfreg_patches(file, module) -> list[dict]`

Derives registry patches from supported self-registration resources in a PE file or windows.pe object, using module for path substitutions. It does not emulate DllRegisterServer; use the self-registration policy/runner for runtime effects.

### `windows.serialized_certificate`

`windows.serialized_certificate(value) -> record`

Parses one SystemCertificates registry Blob into certificate and properties records. Bounds input to 1 MiB and 256 unique properties; requires encoding 1, complete lengths and exactly one certificate property 32. Validates X.509 DER and optional SHA-1 property 3. Preserves all other properties as integer-to-bytes entries without interpreting their trust policy. This is not a trust decision.

### `windows.servicing_graph`

`windows.servicing_graph(psf_index, history_index, psf_payload, targets=None) -> record`

Builds a native cumulative-update dependency graph from PSF and history indexes and a supplied PSF payload. Optional targets restrict inspected nodes; the result describes dependencies rather than applying an update to a running system.

### `windows.servicing_plan`

`windows.servicing_plan(updates, base=None, installed_packages=None, installed_components=None, image='/image3', limit=20) -> record`

Plans cumulative-update assembly stages against a supplied WIM image or declared installed package/component inventory. Returns bounded stage summaries without running Windows servicing or installing the updates.

### `windows.setup_inf`

`windows.setup_inf(file) -> setup_inf`

Parses command-oriented Microsoft setup INF sections with source locations. plan expands known copy catalogues and branches while retaining runtime queries and unknown loops.

### `windows.setver`

`windows.setver(source, name, major, minor, maximum=16MiB) -> file`

Returns a SETVER driver image with the named executable's reported DOS version added or updated. The original source remains unchanged and maximum bounds the processed image.

### `windows.shortcut`

`windows.shortcut(target, short_target='', description='', arguments='', working_dir='', icon_location='', icon_index=0, target_size=0, system_root='') -> bytes`

Builds Windows Shell Link (.lnk) bytes for a target with optional arguments, working directory, description and icon metadata. It serializes a shortcut; it does not resolve or launch its target on the host.

### `windows.sid_string`

`windows.sid_string(source) -> string`

Validates one complete revision-1 binary SID (at most 15 subauthorities) and returns its Windows string form, with a hexadecimal authority when it is at least 2^32. Accepts bytes or a file; no host identity resolution is performed.

### `windows.signing_identity`

`windows.signing_identity(certificate, private_key, chain=[]) -> signing identity`

Loads a DER or PEM X.509 certificate and matching unencrypted PKCS#1/PKCS#8 RSA private key for in-memory PE signing. Optional chain certificates are embedded without establishing trust. The identity exposes only its public certificate; private key material is not printable or exportable.

### `windows.state_repository_dictionary`

`windows.state_repository_dictionary(properties) -> file`

Encodes an ordered dictionary as native SRD1 bytes, returned as an immutable
file. Values may be strings, nested dictionaries, or lists of dictionaries;
other types are rejected. These are wire primitives for AppX XML properties,
not an automatic manifest registration operation. For example,
`{"LaunchPolicy": {"#text": "1"}}` retains the nested text property.

Limits: 1024 entries per dictionary/list, 32 nesting levels, 65536 aggregate
nodes/entries during input conversion, 65534 UTF-16 key bytes, 1 MiB per
string/nested-map payload, and 64 MiB per complete dictionary. Strings are
terminated UTF-16LE; embedded NULs, invalid Unicode and cycles are rejected.

### `windows.state_repository_dictionary_read`

`windows.state_repository_dictionary_read(source) -> dict`

Decodes a file or bytes containing a complete SRD1 dictionary into ordered Starlark dictionaries, booleans, strings and lists of dictionaries. Uses the strict native decoder; rejects unknown types, duplicate keys, truncated extents and excessive depth. Input is limited to 64 MiB before allocation. Property identifiers are preserved, not interpreted.

### `windows.state_repository_hash`

`windows.state_repository_hash(values) -> string`

Computes native StateRepository hash_base32 for a list of NULL, int64, string or bytes values. SHA-256 consumes concatenated LE64 integers, ASCII-lowercased UTF-16LE strings up to their first NUL (without a terminator), and raw bytes; NULL and empty values contribute nothing. Returns 52 unpadded characters using Windows' base32 alphabet. At most 1024 values and 64 MiB of input; floats, booleans and invalid Unicode are rejected.

### `windows.symbol_server`

`windows.symbol_server(base_url, name, key, guid=None, age=None, maximum=256MiB, timeout=45)`

Retrieves a bounded symbol file from a symbol-server layout using its name and identity key, optionally validating against image debug metadata. The GUID must match exactly. Following Microsoft's `PDB1::OpenValidate4`, the Info age must be at least the requested image age, and DBI age must equal the image age (legacy DBI age zero is accepted). A newer Info age alone does not permit a different set of symbol records. Limits and timeout are validated.

### `windows.test_signing_identity`

`windows.test_signing_identity(subject, not_before, not_after) -> signing identity`

Generates an ephemeral RSA-2048 key and self-signed code-signing certificate. not_before and not_after are explicit Unix seconds supplied by the caller. Returns an opaque identity with a public certificate attribute; does not install trust or change driver-signing policy.

### `windows.type_library`

`windows.type_library(value) -> dict`

Reads one standalone MSFT or SLTG type library from a file or bytes, bounded to 16 MiB. Returns the same guid/name/description/version/language/lcid/flags/syskind/types fact dictionary as an element of windows.pe(file).typelibs. Rejects PE containers and unknown signatures; does not register or execute the library.

### `windows.update_catalog`

`windows.update_catalog(device_attributes, caller_attributes, products, locales, user_agent, assume_non_leaf_installed, background=False, network=False) -> windows_update_catalog or windows_update_catalog_request`

Defaults to local-only replay of cached raw catalog responses for the exact caller profile. network=True explicitly synchronizes Windows Update and atomically refreshes this source cache. Missing, damaged or mismatched cached metadata fails without network fallback; cached offers are not a current/latest-offer guarantee. Payload readers inherit the catalog network policy, including lazy reads after boot. Uses explicit device_attributes and caller_attributes string dictionaries, products string, locales list, user_agent, and assume_non_leaf_installed policy. No OS, build, architecture, ring, locale, eligibility or product defaults are supplied. Empty attribute dictionaries are allowed; all arguments are required. Returns an immutable windows_update_catalog with offers (all revisions, including non-leaves), rounds, revision_count and leaf_count. Each offer exposes id, revision, server_id, is_leaf, title, product_release, deployment, update_type, files (name, size, sha1, sha256), prerequisites and bundled_updates. Relationship clauses expose alternatives (id/revision) and is_category. There is no hidden result truncation, preview/client filter or ranking. Select an offer in Starlark and pass it with this catalog to update_media. Catalog discovery downloads metadata only, not payloads or disk images. Optional background=True starts exactly one local replay or explicit synchronization and returns a windows_update_catalog_request; result() waits for the same immutable catalog or original failure without retrying. close() cancels and joins unfinished work; completed results remain readable. Execution cleanup cancels and joins requests automatically. Profile data is copied before launching; no Starlark callbacks run concurrently.

### `windows.update_media`

`windows.update_media(catalog, offer, architecture, edition, language, metadata_name, target_compdb, index_only=False, plan_only=False, metadata_only=False, state_only=False, servicing_only=False, while_preparing=None, installed_stage_limit=0, base=None, image="", bootsect=None, additional_cabinets={}, additional_msus={}, additional_stage_order=[], cache="", wim_cache_bytes=2147483648, verified_cache_bytes=6442450944, servicing_cache_bytes=-1) -> update_media`

Prepares an explicitly selected catalog offer as referenced UUP media, not a complete disk image. catalog must come from update_catalog, and offer must be an original offer from that same catalog. architecture, edition, language, metadata_name (exact aggregated metadata payload name) and target_compdb (composition database name/source) are required caller choices. There is no rescan, fallback offer, ranking or client/preview filter. Dependency closure and signed-location renewal retain the original catalog, request profile, selected revision, declared hashes and sizes. Inspection modes expose metadata or plans without full image construction; servicing uses mandatory reconstructed target hashes. TinyRangeX recipes apply those effects and construct the filesystem, registry and bootable disk.

An optional `base` supplies an existing `archive.wim` instead of downloading a
new base image. It requires an explicit `/imageN` root and a nonempty `bootsect`
file; the selected image must contain SOFTWARE, SYSTEM and COMPONENTS hives.
The returned `image` preserves that selection. This path skips only full-media
hydration, not update dependency or reconstructed-content validation. It can
recover pruned checkpoint bases from the installed component's reverse delta,
expand DCS/LZMS component-store files, and reuse unchanged files from the same
component family only when their declared length and SHA-256 match.

**External-base support is currently inspection-only.** Supply `index_only`,
`plan_only`, `metadata_only`, or `state_only`; ordinary construction is rejected.
Architecture/release compatibility must still be checked by the caller. File
reconstruction and registry-effect enumeration do not implement the complete
CBS ownership/installed-state transaction or all component-manifest actions.
Neither `validate_servicing` nor `servicing_effects` proves that an update is
installed, that a resulting image boots, or that all security updates are
present. Do not substitute a build-number patch or first-boot servicing for
those missing native construction semantics.

The optional `cache` selects the persistent source-range directory for this call (relative paths resolve against the working directory). An empty value preserves the native default. No process-wide environment is changed. Only original source bytes are cached, not constructed images.

The native backend retains downloaded source-media ranges across runs in
`<os.UserCacheDir()>/tinyrangex/uup` (normally
`~/.cache/tinyrangex/uup` on Linux; honors `XDG_CACHE_HOME`). This disk cache
has no automatic capacity eviction and grows only as source ranges are read.
The separate 256 MiB RAM hot cache may evict entries without repeating HTTP.
Decoded source-WIM chunks share a separate lazy 2 GiB RAM ceiling across the
reference ESDs. Windows 11 uses 64 MiB solid chunks; even its initial font set
exceeds the generic archive cache. This is independent of the 6 GiB compressed
serviced-file cache. Initially verified servicing outputs enter that bounded
cache as immutable compressed bytes; cache hits reuse them, while evicted files
are reconstructed and hash-verified again on demand.
Budget these ceilings together with guest memory when
limiting a native smoke run; unused cache capacity is not allocated eagerly.
Cache identity includes the declared SHA-256, payload size and byte range,
not the signed URL or filename. Atomic publication and cross-process locks
prevent partial cache hits and duplicate simultaneous downloads. Cached ranges
are checksummed on disk reads; invalid entries or cache I/O failures stop with
an error instead of silently fetching again. Range checksums do not replace
mandatory reconstructed-file hash verification. New source ranges, failed
downloads and update discovery/location renewal can still require network
requests. Only source bytes are persisted, not parsed or constructed stages.

The returned source exposes `validate_servicing(collect_errors=False,
error_limit=16, feature_id='', on_error=None, source_names=None)`. It reconstructs and fully reads each planned installed-OS
servicing file, retaining strict delta hash verification. By default the first
failure aborts validation. With `collect_errors=True`, validation continues and
returns per-stage `ok`, `verified_count`, `failed_count`, and a bounded `errors`
list of `{feature_id, name, error}` records, alongside `feature_id`, `file_count`, and
successfully verified `bytes`. `error_limit` must be between 1 and 1000; it
limits reported examples, not the number of files checked. Collection is for
inspection and does not permit failed bytes into image construction.
An optional `feature_id` restricts inspection to one installed-OS stage; an
unknown feature is an error.
Optional nonempty `source_names` requires `feature_id`, selects exact logical
source names case-insensitively, and rejects unmatched names. All matching plan
effects remain in their original order; counts cover only the selected effects.
With collection enabled, `on_error(record)` optionally receives each retained
failure immediately (at most `error_limit` calls per stage); callback errors
abort inspection. It is useful for bounded REPL observations during a long scan.
`servicing_only=True` with index_only and an explicit base returns only the full servicing_metadata, open_resident_component and open_resident_components interfaces plus source identity fields. The batch `open_resident_components(identities, workers=4)` accepts a list of at most 65536 exact identity bytes, preserves order and unavailable None entries, and validates each manifest exactly as the single-reader method. Workers are bounded to 1..8; errors join all native workers and return no partial list. No Starlark callbacks run on workers. `source.servicing_metadata(feature_id).open_packages(packages, workers=4)` opens at most 4096 exact package names on 1..8 native workers, preserving order and duplicates as fresh owned parsed snapshots. Every MUM receives the same identity and package-declaration validation as open_package. All workers join before an error is returned; the lowest failing input determines the error and no partial list escapes. It does not infer admission or prune unavailable references. `source.servicing_metadata(feature_id).plan_components(identities, manifests=None)` plans exact store-only components. Optional `manifests` is an equally sized list of immutable files previously returned by that same metadata index's `open_component`; it reuses their validated snapshots rather than reopening/reparsing source metadata. A foreign index, ordinary equal-byte file, mismatched identity, duplicate component, or wrong length fails without a partial plan. This carries source provenance, not admission, catalog trust or installation authorization. No additional parsed-manifest cache is retained. The returned staging plan exposes `cache_stats()` for its bounded decoded-payload cache: hits, misses, loads, loaded_bytes, load_nanoseconds, evictions, retained_bytes, peak_retained_bytes and entries. load_nanoseconds sums loader wall time (including failures); concurrent loads overlap, while hits and single-flight waits are excluded. Each call returns an independent read-only snapshot; observing it does not reconstruct files, evict content or authorize installation. Retaining only this callable does not retain the staging inventories. It binds the same ordered reconstruction stages but omits preliminary CSI ownership/effect plans that authoritative recipe admission replaces. It cannot combine with other inspection modes or a stage limit, does not prune metadata, and does not provide installed-state or boot-media proof. Optional `while_preparing` (servicing_only only) runs once with no arguments on the caller interpreter thread beside native source preparation. It must not mutate the shared immutable WIM, source readers, or catalog. Its return is ignored; callback errors and native failures return no source, after joining the worker. Progress is bounded and delivered on the caller thread after joining. This is overlapping construction, not deferred integrity verification.

`index_only=True` skips canonical CAB resource hydration. Missing bases in
that mode are not by themselves decoder failures; complete image validation
requires fully hydrated media (`index_only=False`). An external WIM already
contains its own base resources, but its inspection result is still not
production boot media.

`source.servicing_effects(include_files=False)` inspects planned registry values and key declarations
without reconstructing or retaining servicing files. Its `files` list is empty;
the default `include_files=True` also returns verified file effects. These are
construction primitives, not a completed CBS transaction.
`registry_keys` contains ordered records with `key`, `architecture`, and
`feature_id`, independently of `registry_values`. Empty CBS index keys must
be created as keys, not as invented default values.
Each registry effect includes `operation_hint` from the manifest (empty when
absent). Preserve this field when translating effects to hive patches:
`operationHint="append"` contributes members to an existing `REG_MULTI_SZ`
through the native patch writer's `append=True`; it must not replace the value.
`operationHint="prepend"` uses `prepend=True`: contribution members precede
existing members, preserving contribution order and removing case-insensitive
duplicates. Reapplying the contribution is idempotent. Both values must be
`REG_MULTI_SZ`; prepend cannot be combined with another patch operation.

`source.inspect_servicing_files(name="", destination_prefix="", limit=100)`
returns bounded planned file metadata without opening payloads. Supply an exact
source/store basename or a destination prefix; both selectors are case-insensitive,
normalize slash direction, and form a union. Results preserve stage/plan order.
`files` contains feature ID, architecture, source name/mode, store path and
destinations; `total` counts all matches and `truncated` reports omitted matches.
`limit` is 0–1000. This is placement inspection, not reconstruction or hash proof.

`source.inspect_servicing_packages(feature_id="", offset=0, limit=100)`
returns selected package manifest metadata in stage/file-plan order. Records in
`packages` contain feature_id, package (canonical CBS identity), source_name and
store_path; the latter opens with `open_servicing_file`. Aggregate update.mum
transport names are not CBS identities. Optional feature matching is
case-insensitive; unknown features are errors. `total`, `next_offset` and
`has_more` support pagination, with nonnegative offset and limit 0–1000. This
lists the selected closure, not final CBS states or all transport MUMs.

`source.inspect_servicing_components(feature_id="", name_prefix="", offset=0, limit=100)`
returns selected component metadata without opening payloads. Optional feature
and component-name prefix filters are case-insensitive and intersect. Unknown
features are errors. `components` records contain feature_id, name, version,
architecture, language, stem, previous_stem, store_path, staged_only and selected_by.
`store_path` is usable with `open_servicing_file`. A nonempty `previous_stem`
identifies the planner's latest known predecessor, possibly from an earlier
stage; it does not by itself prove that predecessor is the active runtime winner.
Results preserve stage/plan order. `total` counts matches, `next_offset` and
`has_more` support pagination. Offset must be nonnegative; limit is 0–1000.
A zero limit counts matches without advancing. This is inspection only, not
proof of installed ownership, completed actions or successful servicing.

`source.inspect_servicing_ownership(feature_id="", deployment_name="", offset=0, limit=100)`
returns planned deployment/component ownership edges, including unchanged resident
components. Optional exact deployment-name and feature filters intersect and are
case-insensitive. Unknown features are errors. `edges` records contain feature_id,
deployment, deployment_version, deployment_architecture, active, source_count,
component and component_stem. `active` describes the deployment's sources, not
whether a shared component is active through another deployment. Pagination is
over edges, so large deployments remain bounded; `total`, `next_offset`,
`has_more`, and offset/limit semantics match component inspection. This is an
ownership plan, not proof that CBS registry changes or component actions ran.

`source.servicing_plan` also reports csi_component_count, csi_deployment_count and
csi_owner_count. These count exact component/owner records and catalog-backed
canonical deployment descriptions. Every deployment root hash must occur in
every source package catalog. This verifies membership, not certificate trust,
and does not apply the planned CBS records or complete servicing.

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

### `windows.winsock_catalog_item`

`windows.winsock_catalog_item(library, protocol, provider, catalog_id) -> bytes`

Builds a Windows NT Winsock 2 Protocol_Catalog9 PackedCatalogItem from an ASCII guest DLL path, 628-byte WSAPROTOCOL_INFOW record, 16-byte Windows-order provider GUID, and nonzero catalog ID. Preserves the transport helper's protocol fields while assigning its provider and catalog identity.

### `windows.wmi_repository`

`windows.wmi_repository(files=None, documents=None, default_namespace='root\cimv2', server_name='')`

Parses supplied repository files, builds an NT5 repository from MOF documents alone, or appends documents to supplied modern repository files. Modern append preserves the original object store, imports existing class layouts and defaults, rejects replacement identities, and rebuilds a checksummed index with three ordered mapping checkpoints. No WMI service or compiler is executed. Modern repositories expose class_layout(namespace, name) and instances(namespace, name); intrinsic classes resolve through __SYSTEMCLASS. Creating a namespace still requires explicit policy for its __NAMESPACE entry, __thisNAMESPACE security descriptor and __SystemSecurity singleton; parsing or appending MOF does not infer namespace security.

### `windows.wow64_registry_key`

`windows.wow64_registry_key(key) -> string`

Maps a 32-bit logical key to its physical AMD64 registry path using Windows 7
and later shared/redirected-key rules. Explicit WOW6432Node paths are not
redirected again. It does not implement older registry reflection semantics.

### `ar` value

An ordered ar member inventory. entries/files expose member records and file views; find(name, occurrence=0) selects a particular occurrence when an archive repeats a member name.

Methods and attributes: `entries`, `files`, `find(name, occurrence=0)`.

### `ar_entry` value

One ar member, combining ownership, mode and timestamp metadata with a file view of its payload. Byte reads and slices operate on this member, not on the enclosing archive.

Methods and attributes: `binary`, `bytes`, `gid`, `hex`, `mode`, `mtime`, `name`, `read`, `size`, `slice`, `uid`.

### `auto` value

A lazy standardized file or directory node. metadata describes the selected source and probes its contents; summary returns entry metadata without probing. files lists immediate children, and indexed paths or find recursively enter nested containers. file retains the original bytes; compressed containers expose their decoded children without an extra path component. page reads a bounded child listing. Nodes created by auto_plan expose directory-derived proposals through plans; follow a proposal's path to open its virtual filesystem. Plain auto returns no plans.

Methods and attributes: `bytes(offset=0, size=remaining)`, `file`, `files`, `find(path)`, `metadata`, `name`, `page(offset=0, limit=100)`, `plans`, `slice(offset=0, size=remaining)`, `summary`.

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

An immutable namespace-aware element. child/children_named select direct children and attribute performs a named lookup; direct_text excludes descendants while text includes their text. select_descendants batches up to 64 unique names in one namespace-aware traversal, returning a frozen name-to-tuple mapping of the original immutable nodes in document order. The receiver is excluded unless include_self=True; all visited node occurrences count toward maximum (at most 1,048,576), with depth bounded to 256 even for edited trees. Failure returns no partial selection. with_children and with_text return edited nodes without changing the original.

Methods and attributes: `attribute(name, default=None, namespace='')`, `attributes`, `bytes(maximum=16MiB)`, `child(name, namespace='')`, `children`, `children_named(name, namespace='')`, `direct_text`, `name`, `namespace`, `prefix`, `qualified_name`, `select_descendants(names, namespace='', include_self=False, maximum=1048576)`, `text`, `with_children(children)`, `with_text(text)`.

### `block_device` value

A random-access block device with declared geometry and capabilities. read/write, zero and trim address byte ranges; extents reports range layout, flush requests durability, and snapshot/commit are available only where supported. stats exposes backend counters.

Methods and attributes: `capabilities`, `commit()`, `extents(offset, length)`, `flush()`, `geometry`, `read(offset, size)`, `size`, `snapshot()`, `stats`, `trim(offset, length)`, `write(offset, value)`, `zero(offset, length)`.

### `byte_channel` value

An owned bidirectional byte transport. read requests a specified amount, read_some returns available bytes within its bound/timeout, write sends bytes, and close releases the endpoint. Channel operations do not imply any particular wire protocol.

Methods and attributes: `close()`, `name`, `read(size, maximum=8MiB)`, `read_available(maximum=64KiB)`, `read_some(maximum=64KiB, timeout=30)`, `write(value)`, `write_available(value)`.

### `byte_view` value

A bounded random-access view of binary data. slice derives a subview, bytes reads a range, find returns a match position, find_all collects bounded matches, and find_indices searches several needles. compare performs the requested binary comparison without advancing a cursor.

Methods and attributes: `bytes(offset=0, size=remaining)`, `compare(other, signed=False, exact=False)`, `find(needle, start=0, end=size)`, `find_all(needle, start=0, end=size, limit=1M)`, `find_indices(needles, start=0, end=size)`, `size`, `slice(offset=0, size=remaining)`.

### `clock.profiler` value

An explicit instrumentation collector. span/end time a region, measure wraps a call and counter adds a named quantity. snapshot exposes current measurements and report applies the requested coverage criterion.

Methods and attributes: `counter(name, amount=1)`, `measure(name, function, *args, **kwargs)`, `report(minimum_coverage=0.95)`, `snapshot()`, `span(name)`.

### `clock.read_profiler` value

Wraps borrowed sources with file(source, label). snapshot returns detached dictionaries of per-label latency, bytes, errors and bounded slowest reads; reset starts a new phase and excludes earlier in-flight calls. Reads are not serialized and source bytes/errors are preserved. Nested labels measure inclusive latency and must not be summed as exclusive work.

Methods and attributes: `file(source, label)`, `reset()`, `snapshot(limit=100)`.

### `clock.span` value

An open timed region belonging to a profiler. end() closes the region and returns its elapsed duration in seconds.

Methods and attributes: `end() -> elapsed seconds`.

### `compiledModule` value

A compilation result rather than an automatically executed program. Check ok and diagnostic before using binary; outputs maps virtual output names to immutable bytes.

Methods and attributes: `binary`, `diagnostic`, `ok`, `outputs (immutable dict of virtual output names to bytes)`.

### `crypto.hasher` value

A mutable incremental digest. update feeds binary input, sum returns the current digest without clearing state, and reset discards accumulated input. Frozen hashers cannot be updated or reset.

Methods and attributes: `reset()`, `sum()`, `update(value)`.

### `database.ese` value

A portable ESE file reader. rows resolves Windows 2000 separated long values. index_entries returns persisted ordered key/data byte pairs: secondary data is the primary bookmark, while primary data is the encoded record. maximum bounds returned entries. verify checks stored pages without running a host database engine.

Methods and attributes: `index_entries(table, index, maximum=100000)`, `info`, `rows(table, maximum=100000)`, `tables`, `verify()`.

### `directory` value

A mutable in-memory directory tree. write adds file content, mkdir creates directories, find retrieves an entry and remove deletes one. list_dir(path) returns sorted absolute paths of immediate files and directories (including empty directories); missing paths return an empty list. Paths are normalized but case-sensitive. Listings reflect mutations and are independent mutable lists. path_names(lower=False, include_empty=True, readonly=False) returns an independent dictionary of all file and directory paths (including root and empty directories), without reading file contents. Values retain exact spelling; lower=True lowercases lookup keys and rejects colliding file names. Directory spelling follows the first sorted descendant file; empty directories fill remaining names in sorted order. include_empty=False returns only files and their ancestors. readonly=True returns a shared frozen dictionary for the current namespace generation. Content or metadata updates do not invalidate that generation; structural edits do. path_index(lower=False, include_empty=True) provides the same namespace as an immutable native mapping with string keys, get, keys, values and items; enumeration is sorted and returned lists are independent. It avoids dictionary construction for lookup-only callers. Later namespace changes do not alter any returned snapshot. Attributes and security descriptors are stored as image-construction metadata; fat_short_path reports the FAT-compatible short-name path.

Methods and attributes: `fat_short_path(name)`, `files`, `find(path)`, `get_security(name)`, `list_dir(path)`, `mkdir(name)`, `path_index(lower=False, include_empty=True)`, `path_names(lower=False, include_empty=True, readonly=False)`, `remove(name)`, `set_attributes(name, readonly=False, hidden=False, system=False, archive=False)`, `set_reparse(name, tag, data)`, `set_security(name, descriptor)`, `write(name, value)`.

### `emulator.execution` value

A retained in-process execution that can be advanced with a bounded run. done distinguishes completed execution from a suspended one; close releases it and closed records that lifecycle state. It is not a QEMU snapshot. AMD64 executions expose read-only stack.low and stack.high bounds, zero after stack release; running them temporarily selects their own machine stack bounds.

Methods and attributes: `close()`, `closed`, `done`, `run(instruction_limit=0)`.

### `emulator.machine` value

The AMD64 execution context returned by emulator.machine for a 64-bit target; x86 targets use the emulator.x86 value. Calls marshal Windows x64 integer arguments, while hooks and provided exports model APIs. imports_named filters import records and provide_exports binds an ordered name-to-argument-count table. Memory/register methods affect guest state; snapshot copies the context, but callback closure state is not independently forked. See [emulation](../emulation.md) for architecture-specific behavior.

Methods and attributes: `allocate(size=0, value=None, address=None, alignment=16, name='allocation', readable=True, writable=True, executable=False)`, `architecture`, `arguments(count)`, `call(address, args=[])`, `call_export(name, args=[])`, `entry`, `free(address)`, `get_register(name)`, `hook(callback, module='', name='', ordinal=0, address=0, argc=0, convention='win64')`, `imports`, `imports_named(names)`, `invoke(address, args=[])`, `load_module(image, name)`, `local_unwind(frame, target)`, `mappings`, `modules`, `pointer_size`, `profile(limit=256, reset=False, calls=None)`, `protect(address, size, readable=True, writable=False, executable=False)`, `provide_export(callback=None, module, name|ordinal, argc=0, convention='win64', value=None, writable=True)`, `provide_exports(callback, module, signatures, convention='stdcall')`, `read(address, size)`, `read_cbytes(address, maximum=32KiB, require_terminator=True, unit_width=1)`, `read_cstring(address, maximum=32KiB, encoding='ascii')`, `read_f32be(address)`, `read_f32le(address)`, `read_f64be(address)`, `read_f64le(address)`, `read_i16be(address)`, `read_i16le(address)`, `read_i32be(address)`, `read_i32le(address)`, `read_i64be(address)`, `read_i64le(address)`, `read_i8(address)`, `read_pointer(address)`, `read_u16be(address)`, `read_u16le(address)`, `read_u32be(address)`, `read_u32le(address)`, `read_u64be(address)`, `read_u64le(address)`, `read_u8(address)`, `resolve_export(module, name='', ordinal=0)`, `run(entry=None, instruction_limit=current, until=None)`, `segment_base(segment)`, `set_register(name, value)`, `snapshot()`, `stack`, `stop(reason, detail='', value=None)`, `transfer(address, stack_pointer=current_rsp)`, `use(plugins)`, `write(address, value)`, `write_f32be(address, value)`, `write_f32le(address, value)`, `write_f64be(address, value)`, `write_f64le(address, value)`, `write_i16be(address, value)`, `write_i16le(address, value)`, `write_i32be(address, value)`, `write_i32le(address, value)`, `write_i64be(address, value)`, `write_i64le(address, value)`, `write_i8(address, value)`, `write_pointer(address, value)`, `write_u16be(address, value)`, `write_u16le(address, value)`, `write_u32be(address, value)`, `write_u32le(address, value)`, `write_u64be(address, value)`, `write_u64le(address, value)`, `write_u8(address, value)`.

### `emulator.plugin` value

A named installation callback with explicit mutable state and optional caller-defined attributes. The emulator calls install(machine) when attaching the plugin; state makes checkpoint participation explicit instead of relying on closure-hidden mutations.

Methods and attributes: `install(machine)`, `name`, `state`.

### `emulator.x86` value

A bounded 32-bit guest execution context. run/call/invoke execute modeled instructions; hooks and provided exports bind guest API calls to callbacks. Read/write and register methods inspect or change guest state. checkpoint/restore and snapshot support controlled variants; tracing, watches and profiles provide bounded observations. Acceleration/rewrite/transform operations require their documented code-identity checks; see [emulation](../emulation.md) for their contracts and checkpoint limitations.

Methods and attributes: `accelerate_loop(address, pattern=None, size=0, digest=None, normalize_relative=False, maximum_instructions=1Mi)`, `accelerate_region(entry, start, size, digest, reenter=False, maximum_instructions=1Mi)`, `accelerate_runtime_region(anchor, size, digest, entry_offset=0, anchor_mask=None, name='runtime executable region', normalize_relative=True, reenter=False, maximum_instructions=1Mi)`, `allocate(size=0, value=None, address=None, alignment=16, name='plugin', readable=True, writable=True, executable=False)`, `call(address, args=[], registers={})`, `call_export(name, args=[], registers={})`, `call_trace(reset=False)`, `checkpoint()`, `code_trace(watch, reset=False)`, `configure_call_trace(enabled=True, limit=unchanged, start=0, size=0, reset=True)`, `configure_trace(enabled=True, limit=unchanged, reset=True)`, `entry`, `free(address)`, `get_register(name)`, `hook(...) and use(plugins)`, `imports`, `imports_named(names)`, `invoke(address, args=[], registers={})`, `load_module(image, name)`, `mappings`, `memory_writes(watch, reset=False)`, `modules`, `override(callback, module, name|ordinal, wrap=False)`, `profile(limit=256, reset=False)`, `protect(address, size, readable=True, writable=False, executable=False)`, `provide_export(callback=None, module, name|ordinal, argc=0, convention='stdcall', value=None, writable=True)`, `provide_exports(callback, module, signatures, convention='stdcall')`, `read_cbytes(address, maximum=32KiB, require_terminator=True, unit_width=1)`, `read_f32be(address)`, `read_f32le(address)`, `read_f64be(address)`, `read_f64le(address)`, `read_i16be(address)`, `read_i16le(address)`, `read_i32be(address)`, `read_i32le(address)`, `read_i64be(address)`, `read_i64le(address)`, `read_i8(address)`, `read_u16be(address)`, `read_u16le(address)`, `read_u32be(address)`, `read_u32le(address)`, `read_u64be(address)`, `read_u64le(address)`, `read_u8(address)`, `restore(checkpoint)`, `rewrite(address, pattern=None, size=0, digest=None, callback, name='inline rewrite', normalize_relative=False)`, `run()`, `set_register(name, value)`, `snapshot()`, `spawn(address, args=[], registers={})`, `stack`, `stop(reason, detail='')`, `transfer(address, esp=None, ebp=None, return_address=None)`, `transform(anchor, size, digest, callback, anchor_mask=None, name='runtime transformation', normalize_relative=True)`, `u32_multiply_accumulate(destination, source, count, scalar, carry=0, subtract=False)`, `watch_code(address, size, limit=4096, stack_bytes=0, captures={})`, `watch_memory(address, size, limit=4096)`, `write_f32be(address, value)`, `write_f32le(address, value)`, `write_f64be(address, value)`, `write_f64le(address, value)`, `write_i16be(address, value)`, `write_i16le(address, value)`, `write_i32be(address, value)`, `write_i32le(address, value)`, `write_i64be(address, value)`, `write_i64le(address, value)`, `write_i8(address, value)`, `write_u16be(address, value)`, `write_u16le(address, value)`, `write_u32be(address, value)`, `write_u32le(address, value)`, `write_u64be(address, value)`, `write_u64le(address, value)`, `write_u8(address, value)`.

### `file` value

Portable random-access byte value. Reader-backed SCS files and slices borrow their repository lifetime and are immutable versions. read/bytes explicitly materialize data; slice and splice compose borrowed ranges without eager payload reads. splice returns a new file, not an edit to its source; write it back explicitly. Existing file implementations may offer additional format-specific attributes.

Methods and attributes: `binary(offset=0, size=remaining)`, `bytes(offset=0, size=remaining)`, `hex(offset=0, size=remaining)`, `read()`, `size`, `slice(offset=0, size=remaining)`, `splice(offset, remove, value)`.

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

Methods and attributes: `container`, `files`, `find(path)`, `format`, `installscript`, `offset`, `payload`, `plan(locations={}, variables={}, components=None, local_files=None, ranges=None)`, `size`.

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

### `scs.repository` value

Owns portable SCS storage and immutable objects. clone imports full advertised Git history natively, retaining no host checkout or pack spool; compressed transport stays in bounded paged memory. Git checkout is lazy. Native workspace publication is distinct from Git commits and does not push. file returns an immutable standalone repository artifact only for snapshot-capable backends (memory); publish live edits first. Opening/checkpointing can repair derived state. No GC, synchronization or format-stability promise.

Methods and attributes: `checkout(name)`, `checkout_git(revision='HEAD', catalog='git')`, `checkpoint()`, `clone(url, catalog='git', max_pack_bytes=256MiB, max_native_bytes=512GiB)`, `close()`, `empty()`, `file()`, `git_refs(catalog='git')`, `refs()`.

### `sfp` value

A parsed SFP package inventory. entries/files expose member metadata and content, find selects a path, and package_label/version identify the package. archive_size/data_offset describe the enclosing container.

Methods and attributes: `archive_size`, `data_offset`, `entries`, `files`, `find(path)`, `package_label`, `version`.

### `sfp_entry` value

An SFP member with its logical path, entry type, timestamps and stored/unpacked lengths. Its read/bytes/slice operations expose decoded member content while payload_offset/record_offset locate its archive records.

Methods and attributes: `binary`, `bytes`, `created_time`, `entry_type`, `file_length`, `flags`, `hex`, `modified_time`, `name`, `parent`, `path`, `payload_offset`, `read`, `record_offset`, `size`, `slice`, `stored_size`.

### `shell_result` value

Completed shell invocation. status is the ordinary numeric exit status, steps is the consumed statement budget, and stdout/stderr are independently bounded captured byte strings. Capability, parser and budget failures raise errors instead of becoming negative feature probes.

Methods and attributes: `status`, `stderr`, `stdout`, `steps`.

### `tar` value

An ordered tar archive view. entries/files retain metadata and payload views; find(path, occurrence=0) selects repeated paths without losing earlier archive entries.

Methods and attributes: `entries`, `files`, `find(path, occurrence=0)`.

### `tar_entry` value

A tar member with path, type, ownership, permissions, timestamp and link target. Payload reads are relative to the member; entry_type and link distinguish regular content from directories and links.

Methods and attributes: `binary`, `bytes`, `entry_type`, `gid`, `gname`, `hex`, `link`, `mode`, `mtime`, `name`, `path`, `read`, `size`, `slice`, `stored_size`, `uid`, `uname`.

### `tcp_bridge` value

An owned native loopback listener forwarding one TCP connection to one byte channel. port is the assigned IPv4 loopback port; close interrupts and joins its workers and closes both transports. The listener is single-use and closes after acceptance. No authentication, protocol interpretation, automatic reconnect, or replay is provided.

Methods and attributes: `close()`, `port`.

### `unix_filesystem` value

A bounded mutable Unix namespace shared directly by shell, compiler and ELF execution. write accepts ordinary portable file values; find returns an immutable file snapshot rather than a live descriptor. Modes and Unix-second timestamps are explicit. Missing paths and invalid canonical absolute guest paths raise errors; host paths are never accessed.

Methods and attributes: `find(path)`, `mkdir(path, mode=0o755, mtime=None)`, `remove(path)`, `stat(path)`, `write(path, data, mode=0o644, mtime=None)`.

### `unix_stat` value

Unix file metadata: byte size, permission bits, directory flag and Unix-second modification time. Permission bits support virtual probes, not a host security boundary.

Methods and attributes: `directory`, `mode`, `mtime`, `size`.

### `video_recording` value

Continuous wall-clock video capture, independent of script input. stop() finalizes and returns the MP4 file; repeated stop returns the same video. close() aborts/discards. stats contains frames, duplicated (missed sampling slots filled with the previous frame), elapsed seconds and done. Stop before stopping/closing the VM; VM teardown aborts owned recorders. QEMU requires FFmpeg with libx264; no audio or host display server. Captures into a fixed letterboxed canvas at a fixed rate. Upscaling uses integer factors; sources larger than the canvas downscale with nearest-neighbor. Default is 1440x900/30fps, libx264 CRF10/YUV420. lossless=True uses libx264rgb CRF0/RGB without color subsampling; the encoded canvas is pixel-exact, but browser playback is not guaranteed. Guest resolution changes are supported. duration auto-finalizes; output/capture/encoder failures are reported by stop, not silently accepted as success. Bounds: even dimensions 2..4096, at most 4096x2160 pixels, 1..60 fps, maximum 1KiB..512MiB, duration (0,3600] seconds. For boot capture: start_paused=True, recorder=vm.record(), vm.resume(), then video=recorder.stop().

Methods and attributes: `close()`, `stats`, `stop() -> file`.

### `vm` value

A live virtual machine. Input helpers send guest keys, text or pointer events; screenshot captures the display. resize(width, height, timeout=60) requests an exact live guest resolution and returns only after it is applied; resize_ready reports current guest-driver readiness. Unsupported modes, guest rejection, and timeout raise errors. Cancellation does not undo a mode change already in progress. pause/resume/reset/powerdown/shutdown/stop control lifecycle, wait observes completion and next_event consumes events. channel and debugger open declared guest endpoints; extensions expose backend-specific features. Check capabilities before using optional operations.

Methods and attributes: `backend_id`, `capabilities`, `channel(name, timeout=30)`, `chord(keys)`, `debugger(protocol, create=False, paused=False, timeout=30)`, `detach()`, `extension(name)`, `has_capability(name)`, `key(key, down=True)`, `next_event(timeout=-1)`, `pause(timeout=30)`, `pointer(x=0, y=0, absolute=False, buttons=[], wheel=0)`, `powerdown(timeout=30)`, `record(width=1440, height=900, fps=30, maximum=64MiB, duration=600, lossless=False)`, `reset(timeout=30)`, `resize(width, height, timeout=60)`, `resize_ready`, `result`, `resume(timeout=30)`, `running`, `screenshot(format='png', timeout=30)`, `send_keys(keys)`, `send_text(text)`, `shutdown(timeout=30, force=True, force_timeout=10)`, `status`, `stop(timeout=30)`, `tap(key)`, `type_and_enter(text, enter='enter')`, `wait(timeout=-1)`.

### `vmm_arm64_boot` value

Portable raw ARM64 handoff containing an immutable firmware image, physical load/entry addresses, RAM base. Optional Darwin handoff metadata exposes encoded NVRAM and an immutable kernel-prefix range; hardware platform selection is separate. CPU register configuration belongs to the handoff; native execution belongs to the selected backend.

Methods and attributes: `address`, `entry`, `image`, `memory_base`, `nvram`, `read_only_address`, `read_only_size`.

### `vmm_arm64_runtime` value

VM-owned guest resource access for an ARM64 platform factory. Exposes memory_base, memory_size, disks, epoch_microseconds, read_memory(address,size), write_memory(address,data), protect_memory(address,size,read=True,write=False,execute=True), counter(), irq(id,level), read_register(id), write_register(id,value), emit(kind,payload=None), and device(kind,options). Native device options and lifecycle are documented in docs/arm64-platforms.md. Runtime operations are revoked when the VM stops; no host paths or native handles are exposed.

Methods and attributes: `counter`, `device`, `disks`, `emit`, `epoch_microseconds`, `irq`, `memory_base`, `memory_size`, `protect_memory`, `read_memory`, `read_register`, `write_memory`, `write_register`.

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

### `vmm_linux_boot` value

Direct Linux boot intent containing borrowed immutable kernel and optional initramfs files and a command line. These inputs remain portable; a capable backend owns their transport and lifetime.

Methods and attributes: `command_line`, `initramfs`, `kernel`.

### `vmm_machine` value

A portable VM specification, not a live VM. It records architecture, resources, disks, networks, channels, display and required capabilities for backend validation and vmm.start.

Methods and attributes: `architecture`, `boot`, `channels`, `cpus`, `disks`, `display`, `memory`, `networks`, `platform`, `required_capabilities`, `start_paused`.

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

Methods and attributes: `age`, `dbi_age`, `guid`, `nearest(rva)`, `signature`, `symbols`.

### `windows.pdb_symbol` value

One PDB symbol record containing its name, kind and relative virtual address. It identifies metadata in the parsed module, not an automatically resolved live-process address.

Methods and attributes: `kind`, `name`, `rva`.

### `windows.pe` value

A lazy PE32/PE32+ inspection value. Metadata attributes expose headers, sections, imports, delay_imports, exports, resources, strings and debug/type-library data from an owned snapshot. delay_imports reports named and ordinal imports with normalized table/IAT RVAs, supporting PE32/PE32+ and legacy VA descriptors. api_set_extension reads version 7 extension contracts, counted hosts/aliases and opaque dispatch metadata without changing their bytes or signatures. Use windows.api_set_namespace for version 6 base namespaces. defender_definition reads the supported RMDX resource header and returns source created_unix/created_filetime metadata, or None when the resource is absent; malformed/ambiguous headers are rejected. It does not decompress definitions or verify signatures, trust, installation or freshness. Type-library registration metadata supports MSFT and SLTG resources. read/disasm use RVAs; patch returns modified file bytes without changing the original. data provides the shared immutable source snapshot. resource_files() explicitly borrows the original input instead, returning frozen type/name/lang/size/file rows without copying resource bodies. Its files require stable source bytes throughout their lifetime, even if this PE object already owns a different materialized snapshot. This is neither hash nor trust verification.

Methods and attributes: `api_set_extension`, `codeview`, `data`, `defender_definition`, `delay_imports`, `disasm(rva, size=256)`, `exports`, `imports`, `info`, `messages`, `patch(rva, data, update_checksum=True)`, `pointer_string_tables(suffix='', minimum=2, maximum=260)`, `read(rva, size)`, `resource_files()`, `resources`, `sections`, `strings`, `typelibs`, `version`, `with_resources(resources)`.

### `windows.signing_identity` value

Opaque RSA code-signing identity. certificate contains the public DER X.509 certificate; private-key material is not exposed by attributes or representations.

Methods and attributes: `certificate (DER bytes; private key is not exposed)`.

### `workspace` value

An SCS capability over a live root. open_file returns a stable immutable trex file version; write_file accepts files, strings or bytes, reusing same-repository content without reading its payload. readonly shares live state, view captures an independent immutable root, and fork creates independent writable state after durable snapshot. Only publish changes named roots, with conflict detection; explicit publication survives later script errors. Paths cannot traverse parents and symlinks are never followed. Renvo source consumers capture a lazy stable tree view.

Methods and attributes: `chmod(path, mode)`, `delete(path)`, `fork()`, `glob(pattern)`, `list_dir(path)`, `mkdir(path)`, `open_file(path)`, `publish(name)`, `read_file(path, line_start=None, line_end=None, output_limit=None)`, `readlink(path)`, `readonly()`, `rename(old, new)`, `replace(path, old, new)`, `search(pattern, ...)`, `snapshot()`, `stat(path)`, `symlink(path, target)`, `view()`, `write_file(path, content)`.
