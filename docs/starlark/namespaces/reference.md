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

### `pointer_chain`

Follows a pointer through a sequence of signed offsets.

### `read_c_string`

Reads a bounded NUL-terminated target string.

### `read_int`

Reads one bounded integer from target memory.

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

### `repeat_ui`

Runs a guest UI procedure repeatedly and returns framebuffer checkpoints.

### `wait_duration`

Waits using selectable VM events while draining them deterministically.

### `wait_for_event`

Returns the first event whose kind is in kinds before timeout.

### `wait_until`

Evaluates predicate after each VM event until it returns a value.

## `vmm/profiles.star`

Portable machine-profile helpers shared by VMM backends.

### `pc`

Builds a portable PC request without selecting a VMM backend.

## `vmm/smoke.star`

Framebuffer-based guest smoke automation for unmodified disk recipes.

### `close_and_verify`

Closes the active guest window and verifies continued UI responsiveness.

### `enter_command`

Enters a command through a supported guest shell surface.

### `frame_delta`

Returns bounded pixel-difference metrics for two framebuffer captures.

### `launch_and_capture`

Launches one guest command and captures its settled visual result.

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

    `target` is an address returned by `resolve`.  Arguments may contain raw
    integers, `pointer(name)`, or `size_of(name)` references.  `inspect`, when
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

## `windows/selfreg/exception.star`

Structured-exception dispatch for bounded 32-bit registration execution.

### `exception_plugin`

Dispatches RaiseException through active compiler SEH3 scope tables.

    The plugin deliberately supports the explicit x86 registration-chain
    contract only. Unknown frame layouts and unhandled exceptions fail closed.

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

### `successful_imports`

Builds a deterministic plugin whose selected imports return success.

## `windows/selfreg/policy.star`

High-level, data-first Windows self-registration policy.

### `registration_patches`

Returns registry patches for one PE without loading system DLL images.

    Structured resources and static PE facts are preferred. The bounded x86
    runner is used only as a fallback. Its writes require success, except for
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

### `bytes_concat`

`bytes_concat(parts) -> bytes`

Native top-level operation.

### `digest`

`digest(value, algorithm='sha256') -> bytes`

Native top-level operation.

### `directory`

`directory() -> directory`

Native top-level operation.

### `error`

`error(message)`

Native top-level operation.

### `help`

`help(value=None) -> None`

Native top-level operation.

### `hex`

`hex(value, width=0) -> string`

Native top-level operation.

### `mirror_file`

`mirror_file(urls, cache, key, sha256='', size=-1, maximum=64GiB, timeout=3600) -> file`

Native top-level operation.

### `open`

`open(name) -> file`

Native top-level operation.

### `repl`

`repl() -> None`

Native top-level operation.

### `stdout`

`stdout(value) -> None`

Native top-level operation.

### `write`

`write(name, value, max_bytes=64GiB) -> None`

Native top-level operation.

### `archive.ar`

`archive.ar(file, maximum_entries=1M, maximum_metadata=64MiB) -> ar`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.cab`

`archive.cab(...)`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.cab_set`

`archive.cab_set(files, cache=True) -> cab`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.installer`

`archive.installer(file, maximum_scan=256MiB, cache=True) -> installer`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.installer_probe`

`archive.installer_probe(file, maximum_scan=256MiB, cache=True) -> dict`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.installscript`

`archive.installscript(file) -> installscript`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.installshield`

`archive.installshield(header, cabinets, external={}) -> installshield`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.kwaj`

`archive.kwaj(file, maximum=512MiB) -> file`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.kwaj_info`

`archive.kwaj_info(file, maximum=512MiB) -> record(file, name, method, decoded_size, compressed_size)`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.sevenzip`

`archive.sevenzip(file, maximum_entries=1M, maximum_metadata=64MiB, max_dictionary=256MiB) -> sevenzip`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.sfp`

`archive.sfp(file, maximum_entries=1M, maximum_metadata=64MiB) -> sfp`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.szdd`

`archive.szdd(file, maximum=512MiB) -> file`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.tar`

`archive.tar(directory, compress='') -> bytes; archive.tar(file, maximum_entries=1M) -> tar`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.wim`

`archive.wim(...)`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.xz`

`archive.xz(file, max_dictionary=64MiB) -> file`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `archive.zip`

`archive.zip(...)`

Native `archive` operation. Limits and timeout arguments are validated before work begins.

### `binary.annotate`

`binary.annotate(...)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.base64`

`binary.base64(value, url=False, padding=True, maximum=512MiB)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.bits`

`binary.bits(...)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.builder`

`binary.builder(...)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.concat`

`binary.concat(...)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.cursor`

`binary.cursor(...)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.decode`

`binary.decode(...)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.encode`

`binary.encode(...)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.extents`

`binary.extents(...)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.f32be`

`binary.f32be(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.f32le`

`binary.f32le(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.f64be`

`binary.f64be(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.f64le`

`binary.f64le(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.hex`

`binary.hex(value, maximum=512MiB)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.i16be`

`binary.i16be(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.i16le`

`binary.i16le(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.i32be`

`binary.i32be(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.i32le`

`binary.i32le(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.i64be`

`binary.i64be(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.i64le`

`binary.i64le(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.i8`

`binary.i8(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.layout`

`binary.layout(...)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_f32be`

`binary.read_f32be(source, offset=0) -> float`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_f32le`

`binary.read_f32le(source, offset=0) -> float`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_f64be`

`binary.read_f64be(source, offset=0) -> float`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_f64le`

`binary.read_f64le(source, offset=0) -> float`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_i16be`

`binary.read_i16be(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_i16le`

`binary.read_i16le(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_i32be`

`binary.read_i32be(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_i32le`

`binary.read_i32le(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_i64be`

`binary.read_i64be(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_i64le`

`binary.read_i64le(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_i8`

`binary.read_i8(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_u16be`

`binary.read_u16be(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_u16le`

`binary.read_u16le(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_u32be`

`binary.read_u32be(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_u32le`

`binary.read_u32le(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_u64be`

`binary.read_u64be(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_u64le`

`binary.read_u64le(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.read_u8`

`binary.read_u8(source, offset=0) -> int`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.replace`

`binary.replace(...)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.strings`

`binary.strings(...)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.text`

`binary.text(...)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.u16be`

`binary.u16be(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.u16le`

`binary.u16le(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.u32be`

`binary.u32be(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.u32le`

`binary.u32le(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.u64be`

`binary.u64be(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.u64le`

`binary.u64le(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.u8`

`binary.u8(value) -> bytes`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.view`

`binary.view(...)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `binary.xml`

`binary.xml(value, maximum=16MiB, max_depth=256, max_nodes=1M)`

Native `binary` operation. Limits and timeout arguments are validated before work begins.

### `block.cache`

`block.cache(base, max_bytes=32MiB, chunk_size=64KiB)`

Native `block` operation. Limits and timeout arguments are validated before work begins.

### `block.device`

`block.device(file, format='raw', logical_block_size=512, physical_block_size=logical, writable=False)`

Native `block` operation. Limits and timeout arguments are validated before work begins.

### `block.nbd`

`block.nbd(device, export_name='', max_request=8MiB, structured=True, handshake_timeout=10, request_timeout=30, workers=4)`

Native `block` operation. Limits and timeout arguments are validated before work begins.

### `block.overlay`

`block.overlay(base, max_dirty_bytes=128MiB, chunk_size=64KiB, trace_operations=0)`

Native `block` operation. Limits and timeout arguments are validated before work begins.

### `block.view`

`block.view(device) -> live read-only file view`

Native `block` operation. Limits and timeout arguments are validated before work begins.

### `clock.monotonic`

`clock.monotonic() -> elapsed seconds`

Native `clock` operation. Limits and timeout arguments are validated before work begins.

### `clock.profiler`

`clock.profiler() -> clock.profiler`

Native `clock` operation. Limits and timeout arguments are validated before work begins.

### `clock.unix`

`clock.unix(...)`

Native `clock` operation. Limits and timeout arguments are validated before work begins.

### `clock.utc`

`clock.utc(...)`

Native `clock` operation. Limits and timeout arguments are validated before work begins.

### `crypto.aes`

`crypto.aes(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.checksum`

`crypto.checksum(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.constant_time_equal`

`crypto.constant_time_equal(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.des`

`crypto.des(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.deterministic`

`crypto.deterministic(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.hash`

`crypto.hash(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.hash_blocks`

`crypto.hash_blocks(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.hasher`

`crypto.hasher(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.hmac`

`crypto.hmac(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.mod_exp`

`crypto.mod_exp(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.mod_inverse`

`crypto.mod_inverse(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.mod_mul`

`crypto.mod_mul(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.random`

`crypto.random(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.rc4`

`crypto.rc4(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `crypto.xtea`

`crypto.xtea(...)`

Native `crypto` operation. Limits and timeout arguments are validated before work begins.

### `database.ese`

`database.ese(file) -> ESE database`

Native `database` operation. Limits and timeout arguments are validated before work begins.

### `database.ese_build`

`database.ese_build(tables, database_pages=0, sort_data=None) -> file`

Native `database` operation. Limits and timeout arguments are validated before work begins.

### `database.sqlite`

`database.sqlite(...)`

Native `database` operation. Limits and timeout arguments are validated before work begins.

### `database.sqlite_build`

`database.sqlite_build(...)`

Native `database` operation. Limits and timeout arguments are validated before work begins.

### `debug.disassemble`

`debug.disassemble(data, address=0, architecture='i386', maximum=64MiB, count=-1); architectures: i8086/x86-16, i386/x86, amd64/x86_64`

Native `debug` operation. Limits and timeout arguments are validated before work begins.

### `debug.gdb`

`debug.gdb(channel, memory_limit=64MiB, stop_queue=256, timeout=15)`

Native `debug` operation. Limits and timeout arguments are validated before work begins.

### `debug.select`

`debug.select(values, timeout=-1)`

Native `debug` operation. Limits and timeout arguments are validated before work begins.

### `emulator.plugin`

`emulator.plugin(...)`

Native `emulator` operation. Limits and timeout arguments are validated before work begins.

### `emulator.x86`

`emulator.x86(image|code, base=0x1000, entry=None, instruction_limit=2M, memory_limit=32MiB, stack_size=1MiB, call_depth_limit=1024, trace=False, trace_limit=4096, profile=False, profile_interval=256, profile_limit=16384, image_name='main', fs_base=0, segment_size=4096)`

Native `emulator` operation. Limits and timeout arguments are validated before work begins.

### `filesystem.fat`

`filesystem.fat(...)`

Native `filesystem` operation. Limits and timeout arguments are validated before work begins.

### `filesystem.fat12`

`filesystem.fat12(directory, size, boot_code=None, hidden_sectors=0, label='NO NAME', file_order=[], directory_label=True, extended_bpb=False, chs=None) -> file`

Native `filesystem` operation. Limits and timeout arguments are validated before work begins.

### `filesystem.fat16`

`filesystem.fat16(directory, size, boot_code=None, hidden_sectors=0, label='NO NAME', file_order=[], directory_label=True, extended_bpb=True, chs=None) -> file`

Native `filesystem` operation. Limits and timeout arguments are validated before work begins.

### `filesystem.fat32`

`filesystem.fat32(...)`

Native `filesystem` operation. Limits and timeout arguments are validated before work begins.

### `filesystem.gpt`

`filesystem.gpt(file) -> parsed GPT; filesystem.gpt(size, disk_guid=...) -> builder`

Native `filesystem` operation. Limits and timeout arguments are validated before work begins.

### `filesystem.host`

`filesystem.host(...)`

Native `filesystem` operation. Limits and timeout arguments are validated before work begins.

### `filesystem.iso9660`

`filesystem.iso9660(...)`

Native `filesystem` operation. Limits and timeout arguments are validated before work begins.

### `filesystem.mbr`

`filesystem.mbr(file) -> parsed MBR; filesystem.mbr(size, boot_code=None, disk_signature=0, chs=None) -> builder`

Native `filesystem` operation. Limits and timeout arguments are validated before work begins.

### `filesystem.ntfs`

`filesystem.ntfs(source, size=None, boot_code=None, hidden_sectors=0, label='NO NAME', version='1.1', log_file=None, upcase=None, upcase_profile='default')`

Native `filesystem` operation. Limits and timeout arguments are validated before work begins.

### `filesystem.udf`

`filesystem.udf(...)`

Native `filesystem` operation. Limits and timeout arguments are validated before work begins.

### `filesystem.vhdx`

`filesystem.vhdx(...)`

Native `filesystem` operation. Limits and timeout arguments are validated before work begins.

### `firmware.acpi_compatible_id`

`firmware.acpi_compatible_id(device, compatible_id)`

Native `firmware` operation. Limits and timeout arguments are validated before work begins.

### `firmware.acpi_table`

`firmware.acpi_table(signature, body, revision=2, oem_id='TREXOS', oem_table_id='TREXACPI', oem_revision=1, creator_id='TREX', creator_revision=1)`

Native `firmware` operation. Limits and timeout arguments are validated before work begins.

### `html.escape`

`html.escape(...)`

Native `html` operation. Limits and timeout arguments are validated before work begins.

### `html.unescape`

`html.unescape(...)`

Native `html` operation. Limits and timeout arguments are validated before work begins.

### `image.compare`

`image.compare(left, right, threshold=8, maximum=128MiB, max_pixels=16MiP) -> record`

Native `image` operation. Limits and timeout arguments are validated before work begins.

### `image.info`

`image.info(source, maximum=128MiB, max_pixels=16MiP) -> record`

Native `image` operation. Limits and timeout arguments are validated before work begins.

### `image.pixel`

`image.pixel(source, x, y, maximum=128MiB, max_pixels=16MiP) -> record`

Native `image` operation. Limits and timeout arguments are validated before work begins.

### `json.decode`

`json.decode(value, maximum=64MiB) -> value`

Native `json` operation. Limits and timeout arguments are validated before work begins.

### `json.encode`

`json.encode(...)`

Native `json` operation. Limits and timeout arguments are validated before work begins.

### `path.base`

`path.base(path) -> string`

Native `path` operation. Limits and timeout arguments are validated before work begins.

### `path.clean`

`path.clean(path) -> logical absolute path`

Native `path` operation. Limits and timeout arguments are validated before work begins.

### `path.dir`

`path.dir(path) -> logical directory path`

Native `path` operation. Limits and timeout arguments are validated before work begins.

### `path.ext`

`path.ext(path) -> extension`

Native `path` operation. Limits and timeout arguments are validated before work begins.

### `path.from_windows`

`path.from_windows(...)`

Native `path` operation. Limits and timeout arguments are validated before work begins.

### `path.join`

`path.join(...)`

Native `path` operation. Limits and timeout arguments are validated before work begins.

### `qemu.acpi_table`

`qemu.acpi_table(file)`

Native `qemu` operation. Limits and timeout arguments are validated before work begins.

### `qemu.audiodev`

`qemu.audiodev(...)`

Native `qemu` operation. Limits and timeout arguments are validated before work begins.

### `qemu.backend`

`qemu.backend(binary='', machine='pc', accelerator='auto', display_frontend='auto', block_transport='auto', overlay_limit=256MiB, stderr_limit=1MiB, devices=[], netdevs=[], chardevs=[], options=[], acpi_tables=[])`

Native `qemu` operation. Limits and timeout arguments are validated before work begins.

### `qemu.chardev`

`qemu.chardev(name, **properties)`

Native `qemu` operation. Limits and timeout arguments are validated before work begins.

### `qemu.device`

`qemu.device(name, **properties)`

Native `qemu` operation. Limits and timeout arguments are validated before work begins.

### `qemu.extension`

`qemu.extension(vm)`

Native `qemu` operation. Limits and timeout arguments are validated before work begins.

### `qemu.netdev`

`qemu.netdev(name, **properties)`

Native `qemu` operation. Limits and timeout arguments are validated before work begins.

### `qemu.option`

`qemu.option(name, value=None); -d accepts a list of debug event names`

Native `qemu` operation. Limits and timeout arguments are validated before work begins.

### `regexp.compile`

`regexp.compile(...)`

Native `regexp` operation. Limits and timeout arguments are validated before work begins.

### `runtime.stage_cache`

`runtime.stage_cache() -> runtime.stage_cache`

Native `runtime` operation. Limits and timeout arguments are validated before work begins.

### `runtime.stats`

`runtime.stats() -> record`

Native `runtime` operation. Limits and timeout arguments are validated before work begins.

### `testing.attempt`

`testing.attempt(...)`

Native `testing` operation. Limits and timeout arguments are validated before work begins.

### `testing.module`

`testing.module(...)`

Native `testing` operation. Limits and timeout arguments are validated before work begins.

### `url.path_escape`

`url.path_escape(...)`

Native `url` operation. Limits and timeout arguments are validated before work begins.

### `url.path_unescape`

`url.path_unescape(...)`

Native `url` operation. Limits and timeout arguments are validated before work begins.

### `vmm.backends`

`vmm.backends()`

Native `vmm` operation. Limits and timeout arguments are validated before work begins.

### `vmm.channel`

`vmm.channel(kind, name, required=True)`

Native `vmm` operation. Limits and timeout arguments are validated before work begins.

### `vmm.disk`

`vmm.disk(source, name='disk0', bus='auto', media='disk', unit=-1, chs=None, read_only=None, snapshot=False, required=True)`

Native `vmm` operation. Limits and timeout arguments are validated before work begins.

### `vmm.display`

`vmm.display(mode, required=True)`

Native `vmm` operation. Limits and timeout arguments are validated before work begins.

### `vmm.machine`

`vmm.machine(architecture, memory, cpus=1, disks=[], networks=[], display=vmm.display('none'), channels=[], start_paused=False, required_capabilities=[])`

Native `vmm` operation. Limits and timeout arguments are validated before work begins.

### `vmm.network`

`vmm.network(kind, name='net0', required=True)`

Native `vmm` operation. Limits and timeout arguments are validated before work begins.

### `vmm.start`

`vmm.start(machine, backend)`

Native `vmm` operation. Limits and timeout arguments are validated before work begins.

### `vmm.validate`

`vmm.validate(machine, backend)`

Native `vmm` operation. Limits and timeout arguments are validated before work begins.

### `web.file`

`web.file(...)`

Native `web` operation. Limits and timeout arguments are validated before work begins.

### `web.redirect`

`web.redirect(...)`

Native `web` operation. Limits and timeout arguments are validated before work begins.

### `web.response`

`web.response(...)`

Native `web` operation. Limits and timeout arguments are validated before work begins.

### `web.zip`

`web.zip(...)`

Native `web` operation. Limits and timeout arguments are validated before work begins.

### `windows.assembly_manifest`

`windows.assembly_manifest(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.catalog_hash`

`windows.catalog_hash(file, algorithm='sha1')`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.catalog_members`

`windows.catalog_members(value)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.certificate`

`windows.certificate(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.creg_compare`

`windows.creg_compare(left, right) -> structural difference report`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.creg_from_patches`

`windows.creg_from_patches(name, patches, keys=[], state=1, generation='windows95') -> file`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.creg_keys`

`windows.creg_keys(file) -> list[list[string]]`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.creg_patches`

`windows.creg_patches(file) -> list[dict]`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.csp_registrations`

`windows.csp_registrations(file, strict=True)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.empty_event_log`

`windows.empty_event_log(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.event_log`

`windows.event_log(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.font_names`

`windows.font_names(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.hive`

`windows.hive(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.hive_from_patches`

`windows.hive_from_patches(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.hive_keys`

`windows.hive_keys(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.hive_log`

`windows.hive_log(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.hive_patches`

`windows.hive_patches(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.hives_from_inf`

`windows.hives_from_inf(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.icon`

`windows.icon(file, index=0, width=32, height=32)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.inf`

`windows.inf(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.inf_patches`

`windows.inf_patches(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.internet_shortcut`

`windows.internet_shortcut(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.kd`

`windows.kd(channel, architecture='i386', packet_limit=65535, memory_limit=64MiB, event_queue=512)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.minidump`

`windows.minidump(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.mof`

`windows.mof(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.msc_snapins`

`windows.msc_snapins(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.ne_fastboot`

`windows.ne_fastboot(modules, overlay_path='C:\\WINDOWS\\WIN100.OVL', maximum=64MiB) -> {bin, overlay}`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.patch_hive`

`windows.patch_hive(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.pdb`

`windows.pdb(file, stream_limit=256MiB)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.pe`

`windows.pe(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.pe32_executable`

`windows.pe32_executable(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.pkcs7_certificates`

`windows.pkcs7_certificates(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.selfreg_patches`

`windows.selfreg_patches(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.setver`

`windows.setver(source, name, major, minor, maximum=16MiB) -> file`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.shortcut`

`windows.shortcut(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.symbol_server`

`windows.symbol_server(base_url, name, key, guid=None, age=None, maximum=256MiB, timeout=45)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.utf16_strings`

`windows.utf16_strings(...)`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.win9x_vxd_library`

`windows.win9x_vxd_library(base, members, exclude=[]) -> file`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.win9x_vxd_library_members`

`windows.win9x_vxd_library_members(file) -> list[string]`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.win9x_vxd_unpack`

`windows.win9x_vxd_unpack(file) -> file`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `windows.wmi_repository`

`windows.wmi_repository(files=None, documents=None, default_namespace='root\cimv2', server_name='')`

Native `windows` operation. Limits and timeout arguments are validated before work begins.

### `ar` value

Methods and attributes: `entries`, `files`, `find(name, occurrence=0)`.

### `ar_entry` value

Methods and attributes: `binary`, `bytes`, `gid`, `hex`, `mode`, `mtime`, `name`, `read`, `size`, `slice`, `uid`.

### `binary.builder` value

Methods and attributes: `align(alignment, fill=0)`, `append(value)`, `bytes()`, `f32be(value)`, `f32le(value)`, `f64be(value)`, `f64le(value)`, `file()`, `i16be(value)`, `i16le(value)`, `i32be(value)`, `i32le(value)`, `i64be(value)`, `i64le(value)`, `i8(value)`, `patch(offset, value)`, `patch_f32be(offset, value)`, `patch_f32le(offset, value)`, `patch_f64be(offset, value)`, `patch_f64le(offset, value)`, `patch_i16be(offset, value)`, `patch_i16le(offset, value)`, `patch_i32be(offset, value)`, `patch_i32le(offset, value)`, `patch_i64be(offset, value)`, `patch_i64le(offset, value)`, `patch_i8(offset, value)`, `patch_u16be(offset, value)`, `patch_u16le(offset, value)`, `patch_u32be(offset, value)`, `patch_u32le(offset, value)`, `patch_u64be(offset, value)`, `patch_u64le(offset, value)`, `patch_u8(offset, value)`, `reserve(size, fill=0)`, `size`, `u16be(value)`, `u16le(value)`, `u32be(value)`, `u32le(value)`, `u64be(value)`, `u64le(value)`, `u8(value)`.

### `binary.cursor` value

Methods and attributes: `align(alignment)`, `bytes(size)`, `f32be()`, `f32le()`, `f64be()`, `f64le()`, `i16be()`, `i16le()`, `i32be()`, `i32le()`, `i64be()`, `i64le()`, `i8()`, `offset`, `remaining`, `seek(offset)`, `skip(size)`, `u16be()`, `u16le()`, `u32be()`, `u32le()`, `u64be()`, `u64le()`, `u8()`.

### `binary.layout` value

Methods and attributes: `decode(source, offset=0)`, `encode(values)`, `size`.

### `binary.xml_document` value

Methods and attributes: `bytes(maximum=16MiB)`, `root`, `with_root(root)`.

### `binary.xml_node` value

Methods and attributes: `attribute(name, default=None, namespace='')`, `attributes`, `bytes(maximum=16MiB)`, `child(name, namespace='')`, `children`, `children_named(name, namespace='')`, `direct_text`, `name`, `namespace`, `prefix`, `qualified_name`, `text`, `with_children(children)`, `with_text(text)`.

### `block_device` value

Methods and attributes: `capabilities`, `commit()`, `extents(offset, length)`, `flush()`, `geometry`, `read(offset, size)`, `size`, `snapshot()`, `stats`, `trim(offset, length)`, `write(offset, value)`, `zero(offset, length)`.

### `byte_channel` value

Methods and attributes: `close()`, `name`, `read(size, maximum=8MiB)`, `read_some(maximum=64KiB, timeout=30)`, `write(value)`.

### `byte_view` value

Methods and attributes: `bytes(offset=0, size=remaining)`, `compare(other, signed=False, exact=False)`, `find(needle, start=0, end=size)`, `find_all(needle, start=0, end=size, limit=1M)`, `find_indices(needles, start=0, end=size)`, `size`, `slice(offset=0, size=remaining)`.

### `clock.profiler` value

Methods and attributes: `counter(name, amount=1)`, `measure(name, function, *args, **kwargs)`, `report(minimum_coverage=0.95)`, `snapshot()`, `span(name)`.

### `clock.span` value

Methods and attributes: `end() -> elapsed seconds`.

### `directory` value

Methods and attributes: `fat_short_path(name)`, `files`, `find(path)`, `mkdir(name)`, `remove(name)`, `set_attributes(name, readonly=False, hidden=False, system=False, archive=False)`, `set_security(name, descriptor)`, `write(name, value)`.

### `emulator.execution` value

Methods and attributes: `close()`, `closed`, `done`, `run(instruction_limit=0)`.

### `emulator.x86` value

Methods and attributes: `accelerate_loop(address, pattern=None, size=0, digest=None, normalize_relative=False, maximum_instructions=1Mi)`, `accelerate_region(entry, start, size, digest, reenter=False, maximum_instructions=1Mi)`, `accelerate_runtime_region(anchor, size, digest, entry_offset=0, anchor_mask=None, name='runtime executable region', normalize_relative=True, reenter=False, maximum_instructions=1Mi)`, `allocate(size=0, value=None, address=None, alignment=16, name='plugin', readable=True, writable=True, executable=False)`, `call(address, args=[], registers={})`, `call_export(name, args=[], registers={})`, `call_trace(reset=False)`, `checkpoint()`, `code_trace(watch, reset=False)`, `configure_call_trace(enabled=True, limit=unchanged, start=0, size=0, reset=True)`, `configure_trace(enabled=True, limit=unchanged, reset=True)`, `entry`, `free(address)`, `get_register(name)`, `hook(...) and use(plugins)`, `imports`, `invoke(address, args=[], registers={})`, `load_module(image, name)`, `mappings`, `memory_writes(watch, reset=False)`, `modules`, `profile(limit=256, reset=False)`, `protect(address, size, readable=True, writable=False, executable=False)`, `provide_export(callback=None, module, name|ordinal, argc=0, convention='stdcall', value=None, writable=True)`, `read_cbytes(address, maximum=32KiB, require_terminator=True, unit_width=1)`, `read_f32be(address)`, `read_f32le(address)`, `read_f64be(address)`, `read_f64le(address)`, `read_i16be(address)`, `read_i16le(address)`, `read_i32be(address)`, `read_i32le(address)`, `read_i64be(address)`, `read_i64le(address)`, `read_i8(address)`, `read_u16be(address)`, `read_u16le(address)`, `read_u32be(address)`, `read_u32le(address)`, `read_u64be(address)`, `read_u64le(address)`, `read_u8(address)`, `restore(checkpoint)`, `rewrite(address, pattern=None, size=0, digest=None, callback, name='inline rewrite', normalize_relative=False)`, `run()`, `set_register(name, value)`, `snapshot()`, `spawn(address, args=[], registers={})`, `stack`, `stop(reason, detail='')`, `transfer(address, esp=None, ebp=None, return_address=None)`, `transform(anchor, size, digest, callback, anchor_mask=None, name='runtime transformation', normalize_relative=True)`, `u32_multiply_accumulate(destination, source, count, scalar, carry=0, subtract=False)`, `watch_code(address, size, limit=4096, stack_bytes=0, captures={})`, `watch_memory(address, size, limit=4096)`, `write_f32be(address, value)`, `write_f32le(address, value)`, `write_f64be(address, value)`, `write_f64le(address, value)`, `write_i16be(address, value)`, `write_i16le(address, value)`, `write_i32be(address, value)`, `write_i32le(address, value)`, `write_i64be(address, value)`, `write_i64le(address, value)`, `write_i8(address, value)`, `write_u16be(address, value)`, `write_u16le(address, value)`, `write_u32be(address, value)`, `write_u32le(address, value)`, `write_u64be(address, value)`, `write_u64le(address, value)`, `write_u8(address, value)`.

### `gdb` value

Methods and attributes: `architecture`, `breakpoint(address, kind='hardware', size=1, timeout=30)`, `close()`, `continue(timeout=30)`, `features`, `interrupt(timeout=30)`, `monitor(command, timeout=30)`, `packet(payload, timeout=30)`, `read_memory(address, size, timeout=30)`, `read_register(name, timeout=30)`, `registers(timeout=30)`, `running`, `search_memory(address, size, pattern, limit=256, timeout=30)`, `step(timeout=30)`, `wait(timeout=30)`, `watchpoint(address, size, access='write', timeout=30)`, `with_register(name, value, callback)`, `with_state(registers, memory, callback, timeout=30)`, `write_memory(address, data, timeout=30)`, `write_register(name, value, timeout=30)`.

### `gdb_point` value

Methods and attributes: `address`, `remove(timeout=30)`, `removed`, `size`.

### `installer` value

Methods and attributes: `container`, `files`, `find(path)`, `format`, `installscript`, `offset`, `payload`, `plan(locations={}, variables={}, components=None)`, `size`.

### `installscript` value

Methods and attributes: `blocks`, `callbacks`, `calls`, `effects`, `evaluate(entry='application', strings={}, numbers={}, profiles={}, maximum_steps=200000, maximum_depth=64)`, `find_function(name)`, `functions`, `strings`.

### `installshield` value

Methods and attributes: `components`, `entries`, `files`, `find(path)`, `groups`, `shortcuts`, `version`.

### `nbd_server` value

Methods and attributes: `close()`, `export_name`, `serve(channel)`, `stats`.

### `qemu.v1` value

Methods and attributes: `block_stats()`, `capabilities`, `hmp(command, timeout=30)`, `process`, `qmp(command, arguments={}, timeout=30)`, `qmp_schema(timeout=30)`.

### `qemu_acpi_table` value

Methods and attributes: `file`, `name`, `properties`.

### `qemu_chardev` value

Methods and attributes: `name`, `properties`.

### `qemu_device` value

Methods and attributes: `name`, `properties`.

### `qemu_netdev` value

Methods and attributes: `name`, `properties`.

### `qemu_option` value

Methods and attributes: `name`, `properties`.

### `runtime.stage_cache` value

Methods and attributes: `clear() -> int`, `compute(name, source, options, function, args=(), kwargs={})`, `stats`.

### `sfp` value

Methods and attributes: `archive_size`, `data_offset`, `entries`, `files`, `find(path)`, `package_label`, `version`.

### `sfp_entry` value

Methods and attributes: `binary`, `bytes`, `created_time`, `entry_type`, `file_length`, `flags`, `hex`, `modified_time`, `name`, `parent`, `path`, `payload_offset`, `read`, `record_offset`, `size`, `slice`, `stored_size`.

### `tar` value

Methods and attributes: `entries`, `files`, `find(path, occurrence=0)`.

### `tar_entry` value

Methods and attributes: `binary`, `bytes`, `entry_type`, `gid`, `gname`, `hex`, `link`, `mode`, `mtime`, `name`, `path`, `read`, `size`, `slice`, `stored_size`, `uid`, `uname`.

### `vm` value

Methods and attributes: `backend_id`, `capabilities`, `channel(name, timeout=30)`, `chord(keys)`, `debugger(protocol, create=False, paused=False, timeout=30)`, `detach()`, `extension(name)`, `has_capability(name)`, `key(key, down=True)`, `next_event(timeout=-1)`, `pause(timeout=30)`, `pointer(x=0, y=0, absolute=False, buttons=[], wheel=0)`, `powerdown(timeout=30)`, `reset(timeout=30)`, `result`, `resume(timeout=30)`, `running`, `screenshot(format='png', timeout=30)`, `send_keys(keys)`, `send_text(text)`, `shutdown(timeout=30, force=True, force_timeout=10)`, `status`, `stop(timeout=30)`, `tap(key)`, `type_and_enter(text, enter='enter')`, `wait(timeout=-1)`.

### `vmm_backend` value

Methods and attributes: `accelerator`, `block_transport`, `capabilities`, `id`, `machine`.

### `vmm_channel` value

Methods and attributes: `kind`, `name`, `required`.

### `vmm_disk` value

Methods and attributes: `bus`, `chs`, `device`, `media`, `name`, `read_only`, `required`, `snapshot`, `unit`.

### `vmm_display` value

Methods and attributes: `mode`, `required`.

### `vmm_machine` value

Methods and attributes: `architecture`, `channels`, `cpus`, `disks`, `display`, `memory`, `networks`, `required_capabilities`, `start_paused`.

### `vmm_network` value

Methods and attributes: `kind`, `name`, `required`.

### `windows.kd` value

Methods and attributes: `breakin()`, `breakpoint(address, timeout=30)`, `close()`, `context(timeout=30)`, `continue(status=0x10002, timeout=30)`, `file_io(handler=None)`, `next_event(timeout=-1)`, `packet(kind, payload, packet_id=None, timeout=30)`, `read_physical(address, size, timeout=30)`, `read_virtual(address, size, timeout=30)`, `request(api, processor=-1, arguments={}, data=b'', timeout=30)`, `set_context(raw, edi=None, esi=None, ebx=None, edx=None, ecx=None, eax=None, ebp=None, eip=None, eflags=None, esp=None, timeout=30)`, `write_physical(address, data, timeout=30)`, `write_virtual(address, data, timeout=30)`.

### `windows.kd_breakpoint` value

Methods and attributes: `address`, `handle`, `remove(timeout=30)`, `removed`.

### `windows.pdb` value

Methods and attributes: `age`, `guid`, `nearest(rva)`, `signature`, `symbols`.

### `windows.pdb_symbol` value

Methods and attributes: `kind`, `name`, `rva`.

### `windows.pe` value

Methods and attributes: `codeview`, `data`, `disasm(rva, size=256)`, `exports`, `imports`, `info`, `messages`, `patch(rva, data, update_checksum=True)`, `pointer_string_tables(suffix='', minimum=2, maximum=260)`, `read(rva, size)`, `resources`, `sections`, `typelibs`, `version`.
