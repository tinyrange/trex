# Calling code and customizing semantic plugins

Both `emulator.x86` and the AMD64 `emulator.machine` expose
`machine.imports_named(names)` for plugin installation. Pass a sequence of
function names or a signature dictionary (its keys are used). Matching is
case-insensitive; results retain the original import spelling, address order,
and duplicate imports from different modules or IAT slots. Ordinal-only imports
match only an explicitly requested empty name. The returned list is independent
and module loading refreshes the query's internal index. Plugins must still
check the returned import's provider module before installing a hook.

Use the smallest execution environment that answers your question. For a
bounded function, start with `windows/emulation:conformance.star`. For Windows
self-registration or code requiring the semantic Windows environment, use
`windows/emulation:runner.star`. Boot and hardware questions belong in QEMU,
not in either in-process environment. These APIs emulate x86/PE32, not PE32+.

## A bounded call

```starlark
load("@stdlib//windows/emulation:conformance.star", "call", "output", "pointer", "session")

def main(args):
    target = session(image = open(args[0]), module = "example.dll",
                     instruction_limit = 100000, memory_limit = 32 << 20)
    result = call(target, name = "GetAnswer",
                  buffers = {"answer": output(4)},
                  arguments = [pointer("answer")], expected_return = 0)
    print(result["buffers"]["answer"])
```

This sketch assumes a caller-supplied `GetAnswer(uint32_t*)` export with that
contract; it is not a claim about an arbitrary DLL. Run the self-contained
[emulator example](../../scripts/examples/emulator_call.star) to try a complete
working call without external media.

`session(image=...)` maps a PE32 image; `session(code=...)` maps raw x86 bytes.
Exactly one is required. Extra `modules` map caller-owned files; `bindings`
declare semantic exports; `plugins` install afterward in list order. Imports
without a declared implementation fail if called, rather than silently
returning success.

`call` accepts one of `name`, `ordinal`, `rva`, or `address`, with optional
`module` for exports and image RVAs. A positional target returned by `resolve`
remains supported, but cannot be combined with selectors. Raw-code RVAs are
relative to the session's raw base.

Use `buffer(bytes)` for input/in-out memory, `output(size)` for zeroed output,
`pointer(name, offset=0)` for pointers, and `size_of(name)` for capacities.
Buffers are bounded and freed after a successful call; returned bytes remain
valid. An expectation failure aborts before cleanup, leaving the machine
available for inspection. Discard that session or restore a prior checkpoint
before another independent experiment. An `inspect` callback runs before
successful cleanup; addresses in the returned report are then historical,
not live allocations. `sequence` shares named buffers across several calls.

The result contains `result` (including `reason`, `value`, and `detail`),
`results`, `buffers`, `addresses`, and `inspection`. The default expected stop
is `return`. `expected_return` and per-buffer `expected` validate the actual
contract; instruction exhaustion is not a successful return. Set
`expected_reason=None` only when explicitly inspecting other stop reasons.

## AMD64 semantic-call profiling

Use `machine.profile(calls=True, reset=True)` on an AMD64 machine to enable
bounded timing of the original semantic callbacks, including dynamically
resolved exports. This is independent of sampled instruction profiling;
callbacks, arguments, native return values and instruction budgets are unchanged.
Timing is off by default. `calls=False` disables collection, and `calls=None`
leaves its setting unchanged.

`profile(limit=256)` returns `calls` sorted by total elapsed seconds, along with
`calls_enabled`, `call_tracked` and `call_dropped`. Each call record has `address`,
`module`, `name`, `count`, `seconds`, `max_seconds`, and the `caller` and first
sixteen integer `arguments` of its slowest observed invocation.
`arguments_truncated` reports omitted arguments. No pointed-to memory is copied.
Times are inclusive of nested native invocations, so do not sum nested durations
as exclusive CPU time. Collection retains at most the constructor's
`profile_limit` distinct callback addresses; calls at additional addresses are
counted in `call_dropped`. `reset=True` returns the old report then clears both
instruction and call counters, without changing either collection setting.
Snapshots have independent counters. Reports include callbacks that fail, and
do not turn those failures into successful native returns.

## Replace or wrap an installed method

```starlark
load("@stdlib//windows/selfreg:plugins.star", "override_plugin")

def customization():
    state = {"calls": 0}
    def observe(event, previous):
        state["calls"] += 1
        return previous(event)
    return override_plugin("observe ticks", [{
        "module": "kernel32.dll", "name": "GetTickCount",
        "callback": observe, "wrap": True,
    }], state = state)
```

Pass this plugin through `runner.run(..., plugins=[customization()])`, or
install it after your base plugin with `machine.use`. It changes a semantic
callback, not guest instruction bytes. The direct equivalent is
`machine.override(callback, module=..., name=...|ordinal=..., wrap=False)`.

- Replacement callbacks receive `event`; wrappers receive `(event, previous)`.
  `previous(event)` calls the preceding semantic callback directly. Do not
  re-enter the guest to call the overridden export from inside its callback.
- `event.args` contains arguments decoded using the existing argument count
  and calling convention. Both are preserved, as are existing hook addresses.
  `event.machine` exposes bounded memory operations.
- Install base plugins first. Missing methods, data exports, and inconsistent
  base ABIs fail explicitly. A wrapper also rejects multiple different base
  callbacks for one symbol. Module names are canonicalized and symbol matching
  follows the emulator's existing case-insensitive policy.
- Overrides are explicit and ordered: the last override wins, or wraps the
  preceding chain. Rules also bind later imported stubs. A later explicit
  `hook` or `provide_export` remains a low-level rebinding operation; complete
  base installation before applying customizations.
- Checkpoints save bindings and rules. Put mutable callback data in the
  `state` supplied to `emulator.plugin` or `override_plugin`; checkpoint restore
  restores registered state in place. Hidden closure state is not captured.
  Invalidate checkpoints when code, inputs, plugins, or initialization change.

The executable [override example](../../scripts/examples/emulator_override.star)
demonstrates wrapping and repeatable checkpoint restoration. Use `hook` when
you are supplying a missing import's ABI yourself; use `provide_export` when
you are defining a virtual module's callable or data export.

For a table of named callable exports sharing a callback, both architectures
support `machine.provide_exports(callback, module="example.dll",
signatures={"First": 2, "Second": 0}, convention="stdcall")`. The result is a
list of addresses in dictionary insertion order, equivalent to individual
`provide_export` calls in that order. Argument counts must be integers from
0 through 4096; invalid table entries are rejected before publishing anything.
Binding failures stop at the failing entry without rolling back earlier entries.
The underlying architecture's calling-convention rules still apply. Ordinal and
data exports use `provide_export`. Batching does not replace import-site hooks.

## The Windows runner

`windows.clone_file_entries(entries)` copies a prepared path-to-metadata dictionary
and each metadata dictionary in insertion order. File sources and other field
values remain shared without reads; the returned dictionary layers are mutable
and independent, including when the input is frozen.

`windows.registration_expand(value, replacements)` applies registration-resource
substitutions in dictionary order, replacing uppercase then lowercase percent
tokens for each entry, for at most four passes (stopping when unchanged).
Unknown and mixed-case tokens remain unchanged; non-string values pass through.
This differs from case-insensitive process environment expansion.

`windows.module_sources(files, exclude=[])` indexes a path-to-source dictionary
by case-insensitive DLL basename. Both slash styles are accepted; basenames
without an extension receive `.dll`. Other extensions are ignored. The first
source for a basename wins, and excluded module names use the same normalization.
Sources are returned unchanged without reads, parsing or eager materialization.

Registry plugins can use `windows.registry_partition(entries, hive, key,
values=False)` to split an identity-keyed dictionary into `(subtree, remaining)`.
Key identities are `HIVE + "\x00" + normalized_key`; value identities additionally
append `"\x00" + normalized_value_name`. Stored identities must already use
uppercase hive names and lowercase slash-separated keys. The target hive/key
is normalized by the operation. Set `values=True` for value dictionaries.
Both outputs preserve input order and own their dictionary storage; values are
shared without mutation. The operation does not generate deletion patches or
change registry tombstones. The registry plugin retains that policy.

`windows.registry_children(entries, hive, key, values=False)` selects direct
children using the same identities without copying nonmatches. For key maps it
returns case-folded child names mapped to decoded names (including percent-escaped
slashes). For value maps, `values=True` returns value names mapped to their
unchanged payloads; names containing slashes are not treated as subkeys. Results
retain first-insertion order; callers handle sorting, source-hive merging and
tombstones.

`runner.run(file, module, ...)` constructs the semantic Windows environment,
installs base plugins before custom plugins, and invokes `DllRegisterServer`
by default. Existing keyword arguments remain supported; avoid repeating the
whole signature in product recipes. Keep reusable environment choices in a
small dictionary and pass them with `**options`, while keeping the target
export and success contract explicit at the call site.

The main groups of options are:

| Concern | Options |
| --- | --- |
| Target and marshaling | `export`, `arguments`, `prepare(machine)`, `execute(machine)` |
| Guest inputs | `modules`, `files`, `directories`, `registry_values`, `registry_keys`, `environment` |
| Identity and OS behavior | `user_name`, `user_sid`, `version`, `system_time` |
| Custom semantics | `plugins`, `plugin_factories` |
| Bounds and observation | `instruction_limit`, `memory_limit`, `trace`, `trace_limit`, `profile` |

`prepare` returns integer arguments for one call. `execute` supplies a stateful
sequence instead. Files and registry inputs are logical guest data, not host
paths or extracted intermediates. `plugin_factories` receive the configured
CRT plugin and module files when extension APIs need them. Do not use fake
success bindings to label an unsupported operation as working.

See the [runner source](../../starlark/stdlib/windows/emulation/runner.star)
for its full signature and result fields, the
[generated reference](namespaces/reference.md) for module contracts and native
methods, and the [investigation workflow](../emulator-investigation-workflow.md)
for checkpoints, bounded watches, stop conditions, and guest smoke boundaries.

## Modeled process and thread boundaries

Module records expose `image_size`: the mapped PE image extent (zero for virtual
export-only modules). Address-to-module queries must check both bounds; an
address above a module is not evidence that it belongs to that module.

AMD64 retained executions expose read-only `stack.low` and `stack.high` bounds.
These are zero after stack release. Running a retained execution temporarily
selects its own machine stack bounds; the Win32 thread scheduler also switches
TEB stack base/limit and restores the parent values after each slice, including
faults. Instruction-limit stops remain runnable, not completed threads. This
does not imply a complete per-thread TLS or Windows scheduler implementation.

The Toolhelp process snapshot currently supports only the process class and
contains the isolated modeled process, never host processes. Snapshot cursor,
thread count, native PROCESSENTRY32W layout and handle lifetime are modeled;
other snapshot classes stop explicitly rather than returning fabricated empty
results.

`@stdlib//windows/emulation:urlmon.star` provides an explicitly selected
`offline_urlmon_plugin()`. Its HTTP(S) `URLOpenStreamW` reports connection failure
and records the request without opening a connection, delivering bytes or
claiming completion. It is not installed implicitly and is not a trust or
signature-verification substitute.

The added scalar DIVSS/MULSS execution supports finite normal operands/results
and signed zeros. NaN, infinity, denormal, overflow and underflow paths stop
explicitly; this is not complete SSE arithmetic support. Integer/single
conversions model their implemented rounding and MXCSR exception behavior.

### Explicit offline Authenticode policy

`offline_wintrust_plugin(files, roots, disallowed, unix_time, policy_flags)` from
`@stdlib//windows/emulation:wintrust.star` is opt-in and is not added to runner
defaults. Supply actual file contents, original-media trust anchors and disallowed
certificate DER, an explicit verification clock and the target Windows policy.
The currently supported policy is `0x23c00`, with FILE/VERIFY/CLOSE and cache-only
chain checking (`0x1440`). Cryptographic signature/timestamp and certificate-path
checks run before the policy's offline allowance. `checks` records the result,
validated paths and unavailable revocation; `handles` owns live verification
states, released on CLOSE. Invalid cryptography and unsupported options stop
safely. Borrowed provider/signer/chain and certificate-DER views support
`WTHelperProvDataFromStateData` and `WTHelperGetProvSignerFromChain`; CLOSE frees
the entire view. CERT_INFO, CMSG_SIGNER_INFO, message/store handles and other
provider internals remain unmodeled. Microsoft-root chain policy is bounded to
the SHA-256-pinned Microsoft Root Certificate Authority 2010; an arbitrary
caller-trusted root never qualifies. Other anchors fail closed, including test
roots, even when the caller enables them. Broader policies remain unsupported. See [PE signing](../pe-signing.md) for the native comparison and
trust boundaries; a valid signature is not proof that an installer completed.

### Worker waits and explicit disconnected WinRT queries

A blocking `GetMessage` pumps queued workers before suspending; x86 and AMD64
MSG buffers preserve their native pointer widths. Worker-exclusive
`SleepConditionVariableSRW` atomically releases its lock and reacquires it after
a selected wake or timeout. Wake-one and wake-all are distinct, and a wake is
not retained for future waiters. Shared-mode waits and waits from the outer
(non-resumable) execution stop explicitly. This is not a full SRW scheduler.

API-level performance-counter, FILETIME and calendar clocks advance with the
same virtual milliseconds used by scheduler deadlines, not host elapsed time.
CPU execution alone does not advance that clock. `FreeLibraryAndExitThread`
terminates the current execution with its exit code; like the existing semantic
FreeLibrary model it does not physically unmap DLLs. `VirtualQuery` writes the
native 28-byte x86 or 48-byte AMD64 information layout.

`iphlpapi.star:no_ipv4_adapters_plugin()` explicitly selects an empty IPv4 adapter
inventory and returns `ERROR_NO_DATA`. It is not the correct model for a
configured but disconnected adapter. `winrt.star:string_reference_plugin()`
models caller-owned UTF-16 HSTRING references, raw-buffer access and no-op
reference deletion; it does not implement owned strings or arbitrary activation.
`disconnected_network_information_plugin(strings)` supplies only the
NetworkInformation static interface's no-Internet-profile query and basic COM
reference ownership. Other classes/methods stop, never return fabricated network
information. All these plugins are opt-in. The runner's `virtual_modules` option
adds explicitly supplied semantic DLL names to loader lookup; callers still
must provide their exports. It does not load DLL bytes or implement missing APIs.

`wininet.star:disconnected_wininet_plugin()` currently models only local
synchronous/asynchronous direct or preconfigured session creation and close.
It retains the async flag but does not implement asynchronous requests or
callbacks, and does not claim any network transfer succeeded. Unimplemented
operations remain explicit stops.


### Resource-only Windows modules

The common Windows kernel/resource/user32 plugins share exact-path,
reference-counted `LoadLibraryExW(..., 0, 0x20)` resource handles. This path
parses the supplied PE as data: it does not map executable instructions,
resolve dependencies, call DllMain, or require the resource PE's ISA to match
the machine. Resource-only images remain absent from GetModuleHandle's
executable inventory. FindResource/SizeofResource and LoadString bind the
same immutable source; final FreeLibrary invalidates subsequent lookups.
Other loader modes retain their existing, separate executable-mapping policy.

LoadStringW's caller-buffer path returns UTF-16 code units and truncates at
`capacity - 1` units, including when that boundary splits a surrogate pair.
The libraryloader-l1-1-0 API-set export uses the same handler as user32.
The secure wide CRT formatter supports bounded unsigned integer formats and
bare non-null `%s`, with UTF-16 capacity/counts. Unsupported format modifiers,
null-string invalid-parameter policy, and range-error handler execution are
not replaced by fabricated success.


The private CRT API-set `_o_malloc`/`_o_free` exports share the modeled CRT
allocation arena with `malloc`/`free` and C++ allocation operators. They do not
create an independent heap or relax allocation ownership checks. The native
SecureBoot advanced installer exercises these exports through factory creation
and final release.

The WCP/Events initialization path additionally exercises these bounded services:

- `_o___stdio_common_vswprintf` handles unsigned integer and explicit narrow/
  wide string conversions with the UCRT legacy-termination flag, default locale,
  and UTF-16 capacity/return counts. `_o___stdio_common_vsnprintf_s` handles
  bounded signed/unsigned integer formats and widths, including sign-aware zero padding. Both reject unsupported options,
  formats, locales and truncation/error-handler paths before writing output.
  UCRT's 64-bit options word occupies two x86 stack slots and one x64 slot;
  variadic 64-bit integers likewise preserve the Windows ABI. SDK
  `corecrt_stdio_config.h` option bits are used, not guessed MSVCRT aliases.
- Private `_o__itow_s` and `wcschr`, and string-API-set `wcsnlen`, reuse the existing
  implementations. Private `_o_towupper` and `_o__wcsicmp` admit only their
  verified ASCII/default-locale subset (and WEOF for the former); unsupported
  NLS-dependent input fails explicitly.
- `RtlCreateUnicodeStringFromAsciiz` owns a tracked allocation released through
  `RtlFreeUnicodeString`. Only bounded ASCII input is admitted without native
  NLS tables. `LdrGetDllHandleEx` currently supports only default-directory
  lookup of an absent ASCII module basename, returning `STATUS_DLL_NOT_FOUND`
  without changing the output pointer. Found-module refcount/pinning semantics
  and nondefault options deliberately stop rather than return invented handles.
- `LdrDisableThreadCalloutsForDll` validates an exact mapped-module base and
  records DontCallForThreads in plugin state. The inspected NTDLL returns
  success for static-TLS modules **without** setting that flag; the emulator
  follows this distinction. Once this bounded loader contract is active,
  CreateThread/work-item creation rejects modules still needing native thread
  notifications or per-thread static TLS. It does not silently omit that work.
  This does not generalize the older separate DisableThreadLibraryCalls model.

These operations enable real WCP parsing and EventsInstaller queue/commit;
none stand in for an installer result or an exception handler. See the native
Events section of `../formats/csi-offline-state.md` for exact binary identities,
independent Install/Inspect behavior and deliberately incomplete CBS scope.

The private CRT `_o_memcpy_s` entry point supports zero-count calls and valid,
nonoverlapping copies up to 16 MiB. It preserves binary bytes and destination
guards on x86 and x64. Invalid arguments, overlap, and oversized operations
stop before writes instead of inventing an invalid-parameter handler policy.
The private `_o__errno` entry point shares the public `_errno` per-thread,
guest-memory-backed integer; it does not clear errors or return a success code.
`_o__wcstoui64` and `_wcstoui64` support bounded C-locale integer prefixes,
base autodetection, optional UTF-16 end pointers, unsigned negation and overflow
saturation with ERANGE. x86 returns the full result in EDX:EAX. Null inputs or
invalid bases set EINVAL and stop rather than inventing invalid-handler policy.

`RtlTimeToTimeFields` converts nonnegative signed 64-bit NT timestamps using the deterministic Gregorian calendar, including leap-century rules and millisecond truncation. Its eight SHORT fields use TIME_FIELDS order (weekday last), not SYSTEMTIME order. Negative timestamps and null pointers remain explicit unsupported inputs; no host clock is consulted.

Native counted Unicode copy and append use the target pointer width, preserve raw UTF-16 units (including surrogate pairs and unpaired surrogates), and leave append output unchanged on insufficient capacity. They do not reinterpret the amd64 descriptor padding as a 32-bit buffer pointer.

### Module filenames and native registry transactions

`runner.run(module_paths={...})` and `kernel32_plugin(module_paths={...})`
accept explicit guest filenames keyed by module name. `GetModuleFileNameA/W`
uses the requested HMODULE; it no longer substitutes the primary module path
for dependencies. The runner preserves declared `files` paths using the loader's
same first-match selection. No host filename or guessed system directory is
introduced. Unknown handles fail without writing; UTF-16 capacities count code
units. Truncation follows the modeled XP versus Vista+ contract.

`registry_transactions_plugin(registry, kernel)` supports unnamed local
`NtCreateTransaction`, synchronous `NtCommitTransaction`/`NtRollbackTransaction`,
and `RegOpenKeyTransactedW`/`RegCreateKeyTransactedW`. Transacted key operations
use private registry overlays. Ordinary handles cannot observe those writes
until commit; rollback and closing an active transaction discard them. Commit
rejects intervening ordinary writes instead of overwriting them. Named or
distributed transactions, timeouts, alternate registry views, asynchronous
completion and non-close use of terminal transacted key handles remain explicit
unsupported paths. This is isolated registry state, not host KTM or a claim of
complete Windows transaction semantics.

Native NetSetup initialization additionally exercises the NTDLL classic ETW
aliases (`EtwRegisterTraceGuidsA/W`, `EtwUnregisterTraceGuids`, enable queries,
and trace-message calls). They share the ADVAPI provider table and preserve
64-bit REGHANDLE values on both x86 and x64. No host tracing session is enabled.
AMD64 `UNPCKHPD` preserves source lanes for aliased operands and does not modify
registers or flags when its memory operand faults.

`wcscpy_s` copies raw UTF-16 units with bounded capacities. Invalid/range inputs
clear the documented destination prefix and set errno, then stop because native
invalid-parameter-handler policy is not supplied. `VarUI4FromStr` (OLEAUT32
ordinal 277 and its named export) supports the observed decimal-integer subset,
including DWORD overflow and guard preservation; other numeric forms, locales,
and nonzero flags fail explicitly rather than being silently approximated.

The process environment publishes `PEB.ImageBaseAddress` and bounded loader-list
prefixes for actual mapped PE images. Lists preserve native pointer widths and
owned filename buffers, keep the primary image first, and refresh when the runner
maps a dependency. Semantic export placeholders are not fabricated as PE images.
Unmodeled loader metadata and unloading remain outside this prefix model.

Modern NTDLL ETW aliases (`EtwEventRegister`, `EtwEventSetInformation`,
`EtwEventEnabled`, `EtwEventWrite`, `EtwEventUnregister`) share the Event Log
plugin's provider ownership with their ADVAPI32 forwarders.
`LdrQueryImageFileExecutionOptions` queries explicit target SOFTWARE state:
absent values return name-not-found; the supported present-value subset is a
matching DWORD with sufficient output space. Other type/buffer policies stop.
`RtlGetAppContainerNamedObjectPath` follows the inspected non-AppContainer branch:
success with an empty native-width UNICODE_STRING, not an invented container path
or a NOT_APPCONTAINER failure. Explicit AppContainer SIDs are unsupported.


Object-directory admission is explicit. `object_directories` maps absolute NT
names to allowed specific/standard access masks, or records containing `access`
and self-relative `security` bytes. Opens retain independent owned handles;
case-insensitive lookup is opt-in, and invalid/closed roots and excess rights
cannot manufacture an object. This is an admission model, not an ACL evaluator.
Security queries require READ_CONTROL and actual target NTDLL
`RtlQuerySecurityObject`; no descriptor is synthesized when facts are missing.
`object_security_module` can select a separately admitted native implementation
image without publishing all its unrelated optional exports to the target loader.
The native routine performs descriptor projection and required-size handling.

Native token queries support owned `TokenStatistics` (class 10), owner, primary
group, integrity level, and explicitly supplied default-DACL/process-trust facts.
Class 6 is `TokenDefaultDacl`, not a statistics shortcut. `token_facts` may provide
`owner`, `primary_group` and `process_trust_sid` SID bytes, `default_dacl` ACL bytes,
and an `integrity_level` RID. Empty bytes explicitly denote a NULL default DACL
or absent process-trust SID; omission is unknown and fails closed for those two
queries. Owner/group otherwise use the explicit setup identity, and integrity
defaults to high. These model facts are not host account or protected-process
observations. Token statistics keep identity stable across handles, assign new
identities to duplicates, and change ModifiedId for actual privilege changes.

### Native setup-process queries and CRT fields

`NtQuerySystemInformation` classes 0 and 1 describe the same bounded
single-processor model as `GetNativeSystemInfo`, not the host CPU. Class 0 uses
44 bytes on x86 and 64 on AMD64, with native-width address/mask fields. Class 1
uses the 12-byte processor structure on both architectures. Its KF feature bits
are translated from the modeled PF instruction-feature indices (CMPXCHG8B, MMX,
SSE, 3DNow, RDTSC, SSE2, SSE3); kernel paging and vendor capabilities are not
inferred. Short buffers preserve their contents and report the required length;
a sufficient-length NULL output is an access violation. ReturnLength is optional.

Read-only native token queries recognize the architecture-width pseudo handles
for current process (-4), current thread (-5), and effective token (-6). No
impersonation token means STATUS_NO_TOKEN for -5, while -6 selects the process
token. These queries neither create handles nor authorize mutating token APIs.
Unknown default-DACL or process-trust facts still fail closed; explicit empty
facts mean NULL, not a fabricated default.

The secure wide formatter shares one renderer between `swprintf_s` and
`vswprintf_s`, with native stack/va-list argument acquisition. The bounded string
forms `%s`, `%ls`, and `%ws` count UTF-16 units, including surrogate pairs.
Invalid-parameter/range-handler policy remains an explicit stop, not assumed
successful truncation. The scanf integer subset supports multiple fields,
literal separators, widths and suppression, including native GUID/property-key
formats. It consumes only actual pointer arguments, preserves unassigned output
on partial matches, and distinguishes EOF from matching failure; string scanning
and general secure scanf policy are not implied.

AMD64 ADDSS preserves the upper 96 destination bits and integer flags. Its
finite-normal/signed-zero subset uses exact guard/round/sticky alignment for all
four MXCSR rounding modes, including exponent gaps beyond binary64 precision.
Inexact masked operations set the precision status; unmasked precision stops
before updating the destination/PC. NaNs, infinities, subnormal operands/results,
and overflow remain explicit unsupported boundaries, as with the existing
bounded scalar multiply/divide model.

### Owned registry-handle duplication

The Windows runner connects registry handles to `DuplicateHandle`, native
`NtDuplicateObject`/`ZwDuplicateObject`, and `NtClose` through an ownership
bridge. The admitted subset is same-process, non-inheritable duplication with
`DUPLICATE_SAME_ACCESS` or an explicit concrete subset of the source grant,
optionally `DUPLICATE_CLOSE_SOURCE`. Native duplicates return NTSTATUS without
changing Win32 last-error state; both process handles must be the current-process
pseudo-handle. Generic/MAXIMUM_ALLOWED requests and access expansion fail closed.
KEY_WOW64 selector bits choose a view and are not retained as granted rights.
The duplicate has an independent lifetime but retains the source key object,
granted-access metadata and deletion tombstone. It cannot retarget a newly
created key at the old pathname. Active transacted duplicates remain routed to
their private overlay; they do not expose uncommitted changes to ordinary keys.
Unsupported inheritance/access-selection modes stop before mutation. Predefined
HKEY constants are not duplicable kernel handles. These checks do not claim
complete access enforcement for every existing registry API.

The process-environment plugin reserves an owned zeroed page for the PEB rather
than allocating only its populated prefix. Native NTDLL reads AMD64 pShimData at
`+2d8`; the old 256-byte allocation let that read alias later loader records.
Loading an additional real runtime therefore looked like an enabled shim table.
The larger reserved region prevents module-count-dependent process state; it
does not implement appcompat or claim semantics for every reserved PEB field.


## Explicit native AMD64 exception runtime

`windows/emulation:native_exceptions.star` binds explicitly supplied real NTDLL
and MSVCRT PE images. RaiseException marshaling tail-enters native RtlRaiseException;
NTDLL walks actual PE unwind tables and native MSVCRT chooses and executes its
own cleanup/catch funclets. RtlUnwindEx and RtlRestoreContext remain native code.
The bridge does not replace private installer routines or manufacture HRESULTs.
It is opt-in, requires AMD64, bounds retained exception records, and exposes
`finish(machine)` for teardown after all native calls. Its `state.raises` is an
input audit, not an independent claim that exceptions were handled. Unsupported
hardware dispatch, dynamic tables, privileged returns and nonlocal transfers
across embedding `machine.invoke` boundaries are not silently emulated.

NtQueryVirtualMemory/ZwQueryVirtualMemory class 6 (MemoryImageInformation) accepts
only the current-process pseudo-handle and actual loaded PE extents. Its x86 and
AMD64 layouts are 12 and 24 bytes. Short outputs remain untouched; non-image
addresses and unimplemented classes fail explicitly. Signing level zero means
unverified, not trusted. Native NTDLL uses this boundary to discover its mapped
exception tables, without reading host memory or synthesizing loader tables.

The AMD64 processor implements FNSTCW and FXRSTOR for the admitted reset x87
state; FXRSTOR restores all sixteen XMM registers and validated MXCSR atomically.
Non-reset x87 contexts remain explicitly unsupported. IRETQ admits only unchanged,
non-null CPL3 CS/SS selectors and canonical 48-bit RIP/RSP. It consumes all five
long-mode frame slots, preserves IOPL and appropriately restricts IF, restores RF,
and rejects task/virtualization flags and privilege/selector changes before
mutating CPU state. The Windows environment initializes CS=33h and SS=2bh;
segment bases remain independent. These instructions let real NTDLL capture and
restore the language-handler context rather than substituting a catch jump.

### Native registry metadata and performance counters

`NtQueryKey` supports KeyFullInformation (class 2) and KeyCachedInformation
(class 4). Both require KEY_QUERY_VALUE and preserve the separate deletion and
handle-lifetime checks. Full information reports source-backed class bytes,
current direct child/value counts, and UTF-16 byte maxima. Short fixed headers
return STATUS_BUFFER_TOO_SMALL without output; a complete header with truncated
class data returns STATUS_BUFFER_OVERFLOW with the full required length. Source
key timestamps are preserved; overlay writes do not synthesize a running registry
clock. Newly created classless keys use zero time. Other information classes
remain explicit unsupported boundaries.

Hive key attributes `class_bytes` and `last_write_time` expose the raw class
payload and unsigned NT FILETIME, respectively. They are read-only metadata,
not a mutation API or an inferred empty class.

`NtQueryPerformanceCounter`/`ZwQueryPerformanceCounter` share the existing
Win32 deterministic clock and 10 MHz frequency. Both outputs are 64-bit on x86
and AMD64; frequency is optional. The native API returns NTSTATUS and leaves
last-error unchanged. It does not measure host execution time.
