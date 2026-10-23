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
