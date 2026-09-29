# Virtual shell and Linux build environment

This is an in-process build-environment implementation, not a wrapper around
`/bin/sh`, host utilities, a native compiler, or a guest Linux installation.
GNU Hello 2.12.1 now completes its original configure, build and upstream test
suite in this environment. The same generated executable is also validated
on native Linux/amd64; this is not general POSIX or GNU tool compatibility.

## Components

- `emulator/shell`: POSIX parsing and word expansion via the BSD-licensed
  `mvdan.cc/sh/v3` syntax/expand/pattern packages; our own executor, virtual
  filesystem and command dispatch. The host-backed `interp` package is not used.
- `shell.MemoryFS`: trex byte-channel file handles, independent open offsets,
  shared offsets for duplicated descriptors, reference-counted open handles,
  open/unlinked file lifetime, stable virtual inode numbers and deterministic
  logical modification times. File data and source/argument expansion are bounded.
  `ImportDirectory` imports existing trex `filesystem.Directory` values.
- `emulator/linux`: static ELF64/amd64 loading, BSS initialization, static PIE
  placement, an aligned argv/envp/auxv stack, instruction and memory budgets,
  and a small Linux syscall environment on the existing amd64 processor.
- `emulator/buildenv`: installs virtual commands into a `MemoryFS`, routes `cc`
  to Renvo's portable `CompileCommand`, writes outputs back to the same virtual
  filesystem, and runs generated ELF files in the Linux emulator.

The shell implements functions, loops, case, conditionals, subshells, pipelines,
command substitution, heredocs, redirections/descriptor duplication, eval,
sourced scripts, exported/prefix variables, basic `read`/`test`/`printf`, and
EXIT traps. Background lists run asynchronously with virtual `$!` identities
and scoped `wait` status collection. Initial utilities include `cat`, `mkdir`, `rm`, `rmdir`, `basename`,
`dirname`, `expr`, `ls`, streaming `sed`, basic `grep`, regular-file `cp`/`mv`, cancellable `sleep`, and normal-format
`diff`. Additional utilities include byte-oriented `tr`, C whole-line `sort`,
adjacent-line `uniq`, streaming C-locale `wc`, `touch`, `chmod`, virtual `awk`,
and virtual `make`. Buildenv also supplies a UTC `date` with an injectable
`Environment.Now` clock; unsupported timezones and format directives are explicit
errors. A nil clock uses `time.Now`, converted to UTC without host timezone lookup.
`sed` supports transliteration, labels/branches, hold/pattern spaces, nested
blocks, and deferred file reads. Quoted heredocs preserve literal backslashes. Arithmetic expands
parameters before parsing and supports signed 64-bit operations, assignments,
and short-circuit evaluation. `read` handles non-whitespace IFS and escapes. Utility option sets are deliberately
explicit; unsupported options and constructs are errors rather than silent no-ops.

Ordinary command exits are returned as a numeric status. Missing commands in
the virtual installation return 127. Unsupported emulator operations are Go
errors, including within `if`, `!`, pipelines and command substitutions. This
prevents an implementation gap from silently passing as a negative feature probe.
Compiler diagnostics are genuine nonzero command exits.

## Go API

```go
files, err := shell.NewMemoryFS(64 << 20)
// Check err.
environment, err := buildenv.New(files)
// Check err; New refuses to replace existing tool files.
result, err := shell.Run(ctx, sourceReader, "./configure", shell.Config{
    FS: files,
    Dir: "/source",
    Env: map[string]string{"PATH": "/bin", "LC_ALL": "C"},
    Stdout: output,
    Stderr: diagnostics,
    Command: environment.Command,
})
// Check both err (emulator failure) and result.Status (shell exit status).
```

Populate `/source` before running. Compile with `-tags renvo_bundle` to make
Renvo's bundled C headers and runtime available. Without that tag, header-free
C still works but the integration must not pretend a libc/sysroot is present.
The APIs take only guest paths and portable readers/writers. Caller-provided
I/O and command handlers must honor cancellation; a blocking arbitrary reader
cannot be forcibly interrupted by the emulator.


## Static object linker

`buildenv.New` installs `/bin/ld`, backed by the portable
`driver.LinkCommand` API. Sources, relocatable objects, relocations and final
image construction remain in memory. `cc` object-only linking shares the same
linker; neither command calls a host linker. The identity explicitly says
`renvo ld`, not GNU ld or BFD.

The initial subset links ELF64/amd64 relocatable objects to a static executable
using Renvo's **main-calling startup**. This is not GNU ld's raw `_start` contract.
It supports `-o FILE`, `-static`, `-s` (output is already stripped), `-nostdlib`,
`-v`, `--version`, `--`, and quoted `@response` files. It does not automatically
supply libc. The `cc` object-link path resolves actual bundled libc objects from
undefined ELF symbols, including strings, allocation, streams, locale, wide
characters, file control, resource limits and the Linux syscall bridge. Each
library source is compiled separately; headerless configure probes do not merge
incompatible prototypes. Hosted object startup initializes argv/environment and
GNU program names, then calls `exit(main(...))` so return runs exit callbacks.
`-nostdlib` disables automatic providers. There is no library-directory search, shared or relocatable output,
entry overrides, or linker scripts. Unsupported options and bad inputs return
nonzero diagnostics without replacing an existing output.

`ar r/c/s/D` and `ranlib` create deterministic ordinary Unix archives with a GNU
symbol index. The reader accepts GNU and BSD long names. The linker extracts
only members needed by strong unresolved symbols, reaching a fixed point at
each archive's command-line position. No host archive tools are used. Archive
replacement, long names, index offsets, malformed-input bounds, backward member
dependencies, unused members and command-line order have regression coverage.

Execution tests cover separate-object function and data relocations, argc/argv,
creation masks and unresolved symbols. Native frontend acceptance additionally
checks the object `main` ABI: it must remain an ordinary exported C function,
not the compiler's special hosted `appMain` entry.

## Creation masks and command discovery

Shell `umask` supports numeric masks and symbolic permissions, including `-S`.
`Config.Umask` defaults to 0022 (a non-nil zero pointer requests 0000). Children
inherit a copy; masks never mutate host state. Redirections, mkdir, copies,
compiler outputs and guest file creation apply the active mask when creating a
file, retaining existing modes on truncation. Linux syscall 95 changes only the
current process mask. MemoryFS implements the optional `ModeFileSystem` creation
interface; legacy providers cannot silently ignore a non-default requested mode.
Linux/amd64 Renvo `fopen` requests 0666 atomically, not executable permissions.

`command -v` discovers functions, implemented builtins/utilities and executable
virtual files without executing them. Plain `command` bypasses function lookup;
`-p` and `-V` remain unsupported. Callback-only commands need a discoverable file
in the virtual installation. `buildenv.New` provisions `/tmp` and installs
`uname`, whose identity is the explicit Linux/x86_64 target, with emulator release
`0.0.0-trex`, not the host kernel. No GNU libc or complete kernel is implied.

## Asynchronous execution and clocks

Jobs share the virtual filesystem but have isolated shell variables, functions,
working directories, and wait tables. Noninteractive background lists start with
null stdin unless explicitly redirected. Inherited descriptors share offsets and
remain open until their last reference closes; command substitutions and pipes
therefore include output from background descendants that retain their writers.

`wait` accepts virtual numeric job IDs or waits for all jobs in the current shell.
It does not treat ordinary nonzero child statuses as emulator failures. An
unsupported operation in any job is still returned as an emulator error, even
when the script never waits for that job.

The public `Run` call **drains outstanding jobs before returning**, so no job can
continue accessing caller resources after completion. A foreground emulator
failure or context cancellation cancels remaining work and joins it. This API
boundary differs from a host shell that can leave processes behind. Command,
filesystem, and clock providers must honor cancellation; arbitrary blocking
caller I/O cannot be forcibly interrupted.

`Config.MaxJobs` (default 256) bounds both active jobs across an execution and
retained wait results per shell. `wait` releases retained results. `Config.Sleep`
accepts a context and `time.Duration`; nil uses Go's cancellable timer. An injected
virtual clock must implement a real wait, not report success without advancing
its clock. The sleep utility accepts one nonnegative decimal-seconds operand.
MemoryFS modification times use a deterministic logical clock. `SetModTime`
imports explicit archive timestamps and advances that clock so later writes
are newer. It never consults the host clock; tar extraction order is not a
substitute for release timestamps.

## AWK and make

AWK uses MIT-licensed GoAWK 1.32.0 in-process. Input, output, `getline`, file
redirections, and `ENVIRON` are connected only to the virtual filesystem,
explicit streams, and exported shell environment. `NoExec` rejects `system()`
and command pipes rather than invoking a host shell. Each invocation has a
context deadline (`Config.MaxAWKTime`, default 30 seconds). Source and virtual
filesystem storage are bounded; GoAWK's internal array/string heap is not a
hard memory sandbox. Byte-oriented C-locale operation is selected.

The make utility is a new portable subset, not GNU make and not Renvo's
small command planner. It supports recursive/simple/conditional/appended
variables, nested variable references, common text functions, includes,
conditionals, `define`, explicit and pattern/static-pattern rules, suffix-rule
forms, phony and order-only prerequisites, automatic variables and directory
forms, and virtual shell recipes. Each recipe has a fresh shell environment.
Dependency checks use actual modification times after recipe execution: a
stamp recipe that leaves a file unchanged does not force its dependents dirty.
`$(shell ...)` uses bounded capture and waits for inherited output descriptors.
Source, step, nesting, and expansion limits apply across make and shell work.

It is not general GNU make conformance: built-in implicit rule databases,
parallel scheduling/jobservers, archive members, makefile remaking/restarts,
double-colon and target-specific rules, and several GNU functions/options
remain unsupported. Recursive command-line override/MAKEFLAGS propagation is
not yet complete. The tested build uses serial explicit Automake recipes.

## Validation

From the trex checkout:

```sh
go test -race -tags renvo_bundle ./emulator/shell ./emulator/linux ./emulator/buildenv
TREX_HELLO_CONFIGURE=help go test -tags renvo_bundle ./emulator/buildenv -run '^TestHelloConfigure$' -count=1
TREX_HELLO_CONFIGURE=configure go test -tags renvo_bundle ./emulator/buildenv -run '^TestHelloConfigure$' -count=1
# Full configure/build, seven upstream tests, and same-image native/virtual CLI checks:
TREX_HELLO_CONFIGURE=build go test -tags renvo_bundle ./emulator/buildenv -run '^TestHelloConfigure$' -count=1
```

The network test fetches `hello-2.12.1.tar.gz` from GNU's FTP archive using HTTPS,
verifies SHA-256
`8d99142afd92576f30b0cd7cb42a8dc6809998bc5d607d88761f512e26c7db20`,
and loads the archive into memory. It runs the original configure without
patching it or pre-answering cache variables. No downloaded tarball, extracted
source tree, config log, or compiled intermediate is written to host disk.
Normal tests are offline; the network workload is explicitly opt-in.

The `build` workload runs the original `make`, `make check`, and `./hello`:
all seven upstream tests pass with zero skips. The injected clock selects a
full-moon date so the upstream long-greeting test actually runs; no test source
is patched. It checks the output contains each individual PASS result.

The exact final ELF is run both in the emulator and on native Linux/amd64 for
default/custom/long greetings, traditional output, help, version, invalid options,
extra operands and `/dev/full` failures. Exit status, stdout and stderr must
match. Only that final executable is materialized for native acceptance; no
source, archive, object or config artifact crosses through host files. The
native comparison is available only on Linux/amd64 and is reported when absent.

Focused offline tests also cover separate-object libc startup, environment,
program names, exit callbacks, resource-limit errors, bounded string operations,
archive linking, descriptor flags, shared offsets and native/virtual file-stream
behavior. `test -t` uses explicit terminal capabilities; buffers, pipes and
ordinary files are not terminals. `/dev/full` reads zeros and returns ENOSPC on
writes, including when inherited as stdout by a generated executable.

The compiler fixes include preprocessed system headers in `cc -c`, C11 inline
linkage and its feature macro, hosted versus explicit freestanding mode, and
unevaluated unary `sizeof` operands in constant expressions. Invalid field/type
probes remain errors. Bundled headers are installed in MemoryFS so a second
make invocation can inspect the same files named by compiler dependencies.

## Remaining work and limits

This establishes the complete **GNU Hello 2.12.1, Linux/amd64, C-locale** build
and execution workload, not arbitrary Gnulib applications. The libc/sysroot is
still a subset: many open/stat/time operations and general resource controls are
not implemented. The virtual `getrlimit` supports RLIMIT_NOFILE with the actual
fixed descriptor capacity; unsupported resource controls are emulator errors.
`config.guess` defaults the unrecognized Renvo libc to a `-gnu` tuple; that is
not evidence of glibc compatibility. See `renvo/libc/README.md`.

This is not full POSIX conformance or a general Linux compatibility layer.
Interactive job control (`jobs`, `kill`, process groups), asynchronous signal
delivery, symlinks, ownership/permission
security enforcement, several shell options and utility operations remain
unimplemented. MemoryFS permissions are metadata for probes, not a security
boundary. Non-EXIT trap registrations are retained, but there is no external
signal delivery API. Some malformed builtin invocations still return emulator
errors rather than the precise POSIX exit status.

The Linux layer currently handles descriptor `read`/`write`/`close`/`dup2`, guest
`open`/`openat` through a portable filesystem provider, exit/exit_group,
anonymous private mmap, mprotect, growing brk, umask, getpid and FS-base arch_prctl.
Other syscall numbers fail explicitly. Files opened by an execution are closed
on exit or failure. Duplicated descriptors share their open-file description,
offset and lifetime, with the channel closed only after the final alias. There is no dynamic linker, fork/exec, networking or host
syscall forwarding. `AT_RANDOM` is supplied
by the caller and defaults to zeros for deterministic tests, **not entropy**.
