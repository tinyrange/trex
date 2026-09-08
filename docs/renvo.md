# In-memory compilation with Renvo

`renvo.go`, `renvo.cc`, and `renvo.make` compile sources held in a Trex
`directory()`. Strings, bytes, and portable file values are supported. The
compiler reads headers and imported packages from that virtual tree, with
Renvo's bundled Go standard library available automatically.

Every call returns a `compiledModule` with `ok`, `diagnostic`, and `binary`.
Check `ok` before consuming the binary. C and Make builds also return an
immutable `outputs` dictionary containing generated virtual file names and
their bytes. Compiler outputs remain in memory, and the source directory is
unchanged.

```starlark
result = renvo.cc(
    source=source,
    input="main.c",                 # Or a list of source paths.
    target="windows/386",
    flags=["-Iinclude", "-DVALUE=42"],
    arena_size=1 << 20,
)
if not result.ok:
    fail(result.diagnostic)
```

`flags` accepts Renvo's C compiler options, including preprocessing, object
compilation, and its supported object-linking options. The default standard
library bundle contains `std/`; projects using C library headers and sources
can provide them in their virtual `libc/` tree, or build Trex with
`-tags renvo_bundle` to include Renvo's library sources. No host include directories
or compilers are used. The default arena is 32 MiB; choose an arena that fits
the memory budget of the eventual execution environment.

```starlark
result = renvo.make(
    source=source,
    input="project/Makefile",
    target="windows/386",
    targets=["all"],
    output="app.exe",
    arena_size=1 << 20,
)
```

Make paths are relative to the Makefile's virtual directory. Renvo's Makefile
language supports variable assignments, explicit dependency rules, `.PHONY`,
and the automatic variables `$@`, `$<`, and `$^`. Recipes must invoke `renvo`
directly. The compiler and linker execute in-process, without a shell or host
`make`. Recipes rebuild each invocation and stop on the first failure;
intermediate outputs become available to subsequent recipes in memory.
`target` and `arena_size` supply defaults for recipes that omit those options.

`output` selects the virtual file returned in `binary`; without it, `binary`
contains the last recipe's primary output. `outputs` includes all generated
files, including dependencies and intermediate files. This is Renvo's
Makefile language, not a GNU Make implementation.

The runnable examples also verify execution using Trex's x86 emulator:

- [C compilation](../scripts/examples/renvo_cc.star) compiles a recursive
  calculation with a virtual header and checks exit code 42.
- [Makefile build](../scripts/examples/renvo_make.star) preprocesses C into a
  virtual `.i` file, compiles it, and checks exit code 42.

Run them with `go run ./cmd/trex scripts/examples/renvo_cc.star` and
`go run ./cmd/trex scripts/examples/renvo_make.star`. Neither example writes
its generated binary to the host.

Windows AMD64 execution is covered by `TestRenvoAMD64Execute`: recursive C
and an in-memory Make build must exit with 42; a Go `fmt.Println` program
must emit exactly `PASS\n` and exit with 0. Run these and the existing x86
examples with `go test ./frontend/starlark -run 'TestRenvo.*Execute'`.
Compilation and PE execution stay in memory. These are bounded execution
smokes, not a claim that the full Renvo self-hosting suite is supported.

## Native ReactOS CI smoke

The `renvo-reactos` GitHub Actions job downloads
[ReactOS 0.4.16](https://sourceforge.net/projects/reactos/files/ReactOS/0.4.16/ReactOS-0.4.16-i386.zip/download)
and verifies its pinned SHA-256 before parsing it. It compiles a Go program for
`windows/386`, constructs the ReactOS system disk and a small test disk in memory,
and boots a fresh QEMU/KVM guest with 512 MiB RAM and networking disabled. The
Ubuntu Actions job grants its runner access to `/dev/kvm` and explicitly requests
KVM; unavailable acceleration fails rather than silently falling back. Local
runs default to TCG and do not require KVM. No host extraction tool or compiler
constructs the guest payload.

The program reads a per-run random input, computes `fib(10)-13`, formats the
answer, and writes a fixed-size result using native Windows file APIs. The host
reads immutable snapshots of the in-memory test disk and requires the exact
nonce-bound answer, including length and padding. An empty file, stale nonce,
partial write, wrong answer, or screenshot change cannot pass the test. A guest
batch wrapper must also confirm exit code zero, and both disk transports must
report zero command errors; writing an answer and then crashing is not success.

```sh
go run ./cmd/trex scripts/smoke/renvo_reactos.star
# Optional already-downloaded media is still checked against the same hash:
go run ./cmd/trex scripts/smoke/renvo_reactos.star \
  media=/path/to/ReactOS-0.4.16-i386.zip output=local/renvo-reactos
```

`cache=directory` selects the original-download cache, `accelerator=tcg|kvm`
selects QEMU acceleration, and `timeout=180` bounds each readiness/result wait
(1–600 seconds). The CI job also has a 20-minute overall limit. Only the original
download is cached; every invocation rebuilds and boots fresh images.

The action fails if the smoke fails, appends a Markdown result to its job summary,
and uploads JSON, screenshots and the guest result as `renvo-reactos-smoke`.
The report starts as failed/incomplete before downloading, so construction or
boot errors cannot leave a success report behind. Consult the action log for
exceptions. All outputs use the `output` prefix; no disk image is written.
This is a bounded native execution check, not full ReactOS or Renvo conformance.
