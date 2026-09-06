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
