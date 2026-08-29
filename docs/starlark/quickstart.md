# trex Starlark quickstart

trex runs a Starlark file whose public `main(args)` function is the entry
point:

```starlark
def main(args):
    source = open(args[0])
    print(source.size)
```

Run it with:

```console
trex script.star input.iso
```

Use `-` as the script name to read one complete script from standard input.
This mode is intended for reproducible one-off programs:

```console
trex - input.iso <<'STAR'
def main(args):
    image = filesystem.iso9660(open(args[0]))
    print(image.root.files)
STAR
```

## Modules

Workspace modules are resolved relative to the entry script. Embedded standard
library modules use `@stdlib//directory:file.star` labels:

```starlark
load("@stdlib//debug:gdb.star", "read_u32")
load(":local_helpers.star", "select_media")
```

Modules are cached within one runtime. trex rejects cycles and does not
extract embedded modules to the host filesystem.

## Language options

trex enables sets, `while`, recursion, top-level control flow, and global
reassignment. Starlark is not Python: it has no `import`, exception-catching
statement, `del`, or Python object model. Optional domain lookups should use
the relevant `find` or `get` operation and test for `None`.

## Scoped REPL

Call `repl()` from a Starlark function to pause it and read Starlark statements
from the runtime's line console:

```starlark
def main(args):
    disk = build_disk(open(args[0]))
    working = block.overlay(block.device(disk))
    repl()
```

The initial REPL namespace contains predeclared APIs, module globals, closure
variables, and assigned caller locals. Values are shared: mutating a list,
directory, overlay, VM, or debugger object remains visible after the REPL.
Rebinding a REPL name does not rewrite the suspended function's lexical local.

Expressions print their value and store it in `_`. Multiline `def`, `for`,
`while`, and `if` statements use a blank line to finish the block. Evaluation
errors print a backtrace and return to the prompt. End-of-file resumes the
calling function.

The REPL uses the same thread, module cache, and runtime resource registry as
the caller. VMs and protocol sessions remain live until explicitly closed or
the outer runtime exits. Nested REPL sessions are rejected.

Use `help(binary)`, `help(binary.read_u32le)`, or a qualified string such as
`help("binary.u32le")` to inspect runtime documentation.

## Output ownership

Archive members, filesystem images, partitions, and generated disks are lazy
trex files. Keep them in memory and pass them directly between APIs.
Call `write(path, value)` only for a requested independently useful final
output, such as a complete disk image, screenshot, trace, or report. The
default 64 GiB output budget fails before creating an oversized output; pass
an explicit larger `max_bytes` only for an intentionally larger final result.

## Nested archives

Archive members remain lazy trex files, so container formats can be
composed without extracting intermediate host files. For example, a Debian
package is an `ar` archive containing XZ-compressed tar archives:

```starlark
def main(args):
    package = archive.ar(open(args[0]))
    control = archive.tar(archive.xz(package["control.tar.xz"]))
    print(control["/control"].read())
```

Use `scripts/inspect/debian_package.star` to list package members, list the
control or data archive, or inspect one path and preview its first 64 bytes.
