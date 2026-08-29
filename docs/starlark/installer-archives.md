# Installer archives

`archive.installer(file)` opens a supported self-extracting installer without
launching it or copying its payload through the host filesystem. The returned
value behaves like the underlying archive: `.files` lists paths, indexed access
returns trex files, and `.find(path)` performs a tolerant lookup.

For collection inventories, `archive.installer_probe(file)` runs the same
bounded parser without failing on an unknown or malformed installer. It returns
a dictionary with `supported`, `recognized`, `format`, `offset`, `size`, and
`error`; supported results also report `container_files` and `payload_files`.
`recognized` remains true for a known format whose version does not yet have a
decoder. Invalid arguments and runtime-initialization failures still raise
errors, while parser and source-read errors remain useful data for choosing the
next decoder to implement.

The supported bootstrap format is a DOS or PE launcher containing an embedded
Microsoft Cabinet. When that Cabinet contains an InstallShield 5 or 6 package,
trex also parses `data1.hdr` and reads the compressed application files
directly from the numbered `data*.cab` volumes. `container` retains the outer
Microsoft Cabinet and `payload` is the deepest recognized archive. Scanning is
bounded to 256 MiB by default and can be reduced with `maximum_scan`.

InstallShield 5 split files are joined directly from the fragment records in
each volume header before deobfuscation and decompression. External payloads
are matched by normalized relative path and size; byte-identical duplicate
members are accepted, while conflicting duplicates remain an error. The
archive's `unresolved` list names external records declared by the media
database but absent from the supplied files.

```python
def main(args):
    disc = filesystem.iso9660(open(args[0]))
    setup = disc["/setup.exe"]
    installer = archive.installer(setup)

    print(installer.format, installer.offset, installer.size)
    print("bootstrap files", installer.container.files)
    for entry in installer.payload.entries:
        print(entry["path"], entry["components"], entry["size"])

    # `write` is optional and creates only the requested final output.
    write("Smc.exe", installer["/Program Executable Files/Smc.exe"])
```

trex verifies per-file MD5 values while reading numbered InstallShield
volumes. Files stored externally beside the volumes, such as `setup.inx`,
remain accessible through the same inner archive.

InstallShield archives may also be opened directly without relying on host
paths or filenames:

```python
package = archive.installshield(
    header = data1_hdr,
    cabinets = [data1_cab, data2_cab],
    external = {"setup.inx": setup_inx},
)
```

A self-extractor can contain more than one nested InstallShield package.
`installer.packages` lists records with `root`, `format`, `payload`, `script`,
and `script_path`, and prevents a
nested package's `data1.hdr` from replacing the primary package merely because
the basenames match. `installer.payload` remains the shallowest primary package
for compatibility. Install plans include files and artifacts from every
package and attach `package_root` provenance to each record.

`entries` deliberately separates `group`, `directory`, and `components` from
the synthetic archive path. For example, Sygate's executable group belongs to
the logical component `<Data>/Program Files`. That metadata is exact, but it is
not by itself a resolved Windows installation directory: the compiled
`setup.inx` script and installer environment choose values such as `TARGETDIR`
at runtime.

## Compiled InstallScript

`archive.installscript(file)` parses the InstallShield aLuZ object format. It
does not execute the installer. `functions`, `blocks`, and `calls` expose the
typed prototypes and instructions, and `find_function(name)` is convenient in
the scoped REPL:

```python
script = archive.installscript(installer.container["/Disk1/setup.inx"])
print(script.find_function("_RegSetKeyValue"))
for call in script.calls:
    if "Reg" in call["callee"] or "Shell" in call["callee"]:
        print(call)
repl()
```

`effects` follows internal wrapper calls to identify candidate registry access
and `CreateShellObjects` operations. Results are explicitly marked
`conditional`: branches, runtime values, existing machine state, and installer
callbacks can decide whether an instruction executes. Literal registry roots,
keys, and value names are resolved when the bytecode establishes them. Unknown
values remain typed bytecode operands rather than being guessed.

`callbacks` exposes the project-function call graph, including callers,
callees, and `entry_candidate` for functions with no incoming project call.
These roots are the externally invoked callback boundaries preserved after
symbol stripping.

`evaluate()` is the bounded abstract interpreter. Its default `application`
entry set evaluates those callback roots; a named entry can be selected for
focused work. It evaluates the
control-flow graph, constant expressions, internal calls, parameter passing,
and small global setter wrappers. Unknown machine-dependent conditions fork,
so an effect is marked `conditional` rather than silently discarded. The
`strings` and `numbers` dictionaries seed global bytecode addresses for a
specific environment. `profiles` supplies portable INI data as
`{filename: {section: {key: value}}}`; the evaluator models profile APIs,
function returns, common by-reference profile-reader wrappers, string-buffer
operations, object properties, and registered InstallScript handlers. Loops
converge by widening disagreeing constants to unknown rather than discarding a
path. Calls expose modeled return values, and `final_globals` records known
terminal global state. `entries` reports completeness and any reached
`semantic_gaps` separately for every callback. `maximum_steps` is a per-callback
budget, so a complex callback cannot prevent later lifecycle entries from being
audited. `incomplete` and `incomplete_reasons` report recursion, depth, or step
bounds instead of presenting a truncated run as definitive.

Protected regions are evaluated along their successful path. Handler
registration and explicit handler dispatch are modeled, including conservative
branching across statically registered candidates when an earlier lifecycle
callback supplied the binding. Exception/failure exits are not treated as
successful installation effects.

## Install plans

`installer.installscript` opens the embedded script when one is present, and
`installer.plan(locations={}, variables={}, components=None)` combines its conservative effects
with the InstallShield file table and shell-object database. The caller
supplies component/system destinations and installer string variables, keeping
the API independent of a host Windows installation:

```python
plan = installer.plan(locations = {
    "<Data>/Program Files": r"C:\Program Files\Sygate\SPF",
    "<TARGETDIR>": r"C:\Program Files\Sygate\SPF",
    "<SHELL_OBJECT_FOLDER>": r"C:\Documents and Settings\All Users\Start Menu\Programs",
}, variables = {"PRODUCT_NAME_NV": "Sygate Personal Firewall"})
for file in plan["files"]:
    if file["resolved"]:
        print(file["source"], "->", file["destination"])
for access in plan["registry"]:
    print(access["operation"], access["root"], access.get("key"), access["conditional"])
for shortcut in plan["shortcuts"]:
    print(shortcut["destination_folder"], shortcut["display"], shortcut["target"])
```

Pass an iterable of exact component names as `components` to plan only the
selected product payload. This is useful when InstallShield media also embeds
its setup engine and support files. Component matching is case-insensitive;
omitting the argument preserves the complete package view.

`registry` includes reads and mutations for auditability. `registry_writes`
contains only create/set/delete operations, while
`definitive_registry_writes` additionally requires a resolved, unconditional,
complete evaluation of that callback entry. Each record carries its
`entry_function`, plus the same `mutation` and `definitive` flags. “Definitive”
is scoped to execution of that entry; installer mode still determines which
callback roots the InstallShield engine invokes.

Files without a supplied component location appear with `resolved=False` and
are named in `unresolved`. `payload.shortcuts` exposes the exact shell-object
records decoded from `data1.hdr`. For Sygate these are the main firewall
shortcut (`smc.exe -start`), online help, and README. `plan["shortcuts"]`
expands their folder, display variable, target, arguments, working directory,
and icon fields using the supplied mappings. `shortcut_calls` separately
retains the conditional `CreateShellObjects` call sites from `setup.inx`.
InstallShield 5 shortcut records additionally expose their component/product
condition, and plans retain it as `component` rather than treating every
conditional shortcut as unconditional.

File-group target expressions are decoded too. Supplying `<TARGETDIR>` resolves
the executable group, `<TARGETDIR>\Help`, and `<TARGETDIR>\Netport`; supplying
`<WINSYSDIR>` resolves the shared system files. Component-name mappings remain
available as explicit overrides.

The plan also exposes `target_defaults`, `profiles`, `artifacts`,
`custom_actions`, and `script_evaluation`. `profiles` contains the bounded INI
files embedded in the installer bootstrap, so portable policy can use package
metadata without opening host files. Target defaults are path expressions
proved from the script and bootstrap INI files. For the Sygate media, `AppType=100` in
`SetAid.ini` proves the default `<PROGRAMFILES>\Sygate\SPF`; without the
profile input the evaluator retains the conditional `SPF` and `SSA` choices.
Artifacts identify PE
images that export `DllRegisterServer` and packaged `.sys`/`.vxd` drivers.
Custom actions contain reachable calls into non-system DLLs such as SetAid;
uninstall entry points are excluded from this installation-oriented view.

For concrete PE registration effects, use the generic portable framework:

```python
load("@stdlib//windows:installer.star", "analyze")

effects = analyze(installer, plan, execute_registration = True)
print(effects["registrations"])
print(effects["services"])
print(effects["drivers"])
```

Registration runs entirely in trex's bounded in-memory x86 emulator.
Packaged files are supplied as memory-backed guest paths and dependencies; no
host process is launched and no intermediate payload is extracted.

`installer(source)` converts the selected payload, definitive registry effects,
emulated registration effects, and shortcuts into a declarative modification
set. It first uses a uniquely proved `TARGETDIR`. For standard InstallShield
packages whose script keeps that value symbolic, it uses the embedded
`Setup.ini` `Startup/AppName` product directory under `Program Files`.
Ambiguous packages fail closed and can be given an explicit `target=` override.

The returned package contains trex file values rather than host staging paths
and can be consumed by a caller-provided filesystem or analysis pipeline.

Payload writes carry replacement intent. Files with fixed PE version metadata
use `if_newer`: the image adapter compares the packaged version with the file
already installed by Windows and retains equal or newer system files. Other
payloads use normal overwrite behavior. This keeps the declarative installer
independent of a particular target filesystem while preserving Windows
shared-runtime version policy.

Shortcut records with a symbolic display variable use the stable media name as
their default when the caller did not supply that variable. Normal shell links
become native `.lnk` files; Internet shortcut records become portable `.url`
files generated by `windows.internet_shortcut`. Ambiguous symbolic defaults and
unknown shortcut types fail rather than producing guessed filenames.

Sygate's outer `Default.dat`, `cltdef.dat`, and `serdef.dat` files are
application configuration variants, not the InstallShield media database.
They are intentionally not interpreted as shortcut records.

## Licensing and provenance

The implementation contains no InstallShield runtime code, installer payloads,
or output from an unlicensed decompiler. Tests construct small synthetic byte
streams. The aLuZ layout was independently implemented using the format
behavior documented by the MIT-licensed
[`jte/installscript-decompiler`](https://github.com/jte/installscript-decompiler)
project, and the source records that reference. No source was copied into
trex. Its full licence is retained in
[third-party format references](../third-party-format-references.md).
Vendor documentation is used only to validate public InstallScript semantics.
Users remain responsible for the licence terms of installers they inspect or
extract; trex does not redistribute third-party software.
