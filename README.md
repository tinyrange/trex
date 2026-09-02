# trex

trex is a preservation-oriented Go and Starlark toolkit for inspecting,
decoding, manipulating, and debugging historical software formats. Its core
APIs operate on caller-owned files, byte channels, events, and clocks so they
can be used without host mounting, extraction, or format-conversion tools.

Product and project names mentioned in this repository are the property of
their respective owners. Their use identifies interoperable formats and
systems and does not imply endorsement or affiliation.

## Capabilities

The tables below describe the implemented behavior, not merely formats that
trex can identify. In particular:

- **read** means an existing object can be parsed and its payload exposed;
- **build** means trex can construct a new complete object from logical input;
- **in-place write** means a mounted existing object can be changed without
  rebuilding it.

A read-only mount and a builder are separate capabilities. Unless a row says
otherwise, parsed archive members and filesystem files are read-only, and no
encrypted variant is supported.

### Filesystems, partitions, and disks

| Component | Read support | Build and write support | Important limits |
| --- | --- | --- | --- |
| In-memory directory | Logical directories and files backed by bytes or lazy files; normalized portable paths and DOS attributes. | Mutable logical tree; creates parents, replaces files, sets metadata and attributes, and emits TAR or gzip-compressed TAR. | It is a construction tree, not a mounted host filesystem. Metadata is consumed only by builders that can represent it. |
| FAT | FAT12, FAT16, and FAT32 BPBs, allocation chains, directories, VFAT long names, case-insensitive lookup, and raw boot/FAT metadata views. | Builds complete FAT12, FAT16, and FAT32 images with VFAT names, DOS attributes, labels, file ordering, hidden-sector/CHS geometry, and caller-supplied boot code. | Mounted FAT is read-only. Builders use 512-byte sectors; they do not update an existing volume or preserve timestamps and extended metadata. |
| NTFS | Reads resident and non-resident unnamed data, fragmented and sparse runs, multi-record attribute extents, NTFS-compressed data through LZNT1, directories and large indexes, hard links, named data streams, per-file security descriptors from `$Secure`, variable sector/cluster geometry, and variable MFT-record sizes. Path lookup is case-insensitive. | Builds complete NTFS **1.1** and **3.1** on-disk formats. Both include boot/MFT metadata, allocation bitmaps, directory indexes, hard links, ordered attribute lists for extension records, DOS short names, timestamps, and labels. The 3.1 builder also emits canonical `$Secure`/`$Extend` metadata, preserves supplied security descriptors, and can preserve caller-supplied reparse tags and raw reparse buffers in `$REPARSE_POINT` attributes and the `$R` index. Boot code, hidden sectors, `$LogFile`, and an exact `$UpCase` can be supplied; the Windows 8.1 profile emits its Unicode 6.2 table and uses that same table for index collation. | Mounted NTFS is read-only; there is no in-place editor. These are on-disk version claims, not blanket compatibility claims for every Windows release that used NTFS. The reader is structurally compatible rather than version-gated, but automated coverage is for generated 1.1 and 3.1 images. EFS encryption, transactional-log replay, interpretation of reparse-point payloads, quotas, object IDs, and mutation of existing volumes are not implemented. The builder uses 512-byte sectors and clusters and does not create compressed, encrypted, sparse, or named-stream files. |
| ISO 9660 | Primary volume descriptors, directory trees, ISO version suffixes, all three Joliet escape levels, and the initial El Torito boot catalog/image. Joliet is preferred when present. | No ISO builder. A regular file permits a same-size payload write only when its backing file is writable; the directory structure and exposed boot metadata remain read-only. | No Rock Ridge interpretation, multi-extent file assembly, session authoring, directory mutation, or ISO rebuilding. Only the initial El Torito boot entry is exposed. |
| UDF | Anchor and volume descriptor discovery, type-1 partition maps, file-set descriptors, ordinary and extended file entries, OSTA compressed Unicode names, and embedded, short, and long allocation descriptors. | Read-only; no builder or in-place writes. | No virtual allocation table, sparable, metadata, or other type-2 partition-map handling; no allocation-extent chaining or UDF filesystem repair. |
| MBR | Validates the boot signature and exposes up to four primary partition slices, boot flags, type bytes, LBAs, sizes, and disk signature. | Builds a bootable MBR containing one primary partition, optional boot code, disk signature, explicit start LBA, partition type, active flag, and optional legacy CHS geometry. | 512-byte sectors only. No EBR chain/logical partitions, hybrid tables, or in-place partition editing. |
| GPT | Validates the primary GPT header and partition-array CRCs and exposes GUIDs, UTF-16 names, attributes, LBAs, offsets, and partition slices. | Builds 512-byte-sector GPT disks with a protective MBR, primary and backup headers/tables, explicit disk/partition/type GUIDs, attributes, names, placement, and up to 128 partitions. | No recovery from a damaged primary table, hybrid MBR, non-512-byte logical sectors, or in-place partition editing. |
| VHDX | Read-only virtual-disk view using redundant checked headers, region and metadata tables, BAT mapping, 512- or 4096-byte logical sectors, fully-present payload blocks, and zero/unmapped block states. | No VHDX builder or writes. | Differencing disks, active-log replay, partially-present payload blocks, and unknown required regions/metadata are rejected. |
| Sparse generated images | Lazy random reads over data-, file-, and zero-backed extents; nested allocation maps and complete streaming output. | Builders compose complete images without materializing zero gaps. | Generated images are immutable and overlapping or out-of-range extents are rejected. |
| Block devices and cache | Portable geometry/capability model, bounded random I/O, file-backed devices, allocation extents, and a bounded concurrent read cache with prefetch forwarding. | Writes, flush, zero, trim, extent discovery, and prefetch are capability-negotiated rather than assumed. | Operations fail explicitly when the backing device lacks the requested capability. |
| Copy-on-write overlay | Reads through to an immutable base and records dirty chunks in bounded memory; exposes dirty extents, statistics, operation traces, and VM leases. | Random writes and zeroing; generation-based immutable snapshots; commit seals the overlay into a complete lazy file view. | Not durable by itself. Dirty memory is bounded, commit requires no active lease, and a sealed overlay accepts no further writes. |
| NBD | In-process fixed-newstyle server over a caller-owned byte channel; export discovery, structured replies, base-allocation status, bounded concurrent requests, and read-only exports. | Advertises and serves write, flush/FUA, trim, write-zeroes, cache hints, and multi-connection only when the device supports them. | No TLS negotiation or host NBD tool is used. Request sizes, workers, queues, and deadlines are bounded. |

### Archives and compression

| Component | Implemented support | Important limits |
| --- | --- | --- |
| AR | Reads System V/GNU archives, GNU filename tables, BSD extended filenames, duplicate names, and member timestamp/UID/GID/mode metadata. | Read-only; symbol tables are ignored as non-payload metadata. |
| Microsoft CAB | Reads single cabinets and ordered cabinet sets, including continued files/folders. Decodes stored, MSZIP, Quantum, and LZX folders with dictionary/history handling and optional bounded caching. | Read-only; no cabinet writer. |
| KWAJ | Reads original-name metadata and decodes methods 0–4: stored, XOR, LZSS, LZH, and MSZIP. | Produces a bounded decoded file; no encoder. |
| 7-Zip | Reads format-major-0 archives using a single Copy or LZMA coder per folder and maps packed folders to file entries with CRC validation. | No coder graphs, BCJ/Delta/LZMA2/PPMd, encryption, external streams, or externally stored filenames. Read-only. |
| SFP | Reads version-1 SFP package trees, names, package label, timestamps, flags, offsets, and payload files. | Version 1 only; read-only. |
| SZDD | Decodes classic `SZDD` mode-A LZSS files with output bounds and truncation checks. | No other mode and no encoder. |
| TAR | Reads regular entries, directories, links, devices, FIFOs, GNU/PAX metadata, and resolves archive hard links. Builds deterministic basic directory/file TAR or gzip-TAR output from an in-memory directory. | Direct file views reject GNU sparse entries. The builder emits ordinary files/directories, not the complete metadata model accepted by the reader. |
| WIM | Reads single-file, multi-image WIM trees, security and file metadata, hard links, reparse tags and payloads, and chunked uncompressed, XPRESS-Huffman, or LZX resources with lazy cached reads. Individual entries expose their metadata and lazy payload; image trees can be applied to an in-memory directory while preserving hard links and raw reparse points. | Read-only source format; no WIM writer, split-WIM assembly, solid-resource authoring, or integrity-table repair. Applying a reparse point preserves its raw data but does not interpret its target semantics. |
| XZ | Exposes concatenated XZ streams as one read-only random-access file, validates stream headers/footers/index CRCs and padding, and enforces a dictionary limit. | Decompression may replay from the beginning for backward random reads; no encoder. |
| ZIP | Reads ZIP directories and lazily exposes Store and Deflate members through Go's ZIP decoder. | Read-only; no encrypted members or archive mutation. Streaming ZIP creation is available separately in the web response layer. |
| LZX | Decodes Microsoft LZX verbatim, aligned, and uncompressed blocks with 15–21-bit windows, repeated offsets, Intel E8 transformation, and CAB or WIM framing. | Decoder only. |
| MSZIP | Decodes cabinet/KWAJ Deflate blocks with a 32-KiB preceding dictionary and compatibility handling for early encoders. | Decoder only; each call requires the exact expected output size. |
| XPRESS | Decodes Microsoft's XPRESS-Huffman block format used by WIM resources. | Huffman variant only; decoder only. |
| LZNT1 | Decodes chunked LZNT1 streams, including overlapping phrase copies and the position-dependent token split used by NTFS compression. | Decoder only; callers supply the exact expected output size. |

### Databases and locale data

| Component | Read support | Build support and important limits |
| --- | --- | --- |
| ESE / Jet Blue | Validates format versions `0x620` and `0x623`, 2–32 KiB pages, redundant database headers, old and extended page checksums, catalogs, multi-level table trees, fixed/variable/tagged columns, inline multi-values, and the represented scalar, binary, text, GUID, and time types. Reads remain lazy through `storage.Reader`, and verification has an explicit page bound. | Builds clean format-`0x620` revision-`0x14` databases with 32 KiB pages, system catalogs, database/table/index space trees, primary and secondary multi-page B+trees, checksums, and caller-sized reserved tails. Unicode indexes require target collation supplied through the portable interface or `sort_data`. No in-place mutation, transaction-log replay, recovery, separated long-value reconstruction, compression, encryption, or other ESE generations are implemented. |
| SQLite 3 | Validates 512-byte through 64-KiB page databases; reads `sqlite_schema`, table and index interior/leaf B-trees, overflow chains, row IDs, null/integer/real/blob/text records, and UTF-8, UTF-16LE, or UTF-16BE text. An optional WAL is checksum-validated and overlays the last complete committed transaction; an incomplete trailing transaction is ignored. Reads are bounded by page, depth, and caller-supplied row limits. | Builds clean SQLite 3 databases from explicit table, index, view, and trigger definitions. It emits schema records, signed row IDs, table/index B-trees, overflow pages, all supported scalar record types, selectable page size/text encoding, user version, and application ID. The builder expects already ordered rows and complete index records; it does not execute SQL, derive indexes, enforce constraints, update existing databases, emit WAL/journal files, manage freelists, or implement SQLite virtual tables and extension behavior. |
| Windows NLS sorting | Validates and decodes caller-supplied `SortDefault.nls` section offsets, base character weights, sort GUIDs, exception tables, and ordinary BMP sort-key levels used by persisted Windows indexes. | Produces sort keys without calling host locale APIs. Ordinary weights, nonspacing marks, case/width/kana suppression, symbols, and punctuation are supported. Expansion, compressed weights, East Asian special weights, Hangul/Jamo, and extension-A scripts fail explicitly rather than emitting incompatible keys. No Microsoft NLS data is embedded. |

### Installers and installation effects

| Component | Implemented support | Important limits |
| --- | --- | --- |
| Installer discovery | Bounded recognition of DOS/PE self-extractors containing an embedded Microsoft CAB, including nested InstallShield packages; probes report recognized-but-unsupported formats without aborting an inventory. | This is not a generic executable unpacker. The supported bootstrap path must expose the cabinet in the scanned range. |
| InstallShield cabinets | Reads InstallShield cabinet metadata/data layouts identified as versions 5–16, split volumes, external files, file groups, components, shell-object shortcut records, compression/obfuscation, and version-6+ MD5 payload checks. Versions 5 and 6 have direct synthetic round-trip coverage. | Read-only. Layouts outside the implemented families return a typed unsupported-version error; accepting a version does not imply every vendor extension is modeled. |
| InstallScript | Parses the implemented `aLuZ` object layout: metadata, variables, types, prototypes, functions, control-flow blocks, strings, call sites, and callbacks. Provides bounded constant evaluation and reports unresolved branches/opcodes rather than inventing state. | It is a static/abstract evaluator, not a full InstallShield runtime. There is no blanket version claim beyond inputs matching the implemented `aLuZ` layout; results carry incompleteness and semantic-gap data. |
| Installer plans | Resolves selected components, file groups, destinations, external/nested packages, shortcuts, registration candidates, and declarative file/registry effects. | A plan records effects; it does not execute an installer process or silently guess unresolved destinations. |

### Windows binary and data formats

| Component | Implemented support | Build and mutation support / limits |
| --- | --- | --- |
| PE/COFF images | Parses PE32 and PE32+ headers, sections, imports, exports/forwarders, resources, messages, version data, CodeView references, pointer-string tables, and MSFT type libraries. Disassembles i386/amd64 code by RVA and interprets bounded AMD64 exception-directory unwind records against a caller-supplied stack snapshot. | Bounded RVA reads and same-layout byte patches with checksum update; constructs small PE32 executables. It is not a general linker, does not rebuild arbitrary section layouts, and does not implement every architecture's unwind format. |
| NE images | Parses the NE structures needed to transform multi-module fast-boot layouts and relocates their resource/segment references. | Specialized transformation rather than a general-purpose NE editor. |
| LE/VxD libraries | Decodes Windows 9x W4-compressed VxD libraries, lists W3 members, and rebuilds a W3 library from validated LE members. | Supports the implemented DS/W4 compression and W3 library layout, not arbitrary LE/LX executable editing. |
| NT registry hives | Reads `regf` keys, values, classes, security cells, segmented large values, and subkey-index variants. Emits logical key/value patches, applies bounded raw hive changes, and can construct the companion legacy log header. Builds formats 1.2–1.5, including template-derived NT 3.51, Windows 2000, and later index layouts, from declarative patches or INF data. | Existing mounts are logical read views; changes produce a patched or rebuilt hive value rather than an operating-system mount. The log helper is not general transaction-log replay or crash recovery. |
| Windows 9x CREG | Reads, compares, and emits logical patches for CREG registries. Builds generation-specific Windows 95, Windows 95 RTM, Nashville, Windows 98, and Windows ME allocator/layout variants. | Rebuilds a complete registry; it does not edit an existing CREG file in place. |
| INF and setup data | Parses INF text/sections/fields, converts AddReg-style rows to typed registry effects, expands setup directory IDs, and builds system hives from INF/TXTSETUP inputs. | Models declared setup data; it does not run SetupAPI or a vendor installer process. |
| Shortcuts and icons | Builds Windows shell links and Internet shortcuts; parses icon groups/images and font name metadata. | Shortcut construction covers the represented fields, not every shell-link extension block. |
| Manifests and type libraries | Parses assembly manifests and MSFT type-library resources, including library/type GUIDs, names, versions, flags, and automation/dispatch type metadata. | Read/analysis only; no general type-library compiler. |
| Certificates and catalogs | Parses certificate/PKCS#7 material, Authenticode-related data, catalog members, and catalog member hashes. | Inspection and hash calculation only; no signing or trust-chain decision. |
| PDB and symbols | Reads MSF 2.0 and 7.0 PDB containers, DBI/public symbol streams, section/OMAP information, GUID/age identity, exact and nearest-RVA lookup, plus HTTP symbol-server retrieval behind the native web frontend. | Focused public-symbol lookup, not a complete CodeView type/debug-information implementation. |
| Minidumps | Reads system architecture, module list, thread list, x86/x64 contexts, stacks, exception records, bounded memory and memory64 ranges, and bounded frame information. Memory ranges remain lazy slices of the caller-owned dump. | Read-only; not every optional minidump stream or unwinding scheme is interpreted. |
| Event logs | Reads classic `LfLe` event logs and EVTX chunks/BinXML template substitutions, including nested direct template tokens; builds an empty classic event-log file. | EVTX output is structured template values rather than full rendered XML; no event-log writer beyond the empty classic log. |
| WMI/MOF/MSC data | Parses MOF declarations and namespaces, MMC snap-in data, WMI repository objects, mappings, and instance/schema records used by the installation model. | Focused repository inspection/construction semantics, not a live WMI service implementation. |

### Execution, debugging, virtual machines, and frontends

| Component | Implemented support | Important limits |
| --- | --- | --- |
| x86 disassembly | i8086/x86-16, i386/x86, and amd64/x86-64 decoding with addresses, bytes, operands, direct-call targets, and instruction-count/byte bounds. | Disassembly only; architecture must be selected explicitly. |
| In-process x86 emulator | Bounded 32-bit x86 execution of raw code and PE32 modules; relocations, imports/exports, mapped memory, hooks, deterministic instruction clock, tracing/profiling, checked runtime transformations, checkpoints, and independent snapshots. | Not an x86-64 or full-system emulator. Memory, instructions, call depth, trace, and plugin execution are explicitly bounded. |
| GDB remote protocol | Packet/checksum/no-ack negotiation, XML target descriptions, arbitrary described registers, memory access, resume/step/interrupt, breakpoints/watchpoints, stop events, temporary register/memory state, and bounded async queues over a byte channel. | Implements the debugger operations exposed by trex rather than every optional GDB remote packet. |
| Windows KD | i386 and amd64 KD framing, acknowledgement/resend, state-change events, processor/register context, virtual and physical memory reads/writes, breakpoints, continue, raw manipulate requests, and file-transfer callbacks. | Requires a KD-capable target/channel; target-specific structure interpretation remains in Starlark policy. |
| Registration analysis | Static resource facts first, then bounded PE32/x86 calls such as `DllRegisterServer` with composable semantic models for COM, registry, services, SetupAPI, type libraries, shell/ADVPack, user profiles and environment blocks, crypto, RPC, event log, performance counters, and related Win32 APIs. Effects are returned as data. | Not a Windows VM and not proof that every DLL path is modeled. Unsupported imports/calls and incomplete registration are reported; no target executable is launched on the host. |
| VM contract | Backend-neutral machine, disk, network, display, channel, lifecycle, input, event, screenshot, debugger-channel, and capability-validation APIs. | Recipes must test capabilities instead of assuming backend behavior. |
| QEMU backend | Starts QEMU with opaque disks exported directly over in-process NBD; supports structured disks/media/CHS, snapshots, display input and screenshots, QMP events, debugger/serial channels, concurrent sessions, and deterministic cleanup. | QEMU is the only production external process. Image parsing, construction, conversion, and debugging protocols remain in trex. |
| Starlark frontend | CLI execution, module loader, scoped resources, REPL, tests, runtime statistics, stage cache, clocks/profiler, URL/HTML/JSON/crypto helpers, resumable verified mirror files backed by a configured local cache, and embeddable program execution. | Host files, HTTP clients, listeners, sockets, and processes are native frontend/backends rather than stable core APIs. |
| Web frontends | Generic Starlark HTTP request/response, file, redirect, and streaming directory-ZIP responses; archive browser with lazy mounting of supported archives, filesystems, hives, and WIM images. The archive browser confines host reads to a pinned root, omits symbolic links and special files, limits mounts and nodes, authenticates remote sessions with an ephemeral access token, and protects mutating requests with a per-process token. | ZIP streaming does not materialize an extracted host tree. The archive browser is an inspection frontend, not a filesystem editor. `-web` binds to loopback unless non-loopback access is explicitly enabled with `-web-public`; remote mode prints an ephemeral session URL but does not provide TLS, so it belongs only on a trusted network or behind a TLS reverse proxy. |
| Inspection scripts | Reusable Starlark scripts and a scoped REPL for archive, installer, disk, debugger, and VM inspection. | Scripts compose the capabilities above and do not add hidden host-tool fallbacks. |

All supported archive, filesystem, binary, and installer processing is
implemented in trex. QEMU is the sole production external-process integration
and is used only as an emulator or debugging target.

## Build and test

trex requires Go 1.25.5 or newer.

```sh
go build ./cmd/trex
go test ./...
go run ./cmd/trex test.star
```

The Go and Starlark suites use synthetic fixtures and do not require
proprietary operating-system media.

## Starlark quickstart

A script exposes `main(args)` and receives lazy file values from `open`:

```starlark
def main(args):
    image = filesystem.iso9660(open(args[0]))
    for name in image.root.files:
        print(name)
```

Run it with:

```sh
go run ./cmd/trex script.star input.iso
```

Embedded modules use `@stdlib` labels:

```starlark
load("@stdlib//windows/installer.star", "analyze")
load("@stdlib//debug:gdb.star", "read_u32")
```

See the [Starlark quickstart](docs/starlark/quickstart.md), the generated
[namespace reference](docs/starlark/namespaces/reference.md), and the
[debugging guide](docs/starlark/debugging.md). Cached immutable downloads are
covered by the [mirror-backed file guide](docs/starlark/mirror-cache.md).

## Go packages

The stable packages are divided by responsibility:

| Packages | Responsibility |
| --- | --- |
| `storage`, `channel`, `block` | Portable byte, file, channel, and block contracts; native I/O is isolated in `storage/native`. |
| `archive/*`, `compression/*` | In-process container decoding and decompression. |
| `filesystem` | Portable in-memory directory trees and sparse image composition. |
| `filesystem/fat`, `filesystem/ntfs`, `filesystem/iso9660`, `filesystem/udf` | Filesystem-specific parsing and image construction. |
| `filesystem/mbr`, `filesystem/gpt`, `filesystem/vhdx` | Partition-table and virtual-disk formats. The host adapter lives separately in `filesystem/native`. |
| `installer/installshield` | InstallShield containers, InstallScript, and installer plans. |
| `binary`, `database/*`, `windows`, `windows/nls`, `firmware/acpi` | Binary, ESE and SQLite database, locale, and platform formats with optional Starlark adapters. |
| `debug`, `emulator/x86`, `vmm` | Debug protocols, CPU emulation, and backend-neutral VM contracts; QEMU lives in `vmm/qemu`. |
| `web/star` | Generic Starlark HTTP responses, redirects, files, and streaming ZIP support. |
| `frontend/starlark`, `frontend/archiveweb` | CLI/REPL assembly, module loading, listeners, and archive browsing. |

Native paths, processes, and sockets stay behind backend packages. Core APIs
accept interfaces owned by the caller.

## Inputs and licensing

trex is licensed under Apache-2.0. Third-party dependency and format-reference
notices are documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
[third-party format references](docs/third-party-format-references.md).

trex does not supply rights to software inspected with it. Users are
responsible for ensuring they may use and process their inputs.
