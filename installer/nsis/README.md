# Native NSIS payloads and installation plans

This package implements the NSIS 2 ANSI, non-solid stored/DEFLATE layout:

- `List(storage.Reader, Options)` / `archive.nsis_list` read metadata and member
  length prefixes only. File bodies are never read by the listing API.
- `Open` / `archive.nsis` decode readable members entirely within trex. Stable
  `/files/NNNNNN` names use instruction indices, not guessed destinations.
- `archive.installer`, `archive.installer_probe` and `auto` recognize the same
  payload. Recognized malformed or over-budget NSIS inputs retain diagnostics.
- `installer.plan` evaluates selected-section straight-line effects, stopping
  at the first unknown action, branch or call. Product recipes can supply
  audited half-open `ranges=[(start,end),...]`; `explicit_ranges` records that
  limited scope. This is not a general NSIS VM. Always reject `unresolved`.

## Provenance

All parser, codec, planner and synthetic-test implementation is original project
Go code under this repository's Apache-2.0 license. No NSIS, 7-Zip, GPL or LGPL
implementation has been copied, translated or vendored. No dependencies were
added. The original canonical-Huffman decoder handles NSIS's LEN-only stored
DEFLATE blocks (unlike standard DEFLATE, no NLEN follows LEN). Tests also use
Go's independent encoder for differential checks of dynamic trees and overlapping
back-references. Installer media is caller-supplied and never redistributed.

Format terminology includes firstheader, metadata block tables, six-operand
instructions, encoded strings, and independently framed data blocks. Synthetic
containers and native inspection of real media provide validation evidence;
no external extractor, guest installer execution, or host staging is used.

## Contracts and limits

- The first header is on a 512-byte boundary; bare containers are accepted by
  the direct API. Signature scan defaults to 16 MiB (256 MiB in generic dispatch).
- Metadata bounds cover packed/expanded sizes (64 MiB each), tables, section
  ranges, string offsets, rendered text, and instructions (one million).
- `maximum_bytes` defaults to 512 MiB and bounds cumulative **unique decoded
  payload** bytes; shared data is decoded once. In generic installer APIs this
  argument currently applies to NSIS. `auto` propagates its expansion budget.
- Listings preserve instruction order, raw ANSI names, duplicates, data offsets,
  packed lengths, compression flags and FILETIME. No ANSI code page is inferred.
- `output_directory_hint` is only the nearest preceding SetOutPath in bytecode
  order, **not** a resolved destination. Variables/language/shell references
  remain symbolic. Unknown variable indices are `${VAR:n}`; literal dollars
  are doubled. Payload names cannot escape into host paths.
- Plans support file writes, directories, attributes, StrCpy, copying/deleting
  already-planned files, string/expand-string/DWORD registry writes, Return,
  progress text, and WriteUninstaller. They do not inspect an existing guest or
  host filesystem/registry. Unresolved plans are partial, not safe to apply.
- Native WriteUninstaller uses the original executable stub, bounded embedded
  icon patches and uninstall container, and computes the CRC excluding the
  initial 512 bytes and final checksum word. It does not execute the result.
- Solid streams, other codecs, Unicode strings and customized opcode tables
  are not supported. The format label does not authenticate a producer version.
  Input signatures/CRCs are not generally verified; product policy should pin
  its installer digest. Generic parsing does not imply successful installation.

```python
source = filesystem.iso9660(open(iso_path))[installer_path]
listing = archive.nsis_list(source)  # cheap, metadata only
installer = archive.installer(source)
print(installer.format, installer.payload.sections)
plan = installer.plan(locations={"<TARGETDIR>": r"C:\Apps\Example"})
if plan["unresolved"]:
    fail(plan["unresolved"])
```

## Validation

Tests cover metadata-only reads, stored/fixed/dynamic compression, overlapping
copies, truncations, malformed tables and trees, bounds, shared payloads,
fail-closed plans, Return, invalid guest paths, and uninstaller patch bounds.
Fuzz targets exercise listing, strings, and the bounded codec.

An opt-in regression opens the ISO using trex, pins the installer SHA-256, checks
all 561 files (36,483,079 decoded bytes), plans the 540-file installation range,
reconstructs the 68,000-byte uninstaller, and checks generic dispatch/budgets:

```sh
TREX_NSIS_TEST_ISO='/path/to/PC World New Zealand 2005-09.iso' \
  go test ./installer/nsis -run 'TestNetscapeMedia|TestUninstallerMedia' -v
```

Member: `/browsers/Netscape 8.0.2/nsb-install-8-0.exe`.
SHA-256: `4defa5ecfc51442b26ddfb99c025b8e1c9b721a3059554f6e97b70eca3249bcd`.
The first header is at 37,888, expanded metadata is 110,680 bytes, and the
payload block begins at 68,594. Listing reads 35,022 bytes after the independent
digest check. No media path is assumed by default.
