# Native parsing coverage: archive-driven additions

These capabilities are available through `auto` and the archive browsers. They
read portable byte sources; no host extractor, mount, conversion tool, installer
execution, or extracted intermediate is involved. Parsing is not proof that an
application installs or runs successfully.

## Executable envelopes

- ZIP self-extractors are recognized behind an `MZ` executable prefix by their
  central directory, using the existing ZIP reader.
- 7z and RAR self-extractors use a bounded 16 MiB signature scan (at most 32
  candidates). Candidates are validated by the archive readers. A validated 7z
  start header or RAR4 main header preserves subsequent parser diagnostics.
- Legacy Mozilla `FILE` PE resources are enumerated without loading the image
  as executable code. Each resource's packed and decoded lengths and zlib
  checksum are checked. Names are retained; conflicting language variants are
  rejected. Nested XPI/ZIP resources remain separately browsable files.
- NSIS 2 ANSI supports independent stored/DEFLATE blocks and end-marker-terminated
  solid LZMA with standard `0x5d` properties and a power-of-two dictionary of
  4 KiB–64 MiB. Solid listing must decode the stream, unlike the metadata-only
  non-solid listing. See `installer/nsis/README.md` for limits and offset meaning.

## Macintosh filesystems

`filesystem/hfs` reads classic HFS, HFS+ embedded in a classic wrapper, standalone
HFS+, and HFSX. It validates volume/fork extents, traverses catalog leaf chains,
resolves ordinary overflow extents, and keeps data and resource forks separate.
HFS+ names are UTF-16 decoded; Unicode is retained while unsafe path characters
are reversibly escaped. Raw names remain metadata, including the legitimate
NUL-prefixed private-data directory.

The reader does not replay journals, decode decmpfs compression, or resolve
HFS+ hard-link inode aliases. An extents-overflow B-tree that itself needs
unavailable overflow extents fails explicitly. These additions establish
readable installation media, not arbitrary modern macOS-volume compatibility.
Layout facts follow Apple's *Technical Note TN1150: HFS Plus Volume Format*;
implementation and synthetic fixtures are original project code.

## ZFS

`filesystem/zfs` adds read-only browsing of single-vdev, unencrypted pools:

- Primary-label uberblock selection with location-bound SHA-256 validation.
- Direct/indirect and embedded block pointers, bounded block/cache sizes, and
  Fletcher-2, Fletcher-4, or SHA-256 data checksums (or checksum-off blocks).
- Stored, empty, LZJB, LZ4, and zlib/gzip-family blocks.
- Dnodes, micro/fat ZAP directories, dataset heads, legacy znodes, and registered
  system-attribute layouts, including spill blocks.

Each dataset exposes its root through `files`; child datasets are sibling
folders. Internal `$` DSL bookkeeping datasets are not presented as user files.
Symlinks are not followed. The reader does not import or modify a pool.

RAID-Z/multi-vdev reconstruction, gang blocks, encrypted blocks, secondary-label
recovery, snapshots, and additional checksum/compression algorithms are outside
this reader's current coverage. The implemented checksum/DVA paths reject
unsupported references rather than delegating them. Pool-label configuration is
used only as a recognition hint; this is not a pool repair or forensic recovery
tool. The known Helios image is a supported single-vdev case.

System-attribute and block-pointer field facts were checked against OpenZFS
declarations (`sa_impl.h` and `zio.h`). No OpenZFS implementation
was copied, translated, linked, or vendored. The Go implementation and synthetic
fixtures are original project code.

## Detection ambiguity

A zero-filled sector range is no longer sufficient to identify TAR. Empty TAR
recognition requires a `.tar` filename in the supplied `auto.SourceContext` as
well as the zero terminator. Explicit TAR parsing remains available without a
filename. Nonempty TAR recognition still validates its header.

## Real-media regression

Media is caller supplied, never downloaded by tests or redistributed:

```sh
TREX_PARSING_ARCHIVE=/path/to/software-archive \
  go test ./auto -run TestArchiveGapMedia -v
```

The suite uses the archive's existing relative paths. Its Helios subtest retains
about 1.5 GiB of decoded image data in memory (2 GiB cap) to avoid repeated replay
of sequential zstd input during random filesystem reads; allow additional Go
allocation overhead. Normal tests skip these media cases unless explicitly opted
in. Synthetic tests need no media.

| Fixture | Verified result |
| --- | --- |
| PC World NZ September 2005: Firefox 1.0.6 | 7z envelope; 12 files, 17,633,003 bytes read |
| Thunderbird 1.0.6 | 7z envelope; 13 files, 23,566,777 bytes read |
| AVG Free 7.0 | RAR envelope; 7 files, 13,488,266 bytes read |
| ATI 5-7 XP/2000 installer | Solid LZMA NSIS; 139 files, 35,229,227 bytes read |
| MotoGP 3 demo | ZIP envelope; 97 regular files, 169,802,924 bytes read |
| Opera 8.0.2 | ZIP envelope; 79 files, 5,187,837 bytes read |
| Mozilla 1.7.11 | 18 decoded FILE resources, 12,330,832 bytes read |
| Mac OS X 10.3 Disk 1 | 7z → APM → embedded HFS+; root listing and complete 3,819,896-byte `mach_kernel` read |
| Oxide Helios generic TTYA image | zstd → GPT → ZFS; boot-environment listing, complete `/etc/release` and `/usr/bin/ls` reads |

Installer totals cover immediate payload files recursively through directories,
not recursive decoding of every archive nested in those files. Filesystem cases
are targeted content checks, not exhaustive verification of every extent.
