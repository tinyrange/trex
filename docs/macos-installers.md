# Intel macOS installer layers

The native readers cover the Apple installer media for Lion (10.7), Mountain
Lion (10.8), Yosemite (10.10), El Capitan (10.11) and Sierra (10.12). No host
mount, conversion or extraction program is needed. Each stage borrows portable
`storage.Reader` / Starlark `file` views; decoded host intermediates are not used.

## Layer order

1. `archive.udif(media)` reconstructs the logical disk from UDIF v4 `koly`
   metadata and BLKX maps. `disk`, `xml`, `trailer` and original table records
   remain accessible. `verify()` checks declared stored-data, BLKX and master
   CRC32s. Ignored sectors contribute no bytes to BLKX CRCs; zero-fill does.
2. Parse **all** partitions using `filesystem.apm` (2048-byte map blocks on
   these older images) or `filesystem.gpt`. Keep driver/map/free partitions;
   do not mistake them for filesystems. EFI system partitions are FAT32 and
   are accessible with `filesystem.fat(partition)["/"]`.
3. `filesystem.hfs(partition)` exposes HFS+/HFSX catalog entries, fragmented
   data/resource forks, BSD metadata, links and extended attributes. Paths
   percent-escape control characters, slash and percent reversibly. Hardlink
   aliases retain `raw_data` / `raw_resource` and target inode paths; symbolic
   links are never followed. `raw_forks=True` is an explicit forensic option,
   not decoded-file evidence. decmpfs types 3/4 decode inline/resource zlib
   files with stored-block escapes; unsupported types fail by default.
4. `archive.xar(package)` exposes the complete decoded XML TOC, original heap
   and member records. Keep PackageInfo, Distribution, Bom, Scripts, Payload,
   resources and signature metadata, rather than selecting Payload alone.
   `member.verify()` checks archived/extracted hashes and decoded lengths.
5. In the outer packages, `InstallESD.dmg` is a **sibling member** of Payload,
   not a file inside its CPIO application tree. Follow its DMG/partition/HFS+
   layers, plus BaseSystem.dmg and AppleDiagnostics.dmg where present.
6. Package Payload/Scripts are independently compressed CPIO streams: Lion
   uses gzip or stored odc; Mountain Lion uses bzip2 or stored odc; later
   releases use PBZX/XZ. `archive.gzip`, `archive.bzip2`, `archive.pbzx` return
   decoded file views. Then `archive.cpio(..., maximum_entries=1000000)` keeps
   Unix entry metadata and borrowed data. Read a stream sequentially with
   `digest(decoded)` to validate all bytes/checksums; hashing each gzip member
   in pathname order causes expensive backward replays. Nested packages in
   CPIO contents must also be inspected.
7. `archive.bom` retains every inventory record, including architecture
   variants with the same path and partial trailing leaves omitted from a
   branch index. A BOM contains metadata, **not file contents**. The automatic
   tree keeps variants under `%00bom-variants`, with original `bom_path`.
8. Sierra EmbeddedOSFirmware.pkg includes `.dmg` files that are actually
   ASN.1 IM4P envelopes. `archive.im4p` preserves their payload and optional
   DER metadata. One payload is LZFSE-compressed (`archive.lzfse`), the other
   stored HFS+. Their HFS+ files include decmpfs type 3/4 compression. Firmware
   contents are browsable/readable, but no firmware is executed.

Header signatures take precedence over a trailer belonging to a nested member:
these outer XAR packages can end with the `koly` of their embedded DMG.

## Explicit example

```python
image = archive.udif(open("Lion-10.7.dmg"))
image.verify()
partitions = filesystem.apm(image.disk, block_size=2048)
hfs_part = [p.data for p in partitions.partitions
            if p.partition_type == b"Apple_HFS"][0]
volume = filesystem.hfs(hfs_part)
package = archive.xar(volume.find("/InstallMacOSX.pkg").data)
for member in package.entries:
    member.verify()
esd_member = [e for e in package.entries
              if e.path.endswith("/InstallESD.dmg")][0]
esd = archive.udif(esd_member.data)
# Select explicit partition and package members to continue; do not materialize.
```

For a complete content traversal and standalone JSON validation report:

```sh
go run ./cmd/trex scripts/inspect/macos_layers.star \
  /explicit/media/Sierra-10.12.dmg /explicit/output/Sierra-report.json
```

Run from the public checkout, or adjust script/media/report paths explicitly
when invoking the root workspace CLI. Original images are opened read-only.
Only the final report is written. `auto(file)` also recognizes UDIF, XAR, PBZX,
IM4P and LZFSE for interactive browsing; explicit APIs expose more metadata.

## Verified original media

Complete native traversals of the five original Apple DMGs read all discovered
installer containers, every XAR member, every decoded CPIO stream, and all HFS+
data/resource/extended-attribute forks. Counts include outer installer packages,
nested packages inside payloads, and firmware filesystems (not just InstallESD).

| Release | UDIF disks | HFS volumes | XAR packages | CPIO streams |
| --- | ---: | ---: | ---: | ---: |
| Lion 10.7 | 3 | 3 | 58 | 72 |
| Mountain Lion 10.8 | 3 | 3 | 17 | 21 |
| Yosemite 10.10 | 3 | 3 | 15 | 17 |
| El Capitan 10.11 | 4 | 4 | 8 | 10 |
| Sierra 10.12 | 4 | 6 | 7 | 11 |

El Capitan and Sierra also expose two EFI FAT volumes each. Their payloads
contain nested USB-C adapter firmware packages; El Capitan additionally contains
NEProviderTargetTemplates.pkg. Lion/Mountain Lion contain a nested
RemoteDesktopClient.pkg. Sierra's two IM4P firmware payloads add two HFS volumes;
one contains 34 type-3 and 120 type-4 decmpfs catalog files, including aliases.
Reports retain partition inventories, decoded-stream SHA-256s, XAR TOC hashes,
flat BOM record counts and hashes of complete HFS fork inventories. These are
content-reading proofs, not installation or boot tests.

## Bounds and verification scope

UDIF plist and XAR TOCs are bounded to 16 MiB, with XML node/depth limits.
UDIF, PBZX and LZFSE chunks and decoded caches are bounded to 64 MiB;
PBZX/LZFSE have at most 100,000 chunks/blocks. LZFSE additionally retains
256 KiB of match history and replays dependent blocks on an uncached backward
read. decmpfs zlib chunks are at most 64 KiB, cached one at a time. Filesystem
and archive indexes use explicit entry limits. XAR members are capped at
64 GiB. Total decoded PBZX/LZFSE bytes may be bounded with `maximum_bytes`;
omitting it deliberately permits these multi-gigabyte installer streams.

Checksum validation proves stored/decoded format consistency, **not Apple
signature authentication, successful installation or bootability**. Unknown
codecs and malformed/truncated inputs fail instead of silently yielding empty
files. These readers do not claim encrypted/segmented UDIF, APFS, newer UDIF
codecs or every decmpfs compression variant. IM4P exposes encrypted bytes if
present, but does not decrypt them; the witnessed firmware payloads are plain.

## Format provenance

UDIF facts: libdmg-hfsplus `dmg/dmg.h` and BLKX checksum conventions.
XAR facts: Apple's open-source xar header/XML TOC definitions.
HFS+ facts: Apple Technical Note TN1150 and HFSPlus format declarations.
PBZX: chunk length pairs and independent XZ streams, confirmed on the actual
Yosemite/El Capitan/Sierra installers. BOM layout: bomutils declarations,
with linked-leaf and architecture behavior confirmed on the original media.
IM4P: bounded ASN.1 envelope structure confirmed on Sierra firmware.
LZFSE/LZVN: Go implementation derived from Apple's BSD-licensed LZFSE
reference algorithms; copyright/license and file provenance are retained in
`archive/lzfse/NOTICE`. All other new fixtures are synthetic, not extracted
Apple payloads. Parsing/decompression remains native Go, without CGO.
