# Nested format support and verification scope

These readers use portable `storage.Reader` / `auto.View` APIs. They do not
launch host extractors, mount filesystems, execute installers, or write decoded
intermediates. The Starlark, web, and desktop frontends share their registrations.
Opening a directory is not proof that every lazy payload is valid.

## Supported additions

| View | Implemented scope | Deliberate limits |
| --- | --- | --- |
| `cpio` | ASCII newc `070701`, checksum newc `070702`, and odc `070707`; concatenated archives; hardlinks within trailer-delimited archives | Binary CPIO is not implemented. Later paths win. Symlinks and devices are metadata only. CRC-format additive checksums are checked on first payload read. |
| `ext4` | Native fresh journal-less ext4 construction; lazy ext2/3/4 inode, extent/indirect and directory views with Unix metadata and relevant CRC32C/CRC16 validation | Fresh Linux read/write mount and guest-write readback verified. No journal replay, in-place editing, xattr/ACL semantics or encryption. See [Linux image foundations](linux-images.md). |
| `squashfs` | Little-endian SquashFS 4.0; zlib, XZ, Zstandard; short/extended inodes, fragments, sparse files, IDs | Other versions/codecs fail explicitly. Xattr IDs are retained but xattr values are not decoded. Directory and data reads are lazy; decoded blocks share a 64 MiB cache. |
| `erofs` | Compact/extended inodes, flat/inline data, LZ4 full/compact indexes, big clusters, interlaced plain clusters, Unix metadata and superblock CRC32C | No external devices, chunked files, fragments, compressed tails, HEAD2 or newer extent-record maps. Xattr area size is retained, not decoded attributes. Symlinks are metadata only. Raw and decoded blocks have separate bounded caches. |
| `bom` | Apple BOMStore v1 Paths inventories, including internal separator keys in path counts | A BOM is an inventory, not a payload archive. File sizes/checksums and link metadata are retained; regular files have `missing_contents`, not invented empty readers. |
| `inno` | ANSI **My Inno Setup Extensions Setup Data (3.0.6.1)**, `rDlPtS02` loader; zlib/bzip2 payloads; embedded and numbered external slices; literal/wildcard `{src}` companions | This is not general Inno Setup support. Text uses Windows-1252. Destination constants remain symbolic. Conditions, shortcuts, registry entries, and compiled setup code are not executed or presented as an installation plan. Other generations fail explicitly. |
| `msi` | Package-root CLSID recognition; decoded CFB stream names with visible table/property markers | This browsing view does not require table decoding or change payload bytes. Generic compound documents retain their original Unicode names. |
| `pe_resources` | Existing PE resource parser exposed as a low-priority recursive view | Real installer envelopes take precedence. Raw EXE bytes remain available; resources alone do not imply an installer. |
| `installshield_sfx` | Existing fixed-record envelope plus four NUL-terminated string fields and exact payload lengths | The string-record variant requires a cabinet first record, safe relative paths, and records through EOF. This outer view is not an InstallScript execution plan and does not assert support for every inner CAB generation. |

The CFB reader also accepts omitted **unused padding** in the final sector;
metadata sectors and every declared stream extent still must be present.
Mozilla FILE recognition now distinguishes its framing from unrelated resource
payloads. MBR recognition requires plausible partition entries, not merely a
boot-sector signature.

## Companion boundaries and limits

`auto.SourceContext.Parent` identifies an archive in its containing tree.
Generic `Lookup` never follows it. CAB discovery uses it only for one layer of
independent CAB wrappers in the containing directory, with at most 256 candidate
wrappers and the entry budget. It does not recursively search arbitrary archives.
Ambiguous wrapped matches are errors.

Inno companion lookup stays within the supplied source tree, rejects traversal,
and checks case-insensitive ambiguity. Invalid UTF-8 names from legacy ZIPs are
interpreted as Windows-1252 only in this ANSI installer context. Wildcards apply
to files in a named directory, not wildcard directory traversal; `*.*` includes
extensionless names. Absent external sources stay visible as missing inventory
entries. Embedded files enforce decoded size and Adler32; framed headers enforce
CRCs. Missing numbered slices fail when their payload is read.

Entry, depth, source-extent and allocation limits remain enforced by the relevant
parser. They are not a single aggregate process-memory budget. CPIO indexes the
whole archive and may need the decoded source size; SquashFS lists directories
lazily. No parser follows filesystem symlinks during companion resolution.

## Real-media validation

All media checks used native **trex Starlark frontends** with files retained in
memory or borrowed from their original source. Hash verification means reading
all bytes of the named payload set, not merely recognizing its header.

| Input | Verified result |
| --- | --- |
| ASUS Googlebook 14 recovery, build `16452207_CL3B.260622.271.R1` | Native ZIP/GPT/liblp/boot inspection; directory walks of all seven logical EROFS volumes and legacy ROOT-B; whole-file and random/boundary reads of selected LZ4 binaries and modules. This does not verify every lazy file, AVB trust, or VM boot. |
| Fedora Server 43 1.6 Netinstall, `images/pxeboot/initrd.img` | XZ-to-CPIO indexing; 362,841,600 decoded bytes, 17 root entries. This was an index/listing check, not a hash of every initrd file. |
| Same disc, `images/install.img/usr/bin/bash` | SquashFS/XZ file read: 1,502,072 bytes; SHA-256 `72c31946a6b51c6332022dce2b542931b825d1174d5efc014ef9a1d5385d4c32`. |
| Mac OS X 10.3 Disc 1, BaseSystem `Archive.bom` | 6,630 path records (plus 13 internal separator keys), reachable through 7z, ISO, Apple partition map, and HFS layers. Inventory only. |
| PC World NZ 2000-08, IE 5.05 `IE_S1.CAB/IE_1.CAB` | All 105 files, 17,970,656 bytes, across sibling wrappers. |
| Same disc, `IENT_S1.CAB/IENT_1.CAB` | All 105 files, 17,968,096 bytes. |
| PC World NZ 2005-09, PowerToys MSI | All 60 streams, 726,826 bytes; stream sizes and hashes unchanged by display-name decoding. |
| PC World NZ 2004-12, Norton SPBBC MSI | All 67 streams, 626,690 bytes, despite omitted final-sector padding. |
| PC World NZ 2005-09, MotoGP URT 3 demo, ZIP/`setup.exe` | Inno file inventory and all 101 payloads, 165,960,467 bytes, including external slice and wildcard/ANSI companions; zero unavailable payloads. |
| PC World NZ 2004-12, RCT3 demo | Correct outer string-record InstallShield SFX; all 10 bundled files, 170,992,008 bytes. No longer mistakes an interior prerequisite CAB for the outer installer. |
| PC World NZ 2000-08, SP6a/`iprop.exe` | PE `FILE/IPROP.DL_/#1033` resource reaches SZDD decoding and nested PE resources rather than a false Mozilla FILE error. |

The MDK2 demo on the 2000-08 disc remains an explicit failure: CAB data block
2047 (EXE offset 67,224,805) has stored checksum 4,024,549,942 but computed
checksum 2,134,792,716. Blocks 0 and 2046 match their stored checksums; the next
block header is invalid. This establishes inconsistent source CAB bytes, not a
missing MSZIP codec. No byte-skipping or guessed repair is performed. Comparison
with an independent copy is needed to distinguish damaged media from a producer
quirk. Older NSIS/Wise candidates are not claimed supported by this work.

The sampled media above are not an exhaustive collection-wide compatibility
claim, and successful archive reads are not application-installation smokes.

## Tests and format references

Focused Go fixtures exercise checksums, truncation, hardlinks/concatenation,
metadata-only BOM entries, SquashFS codecs/fragments/sparse data, unsafe paths,
companion ambiguity/boundaries, MSI names, and launcher record boundaries.
The public-engine Go suite, `go vet`, and public Starlark suite were run. Final
Inno inventory adjustments have focused regression coverage as well.

Format field references used during implementation: Linux
`fs/squashfs/squashfs_fs.h`, BOMStore declarations in `hogliux/bomutils`
`src/bom.h`, and `dscharrer/innoextract` setup/loader/stream format readers
(zlib license). These informed on-disk layouts; no external program is required
at runtime. The launcher variant was verified against its exact declared record
boundaries on the source media.
