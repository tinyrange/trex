# Native CKD and z/OS readers

Portable, read-only Go support for uncompressed `CKD_P370` and compressed
`CKD_C370` base images through `storage.Reader`. Compose with ISO9660 and gzip readers without mounting,
extracting, launching host parsers, or booting a guest. Source-specific media
selection, corpus assertions and audit reports belong in the private recipe
repository; this package contains format readers and synthetic fixtures only.

## Supported scope

- Physical header, tracks, count/key/data fields, record zero, EOF and padding.
- VOL1, format-4 VTOC, format-1 datasets and chained format-3 extents.
- Traditional PDS names/aliases and PS/PDS data-field content through EOF.
- Observed IGW PDSE stored programs and fixed/variable data members.
- Observed IGW HFS directories, regular files, hard links and symbolic links.
- Observed big-endian zFS/Episode aggregates (8192-byte blocks, 1024-byte
  fragments), including direct/indirect blocks and sparse ranges.
- Bounded ESDS, fixed RRDS and KSDS record readers, active multi-level index
  traversal, local BCS/VVDS relationships and KSDS-based alternate indexes.
- Qualified uncompressed extended-format VSAM **data** components, including
  CI-addressed byte bounds and validated physical suffix removal.

This is not universal logical z/OS support. Variable RRDS, ESDS-based alternate
indexes, extended index addressing, multivolume assembly, true sparse HFS file
placement, ISAM, encrypted/compressed datasets and format-8 DSCBs remain unsupported. zFS backing/copy-on-write objects and other
geometries also remain unsupported. Unknown variants fail explicitly; raw
allocation access remains independent of logical decoding.

## Compressed CKD

`OpenCompressed` presents a `CKD_C370` base image as the equivalent
`CKD_P370` image (same device header with the P370 signature, every track
padded to the declared size), so `Open`, `auto()` and every reader above compose
unchanged; `Open` does this automatically. Layout: device header, compressed
header at 512 (version 0, either byte order, cylinder count at 40, null format at
44), level-1 table at 1024, 256-entry level-2 tables of offset/length/size, and
stored tracks beginning with a compression byte and CCHH. Raw and zlib tracks are
supported; the zlib checksum and exact stream end are verified, decoded size is
bounded by the track size and the stored address must match. Missing level-2
tables use the header null format; null level-2 entries carry their own format
in length and size. Formats 0 (record zero plus EOF record) and 1 (record zero
only) are supported. Shadow files (`CKD_S370`), shadow-base references, bzip2
tracks, other null formats and FBA images are rejected. Only the last decoded
track and the level-2 tables are retained. Free-space chains are not needed
for reading and are not validated.

`filesystem.ckd_scan(file, max_errors=N)` parses every track and returns
per-track failures instead of stopping, for distinguishing isolated media damage
from systematic decoding faults.

## CMS EDF minidisks

`OpenCMS(disk, cylinder, extent)` reads a z/VM CMS enhanced-disk-format
minidisk. A minidisk is a cylinder-aligned extent of fixed-size block records
(512, 1024, 2048 or 4096 bytes; record zero excluded). Block n (1-based) is
record `(n-1)%N+1` of minidisk track `(n-1)/N`, where N is taken from the
minidisk's first track (12, 33 and 49 on 3390 for 4K, 1K and 512). Block 3 is
the `CMS1` label: ID at 4, block size 12, directory origin 16, formatted and
maximum cylinders 20/24, blocks 28, used 32, FST size 36 (64) and FSTs per
block 40, packed creation date 44. `extent` (cylinders, from the CP directory)
is authoritative: z/VM volumes carry stale labels from earlier layouts, and a
label is rejected if it claims more cylinders than its extent.

The directory is a fixed-format file of 64-byte FSTs whose first entry
(name `00000001 00000000`, type `DIRECTOR`) describes the directory itself and
must begin at the label's origin; `ALLOCMAP` follows. FST fields: name 0, type 8,
mode 24, record format 30 (`F`/`V` EBCDIC), flags 31, LRECL 32, origin 40, data
blocks 44, records 48, pointer levels 52, pointer size 53 (4 for F, 12 for V),
packed date YYMMDDHHMMSS 54, byte 60 preserved uninterpreted. The 16-bit legacy
fields are zero on observed media and ignored; the directory's own data-block
count is not used for length.

With zero levels the origin is the only data block; otherwise it is the top of
a pointer tree. Fixed-file pointers are 4-byte block numbers; a zero pointer at
level L is (blocksize/4)^L unallocated zero blocks. Content is
`records*LRECL` bytes. Variable-file pointers are 12 bytes: block, number of the
last record that begins in it (or its subtree), and displacement. For data
blocks the displacement is the offset of the first record beginning there,
`0xffffffff` where none does, except that a final block where none does records
the end of data. Upper entries carry 0, or `0xffffffff` when no record begins in
the subtree. Pointer blocks are dense. Data block zero is an all-zero
unallocated block inside a long record. Records are a 2-byte length plus data
and run across block boundaries; each length must be nonzero and at most LRECL.
`Content` returns that stream verbatim, verifying every count and displacement.
Content is not converted from EBCDIC.

Validated against z/VM 4.4 ADCD volumes: driven by the active CP object
directory, 130,178 files (3.6 GB) on 330 minidisks decode with no format
failures; the remaining 35 file failures lie on damaged CCKD tracks.

## CMS libraries and packed files

`ParseCMSLibrary` reads LIBPDS libraries: F 80 content whose first record is
`LIBPDS` (EBCDIC), with the directory length at 8, the directory's first record
at 12 and two words at 16/20 kept uninterpreted (zero in MACLIBs; in TXTLIBs a
byte count equal to sixteen times the following count). The directory fills the
final records with 16-byte entries: name, flags word, 1-based start record.
Entry points and aliases share a member; a member ends before the next record
beginning X'61FFFF61'. MACLIB, TXTLIB, HELPLIB and VMDTDATA libraries use it.
DMSLIB TXTLIBs, LOADLIBs (LIBPDS inside V records) and CSLLIBs (`VMLIB`) are not
decoded yet.

`UnpackCMS` decodes COPYFILE PACK files (F 1024): header X'000140', original
record format and 4-byte LRECL, then the codes in `cms_pack.go`. Each of blanks,
repeated byte and literal has a short form, an 8-bit and a 16-bit count form,
and (for V) an end-of-record form. X'FF' ends the data; the rest of the final
container record is blank or repeats the stream 1024 bytes earlier (the
packer's chunk buffer). Packed streams may also be held in variable-format
container records (`UnpackCMSRecords`). Unobserved codes are rejected.

Validated on z/VM 4.4 ADCD, over every minidisk the active CP directory
defines: 334 LIBPDS/DMSLIB libraries (57,748 members) and 12,234 packed files
decode with every structural check enabled. Packed files on one third-party
product disk (VELOCITY 191) share the header but use a different packer and
are not decoded.

## CMS executables, load libraries and object decks

`ParseCMSModule` reads GENMOD modules (see `cms_module.go`): fixed modules are
bare images; variable modules are one or more segments of an 80-byte header,
core-image records summing exactly to end-origin, and a trailer holding the
loader table, relocation list and optional extra records (service history).
Header halfword 0x28 counts loader entries; byte 0x2D marks a relocation list
(X'80') and 5-byte entries (X'40'). Loader entries are 20 or 24 bytes, chosen by
validation; further segments (CP's CPLOAD nucleus) are found structurally.
`ParseCMSCallableLibrary` reads CSLLIBs: a 56-byte header then one module
segment per routine. `ParseCMSLoadLibrary` reads LOADLIBs: a LIBPDS header
record, OS PDS directory entries (indicator byte: alias X'80', user-data
halfwords; entry padded to 16) in the final records, and members of OS load
module records ended by X'61FFFF61'. `ParseCMSLibrary` also reads the older
DMSLIB TXTLIB format. `ParseObjectDeck` reads object cards (ESD, XSD, TXT, RLD,
END, SYM) following IBM's published object module format, validates ESDID
references and assembles sections. `filesystem.program_object` exposes
`OpenStoredProgramObject` for IEWPLMH trailers.

Validated on z/VM 4.4 ADCD, over every minidisk the active CP directory
defines: 2,342 modules (2,348 segments), 83 LOADLIBs, 18 CSLLIBs and 34,515
object decks (335,076 symbols, 53,726 sections). Loader names may be any
printable EBCDIC (compiler-generated labels use '+', ':', '>', '?' and '='),
and TXT/RLD data may run to column 80 in decks without sequence numbers.
Unsupported on that media: one module (ICKSADSF) with an older header whose
records fall 216 bytes short, two version-1 IEWPLMH objects and four GOFF
object files. `scripts/inspect/zvm_adcd.star` in tinyrangex reproduces these
runs.

## CP object directory

`OpenCPDirectory` reads the compiled z/VM user directory (see `cp_directory.go`)
from CP-formatted 4096-byte pages, whose record numbers run across a
cylinder's tracks; pointers are cylinder, record and a zero byte. VOL1 offset
0x34 selects the active root index page; the root's entries (high key, leaf)
must match the leaf chain. Leaf entries locate each user's 0x220-byte block
(own device count at 0x200) and 80-byte device blocks (type X'80' MDISK, X'40'
LINK, X'08' SPOOL/CONSOLE, X'10' DEDICATE; owner after "DDEV" at 0x44).
Device streams continue on the next page whose blocks belong to the same
owner; each block also links (0x38) to the next device of the user's resolved
configuration, own devices then INCLUDEd profile devices. User-block fields
(storage, classes, machine mode, account, distribution, IPL, AUTOLOG, SHARE,
MAXCONN, POSIX identity, options), the IUCV and NAMESAVE chains, device
modes and password flags, unit-record types and spool classes, and the
header's profile table and POSIX GID index are documented in
`cp_directory_fields.go`; each was checked against USER DIRECT for every user
whose compiled and source entries agree. Passwords are salted by user ID and
are not decoded. On the ADCD media this yields 165 users
and 1,206 devices; the previous generation is rejected because its pages were
reused. It differs from the USER DIRECT source on MAINT 2CC (an edit never
compiled): driving the CMS corpus from the active directory gives 330
minidisks and 130,178 files with failures only on damaged CCKD tracks, while the
source's MAINT 194/3B2 extents on 440W01 are stale, unallocated minidisks.

## Physical and dataset APIs

Use `Open`, `Disk.Track`, `Disk.Walk`, `Disk.ReadVTOC`, `Dataset.Allocation`,
`Dataset.Members` and `Dataset.Content`. `Content(nil, ...)` selects ordinary PS
content. `Walk` validates every physical track and exact cylinder-aligned EOF;
composing with gzip propagates checksum/trailer failures. Its callback borrows
record slices only until the next callback. `Track` returns owned slices.
Physical home addresses are validated, while count-field CCHH addresses are
preserved verbatim rather than assumed to match physical positions.

`Dataset.OpenPages` provides fixed-size allocated pages across extents. Record
zero and CKD framing are excluded; missing page slots fail rather than shifting
subsequent addresses. Zero-filled pages are data, not EOF. `OpenVSAMPages`
additionally removes validated 32-byte suffixes for the qualified uncompressed
extended-format profile. DSCB SMS-managed bit 80 is distinct from extended-format
bit 04; compression and unknown suffix fields are rejected.

Content is not converted to UTF-8. Traditional PS/PDS content retains BDW/RDW
headers. Names outside the invariant EBCDIC alphabet use reversible escapes.
PDSE data members return exact payloads plus `RecordLengths`; no newline
separators are invented. Load modules are not relinked into executables.

## IGW, PDSE and HFS

`ParseAttributePage` validates AD page bounds, anchored 20-byte keys, prefix
compression and trailing-zero suppression. Cell flags are retained, not treated
as liveness. Leaf keys remain strictly ordered; internal namespace separators
can be shortened. `OpenIGW` resolves chained VDF maps (498 slots per nonterminal
page, next address at offset 16) and traverses active level-checked child links,
not stale signatures. Object allocation joins continued type-7003 cells using
logical-page selectors, rejecting unexplained gaps and overlaps.

`ProgramMembers` follows active multi-level name trees. Qualified E5 directory
holes preserve child page identifiers. `OpenStoredProgramObject` preserves the
actual IEWPLMH file (versions 2–5); storage attribute 4004 independently validates
page count. PLMH declared size is not assumed to be stored EOF.
`OpenProgramObject` is a separate optional gap-expanded view, not a stored-file
reader. `DataMembers` handles C3 fixed/variable six-byte frames across page
boundaries, validating byte/record/page counts and maximum record size.

`OpenHFS` resolves referenced typed inodes (including qualified D5/EC flags),
checks directory cycles, retains hard-link identity, stops files at inode EOF
and preserves symlink targets without following them. File bytes stay unchanged.
`OpenEpisode` follows live directory hash chains and bounded indirect trees;
nonzero generations are checked, while restored names may use generation zero.
Device/FIFO/socket entries expose metadata, never ordinary file payloads.

## VSAM

`ParseControlInterval` preserves record boundaries and software EOF.
`ParseVSAMInterval` also decodes fixed RRDS slots and spanned segments.
`ReadVSAMRecords` assembles segments within a control area, checks update
versions, preserves RRNs across vacancies, enforces budgets and checks KSDS key
order. Spanning has synthetic coverage, not a real-media validation claim.

`ParseVSAMIndex` handles 24-byte headers, reverse FLP entries, section-relative
key compression and active children. `ParseVVR` and `ParseCatalogRecord` expose
qualified metadata and component relationships. VVR primary flag 08 identifies
index components, component offset 30 supplies their root, and related indexes
are selected by cluster identity rather than filename suffix. Qualified VVR
CI-addressed data bounds use 64-bit arithmetic; common-cell lengths 85 and 153
are supported. Maximum record length helps distinguish ESDS from linear data.
VVR record-count statistics are not used as EOF.

`Dataset.VSAMRecords` checks local VVR geometry against VTOC allocation and reads
active index order. `AlternateRecords` follows catalog true-name references to
local KSDS bases, dereferencing nonunique alternate keys with exact size, order,
missing-reference and duplicate-reference checks. It is separate from raw AIX
records. Entry and expanded-byte limits apply to both views.

## Automatic browsing and Starlark

`auto()` identifies nested CKD images and exposes:

```text
header.bin
tracks/<cylinder>/<head>/track.bin
tracks/<cylinder>/<head>/<index>-r<number>.key|data
datasets/$volume.json
datasets/<NAME>/metadata.json
datasets/<NAME>/dscb.bin
datasets/<NAME>/allocation.ckd
datasets/<NAME>/content/data.bin
datasets/<NAME>/members/<MEMBER>/data.bin|directory.json
datasets/<NAME>/pages4096/data.bin|layout.json
datasets/<NAME>/records/
datasets/<NAME>/alternate_records/
datasets/<NAME>/files/
datasets/<NAME>/filesets/<NAME>/
```

Views are lazy and organization-dependent. Raw allocation is not a standalone
CKD image. `pages4096` is physical access, not a logical-content claim. VTOC
scanning has a separate one-million-DSCB budget because reserved empty slots are
not dataset entries. Gzip random reads outside its bounded cache replay input;
callers may compose a bounded in-memory block cache. `auto.summary` retrieves
entry metadata without probing arbitrary file contents.

Starlark exposes `filesystem.ckd_scan`, `ckd_attribute_page`,
`ckd_igw_attributes`, `ckd_control_interval`, `ckd_vvr`, `ckd_catalog_record`
and `ckd_vsam_records`. See the generated namespace reference for signatures.
Inspection, media selection and traversal orchestration belong in Starlark.

## Provenance

No GPL implementation source or external implementation was used, copied,
translated, or used as a validation oracle. Layouts were independently decoded
from media and checked against IBM format documentation. Tests contain original
synthetic fixtures, not proprietary payloads. Published IBM references include
DFSMSdfp Advanced Services (format-1/3 DSCBs) and DFSMS Using Data Sets (PDS
directory, CI control fields, spanning, RRDS, VSAM index header/entries/sections).
IBM file-type constant definitions were consulted without copying macro source
or proprietary payloads. The implementation uses portable `storage.Reader` and
`auto.View` interfaces and remains in trex's Apache-2.0 codebase.
