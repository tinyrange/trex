# Native CKD and z/OS readers

Portable, read-only Go support for uncompressed `CKD_P370` images through
`storage.Reader`. Compose with ISO9660 and gzip readers without mounting,
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
placement, ISAM, encrypted/compressed datasets, format-8 DSCBs and compressed
CCKD containers remain unsupported. zFS backing/copy-on-write objects and other
geometries also remain unsupported. Unknown variants fail explicitly; raw
allocation access remains independent of logical decoding.

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
