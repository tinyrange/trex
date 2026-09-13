# PRI2 envelope

The current parser reads the file envelope, not resource maps or qualifiers.
Evidence: Windows 11 26100 MrmCoreR, matching PDB GUID
61B29674-3E81-67A3-127B-98CCB074D3F3, DBI/image age 1,
BaseFile::ValidateStructure at RVA 2f320..2f558. Fields are little endian.

The 32-byte header contains magic (eight bytes), an uninterpreted u32 at 8,
u32 total size at 12, u32 TOC offset at 16, u32 section-data base at 20,
signed u16 count at 24, and uninterpreted fields at 26 and 28.
The parser supports only the observed `mrm_pri2` magic and nonnegative counts.
TOC and data base are eight-byte aligned. The TOC has 32-byte entries:
16-byte type, eight uninterpreted bytes, u32 data-base-relative offset and
u32 complete section length. Nonempty sections occupy at least 40 bytes.
The native validator permits an absent entry with both offset and length zero.

The trailer is 16 bytes at align8(total size)-16: u32 DEFFFADE, repeated
u32 size, repeated eight-byte magic. All section extents precede this trailer.
The Go reader uses widened arithmetic, checks extents before slicing, and
retains complete section bytes without interpreting their headers or payloads.

The retained WinUI CBS resources.pri is 2124600 bytes, has 69 TOC entries at
offset32 and section-data base2240. Its first section is [mrm_decn_info],
followed by [mrm_pridescex], [mrm_hschemaex], and [mrm_res_map2_]. Its native
trailer was checked directly. The Go test uses a synthetic envelope, not an
extracted PRI fixture. The Starlark parser was subsequently run against the
native reconstructed servicing target, with SHA256 checked against the retained
guest file: `2a93db6aded19eb8026b2de11f583271505b26e9a47536d364d4e9ed93a57421`.
It accepted all 69 section extents. This proves envelope parsing of that input,
not resource lookup or Windows startup.

`windows.pri_sections(file, max_bytes=268435456)` exposes the parser to Starlark.
It returns ordered dictionaries with `index`, `type` (trailing NULs removed),
raw eight-byte `metadata`, and complete opaque section `data` as file values.
The explicit input bound is checked before reading; callers can change it.
No host path or extraction step is involved. This function is envelope
inspection, not a resource-name resolver.

## Section integrity

`FileSectionBase::Init` (`31530..31758`) compares the 16-byte section type with
the TOC, the u32 size at section offset24 with TOC offset28, and metadata as
follows: section u32 offset16 equals TOC offset20; section u16 offsets20/22
equal TOC offsets16/18. `GetSectionTrailer` (`31758`) locates the trailer at
align8(section size)-8. It contains u32 DEF5FADE and the repeated section size.
Observed sections have a 32-byte header, followed by payload and the trailer.
`Section.Payload` checks the aligned form and returns its interior without
claiming that format-specific padding is meaningful data. Unaligned section
sizes remain unsupported by that helper. Container-only parsing remains opaque.

## Schema/name layout under investigation

`HierarchicalSchema::Init` (`30adc..30f4c`) accepts the old eight-byte schema
header and the extended 24-byte header. The actual file uses `[mrm_hschemaex] `.
The extended header starts with four u16 values and a 16-byte embedded name
format identifier, here `[def_hnamesx]  `. It is followed by 20 bytes per version
(first u16), then UTF-16 identifiers with code-unit counts in the second and
third u16 fields, then four-byte alignment and the hierarchical-name data.
The native initializer requires at least one version and identifier lengths
of at least two code units. In this file those counts are 1, 33 and 22.

`HierarchicalNames::Init` (`30518..30adc`) distinguishes 24-byte old and 28-byte
extended name headers. For the ordinary (non-large) form, sequential extents are
12 bytes times header u32 offset4, 8 bytes times offset8, 2 bytes times offset12,
2 bytes times offset16, and offset24 raw bytes (extended only). Header flags
bit0 selects a large form: nodes20, scopes16, item indexes4 bytes (30a1f,
30a44, c5534..c5569). Semantic name
node fields, string-offset flags, scope/item indexes, and lookup rules must be
established before exposing a resource resolver; these extents alone do not
prove a valid schema.

### Name nodes and segments

`TryGetName` (`4fb90..50140`) normalizes small 12-byte nodes to the same
representation as large 20-byte nodes. Small fields: u16 parent at0, u16 full
path code-unit length at2, u16 initial character at4, u8 segment length at6,
packed flags/offset at7, u16 low string offset at8, u16 scope/item index at10.
The upper string-offset bits are `((byte7 >> 2) & 0x30) | (byte7 & 0x0f)`.
The large form has u32 parent at0, u16 length at4, u16 initial at6, u8 segment
length at8, flags at9, offset-middle byte at10, offset-low u16 at12, u32 index
at16. Its offset is `(flags & 15)<<24 | byte10<<16 | u16(offset12)`.
For both forms flag0x10 identifies a scope and flag0x20 selects the byte pool.

`CopyNameSegment` (`50140`) sign-extends each byte to a UTF-16 word; it does not
decode UTF-8. `GetUtf16Name` (`8a440`) addresses the UTF-16 pool by code units.
Both check that offset+length is inside the respective pool and points to a NUL.
The Go segment reader additionally rejects embedded NULs and malformed UTF-16.
It does not perform URI normalization, case folding, or parent traversal.

The real WinUI schema node at section offset228 is
`000005004600053001000100`: root parent0, full/segment length5, initial F,
scope index1, byte-pool offset1. The byte pool at section offset3176 starts with
NUL followed by `Files` and NUL. A focused Go golden test uses this twelve-byte
record to verify the node/segment decoder. This is not yet proof that
Files/logo.png is present or absent.

### Hierarchical-name table traversal

`ParseNames` now reads both header generations and both record-width variants.
It checks count/extent arithmetic before allocation and retains string pools
as bounded slices. Scope entries start with their node index; item entries are
node indexes (confirmed by `TryGetItemInfo`, `8a710..8a784`, and `TryGetName`,
`4fc29..4fc38`, `500b8..500c3`). The parser checks each index's ownership against
its node's scope flag and declared index.

`ItemName` walks node parents to root zero, following the path assembly in
`4fec7..4ffd9`. It validates decreasing full-name lengths and scope parents,
limits traversal to the number of nodes, and reads each terminated segment
from the appropriate pool. Results retain original spelling and use `/` between
segments. There is no URI normalization or case-insensitive lookup yet.
Synthetic tests cover small/large records, old/extended headers, out-of-range
indexes, ownership errors, truncation, cycles, and `Files/logo.png` assembly.
Actual-file whole-schema traversal remains to be verified after exposing the
schema payload decoder; container validation and the twelve-byte Files fixture
do not substitute for that integration check.

`ParseSchema` now validates the section, handles old and extended schema
headers, preserves the 20-byte version records, decodes both terminated UTF-16
identifiers, and selects the hierarchical-name format by its exact embedded
type identifier (or the old header's implicit type). Identifier extents and
four-byte alignment are checked before calling `ParseNames`. Unknown types,
truncation, invalid counts and malformed UTF-16 fail explicitly.

`windows.pri_schema(file, section_index, max_bytes=268435456)` exposes a schema
as `identifiers`, `item_count`, and an `item_name(index)` callable. It does not
eagerly allocate every full name, and keeps resource lookup independent of host
paths. Focused schema and frontend tests pass. Actual-file traversal is a
separate pending check; this API does not resolve resource candidates or perform
the manifest URI transformation.

The actual-file schema traversal subsequently passed on the hash-checked WinUI
PRI above: identifiers `ms-appx://Microsoft.UI.Xaml.CBS/` and
`Microsoft.UI.Xaml.CBS`, 200 resource items, all full names decoded successfully.
No decoded name contains `logo` (case-insensitive). The Files subtree does exist:
item0 is `Files/Microsoft.UI.Xaml/Assets/NoiseAsset_256X256_PNG.png`, followed by
compiled XAML resources. Thus `Files/logo.png` is absent from this schema; the
presence of the separate package file logo.png must not be confused with a PRI
resource entry. This narrows the WinUI manifest-file path to the native
not-found/path-literal branch, subject to the resource-map lookup contract.
# Resource maps and decision cardinalities

`ParseResourceMap` reads environment-free `[mrm_res_map2_]` sections, including
mixed standard/large directories, ranges and items, and both locator widths.
The layout and lookup rules are corroborated by Microsoft's
[MrmFiles.h](https://github.com/microsoft/WindowsAppSDK/blob/6b178e79e59d28efb10ef5c8c68b051d2615c3e6/dev/MRTCore/mrt/mrm/include/mrm/common/file/MrmFiles.h)
and [ResourceMap.cpp](https://github.com/microsoft/WindowsAppSDK/blob/6b178e79e59d28efb10ef5c8c68b051d2615c3e6/dev/MRTCore/mrt/mrm/mrmmin/ResourceMap.cpp).
The 32-byte header precedes external-schema bytes, eight-byte value-type atoms,
standard tables, optional large tables, locators, and internal value data.
Directory range/item offsets address the combined standard and large arrays.
Locators remain opaque: validating their extent is not decoding their values.

`ParseDecisions` checks decision/qualifier reference-table extents and indexes.
A resource's candidate count is its decision's qualifier-set-reference count,
not a difference between neighboring candidate offsets. `CandidateCount` also
checks that the candidate span fits the map's value array. It does not evaluate
qualifiers, resolve strings, or certify that a sole candidate is neutral/default.
`windows.pri_resource_candidates(file, section_index, resource_indices)` exposes
bounded count inspection and validates the referenced schema and decision
sections. Tests cover mixed tables, locator widths, absent resources, malformed
extents, invalid decision references and candidate overflow.

In the actual hash-verified Client.Core 1000.26100.133.0 PRI (8,536,200 bytes),
schema section 2 contains 8,281 items. Map section 3 has 5,931 standard and
2,350 large items, with 162,800 values; decision info is section 0. Native
Starlark inspection using the source layout found:

| Resource | Schema index | Decision | First value | Candidates |
| --- | --- | --- | --- | --- |
| Resources/ProductPkgDisplayName | 7334 | 9 | 142864 | 86 |
| Files/Assets/StoreLogo.png | 8244 | 20 | 161110 | 3 |
| Files/Assets/Square44x44Logo.png | 8245 | 15 | 161113 | 2 |
| Files/Assets/Square150x150Logo.png | 8246 | 15 | 161115 | 2 |

All four fail the DMR reference builder's exactly-one-candidate prerequisite
for reduction to a literal. This establishes the index-reference branch for
these names, not arbitrary PRI resources or a successful image smoke. The new
Go frontend still needs integration-time comparison against this actual input.
