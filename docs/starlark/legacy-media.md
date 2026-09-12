# Inspecting legacy media

Keep each layer as a file view. The REPL's `browser = auto(source)` follows
recognized containers using the same API as `web.browse`; see
[automatic file views](auto.md) for fork paths, partition views and limits.
Use explicit readers when a layer requires additional context:

```starlark
bundle = archive.sevenzip(open("original-media.7z"))
disc = bundle.entries[0]
label = filesystem.sgi(disc)
partition = [p.data for p in label.partitions if p.partition_type == 5][0]
volume = filesystem.efs(partition)
image = archive.irix_image(volume.find("/dist/4Dwm.sw").data,
                           volume.find("/dist/4Dwm.idb").data, "4Dwm.sw")
```

`scripts/inspect/media_repl.star` provides small helpers for signatures, member
lists and complete-file hashing. A successful outer-container read does not
establish that its members have no additional layers. Inspect names and headers
of every member, open further containers, and read their files fully too.
These helpers do not install software, mount filesystems or call host decoders.

## VMS layer boundaries

Open Files-11 volumes with `filesystem.ods2(disc)`. File names retain their
version suffixes: `volume.find("/VMS2055.A;1").data` is a saveset file view,
not its recovered contents. `archive.vmsbackup_blocks(file)` validates BACKUP
block CRCs, sequence numbers, record framing and encountered XOR redundancy
payloads, returning blocks and their record data views. `archive.vmsbackup(file)`
joins file records into entries with raw names, attributes and logical data
views. Metadata-only nonempty entries explicitly have `missing_contents=True`
and `data=None`; they are not zero-filled. Pass a file and its32-byte RMS
attributes to `archive.rms_variable` for sequential VAR/VFC record views,
with separate control/data fields. This does not interpret other RMS formats,
indexed structures or nested binary payloads. A successful
ODS-2 traversal or BACKUP block check therefore does not prove that nested
files have been decoded. See the [BACKUP format notes](../../archive/vmsbackup/README.md).

## IRIX format boundaries

SGI disk volume headers and standalone tape directories are different formats.
`filesystem.sgi` reads the former; `archive.irix_tape` reads the latter. Both
check their 512-byte header sums and expose bounded member views. A standalone
`mr` member is an EFS filesystem, not an executable or an inst image.

The disk header's type-6 whole-volume descriptor can extend beyond the supplied
CD image even when every filesystem partition fits. Its `blocks` value remains
the declared count, while `data` contains only available bytes and `complete`
is false. Actual filesystem partitions and boot members still require their
entire declared ranges; this is not a general truncated-partition fallback.

EFS uses 512-byte sector addresses, even on CD media. The reader supports direct
and indirect extents and does not follow symbolic links. Some standalone
miniroots omit a free trailing region. The reader accepts this only when the
stored allocation bitmap proves the omitted range is free and all referenced
extents fit the original input. It never supplies zeros for missing allocated
data. The geometry and inode layouts are documented in SGI's
[IRIX manual, 007-2159-004](https://irix7.com/techpubs/007-2159-004.pdf),
pages 42–44 and 108–109.

Inst payloads consist of a big-endian 16-bit pathname length, pathname bytes and
the stored file bytes described by the IDB. Later images start with a 13-byte
`im001V...P...` header; early tape images start with the first pathname record.
The decoder checks explicit `off()` attributes when available. Without offsets,
repeated names follow IDB occurrence order. It retains duplicate files and their
machine attributes rather than making installation choices.

An overlay filename such as `4Dwm_6522m.sw` still uses the logical image name
`4Dwm.sw`. Inspect `archive.irix_idb(index).items` for subsystem attributes,
then pass that logical name explicitly to `archive.irix_image`. The REPL helper
`irix_image_names` lists candidates from the parsed index; it does not rewrite
metadata or guess from release suffixes.

`cmpsize(0)` means uncompressed storage, not an empty file. Positive `cmpsize()`
selects UNIX compress; reads check the decoded `size()` and BSD rotating `sum()`.
Indexes and images can have block-rounded zero padding, which is checked in
full. Manual pages frequently retain another UNIX pack layer after inst decoding.

`archive.compress` handles UNIX LZW width changes and clear-code alignment.
`archive.pack` handles the older prefix-code format, including its implicit end
symbol and bottom-up canonical code assignment. These are distinct formats;
neither a `.Z` nor a `.z` extension alone is enough to choose a decoder.

## BRU record framing

Classic BRU has 2048-byte records, with 256 bytes of header per data record.
`archive.bru` validates signed-byte checksums, record numbers, archive identity,
names and the end marker before publishing member views. A file spanning records
is a composite view of payload ranges, excluding each record's header.

Trailing output-buffer blocks may be checksummed padding rather than literal
zero bytes, and can contain unused nonzero payload bytes. Their blank record
headers and checksums are validated too. Compressed or extended BRU members and
incomplete multivolume inputs are explicit errors, not raw-file fallbacks.

## XFS miniroots and Macintosh resources

Newer IRIX standalone `mr` files can contain XFS rather than EFS. Use
`filesystem.xfs` on that member; it returns directory metadata and borrowed
payload views, never follows symlinks, and does not replay the log. Legacy
version-4 local and extent forks are supported. Extent btrees, version-5
metadata and realtime-device data are explicit gaps. The layout follows the
[XFS format documentation](https://www.kernel.org/pub/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf).

Older miniroots can use version-1 directories on a version-4 XFS volume.
These are separate format generations: the filesystem version alone does not
select the directory layout. Version-1 shortform directories retain 64-bit
inode numbers; larger directories embed names in hash-ordered tree leaves.
Both forms are supported, including internal-node traversal. Their organization
is described by the project's [xfs_db manual](https://www.man7.org/linux/man-pages/man8/xfs_db.8.html).

Some IRIX web assets retain Macintosh resource forks in `.HSResource`
directories. `archive.mac_resource` separates their resource payloads using
the map, not guessed signatures. Four-byte types, signed IDs, optional raw
names and attributes remain available independently of the synthetic member
path. An unnamed resource is distinct from an explicitly empty name.
Compressed resources using Apple `dcmp` IDs0/1/2/3 are decoded in memory.
Each entry retains `stored_data`, `stored_size` and `compressed` separately
from decoded `data` and `size`. `maximum_decoded_bytes` bounds the total
decoded compressed payload size and each stored compressed input. Uncompressed
payloads remain borrowed views.

The decoders validate output lengths, dictionary indexes, backreferences and
input boundaries. Word-oriented dcmp0 permits the documented single padding
byte for an odd decoded length. Unknown codecs fail explicitly; arbitrary
custom `dcmp` code is never executed. Extended literal lengths are variable
integers, including lengths above127 (observed in the PowerPC Enabler).
The currently unobserved dcmp0 extension5, dcmp1 extensions other than2 and dictionary tagsD3/D4
remain unsupported. InstaCompOne's distance decoding supports histories up to
344064 bytes; larger histories requiring a reference are explicit errors.

Format research: [Kaitai resource compression descriptions](https://formats.kaitai.io/compressed_resource/),
[ResDecompress](https://github.com/maximumspatium/ResDecompress) and
[resource_dasm](https://github.com/fuzziqersoftware/resource_dasm).
MIT reference notices accompany the native decoder; no GPL decoder is used.

The reader uses the layout documented in Apple's
[Resource File Format](https://developer.apple.com/library/archive/documentation/mac/pdf/MoreMacintoshToolbox.pdf#page=151).
Resource payloads may themselves contain formats requiring another decoder;
successfully reading the resource map is not proof of complete recursive decoding.

## CompactPro forks

`archive.compactpro` reads the archive in a CompactPro self-extractor's data
fork. It retains separate `data`/`resource` and `stored_data`/`stored_resource`
views, with catalog metadata and reversible percent-escaped paths. Catalog
and combined decoded-fork CRCs are checked before returning entries.
Encrypted and multi-volume inputs are explicit gaps.

CompactPro LZH decodes into an RLE stream, not directly into the final fork.
Its zero-initialized 8KiB circular window permits references before the first
output byte; offset zero addresses the current ring slot. The window survives
block transitions. These cases and the block-counter/padding rules have
focused native tests and original-media CRC validation.

The recursive archive probe follows CompactPro `.sea`/`.cpt` files and inspects
both forks, including resource maps and their payloads. This matters for the
Text-to-Speech installer: its nested Voices self-extractor contains18 files
whose contents are entirely in their resource forks.

Format descriptions: [CompactPro catalog](https://code.google.com/archive/p/theunarchiver/wikis/CompactProSpecs.wiki),
[LZH](https://code.google.com/archive/p/theunarchiver/wikis/CompactProLzhAlgorithm.wiki),
and [RLE](https://code.google.com/archive/p/theunarchiver/wikis/Rle8182Algorithm.wiki).
The implementation uses format facts and original-media experiments, not
copied GPL/LGPL decoder code.

## Classic StuffIt forks

`archive.stuffit` reads the classic22-byte archive/112-byte member-header
generation. It preserves both forks, original compressed views and Macintosh
metadata, checking every member header and decoded fork with CRC-16/ARC.
The [public format description](https://code.google.com/archive/p/theunarchiver/wikis/StuffItFormat.wiki)
mislabels this CRC as CCITT; all original headers and decoded fork checksums
match ARC with initial value0. Directory end markers may repeat the root name;
their nesting, not matching names, determines directory ownership.

Stored forks, method14 (described below), and
[method13](https://code.google.com/archive/p/theunarchiver/wikis/StuffItAlgorithm13.wiki)
are supported. Method13 switches literal/length codebooks after matches, uses
a64KiB LZSS window, and supports embedded tables or the five predefined sets.
End markers and exact decoded sizes are required. Final padding must be zero,
either to the next byte or to the original encoder's32-bit buffer boundary
after the selector byte. StuffIt5 method15 support is described below.
Other codecs, encryption and StuffItX remain explicit gaps. No GPL/LGPL
implementation is imported or translated.

The Mac7.1 Drag-and-Drop archive contains Finder7.1.3, whose resource fork
requires dcmp0 extension1: 68k BSR/JMP(A5) veneers with changing target and
A5 offsets. This is decoded as resource data, without executing Finder code.

## Classic HFS forks

`filesystem.hfs` reads a raw classic HFS volume (the `BD` header at byte1024).
For each regular file, `.data` and `.resource` are separate readable views.
Checking only `.data` misses resource-only applications such as the System7
Finder. Catalog and overflow extents are resolved natively, without copying
fork contents to host files.

Names remain available as bytes. For unambiguous lookup, `.path` percent-escapes
non-ASCII/control bytes, slash and percent; `.find` uses that exact spelling.
This avoids assuming that every classic volume uses MacRoman. Timestamps retain
the Mac epoch, and Finder information is preserved without interpreting aliases.

HFS Plus, embedded HFS Plus volumes and overflow-file bootstrap beyond its
initial extents are explicit gaps. Resource compression is another layer,
independent of successfully reading the HFS fork bytes.

### Apple installer Tome

The Mac 7.1 System Update 3.0 archive has signature `6b630001`, a 36-byte
header, and a big-endian 16-bit entry count at offset 26. Its 15 catalog records are
128 bytes each. Record offsets are: ID 4 (u16), name length 6 (u8), name 7
(31-byte field), Finder type/creator 38/42, creation/modification times 46/50,
version 54 (u16), Finder flags 56, and data/resource fork descriptors at 60/76.
Each descriptor contains four u32 fields: decoded size, absolute stored offset,
stored size, and the decoded-fork checksum. Name padding and the final
36 record bytes contain nonzero residual data; they are not reserved-zero fields.
These catalog facts agree with the MIT-licensed
[TomeViewerX metadata reader](https://github.com/kainjow/TomeViewerX).
One correction is essential: that reader uses offset28 as the count, but this
field tracks IDs and can exceed the live record count. The Mac7.6 Extras archive
contains three records with IDs4,5,6; MacLinkPlus Archive1 contains46 records
with a highest ID of51. Offset26 gives the correct count and all decoded fork
checksums match. Sparse-ID regression fixtures preserve this distinction.

`archive.tome` decodes the observed `00010000` binary and `00000000` seven-bit
text InstaCompOne chunk modes natively.
It also supports stored chunks selected by a leading header byte of `01`.
The remaining three header bytes are not reserved-zero fields: original CDs
contain values such as `010802a6`. Stored chunks carry bytes through the next
absolute 64KiB decoded boundary and contribute history to following compressed
chunks. The Mac7.6 Extras fork reconstructs 564007 bytes from 564043 stored
bytes with an exact checksum match; regressions cover stored/compressed mixing
and truncated stored input.
On the Mac7.6.1 CD all57 Tome catalogs decode819 file records with matching
fork checksums. A Tome fork can be only a fragment of the eventual installed
fork: Catalina, Agnes and Victoria span two Tomes each. Their header-bearing
parts concatenate with earlier-numbered-Tome tails to form847999,869978 and
934684-byte resource forks, each with11 valid resources. `binary.concat`
composes these original decoded file views in memory; filename/disc sorting
alone does not establish fragment order. The archive API does not pretend that
each fragment is an independently complete resource map.
Each chunk retains up to 32 KiB of preceding history, starts on a byte boundary,
and resets the literal/copy command state. Chunk targets are absolute multiples
of 65536 decoded bytes. The final command may cross a target: a 65537-byte chunk
is followed by a 65535-byte chunk, not another 65536-byte chunk. The final fork
size remains exact. Synthetic regressions cover retained history, crossing
commands, absolute boundaries, truncation, limits and overlapping catalog forks.
The resource and Tome readers share the bounded codec in `archive/internal/instacomp`.

The text mode uses the same literal-run length codes but seven-bit literals,
different copy-length codes and different distance-code thresholds. Its copy
length prefix counts leading ones (up to ten): for counts 0–2, read two bits and
add four times the count; otherwise read that many bits and add `2^count + 4`.
The usual two/three-byte copy adjustment then applies. These rules and checksum
semantics were inspected directly in the Mac7.5 installer's `exfn/241` routines
and tested on all 22 text-mode files, including Hosts and printer descriptions.
No installer code was executed or copied into the implementation.

Original-media checks pass all 15 Mac7.1 files (1044 nested resources) and all
207 files across the six Mac7.5 Tomes (11540 nested resources). Both fork
checksums, exact sizes, complete stored-input consumption, resource maps and
their payloads are validated. Recursive probes retain headers and hashes for
checking payload-specific formats separately.

Checksums start at `0xffffffff`. For each decoded byte, rotate the accumulator
left by eight bits and XOR the byte **sign-extended** to 32 bits. Absent forks
use zero. This is not a CRC; using an unsigned byte gives incorrect results.
Both forks are validated before returning entries and `checksums_verified` is
true. Synthetic tests cover high-bit bytes, wrong checksums and both modes.
Later Mac CDs still require inspection. ID-qualified
paths preserve distinct entries even when their display names coincide; raw
names, Finder metadata, version, dates and both stored fork views remain available.

### Resource-map edge cases on CD media

Mac OS 8.5's DropStuff4.5 `ST46` archive contains ordinary files followed by
`STcp`, `STde`, `STal` and `DIFF` records with creator `STin`. The five
copy/delete/alias metadata payloads have a zero logical data size but742 stored
bytes each; all five data CRCs match those actual bytes. The reader preserves
these bytes, both raw declared sizes, `installer_record`, and one-based path
`occurrence`. Repetitions are allowed only for these evidenced installer records
in ST46, not ordinary duplicate files or file/directory collisions. No record
is applied, chosen over another, or overwritten. The two DIFF records retain
their separate decoded resource forks, not patched installed files.

The OSA Menu `ST50` installer has five physical root records but header count3.
ST46/ST50 counts therefore remain exposed but uninterpreted, like STi2;
`root_count_verified` is false for these variants. Directory nesting, all record
CRCs, stored ranges and decoded byte limits remain checked. Both original8.5
archives now pass every payload CRC and nested archive scan.

Mac OS 9.0.4's Palm Desktop installer uses `ST60`. Its catalog contains128
zero-logical-size,742-byte metadata payloads:124 `STde`, one `STda`, and three
`STmv`, all with creator `STin`. These are retained and CRC-checked as metadata,
not applied. Metadata can name a preceding directory without replacing it.
ST60 also retains alternative ordinary files at the same path: the Palm catalog
has two pairs of help-file variants with different resource forks and creators.
Each occurrence remains separate; parsing does not select an installed variant.
Ordinary file/directory collisions still fail. The header count79 differs from
176 physical root records, so ST60 also reports `root_count_verified=False`.

The Palm Desktop installer on Mac OS 9.2.1 uses `ST65`:298 catalog entries,
204 physical roots versus header count85, and144 zero-logical-size metadata
payloads of742 bytes with types `STde`, `STda`, `STmv`, and `STal` and creator
`STin`. ST65 preserves those records, including metadata naming directories,
and exposes its uninterpreted count separately. Metadata may also precede the
ordinary file it names: Palm's documentation PDF follows such a record.
Metadata participates in occurrence numbering, not ordinary path ownership;
a subsequent pair of ordinary files still triggers duplicate detection.
Ordinary alternative-file
duplicates have not been observed in this catalog; that ST60 exception is not
extended to ST65.

The AOL2.7 CD installer uses the `STi2` StuffIt variant. Its directory markers
can repeat an existing directory path; these records are retained rather than
deduplicated or treated as file overwrites. File/directory path conflicts still
fail. Its header count is not the count of all top-level physical records:
the reader exposes `declared_count` and `top_level_count` separately and reports
`root_count_verified=False` for this installer variant. The field's installer
semantics are not yet interpreted. Other classic variants keep root-count
validation. Every record/header CRC, decoded fork CRC, size and nesting boundary
remains checked; no installer actions execute.

Resource compression detection on the Mac7.6.1 CD requires both attribute bit0
and the `a89f6572` payload tag. FreeHand's FONDs, QuickDraw GX installer records
and Desktop Patterns retain the attribute on uncompressed data. The
[contemporary Resource Manager description](http://preserve.mactech.com/articles/mactech/Vol.09/09.01/ResCompression/index.html)
explicitly describes this second tag check. The parser preserves raw attributes
but reports `compressed` only for tagged, decoded payloads. Tagged malformed
headers still fail; missing tags are not treated as failed decompression.

Cumulus's FileMaker script contains19 separately stored, identical `PREC/128`
records. All records are preserved in map order, without treating ID lookup as
an unambiguous operation. `duplicate_ids` reports the collision; entries expose
one-based `occurrence`, and later occurrences have an ordinal suffix in `path`.
Overlapping payload ranges and inconsistent type/reference tables still fail.

### Apple Partition Map

`filesystem.apm` reads an explicitly selected logical block-size view. The
driver descriptor's device block size is separate metadata: Mac7.6.1's boot CD
declares 2048-byte devices but also contains a 512-byte map. Both maps address
the same HFS bytes: block320 ×512 and block80 ×2048, length256000000. The
existing HFS reader opens that partition with 568 catalog entries, 450 files.
Each file's data and resource forks have been read and hashed independently.

The CD retains a declared `Apple_Free` range beyond the image. Such descriptors
are exposed with their original geometry and no file view, not padded or
silently truncated. Allocated partitions must fit and may not overlap. Raw
names/types, logical data fields and boot metadata are retained; boot checksums
are not verified and no boot code executes. The native reader exposes partition
bytes; choosing and inspecting an inner filesystem remains explicit in Starlark.

Mac OS 8.1 also demonstrates mixed geometry within the 512-byte map:
the `Apple_Driver43_CD` record tagged `CDvr` starts at device block49,
not byte49 ×512. Its block-zero driver descriptor independently names block49
on the 2048-byte device. This driver occupies bytes100352..151551, between
the other drivers; interpreting it in 512-byte units incorrectly overlaps the
partition map. The reader uses device units only for this tagged, independently
described CD-driver case. Each partition exposes its effective `block_size`;
raw `start_block` and `blocks` remain unchanged. Bounds and nonoverlap checks
apply to the resulting byte ranges. A type name alone never changes units.
The resulting Mac OS 8.1 HFS view contains 1388 files; both forks read fully,
and all 1342 nonempty resource forks decode to 60073 resources.

The Mac OS 8.0 raw HFS CD has 771 files, 738 nonempty resource forks and
40478 resources. Its 84 Tomes contain 1453 checksum-verified file records.
Besides the split voices described above, Netscape Navigator 3.01 has a
3000000-byte resource prefix in Internet Access Tome12 and a 780125-byte
tail in Tome13. Concatenating those views yields a valid 2103-resource map;
this is payload reconstruction, not an inferred installation plan. The nested
DropStuff installer uses the supported StuffIt method14 decoder.

### Additional installer compression layers

The Mac OS 8.1 Dayna CommuniCard Installer2.2 (`STi4`) supplies a second
method14 example. Its 54 compressed forks contain 55 blocks: a little-endian
16-bit block count is followed by blocks whose first two little-endian 32-bit
fields give stored block size (including those eight bytes) and decoded size.
These ranges consume every stored fork exactly. The 70267-byte C&SS Init
resource fork uses decoded blocks65536 and4731. All28 Dayna files now decode
with matching fork CRCs, and their resource maps contain322 resources. The
DropStuff w/EE4.0 installer nested in Internet Access Tome2 also passes all
fork CRCs (14 files,441 resources); neither payload scan finds another
recognized archive layer beyond the StuffIt container.

Method14 begins each block directly with 308 literal/length and75 distance
code lengths, using the same recursive length encoding and first-pivot tie
ordering as ADCR03. Unlike ADCR, there is no preceding alphabet-size byte,
and matches start at length4 rather than3. Length extras are zero for the
first four match symbols, then increase once per four symbols; distance extras
are zero for the first three symbols, then increase once per four symbols.
Block output is at most65536 bytes, with up to256KiB of preceding decoded
history retained across blocks. Initial missing history is rejected, not filled.
These facts come from the original CODE1 decoder near byte7180 and its table
initializer at8168. Shared mechanics live in `archive/internal/aladdin`;
archive framing and fork CRC verification remain in `archive/stuffit`.

The installer's own resource map also contains `ADCR` wrappers, including
CODE2–5 and IPac15000. These are not Resource Manager `dcmp` resources:
their ordinary resource attributes do not flag compression. Observed headers
begin `ADCR 03` followed by a three-byte big-endian decoded size.
A bounded probe of the code0
payload with StuffIt method13 rejects its code-length run, so the wrapper must
not be handled by simply skipping its header and reusing that decoder.
`archive_layers` stops explicitly on `ADCR` until the caller selects its
dictionary and decodes it with `archive.adcr`; successfully reading the
enclosing resource map alone does not establish that these payloads are decoded.

`archive.adcr(file, dictionary=None)` implements the observed version03 codec
in Go. Its first payload byte selects a distance alphabet of twice that value
minus one; a 292-symbol literal/length table and the distance table follow.
Code lengths support zeroes, previous-length repetition and recursively coded
length alphabets. Canonical codes use the original first-pivot partition order
for equal lengths; a stable sort produces different symbols. Bits are read
least-significant first, and each table is byte-aligned. Output size and complete
compressed-byte consumption are checked; unused final-byte bits are padding.

History is not implicitly zero-filled. This Dayna installer passes its own
CODE6 bytes248..6757 as the dictionary. With that explicit file view, all60
resources match independently reconstructed REPL hashes and declared sizes.
The decoded code0 contains the expected `3f3c`/`a9f0` jump-table entries, and
STR#211 contains five well-formed Pascal strings. A zero-history control
damages those jump entries; a stable-code-order control overruns its input.
Dictionary selection stays in the inspection recipe: the portable decoder
does not locate, execute or embed proprietary loader code. Version1 is described
separately below; other versions remain unsupported. This wrapper has no checksum, so size checks alone are
not an integrity proof.

The DropStuff w/EE4.0 installer and DataViz TechWeb1/97 self-extractor on
Mac OS 8.1 use another loader generation: CODE4 and CODE3 respectively,
both5448 bytes. Their startup instructions pass bytes162..5447 (5286 bytes)
as history; those dictionary views have identical hashes. Explicit selection
decodes51 DropStuff and6 DataViz resources, with no further recognized archive
layers in those decoded payloads. Do not reuse Dayna's248-byte prefix length
for these loaders. Their archive data forks and outer resource wrappers are
separate inspections; opening the StuffIt data alone misses this compression.

On Mac OS 8.5, DropStuff w/EE4.5 and OSA Menu Installer share an identical
6766-byte CODE13 loader. Its startup uses a PC-relative pointer to the segment
start plus256 and passes length6510: the dictionary is bytes256..6765, not
either earlier loader's prefix. Explicit selection decodes79 and75 resources
respectively. All14 decoded STR# resources consume exactly their declared
Pascal-string counts and lengths; DropStuff's decoded code0 also has the
expected jump-table instructions. These structure checks supplement the
wrapper's size validation; ADCR still supplies no checksum.

The Mac OS 8.1 CD has71 Tome archives containing1529 checksum-verified file
records. Its split voice forks reconstruct to11 resources each; the Netscape
Navigator3.01 resource tail is780127 bytes here (two bytes longer than8.0),
and with the3000000-byte prefix reconstructs to2103 resources. The separate
source versions must not be substituted for one another during verification.

### ADCR version1 resources

The AOL2.7 68k installer on Mac OS7.6.1 has43 ADCR version1 resources.
They retain the8-byte ADCR/version/24-bit decoded-size header, followed by
four zero framing bytes and a big-endian32 stored length for the remaining
payload. Other framing flags are rejected pending evidence.

Version1 is not the version3 Huffman codec. Little-endian16 control words
select literals or two-byte phrase references, least-significant bit first.
References encode a12-bit table index and a length of3..18. The4096-entry
table has16 buckets; insertion uses a shared wrapping8-bit counter. Literal
triplets select a bucket from their byte sum masked with30, shifted by7;
matches also update pending literal triplets before inserting their own phrase
into the referenced bucket. Overlapping copies are valid.

The original DCMP128 resource supplies these layout facts; no external decoder
implementation was used. A bounded Starlark reconstruction and the Go reader
produce identical hashes for all43 resources. All43 avoid initial seed entries;
if another input references one, the API requires an explicit dictionary whose
first18 bytes supply that phrase. No proprietary seed constant is embedded.
Decoded code0 has the expected jump-table instructions and STR#1600's15
Pascal strings consume exactly294 bytes. ADCR has no checksum, so these remain structure/hash proofs.
With this layer decoded, the separate7.6.1 outer-resource scan follows80
archive contexts, including resource-only Tome catalogs.

### Tome catalogs of individual resources

Catalog kind (big-endian16 at header16) distinguishes ordinary file catalogs
(1) from individual-resource catalogs (2). QuickDraw GX also stores kind2
Tomes inside `part` resources of files whose data fork is empty. These are
real compressed payload layers, not copies of the enclosing file's catalog.
The Mac OS 8.1 CD contains78 such resource Tomes; every payload checksum passes.

Kind2 retains128-byte records but uses a different layout: catalog ID at4,
signed resource ID at6, four-byte resource type at8, optional Pascal name at12,
and one16-byte size/offset/stored-size/checksum descriptor at78. The payload
uses the existing Tome chunk decoder and checksum. `archive.tome` exposes
`catalog_kind`; kind2 entries expose `resource_type` and `resource_id`, with
decoded payload in `data` and empty `resource`. File-only metadata is omitted.
Unnamed resources use type/ID in their ID-qualified paths. Kind2 names can be
empty; treating byte6 as a file-name length or reading file-fork descriptors
at60/76 produces incorrect offsets. Unknown catalog kinds are rejected.
The REPL helper `hfs_resource_layers(volume, dictionaries={})` follows these
outer-resource archive layers separately from data-fork scanning. Its optional
map supplies explicitly identified ADCR dictionary views by enclosing HFS path.

### Known-bad Mac OS 8.6 source image

The inspected `MacOS86.iso` (584443904 bytes, SHA256
`9d2060ad2d4ff9970418fd3c4fff946279ee85abd44e4a07cd7fbc0406062b2f`)
passes its 7z member CRC32 `8c7e9edf`, but only312 of1526 nonempty HFS resource
forks parse. From catalog file409, `Journeyman200k.mov`, onward, resource
headers are implausible. Independent ISO9660 and HFS lookups return identical
implausible movie data bytes. Direct catalog inspection confirms the selected
HFS extents; searching within4MiB of the first bad resource location at512-byte
intervals finds no matching resource header. This is evidence of a source-image
problem, confirmed by the media owner, not a new resource encoding. The affected payloads remain
unverified; the readers do not guess offsets or substitute another CD's bytes.

### Historical UFS1 on Ultrix media

`archive.arsenic` decodes raw StuffIt method15 forks using bounded
arithmetic/MTF/BWT processing and in-stream CRC32 validation. Its Go code
and constants are adapted from MIT-licensed KarpelesLab/compcol, with the
notice retained in `archive/arsenic/LICENSE`.
All eight forks in the freeware CD's Macintosh bzip2 StuffIt5 archive
pass CRC32 and match independently probed container lengths. The two
resource forks parse as nine and three resources; all twelve payloads
are read and hashed. Native `archive.stuffit` banner/version5 dispatch now
returns the folder and six files. All eight native fork hashes match the
independent REPL reconstruction. The archive, record and metadata CRC16
fields, parent/previous/file-next links and directory child counts are
checked. Method15 streams supply fork integrity via CRC32, so version5
fork CRC16 attributes are `None`. Other version5 fork methods are not yet
implemented. The nested-media probe recognizes the banner automatically.

The freeware VAX and RISC ISO CDs expose230 and281 files through native
ISO9660. Every file has been read and hashed. Initial recursive scans found
1121 and1391 recognized layers respectively. Both contain additional LHA
`lh5` and StuffIt5 archives, now decoded by their native readers.

`archive.lha` now reads level-0 headers and lh0/lh5 payloads. The freeware
discs carry byte-identical Amiga bzip2 archives containing18 lh5 entries;
all header checksums and decoded file CRCs pass. Native names match the
independent REPL catalog, and every decoded file is hashed. Nested traversal
also reads a seven-member ar library. `archive.hunk_objects` decodes the
AmigaOS bz2.lib into seven object units and46 records; every record boundary
matches the independent REPL catalog, and all raw units/records and25 name,
code and data payloads have been read and hashed. Symbol and relocation
tables are exposed as metadata, not applied to code. BSS is a size declaration,
not a host allocation. The WarpOS bz2.lib also decodes: seven units,93
records and19 stored section payloads. Its EHF PPC_CODE and EXT_RELREF26
framing is confirmed by the archived publisher specification; all record
boundaries match the independent REPL catalog and all stored sections are
read and hashed. Fresh traversal of the whole LHA now follows eight
recognized layers: LHA, one ar library, two Hunk object libraries and four
Hunk executables. ELF object/executable interpretation remains separate;
this is not a claim of complete nested-format coverage for the whole disc.

`archive.hunk_load` reads all four bzip2/bzip2recover load modules in the
AmigaOS and WarpOS directories. Their53 record boundaries match independent
REPL catalogs and their4/4/7/6 section counts and sizes match the header
allocation tables. All17 stored section payloads have been read, hashed and
checked for recognized nested containers (none found). BSS sections are
declarations, including the roughly326KB recovery-program buffers; no bytes
are fabricated or allocated for them. These WarpOS load modules use ordinary
CODE records even though their object library uses PPC extension records.
No program is executed. Overlay, compact-relocation and extended-memory
variants remain unsupported.
Other LHA levels/methods remain explicit
gaps until exercised; no self-extractor code runs.

The VAX binutils2.9.1 archive exercises legacy randomized bzip2 blocks.
`archive.bzip2` now supports these using a Go BSD-licensed reader extension
with the bzip2 randomization table and its retained license notices under
`archive/internal/bzip2`. The original archive passes block/stream CRCs and
decodes47462400 tar bytes,2452 entries and2365 regular files read/hash.
Focused tests check derandomization before run expansion and across read
boundaries; ordinary bzip2 and concatenated-stream tests still pass.

The Ultrix4.2 and4.5 discs contain99 and85 UNIX-compress package streams.
All184 now decode as classic tar, with21950 regular files read and hashed.
Eight require explicit `archive.compress(file, zero_padding=True)` because
the fixed-block media records end in an incomplete zero code. The default
decoder remains strict; no bytes are trimmed and decoded zeroes are retained.
For these eight packages, all1293 regular files additionally match their
original `.inv` entries in path, size and rotating16-bit checksum, with no
missing or extra regular files. These checks establish package decoding,
not complete nested-format coverage or installation semantics.

Following recognized nested formats across these packages finds113 layers
on4.2 and120 on4.5. Each disc also has the same932-byte plain-text
`/usr/new/Readme.tar.Z`: its archive-like suffix causes a probe false positive,
not a decoding failure. The language-support disc adds104 classic-tar
packages,3644 regular files read/hash and18 recognized nested layers. Three
of those packages require zero-padding mode and pass their regular-file
inventory checks. Unknown binary leaves still require separate inspection.

`archive.bsd_dump` reconstructs full single-volume historical BSD dumps
(magic60012, 1024-byte records and old128-byte UFS inodes) without restoring
anything to the host. It checks record checksums and positions, reconstructs
sparse inode data and uses the same directory reader as `filesystem.ufs`.
Hard links share file views; device entries remain metadata. Incremental
dumps and other dump generations are currently rejected explicitly.

Ultrix4.2 `/VAX/BASE/ROOT` contains219 distinct inodes and222 reachable paths
including root. All221 non-root native entries match an independent Starlark
reconstruction in path, inode, mode, size and SHA256. The stream includes ten
continuations and seven END records. Its dump bitmap contains exactly the219
recovered inode numbers. The reader cross-checks dumped inode membership
against recovered records and the allocation map. Ultrix4.5 ROOT additionally
decodes223 reachable paths; all payloads have been read and hashed.

`filesystem.ufs` reads the old inode/directory generation used by Ultrix.
It uses the superblock at8192, UFS1 magic at superblock1372, declared fragment
and cylinder-group geometry, and128-byte inodes. It does not infer a modern
UFS2 layout from a filename. Format references are NetBSD's
[superblock declarations](https://raw.githubusercontent.com/NetBSD/src/trunk/sys/ufs/ffs/fs.h)
and [inode declarations](https://raw.githubusercontent.com/NetBSD/src/trunk/sys/ufs/ufs/dinode.h).

The Ultrix4.2 VAX CD has8192-byte blocks,1024-byte fragments,149 cylinder
groups,576 inodes and1344 fragments per group. The REPL independently walks
440 non-root entries and reads428 files,86 using single-indirect blocks.
The Go reader enumerates the same files plus the root and matches every
REPL file hash. Synthetic fixtures additionally cover both byte orders,
group staggering, sparse holes and double/triple indirection. Mapping and
entry limits bound metadata work; file contents remain borrowed views.
Directory records retain the historical16-bit name length, not a modern
type/name-length pair. Dot entries and directory cycles are checked.

This is filesystem decoding, not installation planning. Ultrix package
names often omit archive suffixes: ULTBASE420 decompresses as Unix compress
and then opens explicitly as classic tar (975 entries,753 regular files
read in the REPL). A name/ustar-only archive probe would miss that tar layer.
ROOT has a different header and remains a separate format investigation.
UFS2, modern inode extensions and inline symlink variants are not implemented.

The Ultrix3.1D DECstation image is a complete601374720-byte disk, not a
single UFS volume. Its root filesystem occupies only20971520 bytes. The
eight-slot label at16312 identifies a/g/h filesystems, b space without a UFS
superblock, and an overlapping whole-disk c view; d/e/f are empty. The root's
fstab identifies a as root, g as /usr and h as /home. These remain separate
file views; the decoder does not combine mount trees or follow network mounts.

`filesystem.ultrix_label` exposes all eight slots, validates magic and
active-table flag and checks nonempty512-byte-sector ranges. There is no
checksum or filesystem-type field. Overlap is retained deliberately: treating
c as a second root filesystem would duplicate a while missing /usr.
The original bytes agree with the layout documented in NetBSD's
[DEC boot-format header](https://raw.githubusercontent.com/NetBSD/src/trunk/sys/dev/dec/dec_boot.h).
The three UFS trees contain148,6375 and0 regular files respectively; symlink
targets are read as data without following them, and device nodes remain
metadata only.

All tests for these formats use constructed fixtures; proprietary media and
extracted payloads are not included in the repository.
