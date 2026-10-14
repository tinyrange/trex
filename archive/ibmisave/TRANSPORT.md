# Qualified optical transport and descriptor profiles

## LD_TRS codec 02

`OpenOpticalTransport(source, maximumRecords, maximumBytes)` follows physical
record lengths and exposes a lazy `storage.Reader`. It does not carve embedded
signatures. Plain object extents and verified IBM037-blank padding pages are
borrowed. The outer 14-byte LD_TRS header contains the invariant EBCDIC tag,
u16 expanded bytes at +8, a zero u16 at +10, and u16 stored frame bytes at +12.
The inner 12-byte frame starts with 02000080, u32 stored length at +4 and u32
expanded length at +8. Both inner/outer lengths must agree; expanded records
are complete 4096-byte pages. Byte and record budgets precede allocations.

The payload uses MSB-first 12-bit codes. Literal codes 1..256 represent bytes
0..255. Nodes 258..4095 start as increasing IBM037 blank-run extensions.
Code 257 is unqualified/reserved. Every output phrase reserves the least
recently used tree node; every node in the referenced prefix chain is touched.
The previous reserved node receives the next phrase's first byte. A dictionary
that merely freezes, wraps, or resets on reaching its capacity is incorrect.

`DecodeTerseWithInfo` reports consumed bits and termination separately. A
complete frame ends with a zero 12-bit code and zero fill to a byte boundary;
producing the expected number of output bytes is not proof of completion.
Native automatic and transport readers require verified termination. Codec 02
is distinct from the LIC variable-width/back-reference codec 03.

The real QSYS Q01/Q02 chains independently validated 8,970/8,211 records,
including dictionary recycling, and all termination trailers. Full streamed
hashes of their known logical bytes are recorded in the private corpus audit.
Each has 930 framed save objects; catalog inventory counts are separately
930/929 and are not assumed one-to-one with saved descriptors.

## Unknown LD_LZ1 tails

The inspected physical streams finish with one zero-expanded LD_LZ1 record.
Its stored length exhausts the input, but its body is not zero padding and its
meaning is unknown. `UnknownTail` preserves the complete original record.
`Complete=false` explicitly limits claims to the known logical prefix.
Nonterminal or nonzero-expanded LD_LZ1 records are unsupported, not skipped.

Automatic views are `logical-prefix.bin`, `transport.json`, and, when present,
`opaque-tail.bin`. Each transport record retains its original source offset,
stored length, logical offset and expanded length. Save-object offsets inside
the logical view refer to that input stream, not physical optical coordinates.
One decoded record is cached; payloads are never extracted to intermediate files.

## Save descriptor profiles

`Open` / `archive.ibmi_save(file)` retain required catalog framing.
`OpenProfile` / `archive.ibmi_save(file, profile="boot750")` additionally accept
only the inspected catalog-free initial QGENESIST/19c1 or QINTAPE/0201 descriptors
with release/target 4705/4705. Auto selects this profile from descriptor bytes,
not a convenient filename. Arbitrary missing catalogs remain errors.

The observed 4705/4705, 4705/3905, and 4600/4600 pairs use a section-table origin
at or after 0x280. The older 3400/3400 font profile uses an origin at or after
0x1e0. All still validate the explicit table pointer, counts, 16-byte rows,
page-aligned stored extents and complete input framing. Other release pairs
remain unsupported. Padding alone does not force a new catalog: only a catalog
at an initial/padded group boundary does. Consecutive duplicate catalogs remain
separate occurrences in the same group.

## Logical saved bytes and character identity

`Section.LogicalReader` preserves declared logical size and the stored prefix;
reads of absent bytes return `ErrUnsaved`. `logical-sections/N.bin` exposes this
view alongside existing `sections/N.bin` stored views. Sparse prefix metadata
prevents speculative auto reads from treating absent pages as corruption.
`Object.StoredAt(address,length)` can compose exactly adjacent stored spans;
it rejects ambiguous spans, holes and address arithmetic overflow. Saved
addresses remain opaque identities, not execution mappings.

Catalog correlations require exact raw names, types and save-group identity.
Unknown program/MI internals, member relationships and object CCSIDs remain
unknown. Source text and catalog descriptions label IBM037 as an explicit
rendering, not detected saved CCSID. No bytes or character-set metadata are
invented to make an unsupported logical object look complete.
