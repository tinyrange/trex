# IBM i optical save streams

`archive.ibmi_save(file)` reads the descriptor layout inspected on IBM i 7.5
optical distribution media. `auto` exposes `saveN/object-name/` directories with
`descriptor.bin`, `stored.bin`, `sections/N.bin`, and an optional `trailer.bin`.
Duplicate names have occurrence subdirectories. Unknown EBCDIC identifier bytes
are percent-escaped; the original name bytes remain available in metadata.

Descriptors are 4096 bytes, with big-endian block counts in 512-byte units.
Section table entries preserve logical length, stored length and an opaque
address. Stored bytes are borrowed slices of the input, not extracted files.
Logical length is not an instruction to pad or decompress a section: those
semantics are not established. Some objects have additional data after the
declared sections; it is preserved as an uninterpreted trailer. Descriptor
declared logical blocks need not equal the sum of section logical lengths.

This is structural decoding, not IBM i object restoration. Standalone SAVF
528-byte transport records, other descriptor release layouts, MI object
internals and companion-volume reconstruction are not implemented. There is no
claim of payload checksum validation. Native bounds checks cover descriptors,
section extents, padding, and entry budgets.

Stored and logical section lengths can differ substantially. The reader keeps
both lengths and does not fabricate the missing logical tail.

## Directory plan

`auto_plan` recognizes a directory containing `QLANGID` and `QUSRLIBS` from
its listing and proposes **Combine IBM i libraries**. Selecting
`$plans/ibmi-libraries` indexes library names across the variant directories;
opening a library parses its save stream and combines its save groups.
Paths use `LIBRARY/V7R5M0/level00/language2924/OBJECT/type-xxxx/`.
Duplicate object/type pairs retain numbered occurrences; metadata identifies
their source path, save group and descriptor offset. Original paths are unchanged.

Listing a proposal reads no member contents. Library contents are validated
lazily, and malformed or unsupported streams fail explicitly. Variants are kept
separate, not overlaid or chosen according to the browser's locale. The plan
does not include QSYS product streams: those contain LD_TRS records not yet
handled by this descriptor parser. It is not a complete distribution reconstruction.

## Structured object inspection (partial)

Object nodes expose JSON metadata lazily through `auto.MetadataView`, including
the save descriptor, section extents, and a verified common object header when
present. Raw type codes remain alongside IBM's documented external type names;
internal-only codes remain numeric. A matching name/type is required before
interpreting the common header. Four database objects in the inspected libraries
start with a different structure and do not pass that check.

The currently verified body layouts are:

- `19DB` save catalogs: library identity and counted 151-byte entries, each
  exposed in `catalog-entries` with name/type/associated-name metadata, counted
  descriptions (explicit IBM037 rendering), and its original record bytes.
  Catalog entries are not one-to-one with saved-object
  descriptors. Unidentified attributes and trailing catalog regions remain raw.
  Exact raw-name/type matches within the same save group are also shown on the
  corresponding object's metadata; duplicate catalog matches are retained.
- `1906` tables: the 256-byte mapping, also exposed as `table.bin`.
- `1903` job descriptions: user, job queue/library and routing-data prefix.
  Priority bytes remain raw because their order has not been established.
- `190A` character data areas: flags, declared byte length and value; invariant
  EBCDIC text is labelled as such and `value.bin` retains the original bytes.
- `0B90` data-space source sections: the inspected type-3, 93-byte row form
  exposes sequence/date metadata and an explicit IBM037 text rendering. The
  saved CCSID is not yet identified, so the filename and metadata identify the
  chosen rendering rather than claiming automatic character-set detection.

All object views currently report `decoding.complete=false`. Unknown fields,
other generations and other object bodies are not implied decoded. Source
inspection is bounded to 1 MiB per candidate section and reports unsupported
framing explicitly; absent logical tails are not fabricated. The common
simple-space body is exposed as `object-space.bin` only when its stored address
validates against the section extent. Larger raw content stays in file views.

Layout evidence comes from native REPL inspection of the original media, not
host extraction or third-party parser code. Semantic references:

- [IBM external object types](https://www.ibm.com/docs/en/i/7.5.0?topic=objects-external-object-types)
- [IBM CRTTBL](https://www.ibm.com/docs/en/i/7.4.0?topic=ssw_ibm_i_74%2Fcl%2Fcrttbl.html)
- [IBM source-file fields](https://www.ibm.com/docs/en/i/7.6.0?topic=file-creating-source-without-dds)

These references describe object semantics, not a guarantee that public API
receiver layouts match saved internal storage.

## Implementation provenance

The parser is independently implemented from observed binary layout facts and
the public semantic references above. No IBM implementation source, proprietary
payloads, or third-party parser implementation is included. Tests construct
synthetic records in Go; they do not require or redistribute installation media.
Character conversion uses the BSD-3-Clause `golang.org/x/text` dependency;
its notice is retained in the repository's dependency licence notices.
This is a provenance statement, not a formal clean-room certification or a
determination of a user's rights to particular input media. The reader grants
no rights to redistribute the content it reads.
