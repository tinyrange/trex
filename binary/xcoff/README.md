# Native XCOFF32 and XCOFF64 inspection

`Open(storage.Reader, maximumSections)` reads 0x01df XCOFF32 file headers,
auxiliary-header entry/TOC fields and bounded stored section views. APIs remain
independent of host files or processes. BSS is metadata, never invented bytes.

`File.ReadLoader(maximumRecords, maximumMetadataBytes)` decodes version-1 loader
symbols, counted names, three-string import descriptors and relocation records.
It validates table extents, section/symbol/import references and relocation
width/address bounds. Metadata reads are batched and budgeted. Name bytes are
preserved as hex or reversible escapes; no saved encoding is guessed.

Automatic `xcoff32` views expose `metadata.json`, `headers.bin`, numbered
`sections/N.bin` and lazy `loader/{metadata,symbols,imports,relocations}.json`.
These loader JSON views are subject to the expanded-byte budget. Opening a plain
section view does not force loader-table decoding.

A loader entry designation may name a data table, not a direct machine-code
entry. In particular an auxiliary entry field of zero does not establish that a
component is a standalone executable. Unknown empty `.except` flags are not
silently treated as BSS or the defined overflow-section type.

Relocation records are interpreted as references but not applied. Linking,
execution and XCOFF32 overflow-section records remain unsupported. Metadata
continues to report `decoding_complete=false` for the whole object.

Layouts were checked against IBM's AIX XCOFF documentation. Regression tests use
original synthetic objects, including malformed counts, string offsets, import
framing, dangling references, width/address errors and budget exhaustion. No
proprietary objects or third-party parser source are fixtures.

## XCOFF64

`Open64` retains independent 64-bit address, size and file-offset domains using
24-byte file headers, 120-byte auxiliary headers and 72-byte section records.
The auxiliary entry/TOC and section indices are validated. `File64.ReadSymbols`
decodes 18-byte symbols and bounded normal/debug name tables, retaining every
auxiliary record as hex and interpreting only tagged AUX_CSECT records.
`ReadRelocations(section, ...)` decodes 14-byte section relocations, rejecting
auxiliary/invalid symbol indices and out-of-section write widths.
`ReadLoader` supports the 56-byte loader header, 24-byte symbols and 16-byte
relocations with explicit 64-bit table offsets. The observed IBM i version-1
and documented version-2 headers use this layout; strings/imports and all
reference bounds are checked. Tables must not overlap.

Auto exposes the same raw headers/sections and lazy loader JSON paths as the
32-bit reader, plus `symbols/symbols.json` and
`relocations/N/relocations.json`. Public metadata changes do not mutate the
validated table references. The three expanded IBM i PASE components were read
through native UDF/IMD/packed views, including 3,306 normal symbols, 7,645 section
relocations, and 3,318 loader relocations. Synthetic tests cover both loader
versions, addresses above 32 bits, auxiliary identity and malformed tables.

This is inspection, not relocation, loading or execution. Other auxiliary
kinds, complete line/debug semantics and unknown flags remain uninterpreted.
Layout references include official IBM, Go and LLVM format declarations;
see the format-reference notice for provenance.
