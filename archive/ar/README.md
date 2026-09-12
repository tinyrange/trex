# ar readers

`archive.ar` reads traditional Unix ar and AIX small indexed archives. Member
files borrow their original bytes; `find(name, occurrence)` preserves access
to repeated names. No linker or host archive command is run.

AIX small archives use a doubly linked member chain. The reader validates its
first/last endpoints, member table names and offsets, optional symbol references,
free-list links, bounds and non-overlap. It does not assume physical member order
matches archive order. Numeric fields are ASCII, with octal modes. The cosmetic
trailer is not an integrity checksum. Deleted members are not active payloads.
Limits bound active members, total header count, names and table bytes.

Layout follows the [IBM small-ar format reference](https://www.ibm.com/docs/en/aix/7.2.0?topic=formats-ar-file-format-small).
Original AIX 4.1.5 U438322/U438109 nested `liblpp.a` files independently match
16 member names, sizes and SHA-256 hashes from a Starlark linked-record probe.
Synthetic tests cover noncontiguous ordering, deleted members, symbols, invalid
links, table disagreement, overlapping ranges, limits and borrowed payloads.

This does not implement BFF backup framing, XCOFF interpretation, archive linking
or installation policy. AIX big indexed archives remain a distinct format.
