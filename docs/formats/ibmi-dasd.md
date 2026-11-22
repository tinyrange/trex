# IBM i DASD pages

`binary/ibmidasd` reads the page envelope observed on IBM i disks: 4096 data
bytes followed by a 512-byte sidecar, at 4608-byte strides from disk offset 0
(the ISSI framing in [power-firmware.md](power-firmware.md)). Eight sector
headers occupy sidecar +8..71.

Each page's virtual address is distributed across its sector headers. The
decoder checks the common scope, the replicated address bits in untagged
sectors, and the ordinary header kind; tagged sectors retain their
distributed address fields.

Indexing takes explicit physical ranges and a page budget. It preserves all
physical matches and does not establish an allocation map or select a current
version. A virtual file requires exactly one match for every requested page;
missing pages are never filled. Files remain borrowed, including unaligned
cross-page reads. Nonzero ISSI controls must agree in all ten locations before
displaced data tails are restored. Unstamped data stays unchanged. Controls
are stamps, and no checksum or authentication is claimed.

The resident LID directory is a counted 32-byte-record directory with an
EBCDIC END marker. `archive/ibmiimd.ReadDirectory` shares its framing
validation with the optical reader while retaining sector fields as metadata;
on disk, components use declared virtual addresses and sector-count lengths,
so sector fields are not physical disk offsets.

Procedure descriptors are also read natively. The observed aligned kind-2
record starts with 0200000000000000, has an entry address at +8 and an exact
NUL-terminated IBM037 name at +56. `binary.ibmi_procedures` checks this
framing and bounds its source and match count.

`binary.ibmi_dasd_index(source,ranges,maximum_pages=1048576)` exposes
`matches(address)`, `file(address,size)` and `page_address(offset)`. The last
operation reads a 4608-byte-aligned physical frame's header and returns its
page address or None. Each match includes `pointer_tags`, a 32-byte bitmap in
the same bit order as the POWER machine's `pointer_tags` result. Each bit
describes one 16-byte quadword at lookup time. Use a disk snapshot for a
consistent comparison with the borrowed data and header views after resuming
a guest. The index also reports compact counts of scanned, recognized and
unmapped pages. `binary.ibmi_lid_directory(source,offset=0,
maximum_entries=4096)` returns the qualified directory records. These APIs
perform no mounting, extraction, restoration of omitted pages or execution.

Regression tests exercise distributed addresses, tagged sectors, inconsistent
headers, bounds, duplicate physical versions, holes, borrowed data, cross-page
reads and stamped-sector integrity.
