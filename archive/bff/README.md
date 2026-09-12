# AIX by-name backups

`archive.bff(file)` returns entries with portable payload file views, original
names, normalized paths, inode/link identity, modes, ownership, timestamps,
device numbers, raw headers, ACL/PCL bytes and stored payload views. No scripts
are executed and no metadata is applied to the host.

The initial reader supports AIX 4.1 extended-name records (type 11), a 72-byte
by-name volume header and type-7 end records. Fields are little-endian; record
lengths and security allocations use eight-byte units. Header checksums sum
`b << (b & 7)` modulo 65536 over all declared header bytes, treating the checksum
word at offsets 4–5 as zero. This was independently established from a bounded
observation of the original media's checksum routine and checked against 743
headers in the development and update packages; no original implementation
was incorporated.

Packed entries use the UNIX pack Huffman body without its standalone magic or
size prefix. The enclosing BFF header supplies the logical size to the shared
native decoder. Decoding checks termination and size and enforces a cumulative
decoded-byte limit. Uncompressed payloads remain borrowed views: BFF has no
payload checksum, so header validation alone does not prove content integrity.

Original U438109 packed files decode to 334650 and 125375 bytes, respectively,
matching independent Starlark probes through the standalone pack decoder.
Nested `liblpp.a` files use AIX small indexed ar; some `.a`-named payloads instead
start with XCOFF executable headers, so extensions are not format evidence.

Distribution padding after the end record may be nonzero and is retained as
`trailer`. Exact-end and 1024-byte-rounded files are accepted. Older record
generations, continuation volumes and larger physical tails fail explicitly;
this is not a claim of complete support for every AIX backup generation.
