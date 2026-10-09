# Bounded PBZX replay cache

`archive.pbzx(source, maximum_bytes=..., replay_cache_bytes=...)` can retain
previously decoded chunks in fast-compressed memory, in addition to its existing
64 MiB decoded LRU. The default replay budget is zero, preserving the original
retention policy. The API consumes borrowed source files, not host paths.

On a first miss, the original XZ stream is decoded and verified to its indexed
end. Only successful output is admitted to the decoded and S2 caches. On a later
decoded-cache miss, an indexed S2 representation avoids repeating XZ decompression.
It contains independently readable **64 KiB blocks**, not a single whole-chunk
S2 stream. The decoded LRU retains only requested blocks. A 4 KiB read contained
within one block therefore replays at most 64 KiB rather than 16 MiB; crossing
block boundaries reads the intersecting blocks. Original chunk boundaries need
not align with replay blocks, and the final block may be short. First access
still decodes and verifies the entire original XZ chunk before serving any bytes.
This is lazy: opening the payload does not predecode it, and reading one chunk does
not prefetch other chunks. There are no persistent decoded intermediates.

The replay budget bounds retained encoded byte arrays. The implementation copies
encoder output into exact-sized backing arrays before admission; charging a
short encoded slice backed by a full decoded-sized allocation would defeat the
memory bound. The byte LRU supplies eviction and single-flight loading. Encoded blocks for one
original chunk are admitted/evicted together. Concurrent misses on different
pages of the same chunk share its original XZ decode; an undersized replay budget
does not cause a single multi-page read to repeat XZ for each page.
Temporary encode/decode buffers, cache metadata and outstanding caller references
are additional to retained-byte budgets, as with the decoded cache.

The cache is internal, ephemeral and not an external file format. Original XZ
checksums remain mandatory; fast-cache hits reuse already-verified bytes. A
full-buffer read accompanied by a trailing XZ checksum error is rejected, not
silently accepted through `io.ReadFull`'s full-buffer error suppression.

Use a representative read trace before reserving memory. Highly compressible
chunks may fit far more of a working set than the decoded LRU; incompressible or
oversized entries still fall back to original-source decoding after eviction.
Increasing total cache memory is not necessary: a caller can transfer a portion
of an existing upper-layer read-cache reservation to the replay cache. That is
recipe policy, not a default imposed on all PBZX users.

Outer caches must also use a small fill size: a 16 MiB outer fill would defeat
block-granular replay. The private High Sierra recipe uses a 64 KiB outer cache
when replay is enabled, preserving its existing byte budget.

The returned file's `stats` attribute is a detached dictionary with cumulative
successful `xz_chunks`, `xz_bytes`, `replay_blocks`, `replay_bytes`, and
`replay_block_size`, plus `decoded_cache` and `replay_cache` statistics. Cache
statistics include hits, misses, evictions, loads, loaded_bytes, retained bytes
and entry count. Counters are observational under concurrent reads, not a single
transactional snapshot. Save construction statistics and subtract them from
later snapshots to measure boot-only work. Wrapped/sliced generic file views do
not forward format-specific attributes; retain the original PBZX value.

Focused tests cover reads across replay blocks, original chunks and EOF, concurrent readers, decoded and
replay eviction, undersized/disabled caches, exact retained allocations, and
failure to admit corrupt original XZ data or checksums.
