# APPX/MSIX reader

Portable ZIP/OPC and manifest parsing; no deployment or host extraction.
`VerifyBlockMap` verifies SHA-256 over successive decoded 65536-byte blocks,
including exact final-block size, file sizes, CRC and complete payload coverage.
The map is bounded to 8 MiB. The caller bounds total decoded bytes per archive.
Bundle maps contain only the bundle manifest; verify members independently.
Signature, content types and code-integrity footprint files are not block-mapped.

This is not signature or publisher authentication. Compressed block boundaries,
local-header lengths, signed ZIP digests, certificate trust and revocation are
not checked by this operation. Never infer trust from a self-consistent map.

Format reference: Microsoft's MIT-licensed msix-packaging implementation,
`src/msix/unpack/AppxBlockMapObject.cpp` and `AppxPackageObject.cpp`.
Implementation here is independent Go code; no Microsoft implementation copied.

Bundle member references accept Windows separators and expose canonical slash
paths; ZIP entry names remain strict. Embedded `IsStub` alternatives remain
inspectable via `packages[].is_stub`. Full-install selection must skip these
alternatives, not install both versions. Missing/external members, traversal,
and duplicate normalized references are rejected.

## Indexed compressed reads

MSIX payload compression resets the deflate dictionary at each 64-KiB block
(`Z_FULL_FLUSH`; Microsoft `src/msix/pack/DeflateStream.cpp`). Valid compressed
block sizes provide bounded raw-member offsets. Reads decode only the requested
blocks, verify each decoded SHA-256, and retain one decoded block per entry.
They do not replay a large DLL's prefix on every backwards page read. A single
whole-file read (`bytes()`) and explicit `verify()` retain ZIP CRC validation;
partial indexed reads validate only the blocks they touch. Starlark file methods
use the same indexed reader. No intermediate host files or whole-payload cache.

Absent/ineligible indexes keep the ordinary bounded ZIP reader. Index eligibility
is not successful block-map validation; callers must still invoke
`verify_block_map` for coverage, size, decoded-byte and CRC checks. Random reads
are still not publisher authentication. Malformed independently addressed blocks
fail rather than returning unverified bytes.
