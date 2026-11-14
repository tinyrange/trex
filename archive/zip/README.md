# ZIP member readers

`archive.zip(file)` and automatic ZIP browsing support Stored (0), Shrink (1),
Implode (6), and Deflate (8) members. Each member exposes `compression_method`,
`compressed_size`, `name`/`path`, `entry_type`, normal file operations, and
`verify()`. Automatic member metadata also includes `compression_method`.

The native legacy readers use fixed-size dictionaries and stream into the
existing bounded 8 MiB member window. Backward reads outside the window restart
the stream; no host extraction, subprocess, or intermediate file is used.

- Shrink uses 9–13-bit LSB-first LZW codes, explicit width increases and
  partial dictionary clearing.
- Implode supports both 4 KiB/8 KiB dictionary flags and both two-/three-tree
  modes, including overlapping matches and zero-initialized prehistory.
- Complete reads and `verify()` check the declared decoded size and central
  directory CRC, including empty members. Invalid trees, codes, truncated
  streams, trailing whole bytes, and output overruns fail closed. Encrypted
  legacy members are not supported.

Checks include hand-authored synthetic regression vectors, bounded replay,
malformed input and fuzz seeds. Real-media validation read and CRC-verified all
477 file entries in `p390microcode.zip` and its ten nested ZIPs, including 171
Implode and 27 Shrink members. Additional validation used Apache Commons
Compress's SHRUNK, 4K/two-tree, 8K/three-tree and lorem-ipsum Implode fixtures
in memory; none of those archives or the IBM media are bundled here.
