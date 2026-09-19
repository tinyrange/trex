These RAR 3/5 decompression components are adapted from Nicholas Waples’
[rardecode v2.4.1](https://github.com/nwaples/rardecode/tree/v2.4.1), under the
BSD-2-Clause license retained in LICENSE. No GPL or UnRAR-licensed source is
included. The upstream host filesystem, volume, archive and encryption layers
are not included; TinyRangeX owns the portable container parser and file API.

Changes: remove filesystem coupling and RAR2 decoding; expose a sequential
solid-stream decoder; bound dictionary and declared PPM budget to 64 MiB each;
convert malformed compressed-data panics to decode errors at the boundary.
Stored RAR2 members need no decoder. No module dependency is added.

Window-boundary fixes retain unfinished LZ matches and account for buffered
filter input when queuing subsequent filters. Focused independent tests cover
both, along with distances that cross the dictionary end.
