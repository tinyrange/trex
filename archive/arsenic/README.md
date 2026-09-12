Arsenic is StuffIt compression method 15, a per-fork arithmetic/BWT codec.
This Go decoder is adapted from KarpelesLab/compcol's `src/arsenic` code
and tables under the retained MIT license. It is not the upstream Rust code.

The caller supplies separate logical-output and intermediate-block limits.
The binary frequency model persists across blocks; selector/MTF models reset.
Each block is inverse-BWT transformed, optionally derandomized, then expanded
using final RLE. Nonempty streams must pass their trailing IEEE CRC32.

Verification: independent Starlark header probe, truncation/limit tests and
fuzzing. All eight forks in the freeware CD's bzip2 Macintosh StuffIt5 archive
pass in-stream CRC32 and match independently probed container lengths. The
README.MPW resource fork additionally parses as a three-entry resource map.
The native StuffIt5 reader uses this decoder and independently checks each
declared fork length; all eight container-returned hashes match the REPL.
