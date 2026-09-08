# LZX throughput benchmarks

Run the reproducible, generated-in-memory fixtures:

```sh
go test ./compression/lzx -run '^$' -bench BenchmarkDecompress -benchmem -count=3
```

These cover CAB and WIM framing, literal-heavy, overlapping-match-heavy, and
uncompressed blocks. They include output allocation and the applicable E8
transform. MB/s is **decoded** decimal megabytes per second, not input throughput.

Opt-in real-media benchmarks use trex's ISO/UDF and archive readers; no extracted
files or third-party fixture bytes are needed:

```sh
CAB_LZX_ISO=/path/to/media.iso CAB_LZX_MEMBERS=/i386/driver.cab,/i386/shell32.dl_ \
  go test ./archive/cab -run '^$' -bench BenchmarkLZXMedia -benchtime=2x -count=3
WIM_LZX_ISO=/path/to/media.iso WIM_LZX_MEMBER=/sources/install.wim \
  go test ./archive/wim -run '^$' -bench BenchmarkLZXMedia -count=3
```

Use paths with the spelling/case exposed by the media filesystem. CAB benchmarks
decode each LZX folder; WIM samples the first compressed chunk of up to 256
resources in lookup order, excluding stored chunks. Reads, archive parsing, and
hashing are outside the benchmark timer. Decoder allocations are included.
Compare the logged output hashes between revisions as well as throughput.
Run cases serially on an otherwise idle machine and retain repeated measurements.

Add `-cpuprofile /path/to/report.cpu.pprof` for a CPU profile. Go profiles include
benchmark setup and verification even though reported ns/op excludes them; use
decoder-filtered views and sufficiently long runs when interpreting profiles.

## Implementation and correctness

The decoder uses a 64-bit bit reservoir, reusable 10-bit Huffman lookup tables
with canonical long-code fallback, and bulk overlapping match copies. The whole
output is already retained by the API, so it also supplies bounded history; E8
translation is deferred until decoding finishes, with Go's optimized byte search
locating candidate fixups. No second window is allocated.
Unconsumed prefetched words are returned before raw-byte reads, and EOF padding
never counts as valid Huffman bits.

Tests cover canonical trees through 16 bits, randomized trees and bit boundaries,
truncation, raw-byte alignment, overlapping/initial-zero/wrapped history, and
cross-frame E8 references. A bounded fuzz check can be run with:

```sh
go test ./compression/lzx -fuzz FuzzDecompress -fuzztime=30s -parallel=2
```
