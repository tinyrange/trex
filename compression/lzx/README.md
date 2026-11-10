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
`DecompressTo` is the bounded-output CAB variant. It writes synchronously to an
`io.Writer`, retaining raw match history across blocks and copying complete
32-KiB frames before restoring E8 addresses. History is trimmed only at frame
boundaries; its working set is bounded by the window and the format's 24-bit
block size, not the folder's expanded size. The compressed input remains owned
by the caller. A failed decode or writer can leave a prefix in the destination;
consumers must not publish partial output. WIM decoding is unchanged.

`BenchmarkLZXStreamMemory` compares full-output and streaming allocation for a
64-MiB generated folder. `FuzzDecompressTo` compares successful output and error
acceptance with the full decoder; targeted tests cover cross-window matches,
E8 operands, partial frames, and short/failing writers.

`DecompressReaderTo` also bounds compressed input buffering, reading from a
stable `io.ReaderAt` with a declared compressed length. Ordinary input buffering
is 64 KiB; an uncompressed format block may require its 24-bit size. Refills
preserve prefetched words, including raw-byte rewinds across buffer boundaries.

`NewIndexedReader` performs one complete decode, saving compressed raw-history
checkpoints at block boundaries and SHA-256 hashes of the initial raw frames.
Random reads resume at a nearby checkpoint, verify reconstructed frames, and
apply the original absolute E8 transform without modifying match history.
Checkpoint spacing must be at least the window size and can be exceeded by one
format block. No full compressed/expanded folder is retained. The source must
remain stable; frame hashes protect deferred content identity, not authenticity.
Reads and scratch-cache release are synchronized. `ReleaseReadCache` preserves
checkpoints; `RetainedBytes` reports checkpoint/history/hash storage, excluding
source, temporary decoder buffers and allocator overhead. `ReadCacheReserve`
provides a working-set allowance based on observed block sizes for bounded cache
owners. Random seeks reuse decoder/input/history scratch after warm-up;
`BenchmarkLZXIndexedRandomSeek` exercises far-apart seeks with byte validation.

`FuzzLZXIndexed` compares error acceptance and random reads against the original
full decoder. Targeted tests cover checkpoint/frame boundaries, E8 match history,
odd raw-block padding, concurrent reads/release and changed deferred source bytes.

Unconsumed prefetched words are returned before raw-byte reads, and EOF padding
never counts as valid Huffman bits.

Tests cover canonical trees through 16 bits, randomized trees and bit boundaries,
truncation, raw-byte alignment, overlapping/initial-zero/wrapped history, and
cross-frame E8 references. A bounded fuzz check can be run with:

```sh
go test ./compression/lzx -fuzz FuzzDecompress -fuzztime=30s -parallel=2
```
