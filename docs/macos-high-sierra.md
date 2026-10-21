# High Sierra 10.13.6: native installed desktop

## Verified scope

The exact fresh-image private `high_sierra_cached_smoke` for catalog product
`041-91758`, macOS 10.13.6 build `17G66`, reaches an unattended rendered Finder
desktop and verifies the original Calculator displaying **2+2=4**. The validated
run reported no storage errors and clean VM shutdown. This is one complete
scripted run, not a broad reliability guarantee or full Apple installer equivalence.

Construction uses native XAR, UDIF, HFS+, BOM, PBZX, XZ, CPIO and AppleDouble
readers and a native HFSX builder. No host extraction, mounting, conversion,
guest instruction patch, replacement bootloader or signature bypass is used.
Installed boot requires an explicitly caller-supplied SMC key; no key is included.
The disposable demo account and no-network profile are not production defaults.

## Original sources and image construction

Acquire **every original compressed package before construction or boot**.
`cache_packages` in `@stdlib//macos:softwareupdate.star` uses the native persistent
mirror cache and returns complete local source files. The private cached smoke
performs this acquisition barrier, then invokes the borrowed-file smoke.
It does not eagerly extract payloads or materialize the guest disk.

The validated product has 11 packages. Its `BaseSystem.dmg` is 486,278,934 bytes;
`InstallESDDmg.pkg` is 4,722,014,048 bytes and contains a 4,721,938,282-byte
`InstallESD.dmg`. Both inspected disk images contain HFS+ volumes. Catalog sizes
are checked, but catalog Digest is an opaque cache-identity component, not an
authenticated Apple signature or a claim of cryptographic package verification.

Core's PBZX/XZ payload expands to an 11,379,286,016-byte odc CPIO stream with
423,209 entries. Core, EmbeddedOSFirmware and SecureBoot provide 423,263 payload
rows. FirmwareUpdate and OSInstall have no Payload and are not passed to the
payload assembler. Their scripts are not executed. The resulting 24 GiB HFSX
image retains original system files, forks, xattrs and hardlinks, with explicit
local-account and setup provisioning. Core and recovery prelinkedkernels had
equal observed SHA-256:
`6f688881a1100528e6aa04a804c164a962b7fec117883e78cde53398923d1968`.

## Machine prerequisites

* **CPUID:** XNU 4570 queries architectural PMU leaf `0xa`. Advertising maximum
  basic leaf 4 could make an out-of-range query return cache geometry, producing
  phantom counters and a WRMSR fault. The Penryn profile enumerates through
  `0xa` and explicitly returns zero for leaves 5 through `0xa`; no unsupported
  PMU is advertised. Earlier features remain accelerator-intersected.
* **RAM:** the x86_64 BIOS/direct-Darwin board supports 8 GiB. The first 3 GiB
  is below PCI MMIO, and remaining RAM starts above 4 GiB. Physical inspection,
  DMA, EFI and E820 agree on this mapping and reject the PCI hole as RAM.
  The i386 limit is 3 GiB; the UEFI profile retains its 2 GiB limit.
* **ATA:** SLEEP (`0xe6`) flushes when supported, completes with an IRQ, and
  accepts no further commands until reset. Bus-master reads perform storage
  I/O on a worker; only the CPU loop publishes guest memory, task-file and IRQ
  changes. Reset, pause and shutdown join outstanding reads. Readiness is
  published before waking the CPU, and the wake is joined before CPU teardown.
* **Inspection:** read-only virtual reads and disassembly accept an explicit
  observed page-table root. The smoke uses the original kernel pmap for KPTI
  observations; it does not modify CR3 or guess a fallback mapping.
* **Writes:** High Sierra uses a 2 GiB write overlay with 4 KiB chunks. The
  earlier 1 GiB cap was exhausted by swap writes and produced explicit EIO.

Native regressions cover CPUID, high-RAM KVM writes and translated reads,
firmware maps, PCI-hole rejection, ATA sleep/reset/flush failures, asynchronous
DMA ownership, short/error reads, wake ordering and inspection-root selection.

## Read-path policy

The smoke retains these cache reservations:

| Cache | Budget | Granularity |
| --- | ---: | --- |
| PBZX verified S2 replay | 1,984 MiB | indexed 64 KiB blocks, original-chunk eviction |
| Disk read cache | 64 MiB | 4 KiB |
| Outer decoded Core cache | 512 MiB | 64 KiB |
| PBZX internal decoded cache | 64 MiB | requested 64 KiB pages |

Replay memory is subtracted from the former 2 GiB disk read cache, rather than
added to the retained budget. `replay_cache_bytes=0` restores the former policy;
the public PBZX API remains opt-in. These are retained-cache budgets, not bounds
on all live memory: original XZ dictionaries, in-flight chunks and concurrent
borrowed results require additional transient storage.

Initial access verifies the complete original XZ chunk before admitting its
independent S2 blocks. Concurrent page misses share that decode. Pages have
exact-sized retained allocations, not small slices retaining a whole chunk.
Even a replay budget too small for admission does not repeat XZ per page within
one read. See [PBZX replay cache](starlark/pbzx-replay-cache.md) and
[read profiling](starlark/read-profiling.md) for API semantics and counters.

## Measurements and interpretation

A controlled replay used the same 2,314 sampled slow Core reads, requesting
8,294,742 bytes across 417 original chunks. Every returned digest matched.
These are sampled reads, not the full guest workload.

| Captured trace | Whole-chunk replay | 64 KiB replay |
| --- | ---: | ---: |
| Initially empty caches | 252.14 s | 223.43 s |
| Second pass | 224.49 s | 0.02146 s |
| PBZX returned bytes, first pass | 27,715,960,832 | 127,664,128 |

The warm difference is a working-set effect: useful pages fit in the same cache
budget. It must not be presented as an equivalent boot-speedup ratio.

The fresh lazy-image run reached desktop in **343.38 seconds**, versus
355.29 seconds for the whole-chunk replay control. The block-granular run then
completed the original Calculator smoke; the earlier control failed its app
launch check. No application/input/timing change was introduced by the
block-granular optimization. The smoke separately waits for the original zero
display before sending the expression once and verifies a changed four glyph.

Across boot plus the completed app check, Core demand was 1,359,842,741 bytes and
PBZX returned 1,818,296,320 bytes: about **1.34x amplification**. The earlier boot
plus failed app attempt returned 87,996,497,920 PBZX bytes, about 65x demand.
Those application workloads differ. These nested returned/copy/cache-fill
volumes are not additive, unique-byte counts or physical host-disk traffic.

At desktop, excluding construction, Core performed 669 original XZ decodes
(11,223,957,504 bytes) and 22,965 replay-block decodes (1,505,034,240 bytes).
**Cold XZ remains the principal limit.** Construction itself still required
577 XZ chunks and about 237 seconds in the decoder layer. A denser Zstandard
candidate reduced cold-trace time only from 223.43 to 218.92 seconds while making
replay slower; it was not retained.

## Boundaries

This validates the specific original payload/provisioned-image smoke, not
firmware updates, Apple's postinstall scripts, all hardware, or all macOS
versions. The inspected HFS+ installer layout does not establish APFS support.
Original XZ checksum validation is not Apple signature authentication.
Machine-specific keys, source packages, screenshots, profiles and investigation
notes remain local and are not part of this repository.
