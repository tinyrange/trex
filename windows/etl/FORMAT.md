# Native kernel ETL reader

No external parser, Windows API, GPL or AGPL code is used. The Go reader is a new
implementation. Format references used for implementation:

* Microsoft PerfView (MIT), `src/TraceEvent/TraceEventNativeMethods.cs` and
  `Parsers/KernelTraceEventParser.cs`: TRACE_LOGFILE_HEADER and kernel payloads.
* Airbus CERT etl-parser (Apache-2.0), `etl/wmi.py`, `system.py`, `trace.py`,
  `parsers/kernel/header.py`: on-disk buffer and record structure definitions.

The applicable reference licenses are included alongside this document. No
Python/C# implementation or runtime dependency is imported. Earlier investigation
consulted another parser; that implementation was not used to implement this reader.

Scope: finalized sequential, uncompressed ETL, 32/64-bit kernel system, compact,
and perfinfo framing, classic and manifest framing. Unsupported record framing,
clock modes, compression, malformed lengths and truncated logs fail explicitly.
Generic non-kernel payloads are counted, not guessed. Payload schema support is
version-gated. Buffer and event loss must be surfaced in every report.

Event order on disk is per-buffer, not global time order. Analysis sorts compact
records by timestamp before attribution. Context-switch spans measure scheduled
thread CPU time (including time interrupted by DPC/ISR), not sampled function CPU.
Unobserved boundaries, unknown TIDs and discontinuities are not assigned to a process.
Summed disk response times overlap and are not boot critical-path wall time.

Implemented payloads (classic kernel group IDs): process 3/start/end/rundown
versions 2–5; thread 5/start/end/rundown versions 1–4; context switch 5/36
versions 2–5; ready thread 5/50 version 2; disk read/write 1/10,11 versions 2–3;
PerfInfo DPC/ISR 15/50,66–69 version 2 (QPC event clock only). Other payloads,
outside those schemas, remain counted but are not attributed by Analyze. Non-kernel providers
are grouped as 255; the report does not decode arbitrary manifest providers.

The first/last observed events bound CPU capacity. No CPU is inferred before the
first or after the last observed switch on a processor. A mismatched old thread
invalidates the span. Unknown thread ownership remains separate from idle.
Only complete switch-out-to-ready and ready-to-switch-in pairs are counted as
blocked/ready time, with thread lifetimes reset on start/exit. Wait reasons use
the kernel's numeric enumeration. Neither totals nor wait reasons establish a
causal chain or distinguish host vCPU descheduling from guest execution.
QPC durations are converted after integer subtraction to avoid FILETIME-sized
floating-point cancellation. Disk response durations always use QPC frequency,
even when event timestamps use FILETIME. No symbol queries/downloads are made.

## Per-process phase attribution

Each process lifetime has a sparse, chronological `timeline` of one-second
buckets relative to the first observed event. `scheduled_cpu_seconds` splits
observed switch spans at second boundaries; `read_bytes` and `write_bytes` are
charged at disk completion, not spread over response time. Missing buckets
have zero attributed work, not proof of scheduler coverage or process idleness.
PID/TID reuse keeps separate lifetimes; discontinuous/unknown CPU remains in
the report's existing global accounting. Unknown disk ownership uses the same
unattributed process row as the totals. Analysis rejects more than 1,000,000
process buckets rather than allocating an unbounded dense process-by-time grid.
These buckets help locate bursts; they do not establish a causal critical path.

## Sampled IP profile

`ProfileTrace` separately decodes 64-bit PerfInfo 15/46 v2 samples and image
load 3/10, unload/rundown 20/2–4 v2–3. Samples correlate with timestamp-sorted
thread/process lifetimes and load/unload address ranges. Kernel images share
the high canonical address space. Image identity includes path, size, checksum
and PE timestamp (a build identity, not necessarily a civil date). PID/TID and
image-base reuse must not relabel earlier samples. End rundown never invents
an earlier lifetime. Unmapped/ambiguous addresses and unknown threads stay
explicit. DPC/ISR-marked samples are tagged, not silently blamed on the
interrupted thread. The event Count field is not a duration or weight; each
supported IP event contributes one sample. No assumed sampling frequency is
used to convert counts into seconds. These are self samples, not caller stacks.

The portable PE `symbolize` operation validates image identity and matching
RSDS GUID / DBI age, then accepts a public symbol only at an exact address or
within the same AMD64 runtime-function interval (including explicit chained ownership). Unnamed leaves and split
fragments remain unresolved rather than inheriting an unrelated prior name.
Symbol fetching/caching is explicit orchestration, never a side effect of ETL
parsing. Missing public PDBs do not justify mismatched-version substitutions.

## Per-process scheduler observations

`SchedulerTrace` / `windows.etl_scheduler` expose the existing decoded thread,
process, context-switch and ready events for bounded interval investigations.

Returns timestamp-sorted scheduler observations for one PID from a finalized
kernel ETL file. Records contain `seconds` relative to `first_tick`, `kind`,
`tid`, `peer_tid`, `peer_pid`, `cpu`, `state`, and `reason`. Kinds are
`process_start`, `process_end`, `thread_start`, `thread_rundown`, `thread_end`,
`in`, `out`, and `ready`. State/reason describe the outgoing thread on a
context switch; they do not describe the incoming thread on an `in` record.

Ownership follows observed thread lifetimes; process boundaries expose PID
reuse, and end rundown never invents an earlier lifetime. A ready record's
peer is the last observed running thread on that CPU, not a proven waker:
interrupts/DPCs may be responsible. Zero peer IDs mean idle or unknown.

Includes `header` loss counters, `first_tick`, `last_tick`,
`switch_discontinuities`, and `unsupported_thread_events`. Unsupported process
schemas are not counted by the latter; use `etl_report` for a schema inventory.
Losses and incomplete ownership prevent reliable interval/causal conclusions.
No wait durations or critical path are inferred. Input/event limits match
`etl_report`; `max_records` must be 1..1000000. Limits and malformed framing
fail rather than silently truncating. No symbols or network access is implicit.
