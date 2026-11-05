# Native kernel ETL reader

No external parser, Windows API, GPL or AGPL code is used. The Go reader is a new
implementation. Format references used for implementation:

* Microsoft PerfView (MIT), `src/TraceEvent/TraceEventNativeMethods.cs` and
  `Parsers/KernelTraceEventParser.cs`: TRACE_LOGFILE_HEADER and kernel payloads.
* Airbus CERT etl-parser (Apache-2.0), `etl/wmi.py`, `system.py`, `trace.py`,
  `parsers/kernel/header.py`, `wintrace.py`, `event.py`: on-disk buffer and record structure definitions.
* Microsoft Windows SDK `um/evntcons.h`: EVENT_HEADER flags, extended-item types,
  and 32/64-bit stack trace data (MatchId followed by addresses).
* Microsoft Windows SDK `shared/evntrace.h`: ordered TRACE_MESSAGE flag fields
  and provider pointer-size flags for WPP TraceMessage records (marker 0x9000).

The applicable reference licenses are included alongside this document. No
Python/C# implementation or runtime dependency is imported. Earlier investigation
consulted another parser; that implementation was not used to implement this reader.

Scope: finalized sequential, uncompressed ETL, 32/64-bit kernel system, compact,
and perfinfo framing, classic, manifest and WPP TraceMessage framing. Default
log-file mode zero and explicit sequential mode one are accepted. WPP optional
sequence/GUID/component-ID/timestamp/system fields are bounded before access;
obsolete performance-timestamp and unknown flags are rejected. Raw event IDs,
GUID bytes and message flags are exposed; WPP payload schemas are not inferred. Unsupported record framing,
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

The first observed event and last activity event bound CPU capacity.
Kernel EventTrace (group 0) and SysConfig (group 11) records are session/static
configuration metadata and do not extend the activity endpoint during logger
finalization. Raw `first_tick`/`last_tick` still include every record;
`capacity_last_tick` and `metadata_trailer_seconds` expose the distinction.
`observed_seconds`, timelines and uncovered CPU use that activity endpoint.
Unsupported activity in any other group still extends capacity, even when its
payload is not decoded: this is not a trim to the last observed switch. No CPU is inferred before the
first or after the last observed switch on a processor. A mismatched old thread
invalidates the span. Unknown thread ownership remains separate from idle.
Only complete switch-out-to-ready and ready-to-switch-in pairs are counted as
blocked/ready time, with thread lifetimes reset on start/exit. Wait reasons use
the kernel's numeric enumeration. Neither totals nor wait reasons establish a
causal chain or distinguish host vCPU descheduling from guest execution.
QPC durations are converted after integer subtraction to avoid FILETIME-sized
floating-point cancellation. Disk response durations always use QPC frequency,
even when event timestamps use FILETIME. No symbol queries/downloads are made.

## Modern event extensions

For modern EVENT_HEADER records, flag bit 0 marks inline extended data after
its 80-byte header. Each serialized item has an eight-byte header (type at
+2, linkage at +4, data length at +6), followed by data and eight-byte alignment.
This is not the SDK's in-memory descriptor containing a DataPtr. Linkage bit 0
continues the chain; bounds, alignment and a maximum of 128 items are enforced.
Padding bytes are not required to be zero. Unknown types retain opaque bytes;
they are not misidentified as user payload. Stack types 5 and 6 contain a
64-bit MatchId followed by 32-bit or 64-bit address values respectively. Their
lengths are validated. Header flags and the 16-byte activity GUID are exposed
without inferring activity relationships. User payload begins after the chain.

Stacks alone do not identify images or establish error values. Address mapping
requires native image epochs for the same process lifetime, compatible trace
clocks and boot identity, and matching PE/PDB identities. Return addresses may
need call-site attribution; unknown or ambiguous frames must remain explicit.

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
an earlier lifetime. The profile also exposes timestamp-sorted `image_events`
with tick, PID, opcode, base and original module identity for explicit cross-trace
correlation. All observed load, unload and rundown events are retained, even
without IP samples; callers must respect PID and address reuse. Unmapped/ambiguous addresses and unknown threads stay
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
