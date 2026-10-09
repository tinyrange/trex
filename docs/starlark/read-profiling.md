# Measuring lazy file reads

`clock.read_profiler(max_files=16384, max_events=1024, min_seconds=0.01)`
measures completed native `ReadAt` calls without copying or eagerly reading
source data. It uses the runtime's monotonic clock. It invokes no Starlark
callbacks on I/O workers and holds no profiler lock while reading a source.

```python
p = clock.read_profiler()
source = p.file(original_file, "installed/path:data")
# Supply source to an image builder, decoder or another file consumer.
# Wrapping the same source at multiple layers can isolate where time is spent.
print(p.snapshot(limit=20))
```

`file(source, label)` borrows a file (or wraps bytes/string) as a read-only file
with the same size and bytes. Native read offsets, partial results and errors
are preserved. Sources must remain valid for the entire image lifetime.
Labels are caller-provided, nonempty strings of at most 4096 bytes; hardlink
reads are attributed to the canonical content source that the builder uses.

`snapshot(limit=100)` returns detached JSON-encodable dictionaries:

- `files`: labels ranked by cumulative latency, with calls, requested/returned
  bytes, non-EOF errors, cumulative seconds and maximum call seconds;
- `slowest_reads`: at most `max_events` calls meeting `min_seconds`, retaining
  the slowest calls and listing them by start time, with label, offset, sizes,
  relative start time, duration and error (sampled error text is truncated to
  4096 bytes; the caller still receives the original error);
- `total`, `elapsed_seconds`, `tracked_files`, `unattributed_calls`,
  `slow_reads` and `omitted_slow_reads` make coverage and sampling explicit.

`max_files` bounds labels with observed reads (1..1000000); once full, new
labels contribute to totals and slow-read samples but not per-label aggregates.
`max_events` is 0..65536; zero disables samples. `limit=0` includes all tracked
labels. Only completed calls appear. Threshold seconds must be a finite float
in 0..86400. The profiler does not cancel, retry or speed up a source read.

`reset()` starts a new phase on all existing wrappers, clearing samples and
aggregates. Calls already in flight are excluded when they complete. For boot
investigations, save construction measurements and reset before starting the
VM so archive indexing does not obscure guest-triggered reads.

**Durations are inclusive.** A disk read can include an installed-file read,
which includes a cached-payload read, which includes decoding and compressed
source reads. Do not sum these nested labels as exclusive CPU time. Cumulative
latency can exceed wall time when reads overlap. Compare layer totals and
aligned individual-call times/offsets to choose a narrower experiment.
