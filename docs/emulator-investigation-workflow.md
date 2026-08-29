# Emulator investigation workflow

Long-running target investigations are expensive when every observation starts
from image construction or process initialization. This workflow keeps those
costs bounded and makes each completed experiment independently reviewable.

## Why this workflow exists

An audit of one multi-day emulator investigation found that its common
initialization prefix was repeated more than a dozen times. Individual runs
took roughly 25 to 30 minutes, several interactive sessions remained alive for
many hours, and overlapping probe scripts accumulated faster than confirmed
facts were recorded. The investigation eventually isolated a useful target
decision, but repeated setup and ambiguous experiment boundaries dominated its
elapsed time.

The corrective principle is simple: build expensive state once, ask one
bounded question at a time, and record the answer before changing the probe.

## Define an experiment before running it

Every run should have a short ledger entry containing:

- a stable identifier;
- one hypothesis;
- the exact observation that distinguishes it from alternatives;
- the cheapest starting checkpoint that contains all prerequisites;
- time, instruction, trace-entry, memory, and output limits;
- the expected success and failure outcomes; and
- a stop condition.

Do not start a full-system run merely to gather more trace data. First identify
the smallest address range, event class, file, registry value, or call boundary
that can answer the hypothesis. A run that cannot distinguish two competing
explanations should be redesigned before execution.

## Checkpoint the common prefix

Use `machine.checkpoint()` immediately after the last shared initialization
step and before installing experiment-specific watches or mutations. Restore
that checkpoint for each variant. Use `machine.snapshot()` only when two
independent machines must be retained simultaneously.

Checkpoints are machine-local and include CPU, mapped memory, executions, and
mutable state exposed by installed plugins. Mutable state hidden only in a
Starlark callback closure is not independently cloned; plugins that participate
in repeatable experiments should expose that state through `emulator.plugin`.

Prefer a hierarchy of checkpoints when initialization has several expensive
stages:

1. parsed media and constructed filesystem;
2. loaded target process and installed generic plugins;
3. initialized service or protocol state;
4. the narrow decision boundary under investigation.

Record the code revision and deterministic inputs associated with a persisted
or long-lived checkpoint. Never reuse it after changing code that contributes
to the captured state.

## Use bounded canonical probes

Keep one canonical probe per question class. Parameterize module names,
addresses, event filters, and capture fields instead of copying a script for
each new hypothesis. Small helpers such as bounded relative-call lookup and
module code watches belong in reusable scripts; target-specific addresses and
interpretation remain in the target investigation.

Collect the minimum useful evidence:

- stop after the first relevant failure unless frequency is the question;
- watch the narrowest executable or memory range possible;
- cap entries and captured bytes;
- capture caller identity and input values before collecting broad traces; and
- summarize target results as structured values rather than retaining verbose
  event streams by default.

Escalate in this order: existing structured events, bounded memory or code
watches, call-site analysis, a narrow native comparison, then a full trace.

## Bound process lifetime and resources

Run expensive development probes in a named resource-controlled scope. Set
explicit memory and swap ceilings appropriate to the workload. Record the unit
name in the ledger and stop that exact unit when the experiment completes or is
abandoned.

At the end of every investigation turn:

1. list relevant scopes and emulator processes;
2. stop obsolete interactive sessions;
3. record peak memory, runtime, and result;
4. verify that no target process remains unintentionally alive; and
5. preserve only checkpoints that have a named future consumer.

An idle REPL can retain substantial memory and stale assumptions even when it
uses little CPU. Process cleanup is therefore part of experiment completion,
not optional housekeeping.

## Keep evidence and implementation separate

The investigation ledger should distinguish:

- observed target facts;
- inferences supported by those facts;
- rejected hypotheses;
- emulator capabilities added during the investigation; and
- target-specific behavior that remains incomplete.

Commit reusable capabilities as soon as their APIs and focused tests are
stable. Keep speculative target policy and captured probes in a separate
stacked branch. Update the ledger at the same time as the experiment that
changes its conclusion; do not rely on chat history or terminal output as the
only record.

Before publishing a reusable commit:

- run focused tests for the changed abstraction;
- regenerate checked-in Starlark documentation;
- run the complete test suite under the normal resource ceiling;
- remove target-specific fixtures and constants from the generic layer; and
- state any snapshot, portability, or fidelity limitations in the API docs.

## Stop conditions

Stop and reassess when any of the following occurs:

- two complete runs produce the same semantic result without eliminating a
  different hypothesis;
- a new probe requires replaying an expensive common prefix that could be
  checkpointed;
- the experiment needs a second copied script instead of a parameter;
- output reaches its bound before the distinguishing event;
- a process exceeds its resource budget; or
- the current result cannot be stated as a falsifiable ledger entry.

At that point, improve the harness or checkpoint boundary before spending
another full run.
