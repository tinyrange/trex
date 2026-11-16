# SCS Git project workspaces

SCS is integrated as ordinary packages in trex's module, not a second CLI or
submodule. Git history is decoded natively into a content-addressed repository;
projects operate on virtual trees and portable file readers without extraction,
a host checkout, mounting, or an external compiler.

## Clone, edit, build and publish

The native CLI exposes `scs.create(path)`, `scs.open(path)` and
`scs.memory(file=None, max_bytes=512 * 1024 * 1024)`. A native repository path is
an explicit final output. Creation is exclusive and never overwrites an existing
file; the native backend locks the repository for its ownership lifetime.

```python
def main(args):
    if len(args) != 2:
        error("usage: project.star remote-url final-repository.scs")
    repository = scs.create(args[1])
    repository.clone(args[0], catalog = "upstream",
                     max_pack_bytes = 256 * 1024 * 1024)
    source = repository.checkout_git("HEAD", catalog = "upstream")
    source.publish("imported")
    project = source.fork()

    # Example for a repository containing this small C source.
    project.write_file("main.c", "int main(void) { return 0; }\n")
    result = renvo.cc(source = project, input = "main.c",
                      target = "windows/386")
    if not result.ok:
        error(result.diagnostic)
    project.write_file("app.exe", result.binary)
    project.publish("built")
    repository.close()

    reopened = scs.open(args[1])
    print(reopened.checkout("built").open_file("app.exe").bytes(0, 2))
    reopened.close()
```

`renvo.go`, `renvo.cc` and `renvo.make` accept SCS workspaces directly. They
capture a stable tree, read the files requested by the in-process compiler, and
keep outputs in an isolated build overlay. They do not modify the input tree;
install desired outputs explicitly with `write_file`. Compiler support and
Make recipe restrictions are described in [the Renvo guide](renvo.md).

For a portable in-memory repository, obtain an independently useful repository
file with `repository.file()` after publication, then reopen it with
`scs.memory(file, max_bytes=...)`. Memory snapshots share immutable pages and
survive closing their original repository. `file()` checkpoints stored records,
but **does not publish live workspace edits**. Native storage already is the
final file: close it and use `scs.open` instead of `repository.file()`.

## Files and stable tree views

```python
original = project.open_file("main.c")
view = project.view()
# Lazy composition borrows original ranges; no payload read until consumed.
patched = original.splice(offset = 0, remove = 0, value = "/* experiment */\n")
project.write_file("main.c", patched)
project.write_file("unchanged-copy.c", original)
```

* `open_file` returns an immutable version implementing trex's `storage.Reader`
  and the usual Starlark file API (`read`, `bytes`, `slice`, `splice`, `size`).
  Workspace edits do not change existing handles. Its repository must stay open.
* A same-repository `write_file` of a whole SCS reader reuses its content
  descriptor without reading or rewriting payloads. Arbitrary readers, slices
  and composites are streamed through native ingestion/deduplication. Composition
  itself is lazy; ingestion is not claimed to be zero-copy for edited ranges.
* `view()` captures an independent read-only live root without publication or a
  sync barrier. `readonly()` instead follows mutations of its source workspace.
  Neither grants mutation/publication authority.
* `fork()` creates an independently writable workspace from a synced snapshot,
  sharing immutable nodes and stored content. Its first call on an unconverted
  Git checkout serializes all tree metadata; it is not a constant-time initial
  Git conversion. Later unchanged snapshots/forks reuse stored identity.
* `read_file`, search and recursive enumeration are convenience operations that
  may read whole payloads or enumerate the tree. Use file readers and path
  lookup when demand-driven access matters.
* Paths are UTF-8, slash-separated, relative to the project root. Absolute paths,
  parent traversal, backslashes and NUL are rejected. Symlinks and gitlinks are
  retained as entries, not implicitly followed or cloned. Git names that cannot
  be represented remain in the stored Git graph, but fail workspace access or
  first publication when reached.

## Go API and ownership

* `scs/repo` owns the repository engine. `Create`, `CreateOptimized`, `Open` and
  `OpenVerified` accept a `storage.Store` and take ownership, including on failure.
  Store provides random reads/writes, length, truncate, sync and close. It is not
  an immutable Reader. A caller-supplied backend controls durability guarantees.
* `storage.MemoryStore` is sparse, paged, quota-bounded and volatile. Its Snapshot
  produces an immutable Reader with copy-on-write pages; Sync is not durability
  beyond process lifetime. Native opening/locking lives in `storage/native` and
  `scs/native`, not the core.
* `filesystem.TreeSource.SnapshotTree()` yields a stable `filesystem.Tree` with
  `Lookup`, `ReadDir` and `OpenFile`. SCS captures the root without flattening the
  tree. A Directory adapter retains the older Directory snapshot behavior.
* `Workspace.WriteReader` accepts portable readers. `storage.Compose` borrows
  immutable Reader ranges; callers must keep those sources alive and stable.
  `storage/star.NewReader` exposes an immutable reader to Starlark without a
  payload copy. Generic Reader interfaces do not guarantee immutable backends.
* `scs/git.Clone` takes an injected `transport.Transport` through Options.
  `scs/native.GitTransport` selects Go HTTP(S), Git or SSH networking only. Local
  filesystem/command Git transports are rejected. Go callers may provide Auth
  and their own transport; the Starlark API has no separate credential option.
* The runtime lifecycle owns repositories until explicit close or script cleanup.
  Workspace/file values borrow that ownership; they do not reopen a closed repo.

## Performance and bounds

Checkout parses the commit/tag and leaves the root as a Git-tree placeholder.
Lookup materializes only directories and blob descriptors along accessed paths;
listing a directory does not materialize each child. First native publication
traverses and validates all metadata; subsequent edits path-copy persistent tree
and index nodes. Unchanged file handles share verified decoded body cache bytes.
Public byte-returning reads still copy so callers cannot mutate that cache.
A small read of a compressed body can still decode the **entire body**.

Clone requests complete history for all advertised refs by default. `refs` can
select exact advertised names (or `HEAD`); there is no shallow/filter/thin-pack
mode, and retains the complete verified wire pack in bounded paged memory before
native decoding. The default transport limit is **256 MiB**; callers can choose
another `max_pack_bytes`. The default native-storage limit is **512 GiB** and
`scs.memory` additionally enforces its own store limit. These are byte/storage
limits, **not total RAM, CPU, object-count or wall-time guarantees**. Decoders,
indexes, concurrent work and caches consume additional memory. Large Linux-history
clone measurements from the standalone source are not benchmarks of this new
memory-backed transport pipeline. Native backend durability was tested on Linux;
other platforms do not inherit a durability certification from these tests.

## Publication and recovery

The SCSREPO2 and SCSREPO3 formats, content identities, sync barriers and named-root
compare-and-swap rules are retained. New memory repositories use optimized V3.
There is no automatic publication on successful script completion or close.
A named checkout may update its own name if its base still matches; other target
names must be new. Git catalog names are also create-only.

A storage write/sync failure poisons the handle; close and reopen to inspect
recovery rather than blindly retrying. Failed sync can leave a complete new root
physically visible even though publication returned an error. Only incomplete
tails are repaired; complete corrupt records are not silently discarded.
Unpublished/orphaned objects may remain in the append-only file. There is no
secure deletion, garbage collection or compaction. Keep independent backups.
The format remains experimental: no new long-term compatibility or migration
promise is made by this integration.

## Scope and provenance

The repository, native Git ingestion and workspace Starlark code were adapted
from `tinyrange/scs` (`j5.nz/scs`) at
`b4ddba5e0f388def4163d8e44860b95153af8c43`. Existing tests
cover publication conflicts, torn tails, corrupt records, short writes and sync
failures. New bounded regressions cover lazy Git traversal, COW snapshots,
immutable body sharing, and a tiny HTTP clone/edit/C-build/publish/reopen workflow.
Host Git is used only as a test oracle/fixture server, not by production decoding.

The source checkout and its history remain untouched. This is a source-copy
integration, not a Git-history import. The repository owner confirmed ownership
and authorized Apache-2.0 licensing for this incorporation; the licence is
retained in `scs/LICENSE`. FUSE/cah, host local-Git import, the standalone
CLI, machine configuration and conversation/build logs are not incorporated.
Git push, fetch/merge workflows, host compiler execution and sandboxing are not
part of this milestone.

## API-first queries and native revision provenance

A native revision is a snapshot with optional parent IDs, author, message and
task metadata. Plain `snapshot()` identities and the existing tree encoding
remain unchanged when those fields are absent. Parents are **native SCS IDs**,
not Git commit IDs. Creating a revision does not promote a name, approve a
review, or record a successful build. Callers explicitly attach provenance;
textual metadata must be valid UTF-8 rather than being silently normalized.

```python
repository = scs.memory()
before = repository.empty()
before.mkdir("src")
before.write_file("src/main.c", "int main(void) { return 1; }\n")
base = before.revision(author="agent", message="initial", task="example")
repository.promote("main", expected="", next=base)

candidate = repository.checkout_revision(base)
candidate.write_file("src/main.c", "int main(void) { return 0; }\n")
revision = candidate.revision(parents=[base], message="return success")
print(repository.is_ancestor(base, revision))  # True
print(repository.merge_bases(base, revision))  # [base]
changes = before.diff(candidate, prefix="src", max_changes=100)
affected = before.affected_targets(candidate, {"compile": ["src/**"]})

# Exact immutable revision selected by a review/build service, not live edits.
repository.promote("main", expected=base, next=revision)
metadata = repository.revision(revision)
history = repository.path_history(revision, "src/main.c", limit=10)
lines = repository.blame(revision, "src/main.c")
repository.close()
```

* `checkout_revision(id)` opens an independently writable native snapshot by ID,
  without a named checkout or an initial snapshot/sync operation.
* `promote(name, expected, next)` is an explicit compare-and-swap. Empty expected
  is create-only; empty next removes an existing name. `drop(name, expected)` is
  a deletion-only equivalent. Authorization and approval remain the responsibility
  of the embedding service; these native APIs do not bypass Server SCS approvals.
* Native `is_ancestor` and `merge_bases` are distinct from `git_is_ancestor` and
  `git_merge_bases`. Git queries accept imported commit IDs, not native IDs.
  Both merge-base APIs return **all** best common ancestors, sorted by ID,
  including multiple bases for criss-cross merges. They do not perform a merge.
* Graph queries accept `max_visited` (default 100,000). Work exhaustion is an
  error, not an approximate ancestry answer. The native revision-summary index
  is bounded to 4,096 entries, process-local, versioned independently of stored
  snapshots, and discardable through `clear_derived_indexes()`.
* `path_history(start, path, limit=1000, max_visited=100000)` follows first parents.
  It compares path metadata/identities, including directory identities, without
  enumerating directory contents. The returned `next` is the **next unexamined
  revision**, to pass as the next start. An empty next ends the walk.
* `blame` and `git_blame` provide deterministic **first-parent**, exact-line LCS
  attribution. They do not implement copy/rename detection, whitespace ignoring,
  or full multi-parent Git blame semantics. Results include target line, source
  line, revision ID and text. Defaults bound visited revisions to 10,000, one
  file version to 1 MiB, cumulative file reads to 8 MiB, and LCS work to 8 million
  cells. `max_cells` cannot exceed 64 million. Exceeding a limit fails the query;
  large blame workloads should use a more specialized derived index later.
* `affected_targets(other, targets, ...)` applies explicit caller-supplied
  path-glob policies to a bounded diff. It is **not dependency discovery**, and
  omitting transitive/configuration inputs from the policy can miss affected
  targets. `prefix` scopes the answer to that subtree. `max_matches` separately
  bounds pattern comparisons (default 100,000).

## Targeted traversal and bounded reviews

`glob()` now traverses only directories whose paths can satisfy its segment
pattern. Whole-segment `**` supports zero or more directories; symlinks and
gitlinks remain entries and are never followed. Search glob selection occurs
before file stat/content reads, against one immutable captured view.
The Go `GlobContext` API and Starlark glob/search operations retain caller
cancellation during traversal. Two-workspace queries observe both contexts.

```python
view = candidate.view()  # retain this same view for every page
first = view.glob_page("src/**", limit=100, max_visited=100000)
# If first.next is nonempty:
second = view.glob_page("src/**", after=first.next, limit=100)
```

`glob_page` returns `paths`, `next`, and `visited`. Paths have full lexical order
(not directory-DFS order). `after` is an exclusive path cursor, not a revision ID;
using a different or live-mutating tree between pages is not a consistent scan.
Limit is 1..10,000. The independent work limit counts examined candidates,
including nonmatching children. Exhaustion is an error, never partial success.
Directory metadata/index loading and frontier construction can still cost the
size of an accessed directory. Pagination is not a constant-time random seek.
The compatibility `glob()` remains a complete, unbounded result API.

`before.diff(after, prefix=".", max_changes=1000, max_visited=100000)` captures
immutable input roots and skips paths outside the slash-delimited prefix before
reading their descriptors/payloads. Exhaustion returns an error. It is bounded,
**not paginated**. Changed file SHA-256 calculation can still read full payloads,
and body/delta decoding has its existing memory costs. Neither a narrow query
nor a pruned diff is an integrity scrub; use `OpenVerified`/`Scrub` for that.

## Opt-in persistent ref catalogs

`repository.enable_indexed_refs()` explicitly migrates named native roots to a
persistent radix index. Migration/open/enumeration are O(number of refs); each
subsequent promotion copies only the affected bounded leaf and index ancestors.
Fast manifests carry the index root instead of serializing the complete refs
map on every sync. Full physical recovery replays verified canonical index-page
transitions, rather than rebuilding every historical catalog.

**Compatibility:** the indexed catalog and version-2 fast-manifest extension
require this newer reader. Older builds reject them. The migration is opt-in,
with no automatic downgrade; keep backups before enabling it. Repositories not
migrated retain the existing flat catalog representation. This remains an
experimental format, not a new compatibility or durability certification.

Writes/sync failures still poison the handle. In-memory promotion occurs only
after a successful barrier; a complete new root can nevertheless be physically
visible following an unsuccessful sync. Close/reopen and reconcile rather than
replaying uncertain operations. The new mode is covered by torn-write, short
 writer, disk-full, sync-failure and concurrent compare-and-swap regressions.

## Selected-ref ingestion

```python
report = repository.clone(remote, refs=["refs/heads/main"], catalog="upstream")
```

Only selected refs and their peeled/symbolic metadata are published. Complete
history reachable from each requested tip is still transferred and verified;
this does not provide path-filtered or shallow Git clones. Unknown selections
fail before a catalog is published. `HEAD` selection uses the advertised tip;
a single selected ref also supplies the checkout default. The complete pack
still uses bounded paged-memory staging and the existing ingestion pipeline.

## Portable on-demand immutable object retrieval

`scs/objects` provides an injected `Source.Fetch(ctx, id)` interface, a verified
shared cache, and lazy portable readers. There is no ambient network backend,
service deployment, credential acquisition, or host-file staging.

* IDs are hex SHA-256 of `kind || logical payload`. All bytes are verified before
  becoming readable. The cache owns its payload copy; mutable source buffers
  cannot alter an already verified object. Zero-length manifests are checked
  locally; incomplete/no-progress source reads fail instead of stalling a fetch.
* `NewCache(source, Limits{CacheBytes, ObjectBytes, Entries})` bounds retained
  payloads, object size (at most 1 GiB), retained entries and concurrent fetches.
  In-flight requests for an ID share a fetch; failures are not cached. The owner
  context governs the source request; cancelling a waiter does not cancel it.
* A cache itself implements Source, so local/regional/authoritative tiers can
  share this interface. Topology, source authority, failure isolation and network
  protocol/versioning are embedding-service responsibilities.
* `Reader(ctx, id, kind, size)` does not fetch until a nonempty in-range read.
  Whole-object verification still fetches that entire object. `ChunkedReader`
  consumes a caller-authenticated manifest and fetches only requested chunks,
  verifying each one. This is an object/reader foundation, **not automatic sparse
  hydration of an arbitrary SCSREPO file or partial Git graph**.
* Readers implement `storage.Reader` and can feed SCS `WriteReader`, portable
  build consumers, or a Starlark file wrapper directly. Fetching an input does
  not imply publishing a workspace edit.
* Cache limits are not a total-RAM promise: returned readers, concurrent fetches,
  manifests and caller-owned data also retain memory. Sources must respect
  cancellation and their own resource/network policies.

## Scaling instrumentation and regression tests

`repository.operation_stats()` exposes cumulative engine counters for appended
records/bytes, requested stored object payload reads/bytes, whole reconstructed
body decodes/bytes, body-cache hits, and derived-index hits/misses. These are not
complete device-I/O, peak-RAM or elapsed-time measurements. Index/run/footer I/O
is not included in the logical appended-record counters.

Regressions exercise one-file edits and one-ref promotions at 100 and 10,000
entries, unchanged-tree sharing, narrow traversal over deferred invalid Git
subtrees, whole-body decompression on small reads, multiple merge bases, query
budgets/cancellation, native/Git first-parent blame, cache identity/ownership,
chunk-only reads, tier reuse, and concurrent publication/fetching. Existing
storage-recovery and Git-oracle tests continue to apply. Distributed storage,
service IAM, a review UI, garbage collection and cache-fleet deployment remain
separate work rather than implicit features of these portable packages.

### Validation of this implementation

Validated with Go 1.25.5 on Linux/amd64:

* `go test ./scs/... ./filesystem/... ./storage/... ./renvostar -count=1`
* `go vet ./scs/...`
* `go test -race ./scs/... -count=1`
* `FuzzGlobStateMatchesOracle`: 91,282 executions in the completed 5-second run.

Observed logical append counters in the bounded scaling fixtures:

| Operation | 100 entries | 10,000 entries |
| --- | --- | --- |
| One indexed-ref promotion | 3 records / 1,303 bytes | 5 records / 2,054 bytes |
| One file edit and snapshot | 8 records / 1,537 bytes | 10 records / 2,606 bytes |

These are fixture measurements, not general throughput or total physical-I/O
claims. Counters omit persistent run/manifest/footer I/O. Indexed-ref recovery
is also exercised on legacy SCSREPO2, optimized SCSREPO3, normal open and
verified physical scanning, together with the storage fault-injection suite.
