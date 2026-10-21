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

Clone requests full history for advertised refs, with no shallow/filter/thin-pack
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
