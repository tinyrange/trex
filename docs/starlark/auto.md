# Automatic file views

The `auto` Go package owns the format registry and the common `View` interface.
Each format package registers a detector in its own `auto.go`. Applications
choose which packages to link; the convenience import collects the built-ins:

```go
import (
    "github.com/tinyrange/trex/auto"
    _ "github.com/tinyrange/trex/auto/imports"
)

result, err := auto.Identify(source, auto.Options{}) // source is storage.Reader
// result.Format identifies the confirmed format; result.View.Entries() lists it.
root := auto.Open(source, "source.tar.gz", auto.Options{})
file, err := root.Resolve("etc/package.zip/readme.txt")
// file.Reader() retains a portable random-access view of the original bytes.
```

`Register(name, priority, detector)` installs a detector. The registry reads at
most 64 KiB once and passes that prefix, the original `storage.Reader`, and
options to each detector in priority/name order. Detectors return `ErrNoMatch`
for unrelated input, a confirmed `View` on success, or a diagnostic for malformed
recognized input. A detector can read beyond the prefix to validate structures.
Readers with expensive size discovery may expose `KnownSize() (int64, bool)`;
identification then reads the prefix without forcing a complete decode.
Extensions do not confirm formats. The core registry has no format imports,
Starlark types, host paths, or process dependencies.

A `View` exposes `Entries() ([]Entry, error)`. Each immediate child has a name,
kind, optional reader, optional directory view, and portable metadata. Existing
parser scripting values are bridged internally by `auto/adapter`; they do not
appear in this public interface. `DecodedView` represents a compression stream
or virtual disk. Node traversal transparently enters its decoded container, or
exposes a single decoded content file when the payload is an ordinary file.
An archive node's `Reader()` always returns its original archive bytes.

Built-in detectors cover ZIP, tar, gzip, bzip2, XZ, 7z, ar, CAB, CFB (including
MSI storage), WIM, SFP, SZDD, KWAJ, FAT, NTFS, ISO9660, UDF, MBR, GPT, and VHDX.
MZ executables are checked with the existing installer recognizers for embedded
CABs, InstallShield packages and SFX envelopes, and Wise overlays. Confirmed
installers expose their payload files and specific format, plus payload offset
and size metadata; their reader still returns the original EXE. Ordinary EXEs
remain readable files. Installer recognition may scan beyond the prefix, bounded
by the smaller of 256 MiB and `maximum`. Detection does not execute installers.
UDF takes precedence on bridge discs. Filesystems that use case-insensitive
lookup retain that behavior; case-sensitive archive members remain distinct.
Duplicate archive paths select the first member. Symlinks are metadata entries,
not traversal instructions. Split archives still require the corresponding
format's explicit multi-volume API.

## Starlark

The `auto` builtin imports the Go registrations and accepts bytes, strings as
byte contents, files, `binary.view(...)`, in-memory directories, and existing
filesystem values:

```python
root = auto(source, name="bundle.tar.gz")
root.metadata                 # name, kind, size, format, container, readable
root.files                    # immediate child auto nodes
root["etc/package.zip/readme.txt"].file.bytes(0, 64)
root.find("missing")          # None
```

Bzip2 uses an in-memory block index and a 2 MiB decoded-block cache. Its first
open scans compressed block boundaries; the first seek to a decoded offset
measures preceding block lengths because bzip2 does not store them. Those
lengths remain indexed, so later seeks decode only the required blocks. Large
forward seeks measure independent blocks on two workers and discard intervening
output. Block and stream checksums are validated. No disk cache is used.

7z retains at most 2 MiB of requested output pages per folder, in addition to
its codec's required dictionary. Intervening decoded bytes are discarded while
folder and entry CRCs are accumulated. LZMA1 dictionary history can satisfy
nearby backward reads without replay. A backward read outside both the page
cache and dictionary must restart the continuous stream; LZMA1 has no independent
block boundaries. Metadata and already parsed directory nodes remain cached.

`maximum` defaults to 512 MiB for eagerly decoded single streams and individual
bzip2 blocks. Indexed bzip2 streams may be larger without retaining all output.
`maximum_entries` defaults to 100,000 and `maximum_depth` to 32. Existing format parsers retain their own limits
and caching behavior (solid archives may decode preceding data). These are not
an aggregate memory budget. Nodes cache parsing and child listings; keep input
bytes stable for their lifetime. Opening a node is lazy; accessing metadata
confirms its format, and accessing children constructs its directory view.
Directory-list summaries set `inspected=false` on uninspected files so listing
an archive does not recursively parse every child.

## HTTP and browser

`web.browse(root, request)` uses the existing Starlark HTTP infrastructure:

- `/blah.tar.gz/etc/blah.zip/test.txt?json=1` returns selected-file metadata.
- `?json=1&offset=0&limit=500` lists immediate children of a container, with
  `total`, `offset`, and optional `next_offset`. The maximum page size is 1,000.
- Without `json=1`, readable nodes return original bytes with GET/HEAD and
  HTTP Range support. Applications may reserve ordinary URLs for their HTML
  page and route `?raw=1` to this primitive.
- Missing paths return JSON 404; invalid paths 400; recognized malformed
  containers 422; traversal/decompression limits 413. A malformed container's
  original bytes remain available through its raw route.

Paths cross archive boundaries without a special separator. Dot segments,
backslashes and NULs are rejected. File names containing URL delimiters must be
percent-encoded once per path component.

The parent repository provides `scripts/web/browser.star` and one HTML file
with embedded CSS and JavaScript. From its root:

```console
go run ./trex/cmd/trex -serve 127.0.0.1:8080 scripts/web/browser.star /path/to/media
```

The browser loads tree branches on demand, provides direct links and history,
filters loaded names, and offers paged hex and plain-text previews with offset
navigation and encoding selection. Downloads retain the original bytes.
`filesystem.host(root, lazy=True)` uses a rooted native backend, skips symlinks
and special files, and reads directory listings only when requested. Its source
handle is closed with the Starlark application lifecycle.
