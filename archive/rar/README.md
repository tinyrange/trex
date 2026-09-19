# RAR readers

`rar.Open(source, maximumEntries)` accepts a portable `storage.Reader`, validates
RAR4/RAR5 headers, and returns lazy member files. `File.ReadAt` supports random
access, `File.WriteTo` streams a complete member, and `File.Verify` checks the
complete member without retaining its output. Complete reads check the declared
length, compression terminator and CRC when present.

Starlark exposes `archive.rar(source, maximum_entries=100000)`. Its `files` list
contains file paths, `entries` includes directories and metadata, and indexing
by a path returns a portable file. The `auto` registry exposes a directory tree.

The NAS collection requires stored RAR2/3/5 members, RAR3 LZ and PPMd, RAR5 LZ,
solid dictionaries and executable filters. Split volumes, passwords and external
RAR5 hash records are not exposed by this API; no encrypted or split members
occur in the audited collection. RAR4 UTF-16 filename compression and RAR5 UTF-8
names are parsed in the container layer.

The archive holds a 2 MiB LRU of 64 KiB decoded pages. Forward solid reads retain
decoder state; a backward cache miss replays the nearest independent member and
checks intervening members. The dictionary and declared PPM model budget each
have a 64 MiB ceiling. No extracted host files or external tools are used.

Decompression components and their BSD-2-Clause attribution live in
[`internal/rarcodec`](../internal/rarcodec/README.md). The container, file views,
checksum integration and page cache are implemented here. Synthetic tests cover
literal compression, header/data corruption, truncation and random access.
Optional media regressions cover PPMd, solid backward seeks, RAR5 and the large
Chicago 490 ISO that exposed cross-window LZ/filter bugs:

```sh
TREX_ARCHIVE_CORPUS=/remote/nas/nas_usb go test ./archive/rar -run TestCorpus
```
