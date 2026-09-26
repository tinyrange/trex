# Alcohol MDS/MDF

`Open(storage.Reader)` reads version-1 MDS descriptors, including sessions,
TOC records, track modes, pregaps, sector sizes, offsets and companion names.
`Image.View(Resolver)` binds portable files and exposes each session/track with
separate `raw`, `data` (or `audio`), and `subchannel` byte views. Passing nil
retains descriptor metadata without pretending that track contents exist.

`filesystem.mds(descriptor, images={"*.mdf": image})` provides the same views
to Starlark. `sessions` contains session records and their `tracks`; track
records expose the byte views and declared geometry. `auto` recognizes MDS
and resolves its MDF through the containing source tree. An isolated descriptor
needs `auto(descriptor, tree=directory, path="disc.mds")` for companion access.
Companion names cannot escape the granted tree or follow symlinks.

CD audio, Mode 1, Mode 2, Form 1/Form 2 and DVD sector layouts are represented
directly. Raw P-W interleaved subchannel bytes are exposed separately when
present. Track offsets and stored lengths govern reads; pregap metadata is
preserved without fabricating absent lead-in sectors. Multiple companion files
are concatenated as byte views, with the declared offset in the first file.
This reader does not perform audio conversion or validate CD ECC/EDC codes.

Metadata parsing checks references, duplicate track/session identities, UTF-16
names, geometry and source bounds. Aggregate descriptor reads are bounded at
8 MiB, and filename references are cached; no MDF payload is read to parse a
descriptor. Track reads allocate no decoded image buffers.

The little-endian layout uses an 88-byte header, 24-byte session records,
80-byte track records, 8-byte CD extent records and 16-byte filename footers.
Layout facts were checked against the primary
[Aaru structure declarations](https://github.com/aaru-dps/Aaru/blob/devel/Aaru.Images/Alcohol120/Structs.cs)
and [LibMirage MDS declarations](https://github.com/cdemu/cdemu/blob/master/libmirage/images/image-mds/image-mds.h).
The Go reader and tests are independently implemented; no parser code was
copied or linked from those projects.

The NAS Chicago 331 descriptor is mixed-mode: one data track, five audio tracks
and interleaved subchannels in 2448-byte stored sectors. Its six declared
extents cover the MDF exactly. The corpus regression reads data, audio and
subchannel boundaries and checks the data track's ISO descriptor:

```sh
TREX_ARCHIVE_CORPUS=/remote/nas/nas_usb go test ./filesystem/mds
```
