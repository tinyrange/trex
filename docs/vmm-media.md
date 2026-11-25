# Read-only removable-media replacement

`vm.replace_media(name, source, timeout=30)` is an optional backend-neutral VM operation. Check `disk.media.replace` in capabilities. `name` is the disk name declared in the machine; `source` is a native file or `block_device`, not a host pathname. This preserves read-profiler wrappers and lazy sources without exporting an intermediate image.

The current QEMU implementation supports read-only, non-snapshot floppy media of unchanged size and IDE CD-ROM media with compatible logical sector geometry. It supplies the actual source through an owned native NBD export and uses stable internal frontend IDs. There is no implicit full-source read, cache warm-up, snapshot, or installed-state construction in this operation. Guest/firmware reads may occur while the media is opened.

An error after submission does not establish that the drive is unchanged: it may be empty or contain the new medium. Do not automatically retry. The runtime retains exports through VM close even after an uncertain reply, so a medium accepted by the emulator is not disconnected merely because its reply was lost. Invalid target kinds, writable/snapshot targets and incompatible floppy geometry are rejected before opening an export. Callers remain responsible for appropriate guest UI/media readiness and write protection.

Native integration tests boot three independently supplied in-memory floppy sectors, observe distinct COM1 bytes after replacement/reset, and require nonzero partial reads on each actual source. They also check transport cleanup and closed-VM/unsafe-target rejection. DOS6.22 and catalog Windows3.11 original Setup exercise the same operation with real read-profiler wrappers. These floppy qualifications do not establish a guest-level IDE-CD-ROM or every-architecture qualification.

Read-profiler totals are logical API reads, not physical host or NAS I/O. Source hashes, cache conditioning and observer wrappers are separate caller policies. In particular, hashing a raw source before wrapping it warms caches but is not counted by that wrapper.
