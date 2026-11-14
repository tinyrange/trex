# Native OS/2 profiles

`os2.profile([(application, key, bytes), ...])` builds the binary linked-record
profile accepted by OS/2 Presentation Manager. Strings must explicitly include
a terminal NUL. Names are case-sensitive. Duplicate keys replace their values
without changing their first position. Application and key links are absolute
file offsets; lengths and allocations are 16-bit, output is bounded to 64 MiB.

The on-disk layout facts were checked against XWorkplace's
`include/helpers/xprf.h` INIFILE_* declarations. No XWorkplace implementation
code is copied, linked or invoked. The writer does not interpret MAKEINI
resources, create desktop objects, install files or install filesystem EAs.

## Packed extended attributes

`os2.extended_attributes(bytes_or_file)` decodes an OS/2 FEA list, including
its four-byte `cbList`, into dictionaries accepted by
`directory.set_extended_attributes`. Input is bounded to 65535 bytes; record
bounds, name terminators, duplicate names and flags are validated. EA value
bytes remain opaque and are copied, not aliased to the input.

The native FAT12/16 writer installs directory EAs using OS/2 `EA DATA. SF`
and per-dirent handles. See `filesystem/fat/os2_ea.md` for layout and limits.
No MAKEINI, EAUTIL, guest installer, or host image-building tool is invoked.

## Linear executables and multimedia streaming

`os2.linear_executable(source, maximum=64MiB)` exposes validated unrelocated
LX objects and original resources, including EXEPACK2 pages. It is read-only,
not a loader or installer. See [lx.md](lx.md) for formats and limits.

`os2.stream_profile(source, maximum=64MiB)` constructs binary `SPI.INI`
from original SSMRES resources without executing installation code.
See [spi.md](spi.md) for the packed handler/protocol layout.
