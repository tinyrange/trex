This is Go's `compress/bzip2` reader, copied from the installed
`go1.27.0-X:nodwarf5` source, with trex modifications for legacy randomized
blocks. The Go Authors' BSD license is in LICENSE.

The fixed randomization table comes from Julian Seward's bzip2/libbzip2
`randtable.c` (libarchive/bzip2 mirror); its notice is in LICENSE.bzip2.
`random.go` is an altered Go representation, not original libbzip2 source.

Derandomization occurs after inverse BWT and before final run-length
expansion, with state reset at each block. Existing block and stream CRC
checks remain mandatory. No external decompressor is used.
