# Third-party format references

## Legacy Microsoft setup media

Office media supplied the fixtures for the native SZ/KWAJ adaptations. The
older `SZ` wrapper has a 12-byte header and starts its LZSS window at 4096−18;
normal SZDD uses its existing 14-byte header and 4096−16 origin. Only these
format facts were checked against the published
[SZDD/KWAJ format description](https://fossies.org/linux/clamav/libclammspack/doc/szdd_kwaj_format.html).
No external decoder implementation was copied or linked.

The Office 2.5 corpus also establishes two distinct split-file constructions:
PowerPoint joins numbered compressed-stream fragments, while Excel joins
independently compressed pieces declared with first/continuation flags. Empty
KWAJ LZH files contain no entropy tables. Size-less LZH byte padding is accepted
only when an incomplete final token emits no bytes and consumes at most the
remaining seven padding bits. Focused tests preserve these distinctions.

## MSI database stream encoding

The MIT-licensed string-pool and packed stream-name descriptions in
[`abemedia/go-msi`](https://github.com/abemedia/go-msi/tree/5dcc3553b5f9d81feb6689c1059982e6a0bf3f2e)
were consulted while implementing the native MSI reader. No dependency or
external extraction command is used. The notice is retained conservatively:

> MIT License
>
> Copyright (c) 2026 Adam Bouqdib
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

The compound-file layout follows Microsoft's
[MS-CFB specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b).
Installer conditions and source selection follow Microsoft's
[condition syntax](https://learn.microsoft.com/en-us/windows/win32/msi/conditional-statement-syntax)
and [Word Count Summary property](https://learn.microsoft.com/en-us/windows/win32/msi/word-count-summary).

## Authenticode page hashes

The SHA-256 page-hash wire layout and padding rules were cross-checked against
[SAS Relic](https://github.com/sassoftware/relic/tree/master/lib/authenticode),
particularly `structs.go`, `pedigest.go`, and `pesign.go`. trex implements the
operation using its existing validated PE ranges and DER constructors. It does
not import Relic or launch an external signer.

Upstream notice retained conservatively: Copyright (c) SAS Institute Inc.
Licensed under the Apache License, Version 2.0; the full license is included
in [LICENSE](../LICENSE). No GPL implementation is incorporated.

## Windows kernel dump header

The PAGE/DU64 field layout used by `windows.kernel_dump_header` was checked
against the `WinDumpHeader64` format declaration in
[QEMU win_dump_defs.h](https://github.com/qemu/qemu/blob/master/include/qemu/win_dump_defs.h).
The reader is independently implemented using bounded TinyRangeX file reads;
no QEMU dump-generation or parsing code is invoked or incorporated.

## jlevere/msdelta

The PA30/PA31 rift grammar, PE source transformations, piecewise mapping
composition and reversal, LZX-delta match-state behavior, Windows Compression
API LZMS container framing, serialized CLI metadata/shared-format maps,
managed signature/index normalization and copy-coordinate overlays,
and the nested three-control binary-delta grammar
used by
`windows/msdelta` were informed by
[`jlevere/msdelta`](https://github.com/jlevere/msdelta) at commit
`fb5ab88843e854f3fd32d553984d8685ae643913`. The implementation was adapted
to trex's bounded Go byte abstractions and verified independently against the
source and target hashes embedded in real PA31 records. No Microsoft
binary, symbol map, generated trace, or patent text is included.

The upstream MIT licence is retained:

> MIT License
>
> Copyright (c) 2025 Jackson Leverett
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

## Public CLI instruction definitions

The bounded managed-method token normalizer in `windows/msdelta` uses the
public CLI tiny/fat method layout and instruction operand encodings, checked
against the MIT-licensed .NET runtime's
[`opcode.def`](https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/opcode.def).
Transform-selection bits are documented in the public Windows SDK
[`msdelta.h`](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/msdelta.h).
No native Microsoft delta implementation is used for this normalization.

## Microsoft MS-DOS 4.0 FDISK MBR

The independently assembled BIOS MBR in `filesystem/mbr` was informed by the
control flow and behavior documented in Microsoft MS-DOS 4.0's
`v4.0/src/CMD/FDISK/FDBOOT.ASM`. The trex implementation adds INT 13h
extensions and does not include the upstream source, but the upstream notice
is retained conservatively:

> MIT License
>
> Copyright (c) Microsoft Corporation.
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

## installscript-decompiler

trex's independently structured InstallScript parser was validated
against the binary layout described by
[`jte/installscript-decompiler`](https://github.com/jte/installscript-decompiler).
This notice is retained conservatively even though trex does not include
that project's source code, generated output, or predefined symbol tables.

> MIT License
>
> Copyright (c) 2018 jte
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

No source or generated output without an identified compatible licence was
used in the implementation.

The historical `incognitte/isDcc` project was evaluated only by reading its
public README and licence terms. Those terms restrict incorporating its code
into another product and distributing modified copies, so its source,
predefined symbol tables, and generated output were deliberately excluded from
trex's implementation and test data.

## Unshield

The InstallShield cabinet layout was validated against
[`twogood/unshield`](https://github.com/twogood/unshield). trex uses its
own bounded parser and in-memory file abstractions; the upstream notice is
retained conservatively.

> Copyright (c) 2003 David Eriksson <twogood@users.sourceforge.net>
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

## SabreTools Wise format records

The MIT-licensed Wise overlay and action records in
[`SabreTools/SabreTools.Serialization`](https://github.com/SabreTools/SabreTools.Serialization/tree/3798dbcb479f42cd607e0ac8a01ed06ba892fbe3/SabreTools.Data.Models/WiseInstaller)
were consulted as format references. The support-stream boundary correction
was established from the original installers' bootstrap instructions, declared
payload extents and CRC-checked streams. No external extractor was executed and
no source implementation was copied. The upstream notice is retained here:

> Copyright (c) 2018-2026 Matt Nadareski
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice (including the next
> paragraph) shall be included in all copies or substantial portions of the
> Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.
