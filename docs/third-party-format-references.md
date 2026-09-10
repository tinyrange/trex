# Third-party format references

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
