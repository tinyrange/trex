# Third-party format references

## Chrome packages and Android recovery filesystems

The CRX3 envelope, signed-data framing, and developer-ID derivation follow
Chromium's [CRX3 schema](https://chromium.googlesource.com/chromium/src/+/main/components/crx_file/crx3.proto)
and [verifier](https://chromium.googlesource.com/chromium/src/+/main/components/crx_file/crx_verifier.cc).
Signature verification is independently implemented with Go's standard crypto
packages; it does not pin a Chrome Web Store signing key.

Android logical-partition metadata versions 10.0–10.2 follow AOSP's
[liblp declarations](https://android.googlesource.com/platform/system/core/+/refs/heads/main/fs_mgr/liblp/include/liblp/metadata_format.h).
Boot and vendor-boot versions 3–4 follow AOSP's
[bootimg.h](https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/main/include/bootimg/bootimg.h).
These readers validate structural bounds and liblp checksums, not AVB trust.

EROFS inode, directory, compression-index, and checksum layouts were checked
against Linux's [EROFS structures](https://github.com/torvalds/linux/blob/master/fs/erofs/erofs_fs.h)
and compression mapping rules in `fs/erofs/zmap.c`. The Go implementation and
synthetic regression fixtures are independently written; no kernel decoder is
copied, linked, or invoked. LZ4 block decoding follows the published
[block format](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md).
Real-media checks used the signed Device Recovery Utility extension and ASUS
Googlebook 14 recovery build `16452207_CL3B.260622.271.R1`, without incorporating
their contents into the repository.

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

## CaddyGlow/ms-delta PA31 playback and fixtures

Reference for `windows/msdelta/playback.go`: `src/pa30/reverse.rs` in
[CaddyGlow/ms-delta](https://github.com/CaddyGlow/ms-delta/tree/6f25d63e8a8573015feb2f6a3d3f98861edbb22c).
Reviewed reference revision: `6f25d63e8a8573015feb2f6a3d3f98861edbb22c`.

The fixtures in `windows/msdelta/playback_test.go` are from that project.
The following manifests are under `docs/fixtures/pa31-native/` at the reviewed
revision:

| Manifest | Entry | Delta SHA-256 |
| --- | --- | --- |
| `reverse/manifest.json` | `abc-268435456` | `cd1944a825c7c771ea47d085c355b1091f14d21b350fad2fcedae2f89ae6fc70` |
| `reverse-extended/manifest.json` | `amd64-pointers-forward` | `8aa620478535d07300ae2b4affd28cd917faef9f6bc76136fa875ba350545716` |
| `reverse-extended/manifest.json` | `managed-x64-forward` | `2bc70243127e483677abcf4ec59c99cd5f0f6ac0e3a51c16adfcb5fae59886fc` |
| `reverse-extended/manifest.json` | `compressed-delete` | `bf7e0a988d594c2f0fb60ee3c639c043ef543c5530784806eed7319e5139c7a9` |

Generation records: `docs/fixtures/pa31-native/README.md`,
`docs/fixtures/pa31-native/reverse/generate.ps1`, and
`docs/fixtures/pa31-native/reverse-extended/generate.ps1`.
Input-family references: `docs/fixtures/pa30-pe-native/README.md` and
`docs/fixtures/pa30-cli-native/README.md`. The manifests record the source and
target roles for reverse application.

The upstream MIT notice is retained in
[`windows/msdelta/playback.LICENSE`](../windows/msdelta/playback.LICENSE) and
reproduced in [binary-distribution notices](dependency-licenses.md):

```text
MIT License

Copyright (c) 2026 windows-uup contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

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


## Linux image and Alpine package foundations

CPIO newc, ext filesystem metadata/checksum layouts and the x86 boot header
follow the Linux kernel's format documentation. Implementations and synthetic
fixtures are native and independent; no external filesystem or package tool is
invoked or linked.

The Apache-2.0 repository `tinyrange/pkg2`, pinned at
`fc584d5fed9ed3f0a29826dd8b3c3d675a2be0ca`, was consulted for Alpine's Starlark
metadata handling, virtual-provide planning and explicit script/trigger plans.
The new `unix/alpine.star` is independently implemented; no source files were
copied. The older guest runner and disabled version-matching behavior are not
incorporated. The Apache License 2.0 is retained in this repository's LICENSE.

Upstream apk-tools format/version behavior was inspected as a reference only.
No GPL implementation is copied, translated or linked; unsupported version
range constraints are explicitly rejected by the basic pinned policy.

## IBM i optical TERSE and XCOFF

Native inspection of original media established LD_TRS outer framing, the
02000080 inner header, record boundaries and byte-aligned zero end-code tails.
The prefix-chain LRU dictionary behavior was informed by the Open Mainframe
Project `tersedecompress` NonSpack algorithm at commit
`12f5f9f34821defeef696c3232d97b7733dc79a6`. It is implemented natively in Go with
bounded arrays, strict declared-output/trailer checks and synthetic fixtures;
no external decompressor or host extraction command is used. Upstream is
Apache-2.0; its full license is retained by the repository LICENSE. The project
and reference source are at
https://github.com/openmainframeproject/tersedecompress/tree/12f5f9f34821defeef696c3232d97b7733dc79a6.

XCOFF64 fields and auxiliary tags were checked against the primary format
declarations in Go's `src/internal/xcoff/xcoff.go` and LLVM's
`llvm/include/llvm/Object/XCOFFObjectFile.h`, alongside native original-media
inspection. No third-party XCOFF parser code is incorporated or invoked.
The native APIs preserve raw names, unknown auxiliary records and non-restored
BSS; saved addresses are never automatically equated with execution addresses.

## IBM SaveDskF and legacy ZIP methods

The native Go SaveDskF reader's header layout and checksum were cross-checked
against Deark `modules/fat.c` at `f7c9af05e43fa754be32d0e4601c30e377fcbc72`. Its IBM LZW dictionary behavior
was informed by the anonymous public-domain `dskdcmps` explanation preserved
in Deark `foreign/dskdcmps.h` and `foreign/readme-dskdcmps.txt`. Jason Summers'
2021 modifications in that file explicitly permit public-domain treatment;
that option is used here. No Deark runtime or external conversion is used.
The Go reader adds strict size/geometry checks and preserves missing sectors
rather than copying the reference converter's zero-padding policy.

ZIP Shrink and Implode follow PKWARE's APPNOTE compression-method descriptions.
Algorithm cross-checks used Apache Commons Compress `BinaryTree.java`,
`ExplodingInputStream.java`, and `UnshrinkingInputStream.java` at
`22cd988a71ac7dff82694933ff4feccf520bec31` (Apache-2.0), and Info-ZIP's `unshrink.c`
in `madler/unzip` at `0b82c20ac7375b522215b567174f370be89a4b12` (Info-ZIP).
The Go streaming readers and synthetic tests are independently written, not
translated or linked third-party decoders. Apache's canonical-code ordering
and tests were used to cross-check the format. No Info-ZIP implementation is
copied. The Apache License 2.0 is retained in the repository's `LICENSE`.

Reference repositories: `jsummers/deark`, `apache/commons-compress`, and
`madler/unzip` on GitHub. Apache's `SHRUNK.ZIP`,
`imploding-4Kdict-2trees.zip`, `imploding-8Kdict-3trees.zip`, and
`lorem-ipsum-implode.zip` were validated in memory only. Proprietary IBM media
was also validated locally but is not redistributed. No new Go dependency
is introduced.

## IBM OS/2 PACK2 and PM profiles

The FT19 decoder and bootstrap tables in `archive/os2pack` are adapted from
Dimitriy Ryazantcev and Jason Summers' MIT-licensed Deark implementation:
`src/fmtutil-ftcomp.c`, `foreign/ftcompdata.h`, and `modules/os2pack.c` at
https://github.com/jsummers/deark. The complete notice is retained in
`archive/os2pack/LICENSE.deark`. Original IBM payloads are not redistributed.

The independently written `os2.Profile` serializer uses binary-layout facts
from XWorkplace's `include/helpers/xprf.h` INIFILE_* declarations; no GPL
implementation was copied, linked or invoked. VGA INT 10h/1Bh layout facts were
checked against SeaBIOS `src/std/vga.h` and `vgasrc/vgabios.c`; the firmware
implementation and tests here are independent, with no SeaBIOS code copied.

## IBM/Microsoft MAPSYM debug symbols

The native `debug.mapsym` reader follows paragraph pointers and record layouts
from Open Watcom's `bld/watcom/h/mapsym.h`. That header was consulted only for
format facts; no implementation was copied. Tests construct synthetic symbol
files. Original IBM kernel symbols were used for local integration inspection,
not bundled in the repository.

## OS/2 FAT extended attributes

- Primary format declarations: Microsoft Windows-driver-samples,
  `filesys/fastfat/fat.h`, `EA_FILE_HEADER`, `EA_SET_HEADER`, `PACKED_EA`.
- Primary address/handle rules: the same repository's `filesys/fastfat/easup.c`.
- Independent implementation: `filesystem/fat/os2_ea.go`; it serializes the
  documented layout and does not copy driver implementation code.
- `os2/ea.go` bounds and decodes packed OS/2 FEA lists into portable directory
  metadata. Opaque value bytes, including typed values, remain uninterpreted.


## OS/2 LX, streaming and multimedia policy

- LX object/page/resource tables follow IBM format declarations. EXEPACK2 bit
  fields were checked against Ryan C. Gordon's `icculus/2ine/lx_loader.c`, which
  identifies LXlite 1.38u as the algorithm source. The bounded Go reader and
  regression fixtures are independently implemented; no runtime loader is used.
- SPI resource and profile layouts were checked against original IBM SSMRES,
  SSMINI and SSM bytes, and `bitwiseworks/os2tk45/h/ssm.h` declarations.
- MMIO/MCI construction uses original IBM CONTROL.SCR, MASTERH9.RT,
  FOURMEG.SCR, SMVINI.SCR, VAPM.SCR and CARDINFO resources. The SDK headers
  `mmioos2.h`, `mcios2.h` and `meerror.h` supply field/error definitions.
  OS2World's `DEV-SAMPLES-DRV-Audio_PDD-/readme.txt` supplied an independent
  primary MMPM2.INI connection example. No installer DLL is executed.
- `archive.szdd_info` preserves the SZDD header's original final filename
  character when expanding underscore-named Windows 3.1 files. The metadata
  parser is independently written and shares the existing native decoder.

## ISA PCM device

8237 addressing/count and Sound Blaster DSP/mixer command facts were checked
against primary emulator implementations `qemu/qemu/hw/audio/sb16.c` and
`dosbox-staging/dosbox-staging/src/hardware/audio/soundblaster.cpp`, plus
`Baron-von-Riedesel/VSBHDA/src/SB.H` command definitions (including 45h/47h
SB16 auto-init continuation). The new Go device, tests, capture conversion and
clock integration are independently written; no implementation code or new
third-party dependency is copied, linked, invoked, or redistributed.
Original IBM/Microsoft media is used only for local integration, not bundled.
