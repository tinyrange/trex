# Third-party notices

trex is licensed under Apache-2.0. Its direct Go dependencies retain their own
licences:

| Dependency | Licence |
| --- | --- |
| `github.com/go-git/go-git/v5` (wire protocol and pack decoding) | Apache-2.0 |
| `github.com/pjbgf/sha1cd` (collision-detecting Git hashes; bundled notices retained) | Apache-2.0 and bundled component terms |
| `github.com/therootcompany/xz` | CC0-1.0 |
| `go.starlark.net` | BSD-3-Clause |
| `golang.org/x/arch` | BSD-3-Clause |
| `golang.org/x/sys` | BSD-3-Clause |
| `golang.org/x/text` | BSD-3-Clause |
| `github.com/benhoyt/goawk` (virtual filesystem; process execution disabled) | MIT |
| `mvdan.cc/sh/v3` (syntax, expansion and pattern packages only) | BSD-3-Clause |

The copyright and licence notices required for compiled trex binaries are
reproduced in [docs/dependency-licenses.md](docs/dependency-licenses.md).

Some independently implemented binary layouts were checked against permissive
third-party format implementations. No third-party source or generated output
is included. The projects, provenance, and conservatively retained licence
texts are listed in
[docs/third-party-format-references.md](docs/third-party-format-references.md).

The Microsoft MS-DOS 4.0 MIT notice retained for the independently assembled
BIOS MBR is also recorded there.

The RAR decompression components in `archive/internal/rarcodec` are adapted from
Nicholas Waples' rardecode v2.4.1 under BSD-2-Clause; the original license is
retained there and reproduced in the binary-distribution notices. The 7z x86
BCJ filter adapts explicitly public-domain code from the existing XZ dependency.
Zstandard uses the existing `github.com/klauspost/compress` dependency; its
notices are also retained below. The archive Zstandard support itself added no
additional Go module dependency.

SCS repository, Git and workspace scripting code in `scs/` is adapted from the
`tinyrange/scs` (`j5.nz/scs`) source at commit
`b4ddba5e0f388def4163d8e44860b95153af8c43`. Its existing tests and storage
invariants were retained; backend boundaries, file/tree adapters and lazy Git
checkout were changed for trex. The SCS repository owner confirmed ownership
and authorized licensing this incorporation under Apache-2.0. A copy of the
licence is retained in `scs/LICENSE`; dependency notices retain their own terms.
See [the integration guide](docs/scs.md) for scope and limitations.
