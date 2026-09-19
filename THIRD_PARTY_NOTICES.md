# Third-party notices

trex is licensed under Apache-2.0. Its direct Go dependencies retain their own
licences:

| Dependency | Licence |
| --- | --- |
| `github.com/therootcompany/xz` | CC0-1.0 |
| `go.starlark.net` | BSD-3-Clause |
| `golang.org/x/arch` | BSD-3-Clause |
| `golang.org/x/sys` | BSD-3-Clause |
| `golang.org/x/text` | BSD-3-Clause |

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
notices are also retained below. No additional Go module dependency was added.
