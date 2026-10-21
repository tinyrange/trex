# SCS integration

Repository, native Git ingestion and workspace Starlark code adapted from
`tinyrange/scs` (Go module `j5.nz/scs`) at
`b4ddba5e0f388def4163d8e44860b95153af8c43`.

The SCS repository owner confirmed ownership and authorized this code's
incorporation under the Apache License, Version 2.0. See [LICENSE](LICENSE).
Third-party dependencies remain under their respective terms; see
[trex's notices](../THIRD_PARTY_NOTICES.md).

The trex adaptation separates portable storage from native opening/locking,
replaces the host transport spool with bounded paged memory, adds lazy Git
checkout and portable file/tree adapters, and wires workspaces into the existing
Starlark runtime and in-process Renvo build consumers. Existing repository
format, publication and recovery invariants and useful regression tests are
retained. FUSE/cah, host Git import, standalone CLI, machine configuration,
conversation notes and historical build logs are not included.

See [the SCS API and integration guide](../docs/scs.md) for usage, ownership,
performance limits, publication and recovery. The original source checkout and
Git history were not modified or imported as commits by this source-copy
integration.
