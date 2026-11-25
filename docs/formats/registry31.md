# Win16 registration inspection

`windows.registry31_entries(file)` reads the reachable key tree of a Win3.1
`SHCC3.10` registration database. Keys are returned with their actual root
(e.g. `.classes`), backslash-separated components and original spelling.
Each key maps to its unnamed Windows-1252 string value, or `None` for an unset
value. A present empty string is distinct from `None`. The Go reader uses
portable TinyRangeX files, not a host registry API or external parser.

Inspection validates record/string arena bounds, indexes, key components,
cycles/shared key nodes, duplicate case-folded paths and key/string aliasing.
It bounds input to 1 MiB, depth to 256 and expanded paths to 16 MiB. Unreachable
hash/free records and allocator slack are not reported as keys. This is not
an allocator/hash-table integrity checker or a registry mutation API; the
existing `windows.registry31` constructor is unchanged.

Tests cover an independently encoded padded/multi-bucket-style layout,
Windows-1252 decoding, unset/empty distinction, malformed indexes, truncated
prefixes, cycles, overlapping arenas, excessive depth, the Starlark binding
and constructor round trips. Actual original Windows Setup's REG.DAT was also
read natively in the Gate2 experimental audit; that is integration evidence,
not a redistributed proprietary fixture.

## Construction and key-only directives
`windows.registry31(entries, sources=[])` accepts strings or `None` as entry
values. `None` creates a key without an unnamed value. Source directives with
no equals sign likewise create key-only state; explicit `= ` or an empty string
creates a present empty value. Explicit entries override source directives.
This distinction is observed in original Windows3.11 SETUP.REG's WordDocument
PackageObjects key. Native source construction now matches all89 independently
observed original Setup entries, including this unset value. Windows3.11's base
recipe now writes those default source registrations even when there are no
application-specific modifications. Other OS recipes are not changed.
