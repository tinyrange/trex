# IRIX distribution metadata and planning

All readers operate on portable random-access files. No host extraction,
mounting, installer or shell is involved.

- `archive.irix_product(file)` reads `pd001V...P...` descriptors and their
  product/image/subsystem hierarchy. Observed product generations 5, 6, 8 and 9
  are validated on original media; original generations 1–3 follow the historic
  structure declarations; generation 4 uses the legacy extension layout and
  is not claimed as original-media validated. Generation 7 is not claimed. Bounds, record budgets,
  counted strings, signed version-range sentinels and zero tape fill are checked.
- `archive.irix_idb(file)` exposes ordered filesystem records, decoded
  `attributes` and source-faithful `raw_attributes`. In particular, quotes and
  escapes in shell actions are retained rather than silently destroyed.
- `archive.irix_image(image, idb, logical_name)` recovers regular-file views and
  validates record layout. Reads validate indexed sizes and BSD checksums.
- `archive.irix_plan(descriptors, selected, ...)` selects subsystem patterns
  against the supplied catalog. An empty selection uses declared default flags;
  `versions` pins exact subsystem versions, otherwise the highest supplied
  version is used. Duplicate candidates at the selected version are errors.

## Explicit context

`installed` maps logical subsystem names to image versions. Prerequisites are
represented as alternative groups: all marks in one group must match installed
or selected versions. Unmet groups are returned intact as issues; the planner
never silently chooses another dependency alternative. Replacement declarations
remove covered installed subsystem names from the effective dependency set.
Image order is retained independently of dependency satisfaction.

`machine` supplies explicit facts such as `CPUBOARD`, `SUBGR` and `GFXBOARD`.
Different keys are conjunctive, repeated values of one key are alternatives,
and an empty value is significant. Historical bare names use the `MACHINE`
fact. An omitted fact is unresolved, not a guessed architecture or a wildcard.

`indexes` is keyed by `product@version`; `images` is keyed by
`product.image@version`. Unqualified inputs are accepted for simple inspection,
but qualified inputs should be used when combining foundation and overlays.
The IDB attributes, not physical `_6522m` filenames, identify membership.
Operations retain the source image and IDB ordinal, including machine variants.

`existing` is the caller's complete current regular-file map. `previous` gives
BSD checksums recorded at the prior installation. `config(update)` can preserve
modified files as `.O`; `config(suggest)` can propose `.N`; `config(noupdate)`
retains the existing file. Missing required history remains an issue. These
checksums reproduce installer policy, not cryptographic identity proofs.

## Boundaries

The result has `selected`, `removed`, `operations`, `hooks`, `issues` and
`resolved`. Operations describe files, directories, links and device nodes;
regular-file contents remain borrowed views. Hard links follow their target
operations and generated suffixes participate in destination collision checks.

`resolved` means no known planning issue. It does **not** mean payload bytes
have all been read, hooks have run, an on-disk filesystem has been built, or
IRIX has booted. `preop`, `postop` and `exitop` commands retain their quoting and
are returned as unexecuted hooks and explicit blockers. Build-time subsystem
expressions are preserved; they are not host shell programs.

Later descriptors contain additional mark arrays (`extensions`, `additional`,
`final`) and attribute strings. Their framing is decoded, but nonempty mark
policies whose install meaning is not established remain planning blockers.
Unknown IDB policy also remains an issue. There is no generic "ignore and mark
complete" fallback.

## Format provenance and validation

Field layouts for the original format come from SGI's historical
[`inst.h`](https://github.com/JohnDTX/irix-3.x-src/blob/main/dist/idbtools/include/inst.h)
and serialized field declarations in `dist/idbtools/libinst`. Later generation
boundaries were established by native cursor inspection of original media.
The Go implementation and synthetic fixtures are independent; no historical
installer code or proprietary media is redistributed.

Original-media validation includes all nine product descriptors in the archived
3.3 bundle and all sixteen on 6.5.22 Overlay 1. This is not an all-disc installed
payload or boot validation.
