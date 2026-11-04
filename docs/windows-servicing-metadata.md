# Owned servicing metadata snapshots

`source.servicing_metadata(feature)` indexes the full stage metadata namespace,
not its preliminary payload plan. Availability is not CBS admission.

`open_package(package)` and `open_packages(packages, workers=4)` return immutable
owned MUM snapshots after exact package-identity validation. The batch call is
bounded to 4096 inputs and 1–8 workers; it joins workers before returning.

`open_catalog(package, manifest=None)` opens the exact companion catalog. When
`manifest` is supplied it must be an owned snapshot returned by this same
metadata index for that same exact package. Equal bytes, a foreign index, or a
snapshot for another package are rejected. This avoids reconstructing the MUM
again. Omitting it retains the ordinary MUM validation path. Neither form proves
catalog signature, certificate trust, timestamp validity, or MUM membership;
those checks remain the caller's responsibility.

The native `AssemblyPlanner.BindFinalStageContent` binds predecessor content for
a terminal stage without evaluating a discarded preliminary package closure.
The planner is then sealed against further stages. Exact component metadata
resolution registers predecessor name hints against that unchanged inventory;
content length and SHA remain authoritative. Earlier stages still run ordinary
binding so their content and installed-inventory projections remain available.
This terminal binding is not package admission or an installed-state result.

`open_catalogs(packages, manifests=None, workers=4, while_opening=None)` captures
owned companion catalog bytes in input order, including duplicates. Omit optional
arguments rather than passing None. A supplied manifest list must have the same
length; None entries perform ordinary MUM validation, while snapshots require the
same index and exact package. Limits are 4096 entries, 1–8 workers, 64 MiB per
catalog and 256 MiB captured per call. No partial result is returned on failure.
The source must permit concurrent reads. The optional callback runs once on the
caller thread beside native reads; workers always join, including on callback
failure. It must not mutate source readers. This API proves neither catalog
signatures nor trust; those remain explicit checks before publication.
