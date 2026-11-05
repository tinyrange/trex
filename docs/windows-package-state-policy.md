# Published Windows package state

CBS `CurrentState` and package `Owners` values are public, operational inputs to
Windows servicing. They are **not internal progress, confidence, or verification
flags**. An inaccurate lower state can cause Windows to act on a false account
of the installation and break a user's system.

## Publication rule

- Do not default or cap a constructed package or owner to `0x20` (Resolved).
  Use that state only with affirmative, package-specific evidence for it.
- Do not claim “not fully installed” because an implementation path is untested,
  a native phase has not been replayed, a timestamp is absent, an observer timed
  out, or a report says `incomplete`. Unknown validation status is not evidence
  of a missing installation effect.
- After applying construction effects, publish the admitted package disposition:
  Installed (`0x70`) for an admitted installation; Staged (`0x40`) for an explicit
  stage-only disposition. Do not promote stage-only packages indiscriminately.
- Preserve each admitted owner's state and integration bits independently of
  package state. A permanent owner (`0x80`) can coexist with a package at `0x70`.
  Zero-state requests remove owners; do not invent owners for them.
- Persist explicit resident predecessor transitions too: an admitted superseded
  target is `0x50`, not the `0x40` used only for action/dirty comparisons. Preserve
  unmentioned resident owners and apply named owner overlays independently.
- Preserve unchanged source-media package states. Do not relabel native staged
  packages, superseded versions, disabled optional features, or removals merely
  to make all entries read Installed.
- Reject unsupported construction states before publication. Do not substitute
  a guessed Resolved state and ship the resulting registry.

The new-package writer is `experiment_package_metadata` in
`starlark/stdlib/windows/servicing/package_store.star`. It runs after file,
registry, installer, and CSI effects in `finish_update_boot_experiment`, retains
exact MUM/catalog/composition checks, and records each published disposition.
The metadata-index planner alone does not authorize package-state publication.

The fresh-image smoke exposed an omitted resident transition: CBS rejected
Recall enumeration with `0x800f0819` (`CBS_E_DUPLICATE_UPDATENAME`), naming both
`.9457` and `.9711` feature packages. Ordinary population already targeted the
older package at `0x50`, but the new-package-only publisher left it at `0x70`.
Resident final-state and owner-overlay publication must accompany the new
package writes. This is concrete lifecycle evidence, not a confidence-based
downgrade or justification for converting packages to Resolved. Regression
coverage checks predecessor `0x50`, unchanged native metadata, independent
owners, zero-owner deletion, and atomic rejection of unsupported transitions.

## Evidence required for an exception

Record the exact package/version, intended operation, and concrete evidence:
for example a validated stage-only request plus source-qualified CSI pins, or
an explicit removal with the payload and install/staging references removed.
A native package query merely reading a state that we wrote is not independent
evidence for that state. Nor does a missing install timestamp prove absence.

The recipe's staged Recall/AIX removal is an explicit `0x20` case: it checks the
exact dependency, exclusive owner, and matching p!/s! references with no i!,
removes staged payload and s!, and retains manifest-resolution data. Installed
or shared dependencies are rejected. WMIC removal instead removes its validated
package/owner closure; it is not a reason to downgrade other packages.

## Validation and reporting

Keep outstanding validation in reports outside the guest. Report a specific
missing effect only when demonstrated, identifying the affected package and
source expectation. Preserve native failures, but distinguish harness deadlines
from Windows failures. No passing boot or ScanHealth result establishes every
package semantic; equally, an unrun check establishes no missing effect.

In the November 4, 2026 experiment, the original ScanHealth completed without
component-store corruption after about 90 minutes, despite a 30-minute observer
timeout. Updates and clean shutdown also succeeded with installed-state
overrides. This rejects the timeout as evidence for “not fully installed”; it
is not a matched proof that every override was correct. The normal publisher
must use admitted dispositions, not those blanket experimental overrides.

The subsequent corrected-disposition experiment on the same date did not use
blanket overrides. Its 4,570-package construction audit had no discrepancies.
Before networking, Get-Packages, CheckHealth, ScanHealth and SFC `/verifyonly`
all exited zero, with explicit no-corruption/no-integrity-violation output and
a clean shutdown. Native Windows Update then successfully installed seven
offers across two passes (including a .NET security update, Defender updates
and two drivers). An empty third search was followed by the same four native
checks, all passing, and a second empty search. Defender real-time protection
was enabled, Explorer responded, and the final shutdown was clean.

That proves the observed integrity and update behavior of this candidate, not
a fully passing regression suite. The exact two-boot smoke stopped at an
Explorer-triggered Client.CBS AppX registration assertion on boot one. Also,
the first online pass reached Windows shutdown but the backend failed on an
unhandled NVMe-region write (`0xd0001004`); recovery and subsequent clean
shutdowns do not retroactively make that cycle clean. Keep these shell/harness
blockers separate from package-state inference. Do not weaken their assertions
or reinstate blanket servicing suppression to conceal them.
