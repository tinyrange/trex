# Native CSI identity and ownership records

These observations concern the COMPONENTS hive in Windows 11 media build
26300.9457. They are format observations, not a claim that offline cumulative
servicing or all associated component actions are implemented.

## Identity names

The binary `identity` and `appid` values contain un-terminated UTF-8 display
identities. They preserve the full component name; the abbreviated WinSxS name
is not an identity. In particular, the IIS ClientCertificateMappingAuthentication
and IISCertificateMappingAuthentication families have colliding abbreviated
name prefixes but different identities and hash suffixes.

CSI name hashing uses four interleaved unsigned 32-bit polynomial streams with
multiplier 65599, combined modulo 2^64 using radix 2^33 - 9. Attribute hashing
combines the name and value hashes in this order: name, culture, type, version,
publicKeyToken, processorArchitecture, versionScope. Neutral culture and absent
attributes are omitted. Family hashes omit version. The implementation currently
rejects non-ASCII identities rather than approximating Windows Unicode folding.
These equations were checked against 30,753 component identities and 4,143
canonical deployment appids in the native hive. Arithmetic was also compared
with asdcorp/haveSxS's published format research; no reference implementation
code is incorporated.

Deployment registry names contain a normalized component name, shortened to
11 leading and 11 trailing characters around `..` when longer than 24, followed
by token, version, and the 16-digit identity hash. Architecture and culture
participate in the hash but do not appear as separate readable fields.

## Deployment sources

A `p!CBS_`, `s!CBS_`, or `i!CBS_` binary value begins with two little-endian
uint32 lengths, followed by the primary UTF-8 string and opaque secondary data.
The primary string is `<package identity>.<update name>`. The secondary data
must not be appended to the update name; .NET records in this image often
contain one additional ASCII `8` or `9` byte. Present/staged/installed records
for a source contain identical bytes.

The source name uses a normalized, lower-case, 60-character primary-string
prefix plus its text hash. Underscore runs are collapsed in the readable prefix,
not the hashed input. All 6,037 native present-source names matched this rule.
The IIS control deployment's CatalogThumbprint equals SHA-256 of its complete
package catalog file, not the manifest hash.

Package CurrentState alone does not activate every deployment in that package.
Installed IIS packages have deployment sources with `p!` and `s!` but no `i!`.
Runtime effects must distinguish staged-only roots and propagate activity along
applicable install edges; a dependency shared with an active root remains active.

The `c!<deployment key>` values on component keys describe transitive ownership,
including unchanged resident components. The pinned IIS ClientCertificate
update has 61 members, like its native predecessor, with precisely six version
replacements. Retaining only the first selection origin loses multiple package
sources. Copying the predecessor's ownership list loses dependency changes.
Explicit prerequisites control optional branches. Publisher-policy
`bindingRedirect` declarations are runtime policy, not versionless install edges.

## File records

An `f!` value name uses the original manifest-relative filename, case-folded.
ASCII letters, digits, hyphens and dots are safe. Other characters become `_`,
with runs collapsed. If any character required substitution (including a literal
underscore), or the name exceeds 25 characters, append `_` and the 16-digit text
hash to the first 25 sanitized characters. Hash the original filename, including
relative directory separators, not the sanitized prefix. All 40,429 native
file records matched this encoding, including nested WebView paths and links.

File-state bits are separate from the name encoding. Matching Microsoft WCP
public symbols (wcp.dll 26100.9441; PDB key
`5D2C0A2BEA78B8EEBEC74A88722B0F541`) identify:

* `SetComponentFileStageFlag` at RVA 0x11a160 passes mask 1 to the file flag setter.
* `IsComponentFileLZMSCompressed` at RVA 0x8a990 queries file flags and tests 0x20.
* `SetPSFXFileMarkersIfNecessary` at RVA 0x1ab980 sets 0x100 for delta-kind 2
  and 0x200 for delta-kind 4. `GetDeltaDirectoryNameFromFlag` at RVA 0x1201a0
  maps kinds 1, 2, 4, 8 to `f`, `r`, `n`, and the empty directory respectively.
  Thus 0x100 and 0x200 record retained reverse/null delta payloads, not PE trust
  or manifest hashing algorithms. Reconstructing an ordinary file does not
  establish either sidecar marker.
* The boolean argument to the file flag setter at RVA 0x65008 is **clear**,
  not **set**: false computes old | mask; true computes old & ~mask. This is
  explicit at 0x65136 and 0x65281. Wrapper names alone do not establish polarity.

Other component/file flags are not yet fully mapped. Do not copy physical
compression/delta flags onto reconstructed uncompressed files, infer flags from
manifest compression, or substitute fabricated package state for a complete
servicing transaction.

## Canonical record planning

The component-state planner hashes the complete decoded manifest, emits the
full identity and staged file names for newly materialized raw payloads, and
records ownership separately for resident components. It must not overwrite a
resident component's CF/f! storage state. The deployment planner verifies each
root manifest's S256H against the CTL members of every source package catalog.
Catalog parsing is membership extraction, not signature or certificate-trust
verification. Existing source secondary bytes are preserved exactly.

The pinned update produces 10,320 new component descriptions, 1,575 deployment
descriptions, and 19,913 component-owner edges. These are planned records, not
an applied or boot-validated transaction. Package states, supersedence, winner
indexes, and declared component lifecycle actions remain separate requirements.

Aggregate package transport names `update.mum` and `update.cat` are not their
CBS store names. Store both under the full package identity
`name~token~architecture~culture~version`; use the canonical catalog name in
CatRoot too. Otherwise consecutive GDR, SSU and LCU stages overwrite the same
transport-named package even though their identities are different.

## Package owner encoding

Matching Microsoft CBS Core symbols (cbscore.dll from the same 26100.9441
servicing stack; PDB key `B116009B2EA16CB10CB19044D6959E1A1`) establish:

* `StorePackageOwner` at RVA 0x7c764 writes `(integration << 16) | state`
  at 0x7c943–0x7c957. The state is the per-owner CbsState, not necessarily the
  package's CurrentState.
* `PACKAGE_INTEGRATION_TYPE_MAP` at RVA 0x3668a0 maps `isolate`, `visible`,
  `hidden`, `liberate`, `delivery` to 1, 2, 3, 4, 5 respectively.
* `PARENT_INTEGRATION_TYPE_MAP` at RVA 0x365ad0 is a **different** enum:
  `standalone`, `separate`, `delegate`, `subsume` map to 1, 2, 3, 4.
* `CbsStateToString` at RVA 0x3b27c maps 0x40 to Staged, 0x70 to Installed,
  and 0x80 to Permanent. The pinned LCU's CurrentState is 0x70 while its
  self-owner value is 0x20080. Copying the predecessor's low owner bits would
  therefore incorrectly assume the new package must also be permanent.

A comparison of the pinned image's 3,619 package MUMs against their native
`Owners` keys found 4,355 present `hidden` edges with integration 3, two
`visible` edges with integration 2, and four omitted-integrate edges with
integration 2. Of 167 present `liberate` edges, 165 retain the containing
wrapper's name as owner (integration 4); the two ProfessionalEdition versions
have their own name as owner (also integration 4). Thus `liberate` is not a
rule to replace every owner name with the child package name. Native
`IsPackageSelfOwned` at 0xf00b0 also recognizes integration 4 independently of
whether the stored owner name equals the package name (0xf01a2–0xf01d5).

Owner intent is independent of current package state. For example,
Containers-Guest-Gated's en-US 26100.8972 package has CurrentState 0x70 and
records intent 0x70 on Containers-Client-Guest's en-US 26100.8972 package,
which has CurrentState 0x40 and a `disposition="detect"` neutral-parent
prerequisite. Other native edges have intent 0x40 while a different owner
keeps the child at CurrentState 0x70. Neither the containing package's state
nor the child's current state alone determines all owner values.

### Nested package parents

The pinned package inventory contains 19 root parent blocks with nested
parents. The MediaPlayer en-US wrapper at 26100.9457 requires the neutral
MediaPlayer package AND either the Client or Server en-US language-pack
package, all with revisionCompare GE against 26100.1742. Flattening all three
identities into one OR test loses the language prerequisite.

CBS `EvaluateIndividualParentBlock` (0x3ad70) reduces the direct identity
alternatives by maximum state (0x3ae19–0x3ae3f, 0x3ae88); recursively reduces
nested alternatives by maximum (0x3af4a–0x3af9c); and takes the minimum of
those two results (0x3afa1–0x3afa6). Separate root blocks are alternatives;
82 installed native packages have a root block whose identity families are
absent or staged and another whose family is installed. The parser preserves
both the block tree and each reference's block membership. The package
applicability predicate now preserves this AND/OR structure; it is not yet a
complete evaluator of all intended-state transitions or baseline rules.

On the pinned en-US 26300.9457 image, the KB5127648 closure now selects 1,184
LCU packages instead of 1,268. The difference is exactly 42 foreign-language
MediaPlayer wrappers plus their 42 child packages: each neutral prerequisite
matched, but its nested language prerequisite did not. All 84 distinct MUMs
are absent from the corrected plan. The LCU's 10,282 new components, 1,573
canonical deployments and 19,875 component-owner edges are unchanged, and
every source package catalog still contains its deployment manifest hash.

`GetParentIntendedState` (0x3b3f0) has additional exact/related-parent handling
and explicit staged-baseline behavior. Its diagnostics at 0x2f5dd0 and
0x2f5d70 say a staged baseline parent allows lower related revisions. Do not
infer those rules from the boolean tree reduction alone.

## Derived indexes

The native COMPONENTS hive has a version-specific cache under
`DerivedData/VersionedIndex/10.0.26100.9441 (WinBuild.160101.0800)/ComponentFamilies`.
Family children have `v!<version>` keys with a DWORD default value and a
`SomeUnparsedVersionsExist` binary value. These flags are not simply installed
or staged state: `PopulateComponentVersionedIndexKey` in WCP tests manifest
properties such as Fusion, boot-critical, single-instance files, servicing stack
and store content. SOFTWARE's SideBySide/Winners is separate; a staged-only
IIS family can appear in the versioned index with no winner. Do not turn every
indexed or newly staged component into an active runtime winner.

## Scoped package-update owner intent

The native inventory contains 4,526 package-reference edges whose containing
package name appears in the child's Owners values. Of these, 123 have owner
intent different from the containing package's CurrentState: 39 have staged
applicability, 72 detect applicability, and 12 selectable conditions. These
are not explained by the child's CurrentState either. For example, the neutral
Hyper-V ClientEdition package's Management-PowerShell update has staged owner
intent while the identically named update in its en-US package has installed
owner intent. A global update-name OR loses this distinction.

A scoped native-manifest audit uses local `detectUpdate/update` references,
resolved parent-package scopes for `detectUpdate/parent`, and `detectNone`
defaults. The containing package's intent caps each update's intent. For the
baseline image, explicit default evaluation agrees with native owner words;
this does not establish that defaults preserve user-modified feature choices.
The planner accepts explicit selectable choices separately from applicability.

In cbscore.dll 26100.9441, matching PDB
`B116009B2EA16CB10CB19044D6959E1A1`, `CApplicability::Initialize` at RVA
0x4de04 appends repeated parent detectUpdate nodes to the detector array at
object +0x20 (0x4df3c..0x4dfce). `EvaluateParent` at 0x5634c initializes the
aggregate boolean true and leaves it false after any false detector
(0x56400..0x56416, 0x5682d..0x56851). Repeated detector siblings are therefore
**conjunctive**, not alternatives. Nested applicability children use a separate
array at +0x30; their alternative reduction is not implemented by treating all
XML children as one flat OR. The MonthlyBundles wrapper's two sibling version
predicates are a real input requiring this distinction.

`PlanCBSPackageOwners` and `windows.cbs_package_owners` implement the supported
scoped subset as a pure, failure-atomic planner. A current-code audit using the
original 3,619 MUMs, explicit baseline intended states, and all 3,619 target
identities produced 4,528 owner records: every name and complete encoded DWORD
matched the original SOFTWARE hive, with no target exclusions. The native hive
has 4,556 owner records; all 28 not emitted by package-reference planning are
self owners, requiring transaction-root/capability history rather than a guessed
incoming package reference. The audit's latest-family
parent resolution is an experimental input, not a complete CBS parent resolver.

Component predicates and removal-owner projection remain explicit errors.
This owner-intent subset is not capability execution, supersedence processing,
final package-state computation, or a registry writer.

### Liberated product owner projection

Native `CCbsExecutionObject::AddPackage` at 0x9787e checks integration 4;
at 0x97898 it compares the resolved child package's release type (+0x278)
with 0x12. Only for this combination does 0x978a1..0x978ad replace the
containing owner with the child identity string (+0x78). This owner is passed
to recursive AddPackage at 0x97996..0x979ac. `CbsReleaseTypeToString`
(0x90678) maps 0x12 through 0x9076a to the UTF-16 string `Product` at
0x295268. This proves the special projection rather than merely correlating
edition names or historical self owners. Both ProfessionalEdition versions
match their native self owners; ordinary liberated references keep their
wrapper names. Execution-package Initialize (0x9c67c..0x9c6f7) copies the
supplied owner, state and integration into parallel arrays without a further
release-type transformation.

### Edition-gated selectability and absent defaults

`CSelectability::ProcessCustomInformation` (0x3557c) recognizes
`EnableSelectabilityForEditions/EnableSelectabilityForEdition` and sets the
selector's +0x1c boolean when any entry matches. Offline `IsCurrentEdition`
(0x35890, offline branch 0x359a3) compares against both session strings at
+0x9b8 and +0x9c0 using `_wcsicmp` (IAT RVA 0x288dd0). These are explicit
session edition identity names, not an inferred marketing label or SKU.
`CCbsUpdate::IsSelectable` (0x53568) reads that boolean.

`GetApplicableSelectableState` calls IsSelectable at 0x53a19. On false, it
jumps to 0x53ac8, bypassing the default/user-choice and selector-disposition
logic. An edition-disabled selector therefore does **not** disable the child.
This is relevant to the removable wrappers with `disposition="absent"` that
permit selection only for IoT editions. The portable planner requires explicit
resolved edition names, validates the known custom XML shape, and ignores the
selector's default only on a proven edition mismatch. It rejects an explicit
choice on such a disabled selector. Namespace declarations are not condition
attributes; resolved element and attribute namespaces are still checked.

`GetApplicableSelectableState` loads the selector disposition from update
+0x1c4 at 0x53aae for an unselected update, while selected applicable updates
retain installed intent. The disposition can be absent, as in NetFx3, without
making a dependent `detectUpdate` predicate unsupported. Native
`CbsStateToString` (0x3b27c) identifies **0x00 as Absent, 0x20 as Resolved,
and 0x40 as Staged**; 0x20 must not be mislabeled absent. The planner can
query an absent dependency and retain selected content with absent disposition,
but still rejects emitting absent/removal owner records. It does not perform
capability planning or removal.

`absentIfCapabilityAbsent` is a boolean execution permission, not a change
to the default selection intent. `PopulateExecutionUpdates` dispatches reference
kinds at 0x9ad7a: package kind 3 goes to 0x9acc9; capability kind 5 goes to
0x9ad9e. The capability branch alone reaches the flag checks at
0x9ae34..0x9afe0, resolution and `PlanCapability`. `CDetectUpdate::Evaluate`
queries `GetInstallState` at 0x9feb2/0x9ff3d; GetInstallState queries
`GetApplicableSelectableState` at 0x5420a, independently of capability
execution. The owner-intent planner validates this boolean without executing
capabilities. Its ten capability-backed baseline dependency roots now match
native owner intent; this does not implement capability creation/removal.

### Owner aggregate is not CurrentState

`CalculateAllOwnersIntendedState` (0x97b68) masks stored owner DWORDs to
16-bit states (0x97c67..0x97c90), overlays execution owners by case-insensitive
name, and overlays the explicitly supplied owner last (0x97ddf..0x97e35).
It takes the maximum state (0x97e35..0x97e5f) and caps values above installed
to 0x70 (0x97e78..0x97e89). This is **owner intent**, not final package state:
in the original 3,619-package image, 92 packages are staged even though the
owner aggregate is installed. A baseline-only experiment capping owner intent
by direct parents' native states matches all 3,619 CurrentStates, including a
staged disposition for missing declared parents. This uses original final
states and a latest-family lookup, so it is not a transaction resolver or proof
that nested parents and version rules may be discarded. Four otherwise
mismatching NetFx2/.NET wrappers have absent neutral parents, not a demonstrated
update-component state override.

`PackageStoreMarkPackagePermanent` (0x1a864c) enumerates owner values and
compares the owner name to the package identity; only a self owner with low
16 bits 0x70 is promoted (0x1a87a2..0x1a87bb, 0x1a885c..0x1a886f).
Other integration bits are retained. Native SSU 9441 declares MUM permanence
but has self-owner 0x20070, while the native LCU has no MUM permanence
attribute yet self-owner 0x20080. Declared permanence and this owner promotion
are therefore not interchangeable.

### Parent version policy still requires a transaction resolver

`PopulateParents` (0x9f3f8) initializes the parent descriptor's revision-ignore
boolean (+0x18 in PackageParent, +0x10 in VersionCompareDescriptor) to true
at 0x9f484. It copies comparison operators from parsed XML at
0x9f4cf..0x9f4e8. `EvaluateVersionCompare` at 0x5a1b4 bypasses the revision
comparison when this boolean is true; major/minor and build comparisons still
run. PopulateParents clears it for explicit revision comparison on LCU packages
or references naming the LCU (0x9f6c7..0x9f773), and for hotpatch, revised
cumulative, and feature-gated RDX package cases (0x9f777..0x9f887). It sets
revision comparison to operator 3 when ignoring revisions (0x9f88b..0x9f891).
These runtime rules are not equivalent to a blanket exact identity test or
blanket latest-family substitution.

`EvaluateComparison` (0x5a29c) implements unsigned EQ/NE/GE/GT/LE/LT
as operators 1..6. Its separate output reports equality, not successful
comparison. `EvaluateVersionCompare` uses that output to proceed from the
packed major/minor DWORD (accessor 0x83490) to build (0x82ee0) and revision
(0x8d700): a successful unequal comparison returns immediately. For example,
build GE accepts 10.0.26200.1 against 10.0.26100.1742 even if revision GE or
EQ would fail in isolation. `parentIdentityMatches` implements this explicit
lexicographic rule; its content-selection role still does not implement the
runtime descriptor policy above. For OnDemand Pack (release type 13, label
0x2c6bf0), PopulateParents changes an otherwise exact, non-explicit build
comparison to GE (0x9f6a3..0x9f6c0).

`GetParentIntendedState` (0x3b3f0) clones the descriptor and sets revision-ignore
after encountering a staged **Baseline-marked** parent. Baseline is not a
synonym for an existing package: `GetPackageCurrentIntendedState` (0x18791c)
returns package flag +0x432 or obtains it from `PackageStoreQueryPackageAttributes`
(0x29144). The latter reads the package's `Baseline` registry DWORD at
0x292ac..0x292d7 (name 0x28df28). The original image contains staged and installed
Baseline-marked FODs, alongside unmarked existing packages. Pending state and
per-session target intent can override CurrentState; callers must not infer
this flag from the state source.

The range path at 0x3b6e8..0x3b775 permits lower related revisions after this
marker is found. Related identities are sorted descending by the swapped
identity comparator at 0x1570e0 before traversal. It retains the maximum
eligible state (0x3b7b1..0x3b7bc), stopping at installed intent. The exact path
also clones and sets the flag at 0x3b535..0x3b569, but then calls IsExactMatch
again at 0x3b5f4. IsExactMatch (0x5921c) checks only the three operators, not
the ignore flag. The true branch at 0x3b5fb goes directly to 0x3b808, which
writes the retained state from r14d (0x40). Thus this EQ/EQ/EQ path does not
enter related-version traversal, despite the lower-revision diagnostic. The
range path does not restart enumeration after relaxing revision; previously
rejected higher versions are not revisited.

Parent parsing initializes both root and nested disposition to detect (0x1004),
not staged (root 0x1c48d, nested 0xa5dd3). EvaluateIndividualParentBlock uses
maximum direct-identity state, substitutes explicit disposition for candidates
below installed unless disposition is detect, and takes the minimum of that
result and maximum nested-block state. Root blocks are alternatives. A missing
detect parent therefore returns absent from the parent evaluator; any later
staging floor belongs to package planning, not parent default disposition.
No-parent evaluation returns the unspecified sentinel 0x1000, which
GetApplicableState converts to installed at 0x5a902..0x5a916.

GetApplicableState (0x5a7c8) separately handles build-branch mismatch and related
superseding packages: after parent eligibility it enumerates relation flag 2
and queries intended states; a candidate above 0x50 leads to a 0x50 result
(0x5aa88..0x5aad8), or 0x40 in the special package/session flag path
(0x5aa1f..0x5aa83). Parent state alone is not final CurrentState.
SetParentRevisionApplicability (0x164bb4) also sets top-level parent ignore
flags to true at 0x164c38..0x164c5a, and has callers in Plan, InitiateChanges,
and action-list processing. These transaction mutations must be accounted for
before using populated descriptors to construct final package states.

### Portable parent-state primitives

`CBSParentStateIndex` takes an explicit effective-intent snapshot including each
package's actual Baseline attribute. `Resolve` requires an explicit populated
runtime comparison descriptor; it does not derive one from XML defaults or
package presence. It implements exact lookup, descending related versions,
lexicographic EQ/NE/GE/GT/LE/LT comparisons, and the staged-Baseline relaxation
above. `EvaluateComparison`'s continuation flag requires both success AND equality
(0x5a2e4..0x5a303): failed strict/NE comparisons at equal higher dimensions do
not proceed to a lower dimension. A fresh index is required when intents change.

`EvaluateCBSPackageParents` uses an explicit identity-to-intended-state resolver
and preserves the parsed tree. It distinguishes absent, resolved, staged,
superseded and installed/permanent inputs; pending/invalid states require query
policy first. No-parent returns 0x1000, not installed. Empty direct-identity
blocks are errors (0x3ae49); absent direct results short-circuit nested blocks.
Standalone bypass is explicit: native 0x3aeaf requires package +0x388 nonzero
and session +0x394 bit 0x40000000 clear. The XML integration alone is insufficient.
Even bypassed standalone blocks retain nested constraints. These primitives do
not yet populate transaction descriptors, compute owner-adjusted final states,
perform supersedence, or write registry records.

### Package execution state is separate from parent state

In `AddPackage`, owner intent (optionally capped by the caller at 0x96661)
is capped by applicability at 0x967d2..0x967dc. This target is passed from
rbp-0x7c at 0x97037 to `CCbsExecutionPackage::Initialize` (0x9707c), which
stores it at execution-package +0x74. There is no unconditional staged floor
in this path. Current state, stored at +0x70, instead comes from the session
target if present, otherwise pending/current state (0x96925..0x9693e), with
`EquivalentStateIfInvalid` normalization at 0x96941. That normalization concerns
negative invalid states, not ordinary staged/absent parent outcomes.

Initialize compares current and target using temporary 0x50-to-0x40 mappings
at 0x9c6f7..0x9c750, but preserves the original values at +0x70/+0x74. This is
action selection, not permission to rewrite superseded state as staged in the
package store. Stage-existing and absent/absent skip decisions precede package
creation (0x96a31, 0x96ab6); the former tests current state below staged, not
parent state. Separate stage/install calls and their transaction flags still
need to be resolved before these fields can construct a complete offline plan.

The parent integration enum is **not** the package-reference owner enum.
ProcessPackageParent passes table RVA 0x365ad0 at 0xa5ce7 to GetEnumStringValue;
its four records map ASCII labels at 0x297028/38/48/58 to standalone=1,
separate=2, delegate=3, subsume=4. Separate is the parser default. Named `set`
is copied to PackageParent +0x20 at 0x9f898..0x9f8a6; neither parent-state
reduction nor GetParentIntendedState reads that field. It remains manifest
metadata for other queries, not an extra state constraint here. The supported
explicit distributionCompare/serviceCompare XML forms are EQ.

Original-image cross-check: using the actual Baseline flags and original
CurrentStates as an explicit effective-state snapshot, populated-descriptor
rules for ordinary/OnDemand/explicit-LCU parents and no standalone bypass,
parent-tree reduction plus the original owner aggregate matches **all 3,619**
native CurrentStates. The first 3,615 manifests yielded 1,452 installed parent
results, 391 staged, and 1,772 unspecified/no-parent. The remaining four
language-pack/SecureStartup manifests with additional attributes were checked
separately after implementing those attribute contracts; all four parent results
are installed, and their owner caps reproduce the two old staged/two new
installed states. The NetFx2 language wrapper's missing neutral parent is
explicitly disposition=staged, integrate=separate: no implicit staged default or
post-parent floor is needed. This is baseline consistency evidence, not a
pending-state, target-update transaction, or boot proof.

## Explicit root actions and uncached applicability

In cbscore 10.0.26100.9441, `IsPackageSelfOwned` (RVA `0xf00b0`)
returns true for an **empty effective owner list**, not only a matching self
owner or an integration-4 owner (`0xf0152..0xf0184`). A matching self name
is case-insensitive and ignores the owner's low-word state (`0xf019d..0xf0232`).
An ordinary installed containing owner is insufficient. With CBSBLR enabled,
the optional preserved owner is self/integration 2 for an empty list; an
existing self name wins immediately and preserves its integration; otherwise
the last enumerated liberated owner name/integration is retained. Native
`PackageStoreGetPackageOwnerFlagsByIdentity` merges the second store's owner
values over matching first-store names and appends new names
(`0x3c120..0x3c226`); missing stores are not an error. Do not sort the resulting
owner list before applying the last-liberated rule.

Execution `Plan` at `0x99857..0x998ce` prefers the explicit action owner at
`+0x68`, otherwise uses this self-owned decision for actions whose state is not
`0x1000`; update-only actions do not gain an implicit owner. The CBSBLR branch
preserves the returned owner/integration; the other branch projects to self
and uses action integration. `0x999bd..0x999fc` passes these values to AddPackage.
`PlanCBSRootPackageOwner` implements the bounded additive stage/install case
with explicit runtime policy, independently of manifest permanence. It must
only be called for actual transaction-root actions, not every discovered child.
The initializer at `0x18ae58` writes the smaller SessionActionEx fields and is
not evidence that the execution-plan action's `+0x68` owner is mandatory.

Uncached `GetApplicableState` (`0x5a7c8`) first rejects a resolved branch
mismatch, evaluates parents, and converts the no-parent `0x1000` result to
`0x70`. Only when that result is at least `0x70` does it collect related
packages with flag 2 (`0x5a923..0x5a998`). `CollectRelatedPackages`
(`0x2c318`) combines persisted and tracked packages by family, deduplicates
identities, and compares the full packed four-part version: flag 2 is strictly
newer, flag 1 strictly older, flag 4 equal (`0x2c4f1..0x2c582`). The family
lookup normalizes its version to `0.0.0.0`; this is not parent revision-ignore
policy. A newer package's effective intended state greater than `0x50` yields
applicability `0x50`, or `0x40` only when both the package `+0x431` and session
`+0xa11` force-staging flags are true (`0x5aa1f..0x5aad8`). A staged newer
package does not supersede an older one. `CBSParentStateIndex.ApplicableState`
implements this uncached reduction, not the state cache or final CurrentState.

A baseline diagnostic incorporating this newer-version applicability still
matched all 3,619 native CurrentStates after capping by native owner aggregate.
Of the first 3,615 packages, applicability was `0x50` for 1,040, `0x70` for
2,184 and `0x40` for 391; the four special-parent packages added two `0x50`
and two `0x70` results. This uses the baseline CurrentStates as the effective
snapshot and previously validated parent outputs. It does not establish the
pending/session snapshot, force-stage flags, or target-update transaction.

### Parent update lookup is not parent applicability

`GetUpdatesFromParentPackages` (`0x58c80`) collects exact references directly
when all three operators are EQ (`0x58dac..0x58ec5`). For a non-exact top-level
reference it collects all related versions, then accepts a candidate if
`DoesMeetParentRule` succeeds for any root block (`0x58dc2..0x58eef`).
`DoesMeetParentRule` (`0x59f30`) is an **OR search** through direct identities
and then nested blocks; it compares family and the populated version descriptor.
It does not reduce parent intended states, check disposition, or apply the
staged-Baseline revision relaxation used by GetParentIntendedState. Thus neither
the parent-applicability reduction nor a latest-family shortcut selects the
correct update scopes.

Missing resolved parent packages are skipped (`0x58f4d..0x58f5b`). Resolved
packages of release enum 15 are appended; others inserted at the front. The
routine enumerates matching update names from all collected packages in a first
non-recursive pass, and only if that entire pass found none does it run a second
recursive pass (`0x59038..0x59137`). `InternalEnumerateUpdate` uses the name
case-insensitively (`0x161316`); its recursion flag gates traversal at `0x161485`.
These are scope-discovery observations, not a completed recursive lookup API.

The selected target closure has 537 parent identity references in 328 of its
1,190 packages. 118 references exactly name another selected target package;
114 exactly name a resident package. A direct-family diagnostic of 76 target
packages containing detectUpdate/parent predicates found 30 predicate
occurrences missing from all their declared parent families. All 30 names were
also absent from every resident/selected package's direct update declarations.
This does not establish runtime descriptors, recursive membership or transaction
state; it narrows the immediate scope-discovery investigation.

For child propagation, AddPackage writes its final capped target to per-session
package state `+0x48` (`0x97325..0x97330`), then passes that target into
PopulateExecutionUpdates (`0x9762d..0x97660`). That routine caps the resolved
applicable/selectable update state by the containing package target
(`0x9a96c..0x9a97c`), not by the original root request. Child owner states must
therefore be recomputed when containing package applicability changes. Parent
notification and planned-parent cache invalidation also occur in AddPackage;
a global fixed-point shortcut has not been established as equivalent.

### Parent-update scope API and recursive fallback boundary

`CBSParentStateIndex.ParentUpdateScope` and
`windows.cbs_parent_update_scopes` implement the identity-selection stage above.
They take explicit populated descriptors and return unique, exact-key-sorted
available identities, not the release-type-dependent native enumeration order.
The shared lexical version predicate is distinct from exact-lookup dispatch:
EQ/EQ/EQ with IgnoreRevision still dispatches an exact top-level reference, but
that same descriptor used by DoesMeetParentRule during another reference's
ranged search can accept a different revision. Focused counterexamples cover
this distinction, nested alternatives, nested-only families, and the absence
of intended-state filtering or staged-Baseline relaxation.

A native-reader audit of 4,557 distinct resident/selected MUMs (3,619 resident,
1,190 selected, 252 overlapping) completed scope selection using explicit
ordinary PopulateParents descriptors. It does not establish hotpatch, RCU, RDX
or subsequent session policy. The selected closure has 30 missing direct parent
update predicate occurrences, all globally absent among these MUMs. Across the
whole union, 20 additional missing occurrences have declarations elsewhere:
one in localized NetFx2 (no resolved parent), and 19 in localized NetFx4 WCF
(whose sole resolved parent is its neutral WCF package). The only declared
backlink to that neutral WCF family is the localized package with separate
integration. This rejects the hypothesis that those missing declarations are
necessarily supplied by delegated children; global name lookup would not be a
valid repair.

The recursive fallback in InternalEnumerateUpdate does not traverse package
reference children indiscriminately. At `0x161492..0x161581` it combines
PackageReferencingChild arrays from package `+0x4c8/+0x4d8` and per-session
package state `+0xa8/+0xb8`. Entries with parent integration below 3 are skipped
(`0x1615a7`). Intended state at least 0x60 requires IsChild; 0x50 is skipped;
lower states use IsPackageActive (`0x1615eb..0x161810`). IsChild resolves the
child and calls its IsParent (`0x59288..0x592a2`), which ORs
DoesMeetParentRule over parent blocks (`0x59e75..0x59eb7`). IsPackageActive uses
GetPackageBestTopOwner and requires its state at least 0x60
(`0x3afde..0x3aff6`). AddReferencingChild (`0x802c8`) keeps package and session
backlinks separate, avoids duplicates, and stores the supplied parent
integration; the child predicate is initially uncached (-1).

### Selected-target propagation diagnostic, not transaction proof

The selected package-reference graph is acyclic over all 1,190 targets, and
contains only one selected version of each family. No target has a strictly
newer resident installed version. With ordinary populated descriptors and
resident CurrentState as the initial snapshot, all three explicit roots have
parent state 0x70; target parent results are 862 unspecified, 327 installed,
and one staged (Containers-Client-Manager). No standalone bypass is required
for those root parent results. All 254 resident Updates selection values are
0xff; this observation is not a general selection-default rule.

A read-only diagnostic, retaining named resident owners, overlaying computed
reference owners, adding explicit root self owners, and propagating containing
package caps changed the staged target count from 57 to 103, 127, 144, 170, 194,
202, 208, 210, then 212. At that point 978 targets had installed intent, all 252
already-resident selected targets retained their original state, and recomputed
target parent states were unchanged. This exposes the incorrectness of a single
all-installed child pass. It does NOT establish equivalence of fixed-point
iteration with native execution planning: delayed supersedence, session policy,
root ownership policy and deployment actions remain separate requirements.

SupersedeLowerVersion (`0x9b944`) collects strictly older family identities with
CollectRelatedPackages flag 1 (`0x9bb08`). Its normal path considers effective
intended state above 0x50 for a 0x50 target, with additional session and execution
flags (`0x9bd81..0x9be4f`). It has distinct removal, maintenance and delayed-LCU
paths; it is not an instruction to lower every historical package owner to
staged. The resident checkpoint LCU's self owner is 0x20040 while the resident
current LCU's self owner is 0x20080; this snapshot alone does not establish the
state immediately after a new LCU transaction.

### State-bearing update detection

Native CDetectUpdate::Evaluate (`0x9fab0`) returns both a predicate and an
effective state. Parent queries aggregate the maximum intended update state
and stop on a satisfied predicate (`0xa0374..0xa03a6`); no match retains zero.
ProcessDetectGroupType initializes the threshold to 0x60 (`0x2020c`), which
EvaluateState (`0x8befc`) interprets as intended state >=0x70. Explicit detector
threshold attributes remain unsupported rather than assuming this default.

CApplicability::EvaluateParent starts its fallback from XML disposition. A
failed detector with disposition detect (0x1004) contributes its actual state
to a minimum (`0x5682d..0x56851`), not an implicit staged floor. The XML enum
map at `0x366a30` confirms absent=0, staged=0x40, superseded=0x50,
installed=0x70, installRequested=0x60, and detect=0x1004. Repeated detectors
inside a block are conjunctive; separate applicability blocks are alternatives
(EvaluateApplicability, `0x551a0`). Selectability caps the resulting state and
cannot override failed applicability.

Local references call GetInstallState with its containing-cap flag zero
(`0x9fea7`, `0x9ff32`). Parent references call the public GetRealInstallState
wrapper (`0x534c0`), which passes flag one (`0x534ea`). The underlying function
only applies QueryPackageIntendedState's minimum when that flag is set
(`0x54224`, `0x54413..0x544df`). Emitted execution updates separately take the
containing target minimum at `0x9a96c`. Thus memoized local update applicability
must not be prematurely capped by the containing package.

The owner planner now retains detector states, separates raw local queries
from capped parent queries and owner emissions, and accepts explicit 0x50
containing intents. Missing/absent detect results still fail if they would emit
an owner requiring removal; this is not silently replaced by staging. Failed
detectNone with no resolved state is rejected. Focused regressions distinguish
0, 0x40, 0x50, 0x70, parent MAX from detector conjunction MIN, applicability
alternatives, local-versus-parent caps, and selectable overrides. A fresh native
media validation retained exact equality for all 4,528 resident owner DWORDs
across 3,619 packages. Initial selected-target planning produces 1,536 edges
(126 staged, 1,410 installed) with explicit initial parent caps. Neither result
is a completed execution transaction. The earlier cap-propagation diagnostic
used the old, prematurely capped local evaluator and is no longer evidence for
the corrected evaluator's final target state distribution.

### Execution ordering and persistence boundaries

The native execution path is not a single traversal of package references.
AddPackage first combines named resident/execution owners with the explicit
owner request (`0x96608`), applies the supplied ceiling (`0x96658..0x9666e`)
and package applicability (`0x9670e`, `0x967d2..0x967dc`). It publishes the
resolved target into session package state +0x48 (`0x97330`) before processing
MUM servicing (`0x9733f`), populating execution updates (`0x97660`), and
recursively admitting queued children (`0x979ac`). ProcessMumServicing invokes
SupersedeLowerVersion only for eligible action 2/3, with package +0x90 and
+0x164 both zero (`0x8fbe6..0x8fc0e`), then marks +0x164 to avoid repetition.
This ordering matters: a completed target list cannot be used as the initial
parent-state snapshot for every recursive admission.

ProcessPackageWatchList (`0x6ea84`) revisits execution packages whose package
or update change flags are set and whose dependents have not been processed.
It calls CollectAffectedDependentPackages and AddPackage with no explicit
owner, unspecified requested state/ceiling, integration 2 and the notifying
execution parent (`0x6eb51..0x6eb9b`). After a pass containing dependent
admissions it restarts the scan (`0x6ec1f..0x6ec22`). The dependency collection
is not a global update-name OR: changed-package dependents must satisfy IsChild
(`0x6ed29..0x6ed99`); reverse-update candidates additionally require effective
intent >=0x40 and the native child/delegation filtering
(`0x6eef7`, `0x6ef99..0x6f041`). This establishes an event-driven replanning
loop, not equivalence to the earlier blanket cap iteration.

MergeExecutionPackage replaces an existing named owner's requested state
(`0x12c468..0x12c477`), rather than taking an unconditional historical maximum.
It marks dependent state dirty when the effective target changes (with 0x50
mapped to 0x40 only for that comparison), resets processed flags and retains
the actual target at +0x74 (`0x12c48f..0x12c546`). Thus the pure owner planner's
MAX of simultaneous reference intents must not be used as the temporal merge
rule for repeated execution passes. The pinned selected inventory has 1,536
package-reference requests and 1,536 unique containing-owner/child pairs, so
intra-pass duplicate-owner request order is not exercised by that inventory.

FinalCommitPackagesState uses the actual target without a 0x50-to-0x40
normalization (`0x11686c..0x1168a9`); pending install/uninstall states are a
separate conditional branch. Its persistence mask is 0x27f (`0x1168d2`).
PackageStorePersistPackage applies an owner ceiling only when mask bit 0x100
is present (`0x6b78a..0x6b79e`), so that final mask does not implicitly cap all
owner states to CurrentState. StorePackageOwner iterates the execution owner's
parallel name/state/integration arrays, optionally caps state, writes
(integration << 16) | state, and deletes zero-state owners in the nonpending
store (`0x7c8ca..0x7c969`, `0x7ca20..0x7ca58`). Unmentioned resident owners
are not erased by this loop. These are prerequisites for the eventual
transaction writer, not evidence that writer or delayed/pending execution is
implemented.

### Manifest-resolved metadata is a separate persistence phase

The matching 26100.9703 cbscore build (PDB
`A3649FD182275D7156E38C3A438791D71`) has a distinct manifest-resolution
commit. `ResolveChain` passes state `0x20` to `CommitPackagesState` at
`0x1274cc`; `StageChain` passes `0x40` at `0x12806b`. These calls must be
interpreted through their control flow, not their linear address order.
`CommitPackagesState` selects `0x229` for the resolved commit and adds
owner-ceiling bit `0x100` below state `0x50`, producing `0x329`. This is
not the final installation mask and does not authorize permanent/installed
owners, install timestamps, or transaction-completion records. Do not reuse
the older 9441 RVAs for this build.

The private `package_store.star` metadata planner derives `PackageIndex`,
`PackageDetect`, `UpdateDetect`, and `ComponentDetect` without any lifecycle
writes. A control over 3,599 real registered packages compared all 7,021
value records in those four indexes, including types, without mismatch.
Foundation/Product release types also populate the System/Product indexes.
PackageDetect stores parent integration (default/separate=2, delegate=3,
subsume=4); standalone omits its direct identities but retains nested rules.
UpdateDetect indexes parent update references, not local references.
ComponentDetect keys contain the normalized component family version and
its full identity hash, not the version-omitting Winners hash. Its string
value uses the base elevation: an alternative-target list can have CSI source
secondary flags `9` while the corresponding ComponentDetect values end in
`@8`. Substituting one encoding for the other is incorrect.

### Published state is not a confidence marker

CBS package and owner states are operational information consumed by Windows.
Resolved (`0x20`) is not a safe default for a constructed installation. A lower
state requires affirmative, package-specific evidence; lack of testing or an
unreplayed native phase is not evidence that a package is not fully installed.

The private writer `experiment_package_metadata` now preserves admitted final
stage/install dispositions after construction effects have been applied. It
retains checks of exact signed MUM/catalog membership, emitted p! pins, transitive
composition, c! backlinks, and actual manifest bytes/digests. Owner states retain
their independent requests and integration bits; they are not capped to the
package state. Existing source registrations are preserved. Unsupported states
fail before publication rather than falling back to Resolved.

This does not make manifest publication alone an installation operation. The
caller applies files, registry, installers and CSI effects before publishing
package dispositions. Outstanding runtime validation belongs in the external
report, not in an artificially lowered CBS registry value. Explicit stage-only
requests and validated removals remain distinct from installed packages.
Certificate-path checks also remain distinct from full trust/revocation policy.

### Historical Not Present observations were circular evidence

An earlier writer registered all new packages at `CurrentState=0x20` and capped
all new owner states at `0x20`. Native DISM then mapped CBS Resolved to Not
Present. Those queries read back our own inputs; they did not independently
identify missing payloads, installer effects, or a required lifecycle executor.
Earlier counts of 806 packages/904 owners describe that historical experiment,
not the current publisher or a list of incomplete installations.

The later retry with installed-state overrides completed offered updates and
ScanHealth without component-store corruption, followed by clean shutdown. The
same ScanHealth ran about 90 minutes, beyond the 30-minute observer deadline.
A timeout therefore did not establish corruption or incomplete installation.
This is runtime evidence, not a matched proof of each state override: use the
actual admitted disposition rather than promoting every package indiscriminately.

A concrete missing effect must identify the affected package and contradictory
source/effect evidence. Blank install times, unrun checks, and literal
`incomplete` annotations are not such evidence. Fresh whole-image smoke remains
required after construction changes, with its status reported separately.

### Ordinary admission reduction and delayed LCU work

`CalculateAllOwnersIntendedState` (`0x97b68`) first loads the effective
store/session owner words and extracts low 16-bit states (`0x97c67..0x97c90`).
Existing execution owners replace matching store states (`0x97d6d..0x97d82`);
the concrete explicit owner request takes precedence over both
(`0x97ded..0x97e31`). MAX is across the resulting owners and is capped to
installed (`0x97e35..0x97e89`). An ownerless concrete request is used only
when there are no owners; an unspecified ownerless request then yields absent.
A zero-valued owner still counts as an owner for this fallback. Consequently an
ownerless supersedence request of 0x50 does not itself overwrite a permanent
self-owner: applicability is the independent limit on the package target.

AddPackage flag 0x40 raises a named request to its effective **store** owner
state (`0x9657d..0x965de`), not the current execution overlay. The queried
`PackageStoreGetPackageOwnerState` (`0x1a6740`) calls the store/session owner
loader (`0x1a67dd`) and returns zero for a missing owner (`0x1a6834..0x1a6846`).
The explicit bypass-owners argument skips aggregation (`0x965e1..0x965ec`),
not the later caller/applicability caps. `ResolveCBSPackageAdmission` implements
this ordinary, resolved-state reduction without changing either owner layer.
It returns the effective request, owner aggregate, caller-capped state, and
applicability-capped target separately. It is not an execution-item merge,
watch-list scheduler, removal authorization or registry writer. Pending states,
unresolved applicability and ambiguous duplicate owner layers are rejected.

The recursive child queue preserves incoming flag 0x40: AddPackage passes the
flag-derived boolean at `0x97480..0x97489`, `0x97608` to
PopulateExecutionUpdates, which adds 0x40 to queued child flags at
`0x9b31e..0x9b326`. This is explicit request policy, not an unconditional
monotonic owner-state rule. Repeated ordinary named owner requests can decrease.

SupersedeLowerVersion queues LCU requests rather than immediately admitting
all old LCUs. An old LCU selected for absent goes into the execution object's
+0x390 queue (`0x9c052..0x9c0dc`); one selected for superseded goes into +0x350
(`0x9c10b..0x9c1ec`). Other packages follow the immediate AddPackage path.
Plan drains these as ownerless requests, state 0x50 with owner bypass false,
then state 0 with owner bypass true; both use ceiling 0x1000, integration 2,
the notifying execution parent, and skip-MUM true (`0x9a3aa..0x9a47b`).
The later drain is conditional on DrainDelayedSupersedenceAfterReservicing
(`0x9a379..0x9a387`); the earlier drain/clear phase must also be accounted for.
This ordering and the feature's effective runtime value cannot be replaced by
simultaneously marking all older package families staged or superseded.

`CBSUpdateStateIndex` exposes the existing scoped detector evaluation as a
resolved execution snapshot, including absent (0) and resolved (0x20) packages
that have not yet been admitted. Each query reports raw local state and the
containing-target-capped state separately. Parent lists, edition names and
selectable choices are snapshotted; immutable manifests remain shared. An event
planner must rebuild the index after changing effective intents or scope policy.
Owner projection uses the same evaluator but retains its staged/superseded/
installed input restriction and explicit removal error. A regression passes
0 -> 0x20 -> 0x40 -> 0x70 -> 0x50 -> 0x40 parent snapshots through scoped update
detection and ordinary named-owner admission, verifying the downward transitions
are not lost to a historical MAX. This is a reduction-sequence check, not a claim
that automatic native dependency scheduling or a complete transaction exists.

The first deferred LCU drain follows the task-root loop unconditionally
(`0x99a33..0x99b40`), in superseded-then-absent order. With
DrainDelayedSupersedenceAfterReservicing enabled it clears both queues immediately
(`0x99b42..0x99b68`); a later drain after re-servicing handles new entries.
The compiled current-state functions for CBSBLR (`0xef004`, feature id
0x3a4c36d) and DrainDelayedSupersedenceAfterReservicing (`0x11a094`, feature id
0x3889761) treat the underlying feature API's default state zero as enabled,
state two as enabled, and state one as disabled. This establishes compiled
defaults, not the effective host/session feature overrides. Execution policy
must remain explicit rather than silently selecting a branch from the MUM.

`TranslateStageChangeToAction` (`0x3aab0`) normalizes superseded 0x50 to
staged 0x40 for action selection, without altering the stored target. Its
12-row table at 0x368760, terminated by (0x1000, 0x1000, 0), maps:

| From | To | Action |
| --- | --- | --- |
| 0 | 0x20 / 0x40 / 0x70 | 1 / 2 / 3 |
| 0x20 | 0 / 0x40 / 0x70 | 9 / 2 / 3 |
| 0x40 | 0 / 0x20 / 0x70 | 8 / 7 / 3 |
| 0x70 | 0 / 0x20 / 0x40 | 6 / 5 / 4 |

Equal normalized states select zero unless the separate action-control flags
change the decision. ProcessMumServicing's action 2/3 gate therefore includes
initial staging as well as installation. That does not by itself imply an
older owned package becomes superseded: its independent applicability still
observes whether a strictly newer version has effective intent above 0x50.

### Related-package order and published update state

In the 26100.9441 CBS binary, `CollectRelatedPackages` (RVA `0x2c318`)
first takes identities from `PackageStoreGetRelatedPackagesFromPackageID`
(`0x2ad0c`), then appends tracker identities not already present, and only then
filters versions. The store reader enumerates numeric values in the
`PackageIndex/<family>~0.0.0.0` object using `EnumNumericValue`; this is not a
sort by version. Flags 1, 2 and 4 select strictly older, strictly newer and
exactly equal versions respectively. `SupersedeLowerVersion` uses flag 1.
Its ordinary request is superseded for an older effective intent above
superseded. The release-type-specific absent branch is separate and is not
permission to remove all older staged packages. `IsLCUPackage` (`0x81360`)
compares the identity name case-insensitively to `Package_for_RollupFix`;
it does not classify every LCU child as a delayed LCU root.

Update detection has a second, session-published state layer which is distinct
from an immutable metadata applicability snapshot. `CCbsUpdate::GetInstallState`
(`0x54178`) first obtains `PerSessionUpdateState` via `0x54b60`. A concrete
`+0x0c` value is returned at `0x54384`, bypassing fresh applicability evaluation;
only missing/unspecified state falls back to `GetApplicableSelectableState`.
The optional parent-query cap is applied afterward at `0x54413` through
`0x544df`. Thus "local query does not apply a containing cap" does **not** mean
that a local query can ignore an already-published, capped update target.

`PopulateExecutionUpdates` iterates the package update array (`+0x2c8`, count
`+0x2e0`), obtains/creates session update state at `0x9a6f7`, evaluates direct
applicability at `0x9a78d`, applies the containing cap, and writes `+0x0c` at
`0x9ac56` before enumerating that update's children. With its preservation
boolean enabled, a new target above staged is additionally limited to staged
when the old update state is at most staged (`0x9ac32`–`0x9ac44`).
`GetApplicableSelectableState` also has a separate applicability-result cache:
`+0x10` is the applicability classification and `+0x14` the detected state
(read at `0x539fd`, written at `0x53bf2`). Its invalidation/session-policy rules
must be modeled independently of the published target.

`CBSUpdateStateIndex` and `windows.cbs_update_index` represent explicit snapshots,
not an automatic native cache lifecycle. `WithPublishedUpdates` / `with_updates`
allows the caller to publish resolved update targets (or clear an override with
unspecified), and ordinary `UpdateState` / `state` honors them before metadata
evaluation. `ApplicableUpdateState` / `applicable` bypasses only the queried
update's publication; detectors still honor published dependency targets. It
does not represent the separate applicability-result cache. The `with_states`
operation invalidates all derived memo results while preserving parsed metadata,
explicit parent/selection policy and published targets. This is useful for read-only experiments,
but it must not be treated as a native AddPackage/watch-list scheduler. An
ordered root/child experiment that recomputes metadata on every package change
is still insufficient transaction evidence, even if all final package and
owner equations are stable. Published update targets and applicability-cache
invalidation remain necessary discriminators.

For the ordinary finalized execution path, the applicability-result cache is
bypassed: `GetApplicableSelectableState` tests session `+0x418` at `0x5393e`
and goes directly to metadata evaluation when nonzero. `CCbsSession::Finalize`
sets this field to 1 at `0x1811e7`, following `FinalizeOCs`, and later calls
`ResetSessionPackagesTargetStates` at `0x1820e8`. `IsLocked` (`0x16199c`) includes
this field (as well as `+0x52c`). This narrows the need to emulate applicability
cache invalidation during ordinary locked execution; it does not bypass the
published update-target lookup in `GetInstallState`.

`InvalidateApplicabilityCache` (`0xa149c`) resets per-package `+0xe8` to
unspecified and each update's classification `+0x10` to zero and detected state
`+0x14` to unspecified. With CBSPlan2 enabled it also clears planned-parent
state. It deliberately leaves published `+0x0c` intact. Conversely,
`ResetSessionPackagesTargetStates` (`0x19ac80`) resets per-package target `+0x48`
and published update `+0x0c`, but does not clear applicability classification.
The package `+0x368` test against 3 in the applicability-cache gate is a package
type, not a dependency or integration state: `PrepareInitializeEx` assigns the
`_CbsPackageType` argument there, and `CbsPackageTypeToString` (`0xeb234`) names
3 `PackageTypeXmlString`, 2 `PackageTypeManifest`, 1 `PackageTypeExpanded`,
0 `PackageTypeCabinet`, and 4 `PackageTypeExpandedWithMum`.


### Parent relationship filters and component self-update predicates

`IsChild` (`0x5923c`) resolves the candidate package and calls its `IsParent`
(`0x59e0c`). The latter tries every top-level `DoesMeetParentRule`
(`0x59f30`), whose nested rules are alternatives. Unlike update-scope exact
lookup, EQ still honors IgnoreRevision here, and nested-only families can match.
`ParentRelationships` / `windows.cbs_parent_relationships` exposes this
state-independent predicate separately from update-name candidate seeding.
On the pinned union, the two results differ for 20 packages; substituting
update scopes for relationship checks would lose real .NET/MediaPlayer edges.

`PackageStorePopulateChildren` (`0x2bf74`) loads the versionless PackageDetect
numeric values, retaining children whose effective store/pending state is >0
(`0x2c130..0x2c155`). These are candidates, not automatically valid children.
`CollectAffectedDependentPackages` checks/caches IsChild. Its update branch
looks up UpdateDetect (`0x6f230`), rejects candidate effective intent <0x40,
and then applies the child filter or the neutral-language shortcut when the
notifying package is currently >=0x70 and has a parent integration >=3.
`ProcessPackageWatchList` marks processed after dependent admissions, clears
update-dirty flags, and also calls the separate satellite helper (`0x120ee0`).
A diagnostic of the ordinary pinned prefix found 1,530 affected persisted
children, 529 outside its recursive admission closure. This is evidence that
the prefix is incomplete, not a completed filtered watch-list transaction.

The newly reached .NET updates contain actual `updateComponent` predicates,
not unconditional payload declarations. `CDetectComponent::Evaluate`
(`0x16fd70`) initializes detected state to absent, while the Boolean is supplied
by `EvaluateSelfUpdate` (`0x170058`) and `ComponentAnalyzerEvaluateSelfUpdate`
(`0x101970`). Multiple identity targets are alternatives (stop on true).
`CheckInternalDetectComponentApplicability` (`0x1015fc`) considers strictly
lower versions in ascending order. It selects effective owner arrays according
to analyzer transaction state; merely having a component manifest is not
installed-owner evidence. Active owners have bit 0 set or elevation 0x80;
ordinary elevation-only owners can advance branch boundaries but do not alone
supply the active-predecessor requirement.

The elevation map (`0x365b20`) is revision=2, distribution=4, build=8,
version=0x20, install=0x80. The request's low flag bit is removed before branch
comparison. Install succeeds without a predecessor. Otherwise an active lower
predecessor is required. The latest lower owner at each applicable elevation
sets the branch boundary; active owners contribute all boundaries.
`CheckBranchApplicability` (`0x933a0`) first checks major/minor using accessor
`0x83490`, then build via `0x82ee0`, then distribution via the constant-zero
accessor `0x8d6e0`. At or above a requested boundary, a nondecreasing field
succeeds; below it, equality is required before proceeding to finer boundaries.
The target version itself and higher versions cannot satisfy this predicate.

`LoadComponentOwners` (`0x699c`) enumerates component deployments, then
`LoadDeploymentOwners` (`0x65c4`) consumes owner type 1/2 separately. The
owner's extra source string is parsed numerically; no extra string uses 0x80
(`0x677b..0x67dd`). The existing image's installed i! source records carry 8,
9, or 128. The component snapshot API takes explicitly resolved effective owner
elevations, not package states, and does not pretend to perform native analyzer
transaction changes. Unknown/malformed inventory fails closed; a missing
snapshot is not treated as a known-empty one.

`CBSComponentStateIndex` and `CBSUpdateStateIndex.WithComponentState` retain
full CSI family distinctions, including type/versionScope. The Starlark
`with_components` operation copies an explicit identity/owner inventory,
invalidates derived update applicability, and preserves published session
update targets. Focused regressions cover branch boundaries, exact/self and
higher-version exclusion, staged-presence versus active ownership, alternate
identity targets, full family isolation and snapshot/publication precedence.
A fresh read-only check of all 627 resident updateComponent updates produced
565 installed and 62 staged raw applicability results, with zero mismatches
against their persisted installed i! deployment-source presence after the
containing-package cap. This validates the resident snapshot, not the missing
analyzer overlay lifecycle, servicing writer, or first-boot result.


### Component analyzer owner-event reduction

The same inspected CBS binary separates pinned sources from installed sources.
`ComponentAnalyzerChangeDeployment` (RVA `0x6af28`) enumerates deployment
components, takes the first update-component target's elevation (or 128 when
none), checks the component-watch index, and calls `MergeComponentChange`
(`0x102950`). This is not an unconditional inventory-wide rewrite.

`MergeComponentChange` inserts a source/elevation/action record into the version
change array at `+0xc8` only when its exact tuple is new; comparator `0x102260`
is case-sensitive and includes both integer fields. It then invokes
`CalculateNetChanges` (`0x1012d4`). That reduction starts from the original
installed (`+8`) and pinned (`+0x48`) arrays, not a previous reduction. Actions
1/2 add/remove pinned ownership; 3/4 add/remove installed ownership. Installed
changes also call `AnalyzeComponentChange` (`0x100ef4`) to enqueue dependent
packages associated with strictly higher component versions. That scheduling
is separate from this pure reduction.

`AddChange` (`0x100bac`) compares source string and elevation via `0x102200`;
it preserves a matching owner rather than replacing it. `RemoveChange`
(`0x103220`) removes the first exact match, otherwise consumes the first
null-source RTM placeholder; absent both, it fails. Null-source matching does
not compare elevation. Empty strings are real names, not null placeholders.
With no events, `+0x188` selects original ownership; with events it selects the
new working arrays (`+0x108` installed, `+0x148` pinned). Only installed ownership
participates in `CheckInternalDetectComponentApplicability`.

`windows.cbs_component_owners` implements this bounded reduction on explicit
inputs. Its event list must be the cumulative transaction prefix with the
original baseline. In particular install/remove/install of the same tuple
does not replay the last install, because that event already exists. The
returned installed elevations can be supplied to `with_components`; pinned
sources must not be included. This API does not load or synthesize an RTM node,
choose deployment actions, implement component watches or reevaluation,
commit CSI changes, or establish a complete CBS transaction.


### Ordinary population prefix and MUM action lifecycle

`PlanCBSOrdinaryPopulation` joins resolved owner admission, named execution-owner
replacement, snapshot updates and ordered publication into one failure-atomic
prefix. Its explicit applicability/MUM callbacks retain recipe policy outside
native reductions. All updates publish before child references are admitted;
children drain depth first. MUM-generated immediate requests precede publication,
whereas explicit deferred requests drain after roots and their children. Missing
references require an explicit omission list. This is not a transaction commit:
watch lists, satellites, component execution, force/pending/CBSBLR policies,
feature-controlled staged restaging, permanence and CSI persistence remain
separate requirements.

In the pinned CbsCore, `TranslateStageChangeToAction` (RVA `0x3aab0`) normalizes
permanent `0x80` to installed `0x70` and superseded `0x50` to staged `0x40`.
Installed to staged selects action 4, not stage action 2. However this table is
**not sufficient to derive MUM eligibility**:

- Execution-package `Initialize` (`0x9c5e0`, branch `0x9c774`) selects install
  action 3 for an unchanged installed item. Equal-state `Merge` does not.
- `MergeExecutionPackage` (`0x12c4e8`) tests the preceding MUM-processed flag
  (`+0x164`). When set, action selection uses the previous execution target and
  clears the flag; otherwise it uses the original package state. Thus neither
  a once-per-item latch nor always comparing to the original state is correct.
- `ProcessMumServicing` (`0x8fbc8`) invokes supersedence for actions 2/3, then
  rechecks `MightReinstallLowerVersions` (`0xb2324`). Actions 4/5/6 invoke lower
  version reinstallation. It sets the processed flag **after** immediate
  recursive work returns. A nested admission can change the action and flag
  before the second check; even skip-MUM admissions still merge and clear flags.
- Execution dirty comparison is separate: it normalizes superseded to staged
  but does not collapse permanent to installed.

The MUM callback receives the actual action, so callers must provide or reject
lower-version reinstall policy rather than silently applying supersedence in its
place. `MUMPopulated` records whether any callback completed, `MUMPasses` counts
completed callbacks, and `MUMProcessed` is the current, merge-resettable flag.
Regression tests distinguish initialization from equal-state merges, processed
and skipped installed/staged/installed sequences, reentrancy, permanent dirty
comparison, and parent publication before child detection.

Earlier experiments produced 13,859 admissions / 3,096 execution items and equal
4,557 final package targets under two simplified MUM gates. The later gate's 938
MUM items (versus 2,561 previously) was incorrectly described as a corrected
native witness: it omitted initialization-only install servicing, reinstall
callbacks and merge-reset behavior. Those counts do not validate native MUM
policy. Fresh replay must use the complete lifecycle and explicit action-aware
callbacks; unchanged targets in the older experiments do not remove this need.

### Satellite watch-list identity and ordering

`IsPackageChildSatellite` (`0x162140`) compares type-2 requirement packages with
satellite capability **name and version**, not merely name. The second field
is identity offset `+0x2c8`, confirmed by `CCbsIdentity::GetAttribute` (`0xd635d`)
and its `Version` literal. Capability language/architecture are not compared
on that branch. Type-1 declaration packages instead intersect satellite language
or architecture declarations case-insensitively.

`EnumerateStoreSatellitePackages` (`0x14f1d4`) calls the package-store capability
enumerator (`0x37e04`) with no filters. It traverses CapabilityIndex child keys
then values in store enumeration order, resolves each package, checks satellite
status, then applies the child predicate. Manifest inventory order is not a
substitute. `ProcessPackageWatchListPackageSatellites` (`0x120ee0`) recursively
admits these packages with no owner, integration 2, ceiling `0x1000`, and the
**notifier's per-session intended state** (`[execution+0x98]+0x48`) as request.
The ordinary dependent watch-list request uses `0x1000` instead; conflating these
requests loses the ownerless fallback behavior.


### Ordinary watch-list scheduling

The optional population `Watch` policy joins notifications to the same execution
items, owner overlays and immutable publications, rather than starting a second
population from final package targets. `ProcessPackageWatchList` (`0x6ea84`)
scans execution insertion order. It skips processed items, selects package-dirty
or update-dirty items, collects dependent packages, then for each dependent drains
its admission and recursive satellites before continuing. Only afterward does it
mark the notifier processed (`+0x168`) and clear update dirty bits (`+0x170` and
update `+0x8c`). Package dirtiness (`+0x16c`) remains sticky. Any ordinary package
merge clears processed even when its target is unchanged (`0x12c510`). The scan
repeats if it made dependent admissions, and newly appended items participate in
the current pass.

Initial update dirtiness must not be inferred by comparing applicability against
the original package target. `AddExecutionUpdate` (`0x9c4ec`) marks an update dirty
when it has **no deployments**, or its initial current and intended states differ
after superseded-to-staged normalization. `MergeExecutionUpdate` (`0x12c65b`)
compares the previous execution update target instead. Initial current state is
`GetStartState` (`0x544ec`), followed by `EquivalentStateIfInvalid` (`0x8c6d8`),
not a fresh applicability query: the start routine first prefers a published
session update, then evaluates transaction deployment state. Pending/invalid
states require explicit resolution outside this ordinary planner.

`CBSOrdinaryWatchPolicy` requires explicit initial-update, dependent and satellite
callbacks. The Starlark `watch` dictionary exposes the same contract. Callbacks
receive independent notifier records and immutable update-index snapshots. The
scheduler bounds scans, admissions and recursive continuations together. It
rejects deferred MUM requests created during notifications because those require
additional transaction-queue policy; it does not silently drain them at an
invented point. It does not load watch indexes, identify children or synthesize
satellite requests automatically. Tests distinguish recursive admission order,
re-admission of already-notified items, sticky package dirtiness versus cleared
update dirtiness, initial deployment-free updates, callback snapshot isolation,
and bounded satellite cycles. Complete real-image watch policy still requires
native initial deployment state and the exact store/session inputs.

### Initial deployment state is a separate read model

Further inspection of the same 26100.9441 cbscore distinguishes the inputs needed
by `InitialUpdate`; these observations do not yet implement its complete policy:

- `CCbsUpdate::GetTransactionState` (`0x54ed0`) normally returns the minimum and
  maximum **deployment current states**. `GetStartState` (`0x544ec`) chooses the
  minimum if the maximum is no greater than the requested update target;
  otherwise it chooses the maximum. An existing session-update state wins before
  this aggregation. Neither an applicability result nor an original containing
  package state is an equivalent deployment inventory.
- A detachable selectable is specifically a selectable, capability-deployment
  update with `absentIfCapabilityAbsent` (`0xa9bf0`). If its first deployment is
  positive, transaction state goes through selection/applicability capped by
  that first state, rather than aggregating every deployment. Deployment-free
  updates use the same selection/applicability path, capped by the queried
  package intended state. Unselected state also respects the disposition and
  the stored selection's absent flag, which caps it at resolved (`0x20`).
- `PackageStoreGetUpdateSelectionState` (`0x2e77c`) reads the package's `Updates`
  value, clears bit 16 for the selection result, and returns that bit separately.
  A missing value returns `-1`; `0xff` instead asks for the metadata default.
  Those sentinels must not be conflated. All existing selection values in this
  image are `0xff`, but new packages and some resident updates have no value.
- Component (`0x7b7c`) and driver (`0x16bbf7`) deployment current-state bodies both
  call `GetDeploymentState` (`0x8120`). This enumerates the exact CSI deployment
  with flags 7 and filters its source primary by a **case-sensitive** comparison
  with the update's `package.update` string (`+0x1d0`). Inventory type 2 yields
  installed; type 3 yields staged; type 1 yields resolved unless package flag
  `+0x378` makes it staged. A registry-key abbreviation or another source for the
  same deployment is not an adequate match. The inventory type-to-registry
  relationship must be respected; the optional flag is not inferred from MUM
  permanence.
- Package deployment state (`0x6c64`) looks up the selected owner in the child's
  persisted owner array, then caps that owner's low-word state by the child's
  `GetTargetState` (`0x4d8f0`). The latter prefers per-session `+0x48`, then package
  pending target `+0x314`, then original `+0x2c0`; it is **not** an arbitrary
  execution-index publication. Normal references select their containing owner;
  liberated Product references select the child's self owner. A missing owner
  yields absent.
- Capability deployment state (`0x6088`) enumerates matching store capabilities
  and takes the greatest current state, stopping once installed. Capability
  current state (`0xa87b8`, with smart-pending false here) derives from original
  states of related internal packages, not their new execution targets. The
  detachable selectable path still applies its stored selection afterward.
- `EquivalentStateIfInvalid` (`0x8c6d8`) first negates a negative state. When the
  target is below that magnitude it returns the **positive magnitude**, not the
  original negative value. At or above the magnitude, invalid installed or
  permanent maps to staged, invalid staged to resolved, and invalid resolved to
  absent. Unsupported negative cases are not a license to guess recovery state.

`windows.csi_identity` and `windows.cbs_deployment_source` expose the bounded
native parsers for read-only inventory inspection. The source parser preserves
opaque secondary bytes separately from the primary and its hash; it does not
interpret arbitrary secondary data as an elevation. A fresh in-memory inspection
of the base matched all 4,143 deployment identities and all 6,037 `p!` source
hashes; every source had an exact component/driver manifest reference and a
matching `s!`, and 2,679 also had `i!`. There were no pinned-only sources in this
baseline. Exact source-qualified reference inspection found 3,358 staged, 2,679
installed and 1,572 absent component/driver references across resident and update
metadata. This is baseline inventory evidence, not proof of a completed watch
replay or a servicing transaction.

### Package publication and execution registration are separate

For cbscore 26100.9441, ordinary `AddPackage` writes its resolved/merged
package target to `PerSessionPackageState+0x48` at RVA `0x97330`, before
`ProcessMumServicing` (`0x9733f`) and `PopulateExecutionUpdates` (`0x97660`).
`GetTargetState` therefore sees these publications during initial deployment
queries and recursive package applicability; it is not limited to explicit root
requests. This publication does not register the execution object.

The execution array insertion at `0x97697` and identity-map insertion at
`0x976d5` occur after MUM recursion and update publication, but before package
reference child admissions (`0x979ac`). `IsPackageInExecution` (`0x11ccb4`)
searches that identity map. Immediate MUM admissions precede their outer first
admission in execution/watch order, while ordinary reference children follow it.
A recursive admission of the same identity before registration creates a
separate native object, rather than merging the unfinished one. The ordinary
single-object planner rejects that case explicitly; recursive merges of already
registered executions remain supported. This finding invalidates tests that
assumed an initially allocated object was already available for recursive merge.

### Capability and watch index inspection refinements

`ProcessSatelliteInfo` uses enum values 1=`declare`, 2=`require`, 3=`applyTo`
(table at `0x3661f0`, strings at `0x297810`). `PopulateCapability` copies that
classification to capability metadata `+0x5c`. Ordinary watch satellite scans
start only for type 2 with nonempty language or architecture requirements
(`RequireSatellites`, `0x124488`). Type 2 child matching compares capability
name and version, not package architecture/language. Type 1 intersection logic
in `IsPackageChildSatellite` is a distinct case, not the ordinary watch gate.
The store scan enumerates CapabilityIndex's immediate children and each child's
values, preserving registry enumeration order; it does not recursively treat
`Dependencies` subkeys as satellite entries (`0x37e04`, `0x38098`).

Update watch inclusion is narrower than a standalone parent-rule check.
`GetWatchingPackages` requires the candidate to occur in the package's cached
referencing-child list, then checks/caches `IsChild`, unless its special neutral
architecture shortcut applies. The shortcut tests an empty **architecture** at
identity `+0x248`, not neutral language. Cached children from `PopulateChildren`
come from PackageDetect's versionless family key and require effective persisted
current/pending state greater than zero. `NotifyPresenceToParents(...,1,1)` adds
newly present children to per-session storage (`+0x90`), distinct from the package
cache (`+0x4b0`). Do not replace these lists with all final-state relationships.

Capability deployment current state first enumerates matching store packages
with exact name, architecture and language filters (`CheckCapabilityMatch`,
`0xa90d4`; empty fields are exact empty matches in this mode). The optional
version filter compares the high version word. `QueryPackageIntendedState`'s
boolean permits smart-pending lookup; it does **not** mean original-only state:
when there is no smart-pending result it falls back to session target lookup.
Enumeration considers staged and above, with CBSCDS controlling inclusion of
superseded entries, and omits satellite packages. The returned capability's
current-state query separately uses original related-package current states.
For the pinned baseline, the eleven update capability identities are name-only;
ten have neutral matching related families with staged/installed states and
NetFX3 has no matching store entry. This is baseline evidence, not a general
name-only or final-target capability algorithm.


### Bounded watch replay and later execution state

The first complete ordinary watch experiment on the pinned image converged at
46,142 admissions and 4,028 execution items, versus 13,859 / 3,096 before watch.
All 4,557 final package targets were unchanged, but action counts changed to
2,871 none, 131 stage, 751 install, and 275 uninstall. No update dirty bits
remained. This demonstrates why equality of package targets is not equality of
an execution plan. The callbacks used the explicit baseline restrictions above;
this is not a native end-to-end servicing or boot witness.

`Plan` (`0x9932c`) performs the first delayed LCU drain, optional capability and
re-servicing work, and its conditional second delayed drain **before** package
watch (`0x9a545`). It then downloads/plans capabilities and validates the plan.
Its re-servicing list is a separate input (`rdx`, retained at `[rbp-0x70]`), not
all installed execution items. The ordinary first single-phase call supplies
null (`0x98af4`); `ProcessSinglePhaseExecution` forwards it to Plan (`0x1212ee`).
A nonempty list first merges installing deployments into component families,
then admits listed packages with separate flags before the second drain. These
operations must not be silently appended after ordinary watch. Subsequent
`CheckOSReservicing` skips offline sessions without the additional session
`+0x978` input (`0x113c41..0x113c66`); offline alone is not the complete guard.

Execution-update initialization (`0x7c5f8`) retains the initial current state at
`+0x78`, normalizing superseded to staged. Merge changes target `+0x80`, not that
initial current state. Stage uses current/target and a separate restaging flag
(`0x69330`); Execute translates current/target with suppression of resolve/stage
actions (`0x3a0e0`). Final package actions do not substitute for these per-update
inputs. Ordinary population therefore retains the first resolved callback result
in `UpdateStarts` (`update_starts` in Starlark), including whether deployments
exist. It preserves the raw callback state, not a fabricated post-stage state;
no stage/execute actions or CSI writes are inferred by retaining it. Callback
copies and returned results own independent maps, and notification cleanup does
not erase the initial state.


### Analyzer family version scope correction

`FindOrAddComponentFamily` (`0x101f43`) and component-watch membership
(`0x38428`) both call `GetKeyFormFromDefinitionIdentityLessVersion` (`0x3855c`).
That routine does **not** erase every version: `versionScope=nonSxS` becomes
`0.0.0.0`, whereas other scopes, including an absent versionScope, become
`major.minor.0.0` (`0x386ce`, `0x38725..0x387a9`). The old analyzer snapshot
incorrectly combined all major/minor versions. This can lend an active owner
from one SxS family to a nonactivating version-elevation owner in another.
The correction is covered by a cross-major/minor activation regression, with
nonSxS and same-major/minor positive controls.

The baseline contains such distinct identities (for example .NET 4.0 versus
10.0, and Common-Controls 5.82 versus 6.0). The successful watch counts above
predate this correction and are not a corrected population witness. A pending
replay collecting initial update states was stopped when this prerequisite bug
was identified; it produced no usable result. A fresh replay is required.

Component analyzer changes are filtered to watched families, not every file or
component: `ComponentAnalyzerChangeDeployment` enumerates the deployment's
component closure, validates install changes against updateComponent metadata,
then calls `PackageStoreIsComponentOnWatch` for each identity before merging a
source/elevation/action. Watch membership requires a value in the store's
family index (`0x38524`), not merely a family key. Its elevation comes from the
first updateComponent entry, or defaults to 128 when none is present
(`0x6b075..0x6b08a`). Ordinary component stage adds pin action 1 (`0x14c9d4`),
install adds 3 (`0x6ad3f`), and uninstall adds 4 (`0x6ab14`). These analyzer
notifications do not themselves write the CSI store.

### Component-watch policy is not implied by an offline update

In the inspected 26100.9441 CBS implementation,
`DetermineComponentWatchlistPolicy` (RVA `b2388`, called by ordinary `Execute`
at `9841e` and `ExecuteSimple` at `115f43`) tests session flags at `+9a0`
with mask `0x0c`. With neither bit present it sets session `+6cc` to one;
`AnalyzerChangeDeployment` then returns without recording analyzer changes.
This gate is separate from the package dependency watchlist.

`CCbsSession::AddPackageTask` (`17bac4`) distinguishes a named update-selection
request from an ordinary package request. The former sets `0x404` for selection
one and `0x808` for selection zero (`17bc04`, `17bc1c`). An ordinary package
install (`17bc6c` onward) instead ORs `0x401`, or `0x11` for an LCU. Uninstall
ORs `0x802`, or `0x22` for an LCU. Neither ordinary case sets mask `0x0c`.
Other package-category flags here also do not set it. Feature/update selection
and capability tasks have separate setters; they must not be inferred from
ordinary package dependency admissions. Thus a fresh package-only update
session does not automatically require the component-watch reevaluation loop.
This does **not** eliminate the CSI stage/install/uninstall source changes or
permit dropping the package watchlist. Loaded/resumed sessions and explicit
feature/capability tasks require their actual policy, not this narrowed case.

### Update execution projection and exact source transitions

`CCbsExecutionUpdate::Execute` (`3a06c`) translates retained update current
`+78` and target `+80` with resolve/stage suppression, independently of its
package's last action. `Stage` (`69330`) is a separate operation: ordinary
current below `0x40`, target above `0x20`, and an eligible package stage pass.
It records staging state at `+84/+88` and on the underlying update; it does
not turn a staged-only source into an installed source. `PlanCBSDeploymentActions`
projects this bounded path, retaining driver identity and manifest order.
Unsupported unstage/unresolve and restage policies are not guessed. The
Starlark population exposes this through `deployment_actions()`; changing
its mutable execution inspection records cannot mutate the retained native
projection input. The method is inspection, not a complete CSI transaction.

The corrected family-key replay of the pinned offer against image 6 of
26300.9457 completed with 46,142 admissions and 4,028 execution items. Its
component/driver references contained 6,386 distinct (primary source, exact
deployment identity) pairs: 1,238 installed-to-superseded, 1,239 absent-to-installed,
1,439 installed unchanged, 2,137 staged unchanged, and 333 absent-to-staged.
Thus the ordinary projection requires 1,572 staged source additions, 1,239
installs and 1,238 uninstalls, not installation of every selected deployment.
These counts are a callback-policy witness, **not** a native completed
transaction or proof that the omitted package references are safe in production.

The native source builder (`cf46` through `d101`) constructs primary from the
canonical package name, a dot, and the exact update name. If an updateComponent
list is present, secondary is decimal `%d` of its first expanded entry's
flags (`d0e5`); it is not always empty. At `d15c`..`d1df`, each entry combines
its elevation with bit one when its assemblyIdentity count exceeds one.
The inferred secondary bytes matched all 4,814 encountered existing source
records, including both `8` and `9` for build-elevated .NET updates. All 1,572
new source pairs in this offer lacked updateComponent predicates, so their
secondary is empty. Existing bytes must still be preserved verbatim.

Driver execution is not just a component source edit. Native
`CCbsExecutionDriver::Execute` (`136c64`) routes install action 3 to `137466`
and uninstall action 4 to `1373bb`, performs the CSI source operation, and
adds a driver operation through `DoqAddDriverOperation` (`10885c`). A writer
must process that queue as well; marking i! records alone is insufficient.
The CSI driver callback `PerformDriverOperation` (`10d34c`) also maintains
driver owners: its install branch calls `SetDriverOwner` at `10d794`, then
conditionally `DrupDriverUpdateStageUpdates` at `10d81b`. The latter (`fe88c`)
is a dynamically resolved driver-library call, not a CBS registry-write helper.
Consequently suppressing DOQ alone would not eliminate the driver-store
construction obligation. This inspection does not establish the driver-library
implementation or authorize executing it as an external servicing fallback.

The preceding replay used the preliminary assembly planner's selected package
metadata, not the whole transport. An omission audit subsequently narrowed its
scope: all 13 omitted SSU root children and all 5,026 omitted LCU root children
returned parent state zero against that final snapshot. However, among 100
other omitted identities present in the LCU metadata, 34 returned nonzero
parent state (29 installed, five staged). These are not automatically safe
omissions. Their 36 incoming edges include 35 `contained=false` references and
one `contained=true` Recall language satellite. Do not assume that XML
`contained=false` alone means an execution reference can be dropped:
`CCbsUpdate::Initialize` (`c381`..`c43d`) creates the package deployment without
testing that field, and `CCbsPackageDeployment::Initialize` (`46ba0`) copies
integration rather than the XML contained field into its runtime descriptor.
Actual source availability and admission policy still need resolution.

The LCU WIM metadata contains the raw MUMs even when `open_servicing_target`
reports a canonical target unavailable. That API reads logical CIX payloads,
not all metadata files; it is not an availability oracle for package MUMs.
Direct portable WIM reads established this distinction without extracting files.

A bounded expansion experiment added the 451 available MUMs reachable from the
100 non-root omissions (5,008 contexts total). Ordinary callbacks completed
48,318 admissions and 4,479 execution items. All original package targets were
unchanged. Of the added packages, 411 stayed absent, 37 became staged and three
became installed: Camera CCX neutral/en-US and Recall en-US at 26100.9549.
Their deployment references added one installed Camera CCX source and 32 staged
sources; 714 further references remained absent-to-absent. None of the 33
positive source additions already existed as an exact deployment in the image.
The complete expanded reference inventory is 7,133 pairs, with 1,605 staging
additions, 1,240 installs and 1,238 uninstalls under these callbacks. All 13 SSU
and 5,026 LCU omitted root parent evaluations remained zero against the expanded
snapshot. The remaining 5,350 non-root missing identities had no raw MUM in the
LCU metadata. These results invalidate treating preliminary payload selection
as complete execution metadata; they remain a policy witness, not native
transaction or boot evidence.

Native package availability is broader than the session-sandbox path alone.
`ResolvePackage` (`597a4`) tries tracker, store, execution-state sources, sandbox,
and alternative store. `ResolvePackageFromExecutionState` (`19af78`) tries the
source descriptor's `+18` and `+10` paths with the UTF-16 `%ws%ws.mum` template
at `2ea9d0`; it also tests membership in the metadata-container object before
loading. No XML-contained gate was seen on this path. Actual preparation/source
provenance must still be established rather than equating all transport entries
with automatically available execution inputs.

Not-found handling also depends on native policy. Child target zero selects the
optional resolve path at `9778d`; session `+9a0` bit `0x10` does likewise at
`977bb`. Its `ResolvePackage` result `0x80070490` skips the child at `97835`.
The package-deployment current-state query maps that same result to state zero
at `6fdf`/`773d` and `7747`. This does not justify ignoring arbitrary resolver
errors or unavailable required sources. Before child admission, target at least
installed can apply `SetUpdateSelectionOverrides` (`86430`) from the deployment's
explicit selection list; the expanded witness had no extra XML children on any
package reference, so it did not exercise that override list.

### Installed membership and winner defaults

A fresh static control of 26300.9457 image 6 found 2,434 canonical deployments
with installed sources and 18,086 components linked to them by c! backlinks.
Their full version-independent CSI identity hashes yielded exactly the 17,044
SOFTWARE SideBySide/Winners families, with no missing or extra family. All
17,238 major/minor branches had exactly the installed-version membership marks
(each REG_BINARY byte 01). Readable-prefix matching is not safe: it collapses
these families to 16,488 because different full names share abbreviated paths.
`windows.csi_identity_hash` exposes the existing native hash arithmetic rather
than reconstructing identities from those names. Its full-version result also
matched all 30,753 component key suffixes in this control.

All 15,910 family-level selected defaults pointed to the numerically greatest
installed version. However, ten *unselected* branches retained an old default
(26100.1) while their membership named 26100.9457; their selected global branch
was 10.26300. Thus rebuilding every branch default from membership is not
byte-equivalent to native incremental servicing. The remaining 1,134 families
had no family-level default. The observed global-default rule matched
versionScope=NonSxS or a policy type, including four win32-policy exceptions to
a NonSxS-only rule. This is a baseline control, not new-image activation proof.

In WCP 26100.9441, `UpdatePossibleWinnersList` (`88594`) adds/removes install
marks through `AddInstallMarkToFamily` (`8c6b0`) and
`RemoveInstallMarkFromFamily` (`1a3820`). Winner persistence is separate:
`WriteWinnersFromChangelist` (`8a4f0`) processes changed pairs, setting the new
winner or clearing the shadowed winner's servicing-family default when none
remains. `SetFamilyWinningVersion` (`8a5b0`) updates a family-level default only
when `GetsFunctionalityServicing` (`8a80c`) is true; it then updates the chosen
major/minor branch's default. That predicate accepts NonSxS or type `policy`
or a type ending in `-policy` (native UTF-16 constants at `33ff68`, `340030`).
`FindNextWinningVersion` (`8d6d0`) scans all major/minor branches for functionality
servicing, otherwise only the queried major/minor branch. Its
`FindHighestVersionInKey` (`1a3230`) parses version value names, excludes an
optional exact version and keeps the numerically greatest remaining value.
This does not justify changing untouched branch defaults or using staged-only
components as winning candidates.

`PerformChangeAnalysis` confirms the ordering: generate closures (`10687e`),
write deployment statuses (`106890`), generate servicing families (`106946`),
update possible-winner membership (`10696e`), analyze change-list (`106997`),
verify closure (`1069a9`), write winner defaults (`1069bf`), then write marks
from analysis closures (`1069cd`). Thus fallback queries see final membership.

`AnalyzeForChangelist` (`8cc0c`) obtains the effective existing winner and finds
its changed-version record, if any. It chooses the greatest changed version
with both nonzero final installed marks (+10) and impactful-install flag (+19).
With no old winner, only that candidate can create a winner. With a surviving
old winner, only a strictly greater candidate replaces it (`8cf1a`). When the
old winner's changed record has zero installed marks, it queries the greatest
remaining member excluding the old version (`8ce14`) and compares that with the
impactful candidate; neither remaining means a pair with no new winner.
`SetImpactfulInstall` (`fb418`) sets +19 independently of final mark count.
`GenerateServicingFamilies` derives marks from component implication backlinks
(`140270`), then adjusts them per installed/uninstalled TLC closure (`1403a5`,
`1403e3`). Its impactful flag depends on closure disposition (entry +30 equals
2) or policy identity (`1402ec`), not merely being staged or present.

`AnalyzeCSIWinnerChange` implements only this choice over explicit, validated
post-closure inputs. It does not derive closures/impact flags, mutate hives,
activate files, or certify a complete CSI transaction. It rejects an effective
winner absent from final membership without a corresponding removal; stale
*unselected* branch defaults are not effective-winner inputs and remain intact.


### Complete metadata inventory and omitted selectable disposition

The repeatable raw/express metadata closure for the pinned base and three new
update roots contains 60,370 packages (57,432 provided by update metadata), with
39,281 referenced identities unavailable in those sources. This is available
metadata, not proof of native tracker admission, parent search scope or final
installation. Do not turn this missing list into a blanket omission policy.

Full-inventory evaluation reached NanoServer IIS's `IIS-WebServer` declaration,
which has `<selectable><detectNone default="true"/></selectable>` with no
`disposition`. In cbscore 26100.9441, `ProcessUpdateGroupType` initializes the
SELECTABLE_TYPE DWORD at offset zero to `0x40` at RVA `0x1e20c` before invoking
`ProcessSelectableType` at `0x1e24f`. The parser writes offset zero only when the
attribute is present (`0x22fc7..0x22fcf`). `CSelectability::Initialize` copies it
to its disposition field (`0x35e36..0x35e38`), which the default-selection getter
returns (`0x702fa..0x702fd`). Thus an omitted selectable disposition means staged;
an explicitly empty or invalid value is not the same case.

Explicit selectable `installed` disposition is also present in the complete
LCU inventory (WinPE-DismCmdlets). In cbscore 26100.9441, the enum table at
RVA 0x366a30 maps `installed` (string RVA 0x297340) to 0x70; the selectable
parser stores that enum at 0x22fc7. GetApplicableSelectableState loads the
disabled selection's disposition at 0x53aae and takes the minimum with
applicability at 0x53ac8. Thus this disposition does not override failed
applicability or the containing package intent. This observation establishes
selection evaluation, not admission of WinPE packages into a client image.

An absent containing package target bypasses applicability evaluation in native
`PopulateExecutionUpdates`: at 0x9a720 a zero target sets the local update target
to zero (0x9a729) and jumps to 0x9a946, bypassing
`GetApplicableSelectableState` at 0x9a78d. This matters for the LCU's WinPE-WiFi
MUM, which contains a local self-reference in WinPE-OneCoreUAP-WiFi-Package.
The ordinary population planner follows this execution-only short circuit;
genuine multi-update cycles still fail. Zero update
publication and child-owner propagation are retained, not skipped.

The English base language pack at 26100.9457 also references an unavailable
EnterpriseG child at 26100.1 while its supersedence target is 0x50. This has a
separate native optional-resolution rule: `ResolvePackageFromStore` passes
package type -1 at 0x27f9f to `ResolvePackageLoadAndInitialize` (0x27fdf).
`PrepareInitializeEx` stores the type in per-session package state +8 at
0x6e587..0x6e58d. `AddPackage` tests that -1 at 0x97795 and a non-null deployment
reference at 0x9779b, then takes optional resolution at 0x97803; only not-found
0x80070490 is skipped at 0x97835. Thus a store-loaded parent's deployment child
may be unavailable even with nonzero target. This is provenance policy, not a
missing-identity allowlist or permission to omit new-source children. The
planner accepts exact store-loaded contexts explicitly; source-backed roots
and arbitrary MUM requests retain their required-resolution behavior.

The new 26100.9711 language pack has the same missing EnterpriseG 26100.1
reference at target 0x70. Checkpoint KB5043080 metadata contains 35,932 packages
but no such localized 26100.1 identity (only the neutral EnterpriseG 26100.1742).
Execution-source MUM resolution uses package type 1, so the store-only exception
above does not cover this case. The decisive policy is established by session
tasks: `IsLCUPackage` (0x81360) performs an ordinal case-insensitive equality
comparison of the identity name to `Package_for_RollupFix` (UTF-16 constant
0x28ca90). `AddPackageTask` calls it at 0x17bc37; for requested installed (0x70),
0x17bc71..0x17bc8c ORs 0x11 for an LCU (0x401 otherwise) into session +0x9a0.
For requested staged (0x40), it sets bit 16 at 0x17bcd5. AddLCUOrGDRToInstall
also sets bit 0x10 for an LCU at 0x17ba91. AddPackage tests bit 16 at 0x977b5
and bit 0x10 at 0x977bb; either uses the optional not-found path at 0x97803.
This is LCU session policy established before admissions, not a list inferred
from missing identities. The planner validates an explicit LCU install/stage
root before enabling it and returns every optional not-found reference with
its parent, update, target and reason. All available children still run, missing
roots/MUM requests still fail, and corruption is not treated as not-found.

A local `detectUpdate` reference to the containing update is removed during
native detector initialization, rather than recursively evaluated. In cbscore
26100.9441, `CDetectUpdate::Initialize` (0x4e764) checks the local-reference
marker and a non-null containing UPDATE_TYPE at 0x4e7b3..0x4e7b8, then compares
the two UTF-16 names case-sensitively at 0x4e7bd..0x4e7de. Equality skips entry
construction via 0x4e855. `CDetectUpdate::Evaluate` returns installed/matching
for an empty resulting list at 0x9fdb9..0x9fdc6. This occurs in the localized
NanoServer IIS 26100.8457 `IIS-Security` update. The shared evaluator therefore
treats an exact local self reference as satisfied, still subject to the package
intent cap. Case-mismatched references, parent references with the same name,
and genuine cycles are not covered by this initialization rule.

The five 26100.9711 LIP packages for ca-ES, eu-ES, gl-ES, id-ID and vi-VN
carry `distributionCompare="GE"` and `serviceCompare="GE"`. Native
`ProcessVersionCompareAttribute` (0x52e48) recognizes these names in the
attribute table at 0x365330 as dispatch values 5 and 3, respectively. Both
branches (0x53117 and 0x531a0) jump directly to 0x5325e, consuming the
attribute without parsing its enum or assigning a descriptor field. Build
(case 4), version (case 2) and revision (case 6) take actual enum parsing
paths. Thus service/distribution values are ignored here, not restricted to
EQ and not extra version dimensions. Parent-state resolution must still run;
these attributes cannot turn an unavailable parent into an installed one.

### Full-inventory population witness and component metadata coverage

With these native rules, the pinned three-root population converges at 179,216
admissions and 59,841 execution entries. Final targets are 55,773 absent,
1,619 staged, 781 superseded and 1,668 installed. All three explicit roots are
installed. A 1,048,576-work budget stopped during the final watch scan at the
same admission count; 2,097,152 completes. This is a population-policy witness,
not a committed CSI transaction or proof that metadata inventory reproduces
native loaded-tracker scope.

The projection has 77,278 deployment-reference records. Non-driver operations
include 416 installs, 414 uninstalls and 359 stage-only references; driver
operations include 824 installs, 824 uninstalls and six stage-only references.
References can share a deployment. The 63,945 optional missing-reference
records are not admitted packages and must not become fabricated content.

Preliminary payload selection does not cover all needed deployment metadata.
Exact complete-stage metadata lookup resolves 574 of the 583 unique newly
staged non-driver identities; the remaining nine are resident DCM manifests.
All 13,172 unique direct component dependencies resolve, as do 264 additional
exact second-level install dependencies. This demonstrates metadata access,
not prerequisite satisfaction or final closure/ownership. Resource selectors,
prerequisites, driver-store operations and CSI change analysis remain separate.


### Complete composition is distinct from applicability

A base-only control traversed every canonical deployment in image 6 of
26300.9457 using its exact decoded manifests. All 4,143 calculated member sets
matched their native `c!` ownership lists, with no extras, omissions or missing
manifests, covering 30,753 exact component identities. The largest composition
(Microsoft-Windows-Multilingual-Deployment) had 990 members. The control used
no update manifests, newer-version replacement or copied predecessor edges.
This proves these ownership sets, not their activation or final winner state.

Matching WCP 26100.9441 explains the edge rule. The dependent-assembly
constructor (`9c94`) initializes its dependency-type byte at offset zero to
zero. `ParseDependencyType` (`c53c0`) maps `install` (string `344320`) to one
and `prerequisite` (`344310`) to zero. `ParseDependentAssembly` writes that
byte through `130c4d`..`130c6f`. `CCompositionalClosure::Drain` walks the
manifest dependency list at `92c3f` and follows only child type one
(`92c52`..`92c62`), parsing its definition identity at `92c74`..`92c7f`.
Thus an omitted dependency type is NOT an install edge. Runtime selectors,
prerequisites and supportedComponent declarations do not add composition
members. Prerequisite/applicability policy remains a separate question; the
preliminary payload planner must not be reused as the final ownership graph.

Draining uses FIFO pending entries; child depth is parent depth plus one
(`92caf`..`92cb6`), with rejection above 128 (`92a62`). Pending disposition
starts at zero (`92fd4`), becoming install disposition two for a top-level
entry. The component's explicit deployment impact can override a nonzero
incoming disposition: `ParseImpactType` (`17ac00`) maps install to zero and
patch to one; `92ef3`..`92f12` translates those to closure dispositions two
and one. `92c3b`..`92c46` forces an initially zero pending disposition to two.
The resulting value is propagated to children (`92cac`) and written to the
member (`92d69`) even on repeated paths. A set-only traversal can reproduce
membership but cannot establish ordered impact propagation.

`CalculateCSIComposition` and `windows.csi_composition` implement that bounded
composition calculation with exact-identity resolver validation. Tests retain
runtime/prerequisite exclusions, ordered diamond-path impact propagation,
root impact behavior, full type/scope/version validation, and depth/work bounds.
Missing install edges fail rather than being treated as optional branches.
These APIs do not change deployment sources, installed marks, winner indexes,
driver stores or image files.

For the pinned update's 583 staged non-driver deployments, exploratory exact
install traversal reached 14,132 unique manifests after resolving 13,172
direct dependencies and additional waves of 264, 104 and nine identities.
Every exact lookup succeeded. That metadata witness is not an applied CSI
transaction. A fresh CLI using the production implementation subsequently
matched all 4,143 native ownership sets and calculated 17,847 membership edges
for those 583 non-driver deployments. The 716 staged driver deployments each
had a one-member composition, bringing distinct required manifests to 14,848.
Every member had disposition two. Driver composition does not implement DOQ,
driver-store construction or driver-owner updates.


### Installed marks count sources, not just active deployments

`CrossReferenceComponentImplicationsToMarks` (`a04c0`) enumerates component
backlinks and sums the three `TlcMarks` counters from each referenced deployment
(`a060a`, `a061a`, `a0672`, `a0683`). `QueryMarksOnTopLevelComponent` (`a0a10`)
counts each `p!`, `i!`, and `s!` value separately: `i!` increments the middle
counter at `a0ef1`..`a0f2d`. It does not collapse all installed sources of one
deployment into a boolean. `GenerateServicingFamilies` initializes the exact
component's total from that middle counter (`140280`..`14028a`), then increments
or decrements once per install/uninstall closure (`1403a5`, `1403e3`).
Only operations zero and one enter this loop (`140160`..`140163`). The
impactful flag is set for disposition two or policy identity before the
operation distinction (`1402ec`..`140389`), so uninstall closures also affect
that flag; nonzero final marks are still required for a winner candidate.

The pinned population's source actions had no install whose exact source was
already installed and no uninstall whose exact source was missing. Base mark
sums identified 18,086 active component identities, agreeing with the prior
winner-membership control. Applying the 1,240 install and 1,238 uninstall
source deltas through the verified compositions affected 17,550 identities:
3,627 became installed, 3,585 lost their final mark, and 10,338 remained
installed. No intermediate count underflowed; final active membership was
18,128. These are analysis counts, not persisted marks or completed servicing.


### Exact source-count and winner analysis control

The portable install-mark analysis sums every installed source payload through
verified deployment compositions. It does not reduce each deployment to an
installed boolean. An unchanged owner remains part of the baseline sum even
when no action names it. Ordinary install/uninstall transitions require exact
source absence/presence respectively; duplicate changes fail. The impactful
flag is set before the native install/uninstall branch, so an uninstall closure
can supply an impactful candidate that remains installed through another source.
No source or winner writes are implied by these counts.

An additional native predicate detail: `IsIdentityPolicy` (`2720c`) and
`GetsFunctionalityServicing` (`8a80c`) accept type `policy` or a nonempty prefix
followed by `-policy`. After comparing the suffix, they explicitly exclude the
bare type `-policy` using `RtlEqualLUnicodeStrings` (`2733b`, `8a95e`). The
portable shared predicate and cross-major/minor tests include this exclusion.

A fresh CLI run of `analyze_servicing_components` on the pinned image and three
update roots verified all 4,143 resident compositions against native c!
backlinks and all 17,044 baseline winner families against source-derived
membership. The combined inventory had 4,777 exact deployments and 34,736
component identities. Production mark analysis returned 17,550 affected
components: 3,627 newly installed, 3,585 losing their last mark, and 10,338 still
installed. Total nonzero-mark identities changed from 18,086 to 18,128. Exact
winner analysis returned 3,636 transitions: 3,596 replacements, 24 new winners,
and 16 cleared winners. Existing branch defaults are inputs, not reconstructed
maxima. This reproduced the independent REPL analysis, but is not evidence of
persisted CSI state, driver operations, payload activation or a successful boot.


### Source secondary metadata and mark persistence

In cbscore 26100.9441, `CCbsUpdate::PopulateUpdateComponents` (`cebc`) builds
source primary text from the package identity and declared update name. It
collects applicable updateComponent declarations through `GetUpdateComponentList`
(`4f6e8`): direct declarations precede nested applicability groups. A declaration
creates one analyzer entry per assemblyIdentity; its flags are elevation OR 1
when the declaration has more than one target (`d167`, `d1d2`..`d1df`). The
secondary source string is decimal formatting of the first analyzer entry's
flags (`d0e5`..`d101`, UTF-16 `%d` at `28d608`). No analyzer entry leaves this
string empty. Selectable conditions do not supply this list. Ordinary component
Execute passes primary/secondary at `6ac6f`..`6aca9`; Stage passes the same
strings at `14c95a`..`14c98b`.

A production `CBSDeploymentSourceData`/Starlark binding control regenerated all
6,037 p!CBS_ payloads in the base image from their package MUMs and exact update
names: every complete payload was byte-identical (5,385 distinct package/update
sources). The canonical deployment planner now derives new source secondary
bytes from retained MUM metadata rather than using empty bytes. Existing opaque
source payloads remain preserved. Unsupported or missing elevation metadata
fails rather than assuming a default not established by this control.

WCP `WriteMarksFromAnalysisClosures` (`13fbd0`) dispatches ordinary native op 0
as set, mask 2 (`13fd16`); op 1 as clear, mask 2 (`13fd0e`). Other op pairs use
mask 1 or 4. `TlcMarkPrefixFromKind` (`15db9c`) maps 1 to p, 2 to i, and 4 to s.
`CommonTlcMarkTwiddle` (`aa7c0`) constructs the exact source value name; clearing
uses the registry delete-value path, while setting serializes primary/secondary
through `MakeMarkValueValue` (`aa9d0`). It does not replace the whole deployment.
After the mark change, backlink clearing for uninstall/unpin is conditional on
both remaining p! and i! counts being zero (`13fdf4`..`13fe13`). Every uninstall
in the pinned ordinary transaction still has p! sources, so treating uninstall
as deletion of all its component backlinks would be incorrect. These are writer
requirements, not evidence that the complete writer has been applied.


Winner deletion is also value-scoped. `ClearServicingFamilyWinningVersion`
(`1a3028`) deletes the family default only for functionality servicing
(`1a3098`..`1a30be`), opens the shadowed version's major/minor branch and deletes
that branch default (`1a319b`..`1a31b6`). It does not delete other branches.
`RemoveInstallMarkFromFamily` (`1a3820`) passes false into `8aa04`; that helper
opens the major/minor branch and deletes the exact four-part version value
(`8ab9b`..`8abc6`). Empty branch keys and unrelated defaults are not removed by
these routines. Adding a mark uses REG_BINARY byte 01 and creates the branch;
setting winner defaults remains a separate change-list operation.

### Native winner family names and value-only plans

`CRawInstallMap::OpenFamilyMap` (WCP RVA `0x26f70`) calls the identity
authority key formatter with flags 2 (omit version). The LH formatter at
`0x6c544` uses name limit 40 and culture limit 8. Its ASCII key-part scanner
(`0x6d990`) copies allowed lowercase letters, digits, `-._` alternately from
both ends, discarding other characters. If raw input remains when the output
fills, its middle two characters become dots: filtering first is not equivalent
when only punctuation remains in the middle. The optional 16-character prefix
is **typeName**, not **type** (`0x300fa0` is `g_LUNICODE_STRING_typeName`).
Type and versionScope still participate in the family hash. Unsupported
Unicode/typeName are rejected rather than approximated.

The production `CSIWinnerFamilyKey` regenerated every one of 17,044 native
SOFTWARE winner-family names, covering 27,559 matching COMPONENTS identities
in the pinned 26300.9457 image. The native architecture table includes x86,
ia64, amd64, arm, arm64, msil, data, wow64, amd64.x86, arm64.x86, arm64.arm,
and arm.x86; unsupported neutral/unknown architecture forms fail closed.

`PlanCSIWinnerWrites` accepts complete baseline membership and affected-version
mark results. It derives final membership, invokes native winner choice, and
returns individual REG_BINARY membership / terminated REG_SZ default edits.
It never deletes a key or rebuilds all branch defaults. Cross-branch replacement
leaves the old branch default intact; clearing deletes the shadowed branch
default and, only for functionality servicing, the family selector. Ordinary
side-by-side servicing does not touch the family selector. The plan applies
nothing and does not substitute for payload, driver, or transaction servicing.

The fresh full population/CSI run still produced 3,636 winner pairs. Plans
contain 3,627 membership sets, 3,585 membership deletes, 3,620 branch-default
sets, 3,614 family-selector sets, and 16 deletes of each default kind. These
are value edits, not proof of a completed update or boot.

### Current-stack source writes and analysis boundary

The 26100.9441 `turbostack.dll` stager calls the same WCP TLC mark helpers,
not necessarily the old WCP transaction wrapper. `PinDeploymentAsync` calls
`AddTlcMark` with mask 1 at RVA `e641b`, after excluding an empty installer
reference. `StageOrUnstageDeploymentFilesAsync` awaits the file operation,
tests its boolean result at `10139f`, and on success with a nonempty installer
calls `AddTlcMark` with mask 4 at `10155b`. A failed result does not write that
staged source. Pending content has a separate path: `ProcessAllDeploymentFiles`
loads it via `LoadPendedContentIfExists` at `e9947`, checks exact membership in
the staging-data identity set, then calls `PendMarkStaged` at `e9a0c`/`e9b88`.
Thus a queued stage action alone is not evidence for a completed staged payload;
the pending-content protocol cannot be substituted with an unconditional mark.

WCP `CommonTlcMarkTwiddle` (`aa7c0`) derives the name from installer kind and
primary source. On add it checks the existing value (`aa8d8`) and preserves it;
only a new value is serialized via `MakeMarkValueValue` (`aa915`). Secondary
bytes are not an instruction to overwrite existing opaque source metadata.
`PlanCSISourceWrites` / `windows.csi_source_plan` implement the resulting
value-only edits for explicit operations on one complete CBS source inventory.
They retain operation order and independent pin/install/stage counts, reject
malformed or mismatched values atomically, and own new payload bytes. Deletion
requires presence as a strict planner precondition; this does not assert that
native deletion of an absent value is an error. Counts do not decide backlink
removal, payload completion, or activation. A compiled read-only control checked
all 4,143 baseline deployments: 6,037 pins, 2,679 installed sources and 6,037
staged sources, with zero edits on replaying every existing add.

Do not infer the installation backend from the staging interface. CBS
`CCbsExecutionComponent::Execute` (`6a4b0`) receives an `ICSITransaction`;
its installation call is at `6aca9`. `ProcessSinglePhaseExecution` calls
`InstallUninstallChain` at `12187f`; the latter calls `WcpCreateTransaction`
at `11b0b1`, `PrepareExecution` at `11b134`, and `TransactionAnalyze` at
`11b318`/`11b3a1`. The offline store wrapper (`8faf0`) calls
`vpfnOpenExistingOfflineStore` (`36cd18`). WCP exposes both generations of
`ICSITransaction::Analyze` and the shared `CommonAnalyze` (`55ce8`). This
ordinary CBS transaction path is the scope of the WCP-derived model above;
using Turbo for manifest staging does not invalidate it.

Turbo also has a separate committer analysis. Its `ComputeChangeList` (`83b7c`)
converts closure entries to identities and invokes WCP `MergeTwoChangeLists`
through IAT `1aa620` at `83e28`; it is not itself a winner-selection algorithm.
The sole direct caller (`8b6e8`) consumes sets prepared by `AnalyzeClosureLoop`
(`89c8c`) and `GetComponentClosure` (`1135cc`). Equivalence of that separate
committer's input selection is not established and must not be claimed merely
because its writer uses shared WCP helpers.

The private `project_servicing_sources` inspection policy joins immutable
population actions to exact MUM source metadata and preserves native baseline
source inventories. It returns separate pin, completed-stage, and installation
plans, explicitly conditional on successful manifest/payload staging, with no
pending-content fallback. The pinned update projects 1,781 changed deployments:
1,605 pin additions, 1,605 staged additions, 1,238 installed removals and 1,240
installed additions. Independently summing the projected final source values
through all compositions matches all 34,736 component mark counts. The exact
inspection entry point ran successfully with this check; it still applies no
state and is not a boot or complete-servicing result.


### Exact component payload staging

`servicing_metadata(feature).plan_components(identities)` takes a complete,
explicit list of full CSI identity bytes. It resolves the full stage manifest
namespace, not the preliminary `PlanAssemblyStages` selection, and returns
immutable `files`, `read_order`, `open(index)`, and `components` members. Each
component description has `stem`, full `identity` bytes, `manifest_sha256` of the
complete decoded manifest, and a `files` mapping from native `f!` value names to
RAW staged flags (1). Descriptions do not invent deployment ownership or claim
payload reads completed. The complete state planner still requires ownership;
callers joining a full population must supply that graph separately. Do not
replace resident CF/f! physical storage state with these RAW descriptions.
Each file record has
`store_path`, `kind`, `source_name`, and `source_mode`. Opening uses native
reconstruction and the content graph's integrity checks. The plan itself does
not prove that all files can be opened. Inputs are bounded to 1,048,576 identities,
64 KiB per identity and 64 MiB combined; duplicate or unavailable identities
reject the entire plan. Store staging never emits runtime registry effects or
runtime links, and does not expand dependencies or choose winners. Resident
content verification, package catalogs, trust, deployment records, drivers and
transaction persistence remain separate requirements.

The pinned 26300.9457 to KB5127648 population's 1,299 unique staged deployments
compose 14,848 unique components. Of these, 10,865 appear in the baseline
composition manifest inventory and 3,983 do not. The preliminary payload plan
omits 110 of the latter (including WMI/WinRM components), and selects 738
components outside this staging set. Availability of a resident manifest alone
is not proof that its payload is intact.

Win32 assembly files may carry an asm.v2 `hash` element containing XMLDSIG
`Transforms`, `DigestMethod` and base64 `DigestValue`, rather than `hash`/`hashalg`
attributes. Preserve these declarations and interpret transforms before using a
digest as raw-file identity. The implemented SHA-256 path accepts identity
transforms, rejects unsupported transforms or algorithms at payload planning,
and rejects conflicting attribute and nested digests. Parsing bounds the
subtree, text and transform counts and rejects duplicates or malformed shapes.

A final component file can be represented directly by a ranged PA30 stream in
the main PSF CIX without a PSFX history edge. This is distinct from a PA30 stream
whose output is itself a checksummed PSF delta record. Direct final targets must
not be discarded with orphan f/r/n intermediate records. Verify the bounded
record SHA-256, header target length/hash, explicit basis if present, and final
reconstructed bytes. Do not invent a predecessor simply because the target is
missing from a history-derived graph.

For example, amd64 Common Controls 6.0.26100.9711 `comctl32.dll` is direct CIX
file 90469, target length 2,698,616, PA30 record offset 1,574,600,417 and length
1,065,410. Native reconstruction produces the declared SHA-256
`645e27c04538e8079b0db62cef14b6353dd83a1b09a68a7d6c1b69e83cfd65e3`.
The previous plan's installed fallback (6.0.26100.9278) has different bytes;
ignoring the nested digest concealed that substitution. This evidence establishes
payload reconstruction, not activation or a completed servicing transaction.


## Resident payload digests and legacy ImageDigest

The exact staging composition's resident files must be verified, not inferred
from manifest presence. In the pinned 26300.9457 base, 10,865 required resident
components declare 15,599 files (2,319,043,482 expanded bytes). All nested
Identity digests match: 15,587 SHA-256 and 12 SHA-1. Of these files, 435 use a
DCS v1 representation in the WIM; hashing the stored container is incorrect.
`archive.dcs(file, maximum_bytes=512MiB)` exposes the existing native LZMS
container decoder with both stored/expanded bounds. `windows.assembly_manifest`
retains each file's nested `digest` (algorithm, transforms, value) separately
from its legacy `hash`/`hash_algorithm` attributes. Neither API establishes trust.

The twelve VC80/VC90 CRT files (x86 and amd64) also declare SHA-1 attributes.
Those attributes do not match the raw or Authenticode digest; they match
`urn:schemas-microsoft-com:HashTransforms.ImageDigest`. Do not reject them as
conflicting raw hashes or silently ignore them. Native WCP 10.0.26100.9441,
PDB 5D2C0A2BEA78B8EEBEC74A88722B0F541, establishes:

- `WcpManifest::GetFileHashes` at RVA 0x1fc50 appends the attribute digest with
  transform 3 (0x1fe37), then the nested digest list.
- `CreateAppropriateDigester` at 0xd70dc maps transform 3 through 0xd7209 to
  the ImageDigest URI at 0x345ae0.
- `CmsGetFileHashInformation` at 0x110a20 prefers the nested list; attribute
  fallback at 0x110b94 is taken only when that list is absent.
- `CmsVerifyFileHashes` at 0xd6a40 checks all supported hashes, not just any one.
  Equality in `ValidateFileHash` (0xd6e9e to 0xd7050) yields disposition 2;
  `CmsVerifyFileHash` maps it to 5 at 0xd6c84, allowing the next hash.

`windows.image_digest` implements the independently observed native byte stream
from `DoImageGetDigestStreamOnStream` (0x2b6b74), not Authenticode: DOS prefix,
fixed NT header, normalized section headers, then section payloads in table
order. It zeroes SizeOfInitializedData, SizeOfImage, CheckSum, resource and
security directory entries; resource-section VirtualSize/VirtualAddress and
SizeOfRawData/PointerToRawData are zeroed. Resource directory bytes (not raw
padding) and `.debug` section payloads are excluded. `.debug` section ranges
receive the same normalization. When resources or debug precede the relocation
section, its RVA/raw offset and the relocation directory RVA are zeroed.
Header padding, inter-section gaps and overlay are not streamed. Relocation
payload remains included. Native `StreamCopy` at 0x2b7868 applies sorted
exclusion intervals. The implementation rejects malformed, truncated,
overlapping or unsupported images rather than implementing permissive native
short-read behavior. All twelve real VC attribute hashes match the native Go
implementation through the fresh inspection entrypoint.

`verify_resident_payloads` verifies the supported nested Identity SHA-1/SHA-256
and legacy SHA-1 ImageDigest declarations independently, with exact full-identity
manifest resolution and collision-checked store paths. Missing files or unknown
hash policies fail closed. This verifies content only: catalog membership/trust,
driver operations, runtime effects and completed servicing remain separate.


### Exact staged-source catalog proof

For the pinned 26300.9457 to 26300.9711 input, the actual population's 1605
stage references belong to 551 packages and 1299 distinct deployments. Each
owning package's exact companion catalog covers both its MUM and every manifest
in each staged deployment's complete composition: 21674 owner/member checks,
14848 unique component identities, including resident manifests. There is no
preliminary-selected-package substitution and no global catalog union.

`PackageMetadataIndex.OpenCatalog` validates the exact MUM identity and resolves
its companion path (including update.mum/update.cat), rejecting absent and
ambiguous companions rather than falling back by basename. The bounded
`windows.catalog_signature` verifier authenticates the single RSA/SHA-256 signer
and recognized RFC3161 timestamp. Direct PKCS#7 SEQUENCE contents and CMS OCTET
STRING contents have distinct signed hash domains; wrong-domain signatures are
rejected. All 551 real catalogs and their timestamp bindings pass. The fresh
inspection entrypoint also checks their code-signing and timestamping X.509
paths at authenticated timestamp times against the 12 existing base ROOT-store
certificates, without host roots, host time, network trust retrieval or embedded
certificate promotion. All 523 distinct chain/time tuples pass.

This remains a content and X.509 path proof, not complete Windows trust-provider
policy. Serialized ROOT properties are preserved, not silently treated as
implemented policy. Revocation, disallowed CTLs, root property constraints and
CBS publisher authorization are separate gaps. No stage marks, installed state,
catalog-store writes or runtime effects are authorized by this inspection.


## Advanced-installer equivalence is not XML equality

The 10.0.26100.9441 WCP image (PDB
`5D2C0A2BEA78B8EEBEC74A88722B0F541`) separates primitive changes from the
advanced-installer queue. `ComputeManifestInstallerDiffs` at RVA `0x157528`
selects one of 21 GUID-specific functions; its boolean means **equivalent**,
not "different". An unknown GUID does not prove equivalence. In `AddChange`,
RVA `0x5eb26` calls that predicate only after the caller's presence/phase
conditions. A true result can still enqueue an inspection invocation according
to descriptor flags (`0x5eb4b` through `0x5eb89`). It is not a general license
to omit all runtime processing. In particular, primitive registry processing
has its own old/remove and new/install operations; dual-mode drivers have a
separate coordinator path.

`MofDiffer` (`0x267e40`) compares the MOF list count and each ordered record:
primary declaration string by ordinal, uninstall-attribute presence, and (when
present) uninstall declaration string by ordinal. It extracts the primary
leaf name using backslash and looks up a manifest file case-insensitively
(`CompareHashesOfFiles`, `0x2677dc`; `FindFile`, `0x16e0c0`). A missing file
cannot prove equivalence. The uninstall branch at `0x267f27` passes the primary
record, not the string at record+0x18, to `GetLeafFileName`; it repeats the
primary file comparison. Comparing the uninstall file's hash instead would
silently implement a different predicate. `ParseMof` (`0x134fe8`) stores the
second attribute string at +0x18 and sets its presence byte at +0x38.

`AreFileHashesEqual` (`0x16df68`) reconciles two dispositions: nested digest
and legacy hash. Either comparable mismatch vetoes equality. At least one
comparable match is required. Nested digest text is compared by ordinal;
legacy hash text is compared case-insensitively. No comparable hash is not a
match. `DoFilesMatchDigestHash` (`0x16e034`) matches digest algorithm and
transform-presence/type before comparing the value. The reusable projection
currently accepts one nested SHA1/SHA256 digest with no transform or one
Identity transform, plus legacy SHA1. Unknown algorithms, unsupported transform
sequences and ambiguous file names fail closed; ASCII-only lookup avoids
pretending Go Unicode folding equals Windows ordinal folding. Authenticity and
actual payload verification remain separate checks.

On the pinned 26300.9457 -> 26300.9711 transition, exact winner/shadowed
resolution finds 105 winner MOF declarations in 83 component transitions.
The initial read-only discriminator found identical ordered declarations and
primary nested SHA256/Identity values in every pair. Two preliminary missing
lookups were only filename casing (`win32_tpm.mof` / `Win32_Tpm.mof` and
`WMIPJOBJ.mof` / `wmipjobj.mof`). `windows.csi_mof_equivalent` preserves this
predicate as native code, with regression cases for declaration order/case,
file lookup case, missing/comparable/conflicting digests and uninstall behavior.
The recipe's runtime analyzer resolves exact identities from the analyzed
manifest inventories, never a version maximum or the preliminary selected set.
Its result is still not a complete queue, state application, or boot proof.


### Writable file controls and destination leaf names

In the same WCP image, `GetDestinationFileNameShallow` (`0x61d8c`) uses the
explicit string at File+0x20 when presence byte +0x1d4 is set. `ParseFile`
(`0x1322ac`) maps attribute index 3 to that field, and its native name-table
entry is `destinationName`. Otherwise the helper splits `file.name` on the
last backslash; with a trailing backslash it returns the preceding part rather
than inventing a host-platform basename rule. Full path macro replacement,
filters and projection policy are separate.

`ParseWriteableType` (`0xd5bd4`) maps `systemData` to 1 and `applicationData`
to 2. The value is File+0xf0; `ParseFileComponentInfo` (`0x601da`) maps either
value to FileComponentInfo+0x105. `InstallComponent` (`0xbc108`) adds
ProcessFileFlags bit 8 for such a file rather than the ordinary bit 1 path.
`ProcessFile` stores new/old writable flags in path-element+0x94 bits 0x20
and 0x40 respectively. Thus the two declarations are reconciled; a single
new manifest is insufficient to choose the operation.

When both sides are writable, the normal commit path at `0x145e2c` can call
`ValidateFileHashAgainstManifest` on the existing destination with the old
manifest's hashes (`0x145f54`). A mismatch does not simply authorize overwrite:
an alternate old-hash vector may be checked, otherwise the branch at `0x14608c`
clears the file-change decision. The validator (`0x274164`) returns hash match
in its first boolean and **security-descriptor match**, not existence, in its
second boolean. Security commit is separate. Other flags (including coordinator
0x1000, collision and force/state flags) affect this path and must be retained.
For the copy path, the IRtlSystemIsolationLayer vtable at RVA 3153760 has
`TransferFileEx` at +0x80; its operation 1 branch (`0xdff33` -> `0xe02c0`)
calls `CopyFileW` at `0xe02e7`. This is not interchangeable with sharing a
mutable runtime destination with an immutable store payload.

A bounded control on the pinned image inspected all 39 writable file
declarations from the exact winners. All are `systemData`. Candidate runtime
paths using the image's System32/SysWOW64, Program Files/(x86), Windows, Fonts
and Default-user template roots all existed and matched the old manifest's
SHA256/Identity value. Five new declared digests differ: PowerShellGet's
`PSModule.psm1` in both architecture roots, `Microsoft.PowerShell.PSReadLine.dll`,
and the two PowerShell shortcuts in the Default-user template. The other 34
are unchanged. These are construction controls, not proof of the full native
macro-resolution policy or permission to overwrite modified user files.


### File directory macros and offline profile resolution

The same pinned WCP separates a directory macro's ID from its actual path.
`ChooseBitnessFromIdentityAndTarget` (`0x60ca0`) defaults to bitness 2 when
architecture is absent. `ChooseBitnessFromStoreAndComponentArch` (`0x5f4c0`)
selects bitness 3 for x86/wow64 in an amd64 store, but retains bitness 2 for
amd64, MSIL and data. The architecture parser table at `0x300d90` encodes
x86 as `0000ffff`, amd64 as `0900ffff`, MSIL as `0800ffff`, data as
`ffffffff`, and wow64/amd64.x86 as `09000000` (little-endian bytes).

`LookupStringReplacement` (`0x61040`) performs ASCII-case-insensitive macro
lookup. Fixed names are 21 LUNICODE_STRING records at `0x42e7d0`, with IDs at
`0x3f3d70`. Seven architecture-dependent names at `0x42e5a0` select tables
`0x3f3dc8` (bitness 2) or `0x3f3d50` (bitness 3). System32 selects 37/41,
Program Files 38/42, Common Files 43/44, drivers `0x20000`/`0xe0000`, WBEM
`0x70000`/`0xf0000`. Explicit syswow64 always selects 41. UserProfile selects
`0x110000` independently of architecture. These IDs go to the user-profile
interface; none is itself a final filesystem path.

`CUserProfile::GetSpecialDirectoryPath` (`0xbf5b0`) dispatches userProfile at
`0xc031e` to `0xc05d7`, then `GetUserProfileDirectoryPath` (`0x11b010`). A
non-null user SID selects that profile's ProfileImagePath. With no SID, the
latter reads the `Default` value below SOFTWARE's
`Microsoft/Windows NT/CurrentVersion/ProfileList` and expands it through the
profile provider. The pinned image contains `%SystemDrive%\Users\Default`.
Its ProgramFilesDir/CommonFilesDir entries, in contrast, contain `X:` paths.
Do not hardcode Users/Default or silently strip arbitrary registry drive letters.

The rerooted user-profile provider initializes a separate environment at
`0x655b4` with SYSTEMDRIVE, WINDIR and SYSTEMROOT from its constructor paths.
Its expansion routine (`0x65f10`) expands that environment, converts Win32 to
NT syntax and ensures a trailing backslash. Registry values are delegated to
the configured registry provider (`0x158070`). Filesystem path translation is
a separate mapping operation (`0x15608`, matching at `0x15ab0`), not a blanket
change of all drive letters to the image root. Complete mapping policy and
constructor provenance remain required before applying runtime destinations.

`CSIFileDirectoryMacro` and its Starlark binding implement the observed amd64
ID-selection policy and reject unsupported architectures/macros. The separate
`CSIFileDestinationName` binding implements the shallow override/last-backslash
rule, including an explicitly empty override and the trailing-backslash case.
Neither is path validation or file-install authorization. The private runtime
analyzer decomposes exact before/after declarations into directory IDs, suffixes
and destination names, leaving missing destinationPath explicit. Driver rules,
profile/root resolution, modified-writable preservation, security and final
filesystem effects remain separate.

### Offline provider roots and image-relative path resolution

On WCP 10.0.26100.9441, `CNtStoreCreationParameters::Initialize` (RVA
0x17288) uses an explicitly supplied Windows path when present. Otherwise,
0x178c9–0x17991 reads `Microsoft\Windows NT\CurrentVersion\SystemRoot`
from the offline SOFTWARE key and converts that value to an NT path. The
registry read is at 0x1795b; conversion at 0x1797f. This is not the host's
SystemRoot. `GetRerootedSIL` (0xfe930) constructs ordered 0x38-byte filesystem
mapping records, including the source-volume/offline-parent pair,
`\SystemRoot\`, the supplied boot location and an optional external-storage
mapping. Generic drive-letter removal is not equivalent to this operation.

The private recipe deliberately supports a narrower mapping: one recorded DOS
volume, one-component recorded Windows directory, and an explicit virtual
Windows directory with the same final component. Unknown volumes, relative,
UNC/device, traversal, alternate-stream and ambiguous path forms fail closed.
Environment expansion uses only the native provider's SYSTEMDRIVE, SYSTEMROOT
and WINDIR variables, never the host environment. ProgramFiles/CommonFiles
(native and x86), ProfileList Default and ProgramData are read from the supplied
offline SOFTWARE hive. Missing values are not replaced with conventional paths.
This policy is path analysis, not an authorization to copy, link or remove files.

`CUserProfile::GetSpecialDirectoryPath` (0xbf5b0) makes the following distinction:
ID 11 (Start Menu) at 0xbfeab calls `GetProgramDataPath` (0x6875c) and appends
`Microsoft\Windows\Start Menu\` (UTF-16 literal 0x386b00). It does **not**
use the no-SID Default profile. ID 0x110000 uses `GetUserProfileDirectoryPath`,
whose no-SID branch reads ProfileList/Default. These roots must remain distinct.
Other observed suffixes are Windows/Fonts (20), Windows/Inf (0x30000),
Windows/Help (0xa0000), Windows/System32 and Windows/SysWOW64 (37 and 41),
and their Drivers (0x20000/0xe0000) and wbem (0x70000/0xf0000) subdirectories.
The native System32 accessor is 0xbefa4; its combine call is at 0xbf054.
The SysWOW64 driver suffix is at 0x386970 and the two wbem literals are
0x386a38 and 0x386a58. This observed amd64 mapping does not establish ARM policy.

Absent `destinationPath` declarations remain explicitly unresolved in this
analysis. They are neither guessed to a root nor classified as store-only.
Driver/implicit projection policy must account for them before application.

Extra file links are separate runtime destinations. `ParseFileComponentInfo`
splits the declared full destination at 0x60654, expands its directory through
the same macro machinery at 0x60680 and retains the path in its link vector.
`InstallComponent` iterates those paths at 0xbc19d and invokes `ProcessFile`
at 0xbc24b with flag 0x10 (in addition to shared flags), rather than silently
reusing the primary file's path or transfer kind. The exact update manifests
contain 147 old and 148 new link declarations, including boot-loader aliases
and UUS/SystemApps paths. Analysis resolves these separately; it does not
claim they share the primary file's mutable-data or transfer policy.

Non-projected files are not ignored by native installation. The branch on
FileComponentInfo+0x107 at 0xbbf6e/0xbc0c9 reaches
`ProcessUnprojectedFile` (0x282f10) through 0xbc2f9. That function inserts
FileInfo and records old/new source paths, hash vectors and flags, with an
optional external-source-directory computation. This is distinct from a
runtime destination projection and is not evidence that the file may be
omitted from staging or subsequent commit processing.

### File-attribute mask parsing

The WCP File constructor (0xe083c) initializes File+0x18 to 0xa0 at 0xe084a.
An explicit `attributes` value is passed to TokenizedBitMaskAttributeMapper
at 0x1328f5; that parser clears the output at 0x158306 and ORs tokens, so an
explicit empty value is zero, not the constructor default. Its seven 32-byte
map entries begin at 0x314ed0: readOnly=1, hidden=2, system=4, archive=0x20,
temporary=0x100, offline=0x1000, notContentIndexed=0x2000. Comparisons use
FsnpDowncaseChar. The separator predicate at 0x1053e0 accepts only tab, LF,
CR and space; vertical tab, form feed and Unicode spaces are not separators.
The native parser does not accept a `normal` token despite the constructor's
0x80 bit. This parsed mask is copied to FileComponentInfo+0x100 at 0x601c7;
final commit-time attribute/security policy remains separate.


### Manifest-local file security and binary controls

The pinned winner-transition manifests resolve all 24,512 old/new direct-file
security references through the exact local
`trustInfo/security/accessControl/securityDescriptorDefinitions` path. The 390
remaining direct files have no security reference; this is not an empty ACL.
There are 20 distinct SDDL values; 354 declarations use `(inherit)`, and 7,864
contain a system-app conditional ACE. All observed definition operation hints
are `replace`. These counts describe declarations, not authorized operations.
`analyze_servicing_file_security` preserves per-side local definitions, hints
and attributes; missing, duplicate and out-of-scope definitions fail closed.

In base WCP 10.0.26100.9441, `ConvertStringSecurityDescriptor` at RVA 0x82b10
compares the complete string against `(inherit)` at 0x82b6f. The matching
branch at 0x82cad clears the descriptor and succeeds without calling the SDDL
converter. This marker must not be compiled as an ordinary empty descriptor.
`CommitFileSecurity` at 0x124854 separately selects explicit, default and
inherited security. `ApplySecurityToObjectWithDefaults` at 0x83800 decomposes
the descriptor: absent owner/group are supplied from the system SID; absent
DACL/SACL are replaced by empty ACLs and corresponding unprotected security
information flags. This is not the same as preserving absent fields verbatim.
The boolean input selects native object-set flags 4 or 8; that flag's full
provenance and the effective inheritance operation remain separate work.

The base WIM image 6 metadata security table contains 473 descriptors in a
186,696-byte block. Existing kernel32.dll security contains six DACL ACEs and
one SACL ACE. Its generic read/execute manifest masks are already mapped to
file mask 0x1200a9. Security entry 432 contains the matching Client.CBS file
conditional ACE: type 9, mask 0x1200a9, builtin-users SID, and `artx` application
data. The expression encodes token 0xf8 + counted UTF-16LE `WIN://SYSAPPID`,
token 0x10 + counted UTF-16LE `MicrosoftWindows.Client.CBS_cw5n1h2txyewy`, then
operator 0x86 and zero padding to a four-byte boundary. The file ACE has flags
0; a directory instance has OI|CI. Raw SDDL construction must therefore remain
distinct from object-type generic-mask mapping and inheritance processing.
These are binary construction controls, not evidence of an applied update.


### Native SDDL compilation and generic file rights

The exact update's 24,902 direct file declarations resolve to 24,158 explicit
security declarations (19 distinct SDDL strings), 354 CSI `(inherit)` markers,
and 390 absent references. `compile_servicing_file_security` preserves these
three cases; it does not authorize a security mutation. The native
`windows.compile_sddl` compiler covers these 19 strings and rejects unsupported
syntax. Its raw output preserves generic rights and is not an effective ACL.
The callback ACE generated for the CBS SYSAPPID Contains expression matches the
base WIM descriptor 432's last DACL ACE byte-for-byte (152 bytes, with the file
propagation flags omitted as in the independent control).

WCP's `CFile::SetSecurityInfo` at RVA `0x67f60` translates option bit 4 to bit 2
before `CSystemObject::SetSecurityInfo` (`0x68008`). That object's bit-2 branch
skips the extra auto-inherit control bits and dispatches provider option 4.
`SetSecurityObjectWithInheritance` (`0x218c7c`) queries parent ACLs and calls
`RtlNewSecurityObjectEx` at `0x2190c4` with auto-inherit flags `0x101b`.
Its file generic mapping is read `0x120089`, write `0x120116`, execute
`0x1200a0`, all `0x1f01ff`. Registry mapping is separately selected by input
bit `0x10000000`; do not use file mapping for registry keys. Before inheritance,
unprotected present-NULL ACLs have their corresponding control bits cleared.
The subsequent control restoration/minimal-descriptor path remains distinct
from the generic mask substitution.

`windows.map_file_security_rights` performs only that substitution, validating
bounded components and supported ACE layouts and preserving all other bytes.
Compiling the WRP default SDDL then mapping its generic rights reproduces the
entire 276-byte base `Windows/System32/kernel32.dll` security descriptor,
including owner, group, six DACL ACEs and one SACL ACE. This independent control
is a regression test; it is not a default ACL substituted for other files.
Defaults, parent inheritance, propagation handling, and commit-path selection
still need their own policy and validation.


The base ntdll PDB is `C3093720177DA6851519DCFFE8DF53FE1`.
`RtlNewSecurityObjectEx` (`0x510a0`) delegates to `RtlpNewSecurityObject`
(`0x51750`). Its final `RtlpApplyAclToObject` (`0x50900`) is **not** just the
standalone generic-right substitution: it skips inherit-only ACEs and clips
supported masks to the mapping's all-access mask (with the system-security bit
retained for the appropriate audit layouts). Do not treat
`map_file_security_rights` as a replacement for that complete operation.
`RtlpGenerateInheritedAce` (`0x544d0`) separately tests OI for file effective
inheritance and CI for directory effective inheritance. Directory propagation
also considers NP and may retain a separate inherit-only ACE; combining and
pruning duplicates is additional behavior. These findings narrow the remaining
inheritance work, not an implemented general inheritance claim.


### Effective explicit ACL execution controls

The same base AMD64 ntdll was executed directly with `emulator.machine`, not
inside a booted guest. Calls to `RtlpCopyAces` at RVA `0x55150` used selection 2
(all source ACEs), clear-flags 0, effective-copy enabled, supplied System owner
and Administrators group, no server principals, and ACL kind 1. The destination
was bounded to 4096 bytes and each call to 100,000 instructions. The controls
returned normally with status zero, in 126–558 instructions. No imported
security behavior was replaced by a shim.

For the WIM-432 conditional ACE with source flags OI|CI and generic read/execute:

* A file receives one flags-0 ACE with mask `0x1200a9`. Every byte equals the
  independent WIM file ACE, including its conditional expression.
* A directory receives that effective ACE followed by an OI|CI|IO ACE retaining
  the generic mask. If the source mask is already `0x1200a9`, the directory
  instead receives one OI|CI ACE. Thus mapping all masks before propagation
  would destroy observable native behavior.
* An inherit-only source contributes nothing to a file and remains inherit-only
  on a directory. NP is retained on explicit directory propagation; it governs
  the later parent-to-child inheritance step, not this copying step.
* Zero-mask callback propagation remains present on a directory, while an
  ordinary zero-mask non-creator ACE is omitted. Creator owner/group substitute
  the supplied principals, including SID-size changes, and may retain separate
  propagation ACEs even for zero masks.
* Effective allow masks exclude ACCESS_SYSTEM_SECURITY; audit masks retain it.
  Effective masks are clipped to the file mapping, not merely generic-mapped.

`windows.copy_explicit_file_acl` implements this bounded explicit-ACE step and
has independent native byte vectors for these cases. It rejects inherited ACEs,
reserved flags, unsupported ACE layouts and unsupported creator identities.
It does not select or merge parents or represent missing/NULL descriptor fields.
The generic-rights-only API retains its narrower, byte-preserving contract.

Direct `RtlpInheritAcl2` calls at `0x53e50` also return normally for a parent
conditional ACL: auto-inheritance adds ID (file flags 16; directory effective 16
and propagation 27). An unprotected explicit ACE remains ahead of the inherited
copy rather than being merged with it. Protected explicit control `0x1004`
suppresses the parent and yields output control `0x1400`. Disabling
auto-inheritance changes the explicit copying path and preserves OI|CI on a
file. These controls do not yet establish the complete WCP flag selection,
parent duplicate pruning, or descriptor defaulting policy.


### Parent-to-child ACL derivation

`windows.inherit_file_acl` implements the separately verified parent-ACE step.
With auto-inheritance enabled, native `RtlpInheritAcl2` controls show OI admits
file-effective inheritance, CI admits directory-effective inheritance, and NP
suppresses onward directory propagation. Parent IO does not suppress its child's
effective grant. Directory OI-only propagation becomes OI|IO|ID. CI plus generic
rights produces separate effective-ID and propagation-CI|IO|ID copies. Existing
ID is accepted on parent ACEs, unlike the explicit-copy API.

Duplicate pruning is not simple byte equality or combining masks. Native
`RtlpIsDuplicateAce` (`0x55640`) tracks uncovered masks in three domains:
effective access, object propagation, and container propagation. Earlier
inherited ordinary ACEs of the same type and principal may jointly cover a
later ACE in all applicable domains. An earlier superset removes a later
subset; a later superset does not replace earlier entries. Audit-success and
audit-failure flags must match. Callback ACEs are not deduplicated, even when
byte-identical. The duplicate-type tables at `0x1920c8` and `0x192130` and direct
native calls support these distinctions.

The regression controls include the OI/CI/NP/IO file/directory matrix, duplicate
ordinary versus callback ACEs, subset ordering, masks 1 and 2 jointly covering
mask 3, audit flag separation, and zero-mask creator behavior. Parent propagation
of an ordinary zero mask is omitted even for a creator SID; its effective
substituted creator ACE can remain. This differs from explicit copying.

No inherited entries correspond to native `STATUS_NO_INHERITANCE` (`0x8000000b`)
in the absent-explicit controls. The primitive represents this as an ACL with
zero entries for inspection/composition; callers must not mistake it for a
policy decision to install an empty DACL. Explicit/parent selection, protected
ACL handling, fallback defaults, owner/group assignment and final descriptor
control bits remain the responsibility of the security-object policy layer.


### WCP final descriptor control and minimal ACL pass

After `RtlNewSecurityObjectEx`, WCP distinguishes containers using its original
input flags masked by `0x50000000` (saved in EBX at `0x218e93`). This branch is
not the separate low option-bit-4 path. For containers, `0x21912e` requests
setting the original descriptor control bits masked by `0x3fc0`. For files,
`0x219180` calls imported `RtlSetControlSecurityDescriptor` with interest mask
`(originalControl & 0x3000) | 0xf00` and set mask `originalControl & 0x3000`.
Thus the file path clears the four auto-inheritance control bits before calling
`GetMinimalSecurityDescriptor` (`0x83c18`); a raw RTL descriptor is not the final
file descriptor.

`IsMinimalAcl` (`0x84dd8`) detects inherited ACEs in a protected ACL and OI/CI
flags on files. `GetMinimalAcl` (`0x856b4`) skips ID ACEs when its protected input
is true and clears OI/CI on file ACEs before adding the survivors to a newly
allocated ACL. This final policy pass is separate from the two implemented
ACE-construction primitives; its invocation/descriptor reconstruction and WCP
option provenance still require integration and validation.

Direct WCP predicate execution using the mapped base ntdll imports confirms
`IsMinimalAcl` returns true for a file ACE with flags 0 or unprotected ID, false
for file OI|CI or protected ID, true for an unprotected directory OI|CI ACE, and
false for protected directory ID. However, the inspected descriptor caller
branches into `GetMinimalAcl` when the saved predicate is true. This apparent
caller/predicate mismatch must be resolved by a bounded caller-path experiment
before treating the helper's filtering as an applied final-descriptor policy.
No production descriptor policy has been inferred from the helper alone.


The bounded caller experiment resolves this mismatch for the pinned build:
`GetMinimalSecurityDescriptor` really does reconstruct when `IsMinimalAcl`
returns true, and preserves an ACL for which it returns false. Direct native
calls returned status zero for these controls:

* File DACL flags 0: new descriptor, same ACL contents.
* File DACL OI|CI: original descriptor, flags unchanged.
* Protected file DACL ID: original descriptor, ID unchanged.
* Directory DACL OI|CI: new descriptor, flags unchanged.
* Minimal DACL plus protected inherited SACL, and the converse: reconstruction
  occurs, but the nonminimal ACL survives unchanged. Protected and AI controls
  in these vectors survive reconstruction.
* NULL DACL and owner/group-only descriptor: original descriptor. Empty DACL:
  reconstruction with an empty DACL, not a NULL DACL.

These observations supersede any inference that this caller unconditionally
removes propagation or protected inherited ACEs. They are specific to the
identified WCP image and do not establish another build's behavior.
The harness executes real WCP and ntdll security routines, supplying only a
bounded allocation/free adapter and forwarding the CRT memcpy import to the
native ntdll memcpy. A synthetic TEB/PEB supplies only the declared heap handle;
no token, security predicate, or security result is substituted. The Auto SD
output storage must accommodate its pointer and size fields, not just a pointer.
A native memset on the reconstruction path required AMD64 MOVLHPS; the CPU
implementation now covers low-to-high quadword movement, aliasing, extended
registers and flag/source preservation with instruction-level regression cases.


### Token-free whole-descriptor construction

Native `RtlNewSecurityObjectEx` (`ntdll+0x510a0`) with flags `0x101b`, NULL
token, explicit owner/group and the file mapping returns successfully without
token queries. `windows.inherit_file_security` implements this bounded path:
protected input ID entries become explicit; unprotected ID entries are discarded
before adding parent inheritance. Owner/group are the explicit child's, not the
parent's. Both AI bits are set and request bits cleared. Absent DACL with no
inherited entries remains absent and gains protection; an explicit empty DACL
remains empty, or receives inherited entries if unprotected. SACL selection is
independent. Native field vectors cover these cases, file/directory split,
creator substitution and distinct audit-success/failure masks. Inputs remain
unchanged and combined ACL size overflow fails closed.

The API requires explicit owner/group and rejects child NULL/defaulted ACLs, extra
control policy and non-revision-2 ACLs. It is not a token access check, a WCP
input-defaulting wrapper, or final file-security application. In particular,
WCP clears unprotected present-NULL fields before RTL; raw native RTL rejects
the tested present-NULL DACL with status `0xc0000077`.

A separate bounded `ApplySecurityToObjectWithDefaults` (`WCP+0x83800`) experiment
stops at the object vtable's SetSecurityInfo entry without executing mutation.
It confirms missing owner and group independently become System, missing ACLs
become empty unprotected ACLs, and present-NULL is still NULL at this boundary.
The bool argument selects options 4 (false) or 8 (true). Unprotected D/S produce
security-info `0x3000000f`; both protected produce `0xc000000f`. AI controls are
not represented in these SetSecurityInfo arguments. Explicit BA owner/WD group
remain unchanged. Native System SID allocation ran through the singleton
initializer; the ancillary harness supplies declared TLS/TEB/shared-data memory,
forwards locks to native RTL, stores one onexit callback in bounded memory, and
returns invalid-handle failures only for the initializer's NULL event notices.
No security result or principal was supplied by a callback.


Native `CommitFileSecurity` (`0x124854`) controls, with an already supplied
object and a stop at its setter, further confirm record `+0x60` selects its
explicit descriptor at `+0x18`. Without it, record `+0x93 & 0x20` selects the
context default at `+0x1a0`; otherwise the second function argument selects the
special descriptor at context `+0x1b0`. With neither, record `+0x95 & 0x10`
branches to `UpdateInheritedSecurity` (`0x269bc0`), otherwise to the context
default. The `+0x95` bit 3 is passed to ApplyWithDefaults, selecting options 4/8.
The producer semantics of these record flags remain separate from this dispatch
control; they must not simply be equated with the manifest `(inherit)` marker.
Disassembly of UpdateInheritedSecurity queries the current descriptor, returns
without mutation for protected DACL, and otherwise clears an unprotected NULL
DACL's presence/default/auto controls before reapplying through defaults. A fresh existing-descriptor query/dispatch experiment confirms this behavior.
The declared query callback copies the input descriptor into the native Auto
output; no security predicate or setter result is substituted. Protected
nonempty and protected empty DACLs return status 0 with changed=0 and never
reach the setter. Unprotected ID ACEs reach SetSecurityInfo unchanged at this
boundary (options 4, security-info 0x3000000f); inheritance processing is later.
An unprotected present-NULL DACL and an absent DACL both reach the setter as
empty ACLs after clearing/defaulting. An independent protected SACL remains
protected while the DACL is unprotected (security-info 0x6000000f). All setter
observations stop before mutation, so changed=0 there is not a completed
application result.


### Inherit marker versus recursive inheritance dispatch

The base WCP coordinator's `FindOrAddNewSecurityDescriptor` (`0xbc314`)
returns status 0 and a NULL SecurityPair for `(inherit)` with an empty cache.
Native `InstallComponent` (`0xbbf08`), stopped before ProcessFile, distinguishes
an absent declaration (flags 0x1, operation 1, NULL pair) from `(inherit)`
(flags 0x41, operation 1, NULL pair) for the same declared component inputs.
The marker is not a non-NULL pair containing a NULL descriptor.

ProcessFile disassembly (`0xbc791..0xbc7be`) handles flag 0x40 by selecting
the supplied pair, retaining an existing pair when the supplied pair is NULL,
and setting record +0x93 bit 0x20 iff the resulting pair is NULL. This is the
explicit-default branch in CommitFileSecurity; repeated declarations require
retaining this selection order rather than independently assigning per-file
ACLs. Record +0x95 bit 0x10 instead has identified setters in
AddEntriesForAutoInherit (`0x2810fe`, `0x281289`) while enumerating a changed
directory's children. CommitDirectoryChanges rewrites it from the actual
UpdateInheritedSecurity changed output (`0x2824cc..0x2824e8`). These static
producer observations must not be mistaken for an end-to-end hierarchy run.

Hierarchy initialization (`0x15bbfc`) selects GetFileSystemDefaultSecurity
flags 0x200 for context +0x1a0, 0x10 for +0x1b0, 4 for +0x1c0, 1 for +0x1d0,
and 0x40 for +0x1e0. The flag-1 string is `O:SYG:SYD:AIARS:AIAR`; it is NOT
the flag-0x200 ordinary-file default.

The ordinary-file flag-0x200 default is `O:SYG:SY`. The special flag-0x10
constant uses TrustedInstaller owner/group and a protected DACL granting it
full access, with generic read/execute for BA, SY, BU and the two application
package groups; its SACL is present empty with AI. Selection of that special
branch remains distinct from reading the constant.

`prepare_servicing_file_security` implements the bounded ordinary-file input
step in the private runtime policy: validated generic mapping, independent
System principal defaults, absent-to-empty unprotected ACLs, and removal of
AI/AR controls not conveyed by file setter option 4. Existing ACEs (including
ID) survive this step. Child present-NULL and defaulted controls fail closed.
It does not select mutations or apply parent inheritance. Native captures also
confirm that absent ACLs with protection bits set still default unprotected.
The exact update's 24,158 explicit declarations (19 distinct descriptors)
all pass this preparation; 354 inherit and 390 absent references stay separate.

Exact base-parent investigation through in-memory WIM apply preserves metadata
without extracting payloads to the host. Of 1,440 distinct direct-file parent
paths (before and after combined), 1,214 exist in the base and use 38 distinct
descriptors; 226 are absent and must not be treated as empty parents. Twelve
of the 38 descriptors contain present-NULL SACLs. Native RTL accepts parent
NULL ACLs: DACL, SACL or both contribute no ACEs for absent, empty and explicit
children, both file and directory. The source NULL rejection is unchanged.
The compositor now distinguishes these roles; the 18 native matrix cases are
regression-tested. All 47 distinct prepared-child/existing-base-parent pairs
from the after-side explicit declarations match native RTL output in control,
owner, group, SACL and DACL with the freshly compiled binding. This is a
construction comparison, not proof that those parents remain unchanged during
servicing or that these file effects are authorized. Missing-parent creation,
mutation dispatch, final file controls and complete image proof remain separate.

### Directory creation and declaration controls

On the pinned WCP, `CommitDirectoryChanges` (RVA 0x281f4c) walks the
hierarchy, queries directory existence through `SilDoesDirectoryExist`
(0x2a3ee0), and obtains `GetSystemSecurity` (0x12d90). Its native initializer
(0x2a2390) constructs the 44-byte self-relative `O:SYG:SY` descriptor with
both ACLs absent, not present empty ACLs. A one-child declared-absent fixture
captured that descriptor in the native directory-create object attributes,
with access 0x1201bf, disposition 3 and options 0x4021. No host directory was
created. Supplying an explicit security pair did not replace this creation
input: after the fixture returned its declared object, native code called
`ApplySecurityToObjectWithDefaults` and reached the object's setter with
option 4 and information 0x3000000f. An absent pair instead reached
`AddEntriesForAutoInherit` without that setter. Both captures stopped before
security mutation or child enumeration. They do not prove a complete
filesystem operation, inherited result, or arbitrary operation-flag policy.

`ProcessDirectory` (0x10dc50) retains an existing new-side security pair at
record +0x60 when the security-selection flag is set but the supplied pair is
NULL (0x10de9b..0x10decb); the old-side +0x68 selection is analogous. Preserve
declaration order rather than deduplicating destinations before policy.
The private declaration analyzer reads only direct assembly/directories/
directory nodes, resolves manifest-local security definitions per side,
and retains raw owner, compression, attribute and security-reference metadata.
Its path resolver does not create implicit file parents or guess missing roots.
Literal dollar signs in suffixes (notably `$Recycle.Bin`) are allowed;
additional `$(...)` macros remain unsupported.

### Directory SDDL compilation controls

The exact runtime transitions contain 2,797 directory declarations (1,405
after-side): 2,645 have explicit security references, 152 have none, and
none use the `(inherit)` marker. Their 95 distinct SDDL strings were compiled
and compared with the pinned WCP `LocalConvertStringSDToSD_Rev1` (0x81c84).
All controls, owner/group SIDs, SACLs and DACLs matched; serialization placement
of the two ACLs was not required to match. This is raw descriptor construction,
not permission evaluation or evidence that these declarations should execute.

The native fixture explicitly denied `LsaOpenPolicy` (0xc0000022), returned no
domain data, and forwarded CRT string routines to the real base ntdll. Fixed
aliases still parsed; the domain-relative `DA` control failed with 0x539.
New supported fixed aliases are AU, BO, CO, IU, LS, LW, NO, NS, RC, SU and UD.
In particular, UD is `S-1-5-84-0-0-0-0-0`. Domain-relative aliases remain rejected.
Native rights parsing ORs symbolic and numeric terms even when interleaved:
`WDWOSD0x1000000` gives 0x010d0000, `0x1000000WD` gives 0x01040000, and `1WD`
gives 0x00040001. Numeric terms use base-zero parsing; `010` gives 8, and
`08` is parsed as successive numeric terms 0 and 8. The implementation rejects
numeric overflow rather than adopting wcstoul saturation.

Native mandatory-label `S:(ML;OICI;1;;;LW)` produces ACE type 0x11, flags 3,
mask 1 and SID S-1-16-4096 in a revision-2 ACL. The bounded compiler accepts
integrity SIDs and masks 0..7, rejects audit flags or placement in a DACL,
and does not add label support to the separate file-inheritance APIs.
The observed `(exists WIN://SYSAPPID)` condition encodes `artx`, local-attribute
token 0xf8, its UTF-16 name and operator 0x87 (with ACE alignment padding).
It is preserved as a callback condition, never replaced by a true/false result.
Compound expressions and unsupported operators remain errors.

The additional directory-only roots were checked in native
`CUserProfile::GetSpecialDirectoryPath` (0xbf5b0) with deliberately nonstandard
cached paths. Diagnostic tracing alone was disabled in this fixture after its
loader-dependent initialization could not run in the minimal process; no path
selector or string-copy result was replaced. The native outputs were:

* 0xb0000: cached Windows directory + `AppPatch`;
* 0x100000: the user provider's supplied root (not a drive inferred from a file);
* 0x3e: `ProfilesDirectory`;
* 0xc0000: `ProfilesDirectory` + `Public`, not the registry `Public` value;
* 7: `ProgramData` + `Microsoft\Windows\Start Menu\Programs\Startup`.

`GetProfilesDirectoryPath` reads the `ProfilesDirectory` value under
`Microsoft/Windows NT/CurrentVersion/ProfileList` via the existing native
registry/environment path-expansion helper. The rerooted user provider copies
its supplied root at 0x229ec0; this recipe explicitly supplies the one-volume
root mapping already required by its path context. Its synthetic regression
fixture has a different Windows name, Default profile, ProfilesDirectory,
ProgramData and an intentionally conflicting Public value. All 2,797 exact
before/after directory paths resolve against the actual base SOFTWARE hive.
This does not establish ordering or permissions for implicitly created parents.

### Directory creation and mandatory-label boundary

The pinned base image's NTFS `NtfsAssignSecurity` (RVA `0x235aa0`, split
body `0x2d59f4`) obtains auto-inheritance flags using
`SeComputeAutoInheritByObjectType`, adds `0x18` only for the effective kernel-mode
path, and always adds `0x4000` before `SeAssignSecurityEx`. This is not WCP's
explicit-security flags-`0x101b` operation. WCP's `CDirectory::CreateNewDirectory`
(`0x10e290`) forwards its descriptor to the filesystem provider; the direct
provider (`0x219390`) reaches `NtCreateFile` (IAT `0x327f18`).

For the 122 first missing directory roots, the 12 existing parent paths contain
no SACL bytes. Two have a present NULL SACL. An in-process kernel probe using
the captured file-object initializer (length `0x78`) and explicitly zero
extended policy fields gives auto flags `1` for eight parents, and `3` for
Servicing/Version, NarratorMCAT/Rules/Languages, DiscoveryHub and its Assets.
This fixture establishes flag derivation, not live token state, authorization,
or a complete create operation. Existing-parent mutations and newly created
ancestors still require ordered processing.

Parent mandatory-label ACE inheritance has an independent 64-case native
comparison (masks 0/7, OI/CI/NP/IO combinations, file/directory). Integrity SIDs
and zero policy masks survive; label masks are not file access masks. The
standalone ACL primitive supports one such label, fails closed on additional
labels, nonintegrity SIDs, unknown policy bits and audit/reserved flags, and
does not select default labels or authorize assignment.

Do not extend whole-descriptor construction by merely accepting ACE type 17.
The real directory SDDL includes `S:(ML;CIOIIO;1;;;LW)`. With a NULL token the
native RTL comparator reaches a missing default-integrity SID for this input.
A declared token fixture (SYSTEM owner/group, no default DACL or trust SID,
variable integrity SID) makes the dependency observable: medium/high/system
integrity returns the inherit-only low label unchanged; untrusted/low returns
`0xc0000446`. Native token queries used classes 10, 4, 25, 6 and 41. These are
controlled inputs, not evidence for the real servicing process's token. Even
for a file, the successful descriptor retains this explicit inherit-only
label; it cannot be inferred from ordinary explicit ACE propagation rules.
`CopyExplicitFileACL` and `InheritFileSecurity` continue to reject labels until
their required policy is represented explicitly.

### Native token acquisition for explicit directory security

The same base WCP's `SetSecurityObjectWithInheritance` (`0x218c7c`) does not
supply a NULL token to RTL. After querying the parent's security, it tests the
TEB impersonation field at `0x179c`. The zero branch calls
`NtOpenProcessToken(-1, TOKEN_QUERY, &handle)` at `0x218e54`; the nonzero branch
calls `NtOpenThreadToken(-2, TOKEN_QUERY, FALSE, &handle)` at `0x218def`.
Both paths pass that handle as argument 7 to `RtlNewSecurityObjectEx` at
`0x2190c4`, with auto-inheritance flags `0x101b`. Acquisition errors take the
failure path rather than substituting a NULL token.

An isolated parent-query fixture and the real directory label input reached
both token-open calls in native execution. The probes stopped before obtaining
any token, and supplied only the declared TEB impersonation selector and parent
descriptor. They prove call routing, not the actual servicing token's identity,
privileges, integrity level, or successful filesystem mutation.

The separate declared-token RTL fixture narrows the inherit-only dependency:
for label flags `0x0b`, token integrity RID `0x1fff` fails with `0xc0000446`,
whereas `0x2000` succeeds. Flags `3` succeed in both cases. Flags `8` (IO with
no propagation) discard the explicit ACE: at token RID `0x1fff` the result has
an effective mask-1 label for that token RID, while at `0x2000` it has no SACL.
For flags `3`, both low and medium fixture tokens accept requested low or high
labels unchanged; the RTL constructor is therefore not a proof of assignment
authorization. For flags `0x0b`, changing the requested RID between low and high
does not change the low-token failure or medium-token success. Do not model
this result as a simple requested-RID-versus-token-RID authorization check.

### Unchanged directory declarations are not permission reapplication

The only mandatory-label directory declaration in these exact runtime inputs is
`/$Recycle.Bin`, owned by the same explorer component identity on both sides
(version `10.0.26100.9444`). Its attributes and SDDL are unchanged. It exists in
the base WIM, has exactly one declaration on each side, and no required file,
link or directory descendant in this transaction. There is no explicit volume
root directory declaration. This is distinct from claiming that all identical
SDDL strings permit skipping a directory.

Native `FileInstallerPathElement` construction (`0xf36fc`) initializes record
`+0x93` to `8`. `PreprocessCurrentObject` (`0x10eeac`) compares old/new pair
`+0x18` descriptors using `CompareSecurityDescriptorFromObjectAgainstManifest`
(`0x10f060`, comparison flags `2`). Equal descriptors preserve the security-
unchanged bit unless record `+0x93 & 1` requires reconsideration and a new pair
exists. The old-side tail of `ProcessDirectory` accumulates that bit from prior
`+0x93 & 2`, then sets bit `2`; duplicate old-side contributions must therefore
not be discarded. Differences in default-security selection, ownership state,
attributes and other operation flags also participate in dirty selection.

`PreprocessDirectoryChanges` (`0x10edcc`) recursively marks a child whose own
state and descendants are unchanged with `+0x94 & 4`. The commit traversal skips
that child. A declared leaf fixture with native-constructed records, separate
old/new allocations of the real Recycle Bin descriptor, equal owner states and
attributes, and one old contribution retained `+0x93 == 0x0a`, acquired
`+0x94 == 4`, and returned changed=false. The native directory commit then
returned success in 133 instructions without reaching filesystem callbacks.
Changing only the label mask from 1 to 2 cleared the skip bit and reported a
change; independently setting the repeated-old-contribution bit also forced
security work. These controls establish the no-op boundary without inventing
an effective servicing token or bypassing label semantics for an actual update.

Grouping declarations for investigation (without collapsing their order) gives
1,368 destinations across both sides: 1,322 have exactly one identical before/
after declaration, three singleton pairs differ in descriptor metadata, and
43 have additions, removals or repeated contributions. The changed singleton
paths are Windows/AppCompat/Backup, Windows/AppCompat/AIDD, and
Windows/AppCompat/Programs; actual source metadata must determine their
security differences. These counts are not a commit plan: unchanged ancestors
can contain changed descendants, and repeated owners need native reduction.

The unchanged-leaf control was subsequently repeated through actual native
hierarchy construction and reduction, not just hand-filled record flags.
`CFileInstallerHierarchy` construction (`0x1527d8`) and initialization
(`0x15bbfc`) completed; initialization supplies the NT prefix `\??\` and a
native identity authority. That authority parsed the real explorer display
identity through `0x3c850`. `ProcessDirectory` (`0x10dc50`) received the NT
Recycle Bin path, flags `3`, old/new operations `2`/`1`, attributes `6`, the
native identity, an empty filter list and the two separately allocated security
pairs. Native lookup (`0x41b94`) returned owner states `4`/`4`, attributes
`0x86`/`0x86`, and flags `+0x93 == 0x0a`. Recursive preprocessing and commit of
the native drive node again skipped the leaf and returned success without
filesystem calls. Repeating the old contribution through `ProcessDirectory`
changed `+0x93` to `0x0b`; preprocessing cleared the security-unchanged and
subtree-skip bits and reported dirty. No identity, comparison or reduction
function was replaced.

These installer-emulation probes use declared heap storage, not a booted
Windows process. Native CRT string routines required page-backed allocations
because they perform page-safe vector reads beyond the requested string size;
rounding only to 16 bytes was insufficient for substring starts. The bounded
heap fixture retains the requested heap handle, supports page-backed allocation
and flags-zero reallocation, and rejects unsupported flags/large requests.
Missing CRT memset was forwarded to the actual NTDLL implementation. A run
whose hierarchy initialization was interrupted by an instruction limit was
excluded and repeated with full checked completion before collecting the
native-reduction evidence above.

The three changed singleton AppCompat descriptors remove the Local Service
(`LS`) full-access OI/CI ACE while retaining the other ACEs. They require actual
security work, unlike the unchanged Recycle Bin leaf.


### Ordered directory reduction and comparison

The native `CFileInstaller` constructor (RVA `1526a0`) owns its hierarchy at
`+18`, sets hierarchy `+170` to the installer, and initializes installer `+10`
to false. Initialization later selects that byte from coordinator flag `800`.
A separately allocated hierarchy therefore lacks a valid owner pointer for the
repeated-new-declaration collision branch; synthesizing a policy object is not
an equivalent fixture. Native constructed installer/hierarchy fixtures accept
repeated owned contributions, preserving the reduction behavior below. This
observation does not authorize ignoring collision/filter policy in production.

`ParseDirectory` starts attributes at `80` and owner at false. Manifest dispatch
sets old-side security selection only for a reference, but new-side selection
unconditionally. Metadata ownership is true for owner=true, non-default
attributes, or a security pair. Owned contributions replace attributes (clear
`200`, set `80`) and identity; an absent pair retains a prior selected pair.
Non-owning contributions cannot downgrade an already-owned side. Repeated old
contributions accumulate the security-change bit. Private reduction preserves
all contributions and counts repeated owned additions for later policy checks.
Native before/after preprocessing vectors cover these cases, including new
owned declarations with no security reference: they are not necessarily no-ops.

`CompareSecurityDescriptorFromObjectAgainstManifest` with flags=2 is asymmetric:
only the object-side ACL drops inherited ACEs. Independent identical descriptors
containing inherited ACEs need not compare equal. ACE order, flags, sizes, SID
bytes and callback suffixes matter; both masks map generic bits to file rights.
Protection and owner/group-defaulted bits participate; ACL AI/AR/defaulted bits
do not. Present NULL versus empty DACL differs, whereas present NULL SACL can
match empty (or object-side inherited-only) SACL. Absent ACL remains distinct.
Native controls verify generic/full-access equivalence, inherited ACE selection,
protection, absent/NULL/empty distinctions, callback suffix inequality, and the
previous mandatory-label equal/changed-mask cases. The private comparator is
bounded to simple ACEs, callback allow and mandatory label; it is not an access
check or inheritance operation. Public descriptor component inspection stays
format-only, with aligned bounded components and checked ACL entry extents.

On the pinned 26300.9457 transition, ordered reduction covers 1,368 destinations,
with 21 repeated-owned-addition destinations, 26 repeated-old destinations and
49 new-side default-security selections. Own-object preprocessing marks 99
changed destinations; `$Recycle.Bin` is unchanged. This is not a subtree skip
plan: implicit ancestors, file changes, discovered children and security
propagation still have to participate before committing the directory graph.


The remaining propagation gate is explicit in disassembly: AddEntriesForAutoInherit
reads hierarchy `+170` -> installer `+8` -> coordinator `+4` and returns before
filesystem calls unless flag `80` is set. With that flag, it queries the directory
name (vtable `28`); enumeration (vtable `80`, flags=1) requires the record's
inheritance bit or a DACL-present selected new descriptor (or, with no new
reference, a DACL-present old descriptor). Enumerated directory children have
unchanged-subtree bit cleared and inheritance bit `+95 & 10` set. The final pass
also clears unchanged-subtree for existing hierarchy children, and clears their
security-unchanged bit when they lack the inherited-update marker. Coordinator
Initialize (`144f70`) copies its first flags argument to `+4` before additional
support-policy adjustments. The exact offline caller's flag-80 selection still
needs proof; do not assume enumeration is universally enabled or disabled.


### Ordinary-transaction inheritance enumeration policy

The propagation gate above was traced to configuration rather than offline
status. `CRawStoreLayout::InitializeConfigurationOptions` (`9f3c4`) queries
GUID `ac66b742-8d1e-4ff0-ae13-68dda5863993`, the `MobileStore` DWORD, default
zero. It writes layout `+2c` only when the result equals **1**, not any nonzero
value. The raw query (`9efd0`) first reads
`SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/Servicing`; a missing or
non-DWORD/non-four-byte value falls back to `COMPONENTS/Configuration`, then
the supplied default. Valid policy zero overrides a store value of one.
`CreateVirtualStoreOverStore` initializes the transaction's raw layout using
that same configuration mechanism; it does not invent an offline default.

`CCSDirectTransaction::AnalyzePrimitiveInstallers` (`1c676c`) tests transaction
`+f04` (its raw layout `+ed8`, plus `2c`) at `1c687a` and selects primitive
flag `10`. `PerformPrimitiveInstallation` (`14e424`, mapping at `14e653`)
converts that to coordinator flag `80`. The ordinary support vtable's numeric
query (`1c8190`) forwards to the same raw-store query. Coordinator initialization
also queries GUID `22b816d4-3603-495c-af4b-b38c04724288`, `SmiHiveUpdates`, and
ORs its **raw numeric result** into the flags at `14515d`; this override must
not be simplified to a boolean. Its default is zero on this ordinary path.
Other observed boolean policy adjustments do not set bit `80`.

Both configuration keys are absent in the pinned 26300.9457 WIM image6, so
`MobileStore` and `SmiHiveUpdates` select zero/default. The private policy
selector independently reports `enumerate_children=False` on those hives.
This disables `AddEntriesForAutoInherit` for this ordinary direct transaction,
not all directory inheritance or security changes. Explicit hierarchy children,
file descendants, parent security on newly created objects, and their own
commit decisions remain necessary. Repair and HKCU-smart-installer coordinator
construction are separate paths and are not covered by this selector.


### Runtime source identity is side-specific

A runtime transition's `identity` is its stable analysis label, not necessarily
the identity of both component manifests. The actual tar.exe transition retains
label BsdTar/10.0.26100.9278 while its after manifest is 10.0.26100.9711. Using
that label for exact payload lookup would select the wrong source version.
It is not by itself proof of distinct native `FileInfo` objects; see the
version-independent interning controls below.
Private runtime analysis now preserves `component_identities` for each side,
and file, link, security and directory declarations carry `component_identity`
separately. Missing exact identities in synthetic inspection records do not
authorize source construction. Native directory own-change comparison evidence
is unaffected; any file-source equality inferred from the old label is invalid.

Native subtree preprocessing was independently exercised with bounded allocated
records (no filesystem hooks): a removed grandchild marks its clean parent and
root changed while an independent clean sibling receives `94 & 4`. Making the
grandchild unchanged makes the full subtree unchanged and sets child skip bits.
A file leaf without source-info pointers gets own-change `93 & 80`; it keeps its
implicit ancestors active. Private graph preprocessing preserves that distinction
and requires already reduced/own-preprocessed file records, including extra links.
It is not permission to skip all unchanged directory declarations independently
or to omit files from a commit graph.


After rebuilding actual runtime records with side-specific identities, 24,807
projected file/link declarations cover 13,232 destinations with no repeated
contributions on the same side. All 11,575 two-sided destinations have different
component identities. This is not a file installation proof: writable-file,
link, collision, phase and removal semantics still govern commit.

A separate native `PreprocessCurrentObject` fixture isolates source identity
from content equality. With one shared FileInfo pointer on both sides and equal
nonempty hash inputs, it returned zero with changed=false and `93==8` in 188
instructions. Changing only the old FileInfo pointer to a distinct allocation,
while retaining the same hash input, returned zero with changed=true and
`93==88` in 192 instructions. The required CRT memcmp import was forwarded to
native NTDLL, not replaced with a comparison result. An earlier stopped
missing-import run was excluded. This matches the source-pointer check at
`10efce` after the native hash comparison and prevents equal-content assumptions
from suppressing a genuinely distinct interned source. Display-identity
inequality alone does not establish that condition.


### Native file reduction and source interning

Fresh `CFileInstaller` construction plus its native NT-prefix initializer
(`11e06c`) and file identity-map initializer (`926ac`) permits bounded
`ProcessFile` execution without initializing filesystem/security providers.
This is deliberately not full `15bbfc` initialization or a commit experiment.
The identity authority is native (`1a1cc8`), and display identities are parsed
by native `3c850`; no comparison, interning or reduction result is replaced.

`InsertFileInfo` (`cb9e4`) hashes the identity with flag 1. Its comparator
(`cc040`) uses AreEqual flag 2 when either key's `ccb24` classification is true:
absent versionScope, or present nonSxS. Native explorer 9444/9711 inputs return
the same pointer for the same source name, but this does not mean that every
version field is ignored for both scopes. Further native GDI+ controls show
that absent scope retains major/minor and ignores build/revision: 1.0.26100.9444,
1.0.26100.9711 and 1.0.26200.9444 coalesce; 1.1 and 2.0 do not. The same rule
holds without type=win32. Explicit nonSxS also coalesces changed major/minor.
The private key includes this scope-dependent version-family tuple. Omitting
it caused four same-side GDI+ collisions and was corrected, not bypassed.
Case differences also coalesce; changing name, architecture, type, or removing
an explicit nonSxS attribute does not. Filename comparison is independently
case insensitive and preserves relative source prefixes: `Amd64\UNIDRV.DLL`
and its case variant coalesce, but `UNIDRV.DLL` alone is distinct. Private
source keys reject other scopes, unknown identity attributes, traversal names
and non-ASCII comparisons rather than guessing broader equivalence.

This narrows the preceding allocated-pointer experiment: swapping an actual
FileInfo pointer still forces change, but the 11,575 version-changing paired
runtime destinations all retain the same bounded native source key. The exact
24,512 projected primary declarations have no same-side source-key collisions.
Full component identities remain mandatory for locating payloads and manifests.

Native ProcessFile/preprocessing controls (old before new, equal present hashes)
produced these `(new state, old state; flags93,94,95; changed)` results:

- ordinary `0/1`: `(2,0; 08,88,01; false)`, including version-only changes;
- inherit `40/41`: `(2,0; 38,88,01; false)`;
- absent/inherit `0/41`: `(2,0; 20,88,01; true)` after clearing bit 8;
- writable `8/8`: `(1,0; 08,e8,01; false)`;
- ordinary/writable `0/8`: `(1,0; 08,aa,01; true)`;
- synthetic immutable/link priority control `10/11`: `(2,7; 88,88,05; true)`;
- isolated writable links `18/18`: `(7,7; 88,88,07; true)`.

The isolated links were dirty because they had no primary hashes. Actual ordinary
InstallComponent links use old/new flags `10/10`: the new primary receives flag
1, but the link loop does not. With primary calls populating their shared
FileInfo, these links preprocess to `(7,7; 08,88,07; false)`. The synthetic
`10/11` control instead becomes `(2,7; 08,88,05; false)`. Link flags bypass
primary metadata even when nondefault attributes are supplied. Immutable flag 1
takes precedence over link flag 10, but is not emitted by the ordinary link loop.
File state inequality alone does not mark a change (unlike directory states).
These native controls back the private reducer and regression tests. The reducer
requires explicit native flags and hash records, rejects unsupported flags and
same-side collisions, and does not authorize copying, deletion or security work.

The fixture uses page-backed bounded heap allocation/reallocation/free and
native NTDLL string/locking implementations. Declared process storage supplies
TEB/PEB, empty environment and CRT TLS; native RTL initializes the needed locks.
The exact base lacks the SideBySide/Tracing key, and the query fixture permits
only that absolute name with NAME_NOT_FOUND. NULL event notification returns
invalid-handle failure. Interrupted dependency-discovery runs are excluded.

### Native file-input producers

On the same pinned WCP, CmsGetFileHashInformation (110a20) converts the nested
SHA256/Identity declaration to HashInfo fields `+18=2`, `+1c=1`, followed by the
32 decoded digest bytes. These fields are digest-method and transform enums,
not a CryptoAPI ALG_ID. Native enum parsers plus the parsed-structure getter
returned the exact manifest digest in a successful bounded control. All 24,902
exact before/after file declarations use this supported shape; the private
selector rejects legacy attributes and other hash/transform combinations.

IsBootCritical (60940) selects category membership with name
Microsoft.Windows.Categories, token 365143bb27e7ac8b, typeName BootCritical and
version 1.0.0.0. Native controls accept case changes in the first three fields,
reject other versions, tokens and BootRecovery. Do not infer this from the
component's name. There are 265 matching file declarations in this transition.
Captured InstallComponent/UninstallComponent calls establish new-only flag2
for boot-critical files, flag8 for writable files, flag40 for a selected security
reference, and flag10 for links. Nonwritable new primaries get flag1 unless
coordinator bit20000 suppresses it; links do not inherit that primary-only bit.
The ordinary primitive mapping cannot set bit20000, but raw SmiHiveUpdates can.

**Compression default correction:** parsed File constructor e083c writes a
qword 1 at +1d0: compress defaults true, while destinationPath-presence byte
+1d5 defaults false. ParseFile attribute index4 sets +1d5; index2 reads compress.
Of the 24,902 file declarations, 24,890 omit compress and twelve explicitly set
false. An earlier inspection defaulted omission to false; that metadata was
invalid. ParseFileComponentInfo copies +1d0 to FileComponentInfo+104.
CFileInstaller+2c0 is a compression mode, not an installer phase. Initialize
115cac calls IsCompactOSEnabled (116010), then selects mode1 for false and mode2
for true. The predicate reads SYSTEM/Setup/Compact: an exact DWORD with nonzero
value enables it; absent/wrong-type values do not. This selected base has no
Compact value. Thus flag20 is absent here despite the true per-file default.
Mode2 with compress=true emits flag20 on primary/link calls. This flag model
does not implement on-disk compression.

DoComponentOperation5f5ec uses parsed File+1d5 as projection input, except for
the dualModeDriver identity type detected by helper5e54c. Absent destinationPath
on ordinary identities dispatches to ProcessUnprojectedFile282f10, which still
interns FileInfo and retains before/after source paths, hashes and compression
bits; it is not permission to discard the declaration. All 390 currently
unresolved declarations have absent destinationPath and type empty or win32,
not dualModeDriver. Unprojected effects and complete native commit remain open.

ProcessUnprojectedFile controls returned success for old flag0 (4,214
instructions) and new flag21 (3,415), sharing the same version-family FileInfo.
The old/new hash pointers occupy +f0/+f8; +114/+115 retain compression and +116
retains new flag1. There is no runtime destination inserted. This flag1 comes
from a component-wide scan for parsed File+128/+130, populated by ParseGac and
ParseNgen respectively. It is not the projected immutable flag. Captured calls
for compression mode1, compress=true, managed=false yielded old/new 0/0;
managed=true yielded 0/1; mode2 yielded 20/21; mode2 with compress=false again
0/1. These captures stop at the actual native ProcessUnprojectedFile entry.

With the corrected version-family key and compression policy, all 24,902 exact
primary declarations (24,512 projected and 390 unprojected) plus 295 links reduce
to 13,117 source records and 13,232 runtime destinations without same-side
collisions. The 6,695 own-changed destinations are unchanged by this correction;
24 new unprojected declarations carry the managed-assembly flag. Zero projection
cases remain unresolved in this bounded selection. Source paths, payloads,
security/default providers and native commit effects still require validation;
zero unresolved projection is not a complete installer or boot proof.

The combined graph has 15,198 nodes and 816 dirty directory subtrees, of which
717 have unchanged own metadata. Case-insensitive traversal of the selected
WIM directory children finds 240 missing directories: 222 implicit ancestors
with changed descendants, fifteen explicit changed directories and three
explicit unchanged directories (Windows/CSC, Windows/Prefetch and
PerfLogs/Admin). The last three remain clean even with all file work included.
Top-level WIM `files` is not a recursive image inventory.

A separate native CommitFileChanges145720 snapshot, with the reduced ordinary
immutable test.dll record and flags0, returned success in 329 instructions
without invoking either provider object. Path and FileInfo bytes remained
unchanged. Replacing only its new digest and running native own-preprocessing
produced 93=88/94=88/95=1. Commit then reached SIL vtable+10 in 282 instructions
(return RVA146502), with flag1, access100001, share7, options4021 and the source
component directory string. The concrete SIL vtable at301f60 identifies slot10 as OpenFilesystemDirectory
(11f630) and slot80 as TransferFileEx (df8b0). The observer stops at that request; no provider
result or filesystem effect has been fabricated. This is a commit-entry
comparison, not successful changed-file installation.

A later independent fixture uses native `RtlGetDirectSystem` (`0x17ae0`),
which returns success after 5,604 instructions and supplies the actual
`0x301f60` SIL vtable. Four existing in-memory NT file callbacks are installed
selectively; the native RTL, heap and TEB/TLS setup are retained. Native
`OpenFilesystemDirectory` opens both source and destination directories,
returning disposition 1. This fixture contains explicit synthetic source and
old-target bytes, not an updated operating-system image.

The dirty immutable commit opens the source file, then issues
`NtFsControlFile` control `0x90284`, with 24 input and 208 output bytes. A
fixture filesystem that explicitly rejects this control with `0xc0000010`
allows native execution to continue. Native `VerSetConditionMask` and an
exact-base version provider satisfy the following 10.0.14394 version check.
The next native boundary is `NtSetInformationFile`: class `0x48` (low DWORD),
88-byte input, flags `0x73`, null root handle and an absolute counted UTF-16
System32 destination. No success is returned for that unimplemented request.
This is evidence of the concrete native link request, not a completed file
commit, verified hardlink model or image-servicing result.

The version-check provider's x64 ABI must marshal its 64-bit condition mask
as one argument; x86 splits it over two stack slots and returns it in EDX:EAX.
A cross-architecture regression preserves opaque high mask bits and checks
success/equality/failure for both ANSI and Unicode version structures, with
a poisoned spare x64 register to reject accidental x86 argument decoding.

#### Full file-hierarchy default-security initialization

The later fixture completes `0x15bbfc` natively, rather than substituting
individual descriptors into an otherwise partial hierarchy. Its five output
slots contain these descriptor lengths and controls:

| Factory flag | Hierarchy offset | Bytes | Control |
| --- | --- | --- | --- |
| `0x200` | `0x1a0` | 44 | `0x8000` |
| `0x10` | `0x1b0` | 256 | `0x9814` |
| `4` | `0x1c0` | 60 | `0x8f14` |
| `1` | `0x1d0` | 60 | `0x8f14` |
| `0x40` | `0x1e0` | 256 | `0x9814` |

All five match the portable SDDL compiler in owner, group, DACL, SACL and
control, using the actual embedded strings. Flag `0x40` differs from `0x10`
by `CIOI` on every DACL ACE. Flags 1 and 4 select the same
`O:SYG:SYD:AIARS:AIAR` string. Generic access masks remain unmapped at this
stage.

Successful construction does not require fabricated domain policy: the
native parser continues after explicit unsupported LSA policy access and
uses fixed and numeric SIDs for these strings. Native NTDLL CRT routines
perform comparison, numeric conversion and character classification; only
bounded allocation and unsupported subsystem boundaries are modeled. An
abandoned earlier parser invocation had retained its lookup spinlock and
reference. Native release/deinitialization in an independent fixture restored
those two values before retrying; treating that stale lock as a missing Sleep
implementation would have hidden the actual prerequisite failure.

With the bounded hardlink/basic-information fixture model, a fresh native
`TransferFileEx` returns status 0, disposition 3. The partial-initializer
fixture still returns `0xc000000d` from the later default-security path.
Completing initialization removes that null-descriptor failure, but does not
itself complete installation: native security assignment queries the
System32 **parent** ACLs (information mask `0xc`, 360-byte subset of the exact
424-byte base descriptor), then requests process-token statistics. The file
security setter, full commit, general open-target hardlink semantics and
whole-image servicing/boot remain separate verification obligations.

The bounded modern-token experiment requests classes 10 (statistics), 4
(owner), 25 (integrity label) and 6 (default DACL); class 6 is not modern
TokenStatistics. The fixture explicitly supplies SYSTEM owner/group,
system-integrity label and a SYSTEM-full-access default DACL. Modern
statistics occupy 56 bytes, including ModifiedId. These are chosen fixture
facts, not recovered live-token state. Native inheritance also passes heap
tag 5 (`0x140000`) to its allocator; the tag occupies bits above
`HEAP_TAG_SHIFT=18` and is not an allocation-mode flag.

Passing these queries did not establish successful security assignment:
execution entered diagnostic formatting and object-name lookup, then stopped
at another unmodeled syscall. No final setter descriptor or full-commit
success was captured. An earlier native security call/return discriminator
is required before extending that diagnostic path or promoting the fixture
callbacks into an image-servicing implementation.

A fresh isolated constructor narrows that diagnostic detour: native RTL also
queries `TokenProcessTrustLevel` (class 41), first on the current-process
pseudo-token `-4`, then on the supplied token. The older fixture rejected the
pseudo-handle as invalid. Declaring both fixture tokens unprotected, with no
trust SID, allows one uninterrupted native constructor call to return status
zero in 4,071 instructions. The 256-byte result has control `0x9c14`; all
components match `inherit_file_security` for the embedded flag-`0x10` file
default and exact System32 parent. This remains a declared-token experiment,
not evidence of the token used by an installed operating system.

An isolated WCP provider-interface fixture then executes
`SetSecurityObjectWithInheritance` for a file, security-info `0x9000000f`,
and the same child descriptor. Its parent query supplies the 360-byte
ACL-only descriptor generated by native `RtlQuerySecurityObject`. Execution
stops before the final provider mutation, with option 8, the target handle,
and the same security-info low DWORD. The outgoing descriptor is 248 bytes,
control `0x9014`: owner, group and DACL equal the RTL constructor output,
but the empty SACL becomes present-NULL. This captures WCP's final request;
it does not establish the resulting NTFS descriptor or successful full
file commit. The interface fixture is not the native direct-SIL factory.


The empty-SACL discriminator is in `CreateSecurityDescriptorFromParts`
(`0x82df0`), not an unconditional ACL-filtering rule. The native reconstruction
checks SACL ACE count and the effective protected-SACL request. Empty
unprotected SACL becomes present-NULL, while empty protected SACL and nonempty
audit SACL remain ACLs. Empty DACL remains an empty ACL. Complete native
`SetSecurityObjectWithInheritance` vectors confirm protection independence,
protected-ID conversion, unprotected-ID replacement by parent inheritance,
file propagation removal, generic file-rights mapping and audit inheritance.
The private `build_servicing_file_security_request` composes the already proven
preparation/inheritance primitives with this bounded ordinary-file final pass.
It returns descriptor plus security-information, not a filesystem effect, and
rejects missing parent evidence and unsupported NULL/defaulted child policy.
The seven small native golden cases run without media in the private servicing
suite (23 cases). The exact System32-parent comparisons also match all parts.

The real `DirectFileSystemProvider::SysSetSecurityObject` (`0x2200a0`) was
subsequently executed to the `NtSetSecurityObject` boundary in an independent
snapshot. Its handle argument is a pointer to an NT handle, not the NT handle
itself. For option 8 and no transaction it passes handle `0x4000c`, information
`0x9000000f`, and the **same pointer and exact 248 bytes** captured above. The
fresh call reaches the observer in 6,846 instructions. The observer stops
before mutation; it does not return fabricated success.

The direct-provider prefix needed explicit fixture process prerequisites:
native `RtlInitializeCriticalSectionEx` initializes NTDLL `FastPebLock`, a
zeroed declared shared-user-data page and an empty process environment support
native environment reads, and CRT memset forwards to native NTDLL. Without
lock initialization a contended-lock/shared-data stop is misleading. The
loaded-module inventory contains only the deliberately mapped modules, so
`LdrGetDllHandleEx` returns DLL-not-found for its specific `wdscore.dll` lookup.
The exact base SOFTWARE hive independently confirms the queried
`Microsoft/Windows/CurrentVersion/SideBySide/Tracing` key is absent; only that
rooted, access-`0x101` query returns name-not-found. Other module/registry
queries stop as unsupported. None of these ancillary adapters implements NT
security assignment. The resulting stored NTFS descriptor, real full-SIL file
commit, and complete-image boot/reboot remain unverified.


### Kernel assignment after the WCP request

The exact base NTFS image identifies `NtfsModifySecurity` at `0x1d460c`.
At `0x1d469b` it calls `SeSetSecurityDescriptorInfoEx` with a pointer to the
information mask, requested descriptor, pointer to current descriptor, flags
`0x4000`, its pool selection and `IoGetFileObjectGenericMapping`. Exact symbols:
NTFS `21A54A0319E06EE0B07B4B4904A01D9F1`, kernel
`C29EBFB06B78B3C020DCA66D99713F9E1`. Kernel `SeSetSecurityDescriptorInfoEx`
(`0x881180`) calls `RtlpSetSecurityObject` (`0x87f780`). These are actual kernel
routines, not the similarly named user-mode RTL approximation.

A bounded in-process kernel fixture executes that wrapper and its real owner
validation. It declares a primary SYSTEM identity with an owner-capable
TrustedInstaller group, no impersonation, no trust SID, one thread with no
pending APCs, and a single-thread token resource. Only fields read by these
native paths are mapped; unexpected token/thread reads fail. Subject capture
and release delimit that declared context; resource callbacks check balanced
acquire/release. Pool adapters allocate bounded kernel-space blocks for tag
`0x64536553`, with observed `ExAllocatePool2` flags `0x100` and legacy pool
class `0x401` after supplying pool argument 1. This chosen pool setting is
fixture policy, not a recovered live NTFS configuration. Native descriptor,
SID, owner membership, ACL combination and normalization routines are not
replaced by successful callbacks.

Descriptor addresses must be in kernel space: the native owner-SID validator
rejects addresses at or below `0x7fffffff0000`. An earlier low-address fixture
returned `STATUS_INVALID_OWNER` even though native owner membership returned
true. Kernel-address input buffers remove that prerequisite failure. The full
initialized wrapper then returns zero in 2,010 instructions for the exact old
276-byte kernel32 descriptor and WCP's 248-byte request. The result has the
same parts/control as that particular request and leaves both inputs intact.

That equality is **not** a general assignment rule. Independent controls show:

* Existing mandatory integrity-label ACEs survive an audit-SACL update, even
  when the requested SACL is NULL. New audit ACEs precede the retained labels.
* Existing audit ACEs are replaced, not retained with the labels.
* Even a protected empty requested SACL becomes protected present-NULL when
  no retained label remains. Empty DACL remains empty.
* Requested protection and file controls replace the tested old AI/protection
  controls; final control values include `0x8014`, `0x9014`, and `0xb014`.
* With NTFS's `0x4000` flag, `RtlpNormalizeAcl` removes exact duplicate ordinary
  allow ACEs, including duplicates separated by deny ACEs. It does not union
  differing masks or remove duplicate denies or conditional allows. The two
  identical CBS SYSAPPID callback ACEs remain separate.

The private `assign_servicing_file_security` implements only this bounded
metadata transformation, not token authorization or filesystem mutation.
It accepts the full ordinary-file request mask, mapped effective file ACEs,
ordinary audit entries and retained mandatory labels. Unknown SACL categories,
unsupported controls, NULL DACL requests and combined ACL overflow fail closed.
Native-derived regression cases cover label retention, audit replacement,
protected-NULL control, empty DACL, duplicate distinctions and input immutability.
The focused private servicing suite now passes 24 cases.

A fresh `SetSecurityObjectWithInheritance` call also executes real direct
provider query (`0x142220`) and set (`0x2200a0`) methods. Provider handle wrappers
need the NT handle at offset 0 and the non-transactional flag byte at offset 8;
an eight-byte wrapper is insufficient for queries. Native RTL services the NT
query callback. The NT setter applies the independently kernel-compared policy
to declared plugin-owned current metadata, recording its actual request and
assigned result before returning success. The isolated full security operation
returns zero in 18,135 instructions, records exactly one target write, preserves
the parent and closes its explicitly opened token. This interface fixture is
still not a constructed full SIL file-hierarchy commit, NTFS disk mutation, or
whole-image boot/reboot proof.

#### Full dirty immutable file commit with native security

A reconstructed full hierarchy now completes native `CommitFileChanges`
(`0x145720`) for one changed immutable primary: status 0 in 33,668 instructions.
The context uses the actual `RtlGetDirectSystem` factory (status 0, 8,974
instructions in this initialization context), actual SIL vtable `0x301f60`,
full `0x15bbfc` hierarchy/default-security initialization, native identity
parsing, old operation 2/new operation 1 declarations and native preprocessing.
The declaration hashes are distinct synthetic 32-byte values with method 2 /
transform 1; this fixture is not payload-authentication evidence.

The file provider starts fresh for this commit, with explicit synthetic source
and old-target bytes. It implements only the observed bounded link/basic-info
requests, forwards security subset queries to native RTL, and applies the
independently kernel-verified security metadata assignment. The source has an
explicit mandatory-label descriptor and the parent has the exact base System32
descriptor. The result has exactly one hardlink replacement, one basic-info
update and one security write. Source and target alias the same file entry and
both expose the new bytes and assigned security. The setter request is the
previously verified 248-byte `0x9000000f` request; final descriptor components
match the independent kernel result including the retained old mandatory label.
Byte-for-byte comparison of self-relative descriptors is inappropriate when
component placement differs. Parent security is unchanged. All transient file
handles and the process token close; only the caller-owned destination-directory
handle remains open.

This proof uses declared NTFS volume attributes `0x300ff`, maximum component
length 255 and name NTFS, plus explicit rejection of FSCTL `0x90284`. It rejects
unmodeled paths and open-target replacement rather than pretending general
POSIX/hardlink behavior. It neither services a real image nor proves other file
states, directory creation, registry/DOQ/advanced-installer work, CBS final state,
trust closure or boot/reboot.

AMD64 snapshots retain callback bindings but **do not clone mutable plugin
state**. Merely placing file state in `emulator.plugin` does not isolate these
AMD64 trials. Each effect-bearing trial above creates a fresh file provider and
reopens its destination directory; earlier snapshots sharing a provider are
initialization evidence only. A native-address hook forwarding to the generic
kernel callback must also preserve its dispatch name; the fixture instead
implements strict file-handle removal directly for `NtClose`, avoiding a
fall-through that initially left transient handles open. Only the corrected
fresh trial supplies the cleanup evidence above.

#### Whole-input file states and writable-file validation

The repeatable update inspector now builds the complete reduced/preprocessed
file and directory hierarchy before its runtime REPL. On the exact pinned
input, it reproduces 13,117 source families, 13,232 file destinations, 15,198
path nodes and 816 dirty directory subtrees. File counts by
(operation, before state, after state, own changed) are:

| Tuple | Count |
| --- | ---: |
| (3, 0, 2, true) | 5006 |
| (2, 0, 0, true) | 329 |
| (1, 0, 2, true) | 1327 |
| (3, 0, 2, false) | 6383 |
| (3, 0, 1, false) | 34 |
| (3, 0, 1, true) | 5 |
| (3, 7, 7, true) | 27 |
| (3, 7, 7, false) | 120 |
| (1, 0, 7, true) | 1 |

The five changed writable paths are the x64/x86 PowerShellGet 1.0.0.1
`PSModule.psm1` files, x64 PSReadLine 2.0.0 DLL, and the two Default-profile
Windows PowerShell start-menu shortcuts. Their declarations are systemData,
flags `0x48` on both sides; preprocessed security flags are `0x88`, directory
flags `0xe8`. The other 34 writable paths are own-clean.

Native writable state-1 commit calls `CFileInstaller::ValidateFileHashAgainstManifest`
(`0x274164`) before replacement. Its transaction context uses the real SIL
pointer at context+`0xd08`. `DoesFileMatchHashInManifest` (`0xd69e0`) calls
`0xd6a40` with a pointer/count span of 56-byte HashInfo elements. By contrast,
the ProcessFile hash-vector input is a begin/end/capacity-end pointer range.
Supplying a pointer/count/capacity record there creates an invalid huge span;
that earlier fixture evidence is rejected. Corrected pointer-range input was
observed at the comparator as exactly one element.

With real SHA-256 digests of the fixture bytes, native comparison returns true
for unchanged old bytes. Native hash-cache static initializer `0x1272d0` and
native initialization of `g_CryptProviderCacheLock` (`0x433800`) are prerequisites.
The destructor registration is retained in explicit fixture state. The existing
CryptoAPI plugin computes the digest from bytes read by the native file-hash
path; no comparison result is substituted. A locally modified control returns
status 0 after native mismatch diagnostics, preserving its bytes without link,
basic-information or security writes. Native NTDLL `_vsnprintf_s` and `strncmp`
handle its bounded CRT formatting/comparison requests.

For matching old bytes, native execution requests `FileDispositionInformationEx`
(class 64), four-byte flags `0x17`, then creates a separate target file and copies
source bytes. The bounded model preserves detached open-file identity during
unlink and rejects other simultaneously open target handles. It models EOF
sizing and actual reads/writes, not successful no-ops. The declared thread is
not impersonating, and its process token has no enabled SeRestorePrivilege.

This path exposed an NT write ABI defect: `NtWriteFile`'s Length is ULONG,
not a full 64-bit stack slot. The reusable callback now masks to the low DWORD.
An x86/x64 regression poisons the upper x64 bits, checks actual written bytes,
IO_STATUS_BLOCK count/canary, and rejects an oversized low-DWORD length without
changing the file. It failed before the fix and passes afterward, alongside
the version-mask ABI regression.

With that corrected provider loaded from the workspace, the fresh native
matched-file trial copies `new-fixture-file` correctly and reaches final file
security assignment at 48,615 instructions. It deliberately stops because the
newly created target has no modeled initial descriptor. The observed setter
request is `0x9000000f`, not a narrowed mask inferred from a transient RAX value.
Initial NTFS file security (including label policy) must be established before
this writable commit can be called complete. The native probe later expired
at its explicit two-hour lifetime; its successful immutable result and partial
writable result are documented evidence, not a remaining live checkpoint.


### Fresh writable, removal and link commit controls

The pinned base kernel's `SeAssignSecurityEx` (`0xa48960`) reaches
`RtlpNewSecurityObject` (`0x8cea00`) through `SeAssignSecurityEx2` (`0x43d980`).
The NTFS new-file path calls `SeComputeAutoInheritByObjectType` and adds
normalization flag `0x4000` before assignment (`0x2d59f4..0x2d5a78`). For a
NULL creator descriptor and the exact System32 parent, the bounded file-type
fixture computes inheritance flag 1. Native assignment with flags `0x4001`,
explicit SYSTEM owner/primary group/default DACL, SYSTEM integrity, no client
token and no trust SID returns success in 6,674 instructions. The result is
168 bytes, control `0x8404`, five inherited DACL ACEs, and no SACL. Locks and
kernel APC-disable count return to zero. This is an explicitly declared token,
not a claim to have captured a running servicing process's token.

Low-integrity and medium-integrity controls distinguish label policy: low
integrity produces a no-write-up mandatory-label ACE, while medium and SYSTEM
produce no SACL for this parent. Do not invent a label just because the token
has one. A parent without DACL auto-inherited control computes flags `0x4000`;
native inherited ACEs then lack the INHERITED_ACE flag. Thus merely calling the
existing flags-0x101b inheritance helper and adjusting descriptor control bits
is not a general creation implementation. Kernel `IoCreateObjectTypes`
(`0xc287e4`) passes a length-0x78 initializer for the file type; the newer
mandatory/trust policy fields are copied by `ObCreateObjectTypeEx` only for a
length of at least 0x80 (`0xab8e27..0xab8e43`). The zero-policy file-type fixture
must not be generalized to arbitrary object types.

A fresh WCP/NTDLL machine, actual SIL factory, full hierarchy initializer,
native identity parser, ProcessFile and preprocess calls now complete the
writable commit in 44,996 instructions, status 0. The file provider attaches
the independently kernel-derived initial descriptor only when the exact
synthetic target is newly created under the unchanged exact parent, with a
NULL object-attributes security descriptor. This is not a generic provider
fallback. All six native NtCreateFile queries in that run supplied NULL
security. The run reads the real old bytes for manifest SHA-256 validation,
unlinks the old target, creates a separate file, sets its EOF, copies the new
bytes, changes basic information once and assigns security once. There is no
hardlink operation. Final security is 248 bytes/control `0x9014`; the old
file's mandatory label is not carried across delete-and-recreate. The final
request still uses security information `0x9000000f`.

The fresh locally-modified control returns status 0 in 24,561 instructions,
reads the old file once, and preserves both its bytes and descriptor with no
link, deletion, creation, sizing, basic-info or security mutations. Both runs
close transient file/token handles; only the caller-owned directory remains.
Each trial constructs a new mutable provider; CPU/memory snapshots do not
isolate plugin state. The revised fixture uses exact base kernel32.dll
security for both source and old target and a declared token statistics group
count of one (the integrity group).

All 329 exact-update removal records have old state 0, ProcessFile flags 0x40
and file flags 1. A fresh native control for that class returns status 0 in
4,247 instructions, unlinks the target once, does not read/hash it or modify
security/basic information, and closes the transient handle. An exploratory
writable-only removal lacks a transaction prerequisite and is not evidence
for that different class.

All 28 dirty link records use new ProcessFile flags 0x50: 27 have old flags
0x50/operation 3/file flags 7; one is operation 1/file flags 2. A link-only
fixture without primary FileInfo prerequisites enters diagnostics and is
invalid as commit evidence. Populate the primary calls sharing the source
identity first, and pass an empty hash vector/NULL selected hash for the link
calls. With those prerequisites, the paired-link control returns status 0 in
9,731 instructions; the added-link control with an initially absent target
returns status 0 in 9,691. Each performs one hardlink and no independent
security/basic-info mutation. The alias shares source bytes/security, and
transient handles close. These bounded synthetic controls establish effect
branches, not execution of the 6,695 changed destinations on an OS image.
Dirty-directory creation/propagation, whole-image application, registry/DOQ,
advanced installers, CBS state, trust, and fresh boot/reboot remain required.

### Directory creation and explicit protected-DACL commits

Fresh native `CommitDirectoryChanges` (`281f4c`) traverses the children of the
supplied parent node. A real coordinator (`2714f0`) is required for its security
pair caches; a zero-filled stand-in does not establish a valid allocator.
`FindOrAddNewSecurityDescriptor` (`bc314`) and `ProcessDirectory` (`10dc50`)
construct the explicit declarations used here. The whole pinned transaction
has 240 missing directory nodes: 222 dirty implicit ancestors, 15 dirty new
owned declarations, and three clean nodes. The explicit set contains three
Client.CBS directories, eleven Filons directories, and ProgramData/whesvc.

For a missing fixture child beneath the actual System32 descriptor, WCP first
supplies the creator descriptor `O:SYG:SY` (both ACLs absent). Native
`SeAssignSecurityEx`, using NTFS's computed `4001` flags and the declared SYSTEM
subject, returns 384 bytes/control `8404`. This is not the descriptor passed
later to the setter. The corresponding NULL-creator ordinary file yields
168 bytes/control `8404`. Adding an owner-enabled TrustedInstaller group does
not alter that directory creation result. The kernel constructor requires
`SeExports+200` to contain the real owner-rights SID, S-1-3-4, constructed by
`SepVariableInitialization`; an uninitialized comparison is not policy evidence.

Fresh directory commits with no selected pair return zero in 6,025 instructions
and create the directory without a separate security setter. Explicit WHESVC,
CBS and Filons commits return zero in 14,322, 19,557 and 19,568 instructions,
respectively. Each creates one directory and issues one security update, with
no independent basic-info or hardlink update. The exact requests are 140, 576
and 584 bytes, all control `9f04`, information `9000000f`. The `0300` bits are
**auto-inherit requests**, not owner/group-defaulted flags. Directory inheritance
retains inherit-only generic ACEs and the callback condition payloads. Native
`SeSetSecurityDescriptorInfoEx` preserves these components and returns control
`9c14`: AR cleared, AI retained, and the absent audit SACL made present-NULL.

The conditional owner is not authorized merely because the subject is SYSTEM.
With the actual `SeLocalSystemSid` global initialized, the SYSTEM-only control
returns `c000005a` in 435 instructions; adding the owner-enabled TrustedInstaller
group yields success in 4,007/4,010 instructions. The former null SID dereference
was a missing fixture prerequisite, not an authorization result. The user-mode
fixture's token statistics were updated to reflect the additional group.
A separate native SACL-category control removes old audit entries but retains
an actual mandatory-label ACE (1,730 instructions). The base kernel32 SACL used
in this segment contains an audit ACE, not a mandatory label; it must not itself
be cited as a label-preservation control.

The private runtime now provides bounded directory request/assignment and
SYSTEM creation constructors. Directory requests currently admit the protected
DACL/absent-SACL forms above with an absent parent SACL. Creation requires an
auto-inherited parent DACL with usable inheritance and an absent parent SACL;
legacy inheritance and token-default-DACL fallback remain explicit failures.
This is important: merely clearing helper control bits on an arbitrary legacy
parent does not reproduce native inheritance ACE flags. Independent native
file/directory creation goldens exercise generic-rights splitting; request
byte goldens cover all three exact explicit directory families. The servicing
suite passes 26 tests, including existing file assignment regressions.

A fresh integration fixture using the portable assignment (not a golden-value
setter) reproduces the CBS native commit and its independently computed kernel
result. A separate fresh implicit-ancestor fixture uses a real new ProcessFile
contribution beneath an undeclared missing directory. Directory commit creates
the ancestor, then commits its child file: one creation, one hardlink, one file
security update and one file basic-info update, returning zero in 36,086
instructions. There is no separate directory setter. Repeating this integration
after replacing the creation golden with the portable creation constructor
produces the same native effects and matches the independent kernel descriptor.
These are synthetic file-provider integrations, not changes to or boot evidence
for the complete OS image. Existing-child propagation and complete transaction
effects remain separate requirements.

The exact-parent inventory refines the creation bounds: parents can carry
SACL_AUTO_INHERITED while their SACL is absent or present-NULL. Native
`SeComputeAutoInheritByObjectType` then selects `4003`, and creation returns
`8c04`, not `8404`. Neither input form creates SACL_PRESENT in the child.
Independent generic-rights file/directory controls and the actual CBS Assets
parent reproduce this distinction; the actual-parent kernel run takes 43,735
instructions. A fresh WCP CBS commit with that parent returns zero in 19,572
instructions and has the same setter components as the System32-parent case.
The portable constructors now admit absent/NULL parent SACLs and preserve the
parent's SACL AI control during creation, while non-NULL SACLs remain guarded.

Whole-input in-memory descriptor construction covers all 237 dirty missing
directories in parent-first order: 212 initial descriptors have control 8404,
25 have 8c04, and 15 receive explicit assignments. The ten existing parent
nodes are own-clean. This coverage check does not mutate the image. There are
also 579 existing dirty directory subtrees; 84 have own changes, including two
removals. Of the other 82, 49 select default security; explicit descriptor
controls are 8404 (4), 9004 (16), 9404 (3), 9014 with SACL (5), and 8004 (5).
Three existing-parent descriptors have non-NULL SACLs. These shapes must not be
silently folded into the new-directory-only rules.

Existing default-directory reduction requires the exact ProcessDirectory
selection flags: old=1, new=3 when neither side has an explicit security pair.
Old=3 is a different, unchanged control and must not be used as evidence for
the actual transaction. The exact old/new pair yields a native setter request
8f04/information 3000000f. Its inherited components match native directory RTL;
kernel assignment retains those components and returns 8c14 (3,882 instructions
for the System32-parent fixture). A fresh full commit using portable assignment
returns zero in 30,855 instructions with one security update and no creation or
basic-info update. The API requires explicit `default=True` rather than silently
interpreting an absent caller selection as default. The suite now passes 27
servicing tests, including independent default-request bytes.

The actual AppCompat transition removes the LocalService allow ACE; using equal
old/new SDDL is only a no-op control. The exact transition, current descriptor
and parent return zero in 16,452 instructions with one security update. The real
coordinator security cache requires native CRT memmove when constructing two
distinct pairs. Native AddEntriesForAutoInherit (280ec8) immediately returns
unless coordinator+4 has bit 80; the same policy guards SimpleRecurseUpdateSecurity
(2833ec). The pinned image's parsed policy has enumerate_children=false, so the
zero-bit fixture matches that configuration rather than bypassing an enabled
propagation requirement. Additional commit phases, directory removal, remaining
SACL forms and full transaction/image integration are not established by these
bounded direct-commit calls.

### Descriptor interning and existing-directory audit updates

The coordinator's exact-SDDL cache matters before preprocessing. WCP
`CompareSecurityDescriptorFromObjectAgainstManifest` has a pointer-equality
fast path at RVA `10f098`; separately allocated inputs still take its asymmetric
inherited-ACE comparison. Equal cached NetworkList descriptors produce no own
change and no commit effect (836 instructions), while repeated old ownership
contributions force the security-selection bit even for identical text. Do not
infer no-op from equal SDDL without reducing all contributions in order.

The pinned servicing directories' noninheritable ordinary audit ACE produces a
432-byte request with control `9f14` and information `9000000f`. Using the actual
Packages parent with its noninheritable audit SACL produces the same request.
Independent kernel assignment returns `9c14`, preserving all four components;
a fresh native commit using the portable assignment completes with one setter.
Propagating audit ACEs and other SACL categories remain outside this bound.
CBS Logs uses an explicit unprotected DACL: request `8f04`, information
`3000000f`. Kernel metadata assignment preserves components and clears AR.
Owner authorization is separate: SYSTEM plus the TrustedInstaller owner group
cannot assign BA (`c000005a`); an explicit BA owner-enabled group permits it.


### FileMap phase and directory-removal boundary

A full native `CFileInstallerHierarchy::CommitChanges` invocation (RVA
`0x28140c`) on the pinned base's WindowsMigration removal completes with zero
in the in-process fixture. The input includes the real old UserExperience-Desktop
identity, all eight removed Assets files with verified source bytes, both removed
directories, actual ancestor/sibling metadata, and all 3,776 resident FileMaps
provided lazily. This is a bounded subtree transaction, not full update evidence.

With normal policy, `CommitLuaCdfs` (`0x282818`) precedes the final filesystem
pass (`CommitDirectoryChanges`, `0x281f4c`, phase bit 2). This transaction deletes
the WindowsMigration map, then its Assets map, before deleting the eight files
and finally Assets and WindowsMigration. It also rewrites three ancestor maps:
root (556 to 564 bytes), Windows (3,084 bytes), and ClientCBS (10,140 bytes).
All three payloads change and receive security-information `0x9000000f` writes.
There are no file creations, hardlinks, or basic-information writes in this trial.
An isolated final-phase call deletes maps later and therefore cannot establish
top-level transaction ordering. Calling the directory routine with flags zero
is likewise not a directory-removal test.

`DeleteDirectoryIfPossible` (`0x282cc0`) enumerates real immediate children,
ignoring `.` and `..`; the nonempty Assets control retains the directory and map.
The fixture observes native extended disposition class 64, four bytes, flags
`0x11`. Actual FileMap ownership must participate: an empty directory alone is
not enough to infer whether an implicit directory can be removed. Skipping the
LUA phase or substituting an empty FileMaps directory changes the input policy.

The fixture declares the actual Windows root through KUSER_SHARED_DATA and
supplies the store root as a native IRtlDirectory through the primitive-installer
support interface. CDF parsing, identity parsing, traversal, and serialization
remain native code; these interface declarations are not replacements for those
algorithms. The observed output still needs portable construction and complete
whole-image integration validation.


### FileMap creation default-DACL prerequisite

The actual FileMaps parent (control 0x9c14) has no inheritable DACL ACE and a
noninheritable audit SACL. Native kernel creation therefore takes token-default
DACL fallback, not inherited WRP ownership. SeComputeAutoInheritByObjectType
selects 0x4003; SYSTEM/TI subject file and directory controls are 0x8c04, SYSTEM
owner/group, no SACL and the supplied token default DACL. A two-ACE default
(SYSTEM full access, Administrators file read) survives unchanged, independently
of the one-ACE SYSTEM default. The bounded Starlark creation constructor now
accepts explicit `token_default_dacl` for this case; omission still fails where
fallback is required. It rejects inheriting/generic-rights/deny/default-NULL
forms rather than generalizing unobserved token policy. Native input/output
security captures and inherited-DACL precedence are tested. A fresh MathCAT
new-map LUA run with this constructor agrees with the native kernel control in
map bytes and final resolved security. This does not complete token acquisition,
all file commit effects, or whole-image servicing.


### Writable projection hash-preservation control

For the real amd64 Microsoft.PowerShell.PSGet transition from 26100.1 to
26100.9549, the projected `PSModule.psm1` is writable (ProcessFile flags 0x48).
An isolated final filesystem phase (`0x281f4c`, phase bit 2) hashes the actual
584,735-byte old destination against its declared SHA-256. With unchanged bytes
it returns zero, deletes and recreates the destination, reads the 585,677-byte
new WinSxS source, copies exactly those bytes (independently hash checked), and
applies security-information 0x3000000f. This is a copy, not a hardlink.

A separate fresh fixture appending a 24-byte user comment returns zero but
preserves the modified 584,759-byte destination byte-for-byte. It reads only
that destination for hashing: no new-source read, deletion, creation, resize,
or security setter occurs. A failed old hash is therefore not by itself an
error or permission to overwrite this writable projection.

Both source payloads are genuine: the old WinSxS DCS source is expanded before
use and matches the manifest digest, and the new payload is opened through the
selected native UUP component plan. The CryptoAPI boundary computes SHA-256
from native-provided buffers, not expected digest substitution. The native
provider cache requires its chain initializer (0x1272d0) and critical-section
initializer (0x1770); static image bytes alone do not initialize its lists.
The bounded adapter supplies allocation and memset for the real payload size.
No WCP file decision is hooked. These are isolated phase controls, not proof
of full CommitChanges ordering, other writable cases, or whole-image servicing.


Fresh full native `CommitChanges` controls subsequently completed: 795,549
instructions for the unchanged real PSModule and 774,505 for the modified
control, both returning zero. Their payload decisions match the isolated phase.
Both first rewrite six existing ancestor FileMaps (root through 1.0.0.1), with
unchanged resolved entries; selector 2 paths become absolute selector 0 paths,
and unused identities are pruned. Each rewritten map receives 0x9000000f security.
The unchanged projection then copies the exact new payload; the modified one
has no non-FileMap mutation. Writable files are not added as immutable entries.

`select_servicing_writable_file_action` implements only this observed paired
0x48/state-1 shape, comparing current projected bytes against the old primary's
identity-transform SHA-256. It validates both bound source identities and hash
shapes, and rejects absent projections or other transition shapes. It returns a
decision without performing writes or bypassing source/security/transaction
validation. All five changed writable projections in the pinned base select
replacement. Private regressions include preservation, source mismatch and
unsupported transform controls. Whole-image servicing remains unvalidated.


### Immutable inherited-security commit selection

Fresh full `CommitFileChanges` (WCP 26100.9441, RVA `145720`)
controls cover the paired inherit-marker class and the new-only inherit-marker
class. Native ProcessFile flags old/new `40/41`, attributes `a0`, and a NULL
selected security pair produce node bytes `02 00 03 b8 88 01`; new-only flags
`41` produce `02 00 01 e0 80 00`. The complete calls return zero in 29,310 and
29,244 instructions respectively. Each creates one hardlink and sends one
security request, with no basic-information write; node bytes remain unchanged.
Transient file/token handles close. These controls use synthetic file payloads,
actual System32 parent security, and fresh mutable providers.

The native request is 168 bytes, control `8014`, information `3000000f`.
Its components match the existing portable file-request constructor with an
explicit `O:SYG:SY` default pair and the actual destination parent. The inherit
marker does not mean retain the source's old protected descriptor or omit the
setter. A separate explicit-WRP new-file control (`02 00 01 c0 80 00`) returns
zero in 30,484 instructions with the same one-link/one-setter/no-basic-write
shape. Source staging attributes therefore remain a separate prerequisite;
these leaf calls do not prove they initialize arbitrary source metadata.

The private immutable request selector validates observed operation/state/flag
classes and chooses explicit versus SYSTEM-default input. Independent full-call
request bytes exercise the inherited branch in tests. The exact transaction's
16 paired inherited and 160 new inherited entries are included, not silently
folded into WRP defaults. Parent descriptors must be those effective at commit
time. Neither this selector nor the controls prove whole-transaction ordering,
owner authorization, source staging, registry/driver effects or updated boot.


### Component-file staging security differs from runtime link security

The same pinned WCP's `CCSDirectTransaction::ApplyAclsAndWofCompressIfNecessary`
(`0x1c8f38`) selects filesystem default security `0x10` for ordinary components
and `0x80` for identities whose type is `driverUpdate` or `dualModeDriver`.
`IsIdentityDriver` (`0x1080c0`) reads the identity's type, not its filename or
runtime destination. The two defaults have TrustedInstaller owner/group and a
protected six-ACE DACL. Ordinary SYSTEM access is GRGX; the driver default
instead grants SYSTEM FA. Administrators, Users and both application-package
principals receive read/execute. The driver constant's SACL has AIAR rather
than AI, but file-request construction removes those control bits.

A fresh native helper execution with compression flag zero, real SIL file
objects and the exact base kernel32 component-directory parent reaches
`NtSetSecurityObject` with a 248-byte descriptor, control `0x9014`, present-NULL
SACL and information mask **`0x9000001f`**. A type-only driverUpdate control
changes SYSTEM's access mask while retaining the request mask and size.
Unlike runtime link security (`0x9000000f`), staging includes LABEL information.
The private `build_servicing_staged_file_security_request` has independent
native descriptor goldens for both selections; its caller remains responsible
for native identity classification and effective store-parent selection.

The exact kernel `SeSetSecurityDescriptorInfoEx`, NTFS flags `0x4000`, confirms
that the NULL-SACL staging request removes an existing medium integrity-label
ACE. Changing only the mask to `0x9000000f` preserves that ACE. This is not a
blanket copy-request rule or permission bypass: native owner and integrity
checks execute under a declared primary SYSTEM subject, owner-capable
TrustedInstaller group and SYSTEM integrity. The additional label path reads
`SeExports+0x1e8`; native `SepVariableInitialization` at `0xc47a0d/0xc47a14`
loads `SeMediumMandatorySid` into that field. The fixture supplies that exact
medium SID and a token integrity group at index 2, attribute `0x60`, rather
than substituting a successful integrity-check callback. Sparse unknown
subject fields still fault. Pool state lives in snapshot memory.

With actual kernel assignment at its NT boundary, the complete ordinary
staging ACL helper returns zero in 122,711 WCP instructions, with exactly one
security request, no basic-attribute writes and a closed transient token.
The source file handle remains caller-owned. This proves the bounded ACL
helper with synthetic payload content, not complete StageComponentFile,
compression dispatch, source attribute initialization or image activation.
`assign_servicing_staged_file_security` implements only the observed NULL-SACL
metadata transformation. It rejects non-NULL staging SACLs and the runtime
mask; the ordinary assignment API continues to reject the staging mask.


### Non-default immutable attributes are not covered by the default skip

The full immutable-file examples with manifest attributes `0xa0` must not be
read as proving that immutable commits never set basic information. The actual
update has six dirty state-2 files with non-default attributes: five `0x81`
(read-only plus NORMAL input) and `Fonts/staticcache.dat` at `0x87` (read-only,
hidden, system plus NORMAL input). Their paired old/new declarations have the
same attributes; an old/new difference is not required for the setter.

Independent complete CommitFileChanges trials, changing only the declaration
attributes to `0x81` and `0x87`, each return zero in 23,524 instructions. Each
records one hardlink, then one NtSetInformationFile class-4 request, then one
security request. Basic-information length is 40, all four timestamps are
zero and the attributes field is the exact respective `0x81`/`0x87` input.
These trials use a bounded metadata-recording provider, not native NTFS
normalization of FILE_ATTRIBUTE_NORMAL. At `0x146870` the immutable path
compares the selected node attributes with `0xa0` and skips only that default;
otherwise `0x146890` invokes CFile::SetAttributes before the security call at
`0x1468e7`. The surrounding per-operation booleans still govern whether this
block is reached. The five non-default read-only targets are System32's
coreglobconfig.dll, icu.dll and secureassessmenthandlers.dll, plus SysWOW64's
coreglobconfig.dll and icu.dll.

Source transfer itself is a separate operation: AddComponentFile's SIL
TransferFile delegates to TransferFileEx (`0xdf8b0`). Its mode 0 selects move,
mode 1 copy and mode 3 hardlink. StageComponentFile selects those modes from
operation flags, not manifest attributes. This static dispatch evidence does
not prove which mode CBS selected for every real payload or its source-file
creation metadata.

### FileMap collision final policy (26100.9441 WCP)

The native `CFileInstaller::CommitChanges` final block at RVA 281d66..281f19
checks file collisions first (`FileHierarchy+180` -> 80188306), then directory
collisions (`+188` -> 80188316 only when `CFileInstaller+10` is true). The
bounded native block, with real native CRT formatting and debugger filtering
disabled at the OS boundary, produced: empty=0 (13 steps), 19 directory
collisions/tolerant=0 (2308), 19/strict=80188316 (2820), one file collision=
80188306 (2585). No collision-decision function was replaced. This proves the
collision check only, not earlier effects or the separate final +198 check.

`InitializeCFileInstaller` (115d6b) copies coordinator flag 800 to the strict
byte. Coordinator initialization (144f70) queries configuration GUID
f39479e2-c59b-4a02-8973-9f58eeca9ffb, mapped by the raw store to DWORD
`SingleResourceOwnership` (default false), and ORs 4800 if nonzero. It also
ORs the raw `SmiHiveUpdates` DWORD. Ordinary primitive flag mapping at
14e5f1..14e676 never supplies 800. Configuration uses SOFTWARE servicing
policy before COMPONENTS Configuration, preserving explicit zero overrides.

The pinned image has both values absent (default zero). Its 19 directory
FileMap dot-entry collisions are therefore nonfatal under this policy; the
resident dot owners remain retained and collisions remain reported. This does
not relax ordinary file ownership conflicts. Private runtime helpers and
configuration/native-result regression cases encode this bounded policy.

### SIL copy creates a normal file; it does not copy basic metadata

A bounded native `CSystemIsolationLayer::CopyFileW` (RVA f466c), ordinary
flags zero, copied a nonempty 16-byte source through native `CreateFileW`
(f49dc) and `CopyFileContents` (f50dc), returning zero after 4635 instructions.
At the OS boundary it requested file creation attributes 80, queried source
FileStandardInformation, set destination EOF (class 20), then read/wrote the
exact bytes. It made no FileBasicInformation or security setter calls. The
fixture explicitly had no impersonation token and disabled backup privilege;
all file operations were bounded in-memory NT callbacks, not replacements for
native copy logic. Source and output byte equality were inspected. The first
empty-copy run used the wrong fixture backing field and is not evidence for
nonempty copy; the corrected run read the source backing and copied 16 bytes.

This records the raw NT creation request, not NTFS archive-bit normalization,
creation timestamps, creation security assignment or the actual staging mode
for every update payload. StageComponentFile selects transfer modes from its
operation flags; proving this SIL branch alone does not choose those flags.

### Registry value reduction checkpoint (26100.9441 WCP)

Complete before/after runtime-manifest inspection found 297896 declared keys
and 454554 values, not that many required writes. Besides HKLM/HKCR there are
236 HKCU and 40 HKU key declarations. Value options include mutable=true (346),
append (38), prepend (2), replace (664), and IEDownlevelValue (1104). Keys also
include virtualization and override policy. Do not flatten all declarations
into unconditional hive patches. Counts include both sides of transitions.

An isolated native registry storage fixture now runs real ProcessValue
(187c0), InterpretValueData (18518), and PreprocessRegistryChanges (143f7c).
It uses native constructors (installer 153750, node 99278), a parsed component
identity, and SetCurrentComponent (101170). The ordinary flags-zero DWORD
controls reduce add operation 1 to the new side, remove operation 2 to the old
side, and old-then-new to operation 3. For identical old/new DWORD 1, native
blob interning shares the data pointer and preprocessing sets value flag 80,
returns zero and reports no change (195 instructions). For DWORD 1 -> 2,
it retains separate data and reports a change with no skip flag (179).
No registry filesystem/provider effects occurred. This does not yet establish
mutable/priority/multi-string/ownership arbitration, root mapping, key security
or commit effects. The separate operation-4 empty-node result is not a general
operation-4 policy.

Observed node layout: values begin/end/capacity at +30/+38/+40 (pointers, not
counts). Value name LUNICODE_STRING at +18, new/old blobs at +30/+48, owner
identity at +60, new/old types at +68/+6c, flags at +70, new/old counters at
+74/+78, operation byte +84. The counters were 10000 for a single ordinary
contribution; their general semantics still require independent controls.

The paired-DWORD fixture subsequently ran real SIL OpenRegistryKey (13e50)
and CreateValuesInKey (10aba4) with bounded NtOpenKey[Ex], NtQueryValueKey and
NtSetValueKey callbacks. Native flags 1 mark mutable at value +70/+72 bit 0;
identical declarations still receive skip bit 80. For old 1 -> new 2:

- mutable/current DWORD 1: query then set 2, return zero, 1987 instructions;
- mutable/current DWORD 9: query, preserve 9, zero, 1168;
- mutable/current absent: query, preserve absence, zero, 1047;
- mutable/current type BINARY with the same four bytes as DWORD 1: query,
  preserve type/data, zero, 1158;
- ordinary/current 9 or absent: set 2 without a query, zero, 1027 each.

Identical old/new DWORD 1, ordinary current modified or absent, returns zero
in 76 commit instructions with neither value query nor setter. The caller's
opened SIL key remains live after this leaf; leaf completion does not imply
key-handle release or whole transaction commit. The private paired-DWORD
selector implements this exact bounded policy; it requires prior ordinary,
single-owner reduction, no override/hint and matching mutable flags, and
rejects unsupported before/after types. It is not general registry application.

The same full native path, using a raw typed-value NT boundary, confirms
ordinary SZ/EXPAND_SZ/BINARY/QWORD matches query then replace (1987 commit
instructions). SZ comparison is byte-exact: `Old` versus `old` preserves
(1168), and a missing terminator or different length preserves (1161).
BINARY 0102 -> 030405 replaces only matching current 0102; modified bytes
or length preserve. QWORD uses eight hex-encoded bytes in this native
InterpretValueData path; text `1` is rejected, not parsed as decimal.
Equal SZ/BINARY/QWORD declarations skip query/set in 76 instructions even
when the current value is absent. The private ordinary-value selector now
supports these types and DWORD, but excludes type transitions and MULTI_SZ.

MULTI_SZ is not ordinary mutable preservation. Native old `One` -> new `Two`
with current `[One, User]` produces `[User, Two]` (3652 instructions), with
current `[User]` produces `[User, Two]` (3365), and current `[one]` produces
`[one, Two]` (3373), preserving case-distinct entries. Both mutable flags 1
and ordinary flags 0 use this merge path. Missing current (2785) or current
of type DWORD (2904) writes `[Two]`; equal declarations still skip without
query/set (76). These are leaf effects through the real SIL, not a complete
registry transaction, key policy, or whole-image application.

#### Multi-string grammar and operation modes

The native multi-string ProcessValue path is not CSV. A first character other
than a quote makes the entire text one entry: commas, whitespace and newlines
are literal. A leading quote selects exactly adjacent `"entry","entry"` syntax.
Doubled-quote escapes, whitespace after commas, trailing commas, unterminated
quotes and trailing garbage return c0150006. Backslashes are literal. Empty
quoted entries contribute no strings; `"A","","B"` produces `[A,B]`.
The malformed-input controls originally stopped on an unavailable diagnostic
import, which was not a rejection result. They were rerun with bounded native
NTDLL `_vsnprintf_s` forwarding and returned the error above. InterpretValueData
alone does not parse MULTI_SZ: its empty blob result is not decoded value proof.
The portable `assembly_registry_data` decoder now uses this observed grammar;
its typed data output still does not encode contribution/commit operations.

Native ParseOperationHintType (e2fec) returns append=0, replace=1, prepend=2.
ProcessValues 19caf..19ccd maps those enums to ProcessValue flags 10,20,08 hex,
respectively; mutable adds bit 1. The earlier flags-zero probe follows the same
merge path as explicit append, but is not the actual ProcessValues flag mapping.
Explicit append/10 reproduces the duplicate/order control (4683 instructions).
Each old entry removes only the first case-sensitive current occurrence; new
entries already present are not moved or duplicated. Current duplicates survive.
Repeated new contributions are deduplicated after native warning diagnostics;
repeated old entries remove one occurrence each. The private merge selector
retains those semantics for ordinary single-owner append/prepend contributions.

Prepend/08, old One -> new `[A,B]`, current `[One,User]`, yields `[A,B,User]`
(4182); existing `[B,User,One,A]` yields `[B,User,A]` (4354), not a reordered list.
Replace/20 writes only the new list without querying current (1033), including
an empty MULTI_SZ. Mutable replace/21 queries: exact old list sets (1993), modified
preserves (1167), absent preserves (1053). All three modes skip equal declarations
in 76 instructions. Replace-mode duplicate contributions remain excluded from
the private selector pending arbitration proof.

Append with no new entries and no remaining current strings deletes the current
value through real NtDeleteValueKey (2661), including a wrong-type value (2462)
or an existing empty MULTI_SZ (2468); an absent value needs no delete (1566).
The unquoted empty declaration is distinct: it writes four zero bytes (2800),
not deletion. The bounded private selector deliberately rejects empty-string
contributions rather than conflating these cases. It rejects noncanonical
current MULTI_SZ data instead of assuming native malformed-data behavior.
No result here proves key creation/security, multi-owner arbitration, registry
root mapping, hive application, transaction cleanup or successful OS updating.

ParseRegistryValue initialization (136df9..136e22) zeroes the hint field at +35,
so an absent hint selects append/enum 0. Explicit modes remain necessary when
selecting paired behavior; hint changes between sides are not yet supported.

Single-sided ordinary values differ from paired mutable updates: new-only DWORD
sets without querying, even when mutable/current modified (1031 instructions;
1027 without mutable). Old-only DWORD deletes without querying (922), including
modified mutable values; absent deletion is tolerated (3926, with diagnostics).
SZ addition/removal and BINARY addition/QWORD removal followed the same paths.
Single-sided MULTI_SZ removal still merges, e.g. removing One from [One,User]
sets [User] (3278), rather than deleting the whole value. The ordinary selector
therefore excludes MULTI_SZ and delegates paired values to the bounded selector.

Raw numeric types retain all 32 bits: FFFF0012, 00020004 and 00100000 with
old 0102 -> new 030405/current old bytes query and set (1987), while modified
FFFF0012 current data preserves (1161). InterpretValueData's default raw-hex
branch handles types above 11. REG_NONE instead ignores text: both hex-looking
and non-hex declarations produce an empty blob; new-only `not hex` sets type 0
with zero bytes. Equal paired NONE skips. The assembly decoder now reflects
this rather than interpreting REG_NONE declaration text as hex.

Ordinary type transitions are supported without conflating byte equality:
DWORD 1 -> BINARY 01000000 sets type 3, even though the bytes match (1027).
Mutable/current DWORD 1 queries and sets type 3 (1987); mutable/current BINARY
with those bytes preserves (1158), because the old type differs. The private
ordinary selector now permits these transitions and includes type in its
no-op comparison. MULTI_SZ-to-other transitions remain outside its scope.

### Registry machine-view mapping and real overlap checkpoint

Native TranslateWowRegistryPath (1dfa0), machine 14c, was compared against all
88 machine-rule prefixes plus a child from its static rule graph (2ff710):
all matched the longest-prefix/insertion-anchor model. Shared exceptions and
COM subtrees are not a blanket Software prefix. Native identity binding and
MakePathRedirectedIfRequired (1be98) give amd64 bitness 2 (unchanged), wow64/x86
bitness 3 (translated). The private policy is pinned to WCP 26100.9441 and
rejects unsupported deeper/multiple explicit WOW6432Node placements. One such
node directly below Software/Classes can stay, relocate or disappear depending
on the resolved shared/redirected branch. Native 249350 confirms HKLM maps to
Registry/Machine and HKCR to Registry/Machine/SOFTWARE/Classes.

Physical machine-key grouping of the actual 454554 value declarations found
208631 single-owner equal groups, 34988 single-owner changed groups, 305
multi-owner equal groups and 7 multi-owner changed groups; 376 non-machine
records remain outside this mapping. These are template comparisons, not
committed effects. Changed templates have no explicit mutable/hint/priority
options; runtime.system32 and runtime.windows are their only macros.

Do not choose multi-owner values from analysis traversal order. Isolated native
ProcessValue with two owners and equal priority keeps the last bytes (reversing
arrival reverses the result); explicit priority 1 beats 0 in either order.
Whole-key/queue ordering is not yet established. The inspected ntprint.inf and
prnms003.inf registrations are in DRIVERS and select amd64 resident packages,
while analysis lists their x86 contributions last. **SYSTEM also contains a
DriverDatabase**, with 267 DriverInfFiles/DriverPackages and ConfigOptions=256;
its ntprint.inf entry is absent. DRIVERS has a separate DriverDatabase without
a ConfigOptions value. The earlier missing-key observation concerned the
individual driver registration, not the entire SYSTEM database. These facts
reject blindly applying analysis order, but do not by themselves establish
which hive a primitive or advanced driver operation must modify. No hive or
image effects have been applied in these probes.


### Native ordering policy is not primitive registry arbitration

Pinned WCP 26100.9441 `ChangeListOrderingContext::Order` (`5caf0`) is used
by `AiQueue::ApplyAdvancedInstallerOrdering` (`268ce0`). The resident amd64
servicing-stack `GlobalInstallOrder.xml` has 1,575 component references. A
native parse with `RtlWcpCreateMicrodomFromXmlBlobEx` (`8e100`) followed by
`ParseAndPopulateOrderFile` (`4df00`) succeeds with all 1,575 records; the
fixture forwards CRT byte operations to the real NTDLL and does not replace
XML parsing or ordering decisions. Large copies require the emulator's
UNPCKLPD, MOVNTPS and SFENCE support. Native tail transfers, rather than nested
invocations, let large CRT operations remain within resumable execution budgets.

`FindArchitectureOrderFor` (`12f0d8`) gives x86=3, wow64=4, amd64=5,
msil=2 and arm64=8 in native controls. `Order` first compares queue category
(+14) and the operation-4 distinction (+10); eligible equal categories then
compare identity policy order, installer policy order and architecture. Its
successful comparison result encodes validity in byte 0 and signed ordering
in byte 1 (`ff01` means less, `0101` greater). With category 3 and operation
2 or 4, real updated `dual_ntprint.inf` x86 sorts before amd64, and updated
MediaPlayer-Core wow64 sorts before amd64. Reversing operands reverses the
result. With operation 1, unmatched driver identity ordering reverses, whereas
the equally listed MediaPlayer references still use ascending architecture as
the final tie-break. The unmatched-identity fixture explicitly selects the
native deterministic identity-hash mode; this is not evidence for the actual
transaction's ordering flags.

These comparisons **do not establish primitive registry processing order**.
`PerformPrimitiveInstallation` (`14e424`, loop beginning `14e76d`) consumes
its supplied change-list vector in order. `GenerateServicingFamilies`
(`13ffa4`) emits its component-servicing hash table's iterator order
(`140549..1405bf`); `AnalyzeForChangelist` (`8cc0c`) walks the resulting
family vector. Neither a lexicographically sorted analysis inventory nor the
advanced-installer architecture ranking can substitute for that population
and enumeration. In particular, isolated equal-priority `ProcessValue`
controls retaining the last contribution cannot justify choosing whichever
shared driver registration appears last in an inspection list. Registry
application, later driver-installer effects and native offline hive mounts
remain separate obligations.

### Primitive family table growth and shared-family controls

`VCComponentServicingTableTraits` insertion (`ed278`) uses native hash helper
`ed528`, seven initial 32-byte bucket chains, and a load threshold of five
entries per bucket. Successful insertions append at the chain tail. After
insertion, an entry count greater than the threshold triggers `93b04`, which
requests **twice the entry count**, not twice the bucket count. `93b88` rehashes
old buckets in index/chain order, appending each entry at its new chain tail.
A native 37-entry control returned capacity/count/threshold 7/35/35,
72/36/360, and 72/37/360 across the first growth boundary. Reinserting the
same nonSxS driver identity with a different version did not add an entry;
changing architecture did. The recurrence gives capacities 7, 72, 722, 7222
and thresholds 35, 360, 3610, 36110.

For the real shared nonSxS families, native `ed528` hashes match
`csi_identity_hash(..., omit_version=True)`. A native six-family table rehashed
by `93b88` to 7222 buckets has this order (all buckets are distinct):

| Family/architecture | Bucket |
| --- | ---: |
| MediaPlayer-Core amd64 | 75 |
| dual_prnms003.inf x86 | 371 |
| dual_ntprint.inf x86 | 1145 |
| MediaPlayer-Core wow64 | 2418 |
| dual_prnms003.inf amd64 | 4817 |
| dual_ntprint.inf amd64 | 5591 |

The actual analysis contains 34736 unique component identities and 3634
version-independent changed-family hashes. **Conditional on these bounding
the complete native family-table input**, its final capacity is 7222 regardless
of the exact count in that range. This bound is not a captured complete native
transaction. The six-family native control establishes rehash and enumeration,
not final registry effects. In particular MediaPlayer's bucket order is the
opposite of the advanced-installer architecture tie-break. Do not conflate
these layers, infer colliding-bucket order from hashes alone, or assume later
driver operations cannot alter primitive registrations.

### Dual-mode registry declarations require coordinator admission first

A whole-key registry ordering question is premature for declarations that the
primitive coordinator does not admit. In `CCoordinator::ProcessChange`
(`145320`), the file and backup-file processing precede the gate at `1454ea`.
Unless coordinator flags at +4 contain `0x400`, the native code checks the first
non-null identity at change+0/change+18 with `IsIdentityDualModeDriver`
(`5e54c`). A true result exits before `CRegistryInstaller::ProcessComponentChange`
(`edd78`, called at `14554b`) and the later primitive installers. This gate
does not skip the earlier file processing and does not authorize dropping the
separate driver operation.

An observation-only native probe stops at `145516` (dual-mode bypass) or
`14552b` (eligible for subsequent installers). With the registry installer
selected, real dual_ntprint.inf and flags zero reaches bypass in 368 instructions;
placing the identity only at change+18 takes 372 instructions and also bypasses.
Flags `0x400` reaches eligibility; `0x200` still bypasses. A MediaPlayer-Core
identity and a type-only `driverUpdate` control reach eligibility without the
override. No registry installer result is stubbed in this probe: execution stops
before either branch performs registry processing.

`PerformPrimitiveInstallation` maps input bit `0x40` to coordinator flag
`0x400` (`14e65f..14e668`). Its transaction caller `AnalyzePrimitiveInstallers`
(`1c676c`) sets input bit `0x40` from byte transaction+f05 (`1c6884..1c6890`),
the +2d option of its raw store layout at +ed8. `InitializeConfigurationOptions`
(`9f3c4`) derives layout+2d from the DWORD `ConfigOptions` under logical
`\Registry\Machine\SYSTEM\DriverDatabase`: `(value & 0x33) == 0x33`.
The pinned SYSTEM database stores 256, which does not satisfy that test.
Offline-store creation has a separate flag-dependent path that can write 0x33,
so the selected store mode must remain explicit rather than inferred from a
missing individual driver registration.

The real runtime contains 107 dual-mode driver transitions and 49,922 raw
registry declarations from them. The original all-manifest overlap counts
include these declarations; those counts are not a primitive execution plan.
This narrows the shared-driver arbitration investigation: establish coordinator
admission and driver-store mode before selecting either the primitive registry
path or the separate driver path. MediaPlayer's ordinary overlap remains.

The configuration predicate was also executed through the complete native
`InitializeConfigurationOptions` helper, with a real native SIL and initialized
layout critical section. The read-only provider supplies the pinned SOFTWARE
SideBySide/Configuration values (CreateNewWindowsVersion=1,
MobileStoreVersion=2, DontRunPoqexecInSmss=1, DisableResetbase=1), the verified
absent Policies/Servicing key, and SYSTEM DriverDatabase/ConfigOptions.
All calls return zero: input 256 and 0 yield layout+2d=0, 0x33 and 0x133 yield
1, and near-miss 0x32 yields 0. Native queries request MobileStore,
MobileStoreVersion, and ConfigOptions; the decision is not a callback stub.
This proves the option for the unmodified baseline hive view, not a different
new-store creation mode.

The separate `CRawStoreLayout::PerformDriverOperation` (`1c414c`) ultimately
calls `g_CbsHelperCallback` (`431430`) virtual +18 with the operation and
constructed driver data (`1c475c..1c4779`). Replaying raw driver manifest
registry declarations is not a substitute for this CBS driver operation.

### Admitted registry manifests, security references and key reduction

The dual-mode type gate is case-sensitive: `dualModeDriver` bypasses while
`DualModeDriver`, `dualmodedriver` and `driverUpdate` pass without the override.
The admission-aware manifest view contains 279758 keys and 404632 values. Its
203931 physical value groups leave two mixed changed-owner collisions:
MediaVersion (amd64 and wow64) and the removed perceptionsimulationservice.exe
AppID. This filtering does not remove file changes or separate driver work.

Whole manifests can be processed natively instead of synthesizing value structs.
`CWcpManifest` has vtable 3030c8 and ParseFromBlob wrapper116c70 (flags0 here).
The fixture uses an asm.v3 manifest, exact identity and HKEY_LOCAL_MACHINE:
changing only the root spelling to HKLM makes this parser return c00000b9.
ProcessKeys1adcc accepts storage, flags, side-operation and parsed manifest.
The real coordinator constructor2714f0 is required for its descriptor table
and aligned-blob pool (d20/d38); zeroing the coordinator is insufficient.
Manifest-local securityDescriptorDefinitions are resolved by the native parser.

The key node has owner identity+60, parent+68, new security pair+70 and old
security pair+78. The parent's pointer is not an old-owner field. Explicit
security chooses the owner even without owner=true. In a same-coordinator
old2/new1 fixture, identical descriptors are interned to the same pair.
PreprocessRegistryChanges143f7c returns zero and marks unchanged leaf flags81
as48, implicit ancestor4a. A changed/added/removed explicit descriptor yields
leaf00 and ancestor0a. Changing only the value yields leaf08 and ancestor0a.
CreateKeysInKey107194 skips flag40 unless flag10 also requires processing.
These are declaration reductions, not proof of committed hive effects.

Security comparison uses key mappings GR/GX20019, GW20006, GAf003f rather
than file rights. Object-side inherited ACEs are removed asymmetrically;
manifest inherited ACEs are not. Interned-pointer equality precedes that
comparison, so two equal separately allocated descriptors containing ID ACEs
are not equivalent to an interned identical descriptor in the reduction path.

All305 distinct admitted SDDLs compile with the recipe's explicit account SID.
Native controls established AN/BG/CG/OW/SO fixed aliases. LA requires the
explicit account-domain SID plus RID500; no domain is inferred from the host
or empty base SECURITY hive. The standalone LSA fixture supplies a named
account domain, a DNS-policy record without a domain SID and supports the
observed query12/query5 sequence; that response is an explicit fixture, not
an independently observed live LSA policy. Other relative aliases stay rejected.
The two real XA declarations use (!(WIN://ISMULTISESSIONSKU)); native encoding
is artx, local-attribute f8 plus UTF16 text, unary NOT a2, with ACE alignment.

### Explicit registry security construction at the NT boundary

The native registry setter83800 runs through the real SIL key and NTDLL.
Even with a protected selected DACL it opens the parent and queries parent
DACL/SACL (security-information12). The fixture supplies explicit parent/current
bytes and a SYSTEM token, not a stubbed inheritance or security decision.
The cached SID initialization registers destructor2f96a0 at CRT table430b20;
that destructor frees the cached allocation. Token queries include statistics,
owner, integrity, group, default DACL and process trust level. The captured
NtSetSecurityObject request supplies information9000000f for a protected DACL,
3000000f otherwise. Its controls are9f04 and8f04 respectively for these controls.
After the bounded NT setter accepts the write, WCP returns zero and closes the
parent and token; the caller-owned leaf key remains open.

Protected SY/KA, unprotected BU/KR with inherited SY/KA, CI generic BU/GA,
creator-owner CI/GA and OI-only parent controls match portable registry
inheritance after the caller's AR bits300 are added. Generic effective rights
map to key rights; propagation stays generic. Creator ownership splits into
an effective substituted SID and an inherit-only creator ACE. An OI-only parent
ACE survives as inherit-only19 on a key container rather than becoming effective.
These binary captures are regression fixtures for inherit_registry_security.
They establish request construction, not kernel assignment, owner authority,
key creation/deletion, default selection, or a whole registry transaction.

DrUpdate stage callback160f0 calls DriverStoreFindW, then ImportW205/245 or
CopyW9/19 for an existing package. Context410 selects ImportW versus the server
import branch. The later exact-SSU-pair inspection below establishes its
offline meaning for the selected 9703 caller; do not transfer old RVAs blindly.
The loader obtains drvstore.dll alongside DrUpdate.dll. Matching drvstore
symbols identify DriverStoreImportW9e550 -> ImportDriverPackage4b654. This is
driver-package processing, not replay of skipped component registry values.

The real registry descriptor at admitted-SDDL index278 contains a low-integrity
mandatory label with zero policy mask and TrustedInstaller owner/group. It
also reaches the native setter and returns zero after the fixture accepts its
request. The requested SACL preserves that zero-mask label; this proves metadata
construction, not TrustedInstaller owner authorization by a real kernel.
With parent CI/medium-label mask1, explicit low-label mask0 and mask1 each
select only the explicit label (flags0). With no explicit label, the parent's
medium label is inherited with flags12. Mandatory masks are policy bits, not
key rights, and zero must not be clipped away. The generic whole-descriptor
API still rejects these explicit-label layouts: category selection belongs to
caller policy and has not yet been integrated into the registry request builder.

### Registry request SACL selection and Owner Rights

Additional native key-setter captures establish that WCP normalizes empty
unprotected SACLs to absent, but preserves protected empty SACLs. An unprotected
NULL SACL also allows the parent audit entries to inherit. Protection determines
both the resulting control and the corresponding high security-information bit.
Audit ACEs precede mandatory labels even when the selected SACL lists its label
first. An explicit low label with mask zero suppresses an inheritable medium
parent label and adds LABEL_SECURITY_INFORMATION (0x10) to the setter request.
Without the explicit label, the parent label inherits CI|ID (0x12), but does not
add that information bit. A protected empty SACL blocks the parent label.
These are setter-request observations, not proof of kernel assignment authority.

Owner Rights S-1-3-4 is not substituted with the owner. Native captures preserve
it in CI|IO propagation ACEs and in effective ACEs; generic rights can still split
an effective mapped ACE from a generic propagation ACE. Creator Owner/Group
S-1-3-0/1 retain their separate substitution rules. Native binary fixtures cover
all three Owner Rights cases and the private request's SACL/category controls.
All 305 admitted registry declaration SDDLs construct requests with an explicit
SYSTEM/inheritable-key fixture parent. This checks declaration coverage only,
not actual image-parent descriptors, commit selection or registry effects.

### Registry defaults and deferred inheritance

`CRegistryInstaller::Initialize` (277d5c) obtains defaults via
`GetRegistryDefaultSecurity` (2690e0), flags 2 into installer+188 and flags 1
into +198 (storage+170/+180). Both native calls return the same bounded
`O:SYG:SYD:AIARS:AIAR` descriptor. The selected default is applied by 84220;
it must not be confused with the general explicit setter 83800. For example,
84220 with only owner/group writes information 3 without inheriting ACLs,
whereas the real default's empty ACLs request both categories.

83800 flag 1 and 84220 flag 2 select a distinct deferred path. It performs no
parent/token query, preserves generic rights, creator identities and ID flags,
and retains selected SACL order, including label-before-audit. The absent or
empty unprotected SACL becomes present-NULL with control 8514 (9514 with
protected DACL), unlike immediate inheritance's 8f04/9f04. Nonempty/protected
SACLs carry SACL AI/AR too (8f14, with protection bits as selected). The real
empty default therefore has an empty DACL, NULL SACL and control 8514 when
deferred. Native binary regressions cover this independently of immediate
inheritance. Later propagation and kernel assignment remain separate work.

### Native key creation and whole-hierarchy controls

A bounded physical registry fixture now reaches `CreateKeysInKey` (107194)
from genuinely parsed, paired and preprocessed manifests. It uses native SIL,
real installer initialization (277d5c), explicit SYSTEM token data and an empty
exclusion-list profile (coordinator flag 20000). The provider returns an explicit
new/existing disposition; it is an in-memory fixture, not a mounted image.
Identical before/after key security and values cause no leaf open/create request.
A value-only change opens/creates the leaf but does not set security when it
already exists; a missing leaf clears the security-unchanged optimization and
gets the selected security. Changed, added or removed security gets explicit or
default security respectively, for both dispositions in the ordinary fixture.
`owner=true` and `overridable=true` guesses did not select mutable-security
comparison; ProcessKeys clears key flag1 when a concrete descriptor is selected.
Do not infer mutable selection from those attributes.

The same physical boundary reaches native `CreateHierarchyInSil` (2768a8),
which preprocesses, pushes roots (279360), pops stack slots (124254), applies
values (10aba4) then traverses child keys (107194). A value-only Fixture->Changed
transition finishes with native return0, REG_SZ UTF-16 Changed, and all opened
handles closed. A missing leaf additionally requests security before writing the
value and also finishes return0 after accepting that in-memory request.

For complete key removal, native hierarchy traversal deletes the declared value,
then queries KEY_FULL_INFORMATION counts bottom-up. It deletes the leaf only
when both child and value counts are zero. An unrelated value preserves the
leaf; an unrelated parent child preserves the parent. Without that parent child,
native code also attempts to delete the now-empty implicit Software ancestor;
there is no blanket 'only explicit keys can be deleted' rule. The bounded fixture
refused that unexpected deletion, then a distinct fixture explicitly supplied an
unrelated parent child and completed return0. Both empty-leaf and extra-value
controls finish with all handles closed. These observations do not establish
kernel security assignment, mutable-tree repair, virtualization, user roots,
actual image ordering or a complete update.


### Ordinary registry hierarchy reduction and commit selection

The pinned WCP `ProcessKeys`/`PreprocessTree`/`CreateHierarchyInSil` fixtures
now distinguish ordinary key reduction from provider effects:

* Paired equal security/value declarations produce leaf operation/flags
  `1/48` and implicit Software `1/4a`. A value-only change clears the subtree
  skip, giving `1/08` and `1/0a`. Changed, added or removed selected security
  gives leaf `1/00`; the unchanged implicit ancestor stays `1/0a`.
* New-only explicit security gives `1/20`; a new-only key without selected
  security gives `1/28`, including `owner="true"`. Its implicit ancestor is
  `1/2a`. Removal gives leaf `2/08` and ancestor `2/0a`.
* Reversing addition/removal order for the paired identical fixture still
  returns `1/48` and `1/4a`. Descriptor preprocessing uses the old selection
  as object and new selection as manifest in the registry-rights comparator.
* Same-side contributions do **not** collapse into one owning record. Native
  cross-component controls retain the first new-side owning identity while
  selecting the last nonempty descriptor on each side. A subsequent absent
  security reference does not clear a prior selection. Duplicate new owners
  emit diagnostics in the fixture's default policy; the reduction records
  collisions but does not authorize them for an actual coordinator policy.

CreateKeysInKey's unchanged skip precedes any provider lookup. A missing key
therefore does not by itself defeat a skip. Once ordinary create/open is
selected, actual create disposition 1 clears security-skip bit 8: even a
value-only change then requests the selected/default security. The default
request for a newly created implicit ancestor uses deferred inheritance.
Removal opens rather than creates and queues the later empty-key check;
actual current child/value counts, not declaration counts, decide deletion.
Native hierarchy controls preserve an undeclared value and an unrelated
parent subkey. Empty implicit ancestors are deletion candidates too.

The exact actual-input attributes `perUserVirtualization="Disable"`,
`perUserVirtualization="DisableRecurse"` and
`mapDesiredAccessToMaxAllowedAccess="False"` produce ordinary reduced flags
and no additional provider operation in successful full hierarchy controls,
both with existing keys and newly created keys. Owner true/false changes
owning-identity bookkeeping, not the ordinary key's mutable bit. This does
not establish behavior for other attribute values or other installer paths.

The recipe's bounded reducer preserves contribution provenance, selected
security and collision counts; preprocessing requires a complete explicit-key
value-change map and security compiled with the target identity context.
It does not supply the native family order, overlap authorization, mounted
user roots, security assignment/access checks, propagation or hive writes.
The native provider controls accept security requests but do not emulate
kernel security assignment. No updated-image boot/reboot proof follows from
these captures.


### Registry macro strings and separate user pass

The admitted raw key inventory is HKLM 52,631, HKCR 226,851, HKCU 236 and
HKU 40. There are no key-path macros. Macro-bearing value names/data include
runtime directory names and two literal `build.PackageMoniker` declarations.
The raw `(side, architecture, key)` grouping has 278,444 groups, 710 overlaps
and 256 overlaps with multiple security/owner references; this is not physical
path grouping or a native family-order proof.

A real SIL is a prerequisite for native registry string macro interpretation:
`CRegistryInstaller` obtains it from coordinator `+d08` through `1de50` and
`668c8`. A fixture without that interface faults before semantic evaluation.
The default SIL creates new CUserProfile instances; populating one unused
profile's caches does not initialize the instance later selected by lookup.
The successful bounded fixture returns one retained native CUserProfile at
that boundary, with a supplied cached Windows path at `+28` of
`\??\Z:\FixtureOS\`. Native macro lookup, directory selection, value processing
and hierarchy commit remain unmodified. The committed outputs establish:

* standalone runtime.windows becomes `Z:\FixtureOS`, and runtime.system32
  becomes `Z:\FixtureOS\System32`, without a trailing separator;
* case-insensitive names and multiple spans expand, including a macro in the
  value's **name**; surrounding text and `%SystemRoot%` remain literal;
* `@{$(build.PackageMoniker)?resource}` remains literal, even on a new-only
  write. The recipe preserves this observed unresolved macro while rejecting
  unmodeled names. Supplying image-relative paths as registry text is wrong.

ProcessKeys flags 0 and 1 omit HKCU; bit 2 selects its per-user pass and emits
an abstract `\REGISTRY\USER` anchor. Explicit HKU/.DEFAULT goes through the
system pass and includes a `.DEFAULT` child. The same ordinary Software,
Software/Classes/CLSID and Control Panel user paths remain unredirected for
native wow64 component controls. `PushHierarchyRoots` with a supplied profile
calls OpenProfileRootKey, rather than opening the abstract name through SIL.
The real no-SID profile's native open requests `\REGISTRY\USER\Template`,
**not** `.DEFAULT`. Physical offline template mounting and non-null SID profile
handling remain separate from this logical pass resolution. Abbreviated HKCU
in the raw XML fixture is rejected by the native manifest parser; the bounded
user resolver accepts the actual full root spellings only.

Deeper-key controls also distinguish hive-boundary flag 2 from implicit-key
status. Machine Software carries the bit even when explicitly declared;
implicit Software/Deep does not. For the system USER tree `.DEFAULT` carries
it; children of the per-user anchor do not. The reducer now follows those
boundaries rather than marking all implicit ancestors as deferred.

### Bounded actual registry preparation and literal key names

Pinned 26300.9457 image6 to KB5127648 declaration validation completed in
per-transition batches: 279758 admitted keys resolved and reduced locally,
404632 values prepared, 107 dual-mode transitions bypassed. This is not a
complete ordered transaction or permission proof. A prior diagnostic that
retained duplicate full XML/declaration/reduction datasets was killed; its
unfinished full reduction is not validation evidence. `repl=registry` now
retains metadata without all file/key/value intermediates and ends on EOF.

Native whole-key controls accept literal `.` and `..` components and `/`
inside registry key names. Actual declarations include provisioning CSP `.`
components and MIME/PushRouter slash names. They must not go through filesystem
normalization. The private resolver and reducer preserve these characters.

The native modern-profile hierarchy commits normal `value` rather than
`IEDownlevelValue`; REG_SZ and REG_EXPAND_SZ accept `operationHint="replace"`.
A REG_MULTI_SZ replace control expands each runtime macro and commits the
terminated UTF-16 list. Preparation preserves option attributes and the
difference between unquoted-empty and quoted-empty multi contributions; it
does not decide commit arbitration from canonical raw bytes alone.

The compact actual physical grouping has 204098 value names: 199515 unchanged
single-owner pairs, 3098 new-only, 200 changed pairs, 1012 old-only, 266 equal
multi-owner pairs, five unchanged multi-contribution groups, one changed
MediaVersion collision and one equal-collision old-only group. These counts
compare contribution sets, not native ordered winners. Only two changed
special groups are new WAM UtilitySession/AAD Capabilities multi-strings.
The raw WIM root used in this diagnostic is X:\Windows; recipe root rebinding
must be explicit before final application.

New-only native MULTI_SZ with no operationHint queries existing
`Existing,Shared`, then adds `Shared,Added` as `Existing,Shared,Added`.
Explicit prepend yields `Added,Existing,Shared`: an already present entry is
not moved. Explicit replace yields only `Shared,Added`. All controls return
zero through native CreateHierarchyInSil with the strict registry provider;
these are value semantics, not physical hive/security effects.

### Primitive family-domain bound from transaction operation inputs

Further call-site inspection narrows the earlier conditional table bound.
GenericAddNew receives operation 0 from InstallDeployment (a38da), 1 from
UninstallDeployment (a3e39), and 2/3/4/5/6 from pin/unpin/payload-unstage/
stage/unstage. GenerateClosures (1d0f94) obtains each operation's application
root and calls CCompleteClosureCalculator::GenerateClosure (927ec), storing
the closure at operation+a0. GenerateServicingFamilies tests operation<=1
at 14015d..140163 before its only table insertion call (1401ab), then walks
all that operation's closure members. It does not enumerate arbitrary store
families or add stage/pin closures to this table.

The complete verified affected install-mark closures contain 17550 distinct
full identities and 13752 distinct version-independent hashes. Those bound
the native family count despite version-scoped families; both imply 7222
buckets under the observed native growth recurrence. This is a source-derived
capacity proof for these complete inputs, not a captured full transaction.
`servicing_primitive_family_capacity` rejects bounds that span a growth step.
Changed-winner-only inventories are not a valid substitute for these inputs.

All six SxS runtime transitions have zero admitted registry keys. The registry
contributors therefore use the native-controlled nonSxS family hash. No
physical value has distinct contributing families tied in a bucket. One key,
RestrictedServices/Static/System, has a tied pair, but both contribute no
owner or descriptor and have no overlapping value name. IdentityCRL is the
only key with differing nonempty descriptors in one side; the same pair is
present before/after, in distinct buckets 1753 (WLIDCli) and 3365 (WLIDSvc).
These facts narrow contribution ordering; they do not authorize overlaps,
replace kernel security assignment, or prove final image effects.

The hive reader/writer's existing component-list APIs round-trip literal dot,
dotdot and slash names. Use key_parts for patches and a component list for
find; the convenience string path parser uses filesystem normalization.

### Registry overlap gate and final counter status

CRegistryInstaller::Initialize (277d5c) copies coordinator bit 0x800 into
strict-key byte +229 and strict-value byte +228. Coordinator initialization
(144f70) queries GUID f39479e2-c59b-4a02-8973-9f58eeca9ffb, whose native raw
layout lookup maps to SingleResourceOwnership, and ORs 0x4800 if true. The
raw SmiHiveUpdates override can also supply 0x800. The ordinary direct inputs
select neither in the pinned store: both configuration values default to 0.
This is the same configuration source as the separately modeled FileMap gate,
not a reason to reuse its collision classification.

Native DoesOverlapExist (128710) controls with one counter set establish:

| Installer offset | Counter | Ordinary mode | Strict mode |
| --- | --- | --- | --- |
| 130 | total key collisions | 0 | 80188309 |
| 138 | critical key collisions | 80188309 | 80188309 |
| 140 | total value collisions | 0 | 80188309 |
| 148 | critical value collisions | 80188309 | 80188309 |
| 150 | state-separation violations | 8018830e | 8018830e |
| 160 | HKCU violations | 80188317 | 80188317 |

All 14 zero/single-counter native controls returned, with real native error
formatting. The recipe status helper requires all six classified counters;
missing counts cannot silently become zero. Counting shared owners alone does
not establish that critical, override, state-separation and HKCU checks pass.


### Boot-first integration boundary and catalog-only boot drivers

The pinned 26300.9457 -> KB5127648/26300.9711 experimental image reached
`CRITICAL_SERVICE_FAILED` (0x5a) before SMSS when it projected the serviced
FileCrypt binary without installing its new package catalogs. The stopped
kernel's KiBugCheckData recorded status 0xc0000428 and the service name
`\FileSystem\FileCrypt`. Adding the selected 551 authenticated package
catalogs to the CBS package store and the existing native CatRoot namespace
removed that early stop and reached Winlogon/Userinit/Explorer with signature
enforcement unchanged. This is a narrow boot-driver observation, not proof
that the CBS transaction, catalog lookup databases, or full first logon are
complete. The experimental applier reports those omissions explicitly.

Replacing a projected file must detach its old WIM hardlink identity. A plain
directory write preserves metadata and can otherwise leave distinct payload
sizes under one identity; the NTFS builder correctly rejects that input.
Case-canonical remove/write with security preservation is the current explicit
experimental policy; reconstruction of the new runtime/store hardlink graph
remains separate.

`component_staging.open(index, lazy=True)` retains a declared-length reader
rather than every reconstructed payload. Reconstruction and integrity checks
occur when content is read and after cache eviction; constructing this reader
is not a fresh all-payload verification. Readers share a bounded 512-MiB cache
per plan, including targets larger than the stage DAG reuse cache. Keeping only
lazy sources also requires dropping completed package/component analysis before
starting an 8-GiB guest, and avoiding duplicate full dirty-disk snapshots during
inspection.


The subsequent fresh-image smoke reached a visible desktop, recorded
`10.0.26300.9711` through the running guest, and completed two user logons and
clean shutdowns. This establishes the boot milestone only. A longer observation
window recorded a taskhostw C++ exception, and the applier still explicitly
omits complete CBS/source ownership and other effects listed in its report;
the image is not a fully validated servicing result.


## Boot-first package lookup discriminator (26300.9711 target)

For the pinned 26300.9457 image-6 to 26300.9711 experiment, selecting package
catalogs solely from staged component-deployment owners omitted componentless
package wrappers. The package-level stage/install execution list added 262
MUM/CAT pairs (813 selected signed catalogs total), including the target
RollupFix, servicing-stack and GDR root packages. These must retain canonical
full package names independently of whether the package owns a component.

A fresh boot with these wrapper MUM/CAT files present still returned
`CBS_E_INVALID_PACKAGE` (0x800f0805) for `/Get-PackageInfo /PackageName:` when
the SOFTWARE package keys were absent. A separate diagnostic candidate added
only `CurrentState=0x40` and `InstallName=<exact package>.mum` on the two missing
target package keys. The same queries then succeeded, reported Applicable Yes,
and reported Staged, not Installed. The old registered cumulative update stayed
Installed. This establishes a lookup requirement, NOT a complete stage or
installation writer; no installed owner, install timestamp or transaction
success record was fabricated by that discriminator.

`/CheckHealth` reported no component-store corruption in both rejected and
recognized-package candidates. That result alone does not establish successful
servicing. The native application must still persist component descriptions,
transitive ownership, deployment source changes, winner changes and complete
package state only after their actual effects are applied. All guest commands
in this discriminator were read-only package/health queries, not installation
or repair.

### Plan against the recipe's actual hive baseline

The media hive and an already-specialized recipe are different servicing inputs.
The 26300 VM recipe completes WMIC removal and staged Recall removal before the
update experiment. A media-derived projection incorrectly expected the retired
WMIC language-pack deployment to retain p!/s! sources; its actual recipe key
retained only appid and CatalogThumbprint. Serialized source-value verification
caught the disagreement before disk construction or boot. Restoring those
sources or weakening readback checks would conceal a stale baseline.

For a boot experiment, assemble the recipe baseline first and use its exact
SOFTWARE/COMPONENTS hives for metadata registration, ordinary population,
composition ownership, source edits, and winner membership. Optional hive inputs
on the Starlark analysis helpers allow that without reconstructing an image or
copying payloads. Keep using the same immutable baseline until the selected
changes are applied.

Completed staged Recall removal instead retains p! and c! while removing s! and
its payload. Its source-qualified current state is Resolved (0x20), neither
Absent (0) nor Staged (0x40). The population initializer now preserves that state;
the ordinary deployment-action projection permits an unchanged 0x20 -> 0x20
source with no stage or execute action. When ordinary population instead requests
0x40 or 0x70, the projection requires payload staging, with an install action
only for 0x70. Existing pins do not establish staged content. This does not
authorize unresolve, force-restage, pending states, or removal below staged.

The experimental CSI writer preserves existing physical CF/f! flags, catalog
choices and opaque source secondary data, and edits only selected values.
Canonical keys with neither pinned nor installed sources have no composition
backlinks even if appid remains. Pinned deployments retain their transitive
backlinks when their installed source is removed. Both candidate hives are
serialized and their sources, retained owners, and winner edits reread before
the recipe tree is updated. Native hive reads represent the unnamed value as
`(default)`; use that spelling for source-import exclusions too.

A fresh disposable image with these value edits reached the Windows desktop and
shut down cleanly. The emitted bytes verified 1,781 source projections and 3,634
winner plans, including 3,981 new component descriptions, 633 new deployments,
and 16,519 additive ownership edges. This is a narrow integration result, not
complete servicing: the target package registrations remained diagnostic Staged
records, not Installed records. Get-PackageInfo and CheckHealth succeeded, but
CheckHealth is not a complete payload scan. One AppXSvc failure was recorded;
it did not reproduce in one matching base-image control, and had also been
observed before adding this CSI writer. No specific CSI cause is established.

For emitted-hive readback, index deployment/component/family nodes once and
cache values of components visited by ownership edges. Native `find` resolves
paths by scanning sibling key cells; calling it for every transitive edge
repeatedly decodes the entire large component index. This indexing changes the
observation cost, not the required readback predicates or constructed state.


### Native driver-store offline context boundary

The selected amd64 Microsoft-Windows-DrvStore component is 10.0.26100.9549,
not the LCU's 10.0.26100.9711 component version. Its matching PDB key is
24D16246F2095EA9A8512FF3C95D48BE1. Native OfflineAddDriverPackageW (c1150)
opens a context with flag 1, calls ImportW (9e550), and conditionally calls
ReflectCriticalW (b49c0). These are separate phases, not replay of the
component manifest's skipped registry primitives.

Use different explicit process and target Windows directories when probing
an offline context. With process C:\Windows and target D:\Windows, OpenW
requests RegLoadKeyW under HKLM with a temporary name formed from
{bf1a281b-ad7b-4476-ac95-f47682990ce7} followed by
D:/Windows/System32/config/SYSTEM. The source path uses backslashes. This
is a literal registry key name: forward slashes must survive key encoding.
The bounded mount fixture maps only explicitly supplied parsed hives; it
is not evidence of native kernel hive loading or privilege enforcement.
After mounting, native code checks CurrentControlSet, reads Select/Current,
opens ControlSet001, and reopens that existing key using NtCreateKey with
an empty relative name and zero DWORD options. Upper bits of the Win64
options slot are not part of the DWORD. No driver-import effects have yet
been established by this context-opening probe.

The native DriverStoreSetLogContext API accepts a caller callback; returning
log token 1 suppresses setup logging in this bounded experiment. This avoids
conflating setup-log initialization with driver-store effects. The separate
loader fixture resolves only requested NTDLL exports and makes no claim
about full native loader behavior.

The target NTDLL (PDB C031D45B0DA18A6E74D06ED6AB2DD9E11) establishes
RtlInitUnicodeStringEx boundary behavior: a 65532-byte source succeeds with
MaximumLength 65534; a 65534-byte source returns STATUS_NAME_TOO_LONG.
On overflow the descriptor lengths and padding are cleared but Buffer still
references the source. Null input clears the complete descriptor. Regression
coverage also preserves UTF-16 code units without decoding unpaired surrogates.

The native context then mounts SOFTWARE and opens SYSTEM/DriverDatabase.
A separate LdrLoadDll ABI bug decoded UNICODE_STRING and output HMODULE as
x86 on AMD64, producing empty module requests and a later unload/exception
cleanup failure. The provider now uses native-width fields, with counted-name
and guarded-handle regression coverage; the actual next dependency is still
to be observed in a refreshed probe.

The refreshed probe resolves NTDLL. Native code requests NtUnloadKeyEx just
after opening a mounted hive, before later Select/Current reads. Do not
immediately discard a referenced source hive in a fixture. The original
media's kernel PDB C29EBFB06B78B3C020DCA66D99713F9E1 identifies NtUnloadKeyEx
at 0x9a2c20, CmUnloadKey at 0x9a32cc and CmpPerformUnloadKey at 0x9a39f8.
The open-subkey/reference checks at 0x9a3bea/0x9a3bfc lead to CmpFreezeHive
at 0x9a3f2c and STATUS_PENDING (0x103) at 0x9a3f3b for deferred unload.
This is a native kernel code observation, not proof that the reduced parsed-hive
fixture implements the complete registry object lifetime or privilege model.

A subsequent NULL OpenW/GetLastError 14 was not evidence of actual memory
exhaustion. CreateDriverStoreNode (0x1e818) calls InsertDriverStoreNode
(0x1f478), whose helper at 0x1f5e0 waits for two synchronization objects.
WaitForMultipleObjectsEx (call at 0x1f622) must return index 1; the old semantic
provider read HANDLE[] as DWORD[] on AMD64 and returned WAIT_FAILED.
InsertDriverStoreNode maps that helper failure to ERROR_OUTOFMEMORY at
0x1f500. Both the immediate wait array and the suspended-wait handle list
now use native pointer width; a cross-architecture regression verifies
wait-any selection, wait-all non-consumption, semaphore consumption, full-width
retained wait handles and invalid-count rejection.

### Native import runtime contracts

With the wait-width correction, native OpenW opens SYSTEM, SOFTWARE and DRIVERS,
reads the actual database versions and returns a non-NULL context. The reduced
experiment still uses original media hives, not the complete update candidate.
ImportW arguments, confirmed from OfflineAddDriverPackageW, are context, INF
path, WORD architecture (9 for AMD64), optional locale name, DWORD flags,
output WCHAR buffer, and DWORD buffer capacity. The flag-zero experiment uses
the selected BasicRender INF/SYS as memory-backed C:\Input files. It has not
established the separate CBS DrUpdate flag/context contract or activation.

Additional runtime contracts matter before interpreting native failures:

* RtlCreateUnicodeString owns a terminated copy, preserves UTF-16 code units,
  accepts at most 65532 source bytes and leaves the destination unchanged for
  an oversized source. The original media NTDLL PDB is
  C3093720177DA6851519DCFFE8DF53FE1; its implementation is at 0x1e290.
* Native RtlGUIDFromString consumes a counted brace-delimited GUID. Data1,
  Data2 and Data3 are written as parsing advances; Data4 is copied only after
  the entire format matches. Thus malformed late fields or trailing text can
  leave the first eight output bytes modified on STATUS_INVALID_PARAMETER.
  The same NTDLL implementation at 0xdad20 was executed directly as an oracle.
* NtQueryValueKey's supported KeyValuePartialInformation class has a 12-byte
  header. The provider distinguishes too-small headers from partial-data
  overflow, returns the complete required size and preserves output guards.
  Other information classes remain explicitly unsupported.
* Counted equality and ordinal comparison operate on UTF-16 code units, not
  host Unicode strings or locale collation. BOOL/BOOLEAN and INT widths differ.
  Differing non-ASCII case-insensitive units and non-ASCII RtlUpcaseUnicodeChar
  still require an explicit native NLS table; they stop rather than substitute
  host casing. Case-sensitive ordinal comparisons preserve surrogate units.
* The native INF loader at 0x2f83d calls CreateFileMappingW with a fifth stack
  slot observed as 0x7fff00000de2: only its low DWORD is the 3554-byte INF size.
  Mapping sizes/offsets composed from DWORD pairs must mask each half; the
  MapViewOfFile byte count remains SIZE_T. CRT strtoul/wcstol/wcstoul end-pointer
  outputs likewise use native pointer width.
* Each unnamed mutex creation denotes a different object. In the old provider,
  repeated CreateMutexW calls at 0x14bf2 returned one handle. A later INF wait
  at 0x18342 saw a destroyed mutex because another context had closed it.
  Named mutex creates/opens now return distinct handles to a shared object;
  closing one handle does not destroy the others. Full cross-thread mutex
  ownership semantics are still a separate gap.
* CPUID already advertised a timestamp counter. Native WIL feature code at
  DrvStore 0xaaebf executes RDTSC. AMD64 now follows the existing x86
  deterministic instruction-clock policy, preserves flags, zero-extends EAX
  and EDX, and snapshots the counter with the CPU. It does not sample host
  wall time or change guest integration timeouts.
* Native code at 0x37c49 compares a failed FindFirstFileW HANDLE against the
  full-width -1. Returning zero-extended 0xffffffff on AMD64 instead made it
  consume uninitialized find data. DWORD failure values such as
  GetFileAttributes' 0xffffffff must not be widened with HANDLE failures.

The security model now distinguishes a process's primary token from an absent
thread impersonation token (ERROR_NO_TOKEN). Token handles have independent
close lifetimes; duplicates own their descriptor bytes and privilege inventory;
thread assignment/reversion retains object references. Token-object descriptor
queries enforce READ_CONTROL and DACL writes enforce WRITE_DAC. The initial
modeled object policy remains SYSTEM/Administrators-only, with no NULL-DACL or
offline image ACL substitution. This is not a complete NT authorization model.

The native privilege request observed during offline opening enables LUIDs 17
and 18. The runner accepts an explicit caller `token_privileges` inventory and
defaults empty. AdjustTokenPrivileges cannot add an unowned or removed privilege:
TRUE with ERROR_NOT_ALL_ASSIGNED is distinct from complete adjustment. Previous
state sizing is checked before mutation. This describes an emulated caller's
capabilities, not privilege grants or security changes in the target image.
Empty-inventory and explicitly owned Backup/Restore controls both exposed the
old mutex defect, excluding privilege inventory as its cause.

After these prerequisites, native ImportW independently computes the expected
basicrender.inf_amd64_a779d7425d822522 repository name, creates that directory and
locates the real 77824-byte selected SYS file. Setup tries FDICopy on ordinary
source files before its raw-copy fallback: a non-MSCF file returns FALSE with
FDIERROR_NOT_A_CABINET, rather than throwing an archive-parser error. Actual CAB
extraction remains on the native format reader. Later native import results
and their limits are recorded below.

Native staging-name formatting calls RtlIntegerToChar with value 1, base 16,
capacity 5. The original NTDLL oracle confirms uppercase digits, base-zero
Decimal, exact-capacity success without a terminator, an optional terminator
only when space remains, and STATUS_BUFFER_OVERFLOW with untouched output.
The subsequent character-pointer conversion RtlAnsiCharToUnicodeChar takes
PCHAR*, not PCHAR. The original NTDLL cff20 oracle returns all 128 ASCII
values unchanged and advances the caller pointer by one byte, including NUL.
Non-ASCII requires native NLS code-page behavior, not Latin1 substitution.

### Native generic driver import completion and limits

With the original-media SYSTEM/SOFTWARE/DRIVERS mount fixture and explicit
caller-owned Backup/Restore privileges, DrvStore 9549 ImportW on the selected
BasicRender 9711 INF returns zero for architecture9, localeNULL, flags0. The
returned path is the expected FileRepository directory followed by BasicRender.inf;
the 260-WCHAR output guard remains intact. Copied SYS77824 and INF3554 bytes,
including the published Windows/INF/oem0.inf, equal the selected plan bytes.
Native execution emits 124 registry patches, including package Version,
FileSize81378, oem0.inf package mapping, DeviceIds/ROOT/BASICRENDER entries,
and DriverInfFiles/oem0.inf Active naming the new package. These are emitted
native requests in a bounded fixture, not edits guessed from the INF.

CopyFileExW receives null progress/cancel pointers and a low-DWORD flags0;
upper stack-slot bytes are not flags. Its in-memory copy preserves available
source metadata. Unsupported callbacks/flags stop explicitly; fail-if-exists,
cancellation, missing parents and protected destinations do not mutate files.
The native delay-load exception c06d007f was a missing
WINTRUST!CryptCATAdminCalcHashFromFileHandle, not a reason to swallow RaiseException.
The adapter computes the real existing portable catalog digest: SHA1 of all
INF bytes, Authenticode ranges for PE files. Native WinTrust 8fe0/8b64 sizing
controls establish a 20-byte required digest, TRUE for NULL-output queries,
FALSE/ERROR_INSUFFICIENT_BUFFER for short non-NULL output, and DWORD argument
widths. Hash calculation does not establish signature trust or catalog membership.

Native counted-prefix comparison preserves WCHAR units and BOOLEAN width;
differing non-ASCII case-insensitive units still require NLS. Native string
duplication eba90 accepts flags0/1/3, validates lengths and owns its allocation;
flag1 adds a terminator, flag3 allocates an empty terminated result, and empty
flag0/1 results have no buffer. Invalid flags/lengths leave output unchanged.
The native registry adapters now support exact representable NtSetValueKey,
NtDeleteValueKey, NtQueryKey cached information, and basic/full value enumeration.
Noncanonical native raw values still stop rather than gaining terminators via
typed patches. The registry model does not yet implement complete NT access
checks, key timestamps/title indexes, native enumeration-order/case preservation,
or kernel hive lifecycle. Cached timestamps/title indexes remain the existing
deterministic zero model; child/value counts and maxima derive from live state.

Generic flags0 import is not the CBS DrUpdate flags205/245 or server-context
contract. It creates an OEM mapping, not proof that the original basicrender.inf
mapping or service activation is updated. ReflectCritical and the update-specific
caller remain separate. No fully serviced candidate or crash-free integration
result follows from this fixture, and no target ConfigOptions/CBS state, services,
ACLs or guest timeouts were overridden.


### Servicing-stack driver companion selection

The selected SSU9703 DrUpdate uses PDB
15BAE6440621EC17F0665C0DBF9F40C61. Its LoadCompanionLibrary1f338 obtains
its own module filename, removes that filename, and loads drvstore.dll from
the same directory. Consequently the CBS companion is the SSU9703 file,
PDB DE6143940C27BA1F0AF204E47261BED81, not OS-component DrvStore9549.
Both payloads exist separately in the selected source. The successful 9549
generic-import fixture establishes shared mechanics, not the CBS dependency.
A bare primary module filename causes native ERROR_BAD_PATHNAME161 before
companion loading; probes must supply the actual selected WinSxS module path.

For this exact DrUpdate, StageDriverUpdate is160b0. It computes import flags
205 + 40 * (update.flags & 1), and chooses direct ImportW when context410 is
nonzero. CreateDriverUpdateContext18b08 populates410 at18c81 from
SystemContextIsOffline30714, which reads native system-context fielda28.
StageDriverUpdates196b4 opens the driver store with flags0 at197c3, not the
generic fixture's flags1. These are native caller observations, not permission
to synthesize update records or force context/ConfigOptions fields.

The native DriverUpdateSetThreadLogToken10410 accepts no-log token1. Using
that setter avoids unrelated SetupapiLogStatus volatile-key setup; no volatile
registry-create semantics were faked. Later context initialization exposed
GetPrivateProfileStringW nSize with stale upper stack bytes. nSize is DWORD;
its scalar result is a terminated, bounded character/code-unit sequence even
for zero/one-character capacities. The selected companion also uses NTDLL
exclusive SRW names. Those aliases share real exclusive ownership with the
Win32 names; contention suspends, try-acquire does not recurse, and invalid
release fails explicitly. Full shared-mode/upgrade fairness is not established.

The exact-pair context probe returns a non-null DriverUpdateOpenContext with
native field410 equal to1 and zero registry patches in the original-media-hive
fixture. A stop-only observation before temporary DriverStoreClose18dfe found
ESI(error)=0 and R12(new context) non-null. Cleanup was not an earlier context
failure: the new context holds SYSTEM root/ControlSet001 and SOFTWARE references
while the temporary context is destroyed. Normal unload with live source
references is rejected, not accepted: original kernel
CmpPerformUnloadKey reference checks9a3bea/9a3bfc reach9a3ed0 with
STATUS_CANNOT_DELETE(c0000121) when deferral is disabled. Original NTDLL
RtlNtStatusToDosErrorNoTeb maps that status to Win32 5. The narrow fixture
therefore retains its mount and returns5 while references exist, instead of
throwing or inventing successful unload. NtUnloadKeyEx's earlier pending103
fixture remains distinct. A narrow read-only NtQueryOpenSubKeysEx fixture
reports the actual explicit handle-table references with modeled process ID4;
it neither consumes handles nor unloads hives. The selected consumer55720 uses
a count followed by24-byte PID/UNICODE_STRING entries. This fixture establishes
only its sufficient-buffer request, not general kernel sizing/authz semantics.

That diagnostic exposed a pre-existing NtOpenProcess stub which wrote constant2
without owning a handle. It now accepts only the modeled current process with
PROCESS_QUERY_LIMITED_INFORMATION, validates unnamed/default OBJECT_ATTRIBUTES
and CLIENT_ID, and publishes a full-width owned process_reference. Other access
or object policies remain explicit gaps, not permissive success. The focused
x86/amd64 control checks full-width handles, output guards, no Win32 last-error
clobber, close ownership, and failure atomicity for unknown IDs/bad OA lengths/
unmodeled access. All149 stdlib/internal controls pass after the later key-enumeration fix. Native cleanup now
finishes and returns the context without changing busy-unload behavior. This
is not staging, activation, trust, complete native last-close/kernel lifecycle,
or a fully serviced image. The actual CBS staging-record producer remains to
be established; no update descriptors or caller flags have been synthesized.

### Exact SSU driver stage-only control

SSU9703 WCP has PDB7CC21FAF1E625E052DD8ADB23E8B25F21. Its raw-store
PerformDriverOperation1c564c extracts INF declarations then calls the registered
CSI callback at1c5c79. The matching CbsCore PDB is
A3649FD182275D7156E38C3A438791D71. Its PerformDriverOperation10f2c0 builds a
zeroed220-byte DRIVER_UPDATE: path from CSI data8 plus filename20, architecture
from18, locale from10 (neutral becomes NULL). On its install branch it writes
record218=1 at10f701 and calls DrupDriverUpdateStageUpdatesffe7c at10f78f,
then a separate install wrapper. This is static caller evidence, not an executed
CBS driver callback or permission to fabricate its ownership/session inputs.

A lower-level control opens the exact SSU DrvStore with flags0 and imports the
selected BasicRender9711 with flags245, architecture9, localeNULL. It does not
construct a CSI descriptor or claim the complete DrUpdate stage callback ran.
The input resides on the fixture's explicit C: volume, repository on its D:
volume. The earlier narrow fixture rejected CreateHardLinkW across those
volumes with ERROR_NOT_SAME_DEVICE17; the production file model now enforces
that distinction and supports shared identity within an explicitly declared
NTFS volume. Native code chooses CopyFileExW itself for cross-volume staging,
not a replacement copy selected by the fixture. No catalog trust is inferred.

ImportW returned0 after observed bounded continuations. Its 260-WCHAR output
guard remained intact. Repository INF3554/SYS77824 SHA256 values match selected
payloads. Fourteen native registry patches set package metadata (FileSize81378,
SignerScore0d000003, StatusFlags30, LockLevel2) and prepend the new package to
DriverInfFiles/BasicRender.inf's package list. Crucially Active remains the
original basicrender.inf_amd64_cf45ae7c2c82746d; no OEM INF mapping is published.
This is stage-only behavior, not activation or an updated service ImagePath.
InstallDriverUpdates181e0 and actual CBS owner/session/caller construction
remain separate obligations. No integration image or application parity follows.

### Native publish scan and key-information short buffers

A distinct lower-level publish control uses native DriverStoreOpenW flags3
(the selected InstallDriverUpdates181e0 no-transaction branch) followed by
DriverStorePublishW flags0. No CSI descriptor or context flag is fabricated.
The publish scan opens source DRIVERS/DriverDatabase/DriverFiles entries with
NtOpenKeyEx REG_OPTION_OPEN_LINK8. The adapter now supports this object-open
semantics: it opens that named key, not a symbolic-link destination. This is
not general registry link following, intermediate-link traversal, or access
validation; other open options remain explicit gaps. The first observed key
1394ohci.sys is an ordinary source key with default value1394.inf.

The first scan stopped advancing on long DriverFiles key names. Native
DrvStore4421c requests KEY_BASIC_INFORMATION, accepts BUFFER_OVERFLOW80000005,
and uses the fixed header NameLength to grow its counted name buffer. Returning
BUFFER_TOO_SMALLc0000023 whenever the whole name did not fit left the caller's
character count unchanged; the outer439xx/440xx loop repeatedly allocated an
undersized buffer. Extra continuations were stopped once opens no longer
advanced. This was an adapter contract defect, not a native timeout.

NtEnumerateKey class0 now returns BUFFER_TOO_SMALL only below its16-byte
header; otherwise it writes the header/partial name and returns BUFFER_OVERFLOW
until all bytes fit. Index/class/length are DWORD slots. Unmodeled classes fail
explicitly; zero timestamps and existing source naming/order remain unchanged.
A cross-architecture long-name control verifies the required length, partial
header/name, exact retry, output guards and no registry writes. The amended
OPEN_LINK pointer-width test also checks unsupported-option failure atomicity.
All149 stdlib/internal tests pass.

### Native leaf deletion and retained key-object references

The next native publish operation deletes source
DRIVERS/DriverDatabase/DriverFiles/BasicRender.sys. The source key is a leaf
with default value basicrender.inf, not an empty placeholder. Two live handles
refer to it. Deleting only the plugin's overlay values would miss that source
value; closing one handle or treating a path tombstone as handle ownership
would incorrectly allow the other handle to reach a later replacement key.

NtDeleteKey now requires an owned handle with explicit DELETE access, rejects
nonleaf deletion, records removal of all effective values including lazy source
values, and marks all live references to that key object deleted. It retains
those references until close. Supported NT operations on them report
STATUS_KEY_DELETED; corresponding Reg operations report ERROR_KEY_DELETED.
Relative native opens/creates through a deleted parent fail without touching
output buffers. Repeating deletion of the same deleted object is idempotent;
that operation must not delete a newer object created at the same path. The
source cache must not resurrect the original values after recreation.

The access check is intentionally narrow: it checks the captured explicit
requested mask, not a complete ACL grant model. Generic/MAXIMUM_ALLOWED or
untracked access remains unsupported rather than being silently authorized.
Registry links, hive-root policy, full security semantics, and exporting key
removals as complete final image effects remain separate gaps. The existing
value-patch report alone does not describe every deleted empty key.

The cross-architecture control covers source-backed values, two deletion
handles plus a read-only reference, DELETE denial, nonrecursive failure,
full-width handles, stale-handle reads/writes/relative opens, output guards,
recreation isolation, real closes, and reset. All150 stdlib/internal tests pass.
Fresh exact-SSU stage/publish passes the deletion and native code closes both
references without an adapter-forced close. This remains lower-level in-process
construction evidence, not successful complete CBS servicing or integration.

### Native publication requires same-volume file identity

After deletion, native publication completes a device-ID size query, allocates
its list, fills that list, then calls GetDriverInfFileDeviceIdCallback for the
individual entries. A second walk of already cached keys is not necessarily a
loop: DriverDatabaseEnumObjects25540 retries ERROR_INSUFFICIENT_BUFFER and
then invokes the property-filter callback. Verify the actual native caller,
output pointer/capacity, and advancing key names before continuing. The observed
fill allocation was0xc52a7 WCHARs; the later stack identifies
DrvDbGetDeviceIdDriverInfMatches rather than another list-size query.

Publication then reaches CreateHardLinkW for D:\Windows\inf\BasicRender.inf
from the selected repository's BasicRender.inf. PublishDriverInfFile35444 calls
SetFileAttributesTxf359bc and DeleteFileTxf36c3c before CreateHardLinkTxfC2EB0
at35623. The source and destination are both on D:, unlike the earlier C:-to-D:
staging fallback. Do not force ERROR_NOT_SAME_DEVICE here, copy bytes while
reporting link success, or treat a path alias as complete open-file ownership.
Writes, metadata, unlink/recreate, open references, mappings and snapshot/clone
behavior must retain the appropriate shared file identity.

The file model now retains shared objects across handles, mappings, rename,
unlink/recreation and prepared-entry clones. CreateHardLinkA/W requires explicit
local NTFS volume facts; a second name references the same object without reading
or copying the lazy payload. Alias-aware sharing checks, file IDs/link counts,
metadata and delete-pending lifetime are covered on x86 and amd64. Independent
prepared-entry clones retain alias groups without sharing mutable entries;
generic machine.snapshot clones CPU/memory but does not fork semantic plugin
state. Generated entries describe aliases with hardlink_to; content-only output
is not sufficient for final image hard-link construction. Full NT authorization,
reparse links and deletion-effect export remain separate requirements.

A fresh exact-SSU control includes the original Windows/INF/basicrender.inf,
old repository INF/SYS and explicit C:/D: NTFS volumes. WIM hard_link_id shows
that the original INF paths share one object; BasicRender.sys exists in the old
repository, not Windows/System32/drivers. Stage ImportW245/OpenW0 and subsequent
PublishW0/OpenW3 both return0. Publish reports changed=1 with its 260-WCHAR
output and DWORD guards intact. Native code emits219 registry effects and sets
SYSTEM DriverInfFiles/BasicRender.inf Active to the selected a779d7425d822522
package. Published INF and selected repository INF share file_id4, while the old
repository INF remains independent (file_id5). No Active/CBS/CSI value is forced.
This establishes lower-level native publication, not DrUpdate reflection, full
CBS caller execution, final image integration or Store/installer/VS parity.

### Native DrUpdate stage and reflection API control

The selected SSU9703 CbsCore install producer writes update.flags=1 at10f701,
then calls its DrupDriverUpdateStageUpdates wrapper at10f78f and install wrapper
at10f7e9. The record has a260-WCHAR INF path at0, WORD architecture at208,
locale pointer at210 and DWORD flags at218. The API control marshals this
observed layout using the exact selected BasicRender9711 WinSxS INF/SYS on D:,
architecture9 and neutral locale. DriverUpdateOpenContext constructs its own
context, including offline410=1. This is an API control, not execution of the
full CBS producer/session or synthesized CSI ownership/transaction state.

DriverUpdateStageUpdates(context, update,1,NULL,NULL) returns0 with14 native
registry effects. DriverUpdateInstallUpdates(context,update,1,NULL,NULL,NULL)
then runs publication, service/configuration reflection and native package
traversal to return0 with242 effects. The record's trailing guard stays intact
and no native exceptions are recorded. Native code updates both BasicRender.inf
Active and ControlSet001/Services/BasicRender ImagePath to the selected
basicrender.inf_amd64_a779d7425d822522 repository; the latter is not a manual
registry replay. The selected WinSxS payloads remain byte-identical to the plan.
The explicitly disabled online-update services receive no writes in this control.

Reflection required the following previously missing semantic operations:

* RegDeleteKeyExA/W supports native/default views, DWORD-width reserved/view
  fields, nonrecursive leaf deletion and the existing deleted-object lifetime.
  It removes lazy source values and retains stale handles until close; creating
  a new key at the name cannot resurrect old values or retarget old handles.
  RegDeleteKeyA/W now also rejects recursive deletion. Alternate registry views,
  empty-subkey self-deletion and complete NT authorization remain explicit gaps.
* RtlAddAccessAllowedAceEx uses measured NT statuses, not Win32 BOOL/last-error
  behavior. It appends actual mask/SID bytes, validates bounded simple ACL/ACE
  extents and preserves every byte on failure. Native NTDLL67e30 comparisons
  cover revisions, flags, invalid SIDs, malformed ACLs and insufficient space.
* RtlValidSecurityDescriptor validates absolute and self-relative SID/ACL fields;
  a revision byte alone is not validity. The existing Win32 validator uses the
  same checks. Present NULL and absent ACLs remain distinct and valid. Existing
  non-simple ACE validation is unsupported, not implicitly granted access.
* RtlAbsoluteToSelfRelativeSD serializes SACL, DACL, owner and group in native
  order, copying aliased principals separately. On short buffers it writes only
  the required DWORD length and returns STATUS_BUFFER_TOO_SMALL; on success it
  preserves the supplied length. Already-relative input is rejected. Native
  comparisons establish these bytes and statuses; this operation is serialization,
  not a substitute for descriptor validation or access authorization.

All156 internal semantic controls pass, including x86/amd64 A/W deletion,
full-width handle ownership, recreation isolation, descriptor output guards,
read-only validation, failure atomicity and NT last-error preservation. These
results establish native driver API progression only. Final key-deletion,
file-link and security effect construction, full CBS integration and a fresh
whole-image boot/application smoke are still required for update completion.


### Portable file-object and LUA application on the exact recipe tree

The private update construction now has separate store preparation, complete
hierarchy/security planning, preliminary file, LUA FileMap, final file and empty
directory-removal passes. The fresh exact 26300.9457 recipe transition applies
117 preliminary and 6,244 final hardlinks, five hash-qualified writable copies,
325 old-only file unlinks (four additional old-only paths were already absent),
652 map writes, seven map removals and 31 empty-directory removals. A separate
resulting-tree traversal verifies all 6,361 changed primary/extra-link aliases
against their exact WinSxS object IDs, security, timestamps and attributes; all
five writable replacements are independent copies; all 329 old-only projections
are absent. Parent-first construction performs 296 directory security writes,
including 242 creations. These are actual in-memory filesystem effects, not
transaction receipts or new boot evidence.

The complete-tree input exposes one additional legitimate audit right: the
SenseTask parent contributes inherited audit mask `0x010d0000`. Native RTL's
already-established audit-copying policy retains ACCESS_SYSTEM_SECURITY;
effective allow ACEs do not. The portable assignment validator now admits that
bit only in audit entries, retaining the separate DACL/category/flag guards.

New FileMap final security is constructed from the native TI-owned six-ACE
protected pair and noninheriting audit mask `0x001f0116`, not copied from a
resident map. All 652 final descriptors have the independently resident map's
resolved components. For a newly created map, the bounded SYSTEM-integrity,
noninheriting-parent case has no prior mandatory label; the complete subsequent
setter overwrites the creation DACL. This final-only construction deliberately
does not represent an acquired token default DACL or its transient descriptor.
Existing map labels remain preserved by the ordinary category selection.

Filesystem hardlink construction must transfer source object metadata as well
as content and identity. Keeping destination timestamps/security makes the MFT
result depend on lexical alias order. Source metadata now follows the new object;
only destination short names remain link-local. Exact basic-information updates
normalize NORMAL and reach all aliases; empty-directory deletion is nonrecursive.
Independent MFT STANDARD_INFORMATION/FILE_NAME tests cover replacement of an old
alias, retained old siblings, shared times and normalized nondefault attributes.

This pipeline is not yet the default boot applier. In particular, the file pass
removes old driver repositories while the original DRIVERS hive still refers to
them. Wiring it before native driver/CSI ownership and DOQ effects would replace
one inconsistency with another. Source-folder and manifest final staging security,
registry/profile and advanced effects, and the subsequent per-package stage/final
commits remain requirements. No package Installed/Active/session state follows
from these file effects alone.


### Native key-removal effect export prerequisite

The registry semantic plugin now retains successful key-removal events beyond
subsequent recreation of the same path. Empty keys produce no value patches,
and removing only live tombstones from a final report loses delete/recreate
object identity. `key_deletions()` reports those events in order; the emulator
runner includes them as `registry_key_deletions` on each result path. Failed
removals and repeated deletion through stale handles add no event; a new object
at the same name can produce a new event. Reset clears the report. The native
x86/amd64 lifecycle control now also checks empty-key export, retained source
removal after recreation, and stale-handle isolation. All 158 internal semantic
controls pass. Applying these events to final hives, including recreation
security and ordered value/key reconciliation, remains a caller obligation.


### Registry effect epochs and driver-key creation

The exact SSU9703 BasicRender stage/reflection API control was rerun against
original recipe hives and old INF/repository files: stage returns0 with14
requests, install returns0 with242 total requests; the record guard survives.
This still is not execution of the CBS owner/DOQ callback or a complete image.

`registry.effects()` captures only surviving owned raw value bytes, final key
metadata, successful key deletions and final value removals. Chronological
`patches()` is not a final-state image: replaying sets after excluding removed
keys can resurrect a value written to an earlier deleted object. Optional patch
and key-deletion offsets isolate a mounted-hive epoch. Capture before namespace
teardown; an emulator mount-root removal is not deletion of the actual hive.
The runner exposes this as `registry_effects` for its own registry plugin;
callers overriding that plugin must capture the authority they actually used.

The bounded driver mount provider now builds/readbacks actual hive bytes before
a successful ordinary unload and updates its backing file object. A subsequent
mount reads those bytes. Busy ordinary unload still returns5 with live owned
references. The pending/unload-reference fixture is not a general kernel hive
lifecycle, authorization or crash-recovery implementation.

New/recreated keys cannot use the hive writer's copied-parent security as a
native default. Original kernel PDBC29EBFB06B78B3C020DCA66D99713F9E1,
CmpCreateChild847708 calls SeAssignSecurity8cd230 at847f02, with the actual
key generic mapping. This path derives auto-inheritance from parent AI controls;
it does not add NTFS's normalization4000. In the explicit no-client SYSTEM
subject fixture, real DriverPackages, DeviceIds/ROOT and DRIVERS/DriverFiles
parents all have legacy control8004 and the same three container-inherit allow
ACEs: SYSTEM full key rights, OWNER RIGHTS READ_CONTROL and Everyone key read.
Their parent owner/group are not SYSTEM. Native assignment returns112bytes,
control8004, the inherited legacy DACL without INHERITED_ACE, and SYSTEM owner
and primary group. Recursive child creation is a fixed point. SYSTEM4000 and
high3000 integrity controls give identical bytes. Locks and APC-disable count
return to zero; each call returns0 in2538instructions. Only bounded owned
allocation/free and one declared token resource were provided; inheritance,
token-default selection and descriptor construction executed in the kernel.
No caller's live servicing token or general creation policy is inferred.

The recipe accepts only this measured DACL/control form and explicitly declared
SYSTEM subject. Other parents, creator descriptors, class/options or principals
stop, rather than inheriting a permissive default. Registry creation providers
supply every missing ancestor's final descriptor before any namespace/handle
mutation. `hive.key.security` reads the bounded original SK bytes directly.
Independent native golden, physical hive deletion/recreation/raw types/literal
parts, stale multi-hive preflight and real busy/unload/remount tests cover these
boundaries. This is actual effect construction, not package lifecycle success.


The fresh native SYSTEM API control now actually closes DriverUpdateContext
(return1) and persists two backing hives before their mount namespaces disappear:
SYSTEM130 surviving raw values/six key-removal events and DRIVERS one value/one
key-removal event. All native registry/file/mapping references are closed and
mounts/pending-unloads are empty. Independent image-hive reads show BasicRender
Active=a779d7425d822522 and its service ImagePath to that repository. Ten new
package-hierarchy keys read back the measured112-byte SYSTEM descriptor, and all
five offline services remain Start4. This is not a completed CBS transaction.

The exact key initializer also establishes GenericExecute20039, distinct from
the WCP registry setter's20019 mapping. The corrected native assignment oracle
with mapping20019/20006/20039/f003f returns the same independent golden; the
bounded recipe's parent ACEs already carry mapped rights. A separate NULL-creator
SeAssignSecurityEx4001 directory control on the actual FileRepository parent
returns140bytes in3778instructions, matching the existing creation helper's
components, with balanced subject locks/APC state. It does not copy the parent
Administrators owner into the new SYSTEM-owned repository directory.

Final file-effect inspection exposed a genuine adapter defect: native DrvStore
opens drvstore.tmp with CreateFile flags06000102, including DELETE_ON_CLOSE.
The old adapter retained it after closing all handles. CreateFileA/W now ties
that flag to an owned open-file object; duplicate handles share it, independent
opens retain their own offsets/lifetimes, and rename cannot delete a replacement
occupant. Delete sharing and readonly failure are checked before truncation.
The existing final unlink machinery waits for remaining handles/mappings/views.
DuplicateHandle now writes a full native-width handle and accepts the modeled
full-width current-process pseudohandle. The distinct NT create option is not
silently treated as the Win32 flag; it remains an explicit unsupported path.
Cross-architecture A/W controls cover surviving readers, duplicates, output
guards, full-width IDs, sharing/readonly failure atomicity, rename/recreation and
final unlink. File/directory query records retain whether creation security
attributes were supplied, rather than inferring NULL creator policy later.
A fresh exact SSU9703 control after this correction again returns stage0,
install0 and Close1. drvstore.tmp is absent from the final native namespace and
export; no manual temporary-file filtering/removal was used. The recorded new
repository directory explicitly has NULL security attributes. The file-effect
planner verifies two already-persisted backing hives, constructs two canonical
file objects and three actual hardlinks over five final paths, and creates the
repository with the independently measured140-byte creation descriptor.
Independent resulting-image reads verify the selected INF3554/SYS77824 hashes,
shared published-INF/repository/WinSxS identity and security, distinct old INF
identity, matching service path/Active, intact input guard and all five offline
service starts4. The old repository remains available; global old-only CSI file
cleanup is still not wired before complete owner/queue handling. This single
native driver construction is not the whole selected driver batch or CBS commit.


### Literal driver-owner leaves and native owner-method control

The COMPONENTS `Drivers/amd64/basicrender.inf` baseline leaf is named
`fKZT4pQLTkE2MkR0IP7z8igX8DZ96dLVu00O/zs4Ot8=`. Its slash is part of the
base64 name, not a registry separator. Hive source exclusions now accept
`key_parts` dictionaries for both key subtrees and exact value removals. Import
uses a case-insensitive component trie, after any drive relocation; display-path
prefixes cannot identify these objects losslessly. Writer format support remains
1.1–1.5; this change does not expand the separate reader's 1.6 support.

The SSU 9703 cbscore image (PDB A3649FD1-8227-5D71-56E3-8C3A438791D7,
age 1) was exercised against an isolated, actual copy of the baseline COMPONENTS
hive. The bounded receiver fixture invokes the native CCbsSession constructor
(71300), CCbsStoreParameters constructor (1b1c20), ConfigureBusinessPolicy
(ae28c), and LoadOfflineRegistryHive (3f008). The receiver's +348 field links the
constructed parameters object; no initialized/installed/session-completion flag
is supplied. This is **not** CCbsSession.Initialize, full store initialization,
or a CSI transaction. The parameters +1c0/+1c1 bytes are the COMPONENTS
OFFLINE_REGISTRY_KEY enable/read-only policy, not session-completion flags.

Native SetDriverOwner (10f9d4) and DeleteDriverOwner (10a234) produced these
actual controls, with independent DWORD output guards and receiver guards intact:

| Operation | Existing/deleted owner | First owner / owners remain |
| --- | ---: | ---: |
| Set an existing owner | 1 | 0 |
| Delete one of three owners | 1 | 1 |
| Delete that absent owner again | 0 | 1 |
| Re-add it while two owners remain | 0 | 0 |
| Delete each owner, final deletion | 1 | 0 |

Final native effects contain three value removals and two key removals: the
literal hash leaf and now-empty INF parent. Native parameter destruction (45f7c)
then executes NtFlushKey and NtUnloadKey2 with flag 1 and **no** surviving key
references. Actual backing-hive bytes have both objects absent; unrelated
BasicDisplay ownership remains. There are no mounts, pending unloads, or owned
registry references afterward. These changes affect the isolated control hive,
not the production image or its admitted driver batch.

The backing provider persists captured bytes on an owned native flush even while
references remain open; flushing never waives the busy-unload check. Its admitted
synchronous unload path requires zero references. Force-unload behavior with live
references remains explicitly unsupported, not a fabricated successful detach.

The required caller inventory is explicit: initially disabled, owned LUIDs
8, 17 and 18. Actual native privilege acquisition enables them on an independent
impersonation token. Omitting 8 yields STATUS_NOT_ALL_ASSIGNED and the native
privilege-not-held failure; no privilege is added to an existing token. The public
NT privilege-adjustment implementation now performs real owned-token mutations
instead of returning an empty success. Native/thread-token attachment, invalid
levels, independent privileges, previous-state capacity failure, and full-width
current-thread pseudo-handles have x86/amd64 controls.

Baseline NTDLL RtlGetControlSecurityDescriptor (eed90) writes its ULONG revision
before validating revision 1; on STATUS_UNKNOWN_REVISION (c0000058) it leaves the
USHORT control untouched. RtlGetControlSecurityDescriptor and
RtlMakeSelfRelativeSD (57000) ran as actual target NTDLL code in the owner-method
control. The former now also has a portable provider with native output-order
regressions. Native absolute registry names split only on backslashes and retain
literal forward slashes, including mounted HKLM children.

Last-owner cleanup exposed a separate RegDeleteKey empty-name contract. Target
KernelBase RegDeleteKeyExW (a7440, internal a75ac) reopens the relative target
with DELETE even for a non-NULL empty name; it does not require DELETE on the
original reader handle. The provider now preserves that behavior and stale-object
lifetime, while rejecting NULL names, hive-root deletion, children-bearing
nonrecursive deletion, and unsupported registry views as before. Full execution
of the target KernelBase helper was not used as a success oracle: its real API-set
query against the image's .apiset section reports the optional advapi registry
contract present, then reaches the still-unmodeled delay-loader dependency. No
false API-set absence was supplied to bypass it.

The owner-method fixture's CRT aliases delegate only actually imported, already
modeled operations. Its observed printf subset is options 3d, NULL locale and the
two string/integer formats; native truncation returns remain negative so the
real CBS string allocator grows its buffer. This is not a general UCRT model.
Creation security for **new** COMPONENTS driver-owner leaves, the admitted driver
queue, full offline-store/session initialization and whole CBS completion remain
separate requirements.

## Ordinary driver queue matching and declaration provenance

SSU 9703 `CCbsExecutionDriver::Execute` (139214) dispatches ordinary install
(action 3) to `DoqAddDriverOperation` (10a7bc) with operation type 0; ordinary
uninstall (action 4, including its jump back to 1398f7) supplies type 1.
The separate `Stage` method (13a944) stages through IServicingStager; stage-only
references must not be relabeled as driver installation. `DriverOperation`
initialization (12b760) copies the driver's **declared MUM INF**, ranking, and
boot-critical bit from CCbsDriverDeployment, obtains the deployment's definition
identity text and architecture, and constructs `package~update` at +10. Its INF
hash comes from the selected INF file in that deployment's manifest, not from
the containing update ID, component identity hash, or arbitrary first INF file.

The portable manifest reader previously discarded attributes on `<driver>`.
It now retains those namespace-qualified attributes on the reference. Ordinary
population actions return independent `driver_attributes` inspection records;
missing metadata stays missing. This preserves provenance without interpreting
unsupported rankings or granting authorization to install a driver.

A bounded native queue control executes the actual `DoqInitialize` constructor
and stops **before** persisted `DoqLoad`; it does not report successful queue or
session initialization. An explicitly declared test-metadata adapter replaces
only DriverOperation.Initialize for these queue controls. The actual queue
allocation, DoqAddDriverOperation, IsEqualDriverOperation (10ee28), and
InsertInOrder (10ed68) execute unmodified. Observations:

* Equality is a case-sensitive UTF-16 comparison of deployment identity (+18)
  and package/update ID (+10), with canceled entries excluded. INF and hash are
  not compared. Distinct package/update owners of the same INF remain separate.
* A same-type duplicate retains the original operation and sequence, even when
  the fixture supplies a different INF/hash. This observation is not permission
  to accept inconsistent metadata in a recipe.
* An inverse of an uncompleted state-0 operation sets the old canceled bit and
  inserts no replacement. Re-adding then obtains the next sequence number.
* A fixture whose prior operation state is 1 causes an inverse to cancel that
  entry and append the inverse with flag 10. State 1 was explicit **test input**,
  not a manufactured image completion state. Persisted/recovery queue policy is
  not implemented by the ordinary empty-queue path.
* Ordered insertion compares sequence IDs (+8), not INF spelling or version.

`PerformDriverOperation` (10f2c0) copies its CSI owner string and calls the import
**wcsrchr**, not wcschr, at 10f517 before replacing the last period with `~` at
10f54c. Package versions containing periods must be retained. A first-period
replacement would silently corrupt owner names. These controls do not establish
new-owner key security, complete native metadata/bootstrap, driver-store effects
for the whole admitted batch, or CBS transaction completion.

## First-owner creation and admitted ownership-method batch

The actual first-new-owner CBS request is RegCreateKeyExW, options 4, access
2001f, NULL class, and an **explicit** 44-byte `O:SYG:SY` self-relative creator
(control 8000, no DACL/SACL). A NULL-creator kernel capture alone is insufficient.
The target kernel SeAssignSecurity (8cd230) was separately executed with this
exact explicit creator and actual COMPONENTS parent: 9717 instructions, owned
240-byte output, seven ACEs, control 8004, lock/APC counters restored to zero.
The result is byte-identical to the actual parent descriptor and remains a
fixed point at INF/hash depth. Both amd64 and x86 baseline INF parents have the
same captured policy. It is not the separate three-ACE DriverDatabase policy.

The explicit-creator path additionally requires the kernel's OWNER RIGHTS data.
SepVariableInitialization copies SeOwnerRightsSid (e67ce8) to SepExports+200 at
c4781c/c47823, then assigns SeExports=&SepExports at c47e16/c47e22. The isolated
kernel fixture supplies exactly that verified SID/table wiring; it does not
claim kernel boot initialization or bypass an owner-ACE check. Substituting
NULL creator to avoid this dependency was not accepted as evidence.

The recipe provider admits only the observed explicit creator/request and the
captured COMPONENTS parent policy. It queries an actual owned thread token and
requires already-owned enabled backup/restore LUIDs. Missing/disabled privileges,
no thread token, a different creator, options, access or class fail before key
creation; x86/amd64 controls verify that these failures add or enable no LUIDs.
The owner-method fixture explicitly invokes actual CBS
BackupRestorePrivilegeAcquisition::Acquire (ad6f8), then Restore (45904), using
its declared initially disabled inventory 8/17/18. This is a bounded caller
fixture, not full CCbsSession initialization. Calling first-owner creation with
no such caller scope correctly failed; token authorization was not relaxed.
The raw NTDLL RtlAcquirePrivilege detour reached an uninitialized native heap
and was not used as a success oracle.

Native first-owner/second-owner/duplicate results were (0,1), (0,0), (1,0).
Deleting the second/last new owners returned (1,1), (1,0); actual native restore,
parameter destruction, flush and unload completed and preserved the old leaf.

The exact admitted population retains 830 stage actions, of which six are
stage-only, plus 1648 ownership operations (824 install, 824 uninstall), with
no empty-queue duplicates or cancellations. All 1648 actual SetDriverOwner /
DeleteDriverOwner calls then ran on a fresh **isolated** COMPONENTS copy, with
independent per-call DWORD expectations and output/receiver guards. Native
restore/destruction persisted through two backing commits. The entire emitted
Drivers inventory matches the independent expected inventory: 717 final hash
leaves, 132 first-owner and 132 last-owner transitions, all captured descriptors
intact, no surviving owned registry/token references or mounts/pending unloads.
Closed-handle tombstones and the four predefined HKEYs are not live references.
BasicDisplay's unchanged hash retains its three new package owners without
uninstalling between owners; BasicRender preserves the distinct old/new hash
identities. The main recipe root remains unchanged.

This proves only the admitted **ownership-method** batch. The associated native
driver-store operations, physical driver files/registry integration, full queue
execution, per-package lifecycle, and fresh whole-image smoke remain mandatory.
The isolated owner hive must not replace the image's COMPONENTS hive before
those related effects have succeeded.

## Full driver-store batch: secure wide-tokenizer prerequisite

After exact payload staging (17473 files, 13492 component-file descriptors,
4095 parents), all 264 first/last-owner driver job INF files were bound to exact
staged/resident component identities and their actual raw SHA-256 bytes checked
against the selected manifest INF digest. They use 237 source directories; all
264 actual driver-store jobs have normal ranking. A first HID-gamepad
DriverUpdateStageUpdates/InstallUpdates/CloseContext control returned 0/0/1,
with the offline context field +410 genuinely 1 and its update guard intact.
Effects are isolated from the main SYSTEM/SOFTWARE/DRIVERS hives.

The full 132-record native stage array exposed msvcrt.dll!wcstok_s while parsing
BTAMP's interface GUID list. The target baseline MSVCRT implementation (PDB
3D6633E0-2A7A-1306-A00D-36101110A822, age 1; SHA-256
a1bd0acd64e1a60368b8878d3987f603d966ed45be2252d2d4d0f92feb10fa8e) at
63960 was run independently with output guards to capture valid-buffer behavior:
leading/consecutive separators, empty strings, empty delimiter sets, repeated
exhaustion, and a non-BMP token. Continuation points at the actual terminating
UTF-16 NUL after exhaustion, not NULL. Returned pointers count UTF-16 code units,
not Unicode code points. The new portable provider uses caller-owned context
and writes only the selected delimiter NUL and continuation pointer; it does not
reuse the legacy process-global wcstok cursor. x86/amd64 tests independently
check captured offsets/bytes, separate streams, changed delimiters, reset input,
and pointer/adjacent-byte guards. Invalid arguments set per-thread errno 22 and
explicitly stop at the unmodeled secure-CRT invalid-parameter-handler boundary;
no fake successful handler return is supplied. The full stdlib/internal suite
passes 167 cases after this addition.

The full stage call is resumed at the missing import after installing the exact
tested helper, never replayed. Large inbox INFs require substantial actual
native parsing. An unchanged coarse file-query count was not enough to diagnose
a loop: bounded native source/section cursors advanced through 106–992 KiB INFs.
The native string-table hash (drvstore 21c00) genuinely calls LCMapStringW and
uses a sum modulo 509; no constant-hash stub or skipped parser was introduced.
The same native execution quantum and final VM smoke bounds remain unchanged.
These are prerequisite and progress facts, not proof that all driver-store
phases or the whole updated image have completed.

## Mounted-key object-name and CryptoAPI delay-load prerequisites

The full native batch next queried ntdll!NtQueryObject, class 1, for an owned
mounted SYSTEM key, ControlSet001/Control/WDF/Schema. The call site is
_RegRtlQueryKeyPathName (drvstore 7c23c, return 7c2de): it reads a UNICODE_STRING
Length at 0 and Buffer at 8 and handles STATUS_INFO_LENGTH_MISMATCH. This is
not a kernel file handle, nor a key in the physical SOFTWARE hive. The private
mount provider now resolves only live registry handles within its uniquely
owned HKLM mount. It emits the actual native REGISTRY/MACHINE namespace with
backslash separators; each encoded registry display component is decoded
separately so literal slashes in the mount name remain literal. It does not
invent a general ObjectManager model or support other information classes.
Guarded x86/amd64 tests cover the 8/16-byte header, UTF-16 byte lengths and
pointer width, NUL, insufficient-buffer ReturnLength without output writes,
non-BMP text, literal slash/percent escaping, closed handles and unknown scope.
All 12 private registry tests pass.

After this dependency was supplied, the same native stage execution advanced
until a real delay-loader exception c06d007e: the explicit module namespace
lacked api-ms-win-security-cryptoapi-l1-1-0.dll. The actual delay-import descriptor
contains CryptAcquireContextW and CryptReleaseContext. The existing CryptoAPI
provider implements these contracts; its two exact API-set aliases now share
that same provider context inventory. A dynamic LoadLibraryExA/GetProcAddress
x86/amd64 test proves cross-namespace acquisition/release, output guards, and
rejection of unknown exports. It does not attest catalog trust or bypass crypto.
The public stdlib/internal regression command passes after the addition.

No exception was suppressed and no hmod, stage result or completed phase was
forged. Because the delay-loader had already failed before the missing import
stop, that isolated attempt was retained only for inspection. A new isolated
hive copy and native context was built with the exact explicit virtual contract
and tested dependencies. The main image still has not received driver effects;
this restart invalidates the old attempt's progress, not its prerequisite tests.

## Catalog metadata and nested driver source files

The next full native attempt passed the CryptoAPI contract and failed resolving
WinTrust!CryptCATOpen (c06d007f), not loading the crypto DLL. The actual drvstore
WinTrust descriptor declares CryptCATClose/Open/EnumerateCatAttr,
CryptCATAdminAcquireContext/ReleaseContext/CalcHashFromFileHandle,
CryptCATGetMemberInfo, and WinVerifyTrust. CryptGetCatalogInfo at c2904 opens
with flags/version/encoding 0 and a real ephemeral CryptoAPI provider handle,
then reads the catalog-level CRYPTCATATTRIBUTE records, not member attributes.
The observed AMD64 structure fields are size@0, reference-tag pointer@8,
flags@16, value-length@20, value pointer@24 (size 40); x86 uses size 24.

The actual staged amd64 ntprint.cat (17498 bytes, SHA-256
7101d5c2d732d5fa417952906fc07aa498760fe75b5c623c63b663379a027353) has one
catalog-level SPC_NAME_VALUE extension (1.3.6.1.4.1.311.12.2.1). Its BMPString
reference tag is OSAttr, flags 0x10001, and its 86-byte value is NUL-terminated
UTF-16LE `2:5.1,2:5.2,2:6.0,2:6.1,2:6.2,2:6.3,2:10.0`. Catalog signature
integrity was independently checked, without establishing publisher trust.
The new bounded Go catalog_attributes reader preserves global extension order,
duplicate names, opaque unknown OIDs and raw flag/value bytes. It does not
mistake member/signer attributes for global extensions. Malformed names, flags,
wrappers and truncations fail. The private readonly open/enumerate/close model
uses actual source bytes and owned CryptoAPI contexts; unknown trust and catalog
installation APIs stop before returning any value. Native ntprint successfully
opened, consumed and closed its actual catalog with no leaked catalog/provider
contexts. A cached old interpreter used the same new Go parser through a bounded
memory-only transfer and exact SHA-256-bound immutable facts; a subsequent fresh
runtime consumed the production builtin directly.

The single ntprint stage first returned error 2 because an investigation input
selector included only direct children of the 237 exact source component roots.
The real admitted Amd64/UNIRES.DLL and other nested files were present in the
WinSxS tree, but absent from the emulated namespace. The corrected selector keeps
actual descendants within exact component boundaries, with no flattening or
synthetic file aliases; regression cases exclude prefix-sharing siblings and
reject missing/invalid component roots. This expanded the current input set from
3557 files/4595 entries to 4064 files/5222 entries. A fresh native AMD64 ntprint
stage returned 0, with the real offline-context field still 1. Its isolated
install advanced through the new dependency below; it is not yet complete.

## Relative NT path status and catalog-hint EA boundary

The ntprint install next required RtlDosPathNameToRelativeNtPathName_U_WithStatus
for an absolute FileRepository/Amd64/UNIRES.DLL path. The baseline NTDLL (PDB
C3093720-177D-A685-1519-DCFFE8DF53FE, age 1) entry d8b90 calls the same internal
converter (3d650, mode 2) as the Boolean entry e1e50; the latter alone converts
NTSTATUS to Boolean with TEST/SETNS. Independent native controls captured
STATUS_OBJECT_NAME_INVALID c0000033 for NULL/empty input, and NAME_TOO_LONG
c0000106 for more than 0x7ffe WCHARs, without changing output/relative buffers.
Native vector string reads require legitimate readable buffer padding; no heap
flags or native initialization success were fabricated. The new status variant
uses the existing owned counted-string allocation/free contract. Its admitted
success scope is absolute DOS paths outside the current-directory subtree;
relative paths and current-directory reference acquisition stop explicitly.
x86/amd64 tests cover measured errors, UTF-16 file-part offsets, buffer guards,
empty relative structures and allocation release; the old Boolean ABI remains 1.
The complete public stdlib/internal suite passes 169 tests after these changes.

The next actual stop is NtSetEaFile, not a completed install. Native drvstore
672c0 first opens the existing file with NtCreateFile: desired access 0x100010
(SYNCHRONIZE | FILE_WRITE_EA), share 7, disposition FILE_OPEN, options 0x4060.
It then passes a 39-byte FILE_FULL_EA_INFORMATION record:
`00000000000f0f002443492e436174616c6f6748696e740001000b006e747072696e742e636174`.
This is name `$CI.CatalogHint`, flags 0, value bytes `01000b00` followed by ASCII
`ntprint.cat`. It is a lookup hint, not a signature/trust verdict. Ignoring the
write would lose real filesystem state. The WIM metadata and NTFS image builder represent EAs. The directory metadata
surface now exposes owned `extended_attributes` name/flags/value dictionaries;
`set_extended_attributes` validates the complete set before replacing it across
all hardlinks, preserving link-local short names and unrelated fields. The
bounded Go FILE_FULL_EA_INFORMATION decoder distinguishes the native linked,
aligned representation from WIM's packed records. File-open handles retain raw
desired access rather than inferring WRITE_EA from data-sharing bits. The private
driver handler admits only the measured v1 hint on an owned FILE_WRITE_EA regular
file under the explicit offline FileRepository. Unknown policy stops. It merges
rather than discards unrelated EAs, marks the shared object dirty, and writes
real native-width IO_STATUS_BLOCK fields. Readonly/access/closed-handle, malformed
chain, buffer guard, snapshot and hardlink tests cover the effect. CopyFile,
file-entry cloning, runner reports, and driver effect plan/apply/readback retain
EAs. None of this accepts a catalog signature or publisher.

A fresh ntprint control subsequently completed native Stage=0, Install=0 and
Close=1: 29 actual hint writes appear on 59 generated aliases in 68 output entries,
with three actual backing-hive commits. File/mapping and mounted-key references
were released; four predefined registry roots are not owned leaked handles.
This single-driver control is not the full 132-driver transaction or whole-image
boot proof.

## Native print-package entropy and registry inheritance

The same install required baseline NTDLL RtlRandomEx (RVA 95db0). This generation
self-initializes its shuffle table using a current-process ProcessCookie query
(class 36, 4 bytes), then updates the caller's ULONG seed and shared table. It
must not be replaced by an arbitrary success or legacy seed-only LCG. The
private helper executes the actual source routine, with an explicitly declared
virtual-process cookie, and admits only that owned current-process query. It
patches neither random tables nor initialization flags and does not claim that
the declared cookie was observed in the target OS. With virtual cookie 6ec81234,
input seed 20000 produced seed 2147123587 and return 1dcd2358, preserving the
adjacent guard. The successful control made four actual calls and one query.
This is bounded AMD64 native-helper execution, not generic NTDLL initialization.

The following real RegCreateKeyW created a GUID under SOFTWARE
Microsoft/Windows NT/CurrentVersion/Print/PackagesToAdd. Its actual 264-byte parent
has a seven-ACE DACL different from COMPONENTS: the non-inheriting administrator
ACE must not be copied to the SYSTEM-owned child. Original kernel
C29EBFB0-6B78-B3C0-20DC-A66D99713F9E, age 6, SeAssignSecurity with the declared
SYSTEM subject, NULL creator, registry mapping and container=1 returned the same
240-byte seven-ACE SYSTEM descriptor already measured for COMPONENTS, in 4170
instructions. A second creation was a fixed point, with locks/APC counts zero.
Only that exact parent-DACL/control case is newly admitted; changed ACE masks
and unknown policies remain rejected. No existing parent ACL was relaxed.

### Legacy CRT comparison validation during native driver staging

The 26300.9457 AMD64 `msvcrt.dll` `_wcsicmp` (RVA `0x60a00`,
CodeView `3D6633E0-2A7A-1306-A00D-36101110A822`, age 1) checks both
pointers before reading either string. A null argument sets `errno` to EINVAL
(22), calls `_invalid_parameter` (`0x2fa00`), then returns `0x7fffffff`.
Do not infer that return from the post-call instructions alone: an isolated
execution of the media-owned CRT followed the handler's unconditional jump to
`0x2fa0c`, native `RtlCaptureContext`, lookup in the mapped CRT's actual `.pdata`,
and media-owned `RtlVirtualUnwind`, then `OutputDebugStringA` with
`Invalid parameter passed to C runtime function.\n`. The handler returned
normally. Five controls covered either/both null pointers, including a null
argument paired with a non-null unreadable address; all returned that value
with errno 22 and without changing the input guard.

This is the legacy AMD64 MSVCRT path, not UCRT handler/fail-fast policy and not
permission to suppress arbitrary invalid parameters. The shared model records
the invalid call and uses the owned thread's errno and diagnostic API. Other
runtimes/widths explicitly stop on this newly admitted path. The native control
requires real FXSAVE state capture and segment-selector reads; neither a
prebuilt CONTEXT nor a skipped unwind is equivalent to that control.

### File-backed read-only mappings are not writable-file growth

The native HelloFace stage reached `CopyDriverPackageFiles`/`SpFileQueueCommit`
and returned error 87 when mapping `FaceDetectorResources.dll` (19,280,448 bytes)
read-only. The old kernel model incorrectly applied its 16 MiB writable-file
growth cap to `CreateFileMappingW` and `MapViewOfFile` for existing read-only
source payloads. No timeout, source package, service, or privilege change is
needed. Existing read-only mappings now retain their source object and allocate
only actual requested guest views, checking the machine's existing allocation
budget before reading payload bytes in at most 1 MiB ranges. Mapping creation
and small EOF views do not materialize a whole large source. Read-only unmap
does not read back or dirty the file. Writable-file growth limits are unchanged.

Both x86 and AMD64 regression controls cover >16 MiB whole views, small EOF
views in a guest whose budget is smaller than the source, write-access/range
rejection, lazy-source preservation, and explicit emulator resource exhaustion
instead of a fabricated OS error when the requested view exceeds the budget.
The isolated native HelloFace control then completed Stage=0, Install=0,
Close=1, with 39 generated entries, two actually changed backing-hive commits,
and no remaining owned file/mapping views or hive mounts. This is a single
package control, not proof that the full updated image has passed its smoke.


### Publish driver files and backing hives as one tree

The offline mount provider's successful hive flush or unload is not sufficient to
publish a driver transaction: the matching final INF, DriverStore files, EAs and
hardlink objects must also pass their file-effect preflight and readback. Build
both on an independently mutable `directory.clone()` and publish only that
returned tree. A late file-effect failure must leave the caller's original hive
bytes and filesystem objects untouched. Reject outstanding mount epochs and
mismatches between each committed backing hive and its final kernel file object.
Compare original metadata as well as content before admitting replacements or
removals; equal file bytes do not prove unchanged security, EAs or timestamps.

`directory.clone()` copies the complete construction metadata, file-data slices,
hardlink reference counts and future allocation/write-order state. It retains
immutable lazy readers (including named streams and reparse payloads) without
reading payloads; their owning source must outlive both trees. Derived child and
short-name lookup caches are rebuilt independently. This is a filesystem-tree
fork, not an emulator checkpoint or a fork of mutable plugin state.


### Device-property values and small-object heap accounting

The full native driver Install path reaches `msvcrt!swprintf_s` from `wvid.inf`
processing with a nine-WCHAR buffer, format `%04lX` and ULONG value 16. The shared
bounded secure formatter supports unsigned decimal/hexadecimal conversions and
literal text, reads only consumed native variadic slots, and measures capacity
and success counts in UTF-16 units. Unsupported conversions fail explicitly;
invalid-parameter and range-error handler policy remains an explicit stop, not a
fabricated returning handler or fail-fast implementation.

The next native property write is the default value below
`Enum/ROOT/VID/0000/Properties/{83da6326-97a6-4088-9453-a1923f573b29}/0010`.
Its registry type is the actual ULONG `0xffff2012`, with 20 raw bytes containing
`wvid.inf` and the native terminators. This is not an ordinary REG_SZ merely
because those bytes are readable UTF-16. Keep unknown numeric types and all raw
bytes unchanged through native query, effect capture and hive serialization.
No device-property interpretation or translation to a different registry type
is necessary to preserve the native effect.

A later Install memory stop was allocation granularity, not 512 MiB of live
application data: 128,928 owned heap objects held 10,446,442 requested bytes, but
one mapped 4-KiB page per object exhausted the unchanged 512-MiB guest limit.
The modeled Win32/NT heaps now own aligned small-object slabs with per-object
logical sizes, heap identity, free-slot reuse and zero-memory semantics. Large
allocations stay separately backed; reallocation preserves the prefix and
in-place bounds; destroying a private heap releases all its slabs. A regression
keeps 20,000 live ten-byte objects under an 8-MiB machine limit on both x86 and
AMD64, then verifies ownership, reuse, zeroing, reallocation and destruction.
This corrects backing storage rather than raising resource limits or returning
success without actual memory.


### WUDF inheritance and target API-set hosts

The HidOverGatt Install path creates an absent key below the existing SOFTWARE
`Microsoft/Windows NT/CurrentVersion/WUDF/Services` parent with NULL creator SD,
NULL class and zero options. Its 468-byte parent has fourteen ACEs and control
`8c14` (including a NULL-SACL-present bit). The matched original kernel
C29EBFB0-6B78-B3C0-20DC-A66D99713F9E age 6, SeAssignSecurity at RVA 8cd230,
with the declared High-integrity SYSTEM subject and registry mapping, returns
the same fourteen ACEs with control `8c04`. The child is a native fixed point;
locks and APC state return to zero. The private creation policy admits only
this exact DACL and those controls, not arbitrary inherited software ACLs.

The next actual delay-load failure is `c06d007e`, last error 126, for
`api-ms-win-security-sddl-l1-1-0.dll` and its declared
`ConvertStringSecurityDescriptorToSecurityDescriptorW` import. Ignoring the
exception or patching its delay-load information would not be a native proof.
The pinned target's real apisetschema.dll contains a v6 namespace with 984
entries and hash factor 31. Its SDDL contract resolves to sechost.dll, security
base and registry L1 to kernelbase.dll, security provider to ntmarta.dll, and
CryptoAPI to cryptsp.dll. Contract matching uses the validated HashedLength
prefix excluding the final revision component; exact full-name matching misses
real backward-compatible entries such as registry L1 ending in revision 2.
It is not a nearest-version or latest-version heuristic.

Decode the actual target schema, keep importer overrides and the value-zero
fallback, and resolve an owned host module and its actual modeled export.
Namespace metadata alone does not admit a DLL, initialize a native image or
supply an absent API. A loader observation guard can stop an unresolved required
lookup before it returns zero, allowing the same pending call to resume after
the missing capability is installed. This avoids inducing, suppressing or
pretending to handle an unrelated native delay-loader exception.


### Native ordinary registry assignment and physical commit

`windows.assign_registry_security` separates registry metadata assignment from
NTFS assignment. Thirteen byte controls from the pinned original kernel cover
explicit owner/group/DACL/audit selection, protection, existing mandatory labels,
LABEL selection, generic-key rights, duplicate ACE retention and AI/AR controls.
Registry assignment does not use NTFS's flags-0x4000 ACL deduplication. The
bounded implementation rejects unestablished controls and ACE categories.

The private ordinary registry planner now reduces the complete admitted key
hierarchy in native family order. It binds the actual selected control set,
uses actual create/open disposition, applies explicit/default security only on
the selected native paths, and removes retiring empty keys bottom-up. Every
emitted touched key's descriptor, values and children are read back before hive
publication; all source hives are checked before the first replacement.
Unchanged profile declarations do not create absent profile keys. Nonempty
retired keys requiring security reset/propagation remain unsupported and fail
closed, as do new-key parents carrying a mandatory label outside the measured
creation policy. In the pinned update all 266 descriptor-bearing retired keys
become empty; those unsupported cases are not silently skipped.

### Offline event registration includes persistent shared autologgers

Static inspection of matching wevtutil PDB
`2331120920A64B86CB502CF16A591A0E1` separates publisher/channel registration
from event definitions retained in PE resources. ProcessProviderNode (`0x264f4`)
validates resources, saves the publisher and channel references, then calls
UpdateEtwSessions (`0x2814c`). OfflineUpdateAutologgerForChannel (`0x2dba8`)
reaches UpdateAutologgerForChannel (`0x2e238`); its shared-session branch calls
UpdateProvidersForChannel, not the dedicated-session security path.

UpdateProvider (`0x2f33c`) derives a shared-session keyword as
`1 << (63 - reference_ordinal)` (`0x2f6c5..0x2f6d2`). The ordinal is not the
manifest's explicit/allocated channel ID. The ordinary Application/System
provider record has Enabled=1, EnableLevel=0, EnableProperty=1, LoggerName,
MatchAllKeyword=0 and the aggregate MatchAnyKeyword. When its selected high-byte
keywords disappear, the old provider key is removed. These six values are also
present in the independent installed IsoEnvBroker and Clipboard controls.
AddChannelReferences (`0x11470`) allocates implicit IDs from 16 while skipping
explicitly reserved IDs; the physical numbered references retain declaration
order. Admin/Operational defaults and exact Application/System ChannelAccess
strings come from InstallChannel (`0x24954`) and matching installed keys.

The private planner handles only this bounded shared-session registration
policy. It globally reduces provider GUID ownership before deleting old
publishers, so the Clipboard GUID handoff preserves and reparents its channel.
It rejects unknown existing child/value state, changed channel configuration,
custom isolation/access/logging/publishing and unsupported creation security.
It is not a complete advanced-installer queue. Regression tests exercise GUID
handoff/removal, two-channel keyword aggregation, explicit ID allocation,
disabled channels and atomic rejection of external configuration.

`windows.event_template_providers` validates CRIM 5.1 provider directories,
bounded non-overlapping WEVT blocks and up to three zero resource-padding bytes.
It does not claim full event-schema/message validation. The updated registration
is checked against the actual final projected PE resource bytes, with Windows
case-insensitive path resolution. All five changed resource binaries in the
pinned update pass exact payload hash binding and GUID-directory validation.

### Source-folder default and manifest creation security

WCP PDB `5D2C0A2BEA78B8EEBEC74A88722B0F541` initializes raw-store member
`+0x38` with GetFileSystemDefaultSecurity selection `0x40` at
`0x827af..0x827eb`. AddComponentFile opens the real-store component directory
and applies this policy only when it was newly created
(`0x13d28c..0x13d2a5`); an existing directory is not reset. The selected SDDL
has TrustedInstaller owner/group, a protected inheritable full-access TI ACE,
and inheritable generic read/execute grants for Administrators, SYSTEM, Users,
and both application-package principals. ApplySecurityToObject decomposes the
input; its S:AI control is not an argument to the principal/ACL interface.
CDirectory::SetSecurityInfo (`0x67d7c..0x67d9a`) selects the established
directory inheritance path. The result is an eleven-ACE descriptor, with
separate effective and inherit-only generic grants, not the six-ACE file policy.
The pure builder matches the independently installed 26100.9441 servicing-stack
source directory byte for byte. Unsupported parent audit inheritance rejects.

WriteManifestFile (`0x1ac1d4`) instead opens through the Manifests directory
with FILE_OVERWRITE_IF, NULL creator security and no subsequent security
setter (`0x1ac275..0x1ac340`). Existing manifest security survives. New manifests
receive the established SYSTEM creation descriptor from their actual parent.
This does not authorize applying the ordinary staged-component-file ACL to a
manifest. Fresh native-only construction applies final security to 3,242 new
source folders and creation/preserved security to 3,981 manifests.

The combined fresh construction completes all new registry, event and staging
security paths, serialized hive checks, catalog/CSI/driver/file passes and AppX
construction without booting a guest or replaying an installer. It still leaves
806 new packages at the resolved-only ceiling. Other advanced obligations and
component/package lifecycle finalization remain separate, and a fresh complete
boot smoke is still required after construction changes.

### Advanced-installer equality is not a blanket no-op rule

Static inspection of WCP 26100.9441 (PDB
`5D2C0A2BEA78B8EEBEC74A88722B0F541`) establishes these independent gates:

- `ExecutionQueueDeriver::AddChange` at `0x5e950` tests installer presence
  on both sides and descriptor change-kind flags before comparing manifests.
- `ComputeManifestInstallerDiffs` at `0x157528` searches 21 GUID/callback
  records at `0x42db70` (24-byte stride, 0x1f8 bytes). Missing callbacks leave
  the result false; structurally equal XML is not an alternative predicate.
- A true result means equivalent. `AddChange` at `0x5eb44..0x5eb89` can still
  enqueue inspection when descriptor +0x10 bit 1 or +0x18 bit 8 is present,
  unless +0x10 bit 0x4000 suppresses that inspection. Equivalence and absence
  of all work must therefore remain separate conclusions.
- The 91 installer descriptions start at `0x42bf00`, stride 80. Presence
  callbacks occupy 68 GUID/callback records at `0x42b8a0`, stride 24;
  category membership supplies an additional presence path.
- The call from `CPendingTransaction::ExtractInformationFromRtlTransaction`
  at `0x8d42a` supplies primary phase bounds 3 through 48. This is not proof
  of a particular invocation's final execution or offline policy.

The descriptors for MOF, Task Scheduler, Firewall Rule, Service, the three
Winsock installers, LodCtr and Counters have equality callbacks and the
0x4000 inspection-suppression flag. Their actual predicates still need to
be satisfied; merely comparing their top-level tags is insufficient. Events
has an equality callback without that suppression flag. HTTP, BFSVC, Network
Drivers, Timezone, Timezone Resource, AppX Registration, Secure Boot, FVE
Update, the transformer placeholder, Per-User Registry and Upgrade have no
entry in this equality table. Their unchanged declarations cannot certify
that those installer obligations have been completed. These findings do not
constitute an implemented queue or authorize final package-state publication.

### Offline timezone resource refresh is not manifest equivalence

Static inspection of timezoneai.dll 26100.9441, matching PDB
`DF658FBCD8FF674A5EC317DB8D7E45A51`, distinguishes its two installers.
`TimezoneAI::_InstallUninstall` (`0x1c90`) returns success without work for
phases 8/10; phases 24/38 call DoOnlineAI (`0x1ff8`). This is an offline
phase no-op, not an XML comparison. `TimezoneResourceAI::_InstallUninstall`
(`0x1d80`) instead executes offline resource loading (`0x3848`), enumeration
and name refresh (`0x2e78`), and current-zone reference update (`0x3ea0`).
The resource installer's unchanged empty declaration does not waive these effects.

`UpdateValueIfNecessary` (`0x4500`) reads MUI_Display/MUI_Dlt/MUI_Std,
accepts REG_SZ references with the case-insensitive `@tzres.dll,-` prefix,
loads the numbered string with a 128-WCHAR buffer, and conditionally writes
Display/Dlt/Std as REG_SZ. Missing string resources leave legacy values alone.
Existing legacy values compare case-insensitively; empty/wrong-type values are
replaced. No new zone keys are created by this pass. The offline resource
loader tries preferred UI languages and then the installation language; the
private recipe currently admits the verified no-preference/en-US installation
and binds the final System32/en-US/tzres.dll.mui to its exact manifest hash.
Unsupported fallback/language, buffer, or Unicode-comparison cases reject.

Current-zone updates require TimeZoneKeyName and both StandardName/DaylightName
resource references; literal user names are preserved. StandardName is updated
from the selected zone's MUI_Std. A nonzero DWORD DynamicDaylightTimeDisabled
preserves a daylight-to-standard alias only when the old references matched;
otherwise DaylightName comes from MUI_Dlt (`0x42c0..0x4468`). The current
control set is selected from SYSTEM/Select, not hard-coded.

The pinned 26300.9457 to 26300.9711 candidate had nine missing legacy values
for Alberta Standard Time, British Columbia Standard Time and Manitoba Standard
Time. Ordinary registry projection had created their definitions, while the
updated resource file held their display/daylight/standard names. The native
resource pass writes those nine values, preserves key security, reads back all
serialized results before publication, and yields zero writes when repeated.
Its resource SHA256 is
`c185e612df9938458bc174951182532397d04a1f204ceac8a46dce810eed2737`.
No guest installer or instruction emulation supplied this construction.
This closes one advanced-installer obligation, not the entire execution queue
or final CBS package lifecycle.

`windows.pe(file).strings` supplies a strict native RT_STRING view: immutable
records `id`, `lang`, `text`, sorted by ID/language, preserving counted embedded
NULs and non-BMP Unicode. It validates all sixteen slots, block-ID arithmetic,
UTF-16 pairs, duplicate block/language identities, and bounded final zero
padding. Empty slots are omitted. Language fallback, resource loading, and
caller-buffer truncation are deliberately not inferred by this format API.

The actual 26100.9703 timezone installer (PDB
`F8ECBFA28DCD5DBE0D5ED7A282B221291`) was independently opened from the
exact ServicingStackUpdate_KB5127647 component plan. Its dispatch range
`0x1ac0+0x540`, complete offline helper range `0x2e78+0x198c`, and registry
constant descriptors `0x9170+0x100` are byte-identical to the inspected 9441
build. The old-build RVAs above were not assumed to transfer without checking.


### Offline HTTP URL reservation replay (26100.9703)

The HTTP installer cannot be discharged by equality of the before/after
`HTTPAI` XML. The 26100.9703 amd64 `httpai.dll`, matching PDB
`2312C802846EF509E0355F875B1414A71`, provides a distinct offline write path:

- `BasicInstaller::Install` RVA `0x1b20` accepts phases 10 and 38. The
  enumerator loop at `0x21a9..0x2252` calls `UrlAclHelper` (`0x2fb8`) for
  each reservation. It does not compare the physical descriptor first.
- `UrlAclHelper` calls `ConvertStringSecurityDescriptorToSecurityDescriptorW`
  at `0x31c1` (IAT `0x63f8`), preserving the self-relative descriptor and
  generic access bits. At `0x3352` it tests phase 10, then calls IRtlKey's
  value setter (`+0xa8`) with registry type 3, the URL value name, converted
  bytes, and the converted descriptor length (`0x3358..0x3387`).
- The registry destination is
  `SYSTEM\CurrentControlSet\Services\HTTP\Parameters\UrlAclInfo`.
  Registry value names are case-insensitive; a URL ACL's generic execute/all
  rights are not file/registry generic mappings.
- The online branch calls the HTTP service API and, on error 183, invokes
  `VerifyUrlAclPresent` (`0x3520`). That online existing-entry behavior is
  not a reason to skip the offline overwrite.

The private policy admits the bounded amd64 paired transition case with
unchanged AddUrl tables and an existing destination key. It now obtains effects
by executing the actual DLL through the native CSI harness described below,
not by predicting its registry writes. The publication boundary compares those
native effects with the physical typed values: equal REG_BINARY bytes need no
serialization; missing, stale, and differently typed values are replaced. It
uses the selected control set, retains unrelated values and key security, and
checks the serialized hive before publication. Changed
reservation tables, overlapping component reservations, unresolved fields,
and absent keys needing unestablished inheritance/queue policy fail rather
than silently being treated as complete. This is not an implementation of
general HTTP uninstall, online service configuration, or the entire CSI queue.

The exact 26300.9457-to-26300.9711 candidate contains four paired components
and six reservations (DLNA, three PeerDist, RasSstp, and RemoteConnectionManager).
All six clean-image descriptors already match; the implementation omission was
masked by the baseline, not a demonstrated corruption of this candidate.
An isolated copy of the real SYSTEM hive with those six values deliberately
damaged is repaired to the original complete URL ACL value map; replay then
writes zero values. The regression additionally exercises missing entries,
wrong registry types, mixed-case names, an inactive control set, generic-right
bytes, unrelated entries, key security, and rejection before publication.

Adjacent negative controls are narrower than queue completion: the UEFI
finalizer already deploys the serviced root's boot assets; the SecureBoot
installer's offline `AvailableUpdates=0x402` write (9703 PDB
`C3294AD35CE6D6E6EBC6439C065A5FFB1`, `Install` RVAs `0x81ac/0x8bbb`) agrees with
the existing candidate value; the FVE installer branches phases 8/10 to
success (9703 PDB `6078D4184146ECF04107D2EDE2EF118F1`, RVAs `0x2335..0x2346`).
These observations do not establish all boot, firmware, or final CBS effects.


### First native advanced-installer execution path

`starlark/stdlib/windows/servicing/installer.star` executes the real amd64 HTTPAI
through the existing Windows semantic runner (the same runner behind COM
self-registration). The production caller pins the entire serviced DLL:
SHA256 `cf6e64fe29b3726acd814dd56e1de9416d3ed97d6da119f99c44e5da339dfaa8`.
The adapter additionally requires the inspected PE architecture and CodeView
identity above. This is a bounded first installer, not a general CSI runtime.

The native sequence is process attach, exported `DllCsiGetHandler` with the
HTTP installer ID and ICSIBasicInstaller IID, vtable slot 3 `Install` in offline
phase 10, native `Release`, and exported `DllCanUnloadNow`. Completion requires
normal return, HRESULT zero, the installer success output equal to one, and
successful object release. There are no jumps into private installer helpers,
no instruction patches, and no synthesized installer-success return values.

The reached service boundary is:

| Interface | Supported behavior |
| --- | --- |
| ICSIInstallerServices | Allocator and system-isolation-layer acquisition |
| IRtlSystemIsolationLayer | Existing absolute SYSTEM registry-key open |
| IRtlKey | Existing relative-key open, typed raw value write, release |
| ICDF | Root/section lookup, HTTP string-table enumeration, string and blob access |
| CDF enumerator / IMalloc | Bounded enumeration, reference tracking, owned-string release |
| WCP runtime helpers | LUNICODE_STRING initialization and bounded diagnostic sink |

The CDF input adapter exposes the observed HTTP table tag `0x22`; its records
contain a URL string index and a blob index whose first DWORD names the SDDL
string. Input indices are session-local opaque tokens. The native DLL fetches
these inputs, calls the existing Win32 SDDL service, chooses the registry path,
and emits the actual raw descriptors. The production policy no longer compiles
SDDL to predict its writes. Other CDF table forms/methods remain unsupported.

The adapter honors Win64 parameter widths: DWORD stack arguments must ignore
the unspecified upper half of their eight-byte ABI slot. It distinguishes
IRtl reference slots from IUnknown slots. CurrentControlSet maps through the
physical SYSTEM Select/Current value; absent keys are rejected until their
creation/security contract is established. New methods fail explicitly rather
than returning default success. Errors from reached WCP services are not
converted into success. The logging sink does not suppress installer errors.

Each execution has a maximum 500,000-instruction budget and a 64-MiB machine
memory bound. Registry writes are owned output records, not mutations of the
source hive. Unsupported extra registry, file, process, service, network, or
exception effects reject the run. Publication checks the entire admitted write
set and readback before replacing a hive. The native code executes even when
all current values match; only redundant serialization is omitted.

`tests/private_starlark/nt6_csi_installer_test.star` supplies a media-backed
regression callable as `verify_http_installer(file)` from the existing prepared
update REPL. It takes the exact caller-provided DLL, not an embedded Microsoft
binary. It verifies independent descriptor bytes, missing/stale/wrong-type
values, casing, inactive-control-set preservation, unrelated values, security,
native replay, a real failure after one write, and instruction exhaustion.
The separate `nt6/update-http` tests cover admission and atomic publication
without requiring installation media. The fresh update smoke exercises the
production module imports and all four real component invocations.

The exact candidate produces six native writes across four invocations
(3,038 Install instructions total), with zero physical changes on its clean
baseline. An isolated damaged copy repairs all six values. A retained run took
about 0.03 seconds for the four complete executions; this is narrow timing
evidence, not a whole-image performance guarantee. Hardware acceleration was
not needed or implemented for this case.

Only HTTPAI is converted so far. Timezone remains the prior direct policy;
other advanced installers, complete queue scheduling, and final CBS lifecycle
publication remain separate work. Renvo/KVM can become an execution backend
later without changing the semantic service/effect boundary, if profiling
justifies it. No compiler performance gates are changed by this work.


### Native timezone handlers share the CSI execution boundary

The former direct timezone-name planner is no longer used for construction.
The pinned 26100.9703 `timezoneai.dll` (SHA256
`12228f33047d2bf84e6ceb1431020419d31d91fa4d1bdebce899348aadad83a8`)
now goes through the same process attach, exported `DllCsiGetHandler`, returned
`ICSIBasicInstaller::Install` (phase 10), release and unload check as HTTPAI.
The factory's two identifiers at RVAs 0x99d0 and 0x99e0 have raw bytes
`d72c9b672bf9d64b8158db4520fa70e3` (primary) and
`2a702873068d40498cd5e33ddaffd52b` (resource). Both primary component directives
(amd64 and wow64) are dispatched to the serviced amd64 basic installer; its
offline path does not inspect component architecture and returns without effects.
This is actual handler execution, not a skipped equal-XML declaration.

Newly exercised CSI interfaces are shared registry/service mechanics, not
installer policy:

- `IRtlKey` slot 13 opens an existing relative key from the 40-byte object
  attributes; observed flags 0/1 and case-insensitive attribute 0x40. Its
  disposition is 1 for present, 2 for absent.
- Slot 19 queries value information into an owned 24-byte LBlob (length,
  capacity, pointer). Observed flags 1, classes 1/2 use native full/partial
  information layouts. Its disposition is 2 for present, 1 for absent—**not**
  the key-open convention. The current-zone DWORD reader uses full information
  and follows its DataOffset. Writes are visible to later reads in the same run.
- `RtlFreeLBlob` releases only the adapter's owned blobs. Slot 25 creates a
  key-name enumerator; its slot 2 consumes an array pointer/capacity pair and
  returns pointers to counted LUNICODE_STRINGs plus an element count. IRtl
  objects release through slot 0, not COM slot 2.
- SIL slot 5 also observes flags 3 with a disposition output when opening the
  existing TimeZoneInformation key. Creation without established security
  still rejects.
- Installer services slot 5 expands the admitted runtime Windows-directory
  macro. Locale conversion is explicitly restricted to the admitted en-US
  installation, rather than inventing a fallback language inventory.

The native resource loader exposed a separate common-runtime defect:
`tzres.dll.mui` is a resource-only PE32 image used by an amd64 process.
`LoadLibraryExW(..., LOAD_LIBRARY_AS_IMAGE_RESOURCE)` must not try to execute
that image with an amd64 CPU or call its process attach. Exact supplied paths
now produce reference-counted resource-only handles consumed by FindResource
and LoadString. They do not enter the executable-module inventory. Tests cover
cross-ISA loading, a trapping entry point that is never called, missing paths,
last-reference invalidation, and double-release failure. `LoadStringW` now
counts/truncates UTF-16 units rather than UTF-8 bytes, including a surrogate
boundary. The libraryloader API-set export uses that same implementation.
The shared secure CRT formatter also admits bounded, non-null `%s` arguments;
unsupported modifiers and invalid-parameter handling still fail closed.

Fresh native construction produced nine writes for Alberta, British Columbia
and Manitoba, with 72,611 resource-handler instructions and 67 instructions
for each primary handler. Independent media-backed fixtures cover missing,
stale and wrongly typed legacy names; current-zone references; disabled-DST
standard aliases; literal-name preservation; selected/inactive control sets;
key security and unrelated values; zero-write replay; and instruction-limit
failure after 3–4 successful native writes. Effect publication validates both
hives before either is written. HTTPAI's real-DLL regression still passes
through the generalized adapter.

This section describes the timezone handler's scope, not the completion state
of other packages. The earlier blanket Resolved publication policy was removed;
see “Published state is not a confidence marker” above. Functional boot evidence
and package-specific construction evidence answer different questions.


### Native offline FVE and SecureBoot handlers

The same basic-installer adapter now admits the serviced 26100.9703 handlers:

| DLL | SHA256 | Factory identifier (raw GUID bytes) |
| --- | --- | --- |
| fveupdateai.dll | `397f7b87707990f2c34cf76bfde3debb674f8fabb3b16375380ddab609bfc012` | `bacf4a084f718a4da69afe4e9c8ce62d` |
| securebootai.dll | `d53e98ff790852c2db27a4cdaafa1996a808e9e43f921f9bf487f23c93d3e5e1` | `aaac4b3adbc2f64c8a6b7d9dfd5155f1` |

The exact candidate has four FVE directives (three bootmgr, one memtest) and
two SecureBoot directives (DbOnly/DbxOnly). Each executes process attach,
its own factory, native phase-10 Install, release and unload check. FVE takes
154 Install instructions with no writes. SecureBoot takes 202 and writes
`SYSTEM/CurrentControlSet/Control/SecureBoot:AvailableUpdates`, REG_DWORD
`0x402`. This is native output, not a recipe-generated replacement. The two
identical native writes coalesce only after both executions succeed; on the
clean candidate they require no physical change. Six executions take about
0.15 seconds. This is not a claim about online firmware or BitLocker work.

SecureBoot reaches SIL OpenRegistryKey flags 2, then relative CreateNewKey
CreateOptions 4. WCP 9441 OpenRegistryKey (`0x1409f..0x140f7`) maps flag 2 to
provider option 4. Its tracing table (`0x31b308`, string `0x37e808`) names it
`OpenForBackupIntent`. The adapter admits existing keys only; it does not
invent key security, implement arbitrary privilege transitions or create keys.
The newly reached `_o_malloc` and `_o_free` exports use the shared CRT's tracked
allocation arena, including cross-alias release ownership.

Publication tests cover missing/stale/wrong-type DWORDs, mixed-case value
names, selected/inactive control sets, unrelated values, security, replay,
missing-key rejection and unauthorized effects. Caller-supplied real DLL tests
exercise all three damaged-state cases; replay still issues one native write
but zero physical patches. SecureBoot initialization takes 481 instructions,
more than its Install body. A 182-instruction bound therefore stops in process
attach, NOT after its write. This failure is deliberately reported as an
initialization-budget control, not a partial-Install failure.

### Smart installers are not basic installers with another GUID

BFSVC 9703 PDB `DF2109A469B820CE976347520CD9D5A61`, SHA256
`1da855d8b988f35b750f6fc8657ab09c0d3620a7c7c2549ac613628ffa7d602b`, rejects
the basic IID. Its smart IID raw bytes are `0db70ff14943d848b472668bc981f67f`;
its own installer ID is `d7e9f0c544e8074589e4701b5a747221`. The returned
vtable has InitializeInstaller at slot 3, QueueComponent(ICDF) at slot 6 and
CommitChanges at slot 7. Queueing reads System/Setup/SystemSetupInProgress,
CDF root section 0x21, ULONG-keyed enumeration slot 17 and blob flags at +0.
WCP AddBfsvc (`0x192eec`) serializes Flags DWORD and Source string index DWORD.
Operations 1/2/3 are Install/Uninstall/Inspect, not phases.

WCP 9441 CommitSmartAI (`0x1e5bcb..0x1e5bf4`) constructs commit bit 2 from
IComponentStoreHelper::IsOffline (helper vtable +0x10 points to `0x127c90`).
BFSVC CommitChanges, however, explicitly rejects that bit at `0x410a`, raising
`0xc00000e5` through RtlRaiseStatus at `0x4b2e`, rather than returning success.
The failed experimental smart adapter was removed, not published as a no-op.
The native descriptor explains the mismatch: BFSVC's phase mask at +0x18
is `0x80000000` (phase 31), whereas IsPhaseOffline (`0x11a020`) accepts phases
3..12 and 60..61. AddChange (`0x5ec4f`) tests the descriptor's 64-bit phase mask.
The serviced-root UEFI finalizer remains a distinct construction operation;
forcing BFSVC's online commit is not an offline repair strategy. Full native
queue derivation and deferred-phase accounting remain unfinished.

EventsInstaller 9703 PDB `F96057FBF721AC7F9828B0E0494639A31` also uses the smart
interface, but QueueComponent takes IWcpManifest (slot 5), not ICDF (slot 6).
QueueComponent `0x4f00` calls manifest slot 3, reads the parsed assembly at +8,
identity string at assembly +0x58, and instrumentation at +0x210. Its WCP
imports operate on native XmlParserGenerator DomElement/attribute/iterator
objects, GetXml, and Microdom; a raw XML pointer or HTTP CDF is not that ABI.
A native parsed-manifest route is available in serviced WCP PDB
`7CC21FAF1E625E052DD8ADB23E8B25F21`: AutoNewPtr<WcpManifest>::Allocate `0x64bcc`,
ParseFromBlob overload `0x114e30` (forwards flags 2 to `0x70470`), destructor
`0x4b2d0`. Initialization currently stops first on the private CRT common-wide
formatter; a bounded observation sees options 61, format
`Local\SM0:%lu:%lu:%hs`, locale null. An experiment using the existing formatter
then reaches missing `ntdll!LdrDisableThreadCalloutsForDll`. Neither experimental
shim nor a fabricated loader-success result was added to production. The event
registration policy has not yet been migrated to native smart execution.


### Native Events smart-installer and WCP parser (26100.9703)

The reusable `starlark/stdlib/windows/servicing/smart_installer.star` adapter now
executes a real `EventsInstaller.dll` and a real loaded `wcp.dll`, without
substituting the WCP parser or DOM implementation. This supersedes the initialization stop
recorded above. This is an explicit-job execution API, **not** evidence that the
whole candidate's advanced-installer queue or CBS commit is complete. The image
recipe still uses its previous event policy until native queue eligibility and
atomic registry publication are connected and verified.

Pinned inputs:

- EventsInstaller SHA-256
  `1a147d18be10c3a15a86715c6b879501afa2052196755f74bbc55a5005e80869`,
  PDB `F96057FBF721AC7F9828B0E0494639A31`;
- WCP SHA-256
  `1a5d390bfbf10e24f124fd423916d15e00af06b7b8a6c982ca00ac1fd7991d85`,
  PDB `7CC21FAF1E625E052DD8ADB23E8B25F21`;
- the amd64 FunDisc 26100.9549 manifest fixture SHA-256
  `20d3116cebed714670541c25b500984352a75878ac4f42fc202f6f1c9691c9ed`.

`AutoNewPtr<WcpManifest>::Allocate` at WCP RVA `64bcc` allocates a 0x38-byte
object, stores it in its pointer owner, and returns that **pointer**, not an
HRESULT. `ParseFromBlob` at `114e30` receives `(this, LBLOB*, stopwatch=null)`.
LBLOB has 64-bit length/capacity at offsets 0/8 and data pointer at 16. The native
parser needs 3,157,424 instructions for the 26,277-byte fixture; its first
one-million-instruction stop was a budget, not a parse failure. Native destructor
`4b2d0` followed by native operator delete `33fb0` releases the parser object.
The adapter destroys it and frees the input buffers immediately after Queue;
the successful Commit demonstrates that this queue owns its required input.

Events' raw smart IID is `0db70ff14943d848b472668bc981f67f`, and its raw CLSID is
`2bfdb93b1e359c4bb1fced0758805998`. Native vtable `2d120` is
`[4e70,4240,5ed0,4e60,2800,4f00,2800,47b0]`: QI/AddRef/Release,
Initialize, unused overload, QueueComponent(IWcpManifest), unused overload,
Commit. The pinned Initialize is a native two-instruction no-op. Queue calls
IWcpManifest slot 3 to obtain the real WcpManifest; it reads the native assembly
at +8 and instrumentation at assembly+0x210. No manually assembled XML parser
objects are substituted. Commit receives the actual offline flag 2 and uses
ICSIInstallerServices slot 3 (allocator) and 13 (VirtualPathToPhysical). The
latter admits only flag 1 and HKLM\Software/HKLM\System, returns an owned
UTF-16 path, and resolves against exactly the target hives mounted in the
isolated emulator. All other methods fail closed.

The explicit-media regression in
`tests/private_starlark/nt6_update_events_native_test.star` passes in a **fresh
CLI using only the shared on-disk implementations**, not the exploratory plugin
overrides:

- Install=1: 22,599 queue instructions, 4,684,947 commit instructions, 3 created
  keys, 3 deleted keys, and 12 final registry value effects. The native installer
  deletes/recreates its publisher and ChannelReferences hierarchy.
- Inspect=3 against the healthy fixture: 13,147 queue instructions and 4,786
  commit instructions, with **no effects**. Do not replace Inspect with Install.
- Changing the actual provider name in the manifest changes the actual native
  registry output, ruling out a cached/synthesized success.
- A 4,640,000-instruction limit fails in offline Commit after its early work;
  no effect report is returned. Malformed XML fails in native manifest parsing.
- Original SYSTEM/SOFTWARE file hashes remain unchanged. Native handler Release
  and DllCanUnloadNow both return zero, and CSI allocator buffers are released.

Queue eligibility remains separate. The 9703 native descriptor table is at
`42df00`, 91 entries of 80 bytes. Events is index 54: DWORDs at offsets
16,20,24,28,32,36 are `[1003,e,80000200,0,2b,4d4c]` in hexadecimal. Its phase mask
therefore includes 9 and 31, not the basic installers' phase 10. Native
`IsEventsPresent` at `10e620` takes an **assembly pointer**, not WcpManifest,
and tests instrumentation's first item. `EventsDiffer` at `268ff0` takes two
WcpManifest references and an output BOOLEAN; despite its name, the inspected
path writes **1 after all elements compare equal**, and 0 on a mismatch.
Do not infer queue operation from that function name or raw XML equality.
`ExecutionQueueDeriver::Initialize` is at `14b460`, its native Impl constructor
at `260d64`, and AddChange at `5efe0`. The Impl constructor installs the real
91-entry descriptor vector via `15f7cc`. Native queue flags/phase selection and
complete job extraction still need verification before recipe integration.


### Native 9703 execution-queue derivation (bounded experiment)

`windows_update_native_queue.star` now uses the pinned WCP parser plus native
`ExecutionQueueDeriver::Initialize` (14b460), `AddChange` (5efe0),
`ShouldRunInspect` (15d330), `AddInspect` (5ecd0), and `Finalize` (5c930).
This is a plan, not an execution or CBS-completion claim. The ordinary flags-0
path admits phases 3..12 with zero context and no external transforms. The
native `CPendingTransaction::GenerateOfflineQueue` call at 204a36..204aa3
supplies this range; its special flags 10/20 depend on store queries and are
not modeled by the adapter. `IsPhaseOffline` at 1181e0 independently admits
3..12 and 60..61; the latter range remains outside this adapter. All target
SIL operations stop rather than inventing an empty target store.

The initializer installs 91 descriptors. Some GUIDs have multiple split-phase
descriptors (including the native Fake-WCP test descriptor); preserve them,
rather than assuming GUID uniqueness. The final vector has 70-hex-byte entries:
GUID at 0, execution operation at 10, phase at 14, flags at 18, after identity
at 28, before identity at 20, and inspect identity at 30. These references
retain parsed identities independently of the parser object. The XML input,
however, is borrowed through AddChange: freeing it immediately after parsing
causes an actual read-after-free. Destroy the manifest before freeing its input.

A FunDisc 9278 -> 9549 pair produces System Protection operation 2, phase 9,
and a provisional Events operation 4, phase 9. Finalize alone omits that Events
entry when no inspection inventory has been admitted. This is NOT evidence
that the real transaction has no Events work: ShouldRunInspect returns true.
AddInspect sets the native inspection-admission state, and Finalize retains
provisional inspection entries only for active installer GUIDs. An added
FunDisc-derived component is a positive control for Events operation 2. With
that active change and a separate resident manifest, native finalization
retains both the provisional and resident Events inspection entries. Raw
execution operation numbers must not be passed directly as smart-installer
operation numbers. Missing installed-component inventory is explicit in the
adapter result; an empty or partial inventory is not full servicing proof.

The full 3,634-pair attempt first stopped parsing HyperV-IcSvcVss (pair 124)
at the private CRT `_o_memcpy_s`. The shared emulator now supports only its
bounded valid nonoverlapping copy and zero-count cases. Invalid parameters,
overlap, or excessive sizes stop before mutation; no invalid-parameter
handler policy is invented. The exact previously failing pair subsequently
parses and derives successfully in a fresh runtime using the on-disk code.

The native AddChange ABI is **new, old**, not old, new. This was independently
resolved through `PrimeResolutionQueue` at 121dfc and `ExecuteSingle` at e92ec:
final-entry +28 becomes execution-member +38 and smart operation 1 (Install);
final-entry +20 becomes member +30 and smart operation 2 (Uninstall). The
public probe accepts (old,new) pairs and reverses them at the native call.
Basic execution operations are 3=Install, 1=Uninstall, 2=Delta, 4=Inspect.
The earlier full-list attempts used the reversed ABI: their parser/import and
instruction-budget evidence remains valid, but their eligibility evidence is
invalidated. No derived queue from those attempts was published or executed.
The 3.3-MiB OneCoreUAPCommonProxyStub pair (index 2122) exceeds 200M parse
instructions per side; a bounded 500M budget succeeds (857,762,492 combined
parse instructions). Do not treat instruction exhaustion as malformed input.

A non-delta control independently proves the corrected ordering: adding an
actual parsed fveUpdateAI directive emits basic Install operation 3 at phase
10, while removing the same manifest emits Uninstall operation 1 at phase 8.
The Events provisional Inspect retains the **old** identity when the native
comparator reports equivalence; do not substitute the new manifest. The
regression checks this identity as well as separate resident inspection.


### Native queue finalization reads transformer settings

The first correctly ordered complete 3,634-transition AddChange run parsed every
manifest but failed closed in Finalize at SIL slot 5. This is not a completed
queue. `QueueTransformerPluginsToExecutionQueue` (0x5b5a0) calls
`QueryTransformCurrentSettingsVersion` (0x263870), which opens
`COMPONENTS\DerivedData\TransformSettingsVersion\<name>` and reads the
`SettingsVersion` DWORD through IRtlKey. The real function defaults to zero for
missing keys/values and wrong types. The SIL absolute-open method is slot 5,
relative-open slot 13, value-query slot 19, release slot 0. Flags 1 with an output
disposition admit missing keys (1 present, 2 missing); partial value information
uses query class 2 with disposition 1 missing / 2 present. Buffers are LBLOBs and
must use WCP's allocator so native RtlFreeLBlob can own their lifetime.

`QueryOSVersionFromRegistry` (0x26366c) reads SYSTEM\Setup\BuildUpdate:
Rollback DWORD and SourceOSVersion/TargetOSVersion QWORD. With Rollback set it
reverses source/target output selection. Consecutive DWORD/QWORD reads reuse the
LBLOB and require growth. The read-only queue bridge uses actual native allocate
and free through nested emulator.invoke, not a WCP function override.

The exact old-only WpnData transition (PushNotifications-Platform-Library,
amd64) passes native finalization with the explicit baseline/candidate hive
snapshots: 4,145,344 parser instructions, 92,552 AddChange instructions, 1,689
Finalize instructions. It queries old WpnData (absent), then old BuildUpdate
Rollback and TargetOSVersion (both absent). It emits no WpnData transformer;
the separate per-user registry delta remains. This does not imply transformer
completion for different registry snapshots. Full-run completion still needs a
new finalization, and unchanged inspection eligibility remains unresolved.

Inspection gate correction: the constants passed to store slot 35 are GUIDs,
not registry-name pointers. QueryConfigurationOption maps f39479e2-c59b-4a02-
8973-9f58eeca9ffb to SingleResourceOwnership, 3e702c22-a64d-47d1-a174-05aaa1982ba9
to EnableInspect, and e8d62e5b-82f5-4f1d-8e22-291bf7dfb3bf to DisableInspect.
Feature_Servicing_EnableInspect uses feature ID 0x355bd17. The current emulator
returns the native unavailable-provider default (false) because dynamic
RtlQueryFeatureConfiguration is absent. That observation is NOT evidence that
the real target feature state is false and cannot authorize omitting inventory.


### Complete changed-component queue and phase-8 controls

The corrected native 9703 deriver plus explicit hive snapshots completes all
3,634 changes: 21,234,964,348 parse instructions, 300,823,195 AddChange instructions,
821,620 Finalize instructions; 117 entries, all flags zero. This is still NOT the
complete queue: ShouldRunInspect=true and unchanged inventory was not supplied.
Counts (phase/operation): AppX Registration 13 (9/2), Events 6 (9/2), FVE 4 each
(8/1,10/3), HTTP 4 each (8/1,10/3), Network Drivers 9 (9/2), Per-User Registry 45
(9/2), Secure Boot 2 (10/3), Services category 4 (3/2), System Protection 20
(9/2), Timezone Resource 1 each (8/1,10/3). No primary Timezone, Task Scheduler,
MOF, Firewall, BFSVC or Upgrade entry appears in this changed-only phase-3..12
vector. Do not infer other phases or inspection completion from that absence.

ICSIBasicInstaller slots 3/4 are Install/Uninstall with the same eight-argument
ABI. FVE vtable 0xf038 maps to Install 0x2130 and Uninstall 0x2990; phase-8 native
Uninstall completes in 154 instructions without effects. HTTP phase-8 removal
really deletes its six URL values: four jobs cost 301/461/301/301 instructions.
IRtlKey slot 24 is CKey::DeleteValue (WCP 0xfed20), argc4; observed flags1 and
null disposition. The common adapter now records isolated value_deletions and
honors them in subsequent queries, instead of returning invented success.
Timezone Resource removal completes in 72,593 instructions without effects when
its exact tzres.dll.mui is supplied; omission correctly fails a resource query.
These removal paths have not yet been integrated into the recipe wrappers.

The six changed Events entries produce ten smart jobs (new Install first, old
Uninstall second, missing sides omitted). Their actual Commit exceeds the old
20M limit. At an explicit 100M limit it reaches 78,444,284 instructions then fails
on the real channel-access SDDL S:(ML;;NRNW;;;ME), from System-Events Kernel-Shim
and LiveDump declarations. The shared SDDL encoder now delegates ML ACEs to the
native format compiler, which validates integrity SID, mask, ACL placement and
flags. Native compiler adds ME and NW/NR/NX tokens. Focused binary/negative tests
pass. The ten-job Events batch must be retried in a NEW CLI after this Go change;
no effects from the failed probes were published. Its budget maximum is now
200M while the default remains 20M. No fake success or installer patch is used.


### Native Network Drivers and executor eligibility boundary

The common smart-installer harness now has an experimental Network Drivers
profile for NetSetupAI (`61daae9a7d4f56a3ca2d27f2066a21a5a094b667fb30660331ced3d94b86584e`).
Unlike Events and System Protection, this descriptor uses ICDF slot 6, not the
IWcpManifest slot 5. WCP's actual XML-to-CDF parser (`0x26d550`) and CCDF factory
(`0x29b4a0`) construct the inputs; their raw/COM/XML owners remain alive through
native commit and final handler release. Metadata slots 3 and 4 supply the
process allocator and the explicit AMD64 target architecture. The inspected
process allocator's native AddRef/Release both return 1; allocated buffers remain
strictly owned and must be released.

Explicit NetSetupApi and NetSetupEngine inputs are hash/PDB pinned. Correct
HMODULE filename lookup is necessary: NetSetupApi derives its sibling engine
path from its own guest filename. Native commit now reaches local registry
transactions and reads serialized network state. The current RPC-runtime probe
uses the target RPCRT4 image to execute its real NDR codec; it is not a completed
Network Drivers profile and has not published effects. The 9 eligible changed
entries (18 ordered after/before jobs) have not yet completed as a batch.

The native per-user executor gate (`CQueueExecutor::DetermineIfHKCUShouldRun`,
WCP RVA `0x1e77f4`) reads SOFTWARE's CBS PackagesPending/FODOrOCPended through a
read-only registry bridge. Controls cover missing key/value, zero/nonzero DWORD,
wrong type, unrelated installer, and flag precedence. The target PackagesPending
key is absent. This alone does **not** justify dropping the 45 Per-User Registry
queue entries: the executor's force/suppress flags must also be established from
the real transaction/store policy. Package completion and unchanged-component
inspection eligibility remain independent unresolved requirements.


### Native RPC security prerequisites (not yet a completed Network AI run)

The target RPCRT4 `RpcpNormalizeSecurityDescriptor` opens `\RPC Control` with
`READ_CONTROL | DIRECTORY_QUERY` and queries owner/group/DACL/mandatory-label
information (0x17). Namespace facts must not be invented to satisfy that call.
The target SYSTEM hive lists `\Windows` and `\RPC Control` in Session Manager
ObjectDirectories, with ProtectionMode 1. Target SMSS
`SmpConfigureObjectDirectories` (0x14400) selects its liberal descriptor for both;
`SmpCreateSecurityDescriptors` (0x9d90), run with actual NTDLL and the hive's mode,
returns success in 1816 instructions. Native self-relative conversion yields a
236-byte **creation** descriptor: owner/group absent, seven DACL ACEs, and a low
mandatory no-write-up SACL. This is not yet the final assigned object descriptor.
Actual x86 and AMD64 NTDLL security-query controls both compact the label ACL's
four unused trailing bytes, returning 232 bytes for 0x17. They preserve short
buffers and omit unrequested components in a DACL-only query.

Pinned SMSS SHA256:
`0d05e81c571aa03f1dde5e8fa40cef98b77e8eca64821ae4efab121983d81de6`,
PDB `69DABD4999B5C5EDFF5FAABB0322FD351`.
Pinned AMD64 NTDLL SHA256:
`651ac9041af8e6b5ebd331d53163244c0a27d36d1433f0f15cac1f28c5f2e82c`,
PDB `C031D45B0DA18A6E74D06ED6AB2DD9E11`.

The target kernel supplies nontrivial token facts; a generic permissive SYSTEM
ACL would be wrong. Kernel SHA256
`4a6af9a3dbbeb440c4a9fbe8a4d6832eae751ac3a85860d860b8313a737a2e3a`,
PDB `B661C6FE72991D160FE37C48B8BC54701`:

- `SepInitSystemDacls` (0xc478dc) allocates SeSystemDefaultDacl (0xfd9c38)
  with capacity 60. Its two unflagged allow ACEs are LocalSystem mask 0x10000000
  (call 0xc47d71) and Administrators mask 0xa0020000 (call 0xc47e42), not two
  generic-all grants.
- `SeMakeSystemToken` (0xc4adbc; call 0xc4b2e0) passes that DACL, Administrators
  as default owner, and LocalSystem as primary group. It uses
  SeSystemMandatorySid (0xf05840). These do not establish the protection/trust SID
  of an arbitrary later process; an unprotected emulated process is a separate
  explicit environment choice.
- `ObpDirectoryMapping` at 0xc826b0 contains 0x20003, 0x2000c, 0x20003, 0xf000f.
  In particular generic read includes traverse; it is not just query+READ_CONTROL.
- The class-41 branch of NtQueryInformationToken at 0xaefc99 requires TOKEN_QUERY,
  returns a native pointer plus any SID, and returns a NULL pointer and pointer-size
  length when its process-trust SID is absent (0xaefd1b..0xaefd68).

Native NTDLL security assignment is being executed, not replaced by a success
stub. Its kernel token-query and heap boundaries use owned emulator semantics.
Loading all NTDLL exports globally also exposes WNF feature initialization; a
separately named native implementation image keeps that unrelated capability
admission distinct. Unchanged-component feature policy remains unresolved.
Network effects are still unpublished; this evidence does not establish completed
NDR decoding, all network jobs, final CBS state, or a fresh whole-image smoke.


#### Native Network paired queue and one-sided effect control

The private common smart-installer adapter now runs all nine changed Network
entries (18 native Install/Uninstall jobs) through real WCP CDF creation,
NetSetupAI Queue/Commit, NetSetupApi, NetSetupEngine, RPCRT4 and ImPlatSetup.
A cold saved-code run completed 313659723 parse, 5023413 queue and 180115 commit
instructions, followed by native Release/unload checks. Its registry effect set
was empty. This validates the paired queue in the modeled environment; it is not
proof of the mutation path or CBS completion.

`prepare_network_runtime` pins SMSS, NTDLL, kernel, RPC and System32
ImplatSetup.dll. The latter is SHA256
`e03a40172afc32344c947e5921f8b265aa8eaa65aee14cc4ba5364c660f7f87f`, PDB
`F27443F4DC30125E4CF6B5B7428CB38B1`; native NetSetupEngine explicitly loads
`C:\Windows\system32\ImplatSetup.dll`, not the similarly named servicing-stack
file. SMSS supplies the directory creation descriptor; real NTDLL assigns an
independent, no-parent directory using the kernel's directory generic mapping
and verified SYSTEM defaults. The 232-byte result has BA owner, SY group and
mapped effective ACE access. This is explicitly an isolated-process namespace,
not an assertion about a booted servicing process's full token or inherited
object namespace. No resulting object security is written into the image.
Optional native feature-query warning 80000022 still does not establish target
effective feature policy.

WCP VirtualPathToPhysical 1ef870 delegates to 1e911c and allocates through the
isolation allocator. NetSetupAI's consumer 14f9c..150de uses/advances its returned
ControlSet path without freeing it on the successful return path. The bridge
tracks its own service-return buffers separately and reclaims remaining ones
only after native commit/release/unload; ordinary IMalloc leaks still fail.
This does not replace native cleanup calls or alter installer return values.

A one-sided first-entry Uninstall is the distinguishing effect control. It
required secure `%ws` formatting and ADDSS beyond the paired no-change path.
Those shared implementations now have focused cross-ABI/rounding tests. The
control currently reaches 2208289 commit instructions, then a native
NetSetupEngine exception with HRESULT 80070006. Its bounded transaction audit
shows create/abort, a successful commit, a new transaction, and close of the
prior committed handle. A stale stack word points into KTMTransaction::Commit,
but this alone does not prove that Commit caused the failure. No effects from
that failed control are accepted or published. Remaining one-sided behavior,
per-user gates, unchanged inspection, other installers and final CBS lifecycle
must be resolved before promotion.

### Network Drivers: real one-sided mutation control

The apparent `80070006` after KTM commit was not a failed transaction. Decoding
the actual stack frames in the retained snapshot gives NetSetupEngine's native
exception constructor `4d6fc` -> `HResultException` `4d680` ->
`RegistryKey::DuplicateFrom` `1d3b0`. Its `DuplicateHandle` call through IAT
`9b690` received the ordinary registry handle `10001`; the semantic kernel
previously had no registry ownership bridge. Shared same-process registry
handle duplication fixes that boundary without overriding an installer result.

A cold saved-adapter one-sided MsLldp Uninstall now completes actual Commit,
Release and unload: parse 3,457,314, queue 188,169, commit 2,329,517 instructions.
It removes 23 SYSTEM keys and 14 values, and sets netsetupsvc Start to 2. Replaying
against an independently rebuilt in-memory hive completes in 356,915 commit
instructions with no further deletions (only the same Start assignment).
Native Install against that removed hive completes in 2,597,775 commit
instructions, creating 18 reported keys and 26 values. No diagnostic exception
hook is present in these saved-adapter runs. These are isolated mutation and
replay controls, not publication: newly created key security still needs an
established creation policy, and native queue eligibility/unchanged inspection
inventory and full CBS lifecycle completion remain separate requirements.

### Network registry creation uses the actual target kernel

The saved native runtime now supplies registry creation security by executing
`SeAssignSecurity` in the pinned target kernel (`B661C6FE72991D160FE37C48B8BC54701`),
not by copying an ACL or substituting an installer result. Actual `CmpCreateChild`
`948976` calls `SeAssignSecurity` `949590` with the registry mapping, container
flag and pool type. The isolated subject is explicitly non-restricted SYSTEM:
BA default owner, SY primary group, SYSTEM integrity, the verified SYSTEM default
DACL, and no process-trust SID. Native owner and integrity selection use token
fields `90`, `98`, `a8`, `b8`, `d0`; these were checked against this image's code.
The only substituted boundaries are owned pool allocation/free and the declared
subject's resource lock. Native `SeDeassignSecurity` `a305a0` frees the output;
no pool allocations, locks or APC-disable counts may remain after assignment.

Actual Network class inheritance produces a 248-byte descriptor; NetworkSetup2
Protocols produces a 216-byte descriptor. Both are native fixed points at the
next child depth, but neither first child equals its source parent. Thus a parent
copy would have been wrong. The common runner's creation callback now receives
parent security from the exact active registry view, including transaction-local
security, and must provide every missing intermediate descriptor before mutation.

Cold saved-adapter removal/reinstall succeeds with this policy. Reinstall now
reports all 25 created/intermediate keys with native descriptors and 26 values;
all are rebuilt and read back by the atomic hive planner. Native install replay
on that rebuilt hive takes 362,324 commit instructions, creates no keys and only
reassigns netsetupsvc Start. The root image was not changed by these controls.
The earlier missing-security publication boundary is resolved for this tested
NULL-creator profile; explicit creators and special creation options still stop.
Queue eligibility, unchanged inspection inventory, other installer families and
CBS completion are not implied by this result.


### Full Network Drivers native mutation/replay control

The saved adapter now pins the target MSVCRT in addition to NTDLL and delegates
AMD64 C++ matching, cleanup and catch dispatch to those native DLLs. A fresh
nine-component removal took 29,283,491 commit instructions with no raised
exceptions, removing 379 keys and 265 values. Reinstall against the independently
rebuilt removed hive took 50,571,651 commit instructions and exercised 16 real
C++ raises, producing 411 keys with native creation security and 488 values.
Native commit, release, unload and bridge allocator checks all passed. All
reported values and key security passed the atomic hive planner's readback.
Replay against the rebuilt installed hive took 663,930 commit instructions:
no raises, no created/deleted keys or deleted values, only the same
netsetupsvc Start=2 write. These are isolated native installer controls, not
proof that the overall CBS transaction is consistent or that the image recipe
has executed the complete derived advanced-installer queue.


### Complete native unchanged-component inspection inventory

For pinned WCP 26100.9703, `CCSDirectComponentEnumerator::Fetch` at
`1dac39..1dae38` does not select components by "winner OR installed marks".
`IsNonSxs` (`93758`) identities require a present, equal winning version. Other
identities reject a present, different winning version, then require a positive
installed-source count. Missing winners are therefore not uniformly fatal or
uniformly sufficient. `CRawInstallMap::GetComponentWinningVersion` (`26bf0`)
is executed natively: NonSxS and policy families follow the family default
branch; ordinary SxS identities query their own major/minor branch. A synthetic
cross-branch native control distinguishes these paths and absent branches.

Candidate enumeration includes every persisted DerivedData/Components identity,
including unowned staged components. Installed counts sum every `i!` source in
every `c!`-linked canonical deployment, not one boolean per owner. In the target
candidate all 34,734 identities were queried natively. Persisted counts match
all 34,716 population-analysis rows; the 18 additional candidates are unowned.
18,119 candidates have positive counts, but the actual native predicate selects
17,227 installed identities. Excluding both sides of the 7,228 distinct changed
identities leaves 13,609 unchanged inspection inputs. All selected manifest
SHA-256 values match their persisted `S256H` values; no missing manifest is
silently excluded. These are inventory facts, not proof of queue execution or
CBS package completion.

One unchanged `dual_netwtw02.inf` manifest is 8,521,977 bytes, SHA-256
`44941b50d88627d78d69dce0ee97976d52ac0e61d9bfb7d7ca63eaf4ab226545`.
Its native WCP parse needs 1,212,224,926 instructions; a 500-million limit
correctly stops before returning a plan. The queue adapter admits explicit
16 MiB per-manifest / 512 MiB total input bounds and at most two billion
instructions per native call. The isolated large-input control completes
parse, derivation, finalization and effect checks without queue entries. This
control does not justify excluding that manifest from the complete inventory.


### Full changed-plus-unchanged native offline queue

The complete pinned WCP derivation processed all 3,634 changed pairs and all
13,609 unchanged inspection manifests. It finalized 1,227 entries, not the
117 entries obtained from changed inputs alone: 45,256,193,304 parse,
432,038,895 derivation and 17,570,163 finalization instructions. It completed
in 4,360.806 seconds in the measured portable-emulator run. Native registry
queries remained read-only; the source COMPONENTS/SOFTWARE hashes were unchanged.

Additional operation-4 inspection entries are Events 748, Network Drivers 11,
Per-User Registry 46, service categories 238 and System Protection 67. Active
entries remain Events 6, Network Drivers 9, Per-User Registry 45, service
categories 4, System Protection 20 and AppX registration 13. Basic entries
remain FVE 4 removals + 4 installs, HTTP 4 + 4, timezone resources 1 + 1,
and Secure Boot 2 installs. Offline service-category entries use phase 3;
they must not be confused with the online phase-31 Services smart installer.

Common smart-job binding preserves native new-Install then old-Uninstall
queue order, and both provisional changed and unchanged inspection identity
references. It requires a finalized queue and the explicit complete inspection
inventory. Common basic binding preserves phases 8/10 and distinguishes native
ExecutionQueueEntry operation numbers from smart-installer operation numbers.
These binders do not substitute for executor eligibility or phase completion.

A fresh, hash-identical execution context completed all 29 Network Drivers
jobs (9 install, 9 uninstall, 11 inspect): 358,384,083 parse, 9,253,013 queue,
214,052 commit instructions; zero registry effects and zero native raises.
All 107 System Protection jobs completed: 429,792,968 parse, 3,295,291 queue,
8,506 commit instructions; zero key-flag or ordinary registry effects. Native
release/unload and bridge ownership checks remained enabled. These aggregate
no-ops complement, but do not replace, the earlier positive mutation controls.

The native HTTP aggregate completes all eight entries, deleting six URL values
in phase 8 and installing all six in phase 10 against a private evolving hive.
Only after all calls and effect readbacks pass is that hive published. A malformed
last installation manifest fails after earlier native calls without changing the
caller's hive. Independent publication tests cover unrelated values, inactive
control sets, security preservation, and late invalid-effect rejection. These
controls still do not prove global phase ordering or completion of other AIs.


The complete Events aggregate (758 jobs, 19,600,696 manifest bytes) also
completes without splitting its native commit: 2,328,519,424 parse, 29,070,624
queue and 411,734,468 commit instructions. Its 748 inspection jobs preserve
the shared-owner decisions; final effects remain 229 keys recreated and 1,018
values. Atomic planner readback passes for SOFTWARE (185 removed/recreated
keys, 803 values) and SYSTEM (44 keys, 215 values). The measured full batch
requires an Events-specific 2,048-job bound, while other smart profiles retain
512; the 64 MiB total manifest bound and 500-million per-call ceiling remain.
These results are isolated construction controls, not yet a fresh whole-image
servicing completion proof.

### Native executor option and phase-3 services-category follow-through

The pinned 26100.9703 `CQueueExecutor::Initialize` maps its input bit 2 to
executor+40. It queries GUID `7e68509a-2eed-40ca-ae36-6e286cc5d571` with default
2 and compares the returned DWORD to 4 for executor+41. This option is
`MobileStoreVersion`, not an unspecified installer-disable policy.
`CRawStoreLayout::QueryConfigurationOption` (a5d90) checks SOFTWARE
Microsoft/Windows/CurrentVersion/Policies/Servicing first, then
SideBySide/Configuration. `CreateOrGetIStore` opens the SideBySide key at
1f9395..1f93ad; its sixth RtlCreateComponentStore argument becomes provider+28,
then layout+d0 in InitializeStoreContext. InitializeConfigurationOptions opens
the Configuration child into layout+d8. The native option probe returns 2 for
the actual target. Nine native controls cover missing values, policy precedence,
zero, wrong type, and short/long DWORD payloads, without mutating inputs.

Do not derive executor+40 from the pending-transaction constructor alone.
CComponentStore+88 is IsOffline (127060). Offline ApplyTransactionNow goes
through PendActiveTransaction (f0d58), which sets pending+1b0 when
ApplyTransactionPOQsToSil (13fb50) returns disposition 1. That pending byte
becomes Initialize bit 2. This actual POQ outcome remains an obligation; the
bounded false/false eligibility control does not justify dropping the 91
per-user queue entries.

The full basic queue additionally executes eight FVE entries (four each in
phases 8 and 10; 154 instructions and no effects each), two SecureBoot entries
(202 instructions and one policy write each), and both timezone-resource
phases (72593 instructions, no further effects against already-prepared hives).
The latter is replay evidence, not a fresh pre-timezone publication proof.

The phase-3 Services category is `MidgroundInstallers::ServicesCategoryInstaller`
(2f91b0), not online ServicesSmartInstaller. Its 24-byte change rows contain
before, after, and inspection identities. Native enumeration loads the new
manifest through callback slot 1, old/inspection through slot 2, obtains target
architecture through slot 3, and reports metrics through slot 7. The adapter
runs real WCP parsing, native SIL, category enumeration and registry merging;
unknown callback methods fail closed. Caller privileges are explicit inputs.

The first four-entry run reached NtOpenKeyEx with access 0x20106 and options 4.
The shared registry model now supports backup/restore opens of existing keys,
using the current effective token's enabled SeBackupPrivilege/SeRestorePrivilege
rather than DesiredAccess. No token provider fails closed; absent privileges
are denied. Thread impersonation replaces process privileges and transaction
forks retain the dynamic query. New privileged key creation remains unsupported.
Native value query/set/delete and enumeration enforce known handle rights.
Cross-architecture controls and the 28-test registry group pass.

The next native dependency was RtlMakeSelfRelativeSD. Target NTDLL's
RtlAbsoluteToSelfRelativeSD (afb70) rejects relative descriptors then enters
RtlMakeSelfRelativeSD (afb90). Shared conversion now exposes both native APIs;
Make also accepts relative descriptors. Native target controls verify short
capacity 71 returns BUFFER_TOO_SMALL with required 72 in 76 instructions, while
capacity 100 serializes the canonical 72 bytes in 185 instructions, retaining
the success capacity and destination guard. Both-architecture shared tests pass.

With real target NTDLL conversion supplied in the retained context, all 242
service-category entries complete: 772875982 initial parse instructions,
772875698 callback parse instructions, 9649853 merger instructions, 244 manifest
queries, metrics [0,0], and native cleanup. Effects are five SOFTWARE REG_MULTI_SZ
values (native IsoSessionCore, netsvcs, SessionEnvSvc; WOW netsvcs and SessionEnvSvc)
and deletion of native IsoEnvBroker under Windows NT/CurrentVersion/SvcHost.
No keys or key security are changed. These effects have not yet been published.
A fresh complete run using the newly saved semantic conversion, atomic service
publication, remaining installers and CBS finalization remain required.


## Experimental source-bound reverse record creation

`component_staging.create_recovery(index, target_filetime)` creates one bounded
CRC-prefixed PA31 reverse-playback file in memory. It accepts only a planned
component payload with an exact expected target SHA256 and an admitted express
edge with a nonempty basis descriptor. The basis is resolved and verified through
the same length/hash-qualified resolver as forward reconstruction. The forward
payload is reconstructed strictly, then the generated reverse record is applied
and checked byte-for-byte against that basis before being returned. Inputs and
the encoded result are each capped at 128 MiB. This API does **not** select or
publish WinSxS `r/` files, update CSI storage flags, or establish CBS ownership.
Unsupported/literal edges fail rather than silently choosing a predecessor.

The portable writer uses raw copy spans and uncompressed literal spans, source
and target SHA256s, deterministic encoding, and an explicit timestamp. It does not
invoke a native codec or normalize PE files. Timestamp policy for servicing is
not established; the one-file content proof deliberately used zero rather than
copying a reference-image timestamp. Windows consumer acceptance remains untested.

For the pinned 26300.9457-to-26300.9711 update, the admitted `bsdtar/tar.exe` edge
produced a 51,657-byte record recovering 81,920 bytes with SHA256
`ab3f7f7510e5a0761f3e7a604af282a9043c96bbf6e3d33609986734471da538`.
Applying the independent native reference record to the same installed file
recovered exactly the same bytes. Generation completed before opening the
reference WIM; no reference bytes were construction inputs. Record encodings
and sizes differ, and this is not evidence of Windows acceptance or completeness
across the other recovery files.

`component_staging.recovery_info(index)` separately observes an exact `r/` entry
in the PSF CIX, returning None if absent and rejecting duplicates. Forward graph
absence alone is insufficient because unreferenced `f/`, `r/`, and `n/` sidecars
are intentionally excluded from ordinary forward payload targets. The exact
`bsdtar/r/tar.exe` entry was also absent from the CIX in this sample.


### Inherited recovery records for unchanged carried files

The pinned update's 5,167 new recovery paths split into 5,042 files with an
explicit admitted forward basis and 125 unchanged predecessor carries. The
5,042 basis candidates have no extra paths relative to the native result.
A basis descriptor alone is not a general recovery-selection rule: literal,
canonical and installed-fallback cases must not be treated as proven absent.
`component_staging.files` exposes `recovery_basis` (name, size, SHA256 or None)
as read-only evidence, and `file_key` from the original manifest filename,
not from a possibly renamed payload source path.

`component_staging.inherited_recovery(index)` returns None for no matching base
sidecar, or a record containing `file` and `source_path`. It accepts only a
hash-qualified predecessor effect. Component family and relative path locate
candidates; installed length and SHA256 bind the actual content. The PA31
source hash, CRC, reverse flag and decoded target hash are checked before any
record is returned. Conflicting recovered targets are rejected. This lookup is
limited to the admitted base image, not arbitrary historical stages or a
reference image. Missing base recovery is not a statement of full servicing
completeness.

All 125 returned records match the native reference byte-for-byte. They are
hardlinks to the old component's recovery object, not independently created
files. The private recipe now retains those links after normal payload staging.
It validates both the constructed installed bytes and existing recovery bytes,
preflights write-order and destination guards, and preserves the original
object's security, EAs, attributes and times. Its top-level `r` directory uses
the component directory security; deeper directories use the established
SYSTEM creation/inheritance model. No reference descriptor or timestamp is
copied into the construction.

The fresh construction-only comparison passed for all 125 files' bytes,
security descriptors, archive attributes and old/new hardlink relationships,
all 35 recovery-directory descriptors, and all 125 reverse-marker selections.
CSI persistence adds 0x100 only through a retained-path/hash proof; removing or
replacing the record rejects persistence. The ordinary uncompressed file still
uses its RAW storage flags; native physical compression flags are not copied.
This does not publish the other 5,042 generated records, validate their Windows
consumer acceptance, or replace the still-required fresh two-boot smoke.


### One-shot native acceptance of generated reverse playback

The generated `bsdtar/tar.exe` record described above was subsequently tested
once through the native amd64 `UpdateCompression.dll` from servicing stack
26100.9703 (SHA256
`52e242e1e3bc220f3c6aacc97ef03fb9bbc6b5a60d5afb599a914ee479478cbc`,
PDB key `654D9CD668E21DB6776A7DC9275AD2531`). The existing generic PE runner
performed ordinary DLL initialization with the admitted base's native cabinet
module and existing system-API plugins; no emulator features or shims were added.
There was one `ApplyDeltaB` invocation, no retry or resumed execution, a
120-second observation deadline, two-million-instruction bound, and 128-MiB
emulated-memory bound. No guest OS was booted.

The call used flags zero, 24-byte x64 DELTA_INPUT structures, the 92,264-byte
installed file, and the generated 51,657-byte PSF record with only its four-byte
CRC prefix removed. The explicit record timestamp remained zero. The native
function returned BOOL 1 after 526,704 instructions and produced 81,920 bytes,
byte-for-byte equal to the admitted recovery basis, SHA256
`ab3f7f7510e5a0761f3e7a604af282a9043c96bbf6e3d33609986734471da538`.
The result arrived within the deadline without lost/truncated output; the
construction process then exited cleanly and was closed.

This supersedes the earlier statement that native consumer acceptance was
untested **for this one generated RAW reverse-playback record**. It does not
establish the servicing timestamp policy, coverage of all other files, complete
CSI/CBS persistence, or the final two-boot integration result. Native decoding
remains validation evidence only; production construction uses the direct-Go
writer and verifier.


### Full explicit-basis recovery coverage and bounded publication

For the admitted KB5127648 component plan against the 26300.9457 recipe
baseline, all **5,042** explicit-basis recovery candidates now generate and
strictly round-trip to their admitted basis identities. The test used explicit
`target_filetime=0`, retained no corpus of generated records, and produced
2,657,678,534 encoded bytes in aggregate. The largest basis was 36,238,752 bytes.
This is direct format validation, not 5,042 native decoder executions and not
proof of CBS lifecycle completion. The earlier one-call native acceptance
experiment remains the sole native decoder execution proof.

Generated records need bounded retention: `component_staging.create_recovery`
now accepts `lazy=True`. It generates once to establish exact encoded length
and SHA-256, retains bytes in a shared 128 MiB plan-local cache, and regenerates
from the admitted forward edge on eviction. Keys include both file index and
explicit target timestamp. Reopened bytes must match the original encoded
identity. Tests cover timestamp separation, eviction, regeneration corruption,
and initial generation failures.

Reference-only inspection of all 5,042 recovery destinations found ARCHIVE
attributes (32), no EAs, and two security policies: 4,763 ordinary component
files and 279 driver files. Both match the existing component-staging security
constructor; drivers grant SYSTEM full access. Do not copy final installed
file ACLs: they differ from recovery ACLs in 4,647 of these cases. The recipe
uses admitted component identities and constructed directory security, never
reference file bytes or reference security descriptors as production inputs.

The generated-recovery planner and publisher remain separate from ordinary
staging pending timestamp policy. They require an explicit target time,
validate installed-content and basis identities, preflight the batch, create
independent files, and return physical-record proofs for CSI reverse flags.
A fresh construction-only check with the new code published tar.exe, acpi.inf,
and acpi.sys: all three matched reference security/attributes, were independent
files, decoded to the exact basis, and selected CSI flag 0x100. This check used
test time zero and is not the full-image publication audit or two-boot smoke.

Timestamp provenance remains unresolved. For tar, the forward CIX timestamp
was 134361247770000000, forward delta target time 134361063130000000, and
constructed base last-write time 134337974206389795; none explains the native
recovery header's 116444736010000000. Do not silently infer recovery time from
any of those values or promote the test's zero timestamp to production policy.


### Recovery timestamp policy: static producer proof

The preceding timestamp uncertainty is resolved by the admitted WCP
26100.9703 binary, matching PDB `7CC21FAF1E625E052DD8ADB23E8B25F21`.
Its six-argument `Windows::Rtl::DeltaDecompressBuffer` starts at RVA
`0x7bdb0`. When the reverse-output pointer is non-null (`0x7be69`), it
writes `0x019db1de` at `[rbp+3]` (`0x7bf25`) and `0xd5d71680` at
`[rbp-1]` (`0x7bf2c`). At `0x7bfe8` it passes `[rbp-1]` in R9 to
`ApplyDeltaGetReverseB`, producing FILETIME `116444736010000000`.
The codec's `DeltaPatch::GetReverseHeader2` (matching UpdateCompression
PDB `654D9CD668E21DB6776A7DC9275AD2531`) copies a supplied non-null
FILETIME at `0x19cbc`/`0x19cbf`; only the null branch consults the clock.
This is static inspection, not another native execution. It grounds the
recipe constant independently of reference records or file timestamps.
Ordinary staging now generates the admitted reverse records with this time,
then merges their verified physical-record proofs with inherited proofs.


### Migration membership and direct driver metadata completion

On the pinned 26100.9703/9711 transaction, baseline `migration.xml` has 727
entries. Ordinary component transitions remove 428 old manifest names and add
427 after-manifests with an asm.v3 `migration` declaration. The removed-only
identity is Microsoft-OneCore-IsoEnvBroker. The resulting 726-name membership
matches the native reference exactly. Retained entries preserve order; newly
added entries use deterministic transition order, not copied reference order.
The writer verifies both decoded declaration hashes and exact staged encoded
manifest bytes, preflights index/source stability, and preserves index security.
This is a migration membership index, not a package lifecycle success marker.

The direct DriverStore path now restores v1 `$CI.CATALOGHINT` EAs for admitted
host-architecture repositories with an actual nested catalog. The exact INF
CatalogFile declaration selects that catalog; signature and authenticated
signing-time certificate paths terminate at the existing ROOT inventory, and
every hinted member must match both its admitted SHA256 and catalog membership
hash. A hint is a lookup name, not a cached signing level or a trust verdict.
The pinned amd64 case publishes 109 file-object hints; all 109 independently
match reference metadata. All aliases share the object update, and unrelated
EAs survive. The x86 print repositories are retained payload on this amd64
host, not host DriverStore installs: their executable hints name package
catalogs, and their data files receive no private-catalog hint. Three inbox
INFs name separate-distribution catalogs absent from both the unchanged and
replacement layouts; an INF name alone does not authorize inventing those
catalogs or a hint. General package executable hints remain a separate gap.

Six admitted host INF replacements explicitly Include `ks.inf` and Need
`KS.Registration`: Bluetooth A2DP/HFP, USBVideo, ACX HDAudio, HDAudio and
USBAudio2. The unchanged admitted ks.inf's AddReg sections declare 274 values
under 137 new MediaCategories keys. Applying this scoped declaration subset
produces 144 keys including the seven retained keys; all values and security
descriptor fields match the native reference. This does not claim completion
of other KS directives or RunOnce work.

The MediaCategories parent has the standard seven-ACE legacy registry DACL
(control 0x8004), BA owner and no SACL. Its child DACL is a fixed point for the
administrator creation subject. New child owner is BA and group is the target
recipe account-domain SID plus RID513. The original parent's group remains
unchanged. This distinction is important: copying the parent's old media SID
would be wrong, and copying a comparison host's SID would also be wrong.
Construction obtains the new SID from admitted recipe state, never the oracle.
Tests cover target-subject variation, explicit Include/Needs scope, architecture
selection, stale INF/hive evidence, and bounded publication.

### 26100.9703 closure flags and index-cache boundaries

Static inspection of WCP with matching PDB
`7CC21FAF1E625E052DD8ADB23E8B25F21` distinguishes closure proofs from
package lifecycle state. `SetComponentClosureState` at RVA `0x1ced70`
sets/clears mask `4` from its first Boolean and mask `8` from its second,
or combines them as `0xc` when equal. Its calls to `SetComponentFlag`
(`0xf6030`, forwarding to `0xf6058`) invert the Boolean because that
writer's true argument clears a mask; false ORs it into the old DWORD.
Other CF bits are preserved. The embedded valid-mask assertion names
`ClosureFlag_ManifestsPresent` and `ClosureFlag_FilesPresent` separately
from compression, payload-deletion, mutable-file, backup and corruption
flags. None is a CBS Installed marker. Do not synthesize `CF=12` from an
intended package target or overwrite retained physical-state bits.

`IsComponentFileStaged` at `0x1b20c0` instead queries the named per-file
record through `0x4eb74`, requires that record to exist, and tests bit 1.
This function does not use the component CF value to prove a staged file.

The versioned index has lazy population paths: `FetchManifest` at
`0x49310` calls `PopulateComponentVersionedIndexKey` (`0x4b684`) at
`0x497eb`, `0x498ac`, `0x499a8`, and `0x49b1d`. The missing-entry branch
of `AssertPresenceOfComponentInVersionedIndexKey` reaches
`TriggerPopulationOfComponentVersionedIndexKey` (`0xed8d0`), which can
fetch the actual manifest. However, the lower family/key lookup at
`0x4bff0` has distinct missing-family behavior selected by input flags
(`0x4c37c` onward). Lazy population exists; these observations alone do
not prove that omitting an entire new version index is sufficient for
all enumeration/query callers. Do not replace that missing proof with
reference-hive copying or a claim of completed servicing.

### Signed package catalog Hint attributes (26100.9703)

The serviced cbscore.dll SHA256 is
`f5f6d930df5370824a96320ca626cdb58a8a6c6707c3b8c57e0be2350c23fc77`,
matching PDB `A3649FD182275D7156E38C3A438791D71`. Static StageChain
analysis locates `CiSetHintsForPackageCatalog2` at `0x7f8b8`, called at
`0x1287de` with the stored package catalog and offline Windows directory.
The function decodes the catalog CTL and invokes `CipSetEasForEachHint`
(`0x6b90c`). It is not an extension-based PE whitelist or a request to hint
every catalog member.

The CTL walker skips subject identifiers shorter than 32 bytes for v2,
selects member attribute OID `1.3.6.1.4.1.311.12.2.1`, decodes SPC_NAME_VALUE,
requires flags masked by `0x10001` to equal `0x10001`, and compares the
name case-insensitively to `Hint`. The value must have a terminating UTF-16
NUL. It builds `%s\WinSxS\%s` relative to the supplied Windows directory
(the equivalent format avoids a duplicate separator when it already ends
in one). It opens each named object and sets its catalog-hint EA. Absent
objects are not created. StageChain logs hint failures rather than using
those lookup hints as the payload-staging success test.

The admitted WOW64 Package0015 catalog demonstrates the distinction:
1,454 member entries contain only 152 Hint attributes. Their flags include
`0x10010001`; requiring equality to `0x10001` instead of the native mask
would incorrectly discard them. Paths include retained older component
versions as well as newly staged files. Signed member attributes, not
reference EAs or extension guesses, select this scope.

`windows.catalog_entries` preserves the ordered member association,
subject bytes, lookup digest, and attribute values. Its parsing is not
signature verification. The recipe separately verifies catalog signatures,
authenticated timestamp chains, safe rooted relative paths and exact
logical member hashes. It preserves unrelated EAs and does not synthesize
cached signing levels. Package execution order determines repeated writes;
host DriverStore catalog hints have the later driver-install precedence.

### Package hint execution is phase-specific

On the same CBS 26100.9703 binary, `PlanStaging` (`0x121f04`) caps the
**requested owner state**, not the AddPackage ceiling: `0x122054..0x122060`
selects min(requested, `0x40`); `0x122124` passes that state and `0x12211c`
passes ceiling `0x1000`. Replacing this with requested Installed plus ceiling
Staged changes the treatment of preexisting owners and is not equivalent.
`ProcesssMultiPhaseExecution` calls PlanStaging at `0x123a20`, ResolveChain
at `0x123a75`, and StageChain at `0x123ab0`, then clears the execution-package
array (`0x123af7`) before later ordinary Plan (`0x123c14`). The later pass has
its own ResolveChain/StageChain/InstallUninstallChain calls. Final population
records therefore cannot be assumed to be the earlier hint-writing chain.
Ordinary Plan calls `ProcessPackageWatchList` at `0x9a225`; PlanStaging
has no corresponding call. Reusing the final dependency-watch expansion for
the initial staging pass therefore needs separate justification.

StageChain's hint loop also consults `Feature_MumXContainerPhase3` at
`0x128778`; when enabled, package field `+0x424 == 0` skips that package.
`DetermineCatalogPresenceFromIndex` (`0xeeec8`) obtains this field through
`IsCatalogPresentInIndex` (`0xf1034`) and writes it at `0xeef3b`.
A physical catalog in the final filesystem alone does not prove that this
phase visited it. The general hint planner's caller must establish the
executed catalog sequence rather than passing every final package record.

Hint writes are file-object-wide: identical old/new component payloads can
share an object, so an old-path write can change a new path's hint. Path-only
last-writer comparisons do not establish publication order. These findings
constrain the unfinished phase planner; they do not claim its completion.

`PlanStaging` also sets AddPackage flag `0x40` at `0x122110`. This is
more than owner preservation: AddPackage forwards it as the dedicated
PopulateExecutionUpdates staging argument (`0x9714a`, `0x972cc`). The latter
caps a target above `0x40` only if the update's retained starting state is at
most `0x40` (`0x9a912..0x9a924`), then propagates the flag into queued package
children (`0x9affe..0x9b006`). Already installed updates are not lowered.
The native population request now exposes `stage_only` for these coupled
semantics and requires resolved update-start inputs. Recipe `phase="prestage"`
uses this request for the multiphase PlanStaging pass without dependency watches.
It is distinct from an explicit stage-only task: `phase="stage"` requests
Staged through ordinary Plan, including dependency watches. The two paths
must not be conflated merely because both run a StageChain.
Regression coverage distinguishes starts Absent, Staged, Superseded and
Installed, verifies retained named-owner state and two-level propagation,
and rejects staging when current update state has not been supplied.

### Staging inspects lower versions without admitting supersedence

CBS 26100.9703 `SupersedeLowerVersion` stores whether execution action is
Resolve or Stage at `0x9b6cc..0x9b6de`. After querying related package states,
`0x9bc2c..0x9bc30` bypasses recursive AddPackage admission when that value
is true. Thus invoking ProcessMumServicing for action Stage does **not** imply
admitting every installed lower version as Superseded. Install action permits
those requests. The tail can separately migrate update selections via
`MigrateUpdateSelectionFrom` (`0x9c0fa`); omitting supersedence requests is
not evidence that all MUM effects are absent.

The recipe regression runs real parsed manifests and ordinary population with
new/old root versions, an old-only child, and an independently referenced
resident package. Both stage modes exclude the superseded-family traversal
while keeping the resident reference; install includes the old family and
child. The input hive remains unchanged.

Two tempting filters are not native substitutes: PopulateExecutionUpdates
reference kind 5 is a capability (ResolveCapability/PlanCapability), not an
ordinary package or component; its unchanged-state shortcut cannot be applied
to all package references. Also CipSetEasForEachHint retains a failing file
write status at `0x6bae4..0x6bae6` and continues iteration at `0x6baf6..0x6baf9`.
A missing signed path does not terminate the remaining hints in its catalog.

### Ordinary absent-start / absent-target admission gate (CBS 26100.9703)

`CCbsExecutionObject::AddPackage` at `0x9677a..0x96799` compares
retained package start (`[rbp-0x74]`) and computed target (`[rbp-0x7c]`)
against zero. With session field `+0x6dc` clear it takes the skip path
`0x967d8..0x96866`, logging that start and target are both absent and
returning before execution initialization/merge and child traversal. The
start comes from session package state `+0x48`, falling back to pending/current
when unspecified, with `Cbs` state normalization at `0x8c398`. The ordinary
planner accepts already-resolved nonpending input starts; session overrides,
subexecution and forced state remain outside its contract.

This is not a metadata availability rule and not a test of requested owner
state alone. Other owners can keep a nonzero aggregate target; a nonzero
start still requires downward servicing. Skipped admissions must not create
an execution owner, publish updates, traverse children, or reserve an execution
position that changes a later independent admission's order. They must not
make a later nonzero request disappear. The complete metadata index remains
available to applicability and later admissions.

The native comparison log skips absent edition branches. Without this gate,
the planner visits the absent Home-Premium MSMQ wrapper and inserts the shared
server package before the driver package, despite both being independently
needed later. This is an execution-order defect, not grounds to filter MUMs
by edition, `contained`, final catalog inventory, or catalog-hint equality.

### Additional 26100.9703 package persistence boundaries

`PackageStorePersistPackage` is `0x6ade0`, not the older build's RVA.
Its mask gates at `0x6b1a7..0x6b2d8` select state (bit 1), source records
(bit 2), update selections (bit 4), status (bit 8), visibility (bit 0x10),
owners (bit 0x20), and capabilities (bit 0x40). Completing only CurrentState
and Owners is therefore not equivalent to the final commit mask.
`StorePackageState` (`0x39190`) always writes the supplied state in its normal
branch. It refreshes install time only when the old state is below `0x70`
and the new state is at least `0x60` (`0x3926d..0x3927b`); install-user
publication additionally depends on an actual token. Its absent/unstore branch
also depends on a caller flag (`0x391df..0x391f7`). These conditions must not
be replaced by unconditional completion timestamps or deletion of every
zero-target registration. This evidence does not authorize final state writes
before component/installer transaction prerequisites are complete.

### Driver owner execution order (CBS 26100.9703)

Queue registration order is not owner-mutation order. `DoqExecuteImmediate`
(0x10d9b8) calls `DoqInstall` twice (0x10dfed, 0x10e019), then
`DoqUninstall` twice (0x10e042, 0x10e06e). Each pair selects noncritical,
then critical INF groups while retaining queue sequence within the group.
Install calls `SetDriverOwner` at 0x10b6de; uninstall calls
`DeleteDriverOwner` at 0x10cb7f. These findings are static controls, not
proof that an entire servicing transaction has completed.

`DriverOperation::Initialize` uses case-sensitive `wcsncmp` against the
eight-character update-name prefix `CRITDOQ-` (0x12b892), setting bit 4.
`DoqIsCritical` (0x10bb98) also includes all operations with an INF matching
any marked operation, using `_o__wcsicmp`; architecture does not split that
classification. This is unrelated to the MUM normal/force ranking.

Apply the already reduced ordinary forward queue through those passes before
computing first/last owners. Replaying registration order can temporarily
remove a still-owned leaf, invent replacement work for unchanged drivers,
and replace its security descriptor. The low-level owner primitive simulator
retains caller order for comparison with individual native calls; the direct
replacement planner explicitly supplies the execution-pass order. Prior
individual-call replay evidence does not establish whole-queue ordering.

Catalog member hashing must include unmapped PE extra data, not just mapped
headers and sections. The unchanged baseline/native `mfc40u.dll` (x86,
10.0.26100.1) contains a 272-byte trailing debug record. The complete digest
matches its signed SHA-256 member (`5c8acdf9...1663e67`); omitting that record
gives `9f39145b...6580f100`. Keep mapped-page hashing separate from complete
catalog hashing so overlays are not added twice by the signing path or treated
as mapped pages. Candidate bytes were identical to both immutable controls;
this was not an update-payload reconstruction failure.

### Legacy catalog digest: physical header padding (26100.1 msvbvm60)

Fresh combined hint verification exposed a second legacy PE layout after the
unsigned debug-overlay correction. Candidate, baseline, and native reference
`wow64_microsoft-windows-msvbvm60_31bf3856ad364e35_10.0.26100.1_none_c9cc1785eea739fd/msvbvm60.dll`
have identical 1,436,032 bytes (SHA-256
`898288bd3b21d0e7d5f406df2e0b69a5bbfa4f241baf29a2cdf8a3cf4d4619f2`).
Its SizeOfHeaders is 0x400 but first raw section begins at 0x1000; contiguous
raw sections end at 0x15c000, followed by debug overlay, then the certificate
table at 0x15c600 of length 0x2380.

The signed Hint in Client-Desktop-Required-WOW64-Package0014 26100.9711 expects
`2b424813df601157a535649a125e969e6b5553e6f673eb91385c9b0455a891f4`.
Mapped-only hashing gives `7676ca2c...`, mapped plus last-section overlay gives
`3a3e1a99...`, and accumulated-SizeOfHeaders overlay hashing gives `83a4e2ff...`.
Including the physical header padding, with checksum/security-directory and
certificate-table exclusions, matches the signed digest exactly. The portable
catalog hasher now includes that padding and starts its accumulated byte count
at the first raw section. The mapped-only page/signing helper is unchanged.
Regression tests cover the exact byte stream, padding mutation, reverse section
table order, and separation from mapped page ranges; the full Windows package
tests and a rebuilt CLI check of the real signed member pass. This correction
invalidates earlier combined-hint proof attempts, not the byte reconstruction.

### CBS9703 selection persistence and migration boundaries

Static inspection of cbscore.dll (PDB A3649FD182275D7156E38C3A438791D71)
identifies StorePackageUpdateSelections at 0x3703c and
GetUpdatesSelectionInformation at 0x9ebec. Only IsSelectable updates enter the
latter. Nondetachable deployment-type 5 records use selection 0xff and two
false flags (0x9ecd2..0x9ed75). Other updates query user selection without
adjustment (0x9ede5), with applicability and current-selection handling before
emitting the arrays. StorePackageUpdateSelections writes each update value via
SetValue (0x37310), adding bit 16 for the supplied absent-state flag only when
selection is not 1 (0x372bd..0x372f8). These are not installation-state values.

Supersedence's first-time-install branch (IsFirstTimeInstall 0x12e414 called
at 0x9c04a) calls MigrateUpdateSelectionFrom (0x1651e4) at 0x9c0fa. Its ordinary
path iterates destination selectable updates, finds an exactly case-sensitive
UTF-16 update-name match in the predecessor (0x1654df..0x1654f5), queries that
predecessor's adjusted selection (0x165534), and sets the destination's user
selection (0x165567). GetUserSelectionWithAdjustment (0x547b4) can change the
0xff default to disabled when its adjustment conditions and queried states
apply (0x548b1..0x549e3). Copying all 0xff registry values or deriving selections
from planned package targets is therefore not an established implementation.
The adjustment fields are metadata, not unexplained runtime flags:
CCbsUpdate::Initialize passes +0x1c8 and +0x1c4 to
CSelectability::GetDefaultSelectionAndDisposition (call 0xca2e, callee
0x70190). The callee copies its default-selection Boolean (+0x18) and
CbsState disposition (+4), respectively. Adjustment requires disposition
Absent (0), default selection true (1), resolved selection 0xff, update
current state below Staged (0x40), and package current state at least
Installed (0x70). A non-missing overlay selection takes precedence over the stored selection;
the absence bits are ORed before the remaining missing-selection sentinel is mapped
to 0xff (0x54888..0x548ab). No adjustment occurs when the caller disables it.
These static findings do not themselves complete migration or persistence.

### Current-version index root creation and full family rebuild (WCP9703)

The earlier missing-family branch is preceded by a broader initialization path:
GetComponentVersionedKey calls OpenComponentFamiliesKey at 0x4c03e, before
opening the requested family at 0x4c0c6. OpenComponentFamiliesKey (0x4c57c)
first calls OpenCurrentVersionedIndexKey (0x4cbb4). The latter uses
OpenOrCreateSubkey (0xed6e4) for VersionedIndex (0x4cc7e) and the current
BuildVersionString result (0x4ccba). The family-root creation is at 0x4c602.

After cache validity checks, the writable path at 0x4c9ef..0x4c9fa dispatches
helper vtable slot +0x10. The CRawStoreLayoutHelper vtable at 0x303e90 contains
0x1801ab4e0 in this slot; that wrapper jumps to PopulateComponentFamiliesKey
(0x13d5d8). It initializes a registry-key enumerator (0xd5550) over the
component-derived-data key at layout +0x88 (call 0x13d6cd), reads UTF-8 identity
values (0x13d7c5), validates/parses them, creates the family at 0x13d967,
sets SomeUnparsedVersionsExist for a newly created family (0x13d98c..0x13d9af),
and creates its v!version child (0x13da5a). Thus rebuilding is not limited to
whatever exact component a caller happened to fetch first.

This establishes the full rebuild path for a missing writable current-version
cache. It does not establish all read-only callers: the helper's slot +0x18
at 0x4c618 calls IsReadOnlyVersionedIndex (0x11ecd0), returning layout byte
+0x30, and the true branch bypasses the population path. Do not fabricate a
pre-populated cache or declare all read-only/enumeration behavior proved from
writable reconstruction alone.

The initialized read-only flag is specifically InitializeStoreContext input
bit 0x10 (0xa5771..0xa577c). The direct provider's
CCSDirect::Initialize passes flags 1 or 9 (0xa53f1..0xa5461), and
CreateVirtualStoreOverStore passes 0 or 8 (0xa4aff..0xa4b87); neither sets
that bit. An instruction-aligned scan of the .text section finds these two
direct calls to InitializeStoreContext. This narrows the concern for those
ordinary creation paths but is not proof against indirect initialization or
later field mutation in other contexts.

### Unsigned PE catalog digest padding (26100.1 vbajet32)

After physical header-padding coverage was corrected, the next exact signed
member failure was the unchanged 30,749-byte `vbajet32.dll` in
`x86_microsoft-windows-m..s-components-jetvba` 26100.1. Candidate, media, and
native bytes have SHA-256
`25681fc405354e54c08e91d2d1cc3212dd17db7cb1fc85c3cb7eee73ab3bbdc8`.
Its headers and raw sections are contiguous through 0x7800, followed by a
29-byte unsigned overlay; no certificate table exists. Hashing those bytes
with PE exclusions gave `e6a9c71c...`, but the signed Hint from
Client-Features-WOW64-Package0111 26100.1742 requires
`26a5177ecba943666fb176549e0c1233607bce198d6ffd092aec7cfb0d2877bd`.
Exactly three virtual zero bytes at EOF produce that signed digest. This is
alignment of physical file length to eight bytes, not alignment of the shorter
hashed stream after header exclusions. The PE catalog hasher now applies this
padding; non-PE catalog members remain unpadded. Tests cover all eight trailing
remainders, equivalence to physically padded PE input, and a non-PE control.
The complete Windows package tests and rebuilt CLI checks for mfc40u.dll,
msvbvm60.dll, and vbajet32.dll all pass against their signed member digests.

Package-hint verification now finishes its read-only hash pass and reports the
count plus at most sixteen detailed mismatches together, rather than requiring
one complete construction per independent layout failure. Any mismatch still
fails the whole plan: it never returns a partially verified publication list.

### Actual hint metadata depends on cross-version file identity

After the three PE hashing corrections, the fresh full pass verifies 13,147
present signed Hint paths in 3,291 catalog executions. Publication retains
13,103 file objects; host-driver precedence then verifies/publishes 109 files.
The actual combined tree still differs from the native comparison: no missing
hint paths, 686 differing values, and 39 extra paths absent from the reference.
All 686 differing paths also have differing WinSxS hardlink groups. This is
not equivalent to a successful audit of a predicted last-writer map.

For example, mdmcxpv6/VSTBS26.SYS in .1 and .9457 remains one candidate
object, while .9711 is separate. Native links all three; the source and target
raw bytes agree. The current staging writer creates a new file unconditionally.
The descriptor's predecessor source_name is not generally a physical alias:
only 284 literal source paths exist in the candidate, while 2,302 do not.
Unioning those literal links explains only 15 of the 686 differing paths.
Do not substitute unrestricted content deduplication or reference-derived
hardlink groups for the native family/version/hydration policy.

### TurboStack owns the newer unchanged-file prestaging path

The matching 10.0.26100.9703 TurboStack image identifies its public PDB as
`07F35F0E5302C9B965FF1CC85F37F9821`. Its symbols, rather than the older WCP
routine names alone, locate the `SXS ... PreStaging` log strings (0x1c7f68,
0x1c7f88). `PreStageComponentAsync` resumes at 0xe84f0 and calls
`GetPreviousFilesAsync` at 0xe87f1. The previous-file map is case-insensitive;
its construction reads previous manifests and calls
`CmsGetFileHashInformation` at 0xe28ca. The ordinary prestaging path also
selects manifest hashes at 0xe8ffc and compares digest bytes at 0xe916a.

There is a separate `PreStageSingleInstanceFileAsync` resume at 0xe9780.
It looks up the file name in a case-insensitive map at 0xe984c, iterates
`ComponentFileInfo` records of size 0x1b8, compares digest lengths at
0xe99bb and digest bytes at 0xe99c9, then passes the matched record to
`PrestageFileAsync` at 0xe9a6e. These paths must not be conflated with
unrestricted cross-family file deduplication.

`FindEligiblePreviousComponentsForFileMatchingAsync` resumes at 0xdd130.
It consults feature implementations named
`Servicing_MFLUseWinnerAndHighestStagedVersion` and
`Servicing_MFL_Resolved_Package_Fix`; their names do not by themselves prove
a feature's effective state. The observed body requires component derived
data to exist (0xdd398..0xdd3d0), queries CF at 0xdd3fe, and excludes a
present CF with either bit in 0x41 (0xdd445..0xdd44a). Its version selection
at 0xdd461..0xdd4cd distinguishes an exact version match, an explicitly
selected fallback, and otherwise the highest eligible version. The calling
argument identities and ordering still require verification before translating
this into construction policy.

A read-only diagnostic restricted to the mismatched component families and
relative file names explains 670/686 differing hint paths by equal raw bytes.
The remaining sixteen compare DCS-encoded retained files with expanded new
files. Expanding only their storage representation makes the logical-byte
prediction explain all 686. This establishes a storage-sensitive identity gap,
not permission to merge every equal-content file. Negative controls outside
the failing paths and the actual native candidate-selection policy remain
necessary.

WCP `AddComponentFile`'s publication call at 0x13d51d dispatches through
`CSystemIsolationLayer::TransferFile` (vtable 0x3033b0, slot 0x30,
implementation 0x118f60), not the low-level filesystem-provider vtable.
The wrapper delegates to `TransferFileEx` at 0xdedb0. The operation formatter
at 0x2289e0 identifies operation 2 as HardLink and 3 as
HardLinkWithCopyFallback. WCP's `CommitFileChanges` also has an equal-hash
branch calling `TransferComponentFile` at 0x1454c4 with operation 3; its full
path/eligibility conditions must be preserved independently of prestaging.

The broader equal-logical-bytes control covers all staged families rather than
only the failing hints: 6,511 proposed joins after hashing 26,488 distinct
objects, including 32 joins contradicted by the native reference. Examples
include cross-major/minor GDI+ identities, previously separate older objects,
and mutable data files. `dssec.dat` is explicitly `writeableType=systemData`;
its .9278 and .9549 manifests declare the same SHA256 digest, but the native
expanded files remain separate objects. Logical digest equality alone is thus
insufficient even within the apparent stem family.

`PreStageComponentAsync` uses two passes over the matched previous-file list,
not two independent manifest formats. The first calls `PrestageFileAsync` at
0xe9255 with the fifth argument true (0xe923e), then checks the returned file
flags for bit 8 at 0xe936d..0xe9384. If that bit is still absent, it restarts
the record vector at 0xe938a..0xe93a8 and calls at 0xe8de8 with the fifth
argument false (0xe8dd1). In `PrestageFileAsync` this boolean is captured at
coroutine offset 0x91. The body asks `IsComponentFileLZMSCompressed` at
0xea420 and returns without publication when both this boolean and the
compressed result are true (0xea455..0xea475). Therefore it prefers an
uncompressed matching source before allowing compressed-source reuse.

The publication call is `AddComponentFile` at 0xea895. Its operation argument
is normally 3 (HardLinkWithCopyFallback, 0xea7d3); a preceding query-result
and count test at 0xea730..0xea745 selects operation 1 when the result is 1
and count exceeds 100. The query's exact interface and count semantics still
need attribution. Do not infer that hardlinking compressed storage is equivalent
to hardlinking its expanded contents: subsequent file commit can expand or
separate objects, and mutable-file behavior remains a required negative control.


### Prestaging transfer selection and bounds (TurboStack/WCP 9703)

Additional static observations from TurboStack PDB
`07F35F0E5302C9B965FF1CC85F37F9821` and WCP PDB
`7CC21FAF1E625E052DD8ADB23E8B25F21`:

* The count queried at TurboStack `ea6f8` really is the source **hardlink
  count**: its file-interface slot `+60` resolves through WCP's CFile vtable
  `3024c0` to `QueryLinkCount` at `112610`. A successful disposition of 1
  and count strictly greater than 100 chooses transfer operation 1 (copy);
  otherwise the operation is 3 (hardlink with copy fallback). Do not turn
  this into a >=100 boundary or a cap on the number of matching manifests.
* The storage-kind array is at **`1c6f50`**, computed from `ea47a`'s
  RIP-relative operand, not at `1b5150`. Its two DWORDs are `8, 2`. The loop
  ignores a kind already present in the output flags (`ea49a..ea4a3`).
* The first, uncompressed-preferred pass also preserves an already-existing
  destination: `ea1d7..ea22a` tests the pass Boolean, output bit 8, and
  `FileExists`; `ea2c4` calls `ManuallyMarkFileStaged` and sets output bit 8.
  This is not permission to replace all old paths with new objects merely
  because their logical bytes compare equal.
* The `TSCSSync` guard (`ea051..ea1bc`) can reject a different source
  component with a negative status in the shared component-status set.
  It is separate from the digest and compressed-source tests.
* A tempting interpretation of WCP AddComponentFile `13d2c3` is WRONG:
  the Boolean at `[rsp+61]` is populated by **IsIdentityDriver** at `13c567`,
  gated by input flag 1 and raw-layout byte `+2d`. It is not the LZMS
  Boolean. Its true branch calls the SIL `DecompressFile` slot `+78`
  (`3033b0+78 -> 227420`) with flags 5 and the manifest hash. The false
  branch calls SIL TransferFile at `13d51d` with flags `200005` and the
  selected operation. This alone does not establish how normal compressed
  component files later become expanded or lose/share object identity.

Previous-component selection is feature-dependent:

* CreateComponentFileListAsyncNew calls `SortedComponents::GetAll` at
  `d6d00` or `d6e08` to obtain the family candidates. With
  `Servicing_MFLUseWinnerAndHighestStagedVersion` enabled it calls
  `FindEligiblePreviousComponentsForFileMatchingAsync` at `d6d60`; otherwise
  it calls `FindAllPreviousComponentsAsync` at `d6e52`. The surrounding
  `Servicing_MFL_Resolved_Package_Fix` feature selects another enclosing path.
* FindEligible's `dd338..dd4cd` picks ONE candidate: matching the supplied
  identity's version first, otherwise an explicitly supplied fallback when
  enabled, otherwise the highest eligible version. In explicit-fallback
  mode the highest-version accumulator is NOT populated; a missing explicit
  version is not license to fall back to the highest one. Eligibility
  requires DerivedData existence and either no CF value or `(CF & 0x41)==0`.
* It parses the selected manifest at `dd729` and appends a single component
  to the output vector only when parsing returns an object and disposition
  bit 4 is absent (`dd72f..dd770`). The vector result does not imply that all
  eligible versions were returned. The caller-supplied identity/fallback
  semantic roles and actual feature configuration still need establishing.
* The feature wrapper at `10a94c` reads state through `df5d8/e100c`, not a
  constant true/false return. `e100c` queries feature `03c6e62f` and includes
  an additional feature-state call using `03a522fa` at `e111c`. Do not infer
  active configuration solely from the feature name or the DLL version.

The equal-hash branch of FileInstaller CommitFileChanges requires care:
`11d6f4` (`IsExternalStoreServicing`) returns true for coordinator flags
`8000` or `80`; `1451f9..145205` gates the earlier source-transfer block on
that result. `NeededInOldWinSxS` (`284ae8`) requires a source path at `+58`
and either path-element bit `+94 & 40` or source byte `+113 == 0`.
These field offsets are observations, not yet a complete ordinary-offline
source-object reuse policy.

A read-only baseline control confirms that the mutable dssec counterexample
was not introduced by the constructed base: native baseline amd64 dssec
9278 store file is DCS (9,486 bytes, hardlink ID 0), while System32/dssec.dat
is expanded (215,943 bytes, hardlink ID 0). After native servicing, both
9278 and 9549 store files are expanded (215,943 bytes each), each still
hardlink ID 0. Thus this control really requires accounting for both old
storage expansion and independent new object identity; a logical-byte
union is incorrect. Reference observations remain audit-only inputs.


### Ordinary payload regeneration versus external-store commit

The other `DecompressComponentFile` caller at `28384a` is NOT an independent
ordinary-source path: CFileInstallerHierarchy::CommitChanges (`28300c`)
caches IsExternalStoreServicing in BL at `28305e..283067` and gates its
unprojected-source loop on BL at `283610`. Both previously inspected
FileInstaller decompression loops therefore need external-store applicability.

For this WCP build, ordinary AnalyzePrimitiveInstallers `1c7c6c` calls
PerformPrimitiveInstallation `14dc34` at `1c7e15`. Primitive flag mapping at
`14de3e..14de86` supplies coordinator `4,8,10,100,80,400,1000` from input
`1,2,4,20,10,40,80`. Initialize `144770` sets its input flags at `14480a`,
ORs configuration extras (including raw SmiHiveUpdates at `14495a..144960`),
and does not directly introduce `8000` in the inspected initialization.
Its repeated R15D contribution is **4000**, not 8000 (`1447fd`). This does
not by itself establish the pinned configuration values.

The ordinary materialization path to inspect instead is the support callback
**EnsureComponentFullyPresent**, vtable `311cb8+50 -> 107ce0`. It skips work
for raw-layout MobileStore byte `+2c`, otherwise calls raw-layout
EnsureComponentFullyPresent `107d20`. That routine queries component
properties and CF, initializes LocalAutoLZMSDecoder, and invokes
**RecursivelyRegenerateComponentPayload** `1c5ec8` at `108041`.
The complete regeneration body ends at `1c72b4`:

* file marker check at `1c6391`, compressed-file type at `1c64e3`;
* temporary name `1c6516`, temporary file creation `1c65c3`;
* original catalog hint read `1c66a1`, LZMS decompression type 5 at `1c670d`;
* hint restored to expanded file `1c68a3`, WOF policy `1c6924`;
* component/file markers adjusted at `1c6d4a/1c6d72` and `1c71ec/1c721c`;
* final publication delegated to lambda `1c01bc` at `1c707a`.

These are locations for establishing the remaining source materialization
policy, not proof of a guessed hardlink-preservation rule. The order of
EnsureComponentFullyPresent relative to previous-file prestaging is still
material: expanding old storage before vs after sharing produces different
objects. Resolve the callback's callers and lambda publication semantics
before asserting the mutable/immutable final topology rule.
