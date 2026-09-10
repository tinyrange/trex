# Windows 11 Dependency Mini Repository

This package currently implements the ARI8 **container, dependency graph,
package identity, SECU, TPLT, JHN8, ALTP, ALTF, PKMP, APPS, RESP, and RESA
sections**, not a complete package registration writer.
Other sections and recipe integration remain
required before a `.pckgdep` can be used as Windows startup metadata. An envelope
round trip does not prove a valid package graph or a successful boot.

The wire contract below was established from matching Microsoft binaries and
public symbols in Windows 11 26100, using the native PE/PDB readers. Addresses
are RVAs, not portable identifiers for other Windows generations:

- `kernelbase.pdb`: GUID `72CCE506-944D-E026-7C17-2AD64287F9BD`, image age 1.
- `AppxDeploymentExtensions.OneCore.pdb`: GUID
  `A374DEC1-9416-774E-0C98-DBAF93D6D608`, DBI/image age 1 (Info age 2).

## Container

All integers are little endian. The deployment writer `Writer::Serialize`
(`379fc`, particularly `37aa4..37b0c`) writes:

| File offset | Field |
| --- | --- |
| 0 | `ARI8` |
| 4 | zero u32 |
| 8 | total file size, u32 |
| 12 | zero u32 |
| 16 | `TOC8` |
| 20 | TOC size: `12 + 8 * count`, u32 |
| 24 | section count, u32 |
| 28 | entries: tag u32, **file-relative** offset u32 |

Sections follow in entry order. Offsets are four-byte aligned. A section's
accessible extent ends at the following section's offset, or at the total file
size for the last section. Tags are not necessarily unique: Attach counts
multiple `RESP` and `RESA` resource records (`7fb4..8032`).

Consumer checks: `_HEADER::Verify` (`7234`) accepts a total extent between 16 and
1 GiB; `_TOC::Verify` (`71a8`) constrains the count to 1..8192. The Go reader
additionally checks every extent, rejects overlaps, and requires the writer's
reserved zeros and an exact total extent. It does not claim to accept every
envelope variation accepted by Microsoft's shallow verifiers.

## Dependency graph contract established so far

`DependencyGraph::Serialize` (`89620`) writes `DEPG`, u32 serialized size, zero
u32, u32 node count, then variable-sized nodes. The consumer's `GetNode`
(`3c510`) advances by each node's u32 size rounded up to four bytes.
`_DEPENDENCY_GRAPH::Verify` (`fb260`) permits 1..641 nodes.

`DependencyGraphNode::Serialize` (`7d610`) writes:

| Node offset | Field |
| --- | --- |
| 0 | node size before alignment, u32 |
| 4 | installation path byte length, u16 |
| 6 | optional extension offset, u16; zero if absent |
| 8 | package identity |

The identity has a 32-byte header: u32 size, u32 flags, u64 version, u32
architecture, u16 name bytes, u16 publisher-ID bytes, u32 publisher bytes,
u16 resource-ID bytes, u16 full-name bytes. Strings follow in that order.
The installation path starts immediately after the identity's declared size.
The writer zeros padding between the node's declared and aligned sizes.

Identity field meanings are corroborated by KernelBase `ConvertToPackageId`
(`5c6c`), `ConvertToPackageInfo` (`34320`), and `GetFullName` (`3dad0`). The
optional node extension's semantics, graph flags, and required companion
sections must be established before constructing package graphs. Do not fill
unknown fields with guesses or generate empty graphs to satisfy the envelope.

`Add_Dependency` (`32c8c`) stores nonempty strings with their terminating UTF-16
NUL and stores empty optional strings as absent/zero length. The identity codec
preserves that distinction and rejects embedded NULs and malformed UTF-16. The
publisher length's field is u32, but `DependencyGraphNode::Serialize` (`7d6aa`)
loads it through a u16; the codec therefore bounds all five strings to 65534
bytes including their terminators. Package naming policy is separate from the
binary record layout.

`GetActualSizeWithoutProperties` (`94610`) sums the identity and installation
path byte counts plus 40 bytes. `GetActualSize` (`8b8b0`) includes properties
only if object field `90` (the first property string's byte count) is nonzero:
it aligns the basic node to four bytes, then adds a 32-byte property header and
the four property strings. Node size is the unaligned total; serialized size is
rounded to four bytes. The codec preserves the two u64 property values as raw
wire fields and the four strings in order. KernelBase `GetPackageProperty`
(`151e90`, dispatch `151ff3..152024`, consumers `152057..15210d`) maps the four
strings to selectors 11..14. Subsequent producer evidence below identifies them
as DisplayName, PublisherDisplayName, Description and Logo. Their original
property strings remain distinct from the resource section's resolved blobs.

The property header contains u32 size, zero u32, two u64 values, and four u16
string byte lengths. Strings immediately follow in order. The optional property
offset in the node must fit u16 even when the complete node is larger. The Go
writer rejects an unrepresentable offset, rather than silently truncating it.
The graph codec preserves input order and repeated identities, requires 1..641
nodes, and validates every nested extent and padding byte. Graph resolution,
root selection, and actual property values remain recipe/construction inputs.

`GetPackageGraph` maps PackageRow::PackageType (offset54) to identity flags:
framework bit2 gives0x21; otherwise resource bit4 gives2; otherwise0
(328e8..32902, r14d=2 at32877). It adds0x10000 for PackageRow::Flags58 bit1,
0x20008 for PackageType bit20, and0x40000 for Flags58 bit80. The graph entry's
field48 equal8 additionally adds0x200000 (32931..32945). This is not the
ARI::Package framework flag0x11 used for SECU presence. PackageRow::Initialize
1ef69d..1ef6a4 confirms offset54 is PackageType; CopyFrom1ee1b5 supplies it
from Entity::Package54. DependencyGraphRow::Initialize1f1c3c (symbol signature
includes DependencyGraphType) writes its type argument to field48 at1f1ca9.

The root is **not** synthesized from a DependencyGraph row. The outer
RetrieveDependenciesAndAddSections9f668 reads ARI::Package38 flags at9f697
and passes them at caller stack40 (9f750) to its overload9f7a4. That overload
reads them at rbp77 (entry stack48) at9f89d and passes them unchanged at
caller stack38 to Add_Dependency32c8c at9f8d5. Only after adding this root
and its mutable-path record does it invoke GetPackageGraph32744 (9f944)
to append supplier nodes. Thus a framework root starts with flags0x11, whereas
the framework supplier mapping above starts at0x21. The per-dependency type8
modifier is not a prerequisite for constructing a dependency-free root.
The inspected WinUI manifest declares no PackageDependency entries.

The repository-row overload of `AddPackageToListForCommit` (`111144`) supplies
additional root flags. At `11116f..11118e`, main/framework/resource types start
at `10`/`11`/`12`; `111191..1111be` adds `10000` for Package.Flags bit 1,
`8` for PackageType bit `20`, and `40000` for Package.Flags bit `80`.
`1111c5..111230` adds `40 << PackageOrigin` for origins 0..6. Origin 7 adds
`2000` only under a feature check; that target feature decision is not yet a
recipe input. `PackageRow::Initialize` (`1ef77a..1ef781`) stores PackageOrigin
at `c4`, after SignatureOrigin at `c0` and before SupportedUsers at `bc`.
The combined flags pass through caller stack `40` at `1113d1` to
`AddPackageToListForCommit348d0`; they are not the raw StateRepository flags.
In particular dependencyTarget bit `80000` is not copied into the DMR root.
An origin-2 ordinary framework root is `111`, not the incomplete `11` base;
the corresponding main-package root is `110`. The recipe regression checks
the serialized framework node and the main/resource/origin projections.

After graph collection, this overload adds ALTP (9f959), ALTF (9f971),
DEPG (9f989), TPLT (9f9ad), and PKMP (9f9c5), in that order. Path selection
inside the ALTP/ALTF builders still needs establishing separately; the order
alone does not supply their string values or prove all companion sections.

## Security context

`SecurityContext::Serialize` (`a15e0`) and the consumer `_SECURITY_CONTEXT::Verify`
(`9ebc`) agree on this layout:

| Section offset | Field |
| --- | --- |
| 0 | `SECU` |
| 4 | section size, u32 |
| 8 | flags, u32 |
| 12 | package SID byte length, u16 |
| 14 | capability SID count, u16 |
| 16 | combined capability SID byte length, u16 |
| 18 | zero u16 |
| 20 | package SID, then consecutive capability SIDs |

`SetCapabilities` (`37830`) creates each well-known SID and concatenates its
actual length, without fixed-size slots. The consumer bounds a SID to 68 bytes,
capability count to 128, and capability bytes to 8704. The Go codec additionally
validates each revision-1 SID and exact extent/count agreement. It accepts
binary SIDs; SID derivation and capability selection are not this codec's job.

`RetrieveSecurityContextAndAddSection` (`34b78`) omits the section when either
of the package flag bits `1` and `2` at package-object offset `38` is set. It
otherwise obtains the package SID, maps a package capability mask to well-known
SID types, and emits the section. Those package-type/mask mappings still need
to be connected to the recipe's actual manifest and repository records. Do not
emit this section universally or choose flags/capabilities to bypass checks.

The matched repository-row producer supplies the legacy `Capabilities` field
at row offset `b8` through caller stack `68` (`1113b1`) to ARI::Package offset
`100` (`36b96..36b9c`). `RetrieveSecurityContextAndAddSection` iterates exactly
ten entries of the table at `3098b0` (`34bbe..34bf1`): mask bits 0..9 map to
well-known SID types `85,86,87,91,88,89,90,93,92,94`, respectively. Their
capability RIDs are `1,2,3,7,4,5,6,9,8,10`, under `S-1-15-3`; see Microsoft's
[capability SID assignments](https://devblogs.microsoft.com/oldnewthing/20220503-00/?p=106557).
The producer does not turn the remaining manifest capability names into extra
SECU entries. Higher mask bits have no entries in this table.

Row `IsInbox` at `50` is passed at caller stack `c8` (`11127d`, `111340`),
forwarded by `348d0` at `3498e..34995` and by `35ae8` at `35cef..35cf6`,
and stored at ARI::Package `104` (`36ba2..36ba8`). The security builder tests
that byte at `34bf3`, normalizes it to 0/1 (`34c04`), and stores it as the
SECU flags value at `34c9d`. This is independent of the graph's origin bits.
`EncodeRepositorySecurity` implements this established mapping, retaining
the required caller-supplied package SID and native section omission rule.

## Required builder inputs still under investigation

`BuildDMR` (`96a1c`) invokes a lambda at `110d60` that retrieves security,
dependencies, applications, and MRT resources before adding a trailer. The
dependency builder at `9f7a4` adds the root dependency, its mutable path, the
package graph, alternate path sections, target platform, and mutable paths.
Some helper calls conditionally omit sections. A graph-only file has not been
established as equivalent to this builder's output.

## Target platform and trailer

`TargetPlatform::Serialize` (`8bec0`) writes a fixed 32-byte `TPLT` record:
signature at 0, eight reserved zero bytes at 4, u32 platform at 12, and u64
values at 16 and 24. **Offset 4 is not a size.** `GetActualSize` (`9ae20`)
returns 32. KernelBase `GetPackageTargetPlatformProperty` (`f7f50`) exposes
offsets 12, 16, and 24 as selectors 1, 2, and 3 respectively. The codec preserves
those fields without inferring version policy or choosing a host-dependent
platform. `AddSection_TargetPlatform` (`33f48`) forwards its input platform and
two u64 values directly to the serialized fields.

`Trailer::Serialize` (`116f20`) writes the eight bytes `JHN8` followed by four
zeros. `GetActualSize` (`cd810`) returns 8, and `GetSignature` (`cd860`) returns
`JHN8`. There is no timestamp or checksum in this marker.

## Alternate paths

`AddSection_AlternatePath` (`111428`) clones one terminated UTF-16 string via
`ISection::StringClone` (`376e0`), not a multi-SZ array. The higher-level builder
(`f300`) concatenates paths using a semicolon (literal at `2574f8`). The codec
preserves this string without splitting or applying host path normalization.

`AlternatePath::Serialize` (`116c80`) emits `ALTP`, u32 actual size, then the
string bytes; the actual size excludes trailing four-byte alignment padding.
`AlternatePathForFirstPackageFamily::Serialize` (`116d40`) emits `ALTF`, u32
actual size, zero u32, u32 string byte length, then the string bytes. The builder
at `111504` explicitly initializes that reserved word to zero. Both serializers
zero their alignment padding, and StringClone represents empty strings with
zero payload bytes. Nonempty strings include exactly one terminating NUL.

For a dependency-free framework root (flags11), both builders consider its
loader path: low-three flag bits equal1 is explicitly accepted (f91b..f921,
8f3a5..8f3ab). CalculateLoaderSearchPath22018 queries PackageExtension category
`windows.loaderSearchPathOverride` (literal25a0a0). If absent,22417..2242a
appends the external path when nonempty, otherwise the installed/mutable path
supplied in r8. The WinUI manifest has only two in-process activation extensions,
no loader override. Its unmodified installed path is therefore the loader path.

ALTP appends each distinct token followed by a semicolon (f652..f756); f4c0
omits the section if the accumulated string is empty. ALTF does not simply
duplicate ALTP: it emits only upon encountering a different family after the
first (8f36e/8f53e..8f545). Finishing an all-one-family graph goes directly
from8f332 to cleanup8f62d without adding ALTF. Thus the single WinUI root has
ALTP `installed-path;` and no ALTF section.

BuildDMR's body110d60 orders security, dependencies, applications, resources,
and trailer. RetrieveApplicationsAndAddSection1b6d8..1b6e6 skips both low ARI
flag bits, returning success at1bba0, so the framework has neither APPS nor SECU.
The guarded Starlark `appx_framework_dependency_file` assembles an unmodified,
dependency-free framework with pre-resolved resource references as ALTP, DEPG,
TPLT, PKMP, RESP, JHN8. Tests check root flags11, Name rather than row ID,
terminal semicolon, retained empty PKMP entry, and omitted companion sections.
It rejects supplier dependencies, non-frameworks, applications, unsupported
extensions, and mutable/external paths. `appx_literal_framework_resources`
supports literal string properties and the verified PRI missing-file-name
fallback: it requires one parsed schema with a Files subtree, rejects a
matching logo resource pending candidate resolution, and requires the actual
logo file. Missing PRI, resource-valued properties and escaping paths fail.
The Windows11 recipe now uses these helpers for Microsoft.UI.Xaml.CBS and
installs the result under each initial user's Packages/FullName/SID.pckgdep.
Other packages still require their complete metadata; this is not yet a
successful fresh-image smoke proof.

Consumer verifiers `7148` and `78dc` bound payloads to 65536 UTF-16 code units.
The Go reader additionally requires exact declared extents, correct ALTF
payload length, reserved zeros, valid UTF-16, and zero alignment padding.

## Mutable paths

`PackageMutablePaths::Serialize` (`8bfc0`) writes `PKMP`, u32 section size,
zero u32, u32 entry count, then ordered variable-sized records. Each record is
a u32 actual size followed by one optional terminated UTF-16 path string;
the record is padded to a four-byte boundary with zeros. Empty paths still
occupy a four-byte record. `PackageMutablePath::GetActualSize` (`94280`)
returns four plus its string byte count, and its serializer (`a1d30`) writes
that actual size before the payload and zeros the alignment padding.

KernelBase Attach (`8597`) accepts 1..641 entries. Its graph conversion loop
(`34061..340ae`) advances the graph node and mutable-path record together,
each by its aligned size. Empty entries and repeated paths therefore must not
be filtered out. The codec preserves order and validates every record, but the
caller must still supply the paths corresponding to the resolved graph nodes.

## Application records

`Applications::Serialize` (`a0080`) writes `APPS`, u32 section size, zero u32,
u32 count, and aligned application records. KernelBase Attach (`8886..88a9`)
requires 1..100 entries. Packages without applications must not get a synthetic
empty APPS record merely to make a uniform section list.

`Application::Serialize` (`9cc70`) writes the following 36-byte record header:

| Offset | Field |
| --- | --- |
| 0 | u32 actual size, excluding four-byte alignment padding |
| 4 | zero u16 |
| 6, 7 | two separate byte-valued fields |
| 8 | u16 first-string byte length |
| 10 | u16 scalar (not a separately appended string length) |
| 12, 14, 16, 18 | four u16 string byte lengths |
| 20, 24 | two u32 scalar fields |
| 28 | u16 sixth-string byte length |
| 30 | u16 content-URI rule count |
| 32 | u32 content-URI payload byte length |

The six strings follow in length-field order (8, 12, 14, 16, 18, 28), then
the content-URI payload. `GetActualSize` (`9a3c0`) sums exactly those payloads
plus 36. The writer zeros alignment padding. The binary codec preserves the
wire fields; `ApplicationFromRepository` supplies the established mapping below.

The `RetrieveApplicationsAndAddSection` callback at `110b18` calls
`Add_Application66730` at `110ce8`. `Application::FindByPackage23394` selects
the named repository columns, and `RowToObject1c7dc` establishes their entity
offsets. The callback maps them as follows:

| Wire string length offset | Repository/source value | Entity offset |
| --- | --- | --- |
| 8 | Resolved ApplicationUserModelId (family + `!` + PackageRelativeApplicationId) | generated from relative ID at `30` |
| 12 | DisplayName | `50` |
| 14 | Description | `60` |
| 16 | Square150x150Logo | `70` |
| 18 | Square44x44Logo | `80` |
| 28 | StartPage | `110` |

These remain original strings, distinct from the separate resolved RESA
references. BackgroundColor at entity `d0` passes through caller stack `40`
(`110cd0`) to object `6c` (`66c38`) and wire offset 24 (`9cd12`). ForegroundText
comes from entity `c0`, caller stack `38` (`110cd4`).

Header offset 10 is the UTF-16 **byte offset** immediately after the first
`!` in the resolved AUMID: `66d84` calls `wcschr` for `!`, `66d98..66dac`
computes the offset, and `9ccdd` stores its low u16. Header byte 7 is the
normalized legacy package Capabilities bit `80` (`110bd4..110bdf`, `66d81`,
`9ccce`), not an application flags field. Header byte 6 is a separately
supplied source-pass flag (`110caa`, `66c87`, `9cd2d`): the first/root package
pass initializes it to 0 (`1b6ee`); the subsequent related-package pass sets
it to 1 (`1b963`). The codec preserves that explicit input without deciding
which related packages to enumerate.

`windows.dmr_applications` exposes this mapping, including structured content
URI rules, and `windows.dmr_package_security` exposes the repository security
mapping. Neither API selects dependency graphs or replaces required RESA or
other extension sections.

`SetForegroundText` (`66f48`) establishes that header offset 20 is a numeric
foreground-text choice: absent/empty input maps to 0, `light` to 1, `dark` to 2;
other nonempty inputs fail. The matching literals are at `260568` and `2759d8`.
This semantic is exposed as ForegroundText rather than an unnamed scalar.
The comparison uses `wcscmp` (`22db10`), so casing is significant.

`SetContentUriRules` (`d8690`, called from `Add_Application` at `66c65`) takes
a rule count, a UTF-16 code-unit count, and a buffer. With nonzero rule count it
copies exactly twice the code-unit count in bytes; it does **not** measure the
buffer using StringClone or stop at its first NUL. Zero rules clear the payload.
The serializer at `9cd20` narrows that payload byte length through u16 before
writing its u32 field. Any implementation must bound that length, not silently
truncate it, and must preserve the rules' internal structure. Treating it as
another ordinary terminated string would lose data.

`RetrieveContentUris` (`256d8..25eb0`) selects repository rules ordered by
`Index`. Its SQL explicitly selects Uri, Type, WindowsRuntimeAccess and Flags
after the identity/index fields. The rule grammar, now implemented separately,
is `[s][a|w](+|-)URI\0` in UTF-16. Bit 0 of Flags emits `s` (`258c8`, `25d51`);
access enum 0 emits nothing, 1 emits `a`, 2 emits `w` (`258af..258c2`, `25dea`).
Type zero emits `-`, nonzero emits `+` (`2589f..258a9`, `25b60`). The URI is
appended, followed by one NUL (`25985`, `259d6`); rules are concatenated with
no extra final NUL. The codec preserves that order, checks the separately
declared count, rejects malformed UTF-16/embedded URI NULs, and bounds the
combined payload to 65534 bytes. It neither normalizes URIs nor evaluates access
policy. The semantic name of Flags bit 0 is not assumed.

## Main-package recipe integration

`appx_main_dependency_resources` resolves the serviced single-schema/map PRI
before `appx_main_dependency_file` assembles the main root's ALTP, DEPG, TPLT,
PKMP, SECU, APPS, RESP, per-application GLOB/RESA, and JHN8 sections. It batches
candidate-count validation and rejects resources needing sole-candidate
reduction. The main and framework builders retain different section-presence
rules. The Windows 11 recipe invokes the main builder for Client.Core and
retains the framework builder for Microsoft.UI.Xaml.CBS.

Client.Core's LogonWebHost declares one include rule for
`https://login.microsoftonline.com/`, with no WindowsRuntimeAccess or flags.
The target Windows.StateRepository.dll's ApplicationContentUriRule SQL has
`WindowsRuntimeAccess INTEGER NOT NULL DEFAULT 0` and `Flags INTEGER NOT NULL
DEFAULT 0`. The recipe projects omitted fields to those schema defaults and
preserves declared rule order. This is schema-backed construction policy,
not a claim that the unavailable native deployment producer was compared.
The observed explicit `none` and `all` access declarations project to 0 and 1
(no prefix and native `a` prefix). Other explicit access/flag declarations are
rejected until their manifest mapping is implemented. Namespace declarations
are not semantic rule attributes. The main DMR builder rejects rules missing from the
repository records rather than silently generating an empty APPS rule list.

Construction tests cover the main section set, root flags, unconditional
zero-flag GLOB, content-rule records, and rejection of missing prerequisites.
They do not substitute for the fresh whole-image smoke or actual PRI parsing.

Direct hash-checked servicing-input validation on Client.Core produced a
33,644-byte DMR with 76 sections and 34 applications. The actual 8,536,200-byte
PRI has SHA-256 `e9028d0636096f01c4e6e8a8ce4d80325ec43fbc747cc5a81a35643d90c2bc19`;
the native Go candidate API returns `[86,3,2,2,95,95,3,2]` for indexes
`[7334,8244,8245,8246,7329,7330,8096,8097]`, matching the independent format probe.
These are construction checks, not evidence that the shell smoke passes.

## Application globalization records

`SetUtf8AndLanguagePreference35df8` queries ApplicationProperty for
`ActiveCodePage` matching `UTF-8` and `LanguagePreference` matching
`WindowsDisplayLanguage`. It creates a `Globalization` section even when both
queries return false. Its string is the package-relative application ID supplied
by the APPS callback (`110bb1..110bbe`), not the full AUMID or an executable path.
`Serializea08e0` writes `GLOB`, unaligned actual size, flags, name byte length,
zero u32, then the terminated UTF-16 name at offset 20. Flag 1 selects UTF-8;
flag 2 selects Windows display language (`a0925..a093a`). `GetActualSize9e5a0`
adds 20 to the stored name byte count; the outer section aligns to four bytes.
`EncodeGlobalization`/`ParseGlobalization` and `windows.dmr_globalization`
implement that record, with empty IDs, malformed lengths and padding rejected.

The actual Client.Core manifest has no ActiveCodePage or LanguagePreference
declarations, so each of its 34 root applications needs a zero-flag GLOB record.
The separate `FindAndAddRedirectionDll7da00` queries ApplicationProperty name
`ImportRedirectionTable` (literal at `262890`); this property is also absent in
the actual Core manifest. This absence does not justify omitting GLOB, whose
producer has no corresponding section-presence condition.

## MRT resource records

`RetrieveMrtResourcesAndAddSections3401c` tests the root dependency node's flags
at `58` (`34074`). Either low bit skips the package RESP builder and supplies
a null root to `RetrieveMrtResourcesForApplicationsAndAddSections34804`, which
returns without adding RESA (`3482c..3482f`). Framework/resource roots therefore
omit both RESP and RESA. Earlier framework recipe construction unnecessarily
resolved and emitted RESP; it now omits those sections. The package-resource
codec and resolution evidence below remain applicable to main-package roots.

For a main root, `34846..34888` enumerates APPS in array order and passes the
zero-based application index to `RetrieveMrtResourcesForApplicationAndAddSection`
(`34d84`). It constructs four mandatory entries, plus StartPage when the
application's stored StartPage pointer is non-null:

| ID | Type | Source application property | Native record assignment |
| --- | --- | --- | --- |
| 1 | 0 | DisplayName | `34eed` |
| 3 | 0 | Description | `34fec` |
| 4 | 1 | Square150x150Logo | `350ce` |
| 5 | 1 | Square44x44Logo | `351f8` |
| 6 | 1 | StartPage, optional | `3533b` |

The first two use the string reference API; the remaining entries pass file
value type 2 to `GetInternalReferenceBlobForManifestValue`. This includes
StartPage: do not replace it with a string literal simply because it resembles
a URL. `35342..3534a` chooses count 5 or 4; `353dc` preserves the APPS index
in the RESA header. Required empty strings need valid empty references rather
than missing records. `EncodeApplicationResources` and
`windows.dmr_application_resources` implement this mapping for already-resolved
literal/index references; they do not guess PRI candidate selection.

`MrtResources::Serialize` (`8d080`) writes a 16-byte header: signature, u32
section size, u16 index, u16 entry count, and zero u32. Subclass signatures are
`RESP` for package resources (`d9b70`) and `RESA` for application resources
(`114780`). KernelBase Attach (`830d..83a7`, `877e..87fc`) bounds the index to
0..640 and count to 1..1024; it permits multiple resource sections per file.

`NamedResource::Serialize` (`8a390`) writes a u32 actual record size, two u16
values, a u16 payload byte count, zero u16, and exactly that many payload bytes.
Each record is rounded to four bytes with zero padding. These two values and
the payload's higher-level meaning still need corroboration from the resource
resolver. The binary codec preserves them without assuming text, a terminator,
or alignment inside the payload. It checks every extent/padding byte and retains
entry order. This does not implement resource selection or resolve PRI values.

### Resource payload producer

The matching `MrmCoreR.pdb` has GUID `61B29674-3E81-67A3-127B-98CCB074D3F3`,
DBI/image age 1. OneCore's package-resource builder (`34118..3460c`) imports
`GetInternalReferenceBlobForManifestValue` from MrmCoreR. It stores the resulting
**reference blob**, not an ordinary resolved display string, as resource data.

MrmCoreR dispatches string/file values at `52a90` to
`GetInternalReferenceBlobForManifestString` (`52b88`) or the file variant
(`52e20`). The string path calls `IsMrtUriReference` (`534b4`). A non-reference
string uses `ReferenceBuilder::GetLiteralBlob` (`37e60`); an MRT reference finds
the default PRI and calls `GetInternalReferenceBlobForResource` (`38a1c`).
These paths must remain distinct; literal encoding is not a substitute for
handling `ms-resource` references.

The literal builder measures a terminated UTF-16 string (including an empty
string's NUL), passes flags `0x100` to `BuildReferenceBlob` (`37e9c`), and supplies
the exact payload byte count. The observed blob header is four u16 fields:
flags, total aligned size, zero, payload byte count. Payload begins at offset 8;
total size is `8 + align4(payloadBytes)`. The builder bounds total size to 8192
bytes. The literal codec validates UTF-16, exact extents and zero padding.

`ValidateReferenceBlob` (`353ac`) requires a kind bit in `0x700`, rejects flags
outside `0x703`, and for index references requires four bytes containing a
nonnegative signed 32-bit index. `GetInternalReferenceBlob` (`37cc0..37dd4`)
emits flags `0x400`, total size 12, zero u16, payload size 4, and the u32 index
from the named-resource result at offset `18`. This is a PRI index, not a URI
hash. Separate literal/index codecs reject each other's reference kind.

`TryGetOnlyValue` (`37dd4..37e60`) requires exactly one candidate, successfully
retrieves candidate zero and its qualifiers, requires `GetIsNeutralOrDefault`
(`73f5c`), and returns `TryGetStringValue` (`36338`). Only success reduces the
resource to a literal; otherwise the reference builder emits the index form.
PRI lookup and qualifier interpretation remain integration requirements. These
results are static matched-binary evidence and Go tests, not yet native execution
comparison or whole-image smoke validation.

The file-value path is different: `GetInternalReferenceBlobForManifestFile`
(`a2e94..a3054`) first looks up the name in subtree `Files` (literal at `e1638`).
Only HRESULTs `80073b17` and `80073b1f` select its fallback: append the file
name to the package path with `DefStringResult_ConcatPathElement` (`1c240`),
normalize slashes (`6f158`), then encode a literal. Other lookup errors are
propagated. The queue wrapper also has a no-PRI fallback, whose cold branch
still needs inspection; do not generalize either branch to string references.

The queue wrapper's early `52e69` call is `DefString_IsEmpty`, not a URI
classification: empty values encode an empty literal at `53022`. With a PRI,
nonempty values reach `a2e94` through `52fc2`. The Files lookup uses
`ResourceMapSubtree::GetResource` (`38988`), returning `80073b17` on a missing
name. Core's schema contains no HTTP names. Its HTTP StartPage values therefore
use the missing-file branch, not a special URL-literal branch.

`EncodeMissingFileResourceReference` and `windows.mrm_missing_file_reference`
implement only that established missing-name/map fallback. They trim backslashes
at the join, append one backslash to a nonempty head, and then replace forward
slashes. They deliberately do not clean dot components or interpret URLs.
This order also matches Microsoft's `DefStringResult_ConcatPathElement` in
[StringResultImpl.cpp](https://github.com/microsoft/WindowsAppSDK/blob/6b178e79e59d28efb10ef5c8c68b051d2615c3e6/dev/MRTCore/mrt/mrm/mrmmin/StringResultImpl.cpp#L812).
Callers must prove the missing-name/map result; empty values belong to the
wrapper's empty-literal branch. Tests cover URL-shaped values, separator order,
dot components, and malformed strings.

The actual WinUI CBS manifest has literal DisplayName, PublisherDisplayName,
Description and `logo.png`, with no declared PackageDependency. Its logo and
resources.pri both exist. This narrows the package's inputs, but does not prove
whether its Files/logo.png lookup selects an index or the native path fallback.

Subsequent native Go traversal of that package's hash-checked PRI decoded all
200 names and found no logo entry; see `../pri/FORMAT.md` for the input hash and
proof scope. Candidate/qualifier decoding is therefore not a prerequisite for
this particular logo's absent-name branch. Other packages' actual resource
references still require appropriate lookup and candidate handling.

`AddSection_MrtResourcesPackage` (`35524..3562c`) initializes the resource section
index to zero and passes zero explicitly to `AddSection_MrtResources`
(`365f0..3678c`); it does not preserve its nominal u16 argument. The latter
consumes 16-byte input entries: payload pointer at0, payload-byte count u16 at8,
two u16 fields at10/12. It copies those fields to NamedResource object offsets8/10
and copies exactly the stated number of payload bytes. The package builder
(`34118..3460c`) emits fields (1,0), (2,0), optional (3,0), and (4,1), sourcing
values from DependencyGraphNode offsets98, a8, b8 and c8 respectively. The first three
use the string-reference API and the last uses the file-reference API. Their
manifest-property names require independent corroboration before recipe mapping.

The resource builder's matching symbol signature takes a
`DependencyGraphNode const&`, **not** `ARI::Package const&`. The identical-looking
offsets in ARI::Package have different meanings; interpreting that object's
setters as evidence for these resource fields is invalid.

`GetPackageGraph` (`329b9..32a6f`) passes StateRepository::Entity::Package string
fields60/70/80/90 into Add_Dependency's four property-string arguments.
`Add_Dependency` copies them to graph-node98/a8/b8/c8 (`333dd`, `334c1`, `335a5`,
`33689`). Matching named setters corroborate entity field60 as DisplayName
(`16f320`), field70 as PublisherDisplayName (`16f420`), and field90 as Logo
(`16f388`). Thus resource IDs1/2/4 and graph properties11/12/14 map to those
names respectively.

`Package::BindAndExecuteForAddOrUpdate` loads entity offset80 at `16ebdc` and
binds parameter14 at `16ebe7..16ebec`. Its SQL at `292f70` names parameter14
Description (following DisplayName and PublisherDisplayName). This completes
the ID1..4 / property11..14 mapping: DisplayName, PublisherDisplayName,
Description, Logo. The same SQL/binder identifies entity a0/a8 as OSMinVersion
and OSMaxVersionTested (parameters16/17, `16ec26..16ec5b`). GetPackageGraph
passes those values to the graph-node80/88 slots, which the node serializer
writes at optional property-record offsets8/16 (`7d803..7d815`).

`EncodePackageResources` now builds the package RESP index0 from named,
already-resolved MRM references. Description nil omits ID3; an empty literal
blob is distinct and retained. DisplayName, PublisherDisplayName and Logo must
all contain valid references. Literal and index forms are supported; arbitrary
manifest strings and unsupported blob forms fail explicitly. This assembler
does not itself classify URIs, resolve PRI resources, or construct the complete
package graph. Focused tests cover IDs/types/order, optional Description, mixed
reference kinds, and invalid inputs.

The Starlark construction primitives are `windows.mrm_literal_reference(value)`,
`windows.mrm_index_reference(index)`, and
`windows.dmr_package_resources(display_name, publisher_display_name, logo,
description=None)`. References and the resulting section are in-memory file
values. The assembler checks each reference's size before reading and preserves
None versus an explicitly supplied empty/invalid reference. These functions do
not choose between literal/index branches or resolve manifest values themselves.

Target-platform version order is also corroborated: the dependency builder
(`9f877..9f88a`, `9f99e..9f9ad`) passes the same minimum/tested versions used in
the root node properties. `AddSection_TargetPlatform` (`33f75`, `33f9b..33f9f`)
stores those arguments in reversed internal object slots, and its serializer
(`8befe..8bf0a`) reverses them again. The final TPLT u64 fields at16/24 are
OSMinVersion/OSMaxVersionTested respectively. Platform ID semantics are not
established by that version mapping.

The repository-load path establishes that the platform identifier is the
related TargetDeviceFamily's **Name enum**, not the database relationship ID.
`OSIntegration::Package::InitializePackageFromRepository` (`1a628..1a62f`)
copies **PackageRepository::PackageRow** fieldb0 to OSIntegration::Package1b0.
This is not Entity::Package, despite the same field offset. The interface call
at1a08b uses PackageTable vtable24ebd0+80, GetPackageRow1ef3b0, then
TryGetPackageRow1efba0/1efad0, RetrieveRow1ef7c0 and CopyFrom1edf50.
CopyFrom reads Entity::Packageb0 as a database ID (1ee074), gets the related
TargetDeviceFamily (1ee0b6), and sign-extends its Name at object24 (1ee13d).
It passes Name at caller stackb0 (1ee16e) to PackageRow::Initialize1ef50c,
which copies callee stackf0 to PackageRowb0 (1ef744..1ef74c).
The commit path (`a3041`, `a2f00..a31c0`) then passes it through ARI::Package98
to the dependency builder and TPLT. Earlier same-offset Entity::Package
reasoning omitted this conversion and was invalidated by the complete chain.
`windows.dmr_target_platform(target_device_family_name, minimum_version,
maximum_version_tested)` accepts the Name enum, including native unknown -1
(wireffffffff), and rejects values outside -1..7fffffff.

`windows.dmr_graph(nodes)` exposes the ordered native DEPG encoder. Each node
dictionary supplies name, publisher_id, publisher, full_name, packed version,
architecture, ARI flags, installation_path, optional resource_id and properties.
Optional properties name minimum_version, maximum_version_tested, display_name,
publisher_display_name, description and logo. DisplayName must be nonempty when
the optional record is supplied, matching the record-presence rule. The wrapper
does not choose dependencies, derive ARI flags, or resolve property strings;
those must be established by construction. Focused frontend tests verify field
mapping, preservation of an original ms-resource property, and input rejection.

The remaining envelope primitives are exposed as
`windows.dmr_alternate_path(value, first_package_family=False)`,
`windows.dmr_mutable_paths(paths)`, `windows.dmr_trailer()`, and
`windows.dmr_container(sections, max_bytes=67108864)`. The container accepts
ordered section files, derives TOC tags from their first four bytes, checks
count/alignment and the aggregate byte bound before reading, and preserves
section order and duplicates. It does not supply or validate semantic required
sections. The mutable-path API preserves empty entries. Tests cover decoding
the assembled records, exact byte-limit boundaries, and malformed inputs.

The current Windows.StateRepository.dll schema confirms TargetDeviceFamily is
package-scoped: `_TargetDeviceFamilyID`, revision/work identity, `Package`,
`Index`, numeric `Name`, `MinVersion`, `MaxVersion`, and optional dictionary.
Package references the selected target-family row; its Name enum is a separate
field, not a shared family row assigned by string.

AppXDeploymentServer.dll (CodeView GUID
00066AAD-B9BD-E9C5-E4AB-16839B07F348, age1) supplies the manifest-name mapping
at RVA422a50: 17 entries of a UTF16 string pointer and a u32 value, stride16.
Reader a5d33..a5d72 scans all entries with imported `_o__wcsicmp`, stores the
matched value at TargetDeviceFamily object offset24, and stores -1 for an
unrecognized name. Manifest getters at vtable18/20/28 provide Name/MinVersion/
MaxVersionTested; versions are written to object28/30. The matched OneCore
TargetDeviceFamily::RowToObject independently reads Index/Name/MinVersion into
object20/24/28 (182f73..182fb9).

The table is Universal=0, Platform.All=0, Windows8x=1, Desktop=3, Mobile=4,
Xbox=5, Team=6, IoT=7, IoTHeadless=8, DesktopServer=9, Holographic=10,
XboxSRA=11, XboxERA=12, Server=13, 8828080=14, 7067329=15, Core=16;
all names except Platform.All have the `Windows.` prefix. No value2 entry.
The desktop recipe now constructs per-package family entities, selects its
desktop constraint before the universal fallback, links Package to that row,
and projects the row's Name (not its identity) into the registry cache.
Focused tests distinguish row5 from Name3 and reject foreign/missing links.

The deployment insertion loop at11a24c..11a278 walks the manifest vector from
index0, assigns Package to object18 and the vector ordinal to object20, then
calls11b178 ->33c698 to insert. Its SQL at4c3970 has Package/Index/Name as
parameters3/4/5. Thus Index is a zero-based manifest ordinal, not a row ID or
family enum. At11a299..11a2a2 the selected row's identity is passed to32d614
(`UPDATE Package SET TargetDeviceFamily=? WHERE _PackageID=? ...`, SQL4a2b70).
The following11a2b4..11a2b8 replaces the in-memory package fieldb0 with the
selected Name, independently corroborating the database/runtime distinction.

### Security-section presence for framework packages

`CollectorPackageInformation::GetIsFramework` (`9d5a0..9d5ae`) reads bit1 of
OSIntegration::Package field18c. `AddPackageToListForCommit`
(`a2f2a..a2f3a`) maps that bit to ARI package flags `0x11` (rather than ordinary
`0x10`). `RetrieveSecurityContextAndAddSection` (`34b9d..34bb1`) returns without
adding SECU when either low ARI flag bit is set. Thus the actual WinUI framework
package requires no SECU section. This is omission, not an empty section or a
fabricated security context.

`EncodePackageSecurity` applies this presence rule to explicit ARI flags and
requires an explicitly constructed SecurityContext for other packages. It
returns nil for an omitted section and delegates present-section validation
to the native codec. Tests cover framework/other low-bit flags, required-context
errors and propagation of invalid SID errors. StateRepository flags and package
type values must not be passed as if they were ARI flags.

The producer's legacy capability-mask table at `3098b0` has ten ordered pairs
of mask bit and WELL_KNOWN_SID_TYPE number:
`1:85, 2:86, 4:87, 8:91, 16:88, 32:89, 64:90, 128:93, 256:92, 512:94`.
Those bytes are established; mapping arbitrary modern manifest capabilities to
this legacy mask is not implied by the table and remains separate work.

## Repository filename

KernelBase `BuildFilenameForPackage` (`70b4`, `2d6b4`, `9fe4`) uses the registry
`Appx\PackageRepositoryRoot`, appends `\Packages\<PackageFullName>`, then
`\<UserSID>.pckgdep`. This filename is guest metadata; it is not a host path or
an instruction to write intermediate files.
