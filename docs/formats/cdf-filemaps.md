# CSI compiled data containers

Observed from native Windows 11 26300.9457 image 6 FileMaps and matching WCP
26100.9441 code. This describes container construction, not a complete servicing
transaction or authenticated update state.

Version-one containers begin with an 84-byte header, magic `PcmH`, version at
4, flags at 8 (native initialization rejects bits outside 3), and an eight-byte
noncryptographic IHA8 checksum at 12. Compute it with bytes 12..19 zeroed:
consume little-endian uint32 words, then individual trailing bytes, accumulating
`h = h * (2^33 - 9) + value` modulo 2^64. Native `RtlIHA8HashLBlob` is at
RVA `0xcdbcc`; the validator is at `0xfd0c`.

Count/offset pairs are blobs at 20/24 (eight bytes per entry), strings at 28/32
(four-byte blob IDs), GUIDs at 36/40 (16-byte inline GUIDs), identities at 44/48
(four-byte blob IDs), and appids at 52/56 (four-byte blob IDs). Root and auxiliary
root blob IDs are at 60 and 64; `0xffffffff` means absent. The format GUID occupies
68..83. A blob-directory entry packs an eight-bit kind above a 24-bit payload
length, followed by its absolute uint32 payload offset. Payloads can share
extents, notably an empty string at another string's start. Native output aligns
payload allocations to four bytes; that padding is not part of the blob length.

`windows/cdf` validates framing, checksum, bounded extents and outer references.
It preserves opaque kinds and payloads. Serialization preserves IDs and indexes,
not physical ordering/padding/shared extents. Nested table and ownership semantics
are separate. The Starlark `windows.cdf_decode`/`cdf_encode` pair exposes this
representation without host intermediates or filesystem mutation.

All 3,776 resident maps parse and round-trip logically through this implementation;
the largest is 772,752 bytes. Observed blob kinds/counts: 1/34,950, 2/86,919,
4/15,532, 6/3,776, 9/3,776. A portable reserialization of the root map is accepted
by native initialization (zero return, valid=true, 1,131 instructions). The same
validator accepts the 553-byte root-map prefix omitting only its final three
zero padding bytes; the checksum happens to agree because the final dot can be
consumed as either a word with zero high bytes or a single trailing byte.

FileMap table observation: all resident kind-6 table header low bytes are 1,
and kind-9 table header low bytes are 0. Do not generalize that to arbitrary CDF
consumers. The complete WindowsMigration transaction rewrites ancestor maps,
including logical data changes: the root-map string index 1 changes from empty
to `\??\C:` and its path-metadata root selector changes from 2 to 0. A mere
checksum patch or payload deletion does not reproduce this transaction.


## Resolved no-hash FileMap schema

The portable reader/writer also supports the observed FileMap format GUID
`28351bff-d525-4155-acb0-6e7c64c725d8` with no auxiliary root. The kind-9 TOC
has two integer keys: 0 points to the kind-6 file table; 1 points to an eight-byte
kind-1 pair `(path string ID, root selector)`. Observed selectors are 0, 1 and 2;
normalizing a path is caller policy, not automatic serialization behavior.

A supported kind-6 table starts with `(count << 8) | 1`, followed by count
uint32 hashes, count string IDs, and count blob IDs. Kind-9 tables use low byte
zero and omit hashes. Compact key/value forms are not guessed. The string-table
hash is the low 32 bits of the four-lane X65599 CSI text hash with native
`FsnpDowncaseChar`; the shared implementation deliberately bounds lookup keys
to ASCII rather than approximating Windows Unicode folding. All 31,152 resident
lookup keys match the hash and array layout. There are 48 adjacent hash collisions,
including `cmd.exe`/`dwm.exe`; the native comparator at RVA `0x911f0` compares
only unsigned hash values. Preserve distinct equal-hash keys and do not use a
hash-to-single-record dictionary or invent a lexical tie-breaking requirement.

Each observed file-record blob is kind 1, 28 bytes: flags, display-name string ID,
two zero uint32 fields, two `0xffffffff` fields, and an identity-index ID. Native
hash-array-bearing records are not implemented. Resident flags are 0 (29,692
records), 2 (255), and 4 (1,205). Their preservation does not imply an interpretation
as filesystem attributes. Identity blobs are kind 4: uint32 attribute count,
then namespace/name/value string-ID triples. A namespace ID of `0xffffffff`
means absent. The reader preserves attribute order and spelling.

`cdf_filemap` resolves these references; `cdf_filemap_encode` rebuilds the
supported schema, interns strings, prunes unused identities, and remaps IDs.
All 3,776 resident maps rebuild with identical resolved path, root selector,
names, flags and owner attributes. Empty maps fail explicitly; deciding whether
a servicing transaction deletes a map is outside serialization.

A stronger native control replaced the five maps consumed by the complete
WindowsMigration fixture with these rebuilt inputs. Native CommitChanges returned
zero after 2,377,539 instructions, with identical deletions, three security writes,
and byte-identical final root/Windows/ClientCBS maps compared with original native
inputs. No other creations, links or basic-information effects occurred. This
establishes interoperability for that subtree, not completeness of servicing.

Decoded comparison of the three ancestor outputs finds no changed file entries
or owners. Windows and ClientCBS path metadata is unchanged as well; their bytes
change through native reserialization. Only the root map changes path metadata
from empty/selector 2 to `\??\C:`/selector 0. Do not attribute all ancestor
payload differences to component ownership changes.

## Immutable replacement and file-only removal

For the actual `Globalization\Time Zone\tzautoupdate.dat` transition, native
ProcessFile receives separate operation 2 (old) and operation 1 (new) declarations;
3 is the accumulated node operation, not a valid ProcessFile input. Old/new
identities are Auto-Time-Zone-Updater-Service 26100.9278/26100.9711, flags
0x40/0x41, attributes 0xa0, with their actual SHA256Identity hashes and cached
manifest security pair. CommitLuaCdfs alone returns zero in 305,557 instructions.
It reads only the two existing FileMaps, not either payload. Its time-zone output
changes only the target owner version, preserving flags zero and all three
sibling entries (including the directory dot entry). The ancestor Globalization
map is byte-identical despite a rewrite; both maps receive security writes.

An old-only removal control returns zero in 265,856 instructions. The target
map shrinks from 996 to 752 bytes, removing only the target entry and its unused
owner. The remaining three entries and ancestor metadata survive. This phase
does not delete the payload. Independent native before/replacement/removal
containers are embedded in `filemap_native_transition_test.go`; portable edits
and serialization are compared by resolved ownership, flags, names, metadata
and identity pruning, not writer-generated expected bytes.

Native traversal at RVA 0x282818 inserts file records for post-file-pass states
2, 6, or 7, excluding file flag 0x40. It inserts a directory dot entry for state
4 except operation 2. Record construction at 0xfb95c derives map flags from
node bytes `(directory_flags >> 3) & 2` and `(file_flags & 2) << 1`; it takes the
post-operation identity. Do not generalize the metadata-only immutable probe
to writable state 1: the preceding file pass may change its state before LUA.
Native existing-map filtering includes identity checks; blindly replacing every
manifest destination without respecting node states and existing ownership is
not established by these controls.

## Addition, new maps, and filenames

An isolated actual ShellHealth_V10.json addition under UsageAndQualityInsights/
Feature_Configs returns zero from LUA in 336,096 instructions. It adds one
26100.9549 ownership record to the three resident entries without reading the
payload. The ancestor map remains logically unchanged. For the actual new
NarratorMCAT/Rules/Languages/de/definitions.yaml declaration, the implicit new
directory has no explicit dot owner: LUA creates a 628-byte map containing only
the file entry. It returns zero in 109,945 instructions, with no file reads and
one map creation and security write. This is a phase probe, not a full directory
creation or payload-installation result.

The new map exposes a real creation-security prerequisite: the FileMaps parent
has noninheritable DACL and audit ACEs, so the kernel uses the token default DACL.
Native SeComputeAutoInheritByObjectType selects flags 0x4003. Native
SeAssignSecurityEx with the declared SYSTEM/TI subject produces control 0x8c04,
SYSTEM owner/group, no SACL and the supplied default DACL. Independent one- and
two-ACE defaults distinguish this from assuming a fixed SYSTEM-only ACL. The
portable constructor now requires explicit token_default_dacl for this fallback;
only mapped, nonpropagating allow ACEs are accepted. The fresh native LUA run
using this portable constructor has identical final CDF bytes and resolved
security to the native-kernel-construction control. WCP's final map security
request is 276 bytes with information 0x9000000f.

`cdf_filemap_name(path, windows_root="/Windows")` derives the portable leaf name
from canonical absolute image paths. Native generator RVA 0xb5948 trims the
drive prefix, substitutes `$$` for the Windows root, filters the readable name
to lowercase ASCII alphanumerics, hyphen, dot and dollar, replacing other
characters with collapsed underscores, and limits that prefix to 100 characters.
Case conversion alone does not require a hash. Replacement, truncation or an
empty path appends an underscore and 16 hexadecimal digits. The hash covers the
complete unfiltered normalized path and uses **uppercase** folding at 0xe12a0,
not the lowercase folding used by entry-table hashes. Root is
`_0000000000000000.cdf-ms`; Windows itself is `$$.cdf-ms`. There is no `root_`
prefix (that spelling in earlier working notes was a transcription mistake).
All 3,776 resident filenames agree with portable derivation from their path
metadata. Independent native vectors cover collapse, punctuation, case, Windows
boundary matching, and the 100-character truncation boundary. Unsupported
Unicode and ambiguous/noncanonical image paths fail closed.

## Ownership filtering and bounded transitions

Fresh inspection of the same pinned WCP/PDB resolves RVA `0x43e60` to
`PrimeCodeIntegrityCdfMaybeFromFile`, `0x114cf4` to `ShouldPortDotBetweenCdfs`,
and `0x44380` to `PortFileInformationBetweenCdfs`. The existing map is filtered
before new records are inserted; this is not a name-only patch operation.

For ordinary records, no matching hierarchy child means port the existing
record. An addressed child with operation 2 or post-pass state 5 is not ported.
Other addressed children compare the **new** identity at node `+0x50` to the
existing map owner with identity-authority flags 1. Matching families and old
contribution flag `+0x94 & 8` admit replacement. Other mismatches enter native
conflict/exception-list logging policy; that policy is not implemented here.
The portable transition fails closed on these conflicts.

For the directory dot, native comparison uses the **old** identity at `+0x58`.
Absent old ownership or a different family preserves the existing dot. Matching
old ownership removes it from the initial table. The subsequent insertion phase
adds the new dot only for state 4 and operation other than 2. A retained dot plus
new ownership is a directory collision, not permission to overwrite it. The
native insertion primitive returns `0xc00000bd` without changing the old value;
the caller increments its separate directory-collision counter and returns zero.

Flags 1 excludes version, not component family. Direct native execution of
`CAttributeValueCollection::CompareTo` (`0x97cd4`) with distinct packed versions
returns unequal without the option (37 instructions) and equal with it (73).
With the option, actual Auto-Time-Zone-Updater family names differing only in
ASCII case compare equal (1,817 instructions); the IANA-TimeZones family control
compares unequal (747). These minimal probes have no file or identity-decision
hooks. They establish the comparison option, not a whole servicing transaction.

`windows.cdf_filemap_transition(document, nodes)` exposes the bounded portable
policy, returning `document` and `directory_collisions` (retained/requested owner
attribute pairs). Nodes contain immediate name (dot for the directory), operation, state,
directory_flags, file_flags, before_identity and after_identity. Identities are
None or the same attribute tuples as the resolved FileMap schema. Callers must
supply **post-preliminary-file-pass** states and select dirty directories. Files
in states 2/6/7 insert unless file flag 0x40 excludes them; state 1 writable
projections do not become immutable FileMap entries. Flags use the native
`((directory_flags >> 3) & 2) | ((file_flags & 2) << 1)` calculation.

Independent native replacement, removal, addition, new-map and directory-owner
captures now test this transition routine, rather than only manually edited
writer inputs. Separate controls cover foreign ownership, directory collisions,
case-insensitive keys, writable exclusion, shared identity isolation and invalid
references. Unused owners are pruned and exact repeated identities are shared;
family equality must never coalesce different versions in the serialized map.
An empty result is represented explicitly but still cannot be encoded. Map and
directory deletion, root-path normalization, traversal/ordering, security and
complete transaction integration remain caller obligations and open work.

### Actual Media Player directory collision

The first full-input provisional trial reaches a preserved dot owned by
Microsoft-Windows-MediaPlayer-Common 26100.1 under
`Program Files (x86)/Windows Media Player`. The reduced old/new directory owners
are instead MediaPlayer-Core 26100.8972/26100.9549 (wow64). Blindly replacing the
dot would discard the resident Common ownership.

An isolated native table-insertion control at `0x44730` returns `0xc00000bd` in
400 instructions, retains old blob ID 17 rather than incoming ID 29, and leaves
the count at one. Native hashing and mixed UTF-16/UTF-8 comparison are unhooked.
The caller `AddFileHashInformationForFile` (`0xfb95c`) then confirms the handling:
773 instructions total, zero return, retained ID 17, one directory collision,
zero file collisions. Three bounded CDF output interfaces capture the attempted
record; a bounded CRT memcmp supplies ordinary memory comparison. No insertion,
collision decision, trace or counter update is hooked. This is a phase-level
fixture, not proof that the whole servicing transaction accepts its diagnostics.

The portable result now keeps that owner and reports both identities separately.
Unresolved ordinary-file ownership conflicts still fail closed. Regressions
verify the retained record, collision diagnostic, and independent ownership of
the diagnostic/document/input buffers.


## Native path-metadata normalization

`windows.cdf_filemap_path(path, volume, windows_root="/Windows")` computes the
path/root_selector pair separately from the leaf filename. The drive designator
is explicit; no host drive is inferred. Canonical printable ASCII image paths
share the filename API's validation. This does not select directory ownership,
write a map, or authorize deletion of an empty result.

A bounded native `AdjustMapParentDirectory` (`0xb4d60`) fixture uses cached
Windows root `\??\C:\Windows` and volume root `\??\C:\`, with output storage
preallocated. Native comparison, trimming and selector decisions are unhooked.
Adapters provide bounded allocation/free, copy/fill, ASCII diagnostic strings,
a single-threaded diagnostic lock, absent optional diagnostic registry/environment
configuration and absent optional DLL loading. After initialization, independent
calls return zero with these results:

| Input image path | Output metadata path | Selector | Instructions |
| --- | --- | --- | --- |
| `/` | `\??\C:` | 0 | 714 |
| `/Windows` | empty | 1 | 2,178 |
| `/Windows/System32` | `System32` | 1 | 2,192 |
| `/Program Files` | `Program Files` | 2 | 2,381 |
| `/WINDOWS/System32/` | `System32` | 1 | 2,210 |
| `/WindowsOther` | `Other` | 1 | 2,187 |

The last vector is intentional: this metadata routine tests a literal
case-insensitive prefix, not the filename routine's path-component boundary.
The portable API requires canonical paths without trailing separators; native
trimming was tested independently, not added as permissive input normalization.
The root result also reproduces the earlier complete WindowsMigration capture:
resident empty/selector 2 becomes absolute NT drive path/selector 0 on rewrite.
These vectors are regression-tested; whole-transaction integration remains open.

The full pinned update's provisional pre-pass-state trial now completes all
806 dirty directories: 424 resident/nonempty, 228 absent/nonempty, seven
resident/empty and 147 absent/empty maps. It reports 19 preserved directory-owner
collisions. Empty absent maps must not be confused with removal of resident maps.
Native CommitDirectoryChanges phase bit 1 selects non-clean file children with
directory flag 0x10. The exact hierarchy contains 117 such files, all operation 3,
state 2, directory flags 0x98 and file flags 1. This census is not proof that the
whole preliminary pass has executed or that all subsequent state stays unchanged.

A fresh read-only media census through the new metadata API checks all 3,776
resident maps: the only metadata difference is the expected root rewrite.


## File-pass selection and map action boundaries

Independent native `CommitDirectoryChanges` (`0x281f4c`) controls stop at the
`CommitFileChanges` entry or immediately after the file loop. These are boundary
observations, not successful file operations. Phase 1 selects file dirflags0x98
(78 instructions) and skips0x88 (68); phase2 reverses that selection (70/78).
Phase0 selects0x98 (76). Clean bit4 (0x9c) and directory kind2 skip the file loop
(58/60). Selected calls receive leaf commit flags0 in these ordinary controls.
Private `select_servicing_file_commit_paths` now captures this bounded selection,
returning sorted candidate paths, **not an execution schedule**. The exact update
contains117 preliminary and6578 final candidates. The inspector retains both.

Native `ProcessFile` sets hierarchy byte+0x179 when process flags bit2 is set
(`0xbca28`/`0xbca2e`). CommitChanges checks that enable byte before its preliminary
pass, then runs FileMaps before the complementary final pass. Special commit and
external-store flags still require their separate policy; selection alone does
not prove the top-level gate or complete transaction has run.

The two direct CommitFileChanges state-write guards were separately executed
without hooks. At `0x1459bb..0x1459d9`, state2 survives both external-condition
values; state6 changes to2 only in the selected external case. At
`0x146584..0x146645` (or the pre-open boundary0x1465c9 for mutable cases), states2,
6 and7 remain unchanged; state1 becomes7 with overwrite flag2 and remains1
without it. The combined controls use2..9 and6..13 instructions respectively.
This confirms the direct-write guards for the117 immutable candidates, not all
callee behavior, I/O success, or a complete preliminary pass.

Native action selection at `0x282b74` is independent of map serialization:
nonempty output reaches BakeCodeIntegrityCdfAndWrite (5 instructions), whether
or not a map existed. Empty output with a resident map reaches RemoveFileMapping
(8); empty/absent reaches cleanup without either operation (4). Boundary hooks
only stop at those operations; they neither perform nor pretend to succeed at
writing/removing files.

Private `plan_servicing_filemap` composes the transition, normalized metadata,
filename and encoding into a write/remove/none record. Removal and no-op have
no content; an empty resident input is rejected rather than conflated with
absence. A remove action concerns the CDF, never the containing directory.
The caller still supplies post-preliminary states, selects dirty directories,
validates collision policy and applies native ordering/security. The planner
performs no filesystem effects. Independent boundary vectors test all four
resident/nonempty combinations and the root rewrite. A fresh read-only census
checks preservation/serialization and complete-removal controls for all3776
resident maps. Ownership comparisons resolve identity references, rather than
requiring stable table indexes after native-compatible interning/pruning.


### Complete preliminary-file leaf controls

Fresh full WCP/NTDLL/SIL fixtures now execute CommitFileChanges (`0x145720`)
with the exact metadata shape of all117 preliminary candidates: before/new
process flags64/67, operation3, attributes0xa0, node bytes90..95 equal
`[2,0,3,136,152,1]`, and native hierarchy preliminary-enable byte179 set.
Actual native hierarchy/default-security construction, identity parsing,
ProcessFile old/new declarations and preprocessing produce these bytes; they
are not injected to simulate successful preprocessing.

Both real security classes are covered. WRP_FILE_DEFAULT_SDDL returns zero in
30,550 instructions (12,227 plus an18,323-instruction continuation after adding
the bounded CRT exit-registration adapter). WRP_FILE_NO_LPAC_SDDL returns zero
in29,380 instructions from a fresh provider. Both leave all six observed node
bytes unchanged, perform exactly one hardlink replacement and one security
write, no basic-info write, and close the process token and transient file
handles. The only retained file handle is the caller-owned destination directory.
The default case's request is276bytes/info0x9000000f; source and target expose
new fixture bytes and identical assigned security, while parent security is
unchanged. Byte attributes0xa0 are declaration inputs, not proof of arbitrary
source filesystem attributes.

The callbacks implement bounded NT file operations, actual native RTL security
queries, independently kernel-compared portable security assignment, explicit
NTFS volume metadata, and unsupported FSCTL0x90284. Native state decisions are
unhooked. Payload names/bytes/hashes are synthetic, so this proves successful
leaf semantics and post-leaf map state for these classes, not authentic payload
installation or transaction-wide ordering/authorization. The full update's
separate payload/catalog verification remains distinct evidence.
