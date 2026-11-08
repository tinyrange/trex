# Server servicing metadata observations

Windows Server Standard Evaluation Desktop Experience 26100.32230, image 2,
and KB5126646 (target 26100.33650) expose 87,428 exact package identities in
the complete metadata closure. This is not an admission count. The bounded
metadata universe is now 131,072, with the conservative closure default still
65,536. Dense package snapshots must expand their pointer pages along with the
API count checks; raising only a validator would index past the old page array.
The regression checks old/new snapshots across 65,535/65,536 and the final slot.

## Parent display qualifier

Matched Microsoft public symbols for amd64 cbscore 26100.32131 identify
`ProcessDetectUpdateType`, `CDetectUpdate::Initialize` and `Evaluate`.
The parser attribute table at RVA 0x32ff30 maps name to 1 and set to 2.
The set path at 0x29c1a writes the string at parsed reference +0x10.
Initialize copies it into detector reference +8 at 0x59be0; name is at +0 and
local-reference flag at +0x10. Evaluate (0x9fe80..0xa12c0) never reads the set
field. Its parent path calls GetUpdatesFromParentPackages at 0xa046d with the
reference name only. The Server WMI SNMP provider's `set="display"` therefore
uses ordinary parent update applicability, including missing/absent/staged
states. Only this observed qualifier is admitted; unknown sets still fail.

## Capability reference version

`ProcessCapabilityUpdateType` passes 2 to `ProcessPartialIdentityType` at
0x5dd64..0x5dd73. The inlined version parser shifts each decimal field by 16
bits and stores the result at 0x1bcb7..0x1bcce. Thus XML `version="1.0"` is
0x10000, not a four-field OS version. `CheckCapabilityMatch` (0xa90b4) skips
version filtering for zero (0xa92f6). Otherwise it calls FileVersionFromString
at 0xa930f and compares its low DWORD at 0xa9464. The parser's third/fourth
fields populate that output (0x3db23..0x3db4d). This matches the baseline's
`XPS.Viewer~~~~0.0.1.0` registration. Name-only references retain wildcard
version semantics; architecture/language restrictions remain explicit.

These are construction/planning observations, not a completed servicing or
boot/application validation claim. Caller session editions must match the
Server product; client Professional selection policy is not interchangeable.

## Multiple detector references

ServerManager-UX's shell deployment declares two alternative parent updates.
Evaluate keeps the greatest observed state at 0xa0339..0xa0342, continues to
the next reference only while the predicate is false (0xa03ba..0xa03c9), and
returns installed/true for an empty initialized list (0xa0189..0xa0196).
Local self references are removed before that reduction; they must not make
a mixed detector unconditionally true. Regression cases cover alternative
parents, all-missing references, staged maxima, and self-plus-staged input.

## Ordinary lower-version reinstallation

In source CBS32131, ProcessMumServicing (0x90b04) invokes
ReInstallSupersededLowerVersion (0x10fe98) for actions 4 through 6.
The ordinary path filters intended state 0x50 (0x110059), retains only the
greatest version (0x110093..0x110098, 0x110308..0x110321), then requests
installed 0x70 with no named owner, integration 2 and skip-MUM true
(0x110422..0x110469). It does not reinstall every superseded predecessor.
The session-flag-4 branch and LCU capability/container verification are distinct
policies, not inferred from this ordinary install path.

MigrateUpdateSelectionFrom (0x144c6c) only considers destination selectable
updates (IsSelectable at 0x144d08). Thus a nonselectable destination has no
selection migration effects. The recipe implements this bounded case and
rejects selectable migration and LCU rollback rather than inventing selection
values. The Server Fonts-UAPFonts predecessor has one nonselectable component
update. The end-to-end servicing regression exercises downward admission of
its newer analogue and verifies that only the greatest superseded predecessor
is admitted, without a fabricated owner or mutation of the baseline hive.

## PA31 LocalVarSig custom modifiers

The x86 GroupPolicy.Management.Interop26100.33296 forward record has a
175008-byte basis and a 205784-byte target. In-process ApplyDeltaB from the
source servicing stack UpdateCompression32131 returns the declared SHA-256
988b0151e48d5ea61bd5184f51e0cca41c4c5abc6ed929b36ccb78a68037e2ff.
The original decoder differed at ten target bytes, all copied from local
signature modifier prefixes (including copies of earlier target bytes).

CliBlobTransformer::Run at 0x5ac00 dispatches LocalVarSig through
0x5ac81..0x5acba: skip 0x4? markers, skip one BYREF, then enter TransformType
directly. It does not call TransformSentinel or TransformParam at that boundary.
Thus a root custom modifier stops the local walk, preserving its token and all
following tokens. Method/field boundaries and pointer-nested modifiers remain
different. Synthetic regression cases cover those contrasting paths.
System32 msdelta.dll is not the PA31 oracle: it rejects the PA31 magic in its
CheckBuffersIdentity routine before decoding.

Component staging's read-only `delta_inputs(index)` exposes the exact verified
source and delta file handles, `psf_record`, and target name/size/SHA-256 for
such diagnostics. It shares record/nested-patch validation with construction,
rejects non-express payloads, and does not reconstruct or publish a target.
`windows.delta_trace` is diagnostic; normal staging still enforces both hashes.

## Mixed-mode native methods in CLI normalization

NCServerPSProvider26100.33648 is a mixed-mode amd64 PE. Its PA31 nested
BSDiff target initially differed only at offset93416. Cabinet's native LZMS
output matched all660200 decompressed delta bytes, isolating preprocessing:
the native source byte93404 was13, while the portable source retained12.
MethodDef449 (RVA93388, ImplFlags0085) begins with native RET-imm16 opcode C2.
MSDelta accepts that byte as a tiny CLI header of48 bytes. The later native
JE opcode74 is consequently read as CLI castclass, mapping apparent TypeRef
018b4812 to018b4813. BSDiff's additive ff then restores the target branch12.

UpdateCompression32131 TransformCliDisasm (572e0; row lookup573d7..573ed)
and MarkNonExe::RunCli4 (58eef..58f1f) read only MethodDef column0 before
calling the header parser48554. Neither filters MethodImplAttributes.
Invalid headers are skipped. The disassembler stops the current body on an
incomplete operand (5746d..5746f,5758c), retaining earlier rewrites and then
visiting the next row. The final MethodDef row remains excluded.
This is delta-format compatibility, not a relaxation of ordinary CLI inspection.
The regression includes native-header recognition, invalid-header skipping,
partial-body termination, next-row continuation, final aliases and MARK bounds.
Native ApplyDeltaB returns659456 bytes with declared SHA-256
 ee0993e607386578da30aed4f53acf24676cdd9abe0d92ffb8de917ebe960c40.

## Directory MARK fallback for unbacked RVAs

The x86 deployment bootmgr.exe33648 PA31 record reconstructs an821080-byte
target from791984 source bytes. Native ApplyDeltaB verifies SHA-256
b87fc9457aa369cb77ccef425489df8903cc58ad64eea075929b8c230ee0bdca.
The portable mismatch was four bytes: two copies of certificate source789308.
The unlisted-I386-pointer pass saw an accidental address in UTF-16 certificate
text because MARK had not claimed the certificate overlay.

DataDirectories construction (UpdateCompression32131 RVA34245..3427e)
first calls SectionHelper's raw-backed RVA lookup33eb4. A zero result falls
back to the original numeric address only when it is less than the file size.
The resulting directory size is clipped to the remaining file bytes. This
applies to every directory, not just Security. A virtual section tail is not
raw backing. Here Security address782336 lies in .data's virtual-only tail,
so native MARK claims782336..791984 directly. The pointer scan itself still
covers the whole file; a breakpoint confirmed its extent791984 and marker03
at the failing byte. Existing cases where Security's numeric value is a valid
raw-backed RVA must retain that mapping rather than always using file offsets.


## Repeated projected files on Server

Server 26100.32230 has installed x86 and wow64 Printing-AdminScripts and
PrintManagement families. Their update transitions contribute 86 same-side
pairs at 43 SysWOW64 destinations. Every pair has equal flags, attributes,
security declaration and hash; the identities remain distinct. The resident
`prncnfg.vbs` FileMap owner is x86, not wow64. Dropping a family or changing
architecture redirection is not the fix.

The source WCP 26100.32131 (PDB key
`FB69071436061AA14615D79CA4D84C161`) was executed with the semantic Windows
emulation runner, native identity authority/parser and native file hierarchy.
No identity, path reduction or collision-decision function was replaced. This
is a bounded reduction experiment, not full installer initialization/commit.
Constructor 152c10, NT-prefix initializer 12079c and identity-map initializer
a3300 establish the hierarchy; authority 7e3d0 and parser 3a5d0 parse the exact
paired 10.0.26100.32860 identities. ProcessFile bf948 receives ordinary flags
old=0/new=1, attributes a0, empty external/filter/hash vectors and null security
and source-hash pointers. Find f62e0 reads back the selected node.

Both insertion orders produce the last identity at new +50 / old +58. New
pairs have bytes +90..95 `02 00 01 08 80 20`; old pairs have
`00 00 02 08 08 01`. New pairs call ReportFileCollision 27c414 and set +95 bit20.
That routine forces its tolerated result when installer +10 is false, leaving
hierarchy +180 zero. Setting +10 true produces +180=1 for these filenames;
old pairs never increment it. Hash equality is not queried in this path.
The Server has neither SingleResourceOwnership nor SmiHiveUpdates configured,
so its ordinary coordinator supplies +10=false.

The reducer previously rejected all repeated destinations before applying
that native policy. It now accepts ordered ordinary-primary overlaps with
identical flags/attributes/security only when the explicit ownership gate is
non-strict. All sources and contributions remain, and new overlap bit20 is
preserved. Missing/strict policy, mixed metadata, writable/link overlaps and
repeated primary source keys still fail closed. Strict-mode filename exceptions
are not implemented. Regression vectors cover both orders/sides, distinct
source hashes, retained sources and rejection controls. The fresh full Server
hierarchy now contains 19,014 nodes and 15,237 sources; all 68 servicing tests
pass. This does not establish full image construction or boot health.


## Inheritable directory audit requests

After file reduction, the Server Defender `DataScan` directory exposed a
separate validator gap. Both its parent and selected SACL contain ordinary
Everyone audit ACE type2, flags c3 (OI/CI/success/failure), mask 010d0000.
The old directory setter admitted only noninheritable audit flags c0 and also
excluded ACCESS_SYSTEM_SECURITY from this mask.

The source NTDLL RtlNewSecurityObjectEx (2cbe0), flags101b with file mapping,
produces control9c14 and two audit ACEs: explicit c3 and inherited d3, each
mask010d0000. Every descriptor component equals the existing portable
inheritance implementation. Native kernel SeSetSecurityDescriptorInfoEx
(850a60, PDB B65A1E5D9D57D828E82F8C75F19E98571), flags4000 and full information
9000000f, accepts the request with AR bits added (9f14) and returns control9c14,
retaining every component. The exact fixed DataScan result matches this output.
The fixture supplies bounded heap/pool storage, an explicit SYSTEM token,
checked resource locks, subject capture/release and an empty thread APC queue;
no inheritance, normalization, ownership or security-decision routine is hooked.
Interrupted setup-discovery runs are excluded.

Independent ordinary audit controls give these final flags when both parent
and selected descriptor have the indicated source flags (all masks010d0000):
SAFA -> c0; OISAFA -> c1,d9; CISAFA -> c2,d2; OICISAFA -> c3,d3;
OICINPSAFA -> c7,d0; OICIIOSAFA -> cb,d3; OICIIDSAFA -> d3.
All seven native inheritance and full-assignment results match the portable
components. Directory request/assignment now accepts these ordinary audit
flags and mask; unsupported categories remain rejected. Creation semantics
remain a separate boundary and are not widened by this setter correction.

## Creation-time audit inheritance

The Server ImageCache directory beneath Windows Defender Advanced Threat
Protection requires a creation descriptor with inherited audit ACEs, distinct
from WCP's later directory setter. Native source-kernel SeAssignSecurityEx
(RVA a2bbe0, matching PDB B65A1E5D9D57D828E82F8C75F19E98571) with
SYSTEM subject, file generic mapping and flags4003 produces control8c14,
SYSTEM owner/group and inherited AU flagsd3/mask010d0000. All descriptor
components match portable inheritance for this actual parent. The fixture
provides kernel SID globals, token and allocation/locking environment only;
no security decision is replaced.

Fourteen file/directory native controls cover noninheriting, OI, CI, OICI,
NP, IO and already-inherited audit ACEs. Directory results are respectively
absent,d9,d2,d3,d0,d3,d3; file results absent,d0,absent,d0,d0,d0,d0.
Creation now preserves that SACL and its PRESENT bit instead of discarding
it. Propagating legacy parent SACLs remain fail-closed: native flags4001
without parent SACL_AUTO_INHERITED produces c0 rather than d0 for the OI
file control. Other audit categories remain unsupported.

The next fresh construction exposed a new-only boot-critical immutable file,
KernelFSFormatter.sys (operation1/process43/securityc0/directory90). The request
admission list allowed flag43 only for paired files, although native-derived
ProcessFile reduction maps bit2 exclusively to directory flag10 (commit phase).
The security-request admission now accepts 41/43 for either operation; security
selection and phase routing remain unchanged. All 7,502 immutable requests in
the Server hierarchy pass against the planned effective parent descriptors.

## Managed registry contributions

Fresh construction next found eight before/after registry key declarations
from the MSIL CertificateServices.ServerManager.DeploymentPlugIn and
FileServer.Management.Plugin.UI components. The generic path mapper rejected
MSIL before mapping their HKLM/Software/Microsoft/ServerManager keys. Native
CSI identity binding already establishes store bitness2 for MSIL, unlike
x86/wow64 bitness3 (see the architecture/macro and registry-view notes in
csi-offline-state.md). The mapper now admits MSIL in the native view; it
does not synthesize WOW6432Node, alter macro identity, or skip declarations.
Unknown architectures still fail. Managed contribution and path tests cover
actual ServerManager keys and a COM subtree with a redirected control.

Registry planning then exposed missing SDDL alias CY in four before/after
Cryptography/Configuration/{Local,Domain} declarations. The actual baseline
SYSTEM key's first two ACEs independently establish SID S-1-5-32-569, with
flags03/0b and masks0003003f/e0010000. The compiler now recognizes that fixed
alias; a byte-exact resident-ACE regression preserves rights and inheritance.
Of 272 distinct registry SDDLs, this was the sole missing form when the
recipe's explicit account-domain SID was supplied.

## Explicit profile value routing

The Server transition changes HKCU Software/Microsoft/UEV/Agent's
UserConsoleVersion from10.0.26100.7309 to10.0.26100.33648. Its paired key
contributions have no security definition or key-structure change. The recipe
now explicitly binds the sole physical Default/NTUSER.DAT template, after
checking ProfileList.Default and rejecting registered account profiles or
additional physical hives. This is not HKU/.DEFAULT; the native per-user
profile-provider distinction remains intact.

The ordinary planner accepts explicit profile_hives for existing-key value
changes only. Profile creation, security and cleanup still fail closed. Shared
value arbitration, mutable preservation, source preflight and complete readback
remain in use. The real candidate publishes4610 sets/479 deletions/229 removed
keys across three hives, and template readback has userconsoleversion
10.0.26100.33648. Regression controls cover two profiles, modified mutable
values, unmodified security, DEFAULT separation and missing-key rejection.

## Catalog verification buffer lifetime

Catalog proofs no longer retain every eagerly decompressed DCS buffer; only
content hashes and metadata survive per member. This did not alone explain
the process kills. A bounded inspection measured approximately8.1GB live heap
before hints with an unconstrained16.2GB GC goal. With measured collection
checkpoints, live heap stayed about8.4GB through the full7974-catalog pass:
16575 present paths verified,1614 absent paths recorded and16500 hint objects
planned. No signature/member checks were skipped. This inspection is not a
fresh full-image validation. A normal fresh run still needs a suitable runtime
memory budget; artificial per-member collections were diagnostic only.

## New disabled Debug registration

Source wevtutil PDB `0A2DC2636072D0009A8B47DCD61D4A061` establishes
SAMLIB's new disabled System Debug channel separately from shared sessions.
InstallChannel (`23874`) selects Type=3 at `23be2`; explicit access reaches
SetChannelAccessSddl (`2798c`), which preserves its string. Installed independent
System Debug channels corroborate the five ordinary channel values and absence
of logging children when none are declared. IsOwnerOfEtwSession (`2f6b0`) treats
Type=3 as dedicated regardless of System isolation. UpdateAutologgerForChannel
(`2d158`) branches on Enabled at `2d259`: disabled channels reach deletion, not
session creation. The portable planner admits only new disabled System Debug
channels, retaining explicit access; replacements/enabled modes still reject.

GetSessionNameAndGuid (`10ab4`) prefixes EventLog-, converts slash/backslash to
hyphens, uppercases, and hashes UTF-16LE without a terminator. Sha256HashToGuid
(`31b88`) takes the first 16 digest bytes and forces byte7's high nibble to5;
it does not set an RFC variant. The bounded ASCII name policy avoids guessing
Windows Unicode casing. Native DeleteSession (`2c3cc`) removes the dedicated
Autologger key and WMI/Security GUID value. Existing state in either location
therefore rejects, rather than being silently ignored. The SAMLIB session GUID
is `efde66c0-943f-54b6-7c1d-9b6550b10605`. The real Server event plan publishes
four providers, removes two, registers two channels and adds no autologgers;
30 values and two publisher subtrees were committed to the retained candidate.
This evidence is native code inspection plus independent installed controls,
not an end-to-end EventsInstaller execution or boot proof.

## Server MediaCategories child security

The actual source parent has control8c14, SYSTEM owner/group, present NULL SACL,
and six inherited DACL ACEs; it is not the legacy client seven-ACE parent.
The source kernel PDB `B65A1E5D9D57D828E82F8C75F19E98571`, SeAssignSecurity
RVA `910e10`, was executed with that exact parent, NULL creator, container1,
registry mapping `20019/20006/20019/f003f`, and an explicit administrator subject
(BA default owner, target account-domain RID513 group, High integrity). Only
allocation/free and the subject-resource lock were substituted; no security
algorithm was hooked. Native execution returned0 in5187instructions with
balanced lock and APC-disable state. The output has control8c04, BA owner,
explicit subject group, no SACL and the same six-ACE inherited DACL.

All descriptor fields match inherit_registry_security with an explicit BA/group
creator, including removal of the parent's NULL-SACL-present bit. An independent
second subject group S-1-5-21-7-8-9-513 also matches, and its native descriptor is
a regression golden. The implementation admits only the exact measured parent
shape. The real Server KS plan creates137keys and writes274values from43
Include/Needs requests; publication and serialized descriptor readback pass.
This proves the scoped MediaCategories subset, not all KS/RunOnce work.

## Server basic installer identities and direct service deltas

The HTTP/timezone rejection was a client-only source path and ABI whitelist,
not evidence that the Server DLLs failed. The final Server onecore-installer
component is26100.33634. HTTPAI SHA256
`ebd0f3c34e7b77852c79edf80eec485cdd526acf51a975f7b1ab3d181765ab8b`,
PDB`FA49CAB8BBD40597AC1ADA338E2CE56D1`, executes all four actual jobs with
steps631/631/631/888 and five reservation writes. A changed URL/SDDL control
produces the changed native output. Its400instruction control fails, not succeeds.
TimezoneAI SHA256
`601d9296d4a461623efd260ef6fb46af477d4160522ad4302ea85ddacc6fbae8`,
PDB`1D4ED37F23398F741867E4D0DE9BA1801`, executes primary offline handling
in67instructions with no writes and resource handling in72631instructions with
10writes. A40000instruction control fails after10writes; partial capture does
not escape the adapter. No ABI callback or security decision was substituted
beyond the existing narrow native adapter. Production selection requires one
present qualified source, its exact SHA256, and matching ABI/PDB identity;
ambiguous source versions, different bytes and unknown ABIs reject.

The actual HTTP publication finds all five reservations already correct;
timezone publication updates10values. These are scoped offline effects, not
CBS completion or proof of online installer phases.

The direct-service architecture rejection was an unchanged x86 WFDSConMgr
contribution, alongside its unchanged amd64 owner. Service signatures must still
participate in global before/after equality and competing-owner detection.
Unchanged paired x86 SvcHost declarations need no registry-view choice; changed
x86 service ownership or membership still rejects. This does not waive native
inspection/queue obligations elsewhere. MDCoreSvc separately adds
launchProtected=antimalwareLight. Independent baseline manifest/physical
controls establish sppsvc/windows=1, ClipSVC/windowsLight=2 and
WinDefend/antimalwareLight=3; unknown values and field removal remain rejected.
The complete direct delta now publishes29values for nine services and six
SvcHost groups while preserving unchanged settings.


## Server managed cache and deferred NGEN declarations

The 41 staged-source lookup failures were case differences in CSI identities
(`versionScope=NonSxS` versus `nonSxS`), not missing payloads. Compare identity
keys case-insensitively, reject conflicting case aliases, and retain exact
admitted stems and file SHA-256 checks. The 106 extra GAC attributes were the
single-space `parameter=" "` annotation. WCP33634 ParseGac (RVA133d6c)
recognizes managedversion, clrversion, managedculture, clrarch, fileCopy and
name, not a parameter identity override. Admit only empty/single-space
annotations; nonblank parameters and other overrides still reject.

Five updated assemblies use the legacy Fusion store: Microsoft.Ink in amd64
and wow64 and three MMC resource assemblies. Their missing clrversion selects
existing `/Windows/assembly/GAC_*` identities without the CLR4 `v4.0_` prefix.
Existing source-media cache paths agree with the declarations. Cross-store
identity changes and missing cache directories remain lifecycle failures.
Microsoft.SecureBoot.Commands adds `hashes.json` on both architectures. New
companions may be linked only from declared, hash-verified staged files into
an existing cache identity, with destination absence checked before the whole
batch is published. Removals remain unsupported. The diagnostic Server batch
refreshes234files (two added companions) and emits200Fusion notifications plus
three transaction counters. This is not runtime Fusion validation.

The exact target WCP33634 has PDB key
`A6060965A74C17D44668092B6B58CB791`. Its NGEN attribute behavior is surprising:
ParseNgen stores win64targetarch as text at parsed record+20/presence+39.
ModifyGacFiles149002..149080 validates `32bitOnly` or `64bitOnly` using
AreStringsEqualByOrdinalCaseInvariant37790. Both successful comparisons join
149201; the string is subsequently freed. Inspection of this function and
GetAssemblySpecificInfo149f90..14a6c3 finds no assignment of that annotation
to AssemblyInfo+118. The constructor148570 sets that DWORD to zero at148602.
CreateRegKeysForNGen280ea8..280ee7 dispatches MSIL mode0 to both queues,
mode1 to Win32 and mode2 to Win64. Thus the observed MSIL `64bitonly`
annotation is admitted without inventing Win64-only dispatch. Other explicit
modes remain rejected. This is matched-native-code analysis, not a full native
GAC transaction execution. The complete diagnostic candidate queues154
commands; native-image compilation itself is deferred and unverified.

## Server boot installer qualification

The serviced boot-onecore component26100.33634 contains:
- FVE SHA256`1ff28931f1a35fdd3ea524e0bb08218afc874bb78645ab83719c6d9b84816f04`,
  PDB`C2D914E918CDBFCDC22A205ECF7CC53B1`.
- SecureBoot SHA256`484051fcb40d931da6dc528ac083b1a856f259023501c67792bfbbc483c019b4`,
  PDB`C635F57EC160C59EA462DA221384A2E21`.
The unchanged bounded CSI ABI adapter executes FVE in154steps with no writes
and SecureBoot in202steps with one selected-control-set AvailableUpdates
DWORD0x402 write. Controls use ControlSet002, absent/stale/wrong-type prior
values, replay, preserved unrelated data/security and failed initialization
under a reduced instruction budget. All pass. Seven real Server jobs produce
two writes, both already present in the candidate. Source selection and direct
execution require qualified hashes and ABI identities; no firmware or online
FVE completion is implied.

## Multiple parent detector indexes

ServerManager-UX's Server-Gui-Mgmt and RSATClient-ServerManager alternatives
both occur as UpdateDetect keys in the installed native SOFTWARE hive, each
with the package value DWORD0. Metadata publication must emit every parent
reference, without applicability pruning; local update references still do
not emit UpdateDetect records. This is independent of the detector predicate's
maximum-state reduction. The diagnostic candidate subsequently publishes2729
new package dispositions and3915resident transitions after CSI verification.

## Bounded oversized payload retention and native health

A serviced Server26100.33650 ScanHealth control exposed a correctness-sensitive
cache thrash, not an exhausted smoke timeout. The 343,667,016-byte WebView
`msedge.dll` had been admitted as the sole oversized entry in the ordinary
compressed LRU. A single 4KiB `ntdll.dll` read evicted it. A native interleaving
probe measured subsequent 4KiB WebView reads at about8.8s versus0.00055s without
eviction. Repeated successful slow reads preceded SOFTWARE hive paging failures
(C0000185); NVMe backing-error and failed-completion counters remained zero.

The compressed stage cache now retains exactly one oversized target separately
from its ordinary128MiB LRU. The oversized slot is capped at513MiB including
chunk accounting; another oversized target replaces it. The decoded chunk cache
remains64MiB. No unbounded pinning, host intermediate files, reduced identity
checks, or guest storage-timeout override is introduced. Reopening after eviction
still validates length and SHA256. The interleaved regression checks one target
reconstruction, bounded retention, replacement, and rejection of changed bytes.

A fresh4GiB/4CPU cc UEFI/NVMe Server26100.33650 control with the corrected cache
completed native Get-Packages, CheckHealth, ScanHealth and SFC `/verifyonly`, all
exit0 and no timeout. ScanHealth reported no component-store corruption in553s;
SFC reported no integrity violations in325s, followed by clean shutdown. Host
available memory stayed above7.19GB and OOM counters did not increase. This is
health evidence for that exact candidate, not a live Windows Update currency
claim. ScanHealth2h and SFC90min bounds were unchanged.


## .NET CLR architecture and global NGEN update

The KB5127690 manifests use `gac.clrarch` independently of the component
architecture, EXE assembly identities, and `fileCopy="false"` alongside explicit
GAC links. No-copy publication must verify every existing cache member against
the target, including companions; it is not permission to skip cache validation.

Matching amd64 WCP 26100.33634 symbols (CodeView
A6060965-A74C-17D4-4668-092B6B58CB79, age 1) identify
GetAssemblySpecificInfo at RVA 0x149f90. At 0x14a094..0x14a0ca it replaces the
component architecture with the declared CLR architecture, storing it at
0x14a4e3. CreateRegKeysForNGen (0x280c94) uses that assembly architecture through
GetLegacyArchitecture at 0x280e4c, rather than the component's WOW64 label.

`IssueNgenUpdate` is a directive, not an assembly command-line option.
ModifyGacFiles (0x148c58) compares it at 0x149217..0x14922c for change operations
1/2, sets installer flag +0x190, and skips ordinary assembly processing.
Operation 3 skips this path. CommitChanges tests that flag at 0x126fab and calls
CreatePlatformSpecificNgenKey for Win32 and, on amd64, Win64 at
0x126fbb..0x12700e. The command constant at 0x313930 is `update /queue`.
Construction queues that operation once per platform without inventing native
image generation or queue completion. Focused regressions cover CLR overrides,
EXE identities, exact no-copy verification, and global queue deduplication.

## SecurityHealth native trust and registration boundary

The pinned SecurityHealthSetup 10.0.29628.1000 payload matches the retained
Server WUA offer. Its extracted Core registration entry is RVA 0x1c29c.
Registration verifies Core, ProxyStub, Agent, Host and SSO signed PE files before
loading the registration DLLs. It expects an extended module path; the native
path helper strips the four-character `\\?\` prefix. A plain DOS path is not
an equivalent input to that helper.

The Server baseline crypt32 image (PDB key
5E25EA41E5E5D9B353DE1453DE52A3611) implements Microsoft-root chain policy at
RVA 0x15930. The inspected branch hashes the root SubjectPublicKey BIT STRING,
not the certificate display name, and checks its AlgorithmIdentifier parameters.
The ordinary production table at RVA 0x12ed80 includes the SHA-256
12eb31fdc89249a0eb67eb65c2977dbe2ad96a909ccbd180f7e2e16b2782caee with DER
parameters 0500. This is the root actually reached by the pinned payload's
verified Microsoft Windows Production PCA 2011 chain. This observation is not
a general replacement for WinTrust, revocation policy, or arbitrary provider
structures. The current exact-file probe admits only the inspected primary
signature, timestamped chains, and policy-7 request with flags 0xf00.

ProxyStub registration completes under that probe. Agent initialization needs
late-bound Kernel32 RtlPcToFileHeader, ETW and SDDL API-set exports. After creating
its COM keys, Agent requests owner security for the new InprocServer32 key
under CLSID {08728914-3F57-4D52-9E31-49DAECA5A80A}. A values-only registry model
cannot answer that query: inherited creation security and the updater subject
must be established. Partial registry effects are not an installed platform.

## MSRT callback-backed extraction boundary

The pinned MSRT 5.146 wrapper (mrtstub PDB key
F8D3D38207E57008E5664FACC7B5A5CC1) contains one CABINET/MRTFULL resource.
Its sole member is mrt.exe, version 5.146.26100.1003, 230303336 bytes,
SHA-256 3efb81098f35bc2efb39f9d46af3e13b34f8d804d5e7db055e77d47890edbcc6.
The wrapper's FDI input name identifies an in-memory callback stream, not a
filesystem cabinet. Treating an absent pseudo-path as a missing input yields
an empty output file; observing a subsequent CreateProcess call is therefore
not extraction proof. Compare the complete produced bytes before publication.

Native FDI callbacks require 64-byte FDINOTIFICATION on amd64 versus 40 bytes
on x86, with pointer-sized context and handles. CAB date/time/attributes must
come from the parsed file table. The adapter now reads the actual callback
stream and invokes native output callbacks with bounded chunks.

The wrapper prepares C:\Windows\System32\MRT.exe and requests default filesystem
compression. Its observed no-compression failure branch still attempts the
child command `"C:\Windows\system32\MRT.exe" /Q`; this is not scan completion.
A real callback-backed extraction needs an explicit file-write bound above
230303336 bytes: the historical 16 MiB bound caused native fwrite failure that
the wrapper reported as 0x8007000e. With a 256 MiB admitted file bound, the
native wrapper produces exactly the member hash above and reaches the child
boundary without any registry patches. The native zero-fill loop also requires
more than ten million instructions; a bounded fifty-million-instruction probe
crosses it. No scan/version marker is justified by extraction alone.

### MRT fresh-media file creation (5.146)

The pinned wrapper's CRT open path calls CreateFileW at RVA 0x24da2.
It passes a 24-byte SECURITY_ATTRIBUTES at rbp-0x59; the native code
explicitly sets lpSecurityDescriptor (rbp-0x51) to zero. The inherit-handle
field is separate. Static SYSTEM staging therefore uses the actual System32
parent descriptor and the bounded SYSTEM creation-security operation, not
an arbitrary copied executable ACL. The baseline Server image has no MRT.exe.
The recipe rejects an existing MRT.exe rather than guessing replacement rules.

The wrapper child-launch helper waits for the real child and returns its exit
code (CreateProcessW 0x21c2, WaitForSingleObject 0x2209,
GetExitCodeProcess 0x2252). No completed scan follows merely from extraction.
The observed wrapper DWORD setter at 0x57e5 writes SendFullPackage=1 under
Software\Microsoft\RemovalTools\MRT; it is not an installed-version marker.
Static staging does not write it, Version, or any scan results. A native /Q
scan and subsequent read-only WUA detection remain integration obligations.

### Server SecurityHealth creation-security investigation

For baseline kernel SHA256 a22c81e8c1507b42bce8d17181c3af9a9314c4b4d6dbaef6bf07e1aa3d179636,
PDB B65A1E5D9D57D828E82F8C75F19E98571, native SeAssignSecurity is
RVA 0x910e10 and SeDeassignSecurity 0xa20ce0. Its actual token-lock calls
are ExAcquireResourceSharedLite 0x2f0d80, not ExclusiveLite 0x229e70;
ExReleaseResourceLite is 0x20d8e0. Pool allocation/free boundaries are
0xb680f0 and 0xb68cd0. Reusing the client kernel's RVAs is invalid.

The isolated declared non-protected SYSTEM subject (default owner BA,
primary group SY, integrity 0x4000) produced real inherited COM-key security
with balanced owned allocations and token locks. Portable registry inheritance
with explicit O:BAG:SY matched the parsed native descriptor for the actual
Classes/CLSID parent. This establishes that assignment operation, not the
identity or privileges of the real SecurityHealth update worker.

SecurityHealth also supplies an explicit protected creator DACL, initially for
Classes/AppID/{2eb6d15c-5239-41cf-82fb-353d20b816cf}. It grants TrustedInstaller
and SYSTEM full access, Users and application packages read/execute, with
corresponding inherit-only OICI ACEs. Native assignment of this real creator
requires SeExports: SepVariableInitialization stores SeOwnerRightsSid
(0xe67848) into SepExports+0x200 at 0xc2f2cf; SeExports (0xfd8a90) points
to SepExports (0xfd90d0). RtlpOwnerAcesPresent (0x37de60) consumes that slot.
The other initialized SID globals used by assignment are CreatorOwner
0xe67788, CreatorGroup 0xe67850 and LowMandatory 0xf04968.

Agent registration queries the owner of the new InprocServer32 key for
{08728914-3F57-4D52-9E31-49DAECA5A80A}, requests SYSTEM ownership, then queries
its DACL. GetNamedSecurityInfoW receives non-NULL output addresses even for
unrequested parts; only requested components are returned, with the other
outputs zeroed. Descriptor storage must be owned by LocalAlloc/LocalFree.
SeTakeOwnershipPrivilege is looked up before the setter; the matching kernel
initializes its LUID to 9 at 0xc2f108/0xc2f116. The old semantic lookup returning
LUID zero is not valid evidence. An empty-privilege control still reaches the
setter: AdjustTokenPrivileges returning TRUE does not establish that all
requested privileges were assigned. The observed protected key DACL directly
grants SYSTEM WRITE_OWNER; a restricted probe changed owner only after checking
that grant and requiring the new owner to equal its declared SYSTEM subject.

These last named-security operations remain inspection-only, not a published
installation: the probe's owner changes are not yet written into registry
plugin effects. The late Agent additionally requires the API-set exports
GetSecurityDescriptorOwner, ConvertStringSidToSidW and AllocateAndInitializeSid.
Existing implementations are insufficient if only exposed through Advapi32.
The final observed stop was AllocateAndInitializeSid in the security-base
contract after the real owner/DACL queries. No registration success, complete
SecurityHealth effects, updater token proof, or boot validation is claimed.


## SecurityHealth native ACL update

For the pinned 10.0.29628.1000 payload, the agent's registration uses
SetEntriesInAclW with two 48-byte amd64 EXPLICIT_ACCESS records: SET_ACCESS,
GENERIC_ALL for SYSTEM (inheritance 3) and TrustedInstaller (inheritance 0),
against the previously created protected eight-ACE DACL. Actual Server ntmarta
SetEntriesInAclW (RVA 45920), using actual ntdll RtlValidAcl, returns a six-ACE
ACL: SYSTEM and TrustedInstaller replacements followed by the unchanged four
BU/AC entries. This is not an append-only grant.

Actual kernel SeSetSecurityDescriptorInfo (RVA 0x84e950), information=4,
then maps generic rights using the registry GENERIC_MAPPING. Its old descriptor
must reside in kernel address space: the code at 0x84f23d..0x84f24a rejects an
owner pointer at or below 0x7fffffff0000 with STATUS_INVALID_OWNER. Supplying
owned kernel-address pool storage (not skipping the check) permits the update.
The probe supplies the explicitly declared SYSTEM subject at the real
SeCaptureSubjectContext/SeReleaseSubjectContext boundary (RVAs 8665568/8665296),
checks balanced subject capture, pool ownership, and token locks, and executes
the native setter body. Output in this case has control 0x8804, owner/group SY,
and concrete KEY_ALL_ACCESS for the two replacement ACEs. Preserving 0x9004
by hand would not match this native operation.

With owned AllocateAndInitializeSid/FreeSid and the observed late UCRT-private
wcsrchr alias bound to actual UCRT code, core internal registration RVA 115356
returns S_OK after 592695 instructions and emits 332 value changes. Core and
all six loaded DLL initializations return TRUE. This proves only the isolated
registration path with the declared subject and probe directory. Named-security
publication, actual updater directory/subject selection, AppX/service sequence,
and fresh-image health/update detection remain separate obligations. No partial
probe output is installation evidence.


## SecurityHealth service update staging

Baseline SecurityHealthCore service control202 queues bit0x200. The queued
callback dispatches it to RVA0x1a6c4 with argument1 (0x13362..0x13375).
Executing this actual helper against the single staged, signature-verified
SecurityHealthSetup.exe selects `10.0.29628.1000-0`, creates that directory,
and launches the wrapper with the selected directory as its second argument.
The emulated child exits0 and produces131 new entries (90 files), byte-identical
to the independently decoded payload. The cloned child's reported dirty root
also includes the parent's already-created output directory; that is not a
132nd new child entry and must not replace the parent object.

The helper waits for both the completed extraction process and the service
stop event at Core RVA0x1380f0. Directly entering it without initialization
leaves a NULL second handle and correctly fails ERROR_INVALID_HANDLE. Native
service initialization at0x10234..0x1025f calls helper0xdb330 with that slot,
manual-reset1, initial-state0. Executing the same constructor, then the update
helper, and finally closing the owned event avoids inventing a signaled wait.
GetExitCodeProcess must read the created process object's real exit code;
unknown, closed, and thread handles must fail rather than imply successful
installation. Regression coverage includes nonzero child status, DWORD output
bounds, STILL_ACTIVE for the current process, duplicate retention and closure
on both x86/amd64.

With those prerequisites the real staging helper returns0 after29529
instructions. Its native value effects are Updates/`10.0.29628.1000-0` QWORD0,
Platform/NewLocation pointing at the selected directory, and Platform/Registered
DWORD0. These are pending startup state, not completed platform registration.
SecurityHealthService.exe subsequently references NewLocation atRVAs0x42fa,
0x4aac and0x4b00. Deriving that startup selection and registration handoff is
still required; setting Registered=1 by policy would fabricate completion.
The isolated core registration has separately been rerun with the runner's
registry plugin exposed to extension factories: it returns0, emits332 values
and75 key records, including published ownerSY/control8804 for the observed
CLSID and InprocServer32. Both probes still declare their SYSTEM subject;
the actual protected service token has not been established.

### SecurityHealth activation is separate from registration

For the inspected Server service and 10.0.29628.1000 core, service RVA
`0x49b8` resolves selector 1 through `CoreLocation` and selector 2 through
`NewLocation`. The latter path deletes `NewLocation`, validates and loads the
selected core, resolves `ServiceMainEx` and `ServiceHandlerEx`, and passes the
service context to the core. Selection and deletion alone are not activation
success.

The new core's `ServiceMainEx` is RVA `0x10220`. Its startup calls the previously
inspected registration routine `0x1c29c` at `0xffd2`. The `Registered=1` write
at `0x100b7..0x100cb` is later: startup passes through routines `0xf960`,
`0x10ff4`, `0x10528`, `0xf37c`, `0x1ca4c` and `0x12828` first. Some intermediate
errors are logged rather than fatal; do not replace that native control flow
with a policy-created success value. Successful isolated registration is not
proof that this readiness write is warranted.

A bounded `ServiceMainEx` probe with an explicitly declared service context
using the native service vtable stopped after 6,032 instructions at the missing
`GetProcessMitigationPolicy` API, before registration and with no registry
patches. The exact call uses the current-process pseudo-handle, policy 16,
a four-byte output and length 4. Native RVA `0xf71c` queries the policy and,
on a successful response lacking bit 0, attempts to set that bit. This is a
startup prerequisite still outside the completed registration probe; a declared
context is not proof of the protected service's actual token or process policy.

The shared service dispatcher must read `SERVICE_TABLE_ENTRY` and write
`ServiceMain` argv using the target pointer width, including COM-triggered
service activation. Native x86/amd64 regression coverage checks ANSI/Unicode
service names, code and name addresses above 4 GiB on AMD64, the actual argv
passed to the native entry, and null-entry rejection. Optional x86 register
diagnostics must not be required of AMD64 execution results.

### Bounded RedirectionGuard support and static payload extraction

The in-memory kernel now admits `GetProcessMitigationPolicy` and
`SetProcessMitigationPolicy` for policy 16 with explicit initial
`redirection_trust_policy` flags. The supported namespace contains no junctions:
reparse inputs are rejected, and no junction trust classification or audit log
is fabricated. Missing initial facts and unrelated policies still fail closed.
This is process-local execution state, not an offline registry completion mark
or evidence of a booted protected service's configuration.

The actual core helper at RVA `0xf71c` returns normally for all four initial
modes. Modes 0 and 2 perform native get/set transitions to 1 and 3 in 26
instructions; modes 1 and 3 only query and return in 17 instructions. No registry
patches are produced. A single resumed startup reaches instruction 7,789 and
stops at the probe's unowned `%ProgramFiles%\Windows Defender` DLL directory,
not at a mitigation API. Do not expand this into an emulated service lifecycle
as a prerequisite to static image construction.

The pinned SecurityHealthSetup PE contains 90 RCDATA payloads directly: eight
root files and two MUI files for each of 41 locales. The private update recipe's
`prepare_securityhealth` reads these resources without executing the wrapper.
Every relative path and payload SHA-256 matches the native extraction output.
The SHA-256 of sorted `relative/path:sha256` entries joined with LF, without a
trailing LF, is `834275c9265cece57d9db4ce6582295eed14661aada70b71a3ae513148befa7e`.
Wrong-source rejection also passes. This verifies extraction only; registration,
metadata publication and fresh-image health/WUA validation remain separate.

For the baseline `/Microsoft/Windows Security Health` registry parent, do not
assume the portable inheritance helper is byte-equivalent to native creation:
the inspected kernel mapping uses execute rights `0x20039`, while the portable
helper's mapping uses `0x20019`. The resulting inherited BUILTIN Users ACE
differs by `KEY_CREATE_LINK` (`0x20`), although owner/group/control match. A recipe
must resolve that explicit mapping difference before publishing Updates key
security; copying the parent or ignoring the comparison is not equivalent.
