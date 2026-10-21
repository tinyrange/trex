# RFE PC backend (experimental)

`rfe.backend()` requires a supported 64-bit native-JIT host and executable
memory. It is exposed by the trex Starlark runtime and
uses the generated `renvo.dev/rfe/x86` CPU from `renvo/emulators/x86.rfe`, not
KVM, QEMU, a subprocess, or a runtime build/extraction of the emulator. Guest
blocks are JIT-compiled in memory by the existing Renvo IR/native engine. The
CPU is a separately authored variant of `amd64.rfe`; the original is unchanged.

The adapter implements the same portable `hypervisor.X86` contract used by
`vmm/cc`. The PC's BIOS, disk attachments/overlays, IDE, VGA and keyboard device
code are shared. Use `vm.extension("rfe.v1").state()` for bounded CPU/device and
text-console inspection. The corresponding cc extension remains `cc.v1`.

The variant decodes 16-, 32- and 64-bit code. Real/protected/v8086 execution
includes segmented addressing and stacks, code-size changes, 386 non-PAE
paging, interrupt gates, TSS stack changes and v8086 IRET. The default PC
execution path tiers hot 16-, 32- and 64-bit scalar/branch/RAM/stack blocks to
native code. Privileged, device, x87 and unsupported instructions use precise
architectural slow paths; this is not an interpreter-only backend. Native
initialization/reinitialization failure is an error, never a silent mode switch.

`PCJIT` keeps live code and translation domains rather than imposing a fixed
block/domain count. Its executable mapping grows from an allocation hint;
invalidated fragments lose admission individually, and host pages are discarded
when all fragments sharing them are dead. Growth rebases prepared calls, fault
sites and profiling symbols under the same serialized W^X publication rules.
Untouched hot code is not thrown away to recycle the entire arena. Native entry
offsets still use a 32-bit arena-relative format; retired offsets are tombstoned,
not reused. This is not a promise of unbounded host memory or unlimited lifetime.

Basic blocks end at control flow, scheduling boundaries or the next code page,
not after sixteen instructions. Regions follow the observed resident hot path
until a repeated node or a genuine boundary, without a 256-instruction/search
quota. Wide bodies carry exact native retirement/memory progress; bodies whose
spill peak exceeds the shared fast frame use a compiler-sized private frame and
a correspondingly grown native stack. Precise budgets, side exits and faults
are checked independently of static body width.

Cold one-pass PCs stay interpreted. Reused code uses observed interpreter and
compilation costs for promotion, and measured native-leaf/session costs for
session payback; there are no PC-specific 4/4/16/128 heat tiers or loop-only
admission rule. Ordinary native leaves publish their validated entry without
requiring a foreign session. Reused one-shot/call/return paths can link when a
successor is resident. Repeated unprofitable sessions accrue measured host-time
loss, paid down by ordinary native work; a successful missing-page refill can
retry immediately. The model learns from actual execution, not a mandatory
synthetic calibration stage, and does not promise optimal decisions for every
workload.

On the supported foreign-call path, native execution polls an atomic notification
at dispatcher selections and complete loop iterations. The PC scheduler arms
that notification for the actual PIT deadline, IRQ, cancellation or device event,
not a fixed 4,096-instruction native/512-instruction Go quantum. Architectural
mode/privilege/IF/shadow changes still return at precise boundaries. Explicit
instruction-budget APIs retain exact budgets. Hosts without a safe foreign-call
bridge retain conservative short-call fallbacks; these safety restrictions are
not removed by increasing an instruction constant.

MOVS/CMPS/STOS/LODS/SCAS lower one precise guest iteration at a time in
16-, 32- and 64-bit modes. REP uses guarded native execution, never host memcpy.
Zero counts, DF, legacy segment/address-size wrapping, long-mode FS/GS bases,
32-bit-address register zero-extension, early REPE/REPNE termination, and
second-page fault/MMIO prefixes retain architectural semantics. XCHG, LOOP/JCXZ, LEAVE, PUSHA/POPA, segment-selector reads/pushes and
accumulator-pair sign extension also have native lowerings, with operand/address
width and precise stack-fault differential coverage. Scalar native
supervisor mappings support CPL 0, 1 and 2; CPL 3 uses user permissions.
Privileged, unsupported ISA, and device operations retain the architectural
path, including fault delivery, interrupt shadows and TSC accounting.

Owned native RAM uses a growable collision-preserving mapping table, not a
64-slot direct-mapped cache. Physical code/PTE byte watches are shared across
aliases and address spaces. Every native store checks the exact bytes, including
stores using cached loop address facts: disjoint data on code/table pages remains
native. Fetch checks execute/MMU access and CS limits for each byte, including
straddling instructions. Exact instruction-range proofs revoke only affected bodies and derived
regions before a physical byte or consumed mapping changes, including inactive
root/mode publications. Disjoint code on the same page remains native. Full
mapping flushes revoke execution authority immediately; unchanged byte snapshots
can recover after a fresh execute/mapping check without rebuilding their retained
dependency storage. Closing/reclaiming the owner releases those dependencies.

Live-proof byte watches are reference-counted. Bytes fetched only for decoding
retain a separate watch: native stores can update their shared physical decode
epoch and remain native when no live body or page-table word depends on them.
All aliases observe the same version; live-code/PTE stores and epoch overflow
still exit before the store. Version storage is separately rooted, pinned and
checked for execution-state/guest-RAM aliases.

Code modes keep separate successor publications over the same RAM owner.
Owned public link directories grow with their live working set and preserve
collision chains rather than evicting valid PCs at a fixed 1,024-entry limit.
Growth starts empty, never moving a proof-bound descriptor into an unrevocable
copy. Generic compatibility tables remain bounded. Native selection accepts
byte-aligned x86 targets, validates immutable arena admissions and checks full
PC/generation/count tags; tombstones do not hide later colliding entries.
Link generations revoke whole contexts without clearing 64 KiB on every
mutation. Host dispatch hashes actual instruction alignment, and unchanged
region candidates are not rebuilt on every dispatch.

CR3/root/privilege-tagged native mappings survive address-space switches. Code
segment identity remains a separate execution proof, not a duplicate RAM owner.
Reverse dependencies retain the consumed PDE/PTE words of inactive roots, so a
physical table write revokes dependent mappings even while another root runs.
Ordinary PTE changes use hash deletion rather than scanning every mapping.
INVLPG also revokes cached sibling slices of a large mapping when its addressed
4 KiB slice is absent. Unrelated data mappings survive; full permission-control
flushes still revoke all applicable grants. Hardware A/D-only walker updates do
not revoke unchanged permissions. Native and architectural accesses preserve
CPL/supervisor/CR0.WP and dirty-bit requirements.

RAM/watch pin leases are shared across root/privilege views, with incremental
pinning of newly allocated byte masks. Per-context metadata has its own lease;
closing the arena releases both. Native code cannot retain borrowed integer
addresses after a call. Firmware/DMA spans and BIOS scratch/BDA writes notify
the same physical barriers as guest stores. Unknown/untracked physical owners
and UEFI retain conservative revocation rather than receiving an unproven
coherence contract.

The `state()["interrupts"]` diagnostics include `jit.native16`, `jit.native32`,
`jit.native64`, `jit.native_memory`, `jit.linked`, `jit.native_sessions`,
`jit.regions`, tier retirement counts, promotions, arena
resets, invalidations and compile failures. `jit.identity_misses`, `jit.epoch_misses` and
`jit.version_faults` distinguish code-proof failure reasons. OS smokes require actual native
retirement (including 32-bit code for enhanced Windows/Windows 98), not merely
an enabled flag. A debugger execution breakpoint temporarily single-steps the
architectural path so a compiled block cannot skip its requested stop.

## Reproducing OS probes

From the private recipe checkout, supply existing media explicitly:

```
go run ./trex scripts/smoke/rfe_msdos_622.star rfe dos.png disk1.img disk2.img disk3.img
go run ./trex scripts/smoke/rfe_msdos_622.star cc cc-dos.png disk1.img disk2.img disk3.img
go run ./trex scripts/smoke/rfe_windows_311.star rfe enhanced win311.png dos1.img dos2.img dos3.img win1.img win2.img win3.img win4.img win5.img win6.img
go run ./trex scripts/smoke/rfe_windows_98_se.star rfe win98.png win98se.iso
```

The probe builds the installed image in memory using existing recipes. Replace
`rfe` with `cc` to keep the same media, image construction, memory size, CHS,
overlay and guest actions. `scripts/debug/rfe_pc.star` is observation-only;
the OS smokes below make explicit success assertions.
The DOS smoke asserts the startup batch's HELLO message and C:\> prompt. The
Windows 3.11 and Windows 98 SE smokes wait for the application, type a unique
marker into Notepad, open File with the PS/2 mouse, save, and assert the changed
content by reading the guest FAT disk. Windows 98 startup can take
several minutes; readiness matches the document glyphs rather than a fixed delay.
No media is bundled or downloaded by tests.

Observed bring-up:

* MS-DOS 6.22: startup batch and C:\> prompt reached under both CPUs, with
  visible VGA capture. Interactive keyboard command completion is not claimed.
* Windows 3.11 standard (`WIN /S`) and default 386 enhanced mode (`WIN`):
  reach Program Manager and open
  `HELLO.TXT` in Notepad, with the expected Windows 3.11 document visibly
  rendered under both RFE and cc. Fresh RFE and cc graphical smokes additionally
  verify keyboard input, a PS/2 mouse-selected File menu, and Notepad's Save
  by reading the typed marker back from `HELLO.TXT` on the guest FAT disk.
  The enhanced-mode smoke also asserts that CR0 retains protected mode and
  paging, ruling out standard-mode fallback. BIOS reads/writes update guest
  page-table Accessed/Dirty bits; without Dirty on disk-loaded code Windows
  incorrectly discards its own code during its DPMI pageable-memory setup.
* Windows 98 SE: fresh RFE and cc smokes reach Explorer and open the hello
  document in Notepad, then verify keyboard editing, mouse-selected File Save,
  and the saved marker on the guest FAT disk. The native smoke waits for the
  complete typed marker to be rendered before using the mouse, then polls for
  actual FAT persistence after Save: an empty PS/2 queue does not prove that
  the application has processed the input. The RFE fix makes VM86 I/O consult
  the TSS permission map even at IOPL3; otherwise the BIOS timer EOI bypasses
  Windows' virtual PIC and blocks its real-mode disk mapper's priority events.

Known incompleteness includes parts of x87 (transcendentals, BCD, environment
pointers, FX state), legacy PAE, hardware task switching, complete segment/gate
validation for implicit accesses, PIC priority rotation/level modes, and full
PIT channels/read-back/BCD behavior. The BIOS now handles IRQ1, translated
keyboard scan codes, its BDA ring, and INT 16h polling/blocking reads. The PS/2
BIOS supports C2 configuration and three-byte IRQ12 far callbacks,
including both PIC acknowledgments. Some enhanced-keyboard combinations remain
incomplete.
cc's accelerator does not currently implement the optional software A20
callback. Keep these gaps distinct from demonstrated boot/application surfaces.

## Measured integration check

On the development Linux/amd64 host, fresh-image unprofiled smokes completed
as follows. Wall times include image construction and all guest actions; these
are workload/host observations, not portable performance guarantees.

| Smoke | Previous structural-limit run | Local-invalidation/successor run |
| --- | ---: | ---: |
| MS-DOS 6.22 startup/prompt | 4.515 s | 5.601 s |
| Windows 3.11 standard keyboard/mouse/save | 31.443 s | 20.241 s |
| Windows 3.11 enhanced keyboard/mouse/save | 29.592 s | 20.941 s |
| Windows 98 SE keyboard/mouse/save | 177.407 s | 146.644 s; repeat 147.866 s |

The two final Windows 98 runs reached Notepad at 135.176 s and 135.868 s,
verified the complete typed marker, used the PS/2 mouse to select File/Save,
and read the edited marker back from the guest FAT disk. Both had zero arena
resets and zero compile failures, with 552.5–554.6 million native 32-bit
instructions. Memory exits were 0.948–1.677 million, versus 3.98 million in
the previous 177.407-second run.

This is approximately a 17% whole-smoke improvement, **not the 80-second goal**.
Intermediate experiments varied substantially; the approximately 129-second
experiment was not reproduced by the final pair and is not the headline result.
Broader segment/flags lowering and cross-root body-sharing experiments were
removed after they regressed timing or showed negligible reuse. Profiling still
shows material interpreter/dispatch, native-transition, compilation/GC, and
shared recipe/readiness costs. No cc/QEMU performance win is claimed. The earlier
same-smoke cc measurement was 63.722 s, not a new comparison run for this revision.

Focused CPU/proof/alias/fault suites, frontend/device integration and native-call
cross-builds passed. The required unchanged 60-second/4-GiB Renvo preflight passed
in 37 s after a cold generated-code rebuild attempt took 63 s; no gate was
relaxed. Full merge-queue validation was not run locally.

## Development

From `trex/renvo`, with `GOWORK=off`:

```
go run ./cmd/renvofmt -w emulators/x86.rfe
go run ./cmd/rfegen
go run ./cmd/rfegen -check
go test ./cmd/rfegen ./rfe/x86
```

Edit the RFE, not `rfe/x86/*.go`. Checked-in generated files make the CPU
importable without a runtime build or temporary source workspace. The command's
regression test checks that generated files exactly match the authored archive.
After removing an authored section, `go run ./cmd/rfegen -prune` removes only
obsolete files carrying this generator's exact header; unexpected handwritten
files are still rejected.
From `trex`, run `go test ./vmm/rfe ./vmm/cc ./frontend/starlark`.

## Execution benchmark

From `trex`, run:

```
go test ./vmm/rfe -run '^$' -bench '^BenchmarkPCExecution$'
```

The same real ALU/RAM/stack/branch loop runs through the PC/device scheduler in
interpreter and native tiers for each code size. Construction and warmup are
excluded. Results include guest instructions per second and the fraction retired
natively, so a nominally enabled JIT cannot masquerade as a native measurement.
These hot-loop numbers are not whole-OS startup or application throughput.
Readiness probes decode each screenshot once with `image.decode`; repeatedly
using `image.pixel` on encoded PNG input measures image decoding as well as the
running guest and can badly distort end-to-end timings.
