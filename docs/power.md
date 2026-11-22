# Power ISA partition emulator

`emulator.power(memory=256MiB, cpus=1, mips=100, pvr=0)` creates an in-process
64-bit big-endian Power ISA machine that runs a **guest partition**. The core
implements the problem-state and supervisor-state architecture: fixed-point,
branch, condition-register, rotate/shift, load/store (including quadword and
load-and-reserve forms), SPRs, MSR, SLB management, storage, segment, program,
system-call, floating-point/vector-unavailable and decrementer interrupts, and
a basic floating-point and vector load/store subset. Hypervisor state is not
emulated; the hypervisor is supplied by the host.

## Hypervisor boundary

- **Hypervisor calls.** `sc 1` from supervisor state calls
  `m.on_hcall(handler)` with a `power_cpu`. The handler reads arguments from and
  writes results to registers; execution resumes after the `sc`. Returning a
  string stops `run()` with kind `hcall` after the call. Without a handler,
  `run()` stops with kind `hcall` and PC on the `sc`. Go code can register
  native handlers per r3 token in `Machine.Hypercalls`; they take precedence
  over the scripted handler, so calls can move to Go as they are confirmed.
- **Partition page table.** Translation uses the CPU's SLB and a host-owned
  hashed page table: `m.map_page(vsid, offset, real, shift=12, segment_1t=False,
  write=True, execute=True, size=None)` (`size` maps consecutive pages) and `m.unmap_page(...)`. `offset` is the page's
  offset within its segment; the page size comes from the SLB entry's L/LP bits
  (4 KiB, 64 KiB or 16 MiB). A hypervisor-call handler typically maintains it.
  `m.set_hashed_page_table(groups)` creates a slot-addressed ISA 3.0 HPT
  (power-of-two PTEGs, at least 2048), entering existing mappings.
  `m.hpte_read(slot)` returns its two doublewords; `m.hpte_write(slot, dw0,
  dw1)` replaces an entry and updates translations, including invalidation.
  Each group has eight slots. If more than one slot maps a virtual page,
  translation follows the first matching primary slot, then the secondary group.
  Invalidating one slot preserves any surviving mapping.
  `m.identity_segments(enabled=True, guest_ranges=[])` resolves missing
  segments as 256 MiB identity segments (VSID = ESID). Each
  `(first_esid, end_esid)` tuple reserves a half-open interval for native guest
  segment interrupts. Reconfiguration drops synthesized entries and retains
  guest-written SLB entries.
  CPU loads and instruction fetches set HPTE reference. Stores set reference
  and change, including cached translations. A translated, tagged AS `stq`
  also sets TS (DW1 mask `0x4000000000000000`). Later ordinary stores can
  clear quadword tags while the page's TS stays set. Backend inspection
  leaves these bits unchanged. Entry writes can clear them, and checkpoints
  retain their current values.
- **Extensions.** Every word the core does not implement is offered to
  `m.on_illegal(handler(cpu, word))`. Returning true means the handler performed
  the instruction (execution continues at the next word unless it set `pc`);
  false raises an illegal-instruction program interrupt; a string stops `run()`
  with PC still on the word. Processor-specific extensions belong in the
  caller's handler, not in this core.

## Processor extensions

The ordinary ISA subset includes `mtvsrd` and `mfvsrd`, moving bits between a
GPR and the first VSR doubleword. FPRs alias doubleword0 of VSR0..31, including
scalar arithmetic, vector memory transfers and read-only inspection. The undefined
second doubleword retains its existing bits. Lower-bank availability follows
MSR.FP and upper-bank availability MSR.VEC, independently of MSR.VSX; a missing
facility raises its unavailable interrupt before modifying the destination.
See [Power ISA2.07, Book I p110](https://fileadmin.cs.lth.se/cs/education/EDAN25/PowerISA_V2.07_PUBLIC.pdf).

`fcfidu` converts unsigned64-bit integers using all four FPSCR rounding modes;
`fctiduz` and `fctiwuz` truncate floating-point values to unsigned64-bit and
unsigned32-bit integers respectively. These
operations update their defined rounding and exception status, preserve the
destination on enabled invalid conversions, and deliver enabled exceptions
according to MSR.FE0/FE1. `fctiwu` converts to unsigned32-bit using all four
FPSCR.RN modes, including ties to even for RN0 and defined FR/FI status.
`mtfsb0` clears its selected writable FPSCR bit and
recomputes VX/FEX summaries. Other floating-point operations retain the basic
subset described above; this does not claim complete IEEE exception handling
for every arithmetic instruction.

`dctdp` and `drsp` convert between decimal32 storage and decimal64 registers.
`dqua` and `dquaq` quantize decimal64 and decimal128, and `dcmpu` and
`dcmpuq` compare those formats. These operations use densely packed decimal
digits and preserve the exponent of an exact conversion when it fits the
destination format. Decimal128 operands occupy an even/odd register pair.

`frim` rounds down, `frip` rounds up, `friz` truncates and `frin` rounds to the nearest integral
floating-point value with ties away from zero, independently of RN.
They preserve signed zero and NaN payloads, quiet signaling
NaNs when VE is disabled, and preserve the destination and FPRF on enabled invalid.
They clear FR/FI and leave XX unchanged, including for fractional inputs; the record form
updates CR1. See Power ISA Book I, section4.6.7.3 (Floating Round to Integer).

`fcpsgn` copies FRA's sign onto FRB's remaining bits, including an unchanged
signaling NaN payload. It leaves FPSCR unchanged; its record form copies the
existing summary to CR1. See Power ISA Book I, section4.6.5.

`emulator.power(extensions=["as"])` enables PowerPC AS instruction forms:
load/store multiple doubleword (primary opcodes 58/62 with DS-form extended
opcode 3: registers RT..31 at consecutive doublewords), load/store string
doubleword indexed (31/565, 31/693) and immediate (31/629, 31/757), and the four MDS select forms (`selii`,
`selir`, `selri`, `selrr`). Select tests XER bit 32+XBI, with signed five-bit
immediates. AS integer comparisons update FXCC (XER 36:39) independently of
the selected CR field, and integer record forms also update FXCC. This follows
[PowerPC AS Book I v2.00](https://wiki.raptorcs.com/w/images/4/49/Book1tags.pdf),
sections 3.2.2 and 3.3.11. Other undefined encodings still reach `on_illegal`.

In AS mode, `lq` sets XER T02/T07/TAG from the pointer type mask, loaded data
and memory tag; `settag` sets TAG to1 independently of prior loads. `stq`
writes TAG without consuming it. Ordinary stores clear affected memory tags.
`cmpla` compares unsigned addresses only when their architectural space
prefixes match, otherwise recording Incomparable in CR and FXCC. These rules
follow Book I pages43,48,70,96; tags and XER are included in checkpoints.
In tags-active mode, `mcrxrt BF` copies `0 || XER[41:43]` into the selected
CR field while preserving XER and the other CR fields (Book I page97).
`dtcs. RA,RS` tests the packed-decimal sign nibble, records negative for B/D
and positive for every other encoding in CR0/FXCC, clears the destination's
sign nibble and XER CA, and preserves the remaining state (Book I page94).
It requires tags-active mode, including for zero magnitudes.
In that mode, `addc` and `subfc` capture binary carries at all sixteen
nibble boundaries in XER DC and their OR in DS. `dsixes RA` materializes
a six in each nibble whose DC bit is clear, preserving XER/CR. Add-carrying
forms (`addc` and `addic`) also record OC at the original first operand's
48-bit or 24-bit offset boundary. Extended arithmetic preserves DC/DS.
These follow Book I pages34-35,61,94 and support native multiword packed
decimal arithmetic without a separate BCD arithmetic engine.

With the AS extension and MSR[TA] set, `scv LEV` saves the following address
in LR and the full-function MSR bits in CTR, preserves SRR0/SRR1, and enters
the translated vector `0xffffffffff003000 + LEV*32`. `rfscv` restores state
from CTR/LR and requires supervisor state. This is the AS interface in
[Book III](https://wiki.raptorcs.com/w/images/f/f6/Book3tags.pdf), pages12,62,71;
it is separate from the later ISA3.0 facility. Interrupt delivery preserves
TA. AS `td` options28/30 implement the logical-address checks in Book I
page73; those options remain ordinary integer traps when TA is clear and
are invalid for tags-active `tw`.

On the POWER9 profile, tags-active `td 29` permits forward indexing within
the 16 MiB segment of its base operand. The regression checks an in-segment
index, a segment crossing and the tags-inactive case. Backward indexing and
operands outside a 16 MiB segment address for this option retain the trap.

`m.hpte_find(vsid, offset, shift=12, segment_1t=False)` looks up a qualified
virtual page without an SLB, returning `(slot, dw0, dw1)` or `None`. VSID is
kept separate from the offset so virtual addresses wider than 64 bits retain
all their significant bits.
`m.hpte_probe(vsid, offset, base_shift=12, page_shift=12, segment_1t=False)`
searches both PTEGs using the base page size for hashing and the actual page
size for matching. It returns `(slot, secondary, dw0, dw1)`. On a miss the
words are zero and the slot identifies the first vacancy, or -1 if full.

`cpu.copy_real_page(destination, source)` copies
one aligned 4 KB real page with its quadword pointer tags, reservation effects,
and store watches. Invalid or unaligned ranges fail before any mutation.

`cpu.copy_real_tagged(destination,source,size)` copies arbitrary matching
quadword alignments in forward order. Full16-byte loads/stores carry tags;
partial leading and trailing stores clear destination tags. Bounds and
alignment are validated before mutation. It does not turn overlapping ranges
into a whole range memmove.

## Observation

`run(instructions=)` returns a record with `kind` (`budget`, `breakpoint`,
`interrupt`, `hcall`, `illegal`, `watch`, `machine-check`, `stopped`), `detail`,
`cpu`, `pc`, `instructions` and `seconds`. By default every interrupt stops
`run()` after delivery (SRR0/SRR1/DAR/DSISR are in the detail);
`stop_on_interrupts(vectors=[...], all=False)` narrows that once guest handlers
exist. `break_at(addr...)`, `watch(low, high)` (real stores), `history(keep=N)`
then `history()`, `disassemble(address, count)`, `events()` (illegal words,
first use of unmodelled SPRs, doorbells) and `interrupts()` (counts by vector)
are bounded observation points. `checkpoint()`/`restore(cp)` copy memory, CPU
state and the page table in memory. RAM is captured in independent 64 KiB
blocks. Zero blocks require no payload, and other blocks are compressed into
the checkpoint as they are read. Restoring a core checkpoint requires the
same memory size, thread count, PVR, nominal instruction rate and AS mode.
A paused machine can additionally capture
script-owned firmware and device state with `cp = m.checkpoint(state=roots)`.
Pass the mutable dicts, lists and native devices used by callbacks. On
`m.restore(cp)` they rewind in place, including shared references, COW block
overlays, memory channels, the TCP client and the TN5250 terminal. A checkpoint
with script state belongs to its originating machine and can be restored
repeatedly within that execution.

`cpu.set_running(False)` parks a CPU
without discarding its registers; `set_running(True)` releases it. The
read-only `running` field reports this state. `run()` returns `idle` when all
CPUs are parked. Firmware may call `cpu.yield_quantum()` to give other CPUs
their next scheduling turn after the current instruction. These operations
and checkpoint restoration require no host threads or processes.
`cpu.wait_for_interrupt()` suspends execution while keeping the decrementer
live; `cpu.wake()` resumes it for a backend event. `waiting` reports this
state independently of `running` (firmware parking). When all unparked CPUs
wait, the virtual clock advances to the earliest enabled decrementer deadline.
No enabled deadline produces an `idle` stop. Clock offsets and wait states
are restored by checkpoints.
`cpu.set_external_interrupt(True)` asserts a level-sensitive external input.
It is delivered at an instruction boundary when MSR[EE] permits it, including
while waiting. The level stays pending across masking and interrupt entry
until the backend withdraws it with `False`; it does not release parked CPUs.
Checkpoints capture the input level.

Reservations cover a 128-byte real-memory granule, as on POWER9. A live
reservation permits a conditional store elsewhere in that same granule;
another CPU's write anywhere in the granule invalidates it.

`m.cpu(i)` returns a `power_cpu` with fields `pc msr cr lr ctr xer srr0 srr1 dar
dsisr dec fpscr instructions` and methods `gpr(i)`, `set_gpr(i, v)`, `set(pc=,
msr=, ..., gpr={i: v})`, `spr(n)`, `set_spr(n, v)`, `crbit(n)`, `set_crbit(n, v)`,
`read(ea, size)`/`write(ea, data)` (translated, no interrupts), `load(ea, size)`/
`store(ea, size, value)` (architected, may raise interrupts), `translate(ea)`,
`slbmte(rs, rb)`, `slb()`, `hpte(ea)` (architected page-table entry doublewords
built from the host page table, for hypervisor lookups), `reservation()` and `stop(kind, detail)`. Real memory
is accessed with `m.read(address, size)` and `m.write(address, data)`.
`cpu.hpte_slot(ea)` returns the actual HPT slot, including secondary-group
placement, or `None` if no matching segment or slot exists. It is read-only
and does not resolve segment misses. `hpte(ea)` preserves stored entry bits
when a slot-addressed HPT exists; otherwise it synthesizes entry words.

`m.pointer_tags(address, size)` reads the hidden quadword tags over an aligned
real-memory range. The result is a byte bitmap, MSB first in ascending 16-byte
address order. It does not execute guest instructions or modify CPU state.

`m.map_window(effective=, real=, size=, write=True, execute=False, user=False)`
installs an explicit backend-owned linear mapping while translation is enabled.
It can describe firmware real-memory aliases independently of guest HPT slots
and invalidation. Windows must be aligned to4KB, fit real memory, and not
overlap each other. They take precedence over HPT mappings; permissions apply
to data, instruction, and user accesses. Windows are captured in checkpoints.
`m.write`/Go`WriteReal` clear memory tags and all affected CPU reservations,
including stores made by device/firmware backends.

## Execution engine

On linux/amd64 the core compiles runs of guest instructions into native code
(the block JIT, `emulator/power/jit*.go`); elsewhere, or with
after `m.set_jit(False)`, every instruction is interpreted.
The JIT is exact: blocks retire whole instructions with the interpreter's
results and instruction counts, never raise interrupts, and leave to the
interpreter before anything they cannot complete natively (a TLB miss, a
page-crossing access, a store to a page holding compiled code, to a watched
range or to another CPU's reservation granule, a taken trap, a misaligned AS
quadword, or an instruction without a native form, such as every hypervisor
call). Time-base, IC, VTB, PURR and DEC reads compute the interpreter's count
at that instruction, so budgets, decrementer deadlines and time stay
identical. Instructions that can make an interrupt deliverable or change the
block's mode (`mtmsrd` setting EE, `rfid`, AS `rfscv`, DEC writes) end their
block and return to the run loop, which checks interrupts as the interpreter
does.

- Blocks never cross a 4 KiB page and are keyed by real address and the MSR
  bits they depend on (SF, TA, IR, DR, PR). Stores to a real page with blocks,
  from any CPU, DMA or `WriteReal`, discard them before the bytes can run.
  After instructions have run, change `Machine.Mem` only through `WriteReal`
  or CPU stores.
- Blocks jump directly to blocks in the same page. Indirect and cross-page
  branches use a per-CPU target cache, validated against the translation
  generation, mode and HPTE slot version. Each block's entry reserves its
  length from the run's allowance, so chains stop exactly at budgets.
- Pages with breakpoints (at the executing alias) use private blocks that stop
  before each breakpoint; changing the breakpoint set discards compiled code.
- Translations are cached per CPU in direct-mapped, hashed data and
  instruction TLBs (16384 entries each). Identity segments
  (`Machine.IdentitySegments`) resolve without SLB entries, so the SLB holds
  only what the guest wrote. A translation through a hashed-page-table slot carries the
  slot's version: replacing or removing a valid entry advances only that
  slot's version, while software-bit and newly-set R/C updates invalidate
  nothing. A read fill of a writable page whose change bit is already set
  admits stores.

`m.state_digest()` hashes memory, tags, the instruction count, the time base
and every CPU's architected registers and SLB. Equal digests after the same
instruction count show that two engines reached the same state; use it to
check that an engine change preserves behaviour (compare a run after
`m.set_jit(False)`).
`m.jit_stats()` reports blocks compiled and invalidated, code-arena
flushes, native runs, instructions and side exits, and `interpreted`: the 32
opcodes the dispatcher interpreted most often, each with `primary`,
`extended` (the extended opcode of forms 4, 19, 30, 31, 59 and 63), `spr` (for
`mfspr`/`mtspr`, else -1), `count` and why: `side_exit` (left a block, usually
a TLB miss), `budget` (fewer instructions remained than the next block's
length) or neither (no native form). Each interpreted instruction costs a
return to the dispatcher, so this list ranks the forms worth compiling.
`exit_reasons` counts side exits by cause: `tlb_tag` (no TLB entry for the
page in this privilege state), `tlb_gen`, `tlb_slot` (HPTE slot replaced),
`tlb_access` (entry not filled for stores), `page_cross`, `real_bounds`,
`store_slow` (a watch or several reservations), `reserved` (a store to
another CPU's reservation granule), `code_page`, `align` (AS quadword) and
`other` (traps, FP unavailable, long strings).

`m.hcall_native(token, name="", gprs={}, zero_fill=None, yield_quantum=False,
script_every=0, msr_set=0, wait=False, wake=None, remove=False)` answers a frequent
hypervisor call without entering Starlark: optionally zero a guest buffer
(`zero_fill` keys `address` and `length` registers, or a fixed `size`, plus
`mask`, `align`, `address_align`, `limit` and `end`), set result registers,
OR bits into the MSR, wait for an interrupt (a cede), wake another CPU
(`wake` keys `index`, the register holding its index, and `limit`, the
first index outside the contract), and end the quantum. Calls outside the
declared contract, and every `script_every`th
call, still reach the `on_hcall` handler, which remains the reference
behaviour. `m.hcall_counts()` returns calls by r3 token, native and scripted.

## Tests

`emulator/power` tests cover arithmetic carries and overflow, rotates, branch
and CTR loops, loads/stores, quadword and reservation semantics, SLB/page-table
translation with storage and segment interrupts, hypervisor calls, system calls
and `rfid`, the extension hook, the decrementer, checkpoints and breakpoints. A
differential test decodes random words with `golang.org/x/arch/ppc64asm` and
requires every word it assigns to an implemented mnemonic to execute without
reaching the extension handler. `TestJITMatchesInterpreter` runs random
programs of the natively compiled forms (with side exits, self-modifying
code, breakpoints, HPTE churn and AS tags) under the JIT and the interpreter
and requires identical state digests.

## Virtual-bus DMA

`m.rpa_block_list(address, maximum_capacity=16MiB)` inspects the demonstrated
absolute RPA block-list chain in real memory. It returns `capacity` and
`entries` with `address`, `real` and `size`, after checking the entire chain.
It does not transfer bytes or change tags, reservations or translation state.
See [the format and supported header profile](formats/rpa-block-list.md).

`m.create_tce_table(index, entries)` creates a sparse 4KB-page DMA window
using the legacy virtual-bus TCE format. `m.tce_write(index, slot, word)`
returns a boolean; `m.tce_write_many(index, slot, words)` validates and
installs a consecutive list atomically. `m.tce_read(index, slot)` returns the exact word, or
`None` for an unknown table/slot. Slots are entry indices, not byte offsets.
Valid entries require a complete real page within partition memory.
Cache bits are retained separately from the 40-bit real page number.
`m.dma_read(index, address, size, lp=0)` returns bytes or `None` on an access
fault; `m.dma_write(index, address, data, lp=0)` returns a boolean.
Both operations check validity and partition ownership; writes also require
the write bit. Transfers may cross noncontiguous pages. Every page is checked
before any destination bytes change. DMA writes clear pointer tags and CPU
reservations through `WriteReal`. Tables and their contents are captured by
machine checkpoints. These APIs implement virtual-bus TCEs, not PCI TCEs.

`m.crq_register(unit, table, address, size)` binds a command/response queue
in a checked DMA window; its pages may be noncontiguous. `m.crq_post(unit,
entry)` publishes a16-byte entry only when the consumer has released the
current slot (valid bit clear). A full queue or DMA fault changes neither
memory nor the producer position. `m.crq_unregister(unit)` releases the
binding without clearing memory or TCEs. These methods return booleans.
Queues and producer positions survive checkpoints; device interrupt routing
belongs to the backend. Registration requires page-aligned storage in whole
4KB pages, with read/write access through the supplied translation table.

`m.crq_attach_optical(unit, device, unsupported_mads=[], lun=0x8000000000000000)` attaches a read-only
RPA/SRP optical target backed by an abstract block device with 2048-byte sectors.
`unsupported_mads` contains `(format, type)` pairs for optional vendor
negotiation messages which should receive the protocol's unsupported status.
`m.crq_request(unit, high, low)` consumes the two request words and returns a
record with `posted` and `error`. It implements queue initialization, capability
and adapter-information MADs, SRP login, and SCSI commands with direct or
indirect DMA descriptors. The backend supplies firmware policy and interrupt
notification after a reply is posted. Unknown operations return explicit errors.

`m.crq_attach_disk(unit, device, lun=0x0001000000000000, vendor='TINYRNGX',
product='Virtual Disk', revision='0001', serial='1')` instead assigns a direct-
access SCSI target. Its geometry and writable/flush capabilities come from the
block device. `block.overlay(block.blank(size))` supplies zero-initialized
portable storage without allocating its entire virtual capacity. The memory
overlay retains actual changed bytes; it is not a host file or a mounted disk.
The target implements bounded READ/WRITE6/10/12/16, capacity, identity,
reservations, sense and cache synchronization. WRITE SAME16 repeats a real
sector pattern with bounded buffering; a zero-capable backing can perform
the equivalent zero operation directly. WRITE AND VERIFY10 reads the actual
backing after writing, with byte comparison when BYTCHK=1. Backing I/O or
verification failures stop without publishing a successful completion.
Unadvertised VPD pages return
ILLEGAL REQUEST; unimplemented commands remain explicit errors.

SRP data-out uses the same checked direct/indirect descriptor decoder as
data-in. Writable commands prepare their result without changing storage;
the transport preflights the completion IU and queue slot before committing
disk bytes. A full ring or inaccessible completion destination leaves both
disk and protocol state unchanged. A core-only machine checkpoint copies
target protocol state. Include the writable block overlay in the checkpoint
roots to rewind its backing bytes too. For a disk image that survives the
execution, export the immutable file returned by `disk.snapshot()`.

`m.crq_attach_optical(unit, None)` attaches an empty drive in its assigned
slot. It answers INQUIRY and reports medium absent until a disc is inserted.
`m.crq_change_optical_media(unit, device)` replaces a disc in the existing
drive without resetting its CRQ, SRP session or reservation. Removal obeys
ordinary and persistent locks while the tray is closed; the guest can
explicitly eject before replacement. Existing initiators independently receive
medium-changed unit attention. Copies/checkpoints retain their own pending
attention and previous immutable media. The API accepts a portable block device
with complete 2048-byte sectors.

`cpu.encode_issi(sidecar, headers, page, stamp, flags)` prepares ISSI disk
framing ([power-firmware.md](formats/power-firmware.md)) from three distinct
real-memory buffers of 512, 64 and 4096 bytes.
Bit1 saves original sector headers and displaced data words, bit2 captures
hidden pointer tags in those headers, and bit4 stamps data-sector control words
and the first/last sidecar words. Bits are numeric masks1/2/4. The page is4KiB
aligned. Tag capture precedes ordinary control stores, which clear overlapping
tags. Hypervisor policy selects the call ABI. `binary/issi` also restores
displaced data and
preserves received controls for the consumer's integrity check. A stamp is not
a checksum. Invalid sizes, overlaps, flags and zero stamps fail before mutation.

`cpu.decode_issi(sidecar, headers, page, flags)` performs the matching restore.
Mask1 restores marked pointer tags; mask2 preserves received data-sector
controls at sidecar+136. Mismatching controls are retained for the consumer's
check.
Tag restoration requires the AS extension when the saved bitmap is nonzero.

`cpu.capture_page_tags(headers, page)` exposes the shared tag-extraction step
without ISSI framing. It updates64 bytes of original native sector headers
from the aligned4KiB page's actual hidden tags, preserving zero-bitmap headers
and all source bytes/tags.

`m.register_hash_process_table(process_table, page_size, table_size)` registers
the POWER9 hash/SLB PATE1 profile:38-bit process-table field,3-bit page-size
field and table-size exponent0..24. The field is not a guest table pointer in
this profile. Registration retains the current HPT/SLBs, clears UPRT/HR/GTSE
in every CPU's LPCR, and invalidates translation caches. `m.hash_process_table`
is the encoded registered word, or None before registration; checkpoints
preserve it and the CPU controls. Firmware policy may restrict this to
PAPR H_REGISTER_PROC_TBL flags18. Radix, memory-resident segment tables and
guest translation shootdown remain outside this API's contract. See the
[PAPR implementation reference](https://github.com/qemu/qemu/blob/master/hw/ppc/spapr_hcall.c)
for the register-field encoding.

The endpoint reports its configured wire-format LUN; peripheral, flat and PAPR
logical-unit encodings of that same address reach the assigned optical device.
The default is target0/channel0/LUN0 in PAPR logical-unit addressing
(`8000000000000000`). Legacy RPA clients can reserve zero inventory entries
as absent, so firmware policy should select a compatible nonzero encoding.
`scsi.Optical` implements discovery, readiness/sense, media capacity, bounded
reads and read-only protection over the actual block device. MODE SENSE6/10
reports fixed error-recovery and DVD-ROM capability pages; changeable values
are masks, and the target has no writable mode parameters. GET CONFIGURATION
filters ordered feature descriptors by request type and starting feature,
retaining the complete length when allocation truncates the response. Its
current profile follows actual media presence. Ordinary and persistent
prevent-removal states are independent; persistent prevent does not block an
initiator's eject command. Additional MMC operations remain explicit errors
until implemented. Data, command
completion and the queue slot are checked before DMA writes begin. Replies
include the actual residual and sense data, and correlate through the request
tag. Checkpoints retain protocol and optical state while sharing immutable
media; they do not capture mutable firmware callback dictionaries.
