# System/370 and ESA/390 conformance tests

See [the emulator API and operating-system recipes](../../docs/s390.md) for
normal use. This directory's CPU implements both System/370 and ESA/390;
testing their shared instructions improves both modes.

## Cornwell/Shirriff CPU tests

[cornwell_test.go](cornwell_test.go) adapts **all 116 test functions** and
**all 209 decimal table entries** from Richard Cornwell's
[S370 `emu/cpu/cpu_test.go`](https://github.com/rcornwell/S370/blob/da2e3f45a1ac73cf16814933546e6183f3136451/emu/cpu/cpu_test.go),
pinned at `da2e3f45a1ac73cf16814933546e6183f3136451`.
Copyright 2024 Richard Cornwell; the upstream file credits Ken Shirriff for
the original test cases. Its full MIT copyright and permission notice is
retained in the adapted file. Thank you to Richard for sharing the tests,
diagnostic media, and advice about tape timing and backward reads.

These are ordinary offline Go tests under `TestCornwellS370`; none are skipped
or marked expected failures. They cover integer arithmetic, logic, branches,
storage, strings, protection and privileged instructions, packed decimal,
and short/long hexadecimal floating point, including seeded randomized cases.
The original names remain searchable. The decimal input table is unchanged.

[cornwell_harness_test.go](cornwell_harness_test.go) binds the fixtures to our
CPU, storage and production instruction/interrupt loop in System/370 BC mode.
Each test has an isolated machine. Fixture word accesses select the containing
aligned word and update storage reference/change bits, matching the upstream
helpers. Register layout, PSW fields, storage keys, and channel masks are mapped
to our representation. No upstream instruction implementation is used.

Differences were investigated against the architecture; a mismatch alone is
not evidence that either emulator's author is wrong:

| Case | Adaptation and basis |
| --- | --- |
| Privileged SSK | Expect key `44`, rather than `40`, for this machine's seven-bit storage keys. SSK sets all seven bits with DAT hardware in both BC and EC modes; BC-mode ISK still returns five. See [IBM Model 168 Guide, GC20-1755-2](https://bitsavers.trailing-edge.com/pdf/ibm/370/systemGuide/GC20-1755-2_370-168_Guide_Jun75.pdf), p. 13. The problem-state protection assertion is unchanged. |
| Decimal row 30 (zero-based), MP | The equal operand lengths cause specification exception `06` before the invalid decimal data would cause `07`. See [System/370 Principles of Operation, GA22-7000-6](https://www.bitsavers.org/pdf/ibm/370/princOps/GA22-7000-6_IBM_System_370_Principles_of_Operation_7th_ed_198003.pdf), interruption priority on p. 6-20 and MULTIPLY DECIMAL. The original row remains visible; the runner applies the documented expectation. |
| Random short AE/SE/ME/DE | The conversion helper returns true on success. Correct the inverted guards so successful cases actually execute; each loop must execute 1,000 cases. Reference calculations use the actual quantized short-HFP operands, retaining the original relative tolerance of `1e-6`. DER preserves CC, as the existing fixed DE vector also checks. |
| Random HER and AER | Check preservation of the low half of destination FPR4, rather than the unrelated low half of FPR0. |
| Random MR | Draw both operands from the local seeded generator so failures are reproducible. |

The suite exposed native CPU defects that are fixed here: add/subtract must
store their result before a completing fixed-point-overflow interruption, and
packed multiply/divide must retain algebraic signs even when quotient, product,
or remainder is zero. A negative overflowing decimal result that truncates to
zero must retain its sign too. Focused regressions also run these behaviors in
ESA/390 mode. See the fixed-point-overflow and decimal instruction descriptions
in [ESA/390 Principles of Operation, SA22-7201-04](https://0x04.net/~mwk/doc/s390/s390.html).

Decimal row 207 edits with overlapping pattern and source fields, which the
architecture leaves unpredictable (GA22-7000-6, p. 8-3). EDIT and EDIT AND MARK
fetch the source an aligned doubleword at a time, ahead of the result stores,
as System/360-class processors do; the row's original expectation,
`40f4f040f2f0` with CC 1, now holds unchanged.

## Cornwell's diagnostic tape

[scripts/inspect/s370_diag.star](../../scripts/inspect/s370_diag.star) fetches
[microsim360 `test_progs/diag1.tap`](https://github.com/rcornwell/microsim360/blob/cccea8cde6a9d5b6867a2f1629f24ba5b7a840e2/test_progs/diag1.tap)
at commit `cccea8cde6a9d5b6867a2f1629f24ba5b7a840e2`, verifies its 1,666,470-byte
size and SHA-256
`21c61161358fe72bc73271dd9ab66bf44eff7db5458d93886746b9475d39cfb3`, and mounts it
directly as SIMH. The diagnostic media are a separate upstream resource, not part
of the MIT test adaptation and not vendored here. The tape is an IBM 9020 D/E
diagnostic library (the UK air-traffic 9020 configuration); the user-supplied
D000 listing (`local/d000.lst` in the outer workspace, not redistributed)
documents its loaders. The tape's copy of D00104 is a later revision than the
listing: it loads the next section whatever processor it runs on.

[scripts/smoke/s370_diag.star](../../scripts/smoke/s370_diag.star) runs the
142 verified 9020E sections from fresh IPLs on the unchanged reel.
Thirteen jobs reach SDM's `EOJ  SDM JOB COMPLETED`. The pack scan ends
through the documented `F/` command.

1. IPL D00104 (GO/NO-GO), D00201 (machine test) and D00402 (hardcore CE
   bring-up). Each stops in a tight loop on any error and otherwise loads the
   next program; the last loads the System Diagnostic Monitor, SDM 12.
2. SDM waits for the operator INTERRUPT key (external interruption X'0040',
   `m.interrupt_key()`), reads a load message card from the reader, and runs
   the sections selected by the load message, printing
   `S Dxxxxx` when a section starts and `T Dxxxxx nn ROUTINES RUN` when it
   ends. Sections for absent unit types are reported `RNV ... UNIT TYPE xx NOT
   AVAILABLE` by SDM itself.
3. D62511 punches the detail deck. The smoke feeds the 256 raw EBCDIC cards
   to D62620 and D62630 in memory. The punch job also tests the paired 2821
   reader/punch buffers in D6A510, D6A521 and D6A530 and runs D30521 on
   the multiplexer. D30533 uses another job to exercise multiplexer channel
   programs in MACH storage. The punch-to-reader
   workflow is described in [FAA 9020 Maintenance Monitor Manual,
   FAA-2000-2, §1.4.2](https://bitsavers.computerhistory.org/pdf/ibm/9020/faa/FAA-2000-2_FAA_9020_Maintenance_Monitor_Manual_198306.pdf).
4. Separate tape jobs exercise the selector channel with two 2401 drives
   and the nine-track functional and interchangeability sections with one
   drive. D31534 transfers data and executes CCWs in the IOCE's MACH
   storage, including a chain with a masked PCI. The smoke checks D405F1's
   backward-read completion and D40604's
   gap and creep exercise. D40581–D405D1 exercise the seven-track 2401
   in separate jobs with and without a data converter. D41560 dumps one
   known record and reports the exact bytes, both file marks, and zero tape errors.
5. Two fresh 2314 volumes run D80501 through D80642 and D80652 through
   D80692. This covers track conditions, file masks, format erase busy
   status, selector HALT I/O during a read or write, Space Count recovery,
   actuator motion, seeks to the travel stop and recovery by recalibration,
   and reads, writes, and scans across overflow segments. Space Count can
   expose code checks and the bit-count appendage past the end of a data field.
   See [GA26-3599-6](https://bitsavers.computerhistory.org/pdf/ibm/2844/GA26-3599-6_2314_2844_Component_Description_Nov71.pdf)
   and [SY26-4000-3, section 1.4.4.4](https://www.bitsavers.org/pdf/ibm/2841/SY26-4000-3_2841_FETOM_Stage_2_Jul70.pdf).
   IBM's [2314 maintenance diagnostics, F6BA/F6BB](https://bitsavers.trailing-edge.com/pdf/ibm/dasd/2314/2314_S01_MDP.pdf)
   describe the drive-busy check during recalibration and the seek timeout.
6. The printer and console job uses the 1052 as the SDM list device and
   checks the D66542 keyboard echo.
7. The 2316 integrity test D806A5 watches for device end when the operator
   replaces the 2314's identifier plug. It scans all 4,060 tracks of a
   read-only pack and reports zero bad tracks. After the scan, the operator
   enters `F/` and SDM reports `D806A TERMINATED REIPL TO CONTINUE`.
   See [IBM 2316 integrity test, F6BE](https://bitsavers.trailing-edge.com/pdf/ibm/dasd/2314/2314_S01_MDP.pdf)
   and [FAA 9020 maintenance monitor manual](https://bitsavers.computerhistory.org/pdf/ibm/9020/faa/FAA-2000-2_FAA_9020_Maintenance_Monitor_Manual_198306.pdf).
8. DA0515 runs all ten routines with a channel-to-channel adapter in wrap
   mode. `m.ctc(0x320, peer=0x420)` joins its two selector interfaces,
   and SDM switch 14 selects wrap mode. The routines verify command pairing,
   attention and ending status, data and command chaining, HALT I/O, and
   Write End of File. See [IBM 9020D/E Principles of Operation, appendix J](https://bitsavers.trailing-edge.com/pdf/ibm/9020/A27-9020-01_9020_D_and_9020_E_Principles_of_Operation_19710601.pdf)
   and [FAA monitor manual, §2.3.5](https://bitsavers.computerhistory.org/pdf/ibm/9020/faa/FAA-2000-2_FAA_9020_Maintenance_Monitor_Manual_198306.pdf).
9. DB0513 and DB0522 exercise the 2701 Data Adapter Unit with the F26329
   multi-device option. `m.dau(0x20)` supplies five RKM addresses at
   `021` through `025` in state zero. The 23 routines cover the DAU's
   diagnostic register, RKM command formatting, sense retention, the
   modified diagnostic write's attention interrupts and control-unit
   busy and end. See [IBM 9020D/E Principles of Operation, appendix K](https://bitsavers.trailing-edge.com/pdf/ibm/9020/A27-9020-01_9020_D_and_9020_E_Principles_of_Operation_19710601.pdf).

The smoke requires the exact section starts and unavailable-unit reports
for each job, a nonzero routine count for every started section, and zero
diagnostic errors.

**Configuration.** `architecture="s360"`, `model="9020"`, 1 MB, at 1 MIPS
(`mips=1`): the diagnostics time devices with fixed `BCT` loops calibrated for
the 9020 CE, and a 50-MIPS virtual CPU finishes them before a 1-byte sense
completes. The library tape is a 3420 at 130, with a 1052 at 01F, a 2540
reader at 00C and a 1403 printer at 00E. The punch job adds a 2540 punch at
00D. The tape jobs use nine-track 2401 Model 2 drives at 3F0 and 3F1, and
the disk job uses a 203-cylinder 2314 at 340.

In the load messages, `E/` selects the 9020E. `A,cuu` adds a device from
SDM's address table, while `APPOO0CUU/` specifies the unit type PP and
options OO explicitly. The smoke uses `A6B00000D/` for the punch,
`A400003F0/` and `A400003F1/` for the scratch drives, and `A80000340/`
for the disk. `I` names the console input, console
output, list and library devices. `W,cuu` withdraws a device and
`Lppss.ppss` selects a range of sections. `B` begins the job or continues
after a console REQUEST and an operator halt. Switch 21 (`SW.00000400`)
lets sections bypass routines that require manual intervention. The
operator still responds to the carriage-tape, keyboard and card prompts.
The FAA smoke also runs separate jobs with switch 21 off.

**System/360 and the 9020.** The tape targets the 9020's System/360-based
processors. `architecture="s360"` implements the System/360 architecture
([A22-6821-7](https://bitsavers.trailing-edge.com/pdf/ibm/360/princOps/A22-6821-7_360PrincOpsDec67.pdf))
over the System/370 basic-control machinery ([s360.go](s360.go)): only
System/360 operation codes are defined; PSW bit 12 selects USASCII-8 decimal
results (signs 1010/1011, zone 0101) rather than EC mode; there are no
control registers, so the timer and interrupt key are masked by the PSW
alone; and CCW flag bits 37-39 must be zero. `model="9020"` adds behaviors the
9020 diagnostics demonstrate where the 9020 departs from both architecture
manuals:

| Section, routines | 9020 behavior |
| --- | --- |
| D30511 12 | An I/O interruption enabled by SSM is recognized after the following instruction |
| D30542 55, 56 | Channel stores into blocks whose storage key is zero succeed with any CAW key |
| D30542/D31544 57, 61 | A fetch-protected CCW gives program check on the multiplexer and combined program and protection check on the selector |
| D11020 85 | An invalid input digit can leave an all-ones sum byte in storage before a data interruption |
| D11020 8B, 8C, 90 | Multiply stores the low product before testing the reserved leading bytes of the multiplicand, and leaves a partial result on that data interruption |

D117E0 exercises PSW bit 12. D11020's decimal results follow the Model 65
serial adder and product-store sequences in [2065 Processing Unit
FEMI, 226-2037-0, §§3.8.1 and 3.8.3](https://bitsavers.trailing-edge.com/pdf/ibm/360/fe/2065/226-2037-0_2065_Processing_Unit_FEMI_Vol_2_Nov65.pdf).

## FAA-corrected validation

[scripts/smoke/s370_diag_faa.star](../../scripts/smoke/s370_diag_faa.star)
starts from the same pinned reel and uses a strictly validated view
ending after its second tape mark. It checks the original bytes at each
listing correction and applies the changes in guest storage or to a
separate in-memory master reel. The two smokes account for all 215
diagnostic and utility sections in the 226-entry tape catalog. The other
11 entries are loaders and resident modules.

- The standalone IOCE IPL executes 66 bring-up sections in tape order.
  IOCE-mode SDM then completes D21010 and D27402, exercising local and
  MACH storage. The configuration uses the IOCE's four-bit storage keys,
  storage access rules and native local-store maintenance commands.
- D40610 senses the physical reflective end-of-tape marker on a 2401.
  The pinned program falls through its successful comparison at `00868E`.
  The FAA source restores the return through R5.
- D70F12 copies a full 80-byte card and writes a tape mark. The corrected
  interrupt-handler branches use the FAA masks for combined channel end
  and device end.
- D81504 runs all three routines, including the full-pack read and
  secondary listings. The smoke checks the home address and record zero
  printouts for all 4,060 tracks, the 226 catalog entries against disk,
  and the final relocation-chain terminator. The utility now runs its
  last relocation-key write before unloading the master. The in-memory
  master uses the generated D00201 location at 150/2/3 and restores the
  FAA SDM catalog buffer at X'8000', leaving X'7000' for D0D60.
  A clear IPL at 350 loads SDM from disk and runs all 78 routines of
  disk-loaded D11011 to `EOJ  SDM JOB COMPLETED`.
- The FAA D0D50A entry and loader instructions bring up MDM-D/E from
  SDM's `LMDM/` command. DB0A10 completes its TPS routine on both
  2701 paths. D6AA00 completes 23 routines across the two 2821
  interfaces with all three printers, a card reader and a card punch.
  Both jobs reach `EOJ  MDM JOB COMPLETE` with zero errors.
- With switch 21 off, D66511 exercises Not Ready, Ready, Request and
  Cancel, and D66531 runs all eight keyboard rows. D80501 reports the
  2314 spindle speed within tolerance after reaching the track index
  during Write Record Zero. D80692 uses the CE's DELAY instruction for
  its access-time test and reports timing within tolerance.
- DA0515 runs all ten routines with switch 21 off. Routine 0A requests a
  subsystem PSW restart for each adapter direction and checks the
  resulting not-ready and Halt I/O statuses.

See the [FAA diagnostic program descriptions](https://bitsavers.org/pdf/ibm/9020/faa/FAA-2371-B_9020_Diagnostic_Program_Descriptions_198012.pdf),
[FAA assembly listings](https://bitsavers.trailing-edge.com/pdf/ibm/9020/faa/FAA_9020_Diagnostics_Source_Code.zip)
and [NOSS BALASM extended mnemonics, table 3-5](https://bitsavers.computerhistory.org/pdf/ibm/9020/IBM_9020_NOSS_BALASM_User%27s_Manual_19730815.pdf).

**Channel and device timing.** Devices implementing `Timed` (tapes and unit
records) report how long each command holds the channel and the device;
[chan370.go](chan370.go) keeps the transitions as TOD deadlines on the
subchannel, so they follow the virtual clock, are reached by idle skipping and
are checkpointed with in-flight transfers. An immediate command (tape motion,
carriage control, feed) ends START I/O with CC 1 and only the status portion
of the CSW; device end follows later as an interruption with zero key,
address and count. A data transfer keeps the subchannel working (CC 2) until
channel end. Tape input reaches storage at channel end, so programs that read
the next program over themselves (as D00104 does) see the old storage meanwhile.
On the 2314, read bytes arrive at disk transfer speed. Selector HALT I/O stops
the transfer and the 2314 fills the remainder of an interrupted write with zeros.
The 9020 IOCE accepts data and channel command addresses in its own MACH
storage at `C00000` through `C1EFFF`. See [IBM 9020D/E Principles of Operation,
appendix H](https://bitsavers.trailing-edge.com/pdf/ibm/9020/A27-9020-01_9020_D_and_9020_E_Principles_of_Operation_19710601.pdf).
Command chaining waits for device end; a device working after channel end
answers busy. Unit-record commands follow the 2821 Control Unit
([GA24-3312-9](https://bitsavers.trailing-edge.com/pdf/ibm/2821/GA24-3312-9_2821_Unit_Description_Oct82.pdf)):
1403 write, space and skip modifiers, the 132-byte print buffer (a write
count other than 132 is incorrect length), diagnostic write, data read and
check read, the 2540 read/feed command sequencing with unusual command sequence,
end of file as unit exception on the read after the last card, and command
reject as unit check alone at initial selection. A paired 2540 supports
2821 diagnostic writes into the reader's column-binary buffer and reads
of the data and check planes. The 2401/2803 has six-byte sense, count-ended
writes, and control-unit busy and ending status for tape motion. HALT I/O
on its selector channel reports the channel termination separately from
the device ending status. [IBM A22-6866-4](https://bitsavers.org/pdf/ibm/2803_2804/A22-6866-4_2400_Tape_Unit_2803_2804_Tape_Controls_Component_Description_Sep68.pdf)

The diagnostics also exposed channel and CPU gaps fixed here, each with a
regression test: incorrect length is never indicated for an immediate
control command, and CD on one ends the chain; System/370 CCW rules (a TIC may be neither the first CCW nor
follow a TIC, command codes ending in 0000 are invalid, flag bits 38-39 must
be zero); programming errors in the first CCW end START I/O with CC 1;
data-address, IDAW and protection checks found during the transfer carry the
device's status; fetch protection of CCWs and output data; HALT I/O to an
available device sets CC 1; and PACK, UNPACK and MOVE WITH OFFSET process
overlapping operands one byte at a time (pp. 7-24, 7-27, 7-36).

**The late-media discrepancy.** The SIMH record at byte 1,633,618 declares
32,767 bytes but its trailer at 1,666,390 is zero. It lies after the volume's
logical end: file 0 (the library) ends at byte 1,629,666 and is followed by
988 tape marks. Its 4-byte header and the next 4,272 bytes are a byte-for-byte
copy of bytes 1,625,390-1,629,665, which begin with the *trailer* of DB0522's
32,767-byte text record and continue with the library's last four records
(DB0522's RLD and DB0A10's header, text and RLD). The SIMH reader reports
the stale copy as `framing_error` when inspecting the original image.
The FAA smoke uses the in-memory prefix ending at byte 1,629,674 and
requires strict SIMH validation of the entire prefix. Both original
tape marks are retained. The reference smoke still mounts the
SHA-256-verified original reel.

## Running the checks

From the `trex` module:

```sh
go test ./emulator/s390 ./archive/simh
go test ./...
go vet ./...
go build ./cmd/trex
go run ./cmd/trex test.star
go run ./cmd/trex scripts/smoke/linux_s390.star
go run ./cmd/trex scripts/smoke/linux_s390_dasd.star
go run ./cmd/trex scripts/smoke/s370_diag.star
go run ./cmd/trex scripts/smoke/s370_diag_faa.star
go run ./cmd/trex scripts/inspect/s370_diag.star inspect
go run ./cmd/trex scripts/inspect/s370_diag.star sdm
```

`s370_diag.star sdm [BUDGET [LOADMSG]]` prints SDM's console and a per-section
summary; other arguments are probe steps (`s370_steps.star`), including
`interrupt_key`, `alter=ADDR:HEX` (the console STORE function), `text=ADDR:LEN`
(EBCDIC strings in storage), `until=DEV:TEXT[:BUDGET[:STEP]]` and
`stream=DEV:BUDGET[:LINES]`. The smoke fetches the tape; the CPU, channel and
synthetic tape tests require neither the tape nor the listing.
