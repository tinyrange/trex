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
| Decimal row 207, overlapping ED | The architecture declares overlapping edit operands unpredictable (GA22-7000-6, p. 8-3). Our sequential implementation encounters invalid source data after partial stores: data exception `07`, bytes `40f4f0402120`. We assert that behavior locally without treating upstream's `40f4f040f2f0`, CC 1, as an architectural error. |
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

## Cornwell's diagnostic tape and the D000 listing

[scripts/inspect/s370_diag.star](../../scripts/inspect/s370_diag.star) fetches
[microsim360 `test_progs/diag1.tap`](https://github.com/rcornwell/microsim360/blob/cccea8cde6a9d5b6867a2f1629f24ba5b7a840e2/test_progs/diag1.tap)
at commit `cccea8cde6a9d5b6867a2f1629f24ba5b7a840e2`, verifies its 1,666,470-byte
size and SHA-256
`21c61161358fe72bc73271dd9ab66bf44eff7db5458d93886746b9475d39cfb3`, and mounts it
directly. The diagnostic media are a separate upstream resource, not part of
the MIT test adaptation and not vendored here.

The native [SIMH reader](../../archive/simh/simh.go) follows Bob Supnik's
[SIMH Magtape Representation and Handling](https://simh.trailing-edge.com/docs/simh_magtape.pdf).
It retains padded records, tape marks, recorded errors, extended metadata and
erase gaps as views of the input. `archive.simh(file)` validates framing
strictly. `strict=False` permits inspection of positionable damaged records
but exposes their `framing_error`; truncated frames still fail.
`m.tape(device, file, format="simh")` reports a mismatched trailer as a guest
data check when that record is read. It does not silently repair the image.
AWS remains the default tape format.

Tape read backward (`0C`) now reverses transfer order and decrements channel
storage addresses, including data chaining and indirect addressing. Marks,
load point, residuals, protected storage and immutable input/overlay data have
regression tests. Subsequent backward IDAWs address the last byte of a 2 KiB
block; see [IBM 4341 Processor Guide, GC20-1877-0](https://vtda.org/docs/computing/IBM/Mainframe/Hardware/System/GC20-1877-0_Guide4341Processor.pdf), p. 132.

**The diagnostic does not yet pass.** The full, unmodified tape IPLs D00104,
performs its forward/backward reads and data comparison, then reaches its
error loop at `000D6C` after 880 instructions. The preceding compare expects
CSW word two `04000000` (device end alone); our forward-space-block command
`37` produces `0C000050` (combined channel/device end, residual 80).
This is concrete evidence for Richard's warning: immediate tape commands
need separate channel completion and delayed device completion. The channel
currently executes tape operations synchronously. The next discriminator is
a native clock-driven completion implementation, tested for immediate status,
busy state and delayed interrupt delivery, followed by the same diagnostic
breakpoint. Do not change the diagnostic expectation to make this pass.

The user-supplied `local/d000.lst` (in the outer workspace, not redistributed)
contains multiple assembly listings, including **D00104, GO/NO-GO FOR SYSTEM
9020**. Its corresponding stop is `000DA4`, with the same CSW comparison;
the tape's assembly has different addresses, so match instructions rather
than treating listing addresses as symbols for this tape. The probe uses a
3215 console approximation at `01F`; it does not implement a complete 1052.

There is also an independent late-media framing discrepancy: the record at
byte 1,633,618 declares length `00007FFF`, but its trailer at 1,666,390 is
`00000000`. Inspection reports this explicitly. It is not the cause of the
early D00104 stop and does not justify rejecting the valid initial records.

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
go run ./cmd/trex scripts/inspect/s370_diag.star inspect
go run ./cmd/trex scripts/inspect/s370_diag.star trace_io break=d6c run=10000 dis=d5c:6 read=f74:4 read=40:8 events=12
```

The networked diagnostic is a bounded investigation, not a passing conformance
gate. The CPU and synthetic tape tests require neither the tape nor the listing.
