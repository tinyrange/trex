"""Inspect or step Richard Cornwell's microsim360 diag1.tap on the native CPU.

Run: go run ./cmd/trex scripts/inspect/s370_diag.star inspect
     go run ./cmd/trex scripts/inspect/s370_diag.star STEP...
Steps are those of s370_steps.star. The tape is read directly as SIMH; no
conversion or extracted intermediate files are used.
"""

load("//scripts/inspect:s370_steps.star", "run_steps")

URL = "https://raw.githubusercontent.com/rcornwell/microsim360/cccea8cde6a9d5b6867a2f1629f24ba5b7a840e2/test_progs/diag1.tap"
SHA256 = "21c61161358fe72bc73271dd9ab66bf44eff7db5458d93886746b9475d39cfb3"
SIZE = 1666470

def source():
    tape = http_file([URL], size = SIZE, cache_bytes = 16 << 20)
    if binary.hex(digest(tape)) != SHA256:
        fail("diag1.tap: SHA-256 mismatch")
    return tape

def machine(tape):
    m = emulator.s390(architecture = "s370", memory = 1 << 20, start = "1985-08-30T12:00:00Z")
    m.tape(0x130, tape, format = "simh")
    m.console(0x01f, type = "3215")
    m.unit_record(0x00e, type = "1403")
    m.unit_record(0x00c, type = "2540R", cards = [])
    return m

def main(args):
    tape = source()
    if len(args) == 1 and args[0] == "inspect":
        # Retain positionable damage for inspection; report it explicitly.
        # archive.simh defaults to strict validation for other consumers.
        records = archive.simh(tape, strict = False).records
        print("%d objects, %d tape marks, %d bad records" % (len(records), len([r for r in records if r.tape_mark]), len([r for r in records if r.bad])))
        for i, r in enumerate(records[:12]):
            if r.data != None:
                data = r.data.bytes(0, min(r.data.size, 80))
                print("%d offset=%d size=%d hex=%s text=%s" % (i, r.offset, r.data.size, binary.hex(data), repr(binary.text(data, encoding = "cp037"))))
        for r in records:
            if r.framing_error:
                print("DAMAGED: " + r.framing_error)
        return
    m = machine(tape)
    m.ipl(0x130)
    run_steps(m, args or ["run=1000000", "screen=01f", "regs", "events=10", "unknown"])
