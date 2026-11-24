"""Inspect or step Richard Cornwell's microsim360 diag1.tap on the native CPU.

Run: go run ./cmd/trex scripts/inspect/s370_diag.star inspect
     go run ./cmd/trex scripts/inspect/s370_diag.star sdm [BUDGET [LOADMSG [SCRATCH_CUU...]]]
     go run ./cmd/trex scripts/inspect/s370_diag.star faa-ioce [BUDGET]
     go run ./cmd/trex scripts/inspect/s370_diag.star STEP...
Steps are those of s370_steps.star. `sdm` runs the System Diagnostic Monitor
with a load message and summarizes each section (see
scripts/smoke/s370_diag.star). The tape is read directly as SIMH; no
conversion or extracted intermediate files are used.
"""

load("//scripts/inspect:s370_steps.star", "run_steps")

URL = "https://raw.githubusercontent.com/rcornwell/microsim360/cccea8cde6a9d5b6867a2f1629f24ba5b7a840e2/test_progs/diag1.tap"
SHA256 = "21c61161358fe72bc73271dd9ab66bf44eff7db5458d93886746b9475d39cfb3"
SIZE = 1666470
LIBRARY_TAPE_MARK = 1629666

def source():
    tape = http_file([URL], size = SIZE, cache_bytes = 16 << 20)
    if binary.hex(digest(tape)) != SHA256:
        fail("diag1.tap: SHA-256 mismatch")
    return tape

def library_reel(tape):
    """Return the pinned library and its two terminal tape marks."""
    end = LIBRARY_TAPE_MARK + 8
    reel = tape.slice(0, end)
    records = archive.simh(reel).records
    marks = [record.offset for record in records if record.tape_mark]
    if marks != [LIBRARY_TAPE_MARK, LIBRARY_TAPE_MARK + 4] or any([record.bad for record in records]):
        fail("diag1.tap: unexpected logical library boundary or bad record")
    return reel

# The test carriage tape the 1403 sections ask the operator to install
# (66 lines, one channel per line). The sections check each skip by spacing
# one line past the channel: the line after channels 1-3 and 10-12 holds
# channel 9 (unit check) and the line after channels 4-9 holds channel 12
# (unit exception).
CE_TAPE = [[1], [9], [2], [9], [3], [9], [4], [12], [5], [12], [6], [12], [7], [12], [8], [12],
           [9], [12], [10], [9], [11], [9], [12], [9]] + [[]] * 42

def machine(tape, scratch_tapes = [], punch = False, element = "", memory = 1 << 20):
    m = emulator.s390(architecture = "s360", model = "9020", element = element, memory = memory, mips = 1, start = "1985-08-30T12:00:00Z")
    m.tape(0x130, tape, format = "simh")
    for dev in scratch_tapes:
        m.tape(dev, tape.slice(0, 0), type = "2401")
    m.console(0x01f, type = "1052")
    m.unit_record(0x00e, type = "1403")
    m.carriage_tape(0x00e, CE_TAPE)
    m.unit_record(0x00c, type = "2540R", cards = [])
    if punch:
        m.unit_record(0x00d, type = "2540P", reader = 0x00c)
    return m

def faa_correction(m, address, original, replacement):
    before = binary.decode(original, "hex")
    after = binary.decode(replacement, "hex")
    if len(after) != len(before) or m.read(address, len(before)) != before:
        fail("diag1.tap: unexpected instruction bytes at %x" % address)
    m.alter(address, after)

def faa_ioce(tape):
    """IPL the IOCE path with the D0010400.SPT monitor selection restored."""
    # This revision of D106D1 assumes a 128 KiB storage element and
    # crosses its end to verify an addressing interruption.
    m = machine(tape, element = "ioce", memory = 128 << 10)
    m.ipl(0x130)
    # Basic Storage tests and clears the area used for the restored
    # instructions. Wait until Go/No-Go returns from the test.
    m.break_at(0x2b6)
    r = m.run(instructions = 9000000)
    if r.kind != "breakpoint" or m.read(0x384, 4) != b"\x00\x00\x00\x01":
        fail("diag1.tap: Go/No-Go did not reach the IOCE monitor selection (%s %s)" % (r.kind, r.psw))
    m.clear_breaks()
    # LOK102 compares GR1 with CEIND and branches to LDNXT only on
    # equality. The IOCE otherwise falls through to the IDM search.
    faa_correction(m, 0x1f00, "000000000000000000000000", "591003844780032A47F002CA")
    faa_correction(m, 0x2c6, "47F0032A", "47F0AF00")
    return m

def faa_ioce_sdm(m):
    """Start the IOCE monitor with D0C00C00.SPT's SPSB probe restored."""
    m.break_at(0x150)
    for address in IDM_ERROR_STOPS:
        m.break_at(address)
    r = m.run(instructions = 65000000)
    if r.kind != "breakpoint" or not r.psw.endswith("000150") or m.read(8, 4) != b"\xd0\xc0\x0c\x00":
        fail("diag1.tap: IDM did not enter SDM (%s %s)" % (r.kind, r.psw))
    # The legacy IOCE takes a program interruption on SPSB. IPLIOC
    # sets the monitor's IOCE flag and returns to restore the PSW.
    faa_correction(m, 0x154, "92060069", "A0000480")
    faa_correction(m, 0x1b6, "47F00158", "47F001BC")
    faa_correction(m, 0x1bc, "0000000000000000", "9206006947F00158")
    m.clear_breaks()
    r = m.run(instructions = 20000000)
    if r.psw != SDM_READY or m.read(0x206, 1) != b"\xff":
        fail("diag1.tap: IOCE SDM did not reach the operator prompt (%s %s)" % (r.kind, r.psw))
    return m

def faa_mdm(tape):
    """Load D0D50A and restore SPSB/INGTSE from D0D50A00.SPT."""
    m = machine(tape)
    m.ipl(0x130)
    r = m.run(instructions = 30000000)
    if r.psw != SDM_READY:
        fail("diag1.tap: SDM did not reach the operator prompt (%s %s)" % (r.kind, r.psw))
    m.cards(0x00c, ["E/A,01F/A,00E/I,01F,01F,00E,130/LMDM/B"])
    # The channel enters the monitor at x80. Stop before the next
    # instruction, then replay both LA instructions after INGTSE.
    m.break_at(0x84)
    m.interrupt_key()
    r = m.run(instructions = 30000000)
    if r.kind != "breakpoint" or m.read(8, 4) != b"\xd0\xd5\x0a\x00":
        fail("diag1.tap: SDM did not enter D0D50A (%s %s)" % (r.kind, r.psw))
    patch = "A00007E81B33433007EB920007EB45700E8641A9100041BA100047F00088"
    faa_correction(m, 0x0fa0, "00" * (len(patch) // 2), patch)
    faa_correction(m, 0x84, "41BA1000", "47F00FA0")
    # Restore the call to MAATR4 and its entry instructions. The raw
    # stream retains the end of MAATR4 from MAATR8 onwards.
    maatr4 = "0C3089300002413391D4A1003000A00007E8920007EB47F0D87C"
    faa_correction(m, 0x0fc0, "00" * (len(maatr4) // 2), maatr4)
    faa_correction(m, 0x304, "00000000", "45700FC0")
    faa_correction(m, 0xa7e0, "00000000", "41500FC0")
    # SKP510 saves the loader's registers and LOT408 restores them.
    faa_correction(m, 0x3fe6, "00000000", "90070548")
    faa_correction(m, 0x588a, "00000000", "98070548")
    # Restore the SIA074 dispatch to SIA200 (SPCI), with its original
    # instruction in the low-store trampoline before SIB010.
    faa_correction(m, 0x73c8, "00000000", "47800FE0")
    faa_correction(m, 0x0fe0, "0000000000000000", "9B00500047F0DC86")
    # SKP600, SKP610, SKP622 and SKP630 manage the unit assignment
    # while the scheduler returns the devices used by a section.
    faa_correction(m, 0x4318, "00000000", "90070548")
    faa_correction(m, 0x4374, "0000000000000000", "5040055850600560")
    faa_correction(m, 0x43b8, "00000000", "98070548")
    faa_correction(m, 0x43de, "00000000", "58400558")
    faa_correction(m, 0x40ae, "00000000", "98070548") # SKP513
    # SKD991 checks each CE's program-status table before announcing EOJ.
    faa_correction(m, 0x3a18, "000000000000", "D503321C0AE8")
    m.clear_breaks()
    return m

# The System Diagnostic Monitor (SDM) loaded from the tape waits for the
# operator INTERRUPT key, then reads a load message card. Its first token
# selects the 9020 model (A/, D/ or E/); A,cuu adds a device from SDM's own
# address table (01F is a 1052-class console, 00E a printer); I names the
# console input, console output, list and library devices; Sx.hhhhhhhh sets
# the 32 diagnostic-monitor switches, of which switch 21 (X'00000400')
# bypasses routines that need manual intervention; L loads sections from the
# library tape and B begins.
LOAD_MESSAGE = "E/A,01F/A,00E/I,01F,01F,00E,130/SW.00000400/L/B"

# The prompt with which the 2540 reader asks for the deck produced by D62511.
DETAIL_DECK = "PLACE DETAIL CDS IN RDR"
END_OF_JOB = "EOJ  SDM JOB COMPLETED"
SDM_READY = "89064000 00000002"
IDM_ERROR_STOPS = [0x200, 0x22c, 0x230, 0x234, 0x238, 0x23c, 0x248, 0x24c, 0x254, 0x258]

# Operator replies to SDM and section prompts: returns a description of the
# action taken, or None.
def operator(m, line, section):
    if "MAKE 2540 PCH NOT RDY" in line:
        m.key(0x00d, "STOP")
        return "stopped the punch"
    if "PLACE BLANK CDS IN PUNCH HOPPER,MAKE RDY" in line:
        m.key(0x00d, "STOP")
        m.key(0x00d, "START")
        return "readied the punch"
    if "PLACE 5 BLNK CDS IN RDR" in line:
        m.cards(0x00c, [""] * 5, replace = True)
        return "loaded 5 blank cards"
    if line.strip().startswith("HLT "):
        # SDM halts a section for an operator action; REQUEST and the B
        # (begin) keyword on the console continue it.
        m.key(0x01f, "REQUEST")
        m.run(instructions = 2000000)
        m.type(0x01f, "B")
        return "continued with B"
    if line.strip() == "S   D66542":
        # The 1052 keyboard exerciser reads the keyboard and, when REQUEST
        # is pressed, types back what was keyed; it runs until the operator
        # presses INTERRUPT, which SDM takes once EOB ends the pending read.
        m.run(instructions = 3000000)
        m.type(0x01f, ECHO)
        m.run(instructions = 3000000)
        m.key(0x01f, "REQUEST")
        m.run(instructions = 8000000)
        m.interrupt_key()
        m.run(instructions = 2000000)
        m.type(0x01f, "")
        return "keyed %s, REQUEST, INTERRUPT and EOB" % ECHO
    return None

# The text keyed to the 1052 exerciser D66542.
ECHO = "ECHO TEST 0123456789"

def sdm(m, message = LOAD_MESSAGE, budget = 20000000000, step = 2000000, blank = 20, show = True, stop = None, detail_cards = None):
    """Runs SDM with a load message and returns its results.

    The result holds each section started ("S" lines) with its routine count
    from the "T" line and the routines that reported errors, the sections SDM
    did not run ("RNV"), the console transcript, and all diagnostic errors.
    "ended" is "end-of-job" at SDM EOJ, "stop" at the requested stop text,
    "budget" on exhaustion, or the machine's stop kind on interruption.
    """
    ready = m.psw() == SDM_READY
    m.cards(0x00c, [message] + [""] * blank, replace = True)
    if not ready:
        r = m.run(instructions = 200000000)
        if r.psw != SDM_READY:
            fail("sdm: not waiting for the operator: %s %s" % (r.kind, r.psw))
    start = m.instructions()
    seen = len(m.screens(0x01f))
    m.interrupt_key()
    spent = 0
    sections, skipped, transcript, errors, current = [], [], [], [], None
    ended = None
    for _ in range(budget // step + 1):
        if spent >= budget or ended:
            break
        r = m.run(instructions = step)
        spent += step
        lines = m.screens(0x01f)
        for line in lines[seen:]:
            transcript.append(line)
            if show:
                print(line)
            words = line.split()
            if len(words) >= 2 and words[0] == "S":
                current = {"section": words[1], "errors": [], "routines": None}
                sections.append(current)
            elif len(words) >= 3 and words[0] == "T" and current and words[1] == current["section"]:
                current["routines"] = words[2]
            elif len(words) >= 2 and words[0] == "RNV":
                skipped.append(words[1])
            elif current and len(words) >= 4 and words[0] == "*" and words[1] in ["SD0", "PGM"]:
                current["errors"].append(words[3])
            elif current and len(words) >= 3 and words[0] == "*" and words[1] == current["section"]:
                current["errors"].append(words[2])
            if (words and words[0] == "*" and len(words) > 1) or "COMPARE ERR,CARD NO." in line:
                errors.append(line.strip())
            if stop and stop in line:
                ended = "stop"
                break
            if line.strip() == END_OF_JOB:
                ended = "end-of-job"
                break
            if detail_cards != None and DETAIL_DECK in line:
                m.cards(0x00c, detail_cards, replace = True)
            if detail_cards != None and "PLACE VALID CDS" in line:
                m.cards(0x00c, [str(i) for i in range(75)], replace = True)
            reply = operator(m, line, current["section"] if current else None)
            if reply and show:
                print("operator: " + reply)
        seen = len(lines)
        if not ended and (r.kind in ["disabled-wait", "check-stop", "stopped"] or r.psw == SDM_READY):
            ended = r.kind
    return {"sections": sections, "skipped": skipped, "transcript": transcript, "errors": errors, "ended": ended or "budget",
            "run": r, "instructions": m.instructions() - start, "time": m.time()}

def main(args):
    tape = source()
    if len(args) >= 1 and args[0] == "faa-ioce":
        m = faa_ioce(tape)
        m.trace_io(skip = [0x00c, 0x00e, 0x01f])
        for address in IDM_ERROR_STOPS:
            m.break_at(address)
        r = m.run(instructions = int(args[1]) if len(args) > 1 else 30000000)
        print("IOCE: %s %s after %d instructions" % (r.kind, r.psw, m.instructions()))
        if r.kind == "breakpoint":
            print("IDM section, routine and error addresses: " + binary.hex(m.read(0x1f4, 12)))
            if r.psw.endswith("00023C"):
                # SVC D0 follows the failing instruction with its format
                # and a section-relative address for the error text.
                print("SVC and program old PSWs: " + binary.hex(m.read(0x20, 16)))
            print("GR2 and GR3: " + " ".join(m.registers().gr[2:4]))
        for line in [e for e in m.events() if "0130 " in e][-8:]:
            print(line)
        return
    if len(args) >= 1 and args[0] == "sdm":
        m = machine(tape, scratch_tapes = [int(cuu, 16) for cuu in args[3:]])
        m.ipl(0x130)
        res = sdm(m, message = args[2] if len(args) > 2 else LOAD_MESSAGE, budget = int(args[1]) if len(args) > 1 else 20000000000, stop = DETAIL_DECK)
        for s in res["sections"]:
            print("%s routines=%s errors=%d %s" % (s["section"], s["routines"], len(s["errors"]), ",".join(s["errors"])))
        print("sdm: ended %s (%s %s) after %d instructions, %s" % (res["ended"], res["run"].kind, res["run"].psw, res["instructions"], res["time"]))
        return
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
