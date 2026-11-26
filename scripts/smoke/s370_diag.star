"""IPL Richard Cornwell's microsim360 diag1.tap on a native 9020E CE.

Run: go run ./cmd/trex scripts/smoke/s370_diag.star [raw-card-deck]
Providing a raw card deck supplies the 2540 valid-card test and enables transcripts.
The pinned tape is fetched, checked by SHA-256 and mounted as SIMH. Fresh
machine (architecture "s360", model "9020", at about 9020 speed, 1 MB, the
tape at 130, a console at 01F, a 2540 reader at 00C and a 1403 printer at
00E). Each job starts with GO/NO-GO, the machine test and hardcore bring-up
before SDM 12 reads its load message. D62511 uses a punch at 00D and supplies
the detail deck for the reader jobs. Printer tests send monitor output to
the console. The tape and disk jobs use a blank nine-track 2401 at 3F0
and a new 2314 volume at 340, respectively. The seven-track tests use
fresh jobs to cover drives with and without the data converter. The
channel-to-channel adapter tests its two interfaces in wrap mode. The
2701 exercises its five ports in state zero with the RKMs disconnected.
The CPU job restores four missing D11792 storage-key checks in memory.
See s370_diag_faa.star for the other sections on this reel.

Proof: SDM reports the expected section starts, routine completions and
unavailable devices, followed by EOJ, with zero diagnostic errors.
D806A5 scans a full 2316 pack and exits through SDM's F/ command.
"""

load("//scripts/inspect:s370_diag.star", "ECHO", "check_1052_operator", "check_storage_dump", "machine", "operator", "read_raw_deck", "restore_d11792_storage_keys", "source", run_sdm = "sdm")

def sdm(m, message, show, **kwargs):
    if show:
        print("SDM load card " + message)
    return run_sdm(m, message = message, show = show, **kwargs)

SECTIONS = [
    "D11011", "D11020", "D11030", "D11130", "D11141", "D11150", "D11510", "D11520", "D11530",
    "D11540", "D11550", "D11560", "D11570", "D115A0", "D115C0", "D115D0", "D115E0", "D115F0",
    "D11600", "D11610", "D11620", "D11630", "D11640", "D11650", "D11660", "D11670", "D11690",
    "D116A0", "D116B0", "D116C0", "D116D0", "D116F0", "D11710", "D11730", "D11740", "D11750",
    "D11760", "D11770", "D11780", "D11792", "D117B0", "D117C0", "D117E0", "D11800", "D11810",
    "D11820", "D11830", "D11840", "D11860", "D118A0", "D118B0", "D118C0", "D118D0", "D118E0",
    "D118F0", "D11900", "D11920", "D11960", "D11970", "D11980", "D11990", "D119A0", "D119B0",
    "D30511", "D30542", "D62610", "D62620", "D62630",
]

NOT_AVAILABLE = [
    "D30521", "D30533", "D31512", "D31522", "D31534", "D31544", "D40501", "D40511", "D40521",
    "D40531", "D40541", "D40551", "D40563", "D40571", "D40581", "D40591", "D405A1", "D405B1",
    "D405C1", "D405D1", "D405E1", "D405F1", "D40604", "D40610", "D41560", "D62511",
]

PRINTER_CONSOLE = [
    "D63514", "D63523", "D63534", "D63543", "D63552", "D63564", "D635F2",
    "D6A540", "D6A552", "D6A562", "D6A572", "D6A580",
]

TAPE_2401 = [
    "D40501", "D40511", "D40521", "D40531", "D40541", "D40551", "D40563", "D40571",
    "D405E1", "D405F1", "D40604",
]

TAPE_2401_SEVEN_TRACK = ["D40581", "D40591", "D405A1", "D405B1", "D405C1", "D405D1"]

PUNCH = ["D62511", "D6A510", "D6A521", "D6A530", "D30521"]

SELECTOR = ["D31512", "D31522", "D31534", "D31544"]

DISK_2314 = [
    "D80501", "D80512", "D80522", "D80532", "D80542", "D80552", "D80562", "D80572",
    "D80582", "D80592", "D805A1", "D805B3", "D805C2", "D805D1", "D805E4", "D805F2",
    "D80602", "D80612", "D80622", "D80632", "D80642",
]

DISK_2314_LATE = ["D80652", "D80661", "D80671", "D80683", "D80692"]

CONSOLE_1052 = ["D66511", "D66521", "D66531", "D66542"]

CE_SECTIONS = (SECTIONS + PRINTER_CONSOLE + CONSOLE_1052 + TAPE_2401 + TAPE_2401_SEVEN_TRACK + PUNCH + SELECTOR +
               DISK_2314 + DISK_2314_LATE + ["D30533", "D41560", "D806A5", "DA0515", "DB0513", "DB0522"])

def check(res, sections, skipped):
    if res["ended"] != "end-of-job":
        fail("s370_diag: SDM did not reach EOJ (%s %s %s)\n%s" % (
            res["ended"], res["run"].kind, res["run"].psw, "\n".join(res["transcript"][-30:])))
    got = [s["section"] for s in res["sections"]]
    if got != sections:
        fail("s370_diag: sections %s" % got)
    if res["skipped"] != skipped:
        fail("s370_diag: not available %s" % res["skipped"])
    for s in res["sections"]:
        if s["routines"] == None or int(s["routines"], 16) == 0:
            fail("s370_diag: %s did not report completed routines" % s["section"])
    if res["errors"]:
        fail("s370_diag: diagnostic errors\n%s" % "\n".join(res["errors"][:20]))

def check_hex_dump(tape, show):
    # One 16-byte record followed by two tape marks in SIMH framing.
    reel = binary.builder(capacity = 32)
    reel.append(binary.decode("1000000001020304A1A2A3A4F1F2F3F4F5F6F7F8100000000000000000000000", "hex"))
    m = machine(tape)
    m.tape(0x3f0, reel.file(), type = "2401", format = "simh")
    m.ipl(0x130)
    # SDM 12 accepts B at the identification prompt and leaves the reel
    # number blank in the report. Its Q message is unavailable.
    res = sdm(m, message = "E/A,01F/A400003F0/I,01F,01F,01F,130/L4156/B",
              budget = 30000000, show = show)
    check(res, ["D41560"], [])
    lines = [line.strip() for line in res["transcript"]]
    if ("RECORD NUMBER 00000001  BYTE COUNT 0010" not in lines or
        not any([line.startswith("000000  01020304 A1A2A3A4 F1F2F3F4 F5F6F7F8 ") for line in lines]) or
        len([line for line in lines if line == "END OF FILE - DEVICE 3F0 - RECORD COUNT 00000001"]) != 2 or
        len([line for line in lines if line == "000 ERRORS ENCOUNTERED ON TAPE NO"]) != 2):
        fail("s370_diag: D41560 did not dump the expected record\n" + "\n".join(lines[-18:]))

def check_pack(tape, show):
    ready = "READY PACK OR POP ID PLUG"
    complete = "EVALUATION COMPLETE VOL DIAG01 DRIVE 340"
    clean = "* TOTAL OF 0000 BAD TRACKS"
    terminated = "D806A TERMINATED REIPL TO CONTINUE"

    m = machine(tape)
    m.dasd(0x340, type = "2314", cylinders = 203, volser = "DIAG01", read_only = True)
    m.ipl(0x130)
    start = sdm(m, message = "E/A,01F/A80000340/I,01F,01F,01F,130/L806A/B",
                budget = 15000000, step = 100000, stop = ready, show = show)
    if start["ended"] != "stop" or [s["section"] for s in start["sections"]] != ["D806A5"] or start["errors"]:
        fail("s370_diag: D806A5 did not ask for a pack\n" + "\n".join(start["transcript"][-16:]))
    # Let the section finish installing its I/O handler after printing.
    m.run(instructions = 100000)
    m.key(0x340, "REMOVE ID PLUG")
    m.key(0x340, "INSERT ID PLUG")

    for _ in range(40):
        m.run(instructions = 500000)
        lines = [line.strip() for line in m.screens(0x01f)]
        if len([line for line in lines if line == ready]) == 2:
            break
    if lines[-1] != ready or complete not in lines or m.dasd_usage()[0x340]["read"] != [(0, 4059)]:
        fail("s370_diag: D806A5 did not scan the full pack\n" + "\n".join(lines[-16:]))

    m.run(instructions = 100000)
    m.key(0x01f, "REQUEST")
    m.run(instructions = 3000000)
    m.type(0x01f, "F/")
    end = m.run(instructions = 8000000)
    lines = [line.strip() for line in m.screens(0x01f)]
    if show:
        for line in m.screens(0x01f)[len(start["transcript"]):]:
            print(line)
    if end.kind != "disabled-wait" or terminated not in lines:
        fail("s370_diag: D806A5 did not accept F/ (%s %s)\n%s" % (end.kind, end.psw, "\n".join(lines[-16:])))
    if [line for line in lines if line.startswith("* ")] != [clean]:
        fail("s370_diag: D806A5 found bad tracks or reported a diagnostic error\n" + "\n".join(lines[-16:]))

def observe_punch_stackers(observations):
    def handle(m, line, section):
        reply = operator(m, line, section)
        if section == "D62511":
            if "PLACE BLANK CDS IN PUNCH HOPPER" in line:
                observations.append(("hopper", m.punch_stackers(0x00d)))
            elif "SHD HAVE 0025 CDS IN P1" in line:
                observations.append(("count", m.punch_stackers(0x00d)))
        return reply
    return handle

def observe_reader_stackers(observations):
    def handle(m, line, section):
        if section == "D62620" and ("PLACE VALID CDS" in line or "SHD HAVE 0025 CDS IN R1" in line):
            observations.append(m.reader_stackers(0x00c))
        return operator(m, line, section)
    return handle

def run_original(tape, valid_cards = None, show = False):
    punch = machine(tape, punch = True)
    punch.ipl(0x130)
    punch_stacks = []
    punched = sdm(punch, message = "E/A,01F/A,00E/A6B00000D/I,01F,01F,01F,130/L6251/L6A51.6A53/L3052/B",
                  budget = 200000000, show = show, handle_operator = observe_punch_stackers(punch_stacks))
    check(punched, PUNCH, [])
    if [kind for kind, _ in punch_stacks] != ["hopper", "hopper", "count", "hopper"]:
        fail("D62511 did not issue the expected stacker-test prompts")
    before, after = punch_stacks[1][1], punch_stacks[2][1]
    counts = [after[i] - before[i] for i in range(3)]
    if counts != [25, 25, 25]:
        fail("D62511: expected 25 cards per punch stacker, got %s" % counts)
    if show:
        print("D62511 observed card counts in P1, P2, RP3: %s" % counts)
    # D62511 runs the stacker test, punches 256 detail cards in order
    # and sends a final blank to feed out the last detail card.
    cards = punch.output(0x00d, raw = True)[:336]
    if len(cards) != 336 or binary.hex(cards[335]) != "40" * 80:
        fail("s370_diag: unexpected punch output (%d cards)" % len(cards))
    deck = cards[-257:-1]

    m = machine(restore_d11792_storage_keys(tape))
    m.ipl(0x130)
    reader_stacks = []
    early = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,00E,130/L0.6263/B",
                budget = 800000000, show = show, detail_cards = deck, valid_cards = valid_cards, handle_operator = observe_reader_stackers(reader_stacks))
    check(early, SECTIONS, NOT_AVAILABLE)
    if len(reader_stacks) != 2:
        fail("D62620 did not issue both stacker-test prompts")
    advances = [reader_stacks[1][i] - reader_stacks[0][i] for i in range(3)]
    if advances != [25, 25, 25]:
        fail("D62620: expected 25 cards per reader stacker, got %s" % advances)
    if show:
        print("D62620 observed card counts in R1, R2, RP3: %s" % advances)

    m = machine(tape, punch = True)
    m.ipl(0x130)
    multiplexer = sdm(m, message = "E/A,01F/A,00E/A6B00000D/I,01F,01F,01F,130/L3053/B",
                      budget = 80000000, show = show)
    check(multiplexer, ["D30533"], [])

    m = machine(tape, scratch_tapes = [0x3f0, 0x3f1])
    m.ipl(0x130)
    selector = sdm(m, message = "E/A,01F/A400003F0/A400003F1/I,01F,01F,01F,130/L3151.3154/B",
                   budget = 300000000, show = show)
    check(selector, SELECTOR, [])

    m = machine(tape, scratch_tapes = [0x3f0])
    m.ipl(0x130)
    tape_tests = sdm(m, message = "E/A,01F/A400003F0/I,01F,01F,01F,130/L4050.4057/L405E.4060/B",
                     budget = 800000000, show = show)
    check(tape_tests, TAPE_2401, [])
    tape_lines = [line.strip() for line in tape_tests["transcript"]]
    if "END RDB-ORIGIN WAS 03F0" not in tape_lines:
        fail("s370_diag: the 2401 interchangeability test did not finish its backward read pass")
    if "CREEP IS + 0.00 INCHES -LOWEST" not in tape_lines:
        fail("s370_diag: the 2401 gap and creep exercise did not finish at nominal tape position")

    for converter, expected_skips in [
        (True, {"D405D1": ["SKIP RTN-DC AVAIL"]}),
        (False, {
            "D40581": ["SKIP RTN-NO DC"],
            "D405B1": ["SKIP RTN-NO DC"] * 3,
            "D405C1": ["SKIP RTN-NO DC"] * 2,
            "D405D1": ["SKIP RTN-NO DC"] * 3,
        }),
    ]:
        m = machine(tape)
        m.tape(0x3f0, tape.slice(0, 0), type = "2401", tracks = 7, converter = converter)
        m.ipl(0x130)
        option = "01" if converter else "00"
        tape_tests = sdm(m, message = "E/A,01F/A40" + option + "03F0/I,01F,01F,01F,130/L4058.405D/B",
                         budget = 150000000, step = 100000, show = show)
        check(tape_tests, TAPE_2401_SEVEN_TRACK, [])
        skips = {}
        units_run = []
        section = ""
        for raw in tape_tests["transcript"]:
            line = raw.strip()
            if line.startswith("S   "):
                section = line.split()[1]
            elif line.startswith("SKIP RTN-"):
                skips.setdefault(section, []).append(line)
            elif line.startswith("UNITS RUN 03F0 "):
                units_run.append(section)
            elif line.startswith("NOT 7 TRK") and line != "NOT 7 TRK":
                fail("s370_diag: unexpected non-seven-track drive: " + line)
        if units_run != TAPE_2401_SEVEN_TRACK or skips != expected_skips:
            fail("s370_diag: unexpected seven-track coverage: units=%s skips=%s" % (units_run, skips))

    for load_range, sections in [("L8050.8064", DISK_2314), ("L8065.8069", DISK_2314_LATE)]:
        m = machine(tape)
        m.dasd(0x340, type = "2314", cylinders = 203, volser = "DIAG01")
        m.ipl(0x130)
        disk = sdm(m, message = "E/A,01F/A,00E/A80000340/I,01F,01F,00E,130/" + load_range + "/B",
                   budget = 500000000, step = 125000, show = show)
        check(disk, sections, [])
        lines = [line.strip() for line in disk["transcript"]]
        if load_range == "L8050.8064":
            if disk["sections"][0]["routines"] != "03" or not any([line.startswith("RPM ") and line.endswith("WITHIN TOLERANCE") for line in lines]):
                fail("s370_diag: 2314 spindle timing was not verified")
        elif "AVG ACCESS TIME WITHIN  TOLERANCE" not in lines:
            fail("s370_diag: 2314 average access timing was not verified")

    m = machine(tape)
    m.ipl(0x130)
    # Select only printer and unit-record sections for this configuration.
    late = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,01F,130/W,00C/L6350.635F/L6A50.6A58/B",
               budget = 800000000, show = show)
    check(late, PRINTER_CONSOLE, ["D6A510", "D6A521", "D6A530"])

    # The 1052 operator tests use the original reel, without switch 21.
    check_1052_operator(tape, show = show)
    m = machine(tape)
    m.ipl(0x130)
    console = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,00E,130/L6652/L6654/B",
                  budget = 100000000, step = 100000, show = show)
    check(console, ["D66521", "D66542"], [])
    if [s["routines"] for s in console["sections"]] != ["06", "02"]:
        fail("s370_diag: unexpected 1052 command or echo routine counts")
    alignment = "This line is checking backspace,so check carefully for alignment."
    lines = console["transcript"]
    if alignment not in lines:
        fail("s370_diag: 1052 backspace alignment did not match")
    layout = ["CHECKING LINE FEED", " " * 18 + "HORZ TAB" + " " * 6 + "NEW LINE"]
    start = lines.index(alignment) + 1
    if lines[start:start + 4] != layout * 2:
        fail("s370_diag: 1052 line-feed or tab layout did not match")
    if [line for line in console["transcript"] if line.strip() == ECHO] != [ECHO, ECHO]:
        fail("s370_diag: the 1052 keyboard exerciser did not echo the operator input")
    check_hex_dump(tape, show)
    check_pack(tape, show)

    m = machine(tape)
    m.ctc(0x320, peer = 0x420)
    m.ipl(0x130)
    # Sense switch 14 selects wrap mode, with both sides on the same IOCE.
    ctc = sdm(m, message = "E/SW.00020400/A,01F/A,00E/AA0000320/AA0000420/I,01F,01F,00E,130/LA051/B",
              budget = 90000000, show = show)
    check(ctc, ["DA0515"], [])
    if ctc["sections"][0]["routines"] != "0A":
        fail("s370_diag: DA0515 did not run all ten routines")

    m = machine(tape)
    m.dau(0x20)
    m.ipl(0x130)
    # DAU option 01 selects the F26329 multi-device attachment.
    dau = sdm(m, message = "E/A,01F/A,00E/AB0010021/I,01F,01F,00E,130/LB051.B052/B",
              budget = 40000000, show = show)
    check(dau, ["DB0513", "DB0522"], [])
    if [s["routines"] for s in dau["sections"]] != ["0F", "08"]:
        fail("s370_diag: the 2701 did not run all 23 routines")

    check_storage_dump(tape, show)
    print("works: diag1.tap completed %d sections with zero errors after restoring D11792's zero-key checks, sixteen jobs reached SDM EOJ and D806A5 terminated after its full pack scan" %
          len(CE_SECTIONS))
    print("D0CF00 preserved storage on reconstructed card IPL and verified console and interrupt-key dumps at all eight printer addresses.")


def main(args):
    valid_cards = read_raw_deck(open(args[0])) if args else None
    run_original(source(), valid_cards = valid_cards, show = bool(args))
