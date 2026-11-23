"""Validate FAA listing corrections against the pinned 9020 diagnostic reel.

Run: go run ./cmd/trex scripts/smoke/s370_diag_faa.star
The unchanged reel remains the reference for scripts/smoke/s370_diag.star.
The corrections below check the original bytes and use guest storage or an
in-memory copy of the utility's master reel.
"""

load("//scripts/inspect:s370_diag.star", "END_OF_JOB", "SDM_READY", "faa_correction", "faa_ioce", "faa_ioce_sdm", "faa_mdm", "library_reel", "machine", "sdm", "source")
load("//scripts/smoke:s370_diag.star", "CE_SECTIONS")

def library_headers(records):
    headers = []
    for i, record in enumerate(records):
        if record.tape_mark:
            break
        if record.data != None and record.data.size == 12:
            data = binary.hex(record.data.bytes(0, 12)).upper()
            if data[1:4] in ["FFF", "FFE"] and data[8] == "D":
                headers.append((i, data))
    return headers

def check_ioce(tape):
    m = faa_ioce(tape)
    m.event_limit(20000)
    m.trace_io(skip = [0x00c, 0x00e, 0x01f])
    faa_ioce_sdm(m)

    headers = library_headers(archive.simh(tape).records)
    expected = [data for _, data in headers if data[1:4] == "FFF" and "D1003000" <= data[8:16] and data[8:16] <= "D1075000"]

    # These are the IDM's actual header reads. It halts on an error
    # before proceeding to another section or handing control to SDM.
    header = "0130 cmds [02 f=20 n=12 st=0C "
    headers = [line.split(header)[1][:24] for line in m.events() if header in line]
    seen = [data for data in headers if data[1:4] == "FFF" and "D1003000" <= data[8:16] and data[8:16] <= "D1075000"]
    if len(expected) != 66 or seen != expected:
        fail("IDM header reads differ from the pinned IOCE bring-up sequence (%d expected, %d read)" % (len(expected), len(seen)))
    m.trace_io(False)
    res = sdm(m, message = "A/A,01F/A,00E/I,01F,01F,01F,130/SW.00000400/L2101/L2740/B",
              budget = 400000000, show = False)
    completed = [(s["section"], s["routines"]) for s in res["sections"]]
    if (res["ended"] != "end-of-job" or completed != [("D21010", "04"), ("D27402", "0C")] or
        res["errors"] or res["skipped"] or "PGM TSTING 00A000 TO 01F000" not in [line.strip() for line in res["transcript"]]):
        fail("IOCE storage diagnostics did not reach SDM EOJ with the expected routine counts\n" + "\n".join(res["transcript"][-18:]))
    return [data[8:14] for data in seen] + [section for section, _ in completed]

def check_job(m, section, required):
    lines = [line.strip() for line in m.screens(0x01f)]
    if ([line for line in lines if line.startswith("S   ")] != ["S   " + section] or
        [line for line in lines if line == END_OF_JOB] != [END_OF_JOB] or
        any([line.startswith("* ") or line.startswith("HLT ") for line in lines]) or
        any([line not in lines for line in required])):
        fail("%s did not finish cleanly (%s)\n%s" % (section, m.psw(), "\n".join(lines[-18:])))

def check_tape_end(tape):
    m = machine(tape)
    # A22-6866-4 describes reels with as little as 50 feet of usable tape.
    m.tape(0x3f0, tape.slice(0, 0), type = "2401", eot_inches = 50 * 12)
    m.ipl(0x130)
    m.break_at(0x8690)
    start = sdm(m, message = "E/A,01F/A400003F0/I,01F,01F,01F,130/SW.00000400/L4061/B",
                budget = 28000000, step = 100000, stop = "S   D40610", show = False)
    if start["ended"] != "stop" or start["errors"]:
        fail("D40610 did not start cleanly")
    r = m.run(instructions = 5000000)
    if r.kind != "breakpoint":
        fail("D40610 did not reach the sense comparison (%s %s)" % (r.kind, r.psw))
    # D4061000.SPT returns through R5 if the comparison succeeded.
    # Preserve the error path by branching to its existing copy.
    faa_correction(m, 0x8690, "D212F31EF251", "078547F0F67C")
    m.clear_breaks()
    m.run(instructions = 60000000)
    check_job(m, "D40610", ["TAPE REWINDING -- END OF TAPE SENSED.", "T   D40610 79 ROUTINES RUN"])

def check_card_to_tape(tape):
    m = machine(tape, scratch_tapes = [0x3f0], punch = True)
    m.ipl(0x130)
    r = m.run(instructions = 30000000)
    if r.psw != SDM_READY:
        fail("D70F12: SDM did not reach the operator prompt (%s %s)" % (r.kind, r.psw))
    card = "FAA 9020 CARD TO TAPE " + "0123456789" * 5 + "ABCDEFGH"
    m.cards(0x00c, ["E/A,01F/A,00E/A,00C/A6B00000D/A400003F0/I,01F,01F,00E,130/L70F1/B", card])
    m.interrupt_key()
    started = False
    for _ in range(250):
        r = m.run(instructions = 100000)
        started = "CARD TO TAPE ROUTINE" in [line.strip() for line in m.screens(0x01f)]
        if started:
            break
    if not started:
        fail("D70F12 did not start the card-to-tape routine (%s %s)" % (r.kind, r.psw))

    # Restore D70F1200.SPT's BALL masks after the utility is loaded.
    for addr in [0x84fd, 0x8537, 0x8627, 0x862f, 0x8637]:
        faa_correction(m, addr, "40", "10")
    m.run(instructions = 35000000)
    check_job(m, "D70F12", ["CARD TO TAPE ROUTINE"])
    data = m.tape_record(0x3f0, 0)
    if len(data) != 80 or binary.text(data, encoding = "cp037") != card or m.tape_record(0x3f0, 1) != None:
        fail("D70F12 did not copy the entire 80-byte card followed by a tape mark")

def disk_master(tape):
    # D8150400.SPT identifies the master reel by the first eight bytes of
    # its IPL record. The pinned reel's initial PSW has a 3F high byte
    # instead of 0F. Mount the corrected copy on a second drive.
    # D00104's disk path compares the D00201 catalog entry against DCDTA
    # and seeks to the separate HEAD1 constant. The pinned Go/No-Go text
    # spans three tracks on the 2314, so D81504 places D00201 at 150/2/3.
    # The D00104 text starts at absolute location 8.
    records = archive.simh(tape).records
    go_no_go = records[2]
    if go_no_go.data.bytes(0, 4) != b"\xd0\x01\x04\x00":
        fail("D81504: expected Go/No-Go text after the IPL header")
    start = go_no_go.offset + 4 - 8
    # SDM must keep the catalog at X'8000'. D0C00C00.SPT initializes
    # R14 there and reserves X'7000' for the D0D60 overlay.
    sdm_text = records[18]
    if sdm_text.data.bytes(0, 4) != b"\xd0\xc0\x0c\x00":
        fail("D81504: expected SDM text")
    monitor = sdm_text.offset + 4 - 8
    updates = [
        (8, b"\x3f", b"\x0f"),
        (start + 0x10f8, b"\x00\x01", b"\x00\x02"),
        (start + 0x1110, b"\x96\x01\x03\xc0", b"\x96\x02\x03\x80"),
        (monitor + 0x182, b"\x41\xef\x10\x00", b"\x41\xe2\x10\x00"),
        (monitor + 0x5c10, b"\x86\x00\x70\x00", b"\x86\x00\x80\x00"),
    ]
    master = binary.builder(capacity = tape.size)
    prev = 0
    for offset, before, after in updates:
        if tape.bytes(offset, len(before)) != before:
            fail("D81504: unexpected master bytes at offset %d" % offset)
        master.append(tape.bytes(prev, offset - prev))
        master.append(after)
        prev = offset + len(before)
    master.append(tape.bytes(prev, tape.size - prev))
    return master.file()

def start_disk_build(tape):
    m = machine(tape)
    m.tape(0x3f0, disk_master(tape), type = "2401", format = "simh")
    # Choose a unit byte the Go/No-Go and Hardcore disk loaders both recognize.
    m.dasd(0x350, type = "2314", cylinders = 203, volser = "FAA902")
    m.ipl(0x130)
    m.break_at(0x80fc)
    start = sdm(m, message = "E/A,01F/A,00E/A400003F0/A80000350/I,01F,01F,00E,130/L8150/B",
                budget = 30000000, step = 100000, stop = "S   D81504", show = False)
    if start["ended"] != "stop" or start["errors"] or m.run(instructions = 1000000).kind != "breakpoint":
        fail("D81504 did not start disk initialization")
    m.clear_breaks()
    # Request initialization, full-pack read and build together. The
    # manual's single-bit BALL branches select each requested routine.
    faa_correction(m, 0x8004, "00", "E0")
    for addr in [0x8123, 0x8307, 0x8945]:
        faa_correction(m, addr, "40", "10")
    # The three immediate-status tests and the I/O interruption handler
    # branch on all selected bits (BALL), including CE without DE on rewind.
    for addr in [0x8589, 0x8591, 0x8599]:
        faa_correction(m, addr, "40", "10")
    faa_correction(m, 0x87ce, "074B", "071B")
    for addr in [0x89d7, 0x8a35, 0x8cc3, 0x8d07, 0x8ef5, 0x8f39]:
        faa_correction(m, addr, "40", "10")
    # RTN03F normally terminates an RLD chain when it reads the next
    # section header. On the final pass, EOF branches straight to RTN03Y.
    # Replay RTN03F's read, zero, and write of the last key before the
    # existing rewind/unload and VTOC write, preserving the last section.
    finish_rld = binary.hex(m.read(0x8b16, 0x1e)).upper()
    if finish_rld != "58C0F0E44130E1A89200F69045B0F52AD2039C22E0F44130E1C845B0F52A":
        fail("D81504: RTN03F's final-key code differs from the pinned reel")
    rewind = "58C0F0E092FFF6904130E13845B0F52AD706ED3BED3B47F0FF10"
    code = finish_rld + rewind
    faa_correction(m, 0x20000, "00" * (len(code) // 2), code)
    faa_correction(m, 0x8f02, "4130E13845B0F52AD706", "5830FF0807F300020000")
    return m

def check_disk_build(tape):
    m = start_disk_build(tape)
    for _ in range(75):
        m.run(instructions = 40000000)
        if END_OF_JOB in [line.strip() for line in m.screens(0x01f)]:
            break
    check_job(m, "D81504", ["INITIALIZATION COMPLETE", "DISK READ COMPLETE", "PASS ONE", "PASS TWO", "DISK BUILD COMPLETE", "T   D81504 03 ROUTINES RUN"])
    if m.dasd_usage()[0x350]["written"] != [(0, 4059)]:
        fail("D81504 did not format the full 2316 pack")

    records = archive.simh(tape).records
    expected = [(data[8:16], binary.hex(records[i + 1].data.bytes(0, 4)).upper()) for i, data in library_headers(records)]

    toc = m.dasd_track(0x350, 150, 0, 6800)[1].partition(" data=")[2]
    entries = [toc[i:i + 16] for i in range(0, len(toc), 16) if toc[i:i + 8] != "00000000"]
    if len(toc) != 2 * 6800 or len(entries) != 226 or [entry[:8] for entry in entries] != [section for section, _ in expected]:
        fail("D81504 did not write the complete diagnostic volume table of contents")
    for entry, (_, first_word) in zip(entries, expected):
        cyl, head = int(entry[8:10], 16), int(entry[10:12], 16)
        rows = [row for row in m.dasd_track(0x350, cyl, head, 4) if row[8:10] == entry[12:14]]
        if len(rows) != 1 or not rows[0].endswith("data=" + first_word):
            fail("D81504: VTOC entry %s does not point to the expected text record" % entry)
    tracks, catalog = {}, {}
    listing = False
    last_row = []
    for line in m.output(0x00e):
        fields = line.split()
        if len(fields) == 9 and fields[0] == "00" and fields[5:8] == ["00", "00", "0008"]:
            if fields[1:3] != fields[3:5]:
                fail("D81504: Home Address and Record Zero disagree in the printout")
            tracks[(int(fields[1], 16), int(fields[2], 16))] = True
        if line.strip() == "PRINT OUT OF THE VTOC AND KEYS":
            listing = True
        if listing:
            if len(fields) == 6 and fields[0].startswith("D"):
                catalog[fields[0]] = fields[1]
            if fields:
                last_row = fields
    if sorted(tracks) != [(c, h) for c in range(203) for h in range(20)]:
        fail("D81504 did not print all 4,060 Home Address and Record Zero pairs")
    if catalog != {entry[:8]: entry[8:] for entry in entries} or not last_row or last_row[0] != "RLD" or last_row[-1] != "00000000":
        fail("D81504 did not print the complete catalog and terminate its last relocation chain")
    boot = m.dasd_track(0x350, 0, 0, 8)
    if len(boot) < 3 or not boot[1].endswith("data=000400000F000010") or not boot[2].endswith("data=07000F9040000006"):
        fail("D81504 did not write the IBM disk IPL records")
    m.ipl(0x350, clear = True)
    res = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,00E/L1101/B",
              budget = 40000000, show = False)
    completed = [(s["section"], s["routines"]) for s in res["sections"]]
    if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
        completed != [("D11011", "4E")]):
        fail("D81504: disk-loaded D11011 did not complete cleanly (%s %s)\n%s" %
             (res["ended"], res["run"].psw, "\n".join(res["transcript"][-18:])))

def mdm_job(m, message, section, routines, budget):
    m.console(2, type = "1052")
    r = m.run(instructions = 35000000)
    if r.psw != SDM_READY:
        fail("MDM did not wait for an operator request (%s %s)" % (r.kind, r.psw))
    m.key(2, "REQUEST")
    m.run(instructions = 10000000)
    if "MDM D/E REVISION 0A READY CD017 SIMPLEX" not in [line.strip() for line in m.screens(2)]:
        fail("MDM did not prompt for a load message")
    m.type(2, message)
    m.run(instructions = budget)
    lines = [line.strip() for line in m.screens(2)]
    if ([line for line in lines if line.startswith("START ")] != ["START   " + section] or
        [line for line in lines if line.startswith("T CE")] != ["T CE1  %s      %s" % (routines, section)] or
        [line for line in lines if line == "EOJ  MDM JOB COMPLETE"] != ["EOJ  MDM JOB COMPLETE"] or
        any([line.startswith("*") or line.startswith("HLT ") or line.startswith("RNV ") for line in lines])):
        fail("%s did not finish cleanly (%s)\n%s" % (section, m.psw(), "\n".join(lines[-45:])))

def check_dual_dau(tape):
    m = faa_mdm(tape)
    m.dau(0x20, peer = 0x420)
    mdm_job(m, "A32/AB0020021/AB0020421/LB0A1,021,421/B/", "DB0A10", "001", 45000000)

def check_dual_2821(tape):
    m = faa_mdm(tape)
    # The 2821 uses the three low address bits to select printer 1,
    # reader, punch, printer 2 or printer 3 in that order.
    m.unit_record(0x028, type = "1403")
    m.unit_record(0x029, type = "2540R", cards = ["FAA 2821 DIAGNOSTICS"] * 16)
    m.unit_record(0x02a, type = "2540P", reader = 0x029)
    m.unit_record(0x02b, type = "1403")
    m.unit_record(0x02c, type = "1403")
    m.unit_record_switch([(0x028 + i, 0x428 + i) for i in range(5)])
    mdm_job(m, "A32/A63000028/A63000428/A62000029/A62000429/A6B00002A/A6B00042A/" +
            "A6300002B/A6300042B/A6300002C/A6300042C/L6AA0,028,428,029,429,02A,42A,02B,42B,02C,42C/B/",
            "D6AA00", "023", 120000000)

def wait_1052_read(m):
    for _ in range(350):
        if "blocked=true" in m.subchannel(0x01f):
            return
        m.run(instructions = 20000)
    fail("1052 did not request keyboard input (%s)\n%s" % (m.psw(), "\n".join(m.screens(0x01f)[-10:])))

def start_1052(tape, section, prompt):
    m = machine(tape)
    m.ipl(0x130)
    start = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,00E,130/L" + section + "/B",
                budget = 90000000, step = 20000, stop = prompt, show = False)
    if start["ended"] != "stop" or start["errors"]:
        fail("D%s: 1052 diagnostic did not reach its operator prompt" % section)
    return m

def check_1052_operator(tape):
    m = start_1052(tape, "6651", "MAKE 1052 NOT RDY")
    m.key(0x01f, "NOT READY")
    # Allow the prompt's carrier return and the diagnostic's not-ready probe.
    m.run(instructions = 2400000)
    m.key(0x01f, "READY")
    m.run(instructions = 2110000)
    if "DEPRESS 1052 REQUEST BUTTON" not in m.screen(0x01f):
        fail("D66511 did not receive device end from the ready transition")
    m.key(0x01f, "REQUEST")
    wait_1052_read(m)
    m.type(0x01f, "ABC", cancel = True)
    m.run(instructions = 26000000)
    check_job(m, "D66511", ["ENTER 3 CHARS.,THEN CANCEL MSG.", "T   D66511 06 ROUTINES RUN"])

    m = start_1052(tape, "6653", "TYPE LOWER CASE TAB THRU LINE FEED")
    # Enter the eight keyboard rows in D6653100.SPT, including the
    # control keys. The first inquiry intentionally overfills its count.
    for row in [
        "05F1F2F3F4F5F6F7F8F9F060501625C1", "98A68599A3A8A48996977C15",
        "81A2848687889192935B7B", "A9A783A58295946B4B6140",
        "7E4C5E7A6C7D6E5C4D5D6D4E", "D8E6C5D9E3E8E4C9D6D74A",
        "C1E2C4C6C7C8D1D2D35A7F", "E9E7C3E5C2D5D44F5F6F",
    ]:
        wait_1052_read(m)
        m.type(0x01f, binary.text(binary.decode(row, "hex"), encoding = "cp037"))
    m.run(instructions = 20000000)
    check_job(m, "D66531", ["T   D66531 08 ROUTINES RUN"])

def check_disk_maintenance(tape):
    m = machine(tape)
    m.dasd(0x340, type = "2314", cylinders = 203, volser = "FAA902")
    m.ipl(0x130)
    res = sdm(m, message = "E/A,01F/A,00E/A80000340/I,01F,01F,00E,130/L8050/L8067.8069/B",
              budget = 500000000, step = 125000, show = False)
    completed = [(s["section"], s["routines"]) for s in res["sections"]]
    lines = [line.strip() for line in res["transcript"]]
    if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
        completed != [("D80501", "03"), ("D80671", "03"), ("D80683", "01"), ("D80692", "01")] or
        not any([s.startswith("RPM ") and s.endswith("WITHIN TOLERANCE") for s in lines]) or
        "AVG ACCESS TIME WITHIN  TOLERANCE" not in lines):
        fail("2314 maintenance did not complete with the operator bypass off\n" + "\n".join(lines[-30:]))

def check_ctc_operator(tape):
    m = machine(tape)
    m.ctc(0x320, peer = 0x420)
    m.ipl(0x130)
    r = m.run(instructions = 30000000)
    if r.psw != SDM_READY:
        fail("DA0515: SDM did not reach the operator prompt")
    # Switch 14 selects wrap mode. Leave the manual bypass off.
    m.cards(0x00c, ["E/SW.00020000/A,01F/A,00E/AA0000320/AA0000420/I,01F,01F,00E,130/LA051/B"], replace = True)
    m.break_at(0x97dc)
    m.interrupt_key()
    r = m.run(instructions = 95000000)
    if r.kind != "breakpoint" or m.read(0x8000, 3) != b"\xda\x05\x15":
        fail("DA0515 did not reach the restart setup")
    # DA051500.SPT's SET4 reads the ATR before saving the pair.
    # Replay the displaced STM after the restored IATR.
    faa_correction(m, 0xafc0, "00" * 10, "0E7890789AB447F097E0")
    faa_correction(m, 0x97dc, "90789AB4", "47F0EFC0")
    m.clear_breaks()
    m.break_at(0x9420)
    prompt = "DEPRESS STOP,RESET AND PSW RESTART ON   CE 1"
    for direction in range(2):
        r = m.run(instructions = 80000000)
        lines = [line.strip() for line in m.screens(0x01f)]
        if (r.kind != "breakpoint" or m.read(0, 8) != b"\x00\x00\x00\x00\x00\x00\x98\xea" or
            len([line for line in lines if line == prompt]) != direction + 1):
            fail("DA0515: missing operator restart for interface %d (%s %s)" % (direction + 1, r.kind, r.psw))
        m.restart(storage_element = 1)
    m.run(instructions = 80000000)
    check_job(m, "DA0515", ["T   DA0515 0A ROUTINES RUN"])

def main(args):
    tape = library_reel(source())
    ioce = check_ioce(tape)
    check_tape_end(tape)
    check_card_to_tape(tape)
    check_disk_build(tape)
    check_dual_dau(tape)
    check_dual_2821(tape)
    check_1052_operator(tape)
    check_disk_maintenance(tape)
    check_ctc_operator(tape)
    print("works: 68 IOCE sections, 3 SDM sections and 2 MDM sections completed with zero errors using FAA corrections.")
    sections = CE_SECTIONS + ioce + ["D40610", "D70F12", "D81504", "DB0A10", "D6AA00"]
    loaders = ["D00104", "D00201", "D00402", "D0B014", "D0C00C", "D0CF00", "D0D107",
               "D0D50A", "D0D601", "D0D704", "D0D800"]
    catalog = [data[8:14] for _, data in library_headers(archive.simh(tape).records)]
    if len(sections) != 215 or sorted(catalog) != sorted(sections + loaders):
        fail("the smoke section lists do not account for the complete pinned tape catalog")
    print("The two smokes cover the tape catalog's 215 diagnostic and utility sections, alongside 11 loader and monitor entries.")
    print("D81504 printed the pack and catalog listings. The generated disk IPL ran D11011 to SDM EOJ.")
    print("1052, 2314 and channel-adapter jobs completed with the manual bypass off.")
