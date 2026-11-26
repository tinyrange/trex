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

# The test carriage tape the 1403 sections ask the operator to install
# (66 lines, one channel per line). The sections check each skip by spacing
# one line past the channel: the line after channels 1-3 and 10-12 holds
# channel 9 (unit check) and the line after channels 4-9 holds channel 12
# (unit exception).
CE_TAPE = [[1], [9], [2], [9], [3], [9], [4], [12], [5], [12], [6], [12], [7], [12], [8], [12],
           [9], [12], [10], [9], [11], [9], [12], [9]] + [[]] * 42

def d405f_scratch_record(data, bad = False):
    size = len(data) // 2
    header = binary.hex(bytes([size % 256, size // 256, 0, 128 if bad else 0]))
    return binary.decode(header + data + header, "hex")

def d405f_scratch_reel(fault):
    # D405F100.SPT WRTFLD, with records using successively longer prefixes.
    pattern = binary.hex(bytes(list(range(256))))
    pattern += "".join([pair * 8 for pair in "BC43 35CA 8A60 6015 0802 8040 2000 1001 0104 2D96 D568 DA35 CA75 609B 47A8 8138".split()])
    normal = [d405f_scratch_record(pattern[:size * 2]) for size in [16, 64, 128, 256, 512]]
    first = list(normal)
    if fault == "compare":
        first[1] = d405f_scratch_record("FF" + pattern[2:32] + "FF" + pattern[34:128])
    if fault == "length":
        first[0] = d405f_scratch_record(pattern[:28])
        first[1] = d405f_scratch_record(pattern[:124])
    if fault == "data-check":
        first[0] = d405f_scratch_record(pattern[:32], bad = True)
    reel = binary.builder(capacity = 512000)
    reel.append(d405f_scratch_record("F0F3C6F0"))  # 03F0 origin, EBCDIC
    for record in first + normal * 499:
        reel.append(record)
    return reel.file()

def machine(tape, scratch_tapes = [], punch = False, element = "", memory = 1 << 20, model = "9020", printer_dualing = False, console_ribbon = False, dual_density = False, boot_2401 = False, printer = True, interval_timer = True):
    m = emulator.s390(architecture = "s360", model = model, element = element, memory = memory, interval_timer = interval_timer, mips = 1, start = "1985-08-30T12:00:00Z")
    if boot_2401:
        m.tape(0x130, tape, format = "simh", type = "2401", model = 2, ring = False)
    else:
        m.tape(0x130, tape, format = "simh", type = "3420")
    for dev in scratch_tapes:
        m.tape(dev, tape.slice(0, 0), type = "2401", dual_density = dual_density)
    m.console(0x01f, type = "1052", ribbon_shift = console_ribbon)
    if printer:
        m.unit_record(0x00e, type = "1403", dualing = printer_dualing)
        m.carriage_tape(0x00e, CE_TAPE)
    m.unit_record(0x00c, type = "2540R", cards = [])
    if punch:
        m.unit_record(0x00d, type = "2540P", reader = 0x00c)
    return m

def check_d11011_machine_check(m, element, logout, mode, console_start, printer):
    m.break_at(0x9288)
    entry = m.run(instructions = 30000000)
    if (entry.kind != "breakpoint" or entry.psw != "01040000 00009288" or
        m.read(0x8000, 4) != binary.decode("d1101101", "hex")):
        fail("D11011 did not start routine 01: %s %s" % (entry.kind, entry.psw))
    m.clear_breaks()
    if mode == "section-handler":
        # FLAGS2 bit 08 requests return of the interruption to the section.
        m.break_at(0x963c)
        armed = m.run(instructions = 10000000)
        if armed.kind != "breakpoint" or armed.psw != "01040000 2000963C" or m.read(0x800f, 1) != b"\x08":
            fail("D11011 did not arm its own machine-check handler")
        m.clear_breaks()
        m.break_at(0x8124)
        m.replay_machine_check(0, element, logout)
        handler = m.run(instructions = 10000000)
        if (handler.kind != "breakpoint" or handler.psw != "01040000 00008124" or
            binary.hex(m.read(0x8030, 8)) != "0104000%d2000963c" % element):
            fail("SDM did not return the old PSW to D11011")
        m.clear_breaks()
        m.break_at(0x813c)
        nested = m.run(instructions = 100000000)
        if nested.kind != "breakpoint" or nested.psw != "00000000 0000813C" or m.read(0x800f, 1) != b"\x08":
            fail("D11011 did not arm its nested check while machine checks were masked")
        m.clear_breaks()
        m.replay_machine_check(0, element, logout)
        m.break_at(0x8152)
        restored = m.run(instructions = 10000000)
        if (restored.kind != "breakpoint" or restored.psw != "01040000 00008152" or
            binary.hex(m.read(0x8030, 8)) != "0004000%d0000814c" % element or
            binary.hex(m.read(0x8070, 8)) != "0104000000008124"):
            fail("D11011 did not consume the pending check and restore its handler")
        print("D11011 received the old PSW, printed its logout and consumed a nested check on LPSW")
    else:
        for expected_resume in [0x9288, 0x9294]:
            m.break_at(0x54a0)
            m.replay_machine_check(0, element, logout)
            handler = m.run(instructions = 60000000 if printer else 3000000000)
            if handler.kind != "breakpoint" or int(handler.psw[-6:], 16) != 0x54a0:
                fail("formatter did not return after the D11011 check: %s %s" % (handler.kind, handler.psw))
            m.clear_breaks()
            m.break_at(0x9288)
            m.break_at(0x9294)
            resume = m.run(instructions = 10000000)
            if resume.kind != "breakpoint" or int(resume.psw[-6:], 16) != expected_resume:
                fail("SDM resumed at %s, want %x" % (resume.psw, expected_resume))
            m.clear_breaks()
        print("SDM retried routine 01 after the first check, then advanced to routine 02 after the second")
    m.clear_breaks()
    m.run(instructions = 100000000)
    lines = [line.strip() for line in m.screens(0x01f)[console_start:]]
    if mode == "section-handler":
        if not any(["MACHINE CHECK ERROR OCCURRED IN BCE 1" in line for line in lines]):
            fail("D11011 did not print its machine-check report")
    elif len([line for line in lines if line == "* MCK D11011 01 0104000%d00009288" % element]) != 2 or "ROUTINE TERMINATED" not in lines:
        fail("SDM did not report both checks and routine termination")
    if END_OF_JOB not in lines:
        fail("D11011 did not reach SDM end of job")


def check_ipl_headers(tape):
    """Verify the IPL execution sequence and the resident SDM records."""
    records = archive.simh(library_reel(tape)).records
    headers = {data: index for index, data in library_headers(records)}
    m = machine(tape)
    m.event_limit(8192)
    m.trace_io(quiet_polls = True)
    m.ipl(0x130)
    # D00402 executes a copy of its register-comparison instructions in low storage.
    for address, index, offset in [(0x40c, 2, 0x404), (0x410, 5, 0x10), (0x424, 8, 0x3342), (0x150, 18, 0x148)]:
        m.break_at(address)
        r = m.run(instructions = 30000000)
        payload = records[index].data
        base = 0x400 if index == 5 else 8
        if (r.kind != "breakpoint" or int(r.psw[-6:], 16) != address or
            m.read(base, 4) != payload.bytes(0, 4) or
            m.read(address, 32) != payload.bytes(offset, 32)):
            fail("unexpected IPL code at %x in payload record %d" % (address, index))
        print("IPL reached %x in %s" % (address, binary.hex(m.read(base, 4)).upper()))
        m.clear_breaks()
    marker = "0130 cmds [02 f=20 n=12 st=0C "
    seen = [line.split(marker)[1][:24] for line in m.events() if marker in line]
    matches = [(headers[h], h[8:16]) for h in seen if h in headers]
    if matches != [(4, "D0020100"), (7, "D0040200"), (14, "D0B01400"), (17, "D0C00C00")]:
        fail("unexpected catalog header sequence before SDM entry: %s" % matches)
    reads = [line for line in m.events() if "resume 0130 cmds [02 " in line]
    idm_header = binary.hex(records[14].data.bytes(0, 12)).upper()
    start = [i for i, line in enumerate(reads) if marker + idm_header in line]
    if len(start) != 1:
        fail("IPL did not scan the IDM header exactly once")
    for i, count in enumerate([12, 12, 12, 12, 36863]):
        prefix = binary.hex(records[14 + i].data.bytes(0, 12)).upper()
        if "n=%d st=0C %s" % (count, prefix) not in reads[start[0] + i]:
            fail("unexpected read of tape record %d during monitor selection" % (14 + i))
    print("IPL scanned the IDM text and relocation records with 12-byte reads, then loaded SDM")
    print(matches)
    if m.run(instructions = 30000000).psw != SDM_READY:
        fail("SDM did not reach its operator wait")
    vector = m.read(0x70, 8)
    if binary.hex(vector).lower() != "000000000f005124":
        fail("unexpected machine-check new PSW: %s" % binary.hex(vector))
    if m.read(0x5124, 32) != records[18].data.bytes(0x5124 - 8, 32):
        fail("machine-check entry differs from SDM text")
    print("SDM installed the machine-check new PSW at 0070 with entry 5124")
    for index, address in [(30, 0x7000), (36, 0x14000)]:
        data = records[index].data
        if m.read(address, data.size) != data.bytes(0, data.size):
            fail("SDM resident area at %x differs from record %d" % (address, index))
        print("SDM loaded %s at %x (%d bytes)" % (binary.hex(data.bytes(0, 4)), address, data.size))
    if m.read(0x4d, 3) != b"\x01\x40\x00":
        fail("SDM common adaptation pointer does not reference the loaded table")

def check_mdm_tape_id(tape, inline):
    m = faa_mdm(tape)
    reel = binary.builder(capacity = 18)
    reel.append(binary.decode("020000001122020000000000000000000000", "hex"))
    m.tape(0x3f0, reel.file(), type = "2401", format = "simh")
    m.console(2, type = "1052")
    if m.run(instructions = 35000000).psw != SDM_READY:
        fail("FAA MDM did not reach the operator wait")
    m.key(2, "REQUEST")
    m.run(instructions = 10000000)
    if "MDM D/E REVISION 0A READY CD017 SIMPLEX" not in [line.strip() for line in m.screens(2)]:
        fail("FAA MDM did not prompt for a load message")
    m.type(2, "A32/A400003F0/L4156,3F0/" + ("Q4156.TAPE001/" if inline else "") + "B/")
    m.run(instructions = 60000000)
    before = [line.strip() for line in m.screens(2)]
    if "START   D41560" not in before or before[-1:] != ["HLT D41560"]:
        fail("FAA MDM did not halt for D41560 tape ID: %s" % before[-10:])
    m.key(2, "REQUEST")
    m.run(instructions = 10000000)
    m.trace_io(quiet_polls = True)
    m.type(2, "B/" if inline else "Q4156.TAPE001/B/")
    m.run(instructions = 60000000)
    lines = [line.strip() for line in m.screens(2)[len(before):]]
    if ("RECORD NUMBER 00000001  BYTE COUNT 0002" not in lines or
        not any([line.startswith("000000  1122 ") for line in lines]) or
        "000 ERRORS ENCOUNTERED ON TAPE001" not in lines or
        "EOJ  MDM JOB COMPLETE" not in lines):
        fail("D41560 did not report TAPE001 and EOF: %s" % lines[-25:])
    events = m.events()
    if (lines[-1:] != ["UIO     0000000026000000"] or
        not any(["SIO 03F0" in event and "[0F " in event for event in events]) or
        not any(["device end 03F0 -> dev 26" in event for event in events])):
        fail("unexpected D41560 post-job tape status")
    print("D41560 reported TAPE001 from %s Q input and reached MDM EOJ. Rewind-unload then returned status 26." %
          ("inline" if inline else "post-halt"))

FORMATTER_SWITCHES = {
    "long": "00000000", "short": "00001000", "switch27": "00000010",
    "switch28": "00000008", "switch30": "00000002", "routine": "00000000",
    "section-handler": "00000000", "short-base-control": "00001000",
    "short-data-control": "00001000", "storage": "00000000", "storage-mcw": "00000000",
    "short-restored": "00001000", "long-restored": "00000000",
}

def check_formatter(tape, element, mode, profile = "00E"):
    """Replay a 9020 machine check at SDM section load and verify the report."""
    printer = profile != "1052-only"
    output = "00E" if profile == "00E" else "01F"
    m = machine(tape, printer = printer)
    m.ipl(0x130)
    options = FORMATTER_SWITCHES[mode]
    short = mode.startswith("short")
    restored = mode.endswith("-restored")
    short_control = short and mode != "short"
    if m.run(instructions = 30000000).psw != SDM_READY:
        fail("SDM startup failed")
    devices = "A,01F/A,00E/" if printer else "A,01F/"
    m.cards(0x00c, ["E/" + devices + "I,01F,01F," + output + ",130/SW." + options + "/L1101/B"], replace = True)
    # Pause at the end of the loader scratch clear, with PSW MC enabled.
    m.break_at(0x1d6a)
    m.interrupt_key()
    before = m.run(instructions = 30000000)
    if before.kind != "breakpoint" or before.psw != "00040000 00001D6A":
        fail("SDM did not reach the machine-check test point: %s %s" % (before.kind, before.psw))
    m.clear_breaks()
    if restored:
        # D0C00C00.SPT statements 7176–7190 and 7210–7221. This control
        # is a single CE (CE 1) receiving a CE or attached IOCE logout.
        # Preserve the CE flag setup and supply the CE's printable identity.
        code = "412000F14140400847F093AC"
        faa_correction(m, 0x5fb0, "00" * (len(code) // 2), code)
        faa_correction(m, 0x53a8, "41404008", "47F09FB0")
        # Keep the attached IOCE number already read from the old PSW.
        # Only zero-filled, non-storage-error logouts use this restoration.
        faa_correction(m, 0x53ce, "43429534", "41200000")
    if short_control:
        faa_correction(m, 0x5528, "00007800", "00007000")
        if mode in ["short-data-control", "short-restored"]:
            payload = archive.simh(library_reel(tape)).records[30].data
            if m.read(0x7800, 400) != b"\x00" * 400:
                fail("short formatter scratch area changed before the control")
            m.alter(0x7800, payload.bytes(0x800, 400))
    if mode == "storage-mcw":
        if not element:
            fail("storage-mcw requires an IOCE machine check")
        check_formatter_storage_mcw(m, element)
        return
    console_start = len(m.screens(0x01f))
    printer_start = len(m.output(0x00e)) if printer else 0
    logout = b"\x00" * (180 if element else 192)
    if mode == "storage":
        if element:
            # IOCE SE request indicator at 352 and LOS at 362.
            logout = binary.decode("00" * 28 + "80" + "00" * 9 + "04" + "00" * 141, "hex")
            m.break_program(6)
        else:
            # CE storage check register 2 at 168, SE1 and data check.
            logout = binary.decode("00" * 40 + "1008" + "00" * 150, "hex")
    if mode in ["routine", "section-handler"]:
        check_d11011_machine_check(m, element, logout, mode, console_start, printer)
        return
    m.break_at(0x519c if mode.startswith("switch") else 0x538a)
    # Replaying the logout exercises the guest handler without needing
    # to generate the preceding hardware fault.
    m.replay_machine_check(0, element, logout)
    identity = m.run(instructions = 30000000)
    old_psw = "0004000%d00001d6a" % element
    if mode.startswith("switch"):
        report = "* MCK SDM 12    " + old_psw.upper()
        outputs = m.screens(0x01f)[console_start:]
        if (identity.kind != "breakpoint" or int(identity.psw[-6:], 16) != 0x519c or
            binary.hex(m.read(0x30, 8)) != old_psw or
            (report in outputs) != (mode == "switch28") or
            (printer and m.output(0x00e)[printer_start:])):
            fail("unexpected suppression path: %s %s %s" % (identity.kind, identity.psw, outputs))
        print("%s suppressed the formatter, machine-check announcement=%s" % (mode, report in outputs))
        return
    if identity.kind != "breakpoint" or int(identity.psw[-6:], 16) != 0x538a:
        fail("SDM did not enter the formatter identity block: %s %s" % (identity.kind, identity.psw))
    m.clear_breaks()
    m.break_at(0x5468)
    identity = m.run(instructions = 30000000)
    if mode == "storage":
        storage_warning = "MCK INT DUE TO STORAGE ERROR- LOS NOT ISSUED"
        announced = storage_warning in m.screens(0x01f)[console_start:]
        if announced != (element == 0) or (element and m.read(362, 1) != b"\x04"):
            fail("unexpected storage-check handling by SDM")
        if element:
            if m.read(0x53ce, 8) != binary.decode("4342953447f09468", "hex"):
                fail("original IOCE path no longer bypasses the storage-check branch")
            print("IOCE logout retains LOS at 362; original SDM branches around its storage DIAG")
        else:
            print(storage_warning)
    if (identity.kind != "breakpoint" or int(identity.psw[-6:], 16) != 0x5468 or
        (mode == "long" and m.registers().gr[2] != "8000538A") or
        (mode == "long" and m.registers().gr[4] != ("00000041" if element else "00000008"))):
        fail("unexpected original-reel formatter identity arguments: %s %s %s" % (identity.kind, identity.psw, m.registers().gr[:5]))
    if restored:
        expected_flags = "0000000%d" % element if element else "00000008"
        expected_ce = "00000000" if element else "000000F1"
        if m.registers().gr[4] != expected_flags or m.registers().gr[2] != expected_ce:
            fail("restored monitor did not derive the expected logout identity")
    if mode == "long" and element:
        # The original IC uses R2 as an index into the IOCE identity
        # table. R2 is still a monitor link and points into section text.
        if (m.read(0x53ce, 4) != binary.decode("43429534", "hex") or
            m.registers().gr[9] != "00005000" or m.read(0xa8be, 1) != b"\x41"):
            fail("unexpected IOCE identity lookup in SDM")
    m.clear_breaks()
    m.break_at(0x5488 if short else 0x5498)
    dispatch = m.run(instructions = 30000000)
    if dispatch.kind != "breakpoint" or binary.hex(m.read(0x30, 8)) != old_psw:
        fail("SDM did not dispatch the machine check: %s %s" % (dispatch.kind, dispatch.psw))
    if "* MCK SDM 12    " + old_psw.upper() not in m.screens(0x01f)[console_start:]:
        fail("SDM did not report the old PSW")
    m.clear_breaks()
    if not short:
        payload_index = 24 if element else 33
        payload = archive.simh(library_reel(tape)).records[payload_index].data
        if m.read(0xd000, payload.size) != payload.bytes(0, payload.size):
            fail("SDM did not load formatter tape record %d verbatim" % payload_index)
    target = 0x70e6 if short_control else (0x78e6 if short else 0xd0e6)
    m.break_at(target)
    entry = m.run(instructions = 100)
    if entry.kind != "breakpoint" or int(entry.psw[-6:], 16) != target:
        fail("SDM did not branch to %x: %s %s" % (target, entry.kind, entry.psw))
    udt = "00000740" if output == "00E" else "00000730"
    if m.registers().gr[3] != udt:
        fail("unexpected formatter output UDT: %s" % m.registers().gr[3])
    m.clear_breaks()
    if mode == "short":
        m.break_program(1)
        finish = m.run(instructions = 100)
        if finish.kind != "program" or finish.detail != "program 0001 at 000078E6":
            fail("unexpected short formatter result: %s %s" % (finish.kind, finish.detail))
        print("old PSW %s, short formatter call to 78E6 raises operation exception 0001" % old_psw.upper())
        return
    m.break_at(0x5490 if short_control else 0x54a0)
    prints_on_1403 = printer and (not short_control or output == "00E")
    finish = m.run(instructions = 60000000 if prints_on_1403 else 3000000000)
    lines = (m.output(0x00e)[printer_start:] if prints_on_1403 else m.screens(0x01f)[console_start:])
    reports = [line.strip() for line in lines]
    if short_control:
        if (finish.kind != "breakpoint" or int(finish.psw[-6:], 16) != 0x5490 or
            "** 9020 D/E SHORT LOGOUT FORMAT **" not in reports or "END OF LOGOUTS" not in reports):
            fail("short formatter control did not print and return")
        check_reg_1_lines = len([line for line in reports if line.startswith("CHECK REG 1")])
        expected = 0 if mode == "short-base-control" or (element and not restored) else 2
        if check_reg_1_lines != expected:
            fail("short formatter control printed %d Check Register 1 headings, want %d" % (check_reg_1_lines, expected))
        if restored:
            heading = "IOCE %d LOGOUT" % element if element else "CE 1 LOGOUT"
            if heading not in reports:
                fail("short formatter report did not contain %s: %s" % (heading, reports[:6]))
        if element and not restored and (m.read(0x7083, 1) != b"\x00" or
            any([line.startswith("IOCE ") and "LOGOUT" in line for line in reports])):
            fail("short formatter control unexpectedly received an IOCE selector")
        if restored:
            print("D0D601 printed the short logout for %s and returned to SDM" % ("IOCE %d" % element if element else "CE 1"))
        else:
            print("%s returned to 5490 and printed %d Check Register 1 headings" % (mode, check_reg_1_lines))
    else:
        if restored:
            heading = "IOCE %d LOGOUT" % element if element else "CE 1 LOGOUT"
        else:
            heading = "IOCE 1 LOGOUT" if element else "CE ³ LOGOUT"
        if finish.kind != "breakpoint" or int(finish.psw[-6:], 16) != 0x54a0:
            fail("long formatter did not return to SDM: %s %s" % (finish.kind, finish.psw))
        if heading not in reports or "END OF LOGOUTS" not in reports:
            fail("formatter report did not reach the expected device: %s" % profile)
        if profile == "01F" and "END OF LOGOUTS" in m.screens(0x01f)[console_start:]:
            fail("formatter failed to select the available high-speed printer")
        print("old PSW %s, record %d, %s, %s and END OF LOGOUTS, returned to SDM at 54A0" %
              (old_psw.upper(), payload_index, "1403 at 00E" if printer else "1052 at 01F", heading))

    if restored:
        if short_control:
            # The formatter borrowed the SDM scratch area for its tables.
            m.alter(0x7800, b"\x00" * 400)
        m.clear_breaks()
        m.break_at(0x519c)
        resumed = m.run(instructions = 100)
        if resumed.kind != "breakpoint" or not resumed.psw.endswith("00519C"):
            fail("SDM did not reach its machine-check continuation: %s %s" % (resumed.kind, resumed.psw))


def check_formatter_storage_mcw(m, element):
    # Keep the IOCE identity and restore fallthrough to the SE logout.
    faa_correction(m, 0x53ce, "43429534", "41200000")
    faa_correction(m, 0x53d2, "47f09468", "47000000")
    # D22A0500 statements 4247–4250 and 5708–5718. The MCW selects SE2,
    # allowing the SDM and the result area to remain in running SE1.
    mcw = 0x5fc0
    faa_correction(m, mcw, "00" * 56, "00fd080020008000" + "00" * 48)
    m.break_at(0x5420)
    m.break_program(6)
    storage_logout = bytes(list(range(1, 49)))
    m.replay_storage_logout(2, storage_logout)
    # In the IOCE logout, byte 352 selects SE2 and byte 362 records LOS.
    m.replay_machine_check(0, element, binary.decode("00" * 28 + "40" + "00" * 9 + "04" + "00" * 141, "hex"))
    request = m.run(instructions = 30000000)
    if request.kind != "breakpoint" or not request.psw.endswith("005420") or m.registers().gr[1] != "00020000":
        fail("SDM did not request the SE2 logout: %s %s" % (request.kind, request.psw))
    faa_correction(m, 0x5420, "83001f1547000000", "83009fc083009fc0")
    m.clear_breaks()
    m.break_at(0x5424)
    stop = m.run(instructions = 2)
    if (stop.kind != "breakpoint" or not stop.psw.endswith("005424") or
        int(stop.psw[-8], 16) % 4 != 0 or m.read(mcw + 8, 48) != storage_logout):
        fail("SE2 logout did not store 48 bytes with CC 0: %s %s %s" % (stop.kind, stop.psw, binary.hex(m.read(mcw + 8, 48))))
    # This machine has two SEs. Selecting SE3 tests storage-interface timeout.
    faa_correction(m, mcw + 4, "20", "30")
    m.clear_breaks()
    m.break_at(0x5428)
    stop = m.run(instructions = 2)
    if (stop.kind != "breakpoint" or not stop.psw.endswith("005428") or
        int(stop.psw[-8], 16) % 4 != 1 or m.read(mcw + 8, 48) != storage_logout):
        fail("Absent SE3 did not leave the result intact with CC 1: %s %s" % (stop.kind, stop.psw))
    print("IOCE %d LOS: SE2 DIAG FD0 stored all 48 bytes with CC 0, and absent SE3 reported timeout CC 1" % element)


def check_9020a_formatter_storage(tape):
    m = machine(tape, model = "9020a", memory = 2 * (128 << 10))
    reel = binary.builder()
    reel.append(d405f_scratch_record("11223344"))
    m.tape(0x530, reel.file(), format = "simh", type = "2401")
    m.ipl(0x130)
    if m.run(instructions = 30000000).psw != SDM_READY:
        fail("9020A SDM did not reach the operator wait")
    m.cards(0x00c, ["E/A,01F/A,00E/I,01F,01F,00E,130/SW.00000000/L1101/B"], replace = True)
    m.break_at(0x1d6a)
    m.interrupt_key()
    before = m.run(instructions = 30000000)
    if before.kind != "breakpoint" or before.psw != "00040000 00001D6A":
        fail("9020A SDM did not reach the check point: %s %s" % (before.kind, before.psw))
    m.clear_breaks()
    # D0C00C00 statements 7210–7244. Restore the selector and branch
    # around the adaptations that suppress the original SE logout.
    faa_correction(m, 0x53ce, "43429534", "41200000")
    faa_correction(m, 0x53d2, "47f09468", "47000000")
    saved_caw = m.read(0x48, 4)
    faa_correction(m, 0x1d6a, "47f0d008", "9c000530")  # SIO at IOCE 2.
    m.alter(0x48, binary.decode("00020100", "hex"))
    m.alter(0x20100, binary.decode("0200220020000004", "hex"))
    m.set_storage_data_parity(0x20107, bad = True)
    fault = m.run(instructions = 1)
    faa_correction(m, 0x1d6a, "9c000530", "47f0d008")
    m.alter(0x48, saved_caw)
    if fault.psw != "00040000 30001D6E" or m.tape_position(0x530).position != 0:
        fail("IOCE 2 did not stop before the read: %s %s" % (fault.kind, fault.psw))

    m.break_at(0x5420)
    request = m.run(instructions = 30000000)
    if (request.kind != "breakpoint" or not request.psw.endswith("005420") or
        m.registers().gr[1] != "00020000" or binary.hex(m.read(352, 6)) != "400000000080" or
        m.read(362, 1) != b"\x16"):
        fail("9020A SDM did not identify the SE2 check: %s %s %s" %
             (request.kind, request.psw, binary.hex(m.read(352, 12))))
    m.clear_breaks()
    m.break_at(0x5440)
    captured = m.run(instructions = 1)
    expected = binary.decode("10402010000000408040002000000040460205fc8040080000010000", "hex")
    if captured.kind != "breakpoint" or captured.psw != "00000000 00005440" or m.read(0x5424, 28) != expected:
        fail("9020A DIAG F15 did not capture the failed IOCE word: %s %s %s" %
             (captured.kind, captured.psw, binary.hex(m.read(0x5424, 28))))

    m.clear_breaks()
    m.break_at(0x54a0)
    first_line = len(m.output(0x00e))
    formatted = m.run(instructions = 60000000)
    report = [line.strip() for line in m.output(0x00e)[first_line:]]
    if (formatted.kind != "breakpoint" or not formatted.psw.endswith("0054A0") or
        m.read(0x11c, 28) != expected or "SE 2 LOGOUT" not in report or "END OF LOGOUTS" not in report):
        fail("9020A storage logout did not print and return to SDM: %s %s" % (formatted.kind, formatted.psw))
    heading = report.index("SE 2 LOGOUT")
    sdr_lines = [i for i in range(heading + 1, len(report)) if report[i].startswith("P SDR")]
    if not sdr_lines or report[sdr_lines[0] + 1].replace(" ", "") != "000100000100000000100000000100000100":
        fail("9020A report did not print the failed SDR data and parity")

    m.clear_breaks()
    m.break_at(0x519c)
    resumed = m.run(instructions = 100)
    if resumed.kind != "breakpoint" or not resumed.psw.endswith("00519C"):
        fail("9020A SDM did not reach its machine-check continuation: %s %s" % (resumed.kind, resumed.psw))
    m.clear_breaks()
    m.set_storage_data_parity(0x20107, bad = False)
    m.alter(0x519c, binary.decode("58201000", "hex"))  # L 2,0(1).
    m.alter_register(1, 0x20104)
    retry = m.run(instructions = 1)
    if not retry.psw.endswith("0051A0") or m.registers().gr[2] != "20000004":
        fail("9020A DIAG F15 did not release SE2: %s %s" % (retry.kind, retry.psw))
    print("9020A SDM collected seven words from an IOCE 2 parity fault, printed the SE 2 logout, and recovered access.")


def check_storage_stop():
    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False)
    m.alter(0, binary.decode("0000000000001000", "hex"))
    m.alter(0x68, binary.decode("0000000000001100", "hex"))
    m.alter(0x1000, binary.decode("58201000", "hex"))  # L 2,0(1)
    m.alter(0x1100, binary.decode("8300300007f4", "hex"))  # DIAG 0,0(3) followed by BR 4.
    m.alter(0x1200, binary.decode("00fd080020008000", "hex"))
    m.alter(0x80000, binary.decode("01234567", "hex"))
    m.restart(storage_element = 1)
    m.alter_register(1, 0x80000)
    m.alter_register(2, 0xdeadbeef)
    m.alter_register(3, 0x1200)
    m.alter_register(4, 0x1000)
    initial = m.checkpoint()
    m.break_at(0x1004)
    baseline = m.run(instructions = 2)
    if baseline.kind != "breakpoint" or m.registers().gr[2] != "01234567":
        fail("running SE2 did not respond to the control load: %s %s" % (baseline.kind, baseline.psw))

    m.restore(initial)
    m.break_program(0x80)
    capture = bytes(list(range(1, 49)))
    m.replay_storage_logout(2, capture)
    stopped = m.run(instructions = 2)
    if (stopped.kind != "program" or not stopped.psw.endswith("001100") or
        binary.hex(m.read(0x28, 8)) != "0000008080001004" or m.registers().gr[2] != "DEADBEEF"):
        fail("stopped SE2 did not take program interruption 0080: %s %s" % (stopped.kind, stopped.psw))

    retry = m.run(instructions = 4)
    if (retry.kind != "breakpoint" or not retry.psw.endswith("001004") or
        m.registers().gr[2] != "01234567" or m.read(0x1208, 48) != capture):
        fail("FD0 did not release SE2 for the retried load: %s %s" % (retry.kind, retry.psw))
    print("SE2 load raised 0080 with LOS active, and succeeded after the guest handler's FD0")


def check_storage_data_check():
    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
    m.alter(0, binary.decode("0004000000001000", "hex"))
    m.alter(0x68, binary.decode("0000000000001140", "hex"))
    m.alter(0x70, binary.decode("0000000000001100", "hex"))
    m.alter(0x1000, binary.decode("58201000", "hex"))  # L 2,0(1).
    m.alter(0x1100, binary.decode("58301000", "hex"))  # L 3,0(1), while SE2 is stopped.
    # DIAG X'280', then rewrite the low word with sound parity and retry the load.
    m.alter(0x1140, binary.decode("830002805050100407f4", "hex"))
    m.alter(0x280, binary.decode("00fd080020008000", "hex"))
    m.alter(0x80080, binary.decode("0123456789abcdeffedcba9876543210", "hex"))
    m.restart(storage_element = 1)
    m.alter_register(1, 0x80080)
    m.alter_register(2, 0xdeadbeef)
    m.alter_register(3, 0xdeadbeef)
    m.alter_register(4, 0x1000)
    m.alter_register(5, 0x89abcdef)
    m.break_at(0x1004)
    initial = m.checkpoint()
    healthy = m.run(instructions = 2)
    if healthy.kind != "breakpoint" or m.registers().gr[2] != "01234567" or m.read(0x30, 8) != b"\x00" * 8:
        fail("storage data check healthy load: %s %s" % (healthy.kind, healthy.psw))

    m.restore(initial)
    # The incorrect parity is in the other half of the fetched doubleword.
    m.set_storage_data_parity(0x80087, bad = True)
    fault = m.checkpoint()
    m.set_storage_data_parity(0x80087, bad = False)
    m.restore(fault)
    raised = m.run(instructions = 1)
    if (not raised.psw.endswith("001100") or m.registers().gr[2] != "DEADBEEF" or
        binary.hex(m.read(0x30, 8)) != "0004000000001004" or binary.hex(m.read(168, 2)) != "200a"):
        fail("native CE data check: %s %s flags=%s" % (raised.kind, raised.psw, binary.hex(m.read(168, 2))))
    m.break_program(0x80)
    stopped = m.run(instructions = 2)
    if stopped.kind != "program" or not stopped.psw.endswith("001140") or m.registers().gr[3] != "DEADBEEF":
        fail("CE data check did not stop SE2: %s %s" % (stopped.kind, stopped.psw))
    resumed = m.run(instructions = 5)
    expected = "0123456789abcdef00100080800080fc0010080a20000201" + "00" * 24
    if (resumed.kind != "breakpoint" or m.registers().gr[2] != "01234567" or
        binary.hex(m.read(0x288, 48)) != expected):
        fail("FD0 data-check capture/retry: %s %s logout=%s" % (resumed.kind, resumed.psw, binary.hex(m.read(0x288, 48))))

    m.restore(initial)
    m.clear_breaks()
    m.alter(0, binary.decode("0000000000001000", "hex"))
    m.alter(0x70, binary.decode("0000000000001150", "hex"))
    m.alter(0x180, binary.decode("0004000000001200", "hex"))
    # Fault with MC masked, wait beyond the SE timeout, then enable MC using LPSW.
    m.alter(0x1004, binary.decode("07000700070082000180", "hex"))
    m.alter(0x1150, binary.decode("58401008", "hex"))
    m.restart(storage_element = 1)
    m.alter_register(1, 0x80080)
    m.set_storage_data_parity(0x80087, bad = True)
    m.break_at(0x1154)
    delayed = m.run(instructions = 12)
    if (delayed.kind != "breakpoint" or m.registers().gr[4] != "FEDCBA98" or
        binary.hex(m.read(0x30, 8)) != "0004000000001200" or binary.hex(m.read(168, 2)) != "2008"):
        fail("masked CE data check: %s %s flags=%s" % (delayed.kind, delayed.psw, binary.hex(m.read(168, 2))))
    print("Native CE data parity fault stopped SE2, the guest recovered with FD0, and a masked fault deferred the interruption past the SE timeout")


def check_9020_configuration():
    for fault in ["ce", "ioce"]:
        for inhibit in [False, True]:
            m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
            reel = binary.builder()
            reel.append(d405f_scratch_record("11223344"))
            m.tape(0x530, reel.file(), format = "simh", type = "2401")
            m.alter(0, binary.decode("0404000000001000", "hex"))
            m.alter(0x48, binary.decode("00080100", "hex"))
            m.alter(0x68, binary.decode("0002000000001140", "hex"))
            m.alter(0x70, binary.decode("0000000000001100", "hex"))
            # SCON for the CE and IOCE, FD7, then a load or an initial CCW fetch.
            m.alter(0x1000, binary.decode("0102014683000300" + ("58201000" if fault == "ce" else "9c000530"), "hex"))
            m.alter(0x1100, binary.decode("58301008", "hex"))  # Load sound data in the faulting SE.
            m.alter(0x300, binary.decode("00fd700000000000", "hex"))
            m.alter(0x80080, binary.decode("0123456789abcdeffedcba9876543210", "hex"))
            m.alter(0x80100, binary.decode("0200220020000004", "hex"))
            m.restart(storage_element = 1)
            m.alter_register(1, 0x80080)
            m.alter_register(2, 0x00200800)  # CE1 and absent SE3.
            m.alter_register(3, 0xdeadbeef)
            m.alter_register(6, 2)  # IOCE2.
            initial = m.checkpoint()
            # Save the desired configuration, reverse it, and restore
            # before injecting the fault.
            configured_state = None
            for setting in [inhibit, not inhibit]:
                m.restore(initial)
                ce_inhibit = setting == (fault == "ce")
                m.alter_register(0, 0xe0c00802 | (0x02000000 if ce_inhibit else 0))
                m.alter_register(4, 0xe0c00802 | (0 if ce_inhibit else 0x02000000))
                m.clear_breaks()
                m.break_at(0x1002)
                partial = m.run(instructions = 2)
                gr = m.registers().gr
                if (partial.kind != "breakpoint" or partial.psw != "04040000 20001002" or
                    gr[0] != "00200000" or gr[2] != "00200800"):
                    fail("SCON partial response: %s %s mask=%s" % (partial.kind, partial.psw, gr[0]))
                m.clear_breaks()
                m.break_at(0x1008)
                configured = m.run(instructions = 3)
                ccr = "c0000000e2c00802" if ce_inhibit else "40000000e0c00802"
                gr = m.registers().gr
                if (configured.kind != "breakpoint" or configured.psw != "04040000 00001008" or
                    gr[4] != "00000000" or gr[6] != "00000002" or binary.hex(m.read(0x310, 8)) != ccr):
                    fail("SCON/FD7 for %s ILOS %s: %s %s CCR=%s" %
                        (fault, setting, configured.kind, configured.psw, binary.hex(m.read(0x310, 8))))
                if setting == inhibit:
                    configured_state = m.checkpoint()
            m.restore(configured_state)
            m.clear_breaks()
            m.set_storage_data_parity(0x80087 if fault == "ce" else 0x80101, bad = True)
            m.break_at(0x1104)
            result = m.run(instructions = 6)
            machine_old = "040400000000100c" if fault == "ce" else "040400023000100c"
            ce_flags = ("2008" if inhibit else "200a") if fault == "ce" else "0000"
            ioce_flags = ("400000000200000000001200" if inhibit else "400000000200000000001600") if fault == "ioce" else "00" * 12
            if (binary.hex(m.read(0x30, 8)) != machine_old or binary.hex(m.read(168, 2)) != ce_flags or
                binary.hex(m.read(352, 12)) != ioce_flags or m.tape_position(0x530).position != 0):
                fail("%s ILOS %s machine-check logout: %s %s" % (fault, inhibit, result.kind, result.psw))
            if inhibit:
                if (result.kind != "breakpoint" or result.psw != "00000000 00001104" or
                    m.registers().gr[3] != "FEDCBA98" or m.read(0x28, 8) != b"\x00" * 8):
                    fail("%s ILOS did not keep the faulting SE accessible: %s %s" % (fault, result.kind, result.psw))
            elif (result.kind != "disabled-wait" or result.psw != "00020000 00001140" or
                  m.registers().gr[3] != "DEADBEEF" or binary.hex(m.read(0x28, 8)) != "0000008080001104"):
                fail("%s failed to stop the faulting SE with ILOS clear: %s %s" % (fault, result.kind, result.psw))
    print("SCON independently controlled CE and IOCE logout stop. FD7 read back the CE configuration and the machine-check handlers verified SE access.")


def check_9020_configuration_links():
    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
    reel = binary.builder()
    reel.append(d405f_scratch_record("11223344"))
    m.tape(0x530, reel.file(), format = "simh", type = "2401")
    m.alter(0, binary.decode("0400000000001000", "hex"))
    m.alter(0x48, binary.decode("00080100", "hex"))
    m.alter(0x68, binary.decode("0400000000001140", "hex"))
    m.alter(0x78, binary.decode("0002000000001200", "hex"))
    m.alter(0x180, binary.decode("0402000000001148", "hex"))
    # Disconnect/reconnect IOCE2 at the CE, then configure SE2 for CE access
    # alone. Reverse the SE2 assignment and retry from the program handler.
    m.alter(0x1000, binary.decode("01029f00053001469f000530018a9c00053001ce58201000", "hex"))
    m.alter(0x1140, binary.decode("9c00053082000180", "hex"))
    m.alter(0x80100, binary.decode("0200220020000004", "hex"))
    m.restart(storage_element = 1)
    for index, value in [(0, 0xe0c00800), (1, 0x80100), (2, 0x800), (4, 0xe0c00802), (6, 0x800),
                         (8, 0xe0000800), (10, 0x400000), (12, 0xe0000002), (14, 0x400000)]:
        m.alter_register(index, value)
    for address, psw, csw in [(0x1006, "30001006", "0000000000000000"), (0x100c, "0000100C", "0000000000000000"),
                              (0x1012, "10001012", "0000000000200000")]:
        m.clear_breaks()
        m.break_at(address)
        stopped = m.run(instructions = 8)
        if (stopped.kind != "breakpoint" or stopped.psw != "04000000 " + psw or
            binary.hex(m.read(0x40, 8)) != csw or m.tape_position(0x530).position != 0):
            fail("9020 configuration links: %s %s CSW=%s" % (stopped.kind, stopped.psw, binary.hex(m.read(0x40, 8))))
    m.clear_breaks()
    done = m.run(instructions = 500000)
    if (done.kind != "disabled-wait" or done.psw != "00020000 00001200" or
        binary.hex(m.read(0x28, 8)) != "0400000580001018" or binary.hex(m.read(0x40, 8)) != "000801080c000000" or
        binary.hex(m.read(0x2200, 4)) != "11223344" or m.tape_position(0x530).position != 1):
        fail("Configured IOCE access after CE addressing check: %s %s" % (done.kind, done.psw))
    print("SCON isolated and reconnected the IOCE and independently routed CE and IOCE accesses to SE2.")


def check_9020_control_configuration(control):
    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
    tape = control == "TCU"
    first, second = ("0130", "0530") if tape else ("0340", "0740")
    if tape:
        reel = binary.builder()
        reel.append(d405f_scratch_record("11223344"))
        for address in [first, second]:
            m.tape(int(address, 16), reel.file(), format = "simh", type = "2420", tcu = 1)
        ccw, data = "0200210020000004", "11223344"
        selected, absent = 0x10000000, 0x08000000
    else:
        for address in [first, second]:
            m.dasd(int(address, 16), type = "2314", cylinders = 1, volser = "SCUTST", scu = 1)
        ccw, data = "1a00210020000005", "0000000000"
        selected, absent = 0x80, 0x40
    m.alter(0, binary.decode("0000000000001000", "hex"))
    m.alter(0x48, binary.decode("00002000", "hex"))
    m.alter(0x2000, binary.decode(ccw, "hex"))
    m.alter(0x2100, b"\xff" * (len(data) // 2))
    # FAA DD8A0900 routines 9 and A. Test the connected and disconnected ports
    # with TIO, including the delay before checking the disconnected port.
    tio_first, tio_second = "9d00" + first, "9d00" + second
    commands = tio_second + tio_first + "01020b40" + tio_second + tio_first + "01460b40"
    commands += tio_second + tio_first + "9c00" + first + "9c00" + second
    m.alter(0x1000, binary.decode(commands, "hex"))
    m.restart(storage_element = 1)
    for register, value in [(0, 0xe0000004), (2, selected), (4, 0xe0000002), (6, selected | absent)]:
        m.alter_register(register, value)
    expected = [
        (0x1004, 0), (0x1008, 0), (0x100a, 0), (0x1010, 3),
        (0x1014, 0), (0x1016, 2), (0x101c, 0), (0x1020, 3),
        (0x1024, 3), (0x1028, 0),
    ]
    configured = None
    for address, cc in expected:
        m.clear_breaks()
        m.break_at(address)
        stop = m.run(instructions = 20000)
        psw = "00000000 %x0%s" % (cc, ("000000%x" % address)[-6:].upper())
        if stop.kind != "breakpoint" or stop.psw != psw:
            fail("9020 %s configuration at %x: %s %s, want %s" % (control, address, stop.kind, stop.psw, psw))
        if address == 0x100a:
            if m.registers().gr[0] != "00000000":
                fail("SCON did not receive a response from %s 1" % control)
            configured = m.checkpoint()
        if address == 0x1016 and int(m.registers().gr[4], 16) != absent:
            fail("SCON did not distinguish installed %s 1 from absent unit 2" % control)
    m.alter(0x1028, binary.decode("82000200", "hex"))
    m.alter(0x200, binary.decode("010200000000102c", "hex"))
    m.clear_breaks()
    m.run(instructions = 500000)
    if m.read(0x2100, len(data) // 2) != binary.decode(data, "hex"):
        fail("9020 %s did not return data from the connected port" % control)
    if tape and (m.tape_position(int(first, 16)).position != 0 or m.tape_position(int(second, 16)).position != 1):
        fail("9020 TCU accepted I/O on the wrong port")
    m.restore(configured)
    m.break_at(0x1010)
    restored = m.run(instructions = 20000)
    if restored.kind != "breakpoint" or restored.psw != "00000000 30001010":
        fail("9020 %s configuration did not survive the checkpoint" % control)
    print("SCON switched %s 1 between IOCE paths. TIO returned CC3 on the disconnected port and SIO read through the connected port." % control)


def run_9020_instruction(m, instruction, cc, system = "00000000"):
    # EX the instruction, then branch back to the same observation point.
    m.clear_breaks()
    if m.psw().endswith("001004"):
        m.run(instructions = 1)
    m.alter(0x1800, binary.decode(instruction, "hex"))
    m.break_at(0x1004)
    stop = m.run(instructions = 4)
    if stop.kind != "breakpoint" or stop.psw != "%s %x0001004" % (system, cc):
        fail("9020 instruction %s: %s %s, expected CC%d" % (instruction, stop.kind, stop.psw, cc))


def rcu_io(m, device, ccws, cc, status, wait = 128):
    address = ("0000%x" % device)[-4:]
    m.alter(0x2000, binary.decode(ccws, "hex"))
    before = m.read(0x40, 8)
    run_9020_instruction(m, "9c00" + address, cc)
    if cc == 3 and m.read(0x40, 8) != before:
        fail("RCU disconnected path %s changed the CSW" % address)
    if cc == 0:
        m.alter(0x1800, b"\x07\x00")
        m.clear_breaks()
        m.run(instructions = wait)
        run_9020_instruction(m, "9d00" + address, 1)
    if status != None and binary.hex(m.read(0x44, 2)) != status:
        fail("RCU %s CCWs %s: CSW %s, wanted status %s" %
             (address, ccws, binary.hex(m.read(0x40, 8)), status))


def check_9020e_rcu():
    for consoles, last in [(60, 0x33), (90, 0x3b)]:
        m = emulator.s390(architecture = "s360", model = "9020e", mips = 1, interval_timer = False)
        m.rcu(0x20, peer = 0x420, consoles = consoles)
        m.alter(0, binary.decode("0000000000001000", "hex"))
        m.alter(0x1000, binary.decode("4400900007f8", "hex"))
        m.alter(0x48, binary.decode("00002000", "hex"))
        m.restart(storage_element = 1)
        m.alter_register(8, 0x1000)
        m.alter_register(9, 0x1800)

        # D9051200 statements 2373–2417. Exercise every address on both
        # console sizes, including the two DAU and expanded RKM/R addresses.
        for device in range(0x21, last + 1):
            run_9020_instruction(m, "9d0000%x" % device, 0)
            run_9020_instruction(m, "9d0004%x" % device, 3)
            dau = device in [0x32, 0x33]
            dg = device <= 0x2c or (device >= 0x34 and device <= 0x38)
            console = device in [0x30, 0x31, 0x3b]
            if dau:
                data, expected = "21", "80"  # DAU Reset and S0 readback.
            elif console:
                data, expected = "10234567", "10234567"
            else:
                data, expected = "aa25", "aa15" if dg else "aa25"
            if not dau:
                rcu_io(m, device, "af00000020000001", 1, "0c00")
            count = len(data) // 2
            m.alter(0x2100, binary.decode(data, "hex"))
            m.alter(0x2200, b"\xff" * 4)
            chain = format0_ccw("31", 0x2100, "40", count) + format0_ccw("22", 0x2200, "00", count)
            rcu_io(m, device, chain, 0, "0c00")
            if binary.hex(m.read(0x2200, 4)) != expected + "ff" * (4 - count):
                fail("RCU configuration wrap at %x: %s" % (device, binary.hex(m.read(0x2200, 4))))
            if not dau:
                rcu_io(m, device, format0_ccw("22", 0x2200, "00", count), 0, "0c00")
                if m.read(0x2200, count) != b"\x00" * count:
                    fail("RCU retained the CI shift register after the chain")
                rcu_io(m, device, format0_ccw("12", 0x2200, "00", 2 if dg else 4), 0, "0c00")
                status_data = binary.hex(m.read(0x2200, 2 if dg else 4))
                if status_data != ("0010" if dg else "00000000" if console else "00010000"):
                    fail("RCU diagnostic status at %x: %s" % (device, status_data))
        run_9020_instruction(m, "9d000020", 3)
        run_9020_instruction(m, "9d0000%x" % (last + 1), 3)

        # D9051200 routines 9, 11 and 18. Data faults are reported as
        # ending checks. An unsupported DAU command is rejected at selection.
        m.alter(0x2100, binary.decode("1010efef", "hex"))
        rcu_io(m, 0x21, "31002100400000023100210200000002", 0, "0e00")
        rcu_io(m, 0x21, "0400220000000002", 0, "0c00")
        if binary.hex(m.read(0x2200, 2)) != "0800":
            fail("RCU write/write parity failure did not set Data Check")
        rcu_io(m, 0x21, "3100210000000001", 0, "0e40")
        rcu_io(m, 0x21, "0400220000000002", 0, "0c00")
        if binary.hex(m.read(0x2200, 2)) != "0100":
            fail("RCU short write did not set Wrong Length Message")
        m.alter(0x2100, b"\xf1")
        rcu_io(m, 0x32, "3100210000000001", 0, "0e00")
        rcu_io(m, 0x32, "0400220000000002", 0, "0c00")
        if binary.hex(m.read(0x2200, 2)) != "0800":
            fail("RCU did not detect the DAU diagnostic data check")
        rcu_io(m, 0x32, "1200220000000002", 1, "0200")
        rcu_io(m, 0x32, "0400220000000002", 0, "0c00")
        if binary.hex(m.read(0x2200, 2)) != "8000":
            fail("RCU did not report Command Reject for DAU Read Status")

        # DD8A0900 routine C. Select an absent RCU as a control and then
        # combine both IOCE bits. The real CCR latches an invalid mask.
        m.alter_register(2, 0xc0000000)
        m.alter_register(4, 0x20000002)
        run_9020_instruction(m, "0142", 2)
        if m.registers().gr[4] != "40000000":
            fail("RCU 1 and absent RCU 2 did not respond independently")
        rcu_io(m, 0x21, "af00000020000001", 3, None)
        rcu_io(m, 0x421, "6700000020000001", 1, "0c00")
        alternate = m.checkpoint()
        m.alter_register(2, 0x80000000)
        m.alter_register(4, 0x20000000)
        run_9020_instruction(m, "0142", 0)
        for device in [0x21, 0x421]:
            rcu_io(m, device, "af00000020000001", 3, None)
        m.alter_register(4, 0x20000006)
        run_9020_instruction(m, "0142", 2)
        if m.registers().gr[4] != "80000000":
            fail("RCU acknowledged a multiple-IOCE assignment")
        rcu_io(m, 0x421, "af00000020000001", 3, None)
        rcu_io(m, 0x21, "0400220000000002", 0, "0c00")
        if binary.hex(m.read(0x2200, 2)) != "0010":
            fail("RCU did not latch multiple-IOCE sense on the lower path")
        m.alter_register(4, 0x20000004)
        run_9020_instruction(m, "0142", 0)
        rcu_io(m, 0x21, "0400220000000002", 0, "0c00")
        if binary.hex(m.read(0x2200, 2)) != "0000":
            fail("RCU retained multiple-IOCE sense after a corrected SCON")
        m.restore(alternate)
        run_9020_instruction(m, "9d000021", 3)
        run_9020_instruction(m, "9d000421", 0)

        # A control unit holds one data transfer at a time. An attempt
        # through a different address gets busy, followed by CUE at end.
        m.alter(0x2000, binary.decode("2200220000000004", "hex"))
        run_9020_instruction(m, "9c000430", 0)
        run_9020_instruction(m, "9d000421", 1)
        if binary.hex(m.read(0x44, 2)) != "5000":
            fail("RCU did not report Control Unit Busy to a different address")
        m.alter(0x1800, b"\x07\x00")
        m.clear_breaks()
        m.run(instructions = 128)
        run_9020_instruction(m, "9d000430", 1)
        if binary.hex(m.read(0x44, 2)) != "2c00":
            fail("RCU did not include Control Unit End after a busy selection")

        # DD8A0900 routine C checks the second unit's DAU register for
        # cross talk. Each RCU retains its own DAU configuration.
        m.rcu(0x60, unit = 2, peer = 0x460, consoles = consoles)
        m.alter_register(2, 0x40000000)
        m.alter_register(4, 0x20000002)
        run_9020_instruction(m, "0142", 0)
        run_9020_instruction(m, "9d000061", 3)
        m.alter(0x2100, b"\xc0")
        rcu_io(m, 0x472, "31002100400000012200220000000001", 0, "0c00")
        if m.read(0x2200, 1) != b"\xc0":
            fail("RCU 2 DAU did not return its independent configuration")
        rcu_io(m, 0x432, "2200220000000001", 0, "0c00")
        if m.read(0x2200, 1) != b"\x80":
            fail("RCU 2 wrote into RCU 1's DAU configuration")

        # D9051200 routines 4–6. Test sets a masked report; enabling
        # attention first returns CE/DE, then presents an actual interruption.
        m.alter_register(2, 0x80000000)
        m.alter_register(4, 0x20000004)
        run_9020_instruction(m, "0142", 0)
        rcu_io(m, 0x21, "1f00000020000001", 1, "0c00")
        rcu_io(m, 0x21, "6700000020000001", 1, "0c00")
        run_9020_instruction(m, "9d000021", 0)
        rcu_io(m, 0x21, "9f00000020000001", 1, "0c00")
        run_9020_instruction(m, "9d000021", 1)
        if binary.hex(m.read(0x44, 2)) != "8000":
            fail("RCU did not present masked attention after enabling it")
        m.alter(0x2200, b"\xff\xff")
        rcu_io(m, 0x21, "67000000600000011200220000000002", 1, "0c00")
        if m.read(0x2200, 2) != b"\xff\xff":
            fail("RCU executed a chained Read Status after Control Test")
        m.alter(0x78, binary.decode("0000000000001500", "hex"))
        m.alter(0x1500, b"\x07\xf7")  # Return to the breakpoint after the interruption.
        m.alter_register(7, 0x1500)
        m.alter(0x600, b"\x80")
        run_9020_instruction(m, "80000600", 1, system = "80000000")
        m.clear_breaks()
        m.break_at(0x1500)
        stop = m.run(instructions = 8)
        if (stop.kind != "breakpoint" or not stop.psw.endswith("001500") or
            binary.hex(m.read(0x3a, 2)) != "0021" or binary.hex(m.read(0x44, 2)) != "8000"):
            fail("RCU Control Test did not deliver attention at 021: %s %s" % (stop.kind, stop.psw))
        print("9020E RCU %d-console profile verified %d interfaces, configuration wrap, data and length checks, SCON path switching and attention." %
              (consoles, last - 0x20))


def set_rcu_state(m, unit, state, ioce):
    m.alter_register(2, 0x80000000 >> (unit - 1))
    m.alter_register(4, (state << 30) | 0x20000000 | (4 >> (ioce - 1)))
    run_9020_instruction(m, "0142", 0)


def read_rcu_data(m, address, command, expected):
    count = len(expected) // 2
    m.alter(0x2200, b"\xff" * count)
    rcu_io(m, address, format0_ccw(command, 0x2200, "00", count), 0, "0c00")
    data = binary.hex(m.read(0x2200, count))
    if data != expected:
        fail("RCU %x command %s returned %s, expected %s" % (address, command, data, expected))


def check_9020e_rcu_outboard():
    for consoles, display_index, dg in [(60, 0, 3), (90, 4, 15)]:
        m = emulator.s390(architecture = "s360", model = "9020e", mips = 1, interval_timer = False,
                          display_elements = display_index + 1)
        m.rcu(0x20, unit = 1, peer = 0x420, consoles = consoles)
        m.rcu(0x60, unit = 2, peer = 0x460, consoles = consoles)
        m.alter(0, binary.decode("0000000000001000", "hex"))
        m.alter(0x1000, binary.decode("4400900007f8", "hex"))
        m.alter(0x48, binary.decode("00002000", "hex"))
        m.restart(storage_element = 1)
        m.alter_register(8, 0x1000)
        m.alter_register(9, 0x1800)
        set_rcu_state(m, 1, 3, 1)
        set_rcu_state(m, 2, 3, 2)
        rcu_io(m, 0x21, "0700000020000001", 1, "0100")
        for primary, alternate, write, expected in [
            (0x21, 0x461, "8a40", "8a50"),
            (0x2d, 0x46d, "8eff", "8c00"),
            (0x30, 0x470, "10234567", "10234567"),
        ]:
            rcu_io(m, primary, "af00000020000001", 1, "0c00")
            rcu_io(m, primary, "0700000020000001", 1, "0c00")
            m.alter(0x2100, binary.decode(write, "hex"))
            rcu_io(m, primary, format0_ccw("31", 0x2100, "00", len(write) // 2), 0, "0c00")
            read_rcu_data(m, primary, "22", expected)
            rcu_io(m, alternate, "af00000020000001", 1, "0c00")
        m.alter(0x2100, b"\x80")
        rcu_io(m, 0x32, "3100210000000001", 0, "0c00")
        read_rcu_data(m, 0x472, "22", "80")
        m.alter(0x2100, b"\xc0")
        rcu_io(m, 0x472, "3100210000000001", 0, "0e00")
        read_rcu_data(m, 0x472, "04", "0800")
        read_rcu_data(m, 0x32, "22", "80")
        rcu_io(m, 0x21, "6700000020000001", 1, "0c00")  # Leave the device's Test report masked.
        saved = m.checkpoint()

        for restored in [False, True]:
            if restored:
                m.restore(saved)
            set_rcu_state(m, 2, 2, 2)
            rcu_io(m, 0x462, "af00000020000001", 1, "0100")
            for address, expected in [(0x21, "0100"), (0x22, "0c00"), (0x462, "0100")]:
                rcu_io(m, address, "0700000020000001", 1, expected)
            rcu_io(m, 0x61, "0700000020000001", 3, None)
            rcu_io(m, 0x461, "9f00000020000001", 1, "0c00")
            run_9020_instruction(m, "9d000461", 1)
            if binary.hex(m.read(0x44, 2)) != "8000":
                fail("RCU did not deliver the DG's pending Test report after handoff")
            read_rcu_data(m, 0x461, "12", "0010")
            for address, readback in [(0x461, "8a50"), (0x46d, "8c00"), (0x470, "10234567")]:
                read_rcu_data(m, address, "22", readback)
            rcu_io(m, 0x461, "0700000020000001", 1, "0c00")
            read_rcu_data(m, 0x461, "12", "0000")
            rcu_io(m, 0x46d, "6700000020000001", 1, "0c00")
            read_rcu_data(m, 0x46d, "12", "00010000")
            rcu_io(m, 0x46d, "0700000020000001", 1, "0c00")
            read_rcu_data(m, 0x46d, "12", "00000000")
            set_rcu_state(m, 2, 1, 2)
            rcu_io(m, 0x22, "0700000020000001", 1, "0c00")
            set_rcu_state(m, 1, 2, 1)
            rcu_io(m, 0x22, "0700000020000001", 1, "0100")
            rcu_io(m, 0x461, "0700000020000001", 1, "0100")

        # DE1 tail 1 reaches DG3 in the 60-console profile. DE5 tail 1
        # reaches DG15 in the 90-console profile (tables 4-6 and 4-7).
        set_rcu_state(m, 1, 3, 1)
        set_rcu_state(m, 2, 0, 2)
        address = 0x20 + dg + (7 if dg > 12 else 0)
        base = 0x280000 + display_index * 0x80000
        m.alter(base + 32, binary.decode("48000000000000005000000000000800", "hex"))
        m.alter(base + 0x800, binary.decode("0123456789abcdef4000000000000000", "hex"))
        m.alter_register(2, 0xe1000800)  # DE in State Three with Inhibit DE Stop.
        m.alter_register(3, 0x80000000)
        m.alter_register(4, 0x00040000 >> display_index)
        run_9020_instruction(m, "0124", 0)
        rcu_io(m, address, "af00000020000001", 1, "0c00")
        rcu_io(m, address, "9f00000020000001", 1, "0c00")
        m.alter(0x2100, b"\x88\x00")  # Put only CVG1 online.
        rcu_io(m, address, "3100210000000002", 0, "0c00")
        if m.read(base + 36, 1) != b"\xff" or m.read(base + 68, 1) != b"\x00":
            fail("RCU DG %d did not request the configured CVG" % dg)
        for order, active in [("47", False), ("57", True), ("77", False), ("57", False), ("07", True)]:
            rcu_io(m, address, order + "00000020000001", 1, "0c00")
            m.alter(base + 36, b"\x00")
            m.alter(0x1800, b"\x07\x00")
            m.clear_breaks()
            m.run(instructions = 20000)
            if m.read(base + 36, 1) != (b"\xff" if active else b"\x00"):
                fail("RCU DG %d did not change refresh after control %s" % (dg, order))
        m.set_storage_data_parity(base + 0x800, bad = True)
        m.run(instructions = 20000)
        run_9020_instruction(m, "9d0000%x" % address, 1)
        if binary.hex(m.read(0x44, 2)) != "8000":
            fail("RCU DG %d did not report its detected DE parity error" % dg)
        read_rcu_data(m, address, "12", "2000")
        m.set_storage_data_parity(base + 0x800, bad = False)
        rcu_io(m, address, "0700000020000001", 1, "0c00")
        read_rcu_data(m, address, "12", "0000")
        print("9020E %d-console operative RCU verified ownership, retained configuration and Test attention, and DG%d refresh control and parity reporting." %
              (consoles, dg))


def check_9020e_dau_configuration():
    m = emulator.s390(architecture = "s360", model = "9020e", mips = 1, interval_timer = False)
    m.rcu(0x20, unit = 1, peer = 0x420)
    m.rcu(0x60, unit = 2, peer = 0x460)
    m.dau(0x80, peer = 0x480, unit = 1)
    m.dau(0x88, peer = 0x488, unit = 2)
    m.alter(0, binary.decode("0000000000001000", "hex"))
    m.alter(0x1000, binary.decode("4400900007f8", "hex"))
    m.alter(0x48, binary.decode("00002000", "hex"))
    m.restart(storage_element = 1)
    m.alter_register(8, 0x1000)
    m.alter_register(9, 0x1800)
    set_rcu_state(m, 1, 3, 1)
    set_rcu_state(m, 2, 3, 2)

    for addr in ["0081", "0481", "0089", "0489"]:
        run_9020_instruction(m, "9d00" + addr, 3)
    for rcu, paths, value in [(0x32, ["0081", "0481"], b"\x80"), (0x473, ["0489", "0089"], b"\x40")]:
        m.alter(0x2100, value)
        rcu_io(m, rcu, "3100210000000001", 0, "0c00")
        run_9020_instruction(m, "9d00" + paths[0], 0)
        run_9020_instruction(m, "9d00" + paths[1], 3)
    read_rcu_data(m, 0x472, "22", "80")
    read_rcu_data(m, 0x33, "22", "40")
    m.alter(0x2100, b"\xc0")
    rcu_io(m, 0x472, "3100210000000001", 0, "0e00")
    read_rcu_data(m, 0x472, "04", "0800")
    read_rcu_data(m, 0x32, "22", "80")

    # Request B while a long diagnostic write on A is still transferring.
    m.alter(0x2400, b"\x7a" * 512)
    m.alter(0x2000, binary.decode("0900240000000200", "hex"))
    run_9020_instruction(m, "9c000081", 0)
    m.alter(0x2100, b"\x40")
    rcu_io(m, 0x472, "3100210000000001", 0, "0c00")
    read_rcu_data(m, 0x32, "22", "80")
    run_9020_instruction(m, "9d000481", 3)
    pending = m.checkpoint()
    for restore in [False, True]:
        if restore:
            m.restore(pending)
        m.alter(0x1800, b"\x07\x00")
        m.clear_breaks()
        m.run(instructions = 2500)
        run_9020_instruction(m, "9d000081", 1)
        if binary.hex(m.read(0x44, 2)) != "0c00":
            fail("DAU reconfiguration changed the ending status on the first interface")
        read_rcu_data(m, 0x32, "22", "40")
        run_9020_instruction(m, "9d000081", 3)
        read_rcu_data(m, 0x481, "0a", "7a")

    m.alter(0x2100, b"\x81")  # A plus Reset.
    rcu_io(m, 0x32, "3100210000000001", 0, "0c00")
    read_rcu_data(m, 0x081, "0a", "00")
    run_9020_instruction(m, "9d000481", 3)
    run_9020_instruction(m, "9d000489", 0)
    m.alter(0x2100, b"\x00")
    rcu_io(m, 0x32, "3100210000000001", 0, "0c00")
    read_rcu_data(m, 0x472, "22", "00")
    run_9020_instruction(m, "9d000081", 3)
    run_9020_instruction(m, "9d000481", 3)
    print("9020E RCU selected the live IOCE paths of both 2701s, deferred an active handoff, rejected dual enable and reset the selected DAU.")


def check_9020e_rkm():
    for consoles, rkm, adjacent, rcu in [(60, 1, 2, 0x2d), (90, 5, 4, 0x3a)]:
        m = emulator.s390(architecture = "s360", model = "9020e", mips = 1, interval_timer = False)
        m.rcu(0x20, consoles = consoles)
        m.dau(0x80, peer = 0x480, unit = 1)
        m.dau(0x88, peer = 0x488, unit = 2)
        m.alter(0, binary.decode("0000000000001000", "hex"))
        m.alter(0x1000, binary.decode("4400900007f8", "hex"))
        m.alter(0x48, binary.decode("00002000", "hex"))
        m.restart(storage_element = 1)
        m.alter_register(8, 0x1000)
        m.alter_register(9, 0x1800)
        set_rcu_state(m, 1, 3, 1)
        first, second = 0x80 + rkm, 0x488 + rkm
        for address, value in [(0x32, b"\x80"), (0x33, b"\x70")]:
            m.alter(0x2100, value)
            rcu_io(m, address, "3100210000000001", 0, "0c00")
        rcu_io(m, rcu, "af00000020000001", 1, "0c00")
        m.alter(0x2100, b"\x88\x00")  # Online on DAU 1.
        rcu_io(m, rcu, "3100210000000002", 0, "0c00")

        m.alter(0x2200, b"\xff")
        rcu_io(m, first, "0600220000000001", 0, "0e00")  # DAU 1 in State Zero.
        if m.read(0x2200, 1) != b"\xff":
            fail("the State Zero DAU wrote live RKM status")
        read_rcu_data(m, 0x80 + adjacent, "04", "01")  # Shared DAU timeout sense.
        read_rcu_data(m, first, "0a", "00")  # RKM order formatter remains visible.
        m.alter(0x2100, b"\xb0")
        rcu_io(m, 0x32, "3100210000000001", 0, "0c00")

        read_rcu_data(m, first, "06", "10")
        read_rcu_data(m, first, "0e", "00")
        rcu_io(m, rcu, "6700000020000001", 1, "0c00")  # Set RKM Error Status 2 Test.
        read_rcu_data(m, rcu, "12", "00010000")
        read_rcu_data(m, first, "06", "12")
        read_rcu_data(m, first, "06", "12")  # Summary persists until the error byte is read.
        saved = m.checkpoint()
        for restore in [False, True]:
            if restore:
                m.restore(saved)
            read_rcu_data(m, first, "16", "01")
            read_rcu_data(m, first, "06", "10")
            read_rcu_data(m, rcu, "12", "00000000")

        # A longer channel count receives exactly one byte and reports a residual.
        m.alter(0x2200, b"\xff\xff")
        rcu_io(m, first, "1600220000000002", 0, "0c40")
        if m.read(0x2200, 2) != b"\x00\xff" or m.read(0x46, 2) != b"\x00\x01":
            fail("RKM status did not terminate at one byte")

        for address in [second, 0x80 + adjacent]:
            m.alter(0x2200, b"\xff")
            rcu_io(m, address, "0600220000000001", 0, "0e00")
            if m.read(0x2200, 1) != b"\xff":
                fail("an unconfigured RKM port transferred status")
            read_rcu_data(m, address, "04", "01")

        # Move the same endpoint to DAU 2, preserving its test bit.
        rcu_io(m, rcu, "6700000020000001", 1, "0c00")
        m.alter(0x2100, b"\x84\x00")
        rcu_io(m, rcu, "3100210000000002", 0, "0c00")
        rcu_io(m, first, "1600220000000001", 0, "0e00")
        read_rcu_data(m, second, "16", "01")

        # The RCU configuration interface still responds while normal I/O is stopped.
        for order, active in [("47", False), ("57", True), ("77", False), ("57", False), ("07", True)]:
            rcu_io(m, rcu, order + "00000020000001", 1, "0c00")
            read_rcu_data(m, rcu, "22", "8400")
            if active:
                read_rcu_data(m, second, "06", "10")
            else:
                rcu_io(m, second, "0600220000000001", 0, "0e00")
        print("9020E %d-console RKM %d returned live status, shared RCU errors, switched DAUs and obeyed Stop, Resume and Disable." % (consoles, rkm))
        check_9020e_rkm_memory(m, second, rcu, whole_memory = consoles == 60)
        check_9020e_rkm_keyboard(m, second)
        check_9020e_rkm_operators(m, second, rcu)
        check_9020e_rkm_special_move(m, second, rcu)
        check_9020e_rkm_console(m, rkm, second, rcu)
        check_9020e_rkm_sparing(m, consoles)
        check_9020e_rkm_disconnect(m, first, second, rcu)


def write_rkm(m, port, command, data, flags = "00"):
    m.alter(0x2400, data)
    rcu_io(m, port, format0_ccw(command, 0x2400, flags, len(data)), 0, "0c00", wait = max(128, 32 + 15 * len(data)))


def read_rkm(m, port, command, expected):
    m.alter(0x2400, b"\xff" * len(expected))
    rcu_io(m, port, format0_ccw(command, 0x2400, "00", len(expected)), 0, "0c00", wait = max(128, 32 + 15 * len(expected)))
    actual = m.read(0x2400, len(expected))
    if actual != expected:
        fail("RKM %x command %s read %d bytes, prefix %s, expected prefix %s" %
             (port, command, len(actual), binary.hex(actual[:16]), binary.hex(expected[:16])))


def check_9020e_rkm_memory(m, port, rcu, whole_memory):
    # DB8B1100 routine 5 reads beyond 7FFF after writing a sentinel there.
    write_rkm(m, port, "05", b"\x7f\xff")
    write_rkm(m, port, "c1", b"\xa6\x4c\x37")
    write_rkm(m, port, "25", b"\x7f\xff")
    read_rkm(m, port, "c2", b"\xa6\x4c")
    read_rkm(m, port, "c2", b"\x37")
    if whole_memory:
        write_rkm(m, port, "05", b"\x00\x00")
        read_rkm(m, port, "c2", bytes([0x4c, 0x37] + [0] * 32765 + [0xa6, 0x4c]))

    # DB8B1100 routine 6 compares both modified orders to its 256-byte table.
    ascending = bytes(list(range(256)))
    translated = bytes([i ^ 1 if i & 0x3e == 0x3e else i for i in range(256)])
    for write, read in [("c1", "e2"), ("e1", "c2")]:
        write_rkm(m, port, "05", b"\x10\x00")
        write_rkm(m, port, write, ascending)
        write_rkm(m, port, "05", b"\x10\x00")
        read_rkm(m, port, read, translated)
    saved = m.checkpoint()
    write_rkm(m, port, "05", b"\x10\x00")
    write_rkm(m, port, "c1", b"\xff")
    m.restore(saved)
    write_rkm(m, port, "05", b"\x10\x00")
    read_rkm(m, port, "c2", translated)

    # DB8B1100 routine 8 sets and clears each bit by address.
    for bit in range(8):
        write_rkm(m, port, binary.hex(bytes([0xc5 + 8 * bit])), bytes([0, 0x80 + bit]))
    write_rkm(m, port, "05", b"\x00\x80")
    read_rkm(m, port, "c2", binary.decode("8040201008040201", "hex"))
    for bit in range(8):
        write_rkm(m, port, binary.hex(bytes([0x45 + 8 * bit])), bytes([0, 0x80 + bit]))
    write_rkm(m, port, "05", b"\x00\x80")
    read_rkm(m, port, "c2", b"\x00" * 8)

    write_rkm(m, port, "01", b"\x7a\x10")
    read_rcu_data(m, port, "06", "14")
    read_rkm(m, port, "02", b"\x7a\x10")
    read_rcu_data(m, port, "06", "10")
    # DB8B2200 routine 1 expects normal CE/DE with SLI and a latched
    # procedural error when Load I/O Address is one byte short or long.
    write_rkm(m, port, "05", b"\x7f\xff")
    for wrong in [b"\x00", b"\x00\x00\x00"]:
        write_rkm(m, port, "05", wrong, flags = "20")
        read_rcu_data(m, port, "06", "11")
        read_rcu_data(m, rcu, "12", "04000000")
        read_rcu_data(m, port, "0e", "04")
        read_rcu_data(m, port, "06", "10")
    read_rkm(m, port, "c2", b"\xa6\x4c")
    print("9020E RKM at %x verified the 32 KiB address wrap, all 256 modified bytes, bit operations, queue address and bad-length recovery." % port)


def check_9020e_rkm_keyboard(m, port):
    # DB8B1100 routine 7. Test data and marker at separate memory
    # addresses and then read through the independently loaded I/O address.
    write_rkm(m, port, "05", b"\x00\x02")
    write_rkm(m, port, "c1", b"\x37")  # Sentinel outside the first keyboard entry.
    for command, payload, address, expected in [
        ("85", "0000ff", "0000", "ff8037"),
        ("85", "2aaaaa", "2aa9", "00aa8000"),
        ("85", "555555", "5555", "5580"),
        ("a5", "00a5a5", "00a5", "a508"),
    ]:
        write_rkm(m, port, command, binary.decode(payload, "hex"))
        write_rkm(m, port, "05", binary.decode(address, "hex"))
        read_rkm(m, port, "c2", binary.decode(expected, "hex"))
    write_rkm(m, port, "85", b"\x00\x02\x02")
    write_rkm(m, port, "05", b"\x00\x02")
    write_rkm(m, port, "85", b"\x00\x00\x01")
    read_rkm(m, port, "c2", b"\x02\x80\x00\x00")
    print("9020E RKM at %x verified both Keyboard Write markers and preservation of the separate I/O address." % port)


def start_rkm_operator(m, port, command, operands):
    # DB8B1100 DOBZYCCW reads all three RKM status bytes in the same chain.
    data = binary.decode(operands, "hex")
    m.alter(0x2400, data)
    m.alter(0x2500, b"\xff" * 3)
    ccws = format0_ccw(command, 0x2400, "60", len(data))
    for i, read in enumerate(["06", "0e", "16"]):
        ccws += format0_ccw(read, 0x2500 + i, "60" if i < 2 else "20", 1)
    rcu_io(m, port, ccws, 0, "0c00", wait = 256)
    result = binary.hex(m.read(0x2500, 3))
    if result != "500000":
        fail("RKM %s operator chain returned %s instead of busy/DCF" % (command, result))


def wait_rkm_operator(m, instructions):
    m.alter(0x1800, b"\x07\x00")
    m.clear_breaks()
    m.run(instructions = instructions)


def check_9020e_rkm_console(m, rkm, port, rcu):
    constants = b"\x00\x12\x34\x56\x78\x9a\xbc\xde"
    m.rkm_console(rkm, 3, constants)
    m.rkm_console(rkm, 17, b"\x87" * 8)
    port_address = ("0000%x" % port)[-4:]
    rcu_tio = "9d00" + binary.hex(bytes([0, rcu]))
    write_rkm(m, port, "05", b"\x3f\xf8")
    write_rkm(m, port, "c1", b"\x00" * 8)
    for position, summary, error, result in [(0, 1, "02", b"\x00" * 8), (3, 0, "00", constants)]:
        # DB8B1100 observes CE/DE followed by attention A, and the next
        # status sample contains both Interrupt and Constants Fetched. Its
        # NRPQMASK clears the Error 1 summary before comparing the bytes.
        write_rkm(m, port, "21", bytes([position]))
        read_rcu_data(m, port, "06", "00")
        wait_rkm_operator(m, 2000)
        run_9020_instruction(m, "9d00" + port_address, 1)
        if m.read(0x40, 8) != b"\x00\x00\x00\x00\xc0\x00\x00\x00":
            fail("RKM Fetch Display Constants did not deliver attention A")
        read_rcu_data(m, port, "06", binary.hex(bytes([0x30 | summary])))
        read_rcu_data(m, port, "0e", error)
        read_rcu_data(m, port, "06", binary.hex(bytes([0x10 | summary])))
        write_rkm(m, port, "05", b"\x3f\xf8")
        read_rkm(m, port, "c2", result)

    # DB8B3100 derives byte count from the returned address and decodes
    # two-byte entries. Load before one entry and after another to exercise
    # both the external console input and the load-queue command.
    m.rkm_input(rkm, 17, 6, 0x34)
    write_rkm(m, port, "01", b"\x62\xa0")
    read_rcu_data(m, port, "06", "14")
    m.rkm_input(rkm, 3, 2, 0x71)
    saved = m.checkpoint()
    for restore in [False, True]:
        if restore:
            m.restore(saved)
        wait_rkm_operator(m, 2000)
        run_9020_instruction(m, "9d00" + port_address, 1)
        if m.read(0x40, 8) != b"\x00\x00\x00\x00\x81\x00\x00\x00":
            fail("RKM console polling did not deliver attention B")
        read_rcu_data(m, port, "06", "3c")
        read_rcu_data(m, port, "06", "1c")
        read_rcu_data(m, port, "22", "62a4")
        read_rcu_data(m, port, "06", "10")
        write_rkm(m, port, "05", b"\x62\xa0")
        read_rkm(m, port, "c2", b"\x43\x71\xd1\x34")

    # DB8B4100 checks the 36–54 ms timeout and expects the error to
    # survive reading Error 1 and reading the queue address.
    write_rkm(m, port, "01", b"\x71\x60")
    m.rkm_input(rkm, 3, 4, 0x56)
    wait_rkm_operator(m, 2000)
    run_9020_instruction(m, "9d00" + port_address, 1)
    if m.read(0x44, 2) != b"\x81\x00":
        fail("RKM timeout control did not first deliver attention B")
    wait_rkm_operator(m, 30000)
    run_9020_instruction(m, rcu_tio, 0)
    wait_rkm_operator(m, 24000)
    run_9020_instruction(m, rcu_tio, 1)
    if m.read(0x44, 2) != b"\x80\x00":
        fail("RKM timeout did not deliver RCU attention")
    read_rcu_data(m, port, "06", "39")
    read_rcu_data(m, port, "0e", "08")
    read_rcu_data(m, port, "06", "19")
    read_rcu_data(m, port, "02", "7162")
    read_rcu_data(m, port, "06", "11")
    read_rcu_data(m, port, "0e", "08")
    rcu_io(m, rcu, "0700000020000001", 1, "0c00")

    write_rkm(m, port, "01", b"\x7f\xff")
    m.rkm_input(rkm, 3, 2, 0x72)
    wait_rkm_operator(m, 2000)
    run_9020_instruction(m, rcu_tio, 1)
    if m.read(0x44, 2) != b"\x80\x00":
        fail("RKM queue overflow did not deliver RCU attention")
    read_rcu_data(m, rcu, "12", "01000000")
    read_rcu_data(m, port, "0e", "01")
    read_rcu_data(m, port, "02", "0000")
    write_rkm(m, port, "01", b"\x62\xa0")
    read_rcu_data(m, port, "0e", "00")
    read_rcu_data(m, port, "02", "62a0")

    # The RCU still answers while its Disable Interfaces order isolates
    # the console bus. Reset reopens it without clearing RKM memory.
    write_rkm(m, port, "05", b"\x70\x10")
    write_rkm(m, port, "c1", b"\xc7\x61")
    write_rkm(m, port, "01", b"\x70\x10")
    rcu_io(m, rcu, "7700000020000001", 1, "0c00")
    m.rkm_input(rkm, 3, 2, 0x73)
    wait_rkm_operator(m, 2000)
    rcu_io(m, rcu, "0700000020000001", 1, "0c00")
    write_rkm(m, port, "05", b"\x70\x10")
    read_rkm(m, port, "c2", b"\xc7\x61")
    write_rkm(m, port, "01", b"\x70\x10")
    wait_rkm_operator(m, 2000)
    run_9020_instruction(m, "9d00" + port_address, 1)
    if m.read(0x44, 2) != b"\x81\x00":
        fail("RKM console did not resume after interfaces were reset")
    read_rcu_data(m, port, "02", "7012")
    write_rkm(m, port, "05", b"\x70\x10")
    read_rkm(m, port, "c2", b"\x43\x73")
    print("9020E RKM at %x verified Fetch Display Constants, A/B attention, keyboard records, queue checkpoint, timeout, overflow and interface isolation." % port)


def check_9020e_rkm_sparing(m, consoles):
    rcu_addresses = [0x2d, 0x2e, 0x2f, 0x39, 0x3a]
    groups = [(1, 3, 0x30, 3, "efffffff"), (2, 3, 0x31, 3, "efffffff")]
    if consoles == 90:
        groups = [(4, 5, 0x3b, 31, "fffffffe")]
    for group, spare, rcon, position, mask in groups:
        active_port, spare_port = 0x488 + group, 0x488 + spare
        for number in [group, spare]:
            address = rcu_addresses[number - 1]
            rcu_io(m, address, "af00000020000001", 1, "0c00")
            m.alter(0x2100, b"\x84\x00")
            rcu_io(m, address, "3100210000000002", 0, "0c00")
        rcu_io(m, rcon, "af00000020000001", 1, "0c00")
        m.alter(0x2100, b"\xff" * 4)
        rcu_io(m, rcon, "3100210000000004", 0, "0c00")

        constants = bytes([0x40 + group]) * 8
        m.rkm_console(group, position, constants)
        check_sparing_fetch(m, active_port, position, constants)
        for port, sentinel in [(active_port, b"\x1a\x1b"), (spare_port, b"\x2a\x2b")]:
            write_rkm(m, port, "05", b"\x62\xa0")
            write_rkm(m, port, "c1", sentinel)
            write_rkm(m, port, "01", b"\x62\xa0")
        m.rkm_input(group, position, 2, 0x70 + group)
        saved = m.checkpoint()
        for restored in [False, True]:
            if restored:
                m.restore(saved)
            else:
                m.alter(0x2100, binary.decode(mask, "hex"))
                rcu_io(m, rcon, "3100210000000004", 0, "0c00")
            read_rcu_data(m, rcon, "22", "ffffffff" if restored else mask)
            receiving = active_port if restored else spare_port
            other = spare_port if restored else active_port
            wait_rkm_operator(m, 2000)
            run_9020_instruction(m, "9d00" + ("0000%x" % receiving)[-4:], 1)
            if m.read(0x44, 2) != b"\x81\x00":
                fail("RCON %x: the selected RKM did not report console input" % rcon)
            run_9020_instruction(m, "9d00" + ("0000%x" % other)[-4:], 0)
            read_rcu_data(m, receiving, "02", "62a2")
            read_rcu_data(m, other, "02", "62a0")
            write_rkm(m, receiving, "05", b"\x62\xa0")
            read_rkm(m, receiving, "c2", bytes([0x40 | position, 0x70 + group]))
            write_rkm(m, other, "05", b"\x62\xa0")
            read_rkm(m, other, "c2", b"\x2a\x2b" if restored else b"\x1a\x1b")
            check_sparing_fetch(m, receiving, position, constants)
            check_sparing_fetch(m, other, position, None)
        print("9020E %d-console RCON %x moved console %d between RKMs %d and %d, including pending input and checkpoint restore." %
              (consoles, rcon, position, group, spare))


def check_sparing_fetch(m, port, position, constants):
    write_rkm(m, port, "21", bytes([position]))
    wait_rkm_operator(m, 2000)
    run_9020_instruction(m, "9d00" + ("0000%x" % port)[-4:], 1)
    if m.read(0x44, 2) != b"\xc0\x00":
        fail("RKM %x did not report the Fetch reply" % port)
    read_rcu_data(m, port, "06", "31" if constants == None else "30")
    read_rcu_data(m, port, "0e", "02" if constants == None else "00")
    if constants != None:
        write_rkm(m, port, "05", b"\x3f\xf8")
        read_rkm(m, port, "c2", constants)


def check_9020e_rkm_disconnect(m, first, second, rcu):
    disconnect = "4700000020000001"
    m.alter(0x2100, b"\x8c\x00")
    rcu_io(m, rcu, "3100210000000002", 0, "0c00")  # Connect both 2701s.
    rcu_io(m, rcu, "0700000020000001", 1, "0c00")
    rcu_io(m, first, disconnect, 0, "0c00")
    if binary.hex(m.read(0x40, 8)) != "000020080c000001":
        fail("RKM Disconnect should transfer no bytes")
    read_rcu_data(m, first, "06", "10")  # DB8B1100 routine 0A.
    read_rcu_data(m, first, "04", "00")

    start_rkm_operator(m, first, "81", "53000100")
    rcu_io(m, second, disconnect, 0, "0c00")
    read_rcu_data(m, second, "06", "50")
    wait_rkm_operator(m, 2000)
    write_rkm(m, second, "05", b"\x53\xff")
    read_rkm(m, second, "c2", b"\x6c")

    # Save while a fixed-length operand is still on the bus. After Restore,
    # all four bytes must be received before the Clear data operator starts.
    write_rkm(m, first, "05", b"\x54\x00")
    write_rkm(m, first, "c1", b"\x81")
    m.alter(0x2400, b"\x54\x00\x00\x01")
    m.alter(0x2000, binary.decode(format0_ccw("81", 0x2400, "00", 4), "hex"))
    first_hex = ("0000%x" % first)[-4:]
    run_9020_instruction(m, "9c00" + first_hex, 0)
    operand = m.checkpoint()
    run_9020_instruction(m, "9e00" + first_hex, 2)
    m.restore(operand)
    wait_rkm_operator(m, 200)
    run_9020_instruction(m, "9d00" + first_hex, 1)
    write_rkm(m, first, "05", b"\x54\x00")
    read_rkm(m, first, "c2", b"\x6c")

    start = b"\x50\x00"
    sentinel = b"\xee" * 128
    pattern = bytes(list(range(128)))
    write_rkm(m, first, "05", start)
    write_rkm(m, first, "c1", sentinel)
    write_rkm(m, first, "05", start)
    m.alter(0x4000, pattern[:8])
    m.alter(0x4100, pattern[8:])
    ccws = format0_ccw("c1", 0x4000, "80", 8) + format0_ccw("c1", 0x4100, "40", 120) + "0300000000000001"
    m.alter(0x2000, binary.decode(ccws, "hex"))
    run_9020_instruction(m, "9c00" + first_hex, 0)
    wait_rkm_operator(m, 500)
    read_rcu_data(m, second, "06", "90")
    m.alter(0x4100 + 52, b"\xb6" * 68)  # Change bytes that have not crossed the bus.
    pattern = binary.decode(binary.hex(pattern[:60]) + "b6" * 68, "hex")
    wait_rkm_operator(m, 400)
    sending = m.checkpoint()
    for halt in [False, True]:
        if halt:
            m.restore(sending)
            run_9020_instruction(m, "9e00" + first_hex, 2)
        else:
            rcu_io(m, second, disconnect, 0, "0c00")
        run_9020_instruction(m, "9d00" + first_hex, 1)
        csw = binary.hex(m.read(0x40, 8))
        sent = 128 - int(csw[12:], 16)
        if csw[:12] != "000020100c40" or sent <= 60 or sent >= 128:
            fail("interrupted RKM Write did not stop in its second data CCW: %s" % csw)
        read_rcu_data(m, second, "06", "10")
        # The unaccepted suffix is still present at the current I/O address.
        read_rkm(m, second, "c2", sentinel[sent:])
        write_rkm(m, second, "05", start)
        expected = binary.decode(binary.hex(pattern[:sent]) + binary.hex(sentinel[sent:]), "hex")
        read_rkm(m, second, "c2", expected)

    # Interrupt the reverse direction and compare both the CSW and storage
    # against the prefix already visible during the read.
    write_rkm(m, first, "05", start)
    write_rkm(m, first, "c1", pattern)
    write_rkm(m, second, "05", start)
    m.alter(0x4200, sentinel)
    m.alter(0x2000, binary.decode(format0_ccw("c2", 0x4200, "00", 128), "hex"))
    second_hex = ("0000%x" % second)[-4:]
    run_9020_instruction(m, "9c00" + second_hex, 0)
    wait_rkm_operator(m, 500)
    if m.read(0x4200, 16) != pattern[:16] or m.read(0x4260, 16) != sentinel[:16]:
        fail("RKM Read did not expose the accepted prefix during transfer")
    rcu_io(m, first, disconnect, 0, "0c00")
    run_9020_instruction(m, "9d00" + second_hex, 1)
    csw = binary.hex(m.read(0x40, 8))
    received = 128 - int(csw[12:], 16)
    if csw[:12] != "000020080c40" or received <= 16 or received >= 128:
        fail("interrupted RKM Read did not report a partial transfer: %s" % csw)
    if m.read(0x4200, received) != pattern[:received] or m.read(0x4200 + received, 128 - received) != sentinel[received:]:
        fail("RKM Read stored bytes beyond the accepted prefix")
    read_rcu_data(m, first, "06", "10")
    read_rkm(m, first, "c2", pattern[received:])
    print("9020E RKM at %x/%x verified idle Disconnect, both Busy bits, checkpointed operands, and partial reads and writes with correct residuals." %
          (first, second))


def check_9020e_rkm_special_move(m, port, rcu):
    # DB8B1100 routine 0E initializes the destination to zero. The
    # comparisons require Special Move to generate display blanks.
    write_rkm(m, port, "05", b"\x00\x00")
    write_rkm(m, port, "c1", b"\x00" * 376)
    write_rkm(m, port, "05", b"\x2a\xaa")
    write_rkm(m, port, "c1", b"\xe0" * 375)
    start_rkm_operator(m, port, "41", "000001772aaa")
    active = m.checkpoint()
    expected = binary.decode(("e0" * 15 + "6c" * 20 + "e0" * 15 + "6c" * 25) * 5 + "00", "hex")
    for restore in [False, True]:
        if restore:
            m.restore(active)
            read_rcu_data(m, port, "06", "50")
        wait_rkm_operator(m, 2500)
        read_rcu_data(m, port, "06", "10")
        write_rkm(m, port, "05", b"\x00\x00")
        read_rkm(m, port, "c2", expected)

    # DB8B3100 supplies consecutive 15-byte rows at 26EC. Distinct
    # bytes distinguish the modeled source progression from copying by
    # destination offset. The target is deliberately unaligned.
    source = bytes(list(range(225)))
    target = b"\x11\x03"
    write_rkm(m, port, "05", b"\x26\xec")
    write_rkm(m, port, "c1", source)
    write_rkm(m, port, "05", target)
    write_rkm(m, port, "c1", b"\xfa" * 156)
    write_rkm(m, port, "41", binary.decode("1103009b26ec", "hex"))
    wait_rkm_operator(m, 1000)
    expected_hex = ""
    for offset in [0, 30]:
        expected_hex += binary.hex(source[offset:offset + 15]) + "6c" * 20
        expected_hex += binary.hex(source[offset + 15:offset + 30]) + "6c" * 25
    expected_hex += binary.hex(source[60:65]) + "fa"
    write_rkm(m, port, "05", target)
    read_rkm(m, port, "c2", binary.decode(expected_hex, "hex"))

    # DB8B2200 lists five- and seven-byte Special Move operands as
    # procedural errors. Neither is allowed to start a data operator.
    m.alter(0x2400, binary.decode("1103009b26ec00", "hex"))
    for count in [5, 7]:
        rcu_io(m, port, format0_ccw("41", 0x2400, "20", count), 0, "0c00")
        read_rcu_data(m, port, "06", "11")
        read_rcu_data(m, port, "0e", "04")

    rcu_tio = "9d00" + binary.hex(bytes([0, rcu]))
    # The last valid source byte can be followed by blanks. A later
    # source read and a target write past storage raise Error 2 bit 3.
    write_rkm(m, port, "05", b"\x7f\xf1")
    write_rkm(m, port, "c1", b"\x4d" * 15)
    write_rkm(m, port, "05", b"\x10\x00")
    write_rkm(m, port, "c1", b"\xee" * 51)
    write_rkm(m, port, "41", binary.decode("100000237ff1", "hex"))
    wait_rkm_operator(m, 300)
    run_9020_instruction(m, rcu_tio, 0)
    read_rcu_data(m, port, "16", "00")
    for operand, address, data in [
        ("100000327ff1", b"\x10\x00", binary.decode("4d" * 15 + "6c" * 20 + "ee" * 16, "hex")),
        ("7fec001526ec", b"\x7f\xec", binary.decode(binary.hex(source[:15]) + "6c" * 5, "hex")),
    ]:
        write_rkm(m, port, "41", binary.decode(operand, "hex"))
        wait_rkm_operator(m, 250)
        run_9020_instruction(m, rcu_tio, 1)
        if m.read(0x44, 2) != b"\x80\x00":
            fail("RKM Special Move overflow did not raise RCU attention")
        read_rcu_data(m, port, "16", "10")
        write_rkm(m, port, "05", address)
        read_rkm(m, port, "c2", data)
    print("9020E RKM at %x verified the FAA Special Move pattern, compact input, partial lengths, mid-operation restore and both address limits." % port)


def check_9020e_rkm_operators(m, port, rcu):
    # DB8B1100 routine 0C clears to X'6C'. Check the ends of the FAA
    # ranges and ensure the neighboring bytes retain their former data.
    write_rkm(m, port, "05", b"\x00\x00")
    write_rkm(m, port, "c1", b"\x00" * 32768)
    for command, operands, address, expected in [
        ("81", "00000001", b"\x7f\xff", b"\x00\x6c\x00"),
        ("81", "00000200", b"\x01\xfe", b"\x6c\x6c\x00"),
        ("81", "22a01f00", b"\x41\x9e", b"\x6c\x6c\x00"),
        ("a1", "77a10001", b"\x77\xa0", b"\x00\x6c\x00"),
    ]:
        if operands == "22a01f00":
            start_rkm_operator(m, port, command, operands)
        else:
            write_rkm(m, port, command, binary.decode(operands, "hex"))
        wait_rkm_operator(m, 167000)
        read_rcu_data(m, port, "06", "10")
        write_rkm(m, port, "05", address)
        read_rkm(m, port, "c2", expected)

    # DB8B1100 Blink Set and Reset affect only the most significant bit.
    pattern = bytes(list(range(128)))
    write_rkm(m, port, "05", b"\x00\x00")
    write_rkm(m, port, "c1", pattern)
    for command, expected in [("b1", bytes(list(range(128, 256)))), ("91", pattern)]:
        start_rkm_operator(m, port, command, "00000080")
        wait_rkm_operator(m, 167000)
        write_rkm(m, port, "05", b"\x00\x00")
        read_rkm(m, port, "c2", expected)

    # Halt before all four operand bytes arrive. No operator starts.
    m.alter(0x2400, b"\x00\x00\x02\x00")
    m.alter(0x2000, binary.decode(format0_ccw("81", 0x2400, "00", 4), "hex"))
    hex_port = ("0000%x" % port)[-4:]
    run_9020_instruction(m, "9c00" + hex_port, 0)
    run_9020_instruction(m, "9e00" + hex_port, 2)
    run_9020_instruction(m, "9d00" + hex_port, 1)
    read_rcu_data(m, port, "06", "10")
    write_rkm(m, port, "05", b"\x00\x00")
    read_rkm(m, port, "c2", b"\x00\x01")

    # RCU Stop freezes the operation across its unpaused completion time.
    start_rkm_operator(m, port, "81", "50002000")
    rcu_io(m, rcu, "4700000020000001", 1, "0c00")
    wait_rkm_operator(m, 40000)
    rcu_io(m, rcu, "5700000020000001", 1, "0c00")
    read_rcu_data(m, port, "06", "50")
    wait_rkm_operator(m, 167000)
    read_rcu_data(m, port, "06", "10")
    write_rkm(m, port, "05", b"\x6f\xff")
    read_rkm(m, port, "c2", b"\x6c\x00")

    # MV7 copies forward from address zero with an overlapping target.
    # The written E0 must propagate throughout, including the last byte.
    write_rkm(m, port, "05", b"\x00\x00")
    write_rkm(m, port, "c1", b"\xe0")
    start_rkm_operator(m, port, "61", "00017ffd0000")
    active = m.checkpoint()
    for restore in [False, True]:
        if restore:
            m.restore(active)
            read_rcu_data(m, port, "06", "50")
        wait_rkm_operator(m, 167000)
        read_rcu_data(m, port, "06", "10")
        write_rkm(m, port, "05", b"\x7f\xfc")
        read_rkm(m, port, "c2", b"\xe0\xe0\x00")

    # DB8B4100 checks both address registers. The asynchronous fault
    # arrives on the RCU address, while the DAU returns the RKM error.
    rcu_io(m, rcu, "9f00000020000001", 1, "0c00")
    rcu_tio = "9d00" + binary.hex(bytes([0, rcu]))
    run_9020_instruction(m, rcu_tio, 0)
    for operands in ["7ffe00037ff0", "7ff000037ffe"]:
        write_rkm(m, port, "61", binary.decode(operands, "hex"))
        run_9020_instruction(m, rcu_tio, 1)
        if binary.hex(m.read(0x44, 2)) != "8000":
            fail("RKM operator overflow did not deliver RCU attention")
        read_rcu_data(m, port, "06", "12")
        read_rcu_data(m, rcu, "12", "00100000")
        read_rcu_data(m, port, "16", "10")
        read_rcu_data(m, port, "06", "10")
        write_rkm(m, port, "05", b"\x00\x00")
        read_rkm(m, port, "c2", b"\xe0")
    print("9020E RKM at %x verified Clear, Blink and forward-overlapping Move, chained busy status, Halt, Stop/Resume, checkpoint and both overflow reports." % port)


def check_9020e_display_storage():
    m = emulator.s390(architecture = "s360", model = "9020e", display_elements = 2, interval_timer = False, mips = 1)
    m.rcu(0x20)
    m.alter(0, binary.decode("0000000000001000", "hex"))
    m.alter(0x1000, binary.decode("4400900007f8", "hex"))
    m.alter(0x68, binary.decode("0000000000001500", "hex"))
    m.alter(0x48, binary.decode("00002000", "hex"))
    m.restart(storage_element = 1)
    m.alter_register(8, 0x1000)
    m.alter_register(9, 0x1800)
    m.alter(0x600, binary.decode("00fd500000000000a5a5a5a5", "hex"))
    run_9020_instruction(m, "83000600", 0)  # DIAG Define Storage
    if binary.hex(m.read(0x608, 4)) != "a5a5a512":
        fail("9020E Define Storage did not return one SE and two DEs")
    m.alter_register(3, 0x280000)
    m.alter_register(1, 0xfedcba98)
    run_9020_instruction(m, "50103000", 0)  # ST 1,0(3)
    if binary.hex(m.read(0x280000, 4)) != "fedcba98":
        fail("9020E store missed the default DE 6 address")

    # A27-9020-01, §8.4.5.7. Exchange the two Display Elements in the
    # CE and IOCE translators. Storage module numbers begin at one.
    m.alter_register(4, 0x10000760)
    m.alter_register(5, 0x84)
    run_9020_instruction(m, "0d45", 0)  # SATR 4,5
    run_9020_instruction(m, "0e67", 0)  # IATR 6,7
    if m.registers().gr[6] != "10000760":
        fail("9020E IATR did not return the exchanged DE assignment")
    run_9020_instruction(m, "50103000", 0)
    m.alter_register(3, 0x2bfffc)
    m.alter_register(1, 0x01234567)
    run_9020_instruction(m, "50103000", 0)
    if binary.hex(m.read(0x300000, 4)) != "fedcba98" or binary.hex(m.read(0x33fffc, 4)) != "01234567":
        fail("9020E exchanged DE did not store at both ends of its 256 KiB range")
    m.alter_register(3, 0x300000)
    run_9020_instruction(m, "58203000", 0)  # L 2,0(3)
    if m.registers().gr[2] != "FEDCBA98":
        fail("9020E load missed DE 6 after exchanging the ATR slots")

    # Protection, bounds and installation checks all start with the same map.
    m.alter_register(1, 0x58)
    run_9020_instruction(m, "0813", 0)  # SSK 1,3
    run_9020_instruction(m, "0973", 0)  # ISK 7,3
    if not m.registers().gr[7].endswith("58"):
        fail("9020E display storage did not retain its independent key")
    assigned = m.checkpoint()
    for label, instruction, operand, code in [
        ("unassigned SE slot", "58203000", 0x80000, 5),
        ("upper half of DE 7 slot", "58203000", 0x2c0000, 5),
        ("absent display slot", "58203000", 0x380000, 5),
        ("uninstalled DE identifier", "0d45", 0x10000860, 6),
        ("DE identifier in an SE slot", "0d45", 0x16000760, 6),
        ("SE identifier in a DE slot", "0d45", 0x10000160, 6),
        ("LPSB into DE 6", "a1000600", 0x300000, 6),
        ("DE fetch with a nonmatching key", "58203000", 0x300000, 4),
    ]:
        m.restore(assigned)
        m.clear_breaks()
        m.alter_register(3, operand)
        m.alter_register(4, operand)
        m.alter(0x600, binary.decode(("0000000%x" % operand)[-8:], "hex"))
        m.alter(0x1800, binary.decode(instruction, "hex"))
        if code == 4:
            m.alter(0x620, binary.decode("0020000000001004", "hex"))
            run_9020_instruction(m, "82000620", 0, system = "00200000")
            m.alter(0x1800, binary.decode(instruction, "hex"))
            m.clear_breaks()
        m.break_program(code)
        stop = m.run(instructions = 4)
        if stop.kind != "program" or m.read(0x2a, 2) != bytes([0, code]):
            fail("9020E %s: %s %s, expected program %04x" % (label, stop.kind, stop.psw, code))
    m.restore(assigned)

    # SCON disconnects DE 6 from its CE. The next CE access must fail.
    m.alter_register(2, 0x00040000)
    m.alter_register(4, 0xe0000000)
    run_9020_instruction(m, "0142", 0)
    m.alter(0x1800, binary.decode("58203000", "hex"))
    m.clear_breaks()
    m.break_program(5)
    if m.run(instructions = 4).kind != "program":
        fail("9020E CE accessed DE 6 after SCON removed its connection")
    m.restore(assigned)
    run_9020_instruction(m, "58203000", 0)
    if m.registers().gr[2] != "FEDCBA98":
        fail("9020E checkpoint did not restore the DE link and translated data")

    # The IOCE accepted the same ATR but may transfer only into SEs.
    rcu_io(m, 0x21, format0_ccw("af", 0, "20", 1), 1, "0c00")
    rcu_io(m, 0x21, format0_ccw("12", 0x2200, "00", 2), 0, "0c00")
    rcu_io(m, 0x21, format0_ccw("12", 0x300000, "00", 2), 0, "0c20")
    if binary.hex(m.read(0x280000, 4)) != "fedcba98":
        fail("9020E IOCE transfer wrote into DE 6")
    print("9020E display storage verified fixed 256 KiB ranges, exchanged ATR slots, guest protection, SCON and IOCE exclusion.")


def check_9020e_display_logout():
    m = emulator.s390(architecture = "s360", model = "9020e", display_elements = 1, interval_timer = False)
    m.alter(0, binary.decode("0004000000001000", "hex"))
    m.alter(0x70, binary.decode("0000000000001100", "hex"))
    m.alter(0x68, binary.decode("0000000000001140", "hex"))
    m.alter(0x1000, binary.decode("58201000", "hex"))  # L 2,0(1)
    m.alter(0x1100, binary.decode("58301000", "hex"))  # L 3,0(1)
    m.alter(0x1140, binary.decode("8300028007f4", "hex"))  # DIAG 280 followed by BR 4.
    m.alter(0x280, binary.decode("00fd080060008000" + "ff" * 49, "hex"))
    m.alter(0x281240, binary.decode("0123456789abcdef0011223344556677", "hex"))
    m.restart(storage_element = 1)
    m.alter_register(4, 0x1000)
    m.alter_register(2, 0xdeadbeef)
    m.alter_register(3, 0xdeadbeef)
    ready = m.checkpoint()
    for offset, data, parity in [(0, "0123456789abcdef", "01"), (8, "0011223344556677", "fe")]:
        m.restore(ready)
        m.clear_breaks()
        address = 0x281240 + offset
        m.alter_register(1, address)
        m.set_storage_data_parity(address + 7, bad = True)
        raised = m.run(instructions = 1)
        if (not raised.psw.endswith("001100") or m.registers().gr[2] != "DEADBEEF" or
            binary.hex(m.read(168, 2)) != "600a"):
            fail("9020E DE parity: %s %s, CE check %s" % (raised.kind, raised.psw, binary.hex(m.read(168, 2))))
        m.break_program(0x80)
        stopped = m.run(instructions = 1)
        if stopped.kind != "program" or not stopped.psw.endswith("001140") or m.registers().gr[3] != "DEADBEEF":
            fail("9020E DE remained accessible after Logout Stop: %s %s" % (stopped.kind, stopped.psw))
        m.break_at(0x1144)
        collected = m.run(instructions = 2)
        bank = binary.hex(m.read(0x288 + 2 * offset, 16))
        box = int(binary.hex(m.read(0x2b4, 2)), 16) >> 6 & 0xf
        if (collected.kind != "breakpoint" or collected.psw != "00000000 00001144" or
            bank[:24] != data + "00" + parity + "02a4" or int(bank[24:26], 16) & 0x18 != 0x18 or
            box != 6 or m.read(0x2b8, 1) != b"\xff"):
            fail("9020E DE %s logout: %s %s, bank %s, module %x" %
                 ("odd" if offset else "even", collected.kind, collected.psw, bank, box))
        m.set_storage_data_parity(address + 7, bad = False)
        m.clear_breaks()
        m.break_at(0x1004)
        retried = m.run(instructions = 3)
        if retried.kind != "breakpoint" or m.registers().gr[2] != data[:8].upper():
            fail("9020E display load did not recover after FD0: %s %s" % (retried.kind, retried.psw))
    print("9020E DE parity stopped both display banks in turn, and FD0 collected their native logout data and released the DE.")


def check_9020e_defeat_interleave():
    m = emulator.s390(architecture = "s360", model = "9020e", display_elements = 1, interval_timer = False)
    m.alter(0, binary.decode("0000000000000ff8", "hex"))
    m.alter(0xff8, binary.decode("087c088d07000142", "hex"))  # Set distinct keys, then SCON CE 1 to State Zero.
    m.alter(0x600, binary.decode("0001080000008000", "hex"))  # D22A45 M6MCW.
    for address, word in [(0x280000, "f0f1f2f3f4f5f6f7"), (0x280008, "e0e1e2e3e4e5e6e7"),
                          (0x2a0000, "1011121314151617"), (0x2a0008, "2021222324252627")]:
        m.alter(address, binary.decode(word, "hex"))
    m.restart(storage_element = 1)
    m.alter_register(1, 0x2a0000)
    m.alter_register(2, 0x00000800)
    m.alter_register(4, 0x20840800)
    m.alter_register(6, 0x1026)
    m.alter_register(7, 0x10)
    m.alter_register(8, 0x48)
    m.alter_register(10, 0x2a2000)
    m.alter_register(11, 0x2a0000)
    m.alter_register(12, 0x282000)
    m.alter_register(13, 0x2a2000)
    initial = m.checkpoint()

    for control, load_at, branch_at, mvc_at, mvc_tail, low, high, first, second in [
        ("00", 0x1004, 0x1008, 0x1026, 0x1028, 0x2a2000, 0x2a2008, "1011121314151617", "2021222324252627"),
        ("80", 0x1004, 0x21000, 0x1026, 0x21020, 0x282008, 0x2a2008, "e0e1e2e3e4e5e6e7", "2021222324252627"),
        ("40", 0x100c, 0x21008, 0x102e, 0x21028, 0x282000, 0x2a2000, "f0f1f2f3f4f5f6f7", "1011121314151617"),
    ]:
        m.restore(initial)
        m.clear_breaks()
        m.alter(0x1000, binary.decode("83" + control + "0600", "hex"))
        m.alter(load_at, binary.decode("58301000", "hex"))  # L 3,0(1)
        m.alter(branch_at, binary.decode("07f6", "hex"))
        m.alter(mvc_at, binary.decode("d20f", "hex"))
        m.alter(mvc_tail, binary.decode("a000b000", "hex"))  # MVC 0(16,10),0(11)
        m.break_at(0x102c)
        stop = m.run(instructions = 12)
        if (stop.kind != "breakpoint" or m.registers().gr[3] != first[:8].upper() or
            binary.hex(m.read(low, 8)) != first or binary.hex(m.read(high, 8)) != second):
            fail("9020E DIAG I2 %s load or cross-bank MVC: %s %s" % (control, stop.kind, stop.psw))
        if control == "00":
            continue

        # The two key cycles in this logical block now reach distinct
        # physical blocks. ISK ORs their keys and SSK writes both.
        m.alter_register(1, 0x68)
        m.alter_register(2, 0x2a2000)
        m.alter(mvc_tail + 4, binary.decode("09520812", "hex"))  # ISK 5,2 and SSK 1,2
        m.clear_breaks()
        m.break_at(0x1030)
        stop = m.run(instructions = 3)
        if (stop.kind != "breakpoint" or not m.registers().gr[5].endswith("58") or
            m.storage_keys(low, 1) != b"\x68" or m.storage_keys(high, 1) != b"\x68" or
            m.storage_keys(low + 0x800, 1) != b"\x00" or m.storage_keys(high + 0x800, 1) != b"\x00"):
            fail("9020E DIAG I2 %s did not read and update the two expected storage keys" % control)
        active = m.checkpoint()
        m.restore(initial)
        m.restore(active)
        if m.storage_keys(low, 1) != b"\x68" or m.storage_keys(high, 1) != b"\x68":
            fail("9020E checkpoint did not restore the storage keys")
        # DIAG at logical 1030 reads its MCW with the old map and clears
        # both lines. The next instruction at 1034 then uses normal storage.
        m.alter(0x600 if control == "80" else 0x608, binary.decode("0001000000008000", "hex"))
        m.alter(0x1030 if control == "80" else 0x1038, binary.decode("83000600", "hex"))
        m.alter(0x1034, binary.decode("5830b000", "hex"))
        m.clear_breaks()
        m.break_at(0x1038)
        stop = m.run(instructions = 3)
        if stop.kind != "breakpoint" or m.registers().gr[3] != "10111213":
            fail("9020E DIAG did not restore normal addressing: %s %s" % (stop.kind, stop.psw))
        m.restore(active)
        m.alter(0, binary.decode("0000000000001004", "hex"))
        m.alter(0x1004, binary.decode("5830b000", "hex"))
        m.clear_breaks()
        m.restart()
        m.break_at(0x1008)
        stop = m.run(instructions = 2)
        if stop.kind != "breakpoint" or m.registers().gr[3] != "10111213":
            fail("9020E PSW restart did not restore normal addressing: %s %s" % (stop.kind, stop.psw))

    m.restore(initial)
    m.clear_breaks()
    m.alter(0xffe, binary.decode("0700", "hex"))  # Leave the CE in State Three.
    m.alter(0x600, binary.decode("00fd50000000000000000000", "hex"))  # Operational FD5 kernel.
    m.alter(0x1000, binary.decode("8380060058301000", "hex"))
    m.break_at(0x1008)
    stop = m.run(instructions = 8)
    if stop.kind != "breakpoint" or m.registers().gr[3] != "10111213" or m.read(0x60b, 1) != b"\x11":
        fail("9020E DIAG I2 was not ignored in State Three: %s %s" % (stop.kind, stop.psw))
    print("9020E DIAG verified both bank selections, a cross-bank MVC, both key cycles, restart, checkpoint and the State Three control.")


def display_wire_word(word):
    value = int(word, 16) & ((1 << 63) - 1)
    odd = 1
    for i in range(63):
        odd ^= value >> i & 1
    return ("0000000000000000%x" % (value | (odd << 63)))[-16:]


def expect_display_wrap(m, words):
    m.clear_breaks()
    m.break_at(0x101c)
    result = m.run(instructions = 42000)
    expected = [display_wire_word(word) for word in words]
    actual = binary.hex(m.read(0x688, 8 * len(words)))
    if result.kind != "breakpoint" or result.psw != "00000000 0000101C" or actual != "".join(expected):
        mismatch = [i for i in range(len(expected)) if actual[i * 16:(i + 1) * 16] != expected[i]]
        detail = (expected[mismatch[0]], actual[mismatch[0] * 16:(mismatch[0] + 1) * 16]) if mismatch else ()
        fail("DE wrap of %d doublewords: %s %s, first mismatches %s %s" %
             (len(words), result.kind, result.psw, mismatch[:8], detail))
    if m.read(0x688 + len(words) * 8, 8) != b"\xff" * 8:
        fail("DE wrap wrote beyond the MCW count")


def check_9020e_display_wrap():
    # D24A0100 routine 6. Six SOD/Transfer quadwords start separate
    # streams containing four data quadwords and one EOD each.
    m = emulator.s390(architecture = "s360", model = "9020e", display_elements = 1, memory = 1 << 20, mips = 1, interval_timer = False)
    m.alter(0, binary.decode("0000000000000ffe", "hex"))
    m.alter(0xffe, binary.decode("0142", "hex"))  # SCON the CE to State Zero.
    # DLY 1 lets every CVG see a slot before the CE tests and stops them.
    m.alter(0x1000, binary.decode("0124830006000b0195ff10244770800850701000920010248300068083000608830006300700", "hex"))
    m.alter(0x68, binary.decode("0002000000001500", "hex"))
    m.alter(0x600, binary.decode("0001080060fd00000001000060010000", "hex"))  # Force all, then reset.
    m.alter(0x630, binary.decode("00fd000060000000", "hex"))  # FD0 DE6.
    m.alter(0x680, binary.decode("00ad312061fc1000", "hex"))  # DE6, DG1, 72 doublewords.
    m.alter(0x688, b"\xff" * 584)
    base, word_address = 0x280000, 0x4000
    headers, streams = [], []
    for cvg in range(6):
        source = word_address + 80 * cvg
        sod = "48000000" + ("00" if cvg == 0 else "ff") + "00000%x" % (cvg + 1)
        transfer = "5000000000" + ("000000%x" % source)[-6:]
        header = sod + transfer
        headers.append([sod, transfer])
        m.alter(base + 32 + 32 * cvg, binary.decode(header[:8] + "00" + header[10:], "hex"))
        m.alter(base + 48 + 32 * cvg, b"\xff" * 16)  # Transfer must skip this quadword.
        data = []
        for pair in range(5):
            high = ("00000000" if pair < 4 else "40000000") + "0000%x0%x1" % (cvg + 1, pair + 1)
            low = "000000000000%x0%x2" % (cvg + 1, pair + 1)
            data.append([high, low if pair < 4 else high])
            m.alter(base + source + pair * 16, binary.decode(high + low, "hex"))
        streams.append(data)
    m.restart(storage_element = 1)
    m.alter_register(2, 0x800)
    m.alter_register(4, 0x20c40800)
    m.break_at(0x1000)
    if m.run(instructions = 4).kind != "breakpoint":
        fail("DE wrap could not select CE State Zero")
    m.alter_register(1, base)
    m.alter_register(2, 0xe0000800)
    m.alter_register(3, 0xaa000000)  # DG1–4 on buffers A–D.
    m.alter_register(4, 0x00040000)
    m.alter_register(7, 0xffffff00)
    m.alter_register(8, 0x1000)
    before_scon = m.checkpoint()
    m.clear_breaks()
    m.break_program(6)
    m.break_at(0x1010)
    observed = m.run(instructions = 512)
    if observed.kind != "breakpoint" or any([m.read(base + 36 + 32 * cvg, 1) != b"\xff" for cvg in range(6)]):
        fail("DE forced request did not set the SOD test-and-set byte: %s %s" % (observed.kind, observed.psw))
    before_wrap = m.checkpoint()
    m.clear_breaks()
    pending = m.run(instructions = 8)
    if pending.kind != "budget" or not pending.psw.endswith("00101C") or m.read(0x688, 8) != b"\xff" * 8:
        fail("DE wrap did not wait for the virtual refresh clock: %s %s" % (pending.kind, pending.psw))
    inflight = m.checkpoint()
    for changed in [False, True]:
        m.restore(inflight)
        if changed:
            streams[0][0][0] = "0123456789abcdef"
            m.alter(base + word_address, binary.decode(streams[0][0][0], "hex"))
        words = [word for pair in headers for word in pair]
        words += [word for i in range(5) for cvg in range(6) for word in streams[cvg][i]]
        expect_display_wrap(m, words)
        m.clear_breaks()
        m.break_at(0x1024)
        if m.run(instructions = 4).psw != "00000000 00001024" or binary.hex(m.read(0x658, 4)) != "d5401c10":
            fail("DE reset and FD0 did not report the DG assignment")

    # D24A routine 4 captures one CVG, including the next SOD after
    # either an even or an odd EOD. The even Transfer skips a poison pair.
    for eod_even in [False, True]:
        m.restore(before_wrap)
        m.alter(0x680, binary.decode("00ad303061801000", "hex"))
        data = ["0000000000000201", "0000000000000202", "0000000000000301", "0000000000000302"]
        jump, end, last = "5000000000004040", "4000000000000502", "0000000000000501"
        m.alter(base + word_address, binary.decode("".join(data) + jump + "ff" * 24, "hex"))
        m.alter(base + 0x4040, binary.decode((end + last) if eod_even else (last + end), "hex"))
        next_header = "48000000ff000001"
        expect_display_wrap(m, headers[0] + data + [jump, jump, end if eod_even else last, end, next_header, headers[0][1]])

    # The long capture spans a full 266 doubleword buffer with only
    # the selected CVG on DG1, even when Force activated all six.
    m.restore(before_wrap)
    m.alter(0x680, binary.decode("00ad342861801000", "hex"))
    m.alter(0x688, b"\xff" * (267 * 8))
    long_words = ["0000000000000" + ("000%x" % i)[-3:] for i in range(1, 265)]
    long_words[-1] = "4000000000000001"
    m.alter(base + word_address, binary.decode("".join(long_words), "hex"))
    expect_display_wrap(m, headers[0] + long_words)

    m.restore(before_wrap)
    m.alter(0x680, binary.decode("00ad312065fc1000", "hex"))  # DG5 is disconnected.
    m.clear_breaks()
    m.break_at(0x101c)
    missing = m.run(instructions = 16)
    if missing.kind != "breakpoint" or missing.psw != "00000000 1000101C" or m.read(0x688, 8) != b"\xff" * 8:
        fail("DE wrap on a disconnected DG did not return CC1: %s %s" % (missing.kind, missing.psw))

    m.restore(before_scon)
    m.alter_register(3, 0x60000000)  # DG1 and DG2 both assigned buffer B.
    m.alter(0x1002, binary.decode("83000630", "hex"))
    m.clear_breaks()
    m.break_at(0x1002)
    invalid = m.run(instructions = 4)
    if invalid.kind != "breakpoint" or invalid.psw != "00000000 20001002" or m.registers().gr[2] != "00040000":
        fail("DE SCON accepted two DGs on one buffer")
    m.clear_breaks()
    m.break_at(0x1006)
    if m.run(instructions = 4).kind != "breakpoint" or binary.hex(m.read(0x658, 4)) != "b0401c11":
        fail("DE FD0 did not report the rejected DG assignment")
    print("9020E DE6 verified forced SOD, 12-, 72- and 266-doubleword wraps, Transfer/EOD, parity, checkpoint, timeout and DG configuration in FD0.")


def check_9020e_display_contention():
    # D24A0100 routine 8 and CETLDS. The same guest load stream runs with
    # DE6 idle and with all 24 CVGs requesting full-length display images.
    m = emulator.s390(architecture = "s360", model = "9020e", display_elements = 1,
                      memory = 1 << 20, mips = 5, start = "1985-08-30T12:00:00Z")
    base = 0x280000
    m.alter(0, binary.decode("0000000000000ffe", "hex"))
    m.alter(0xffe, binary.decode("0142", "hex"))  # Select CE State Zero.
    m.alter(0x50, binary.decode("7fffffff", "hex"))
    # SCON, DIAG Force, DLY 200, wait for a timer step and save the timer.
    m.alter(0x1000, binary.decode("0124830006000bc858600050556000504780800c5860005047f08100", "hex"))
    m.alter(0x1100, binary.decode("5830200058504000" * 50 + "46108100587000500700", "hex"))
    for cvg in range(24):
        m.alter(base + 32 + cvg * 32, binary.decode("48000000000000005000000000000800", "hex"))
    m.alter(base + 2048, b"\x0f" * (0xa7f0 - 2048))
    m.alter(base + 0xa7f0, binary.decode("40000000000000004000000000000000", "hex"))
    m.restart(storage_element = 1)
    m.alter_register(2, 0x800)
    m.alter_register(4, 0x20c40800)
    m.break_at(0x1000)
    if m.run(instructions = 4).kind != "breakpoint":
        fail("DE contention could not select CE State Zero")
    for r, val in [(1, 27778), (2, 0xe0000800), (3, 0xaa000000), (4, 0x40000), (8, 0x1000)]:
        m.alter_register(r, val)
    m.clear_breaks()
    m.break_at(0x1002)
    if m.run(instructions = 4).kind != "breakpoint":
        fail("DE contention could not configure the four buffers")
    m.alter_register(2, base + 2048)
    m.alter_register(4, base + 2056)
    m.clear_breaks()
    ready = m.checkpoint()
    timings = []
    for force, mcw, tas, low, high in [(False, "0001000000000000", b"\x00", 330, 337),
                                      (True, "0001000060fd0000", b"\xff", 2940, 3060)]:
        m.restore(ready)
        m.alter(0x600, binary.decode(mcw, "hex"))
        m.break_at(0x1298)
        stop = m.run(instructions = 55000000)
        if stop.kind != "breakpoint" or not stop.psw.endswith("001298"):
            fail("D24A CE load loop, force %s: %s %s" % (force, stop.kind, stop.psw))
        regs = m.registers().gr
        ticks = (int(regs[6], 16) >> 8) - (int(regs[7], 16) >> 8)
        if (any([m.read(base + 36 + 32 * cvg, 1) != tas for cvg in range(24)]) or
            regs[3] != "0F0F0F0F" or regs[5] != "0F0F0F0F" or ticks < low or ticks > high):
            fail("D24A CE load loop, force %s: %d ticks, expected %d–%d and TAS %s" %
                 (force, ticks, low, high, binary.hex(tas)))
        timings.append(ticks)
        m.clear_breaks()
    print("9020E D24A routine 8 load loop took %d ticks idle and %d ticks with 24 active CVGs (FAA window 2940–3060)." % tuple(timings))


def check_9020_ioce_defeat_interleave():
    for control, offset, target, connected in [("80", 0, 0, True), ("40", 8, 0, True),
                                                ("80", 0, 0x80000, True), ("80", 0, 0x80000, False)]:
        m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, mips = 1, interval_timer = False)
        reel = binary.builder(capacity = 24)
        reel.append(d405f_scratch_record("0102030405060708090a0b0c0d0e0f10"))
        m.tape(0x130, reel.file(), type = "2401", format = "simh")
        m.alter(0, binary.decode("0000000000000ffa", "hex"))
        m.alter(0xffa, binary.decode("0d8901cd", "hex"))  # SATR 8,9 and SCON 12,13.
        m.alter(0xffe, binary.decode("0142", "hex"))
        m.alter(0x600, binary.decode("0001080000008000", "hex"))
        m.alter(0x1000, binary.decode("83" + control + "0600", "hex"))
        m.alter(0x1004 + offset, binary.decode("9c000130", "hex"))  # SIO 130
        m.alter(0x21000 + offset, binary.decode("07f7", "hex"))  # BR 7 to TIO
        m.alter(0x1100 + offset, binary.decode("9d00013047401120", "hex"))  # TIO, BC 4
        m.alter(0x21100 + offset, binary.decode("47f01100", "hex"))  # B 1100
        m.alter(0x20040 + offset, binary.decode("00003008", "hex"))  # CAW
        # For SE2, logical slot 4 maps to physical slot 2. The control
        # where SE2 has no CE1 connection still leaves its IOCE attached.
        buffer = 0x184004 if target else 0x4004
        m.alter(0x23000 + offset, binary.decode(format0_ccw("02", buffer, "00", 16), "hex"))
        m.restart(storage_element = 1)
        m.alter_register(1, 0x1000)
        m.alter_register(2, 0x00000800)
        m.alter_register(4, 0x20c00804)
        m.alter_register(7, 0x1100)
        m.alter_register(8, 0x10020000)
        m.alter_register(9, 0x84)
        m.alter_register(12, 0x20000804 if connected else 0x20000004)
        m.alter_register(13, 0x00400000)
        m.break_at(0x1120)
        stop = m.run(instructions = 80000)
        csw = binary.hex(m.read(0x40 + offset, 8))
        if stop.kind != "breakpoint" or csw != "000030100c000000":
            fail("9020 IOCE DIAG I2 %s in SE at %x: %s %s CSW %s" % (control, target, stop.kind, stop.psw, csw))
        if connected:
            ranges = [(target + 0x4004 + offset, "01020304"), (target + 0x24000 + offset, "05060708090a0b0c"),
                      (target + 0x4010 + offset, "0d0e0f10")]
        else:
            ranges = [(target + 0x4004, "0102030405060708090a0b0c0d0e0f10")]
        for address, wanted in ranges:
            if binary.hex(m.read(address, len(wanted) // 2)) != wanted:
                fail("9020 IOCE DIAG I2 %s did not transfer via the expected SE mapping to %x" % (control, address))
        if target:
            continue
        # Reverse tape motion reads the same buffer from its high end.
        for address, wanted in ranges:
            m.alter(address, b"\xff" * (len(wanted) // 2))
        m.alter(0x23000 + offset, binary.decode(format0_ccw("0c", buffer + 15, "00", 16), "hex"))
        m.alter(0x1120 + offset, binary.decode("9c00013007f7", "hex"))
        m.clear_breaks()
        m.run(instructions = 1)
        m.break_at(0x1120)
        stop = m.run(instructions = 80000)
        if stop.kind != "breakpoint" or m.tape_position(0x130).position != 0:
            fail("9020 IOCE DIAG I2 %s did not finish the backward tape read" % control)
        for address, wanted in ranges:
            if binary.hex(m.read(address, len(wanted) // 2)) != wanted:
                fail("9020 IOCE DIAG I2 %s put backward-read bytes in the wrong banks at %x" % (control, address))
    print("9020 IOCE used both SE bank maps for CAW, CCW, CSW and forward and backward tape reads, including SATR remapping and SCON isolation.")


def check_9020_diag_timer():
    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, mips = 1, idle_skip = False)
    m.alter(0, binary.decode("0000000000001000", "hex"))
    m.alter(0x50, binary.decode("00010000", "hex"))
    m.alter(0x600, binary.decode("00010800000080000001000000008000", "hex"))
    m.alter(0x1000, binary.decode("8300060007f207f3", "hex"))
    m.restart(storage_element = 1)
    m.alter_register(2, 0x1004)
    m.alter_register(3, 0x1008)
    m.break_at(0x1004)
    if m.run(instructions = 2).kind != "breakpoint":
        fail("9020 DIAG did not reach the timer-inhibited loop")
    inhibited = m.checkpoint()
    before = int(binary.hex(m.read(0x50, 4)), 16)
    m.clear_breaks()
    m.run(instructions = 1024)
    if int(binary.hex(m.read(0x50, 4)), 16) != before:
        fail("9020 interval timer ran while inhibited")
    m.restore(inhibited)
    m.run(instructions = 1024)
    if int(binary.hex(m.read(0x50, 4)), 16) != before:
        fail("9020 checkpoint dropped the interval timer inhibit")
    m.alter(0x1004, binary.decode("8300060807f3", "hex"))
    m.run(instructions = 1024)
    m.run(instructions = 1)  # Service the interval timer at the next batch boundary.
    ticks = before - int(binary.hex(m.read(0x50, 4)), 16)
    if ticks < 76 or ticks > 79:
        fail("9020 resumed interval timer counted %d ticks for 1024 microseconds" % ticks)
    print("9020 DIAG inhibited and resumed the interval timer without counting the stopped time.")


def check_9020_count_logout():
    # The FAA startup reads byte 137, byte 167 and word 49 at MCKDI.
    # The same assembler instructions run with the panel moving PSA
    # words between physical banks once the CE enters State Zero.
    for switch, bank, mc_bit, next_instr, no_rev, rev in [
        ("PROC", 0, "00", 0x1408, 0, 0),
        ("NO REV", 0, "04", 0x21400, 0x10, 0),
        ("REV", 8, "00", 0x21408, 0, 0x80),
    ]:
        m = emulator.s390(architecture = "s360", model = "9020e", display_elements = 1, interval_timer = False)
        m.alter(0, binary.decode("00" + mc_bit + "000000000ffe", "hex"))
        m.alter(0xffe, binary.decode("0142", "hex"))  # SCON CE 1 to State Zero.
        m.alter(0x600 + bank, binary.decode("0201080100008000", "hex"))  # D22A4500 M6MCW.
        m.alter(0x70 + bank, binary.decode("0000000000001400", "hex"))
        m.alter(0x1000 + bank, binary.decode("8300060041500001", "hex"))  # DIAG, then LA 5,1.
        m.alter(0x1400 + bank, binary.decode("43600089437000a7", "hex"))  # IC 6,137 and IC 7,167.
        m.alter(next_instr, binary.decode("588000c4", "hex"))  # L 8,196.
        m.interleave_switch(switch)
        m.restart(storage_element = 1)
        m.alter_register(2, 0x00000800)
        m.alter_register(4, 0x20840800)
        m.break_at(0x1004)
        phase = m.run(instructions = 15)
        if phase.kind != "breakpoint":
            fail("9020E LOG ON COUNT failed to arm in %s: %s %s" % (switch, phase.kind, phase.psw))
        armed = m.checkpoint()
        m.interleave_switch("PROC")
        m.restore(armed)
        m.clear_breaks()
        m.break_at(0x140c)
        stop = m.run(instructions = 128)
        old = binary.hex(m.read(0x30 + bank, 8))
        gr = m.registers().gr
        if (stop.kind != "breakpoint" or gr[5] != "00000000" or old != "00" + mc_bit + "000000001004" or
            int(gr[6], 16) != no_rev or int(gr[7], 16) != rev or gr[8] != "20840800"):
            fail("9020E LOG ON COUNT in %s: %s %s, old PSW %s and GR5–8 %s" % (switch, stop.kind, stop.psw, old, gr[5:9]))

    # The timer also completes with the CE in a disabled wait. The
    # old PSW must show the LPSW committed while the count was running.
    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, mips = 5, interval_timer = False)
    m.alter(0, binary.decode("0000000000000ffe", "hex"))
    m.alter(0xffe, binary.decode("0142", "hex"))
    m.alter(0x600, binary.decode("0201081000008000", "hex"))
    m.alter(0x620, binary.decode("0002000000001100", "hex"))
    m.alter(0x70, binary.decode("0000000000001400", "hex"))
    m.alter(0x1000, binary.decode("8300060082000620", "hex"))
    m.alter(0x1400, binary.decode("0700", "hex"))
    m.restart(storage_element = 1)
    m.alter_register(2, 0x00000800)
    m.alter_register(4, 0x20800800)
    ready = m.checkpoint()
    m.break_at(0x1402)
    stop = m.run(instructions = 128)
    if stop.kind != "breakpoint" or binary.hex(m.read(0x30, 8)) != "0002000000001100":
        fail("9020 counted logout did not interrupt a disabled wait: %s %s" % (stop.kind, stop.psw))

    # The high five counter bits carry through the cycle counter. At
    # one nominal instruction per machine cycle this two-instruction
    # loop increments approximately 512 times in 1024 cycles.
    m.restore(ready)
    m.clear_breaks()
    m.alter(0x600, binary.decode("02010c0000008000", "hex"))  # 1024 cycles
    m.alter(0x1000, binary.decode("830006004150500107f7", "hex"))
    m.alter_register(7, 0x1004)
    m.break_at(0x1402)
    stop = m.run(instructions = 4096)
    iterations = int(m.registers().gr[5], 16)
    if stop.kind != "breakpoint" or iterations < 511 or iterations > 513:
        fail("9020 1024-cycle logout: %s after %d loop iterations" % (stop.kind, iterations))
    print("9020 LOG ON COUNT verified all panel positions, saved the next PSW, survived checkpoint, and expired in a wait and a 1024-cycle run.")


def check_9020_mark_parity():
    for module, address, logout_bank, mcw in [(2, 0x80100, 0, "00fd080020008000"),
                                              (6, 0x280108, 16, "00fd080060008000")]:
        m = emulator.s390(architecture = "s360", model = "9020e", display_elements = 1, memory = 1 << 20, interval_timer = False)
        m.alter(0, binary.decode("0004000000000ffe", "hex"))
        m.alter(0xffe, binary.decode("0142", "hex"))
        m.alter(0x68, binary.decode("0002000000001500", "hex"))
        m.alter(0x70, binary.decode("0000000000001100", "hex"))
        m.alter(0x600, binary.decode("10010800000080000001080000008000" + mcw, "hex"))
        m.alter(0x1000, binary.decode("830006004490300041500001", "hex"))  # DIAG MCW4, EX 9,MVC, LA 5,1.
        m.alter(0x1100, binary.decode("50a00280830006088300061007f6", "hex"))  # Handler store, normal marks, FD0, retry.
        m.alter(0x1200, binary.decode("d20010002000", "hex"))
        m.alter(0x4000, b"\xff" * 8)
        m.alter(address, b"\xf0" * 8)
        m.restart(storage_element = 1)
        m.alter_register(2, 0x00000800)
        m.alter_register(4, 0x20c40800)
        m.break_at(0x1000)
        if m.run(instructions = 4).kind != "breakpoint":
            fail("9020E mark parity could not select State Zero")
        m.alter_register(1, address + 4)
        m.alter_register(2, 0x4000)
        m.alter_register(3, 0x1200)
        m.alter_register(6, 0x1004)
        m.alter_register(9, 3)
        m.alter_register(10, 0x12345678)
        m.clear_breaks()
        m.break_program(6)
        m.break_at(0x1004)
        phase = m.run(instructions = 3)
        if phase.kind != "breakpoint":
            fail("9020E MCW4 failed to reverse mark parity: %s %s" % (phase.kind, phase.psw))
        armed = m.checkpoint()
        m.restore(armed)
        m.clear_breaks()
        m.break_at(0x110c)
        stop = m.run(instructions = 16)
        check = binary.hex(m.read(168, 2))
        bank = 0x618 + logout_bank
        if (stop.kind != "breakpoint" or m.read(address, 8) != b"\xf0" * 8 or
            m.registers().gr[5] != "00000000" or check != "%x012" % module or
            binary.hex(m.read(0x280, 4)) != "12345678" or
            binary.hex(m.read(0x30, 8)) != "0004000000001008" or
            m.read(bank, 9) != binary.decode("f0f0f0f0f0f0f0f00f", "hex")):
            fail("9020E mark parity for module %d: %s %s CE check %s logout %s" %
                 (module, stop.kind, stop.psw, check, binary.hex(m.read(bank, 24))))
        if module == 6:
            if int(binary.hex(m.read(bank + 12, 1)), 16) & 0xa2 != 0x22:
                fail("DE logout missed the bad mark parity or store operation")
        elif int(binary.hex(m.read(bank + 19, 1)), 16) & 8 or not int(binary.hex(m.read(bank + 20, 1)), 16) & 0x80:
            fail("SE logout missed the inverted mark parity or the mark check")
        m.clear_breaks()
        m.break_at(0x1008)
        stop = m.run(instructions = 4)
        if stop.kind != "breakpoint" or binary.hex(m.read(address, 8)) != "f0f0f0f0ffffffff":
            fail("9020E MVC did not recover after clearing MCW4 and collecting FD0")
    print("9020 MCW4 cancelled the FAA-style EX/MVC in the SE and DE, logged the inverted marks and preserved data until a successful retry.")


def check_9020_scan_address_parity():
    # D22A4500 routine 2 stages MCW3 and a B13 scan frame. Deliberately
    # place invalid instructions where STD and LR would be fetched from
    # storage so the no-fault run also verifies both scanned instructions.
    for module, address, offset in [(2, 0x80100, 0), (6, 0x280108, 16)]:
        m = emulator.s390(architecture = "s360", model = "9020e", display_elements = 1, memory = 1 << 20, interval_timer = False)
        m.alter(0, binary.decode("0004000000000ffe", "hex"))
        m.alter(0xffe, binary.decode("0142", "hex"))
        m.alter(0x68, binary.decode("0002000000001500", "hex"))
        m.alter(0x70, binary.decode("0000000000001100", "hex"))
        m.alter(0x600, binary.decode("006b08000000800000fd0800%x0008000" % module, "hex"))
        m.alter(0x1000, binary.decode("6840300047f01008", "hex"))  # LD 4,0(3); B 8(1).
        m.alter(0x1100, binary.decode("50a0028083000608", "hex"))  # ST 10,640; FD0.
        m.alter(0x4000, binary.decode("1122334455667788", "hex"))
        m.alter(address, binary.decode("f0f0f0f0f0f0f0f083000600070000000000000000000000", "hex"))
        m.restart(storage_element = 1)
        m.alter_register(2, 0x00000800)
        m.alter_register(4, 0x20c40800)
        m.break_at(0x1000)
        if m.run(instructions = 4).kind != "breakpoint":
            fail("9020E scan could not select State Zero")
        m.alter_register(1, address)
        m.alter_register(3, 0x4000)
        m.alter_register(10, 0x12345678)
        ready = m.checkpoint()
        for mcw_byte, parity in [("00", 0), ("06", 1), ("0a", 2), ("0e", 3)]:
            m.restore(ready)
            m.clear_breaks()
            frame = (mcw_byte + ("010808" if parity else "010800") + "00000000" +
                     "0000000002b13808" + "0000189147f00000" + "00000000f0000000" +
                     "00008000d0800000" + "1000000070000000" +
                     "000400001f" + ("000000%x" % (address + 30))[-6:] + "8300604100000000")
            m.alter(0x80, binary.decode(frame, "hex"))
            m.break_at(address + 14)
            m.break_program(6)
            phase = m.run(instructions = 12)
            if phase.kind != "breakpoint":
                fail("9020E MCW3 did not enter scanned STD: %s %s" % (phase.kind, phase.psw))
            prefetched = m.checkpoint()
            m.restore(prefetched)
            m.clear_breaks()
            m.break_at(0x1108 if parity else address + 20)
            stop = m.run(instructions = 16)
            gr9 = int(m.registers().gr[9], 16)
            word = binary.hex(m.read(address, 8))
            if stop.kind != "breakpoint":
                fail("9020E scan module %d parity %d: %s %s" % (module, parity, stop.kind, stop.psw))
            if not parity:
                if word != "1122334455667788" or gr9 != address:
                    fail("9020E scanned STD and LR did not execute: word %s GR9 %x" % (word, gr9))
                continue
            old = binary.hex(m.read(0x30, 8))
            check = binary.hex(m.read(168, 2))
            bank = 0x610 + offset
            log = binary.hex(m.read(bank, 24))
            if (word != "f0f0f0f0f0f0f0f0" or gr9 or old != "000400000f" + ("000000%x" % (address + 18))[-6:] or
                binary.hex(m.read(0x280, 4)) != "12345678" or check != "%x012" % module or
                not log.startswith(word + "ff")):
                fail("9020E cancelled scanned store: module %d parity %d old %s CE %s GR9 %x FD0 %s" %
                     (module, parity, old, check, gr9, log))
            pa, pb = parity >> 1, parity & 1
            if module == 6:
                if int(log[20:24], 16) != (0x8010 ^ (pa << 15) ^ (pb << 7)) or int(log[24:26], 16) & 0x24 != 0x24:
                    fail("9020E DE address check or flipped parity is missing from FD0: %s" % log)
            else:
                checks = int(log[40:42], 16) & 0x50
                sp_parity = int(binary.hex(m.read(0x610 + 44, 1)), 16) & 0x02
                if int(log[38:40], 16) & 3 != 2 ^ parity or checks != 0x40 | (pa << 4) or sp_parity != (1 ^ pa) << 1:
                    fail("9020E SE address/SP check or flipped parity is missing from FD0: %s" % log)
    print("9020 MCW3 resumed scanned STD and LR, cancelled the store on PA, PB or both in SE2 and DE6, and reported each fault through CE logout and FD0.")


def check_9020_sum_parity():
    # D22A4500 routines 1 and 4 write with MCW2, then use MCW1 to restore
    # normal outgoing parity before the storage check on the readback.
    for model, displays, module, address in [("9020", 0, 2, 0x80800), ("9020e", 1, 2, 0x80800), ("9020e", 1, 6, 0x280800)]:
        m = emulator.s390(architecture = "s360", model = model, display_elements = displays, memory = 1 << 20, interval_timer = False)
        m.alter(0, binary.decode("0000000000000ffe", "hex"))
        m.alter(0xffe, binary.decode("0142", "hex"))  # SCON CE 1 to State Zero.
        m.alter(0x68, binary.decode("0002000000001500", "hex"))
        m.alter(0x70, binary.decode("0000000000001100", "hex"))
        m.alter(0x608, binary.decode("000108000000800000fd0800%x0008000" % module, "hex"))
        m.alter(0x1100, binary.decode("50a0028083000610", "hex"))  # ST 10,640; FD0.
        m.restart(storage_element = 1)
        m.alter_register(2, 0x800)
        m.alter_register(4, 0x20c40800)
        m.break_at(0x1000)
        if m.run(instructions = 4).kind != "breakpoint":
            fail("%s MCW2 could not select State Zero" % model)
        m.alter_register(5, 0xa6)
        m.alter_register(10, 0x12345678)
        ready = m.checkpoint()
        for index in range(16):
            lane, odd = index & 7, index >= 8
            m.restore(ready)
            m.clear_breaks()
            target = address + (8 if odd else 0)
            m.alter_register(1, target)
            m.alter_register(2, lane)
            m.alter(0x600, binary.decode("2001080000008000", "hex"))
            m.alter(0x680, binary.decode("0004000000001010", "hex"))
            # DIAG MCW2; STC 5,0(2,1); DIAG MCW1; LPSW; LD then STD.
            m.alter(0x1000, binary.decode("830006004252100083000608820006806840100060400288", "hex"))
            # Recover by storing the same data under good parity and retrying LD.
            m.alter(0x1108, binary.decode("4252100082000680", "hex"))
            m.break_program(6)
            m.break_at(0x1004)
            armed = m.run(instructions = 3)
            if armed.kind != "breakpoint":
                fail("%s MCW2 failed to arm: %s %s" % (model, armed.kind, armed.psw))
            m.restore(m.checkpoint())
            m.clear_breaks()
            m.break_at(0x1108)
            stop = m.run(instructions = 16)
            expected = binary.decode("00" * lane + "a6" + "00" * (7 - lane), "hex")
            log = m.read(0x618, 48)
            offset = (16 if module == 6 else 24) if odd else 0
            parity = 0xff ^ (0x80 >> lane)
            parity_offset, flag_offset, flag = (9, 12, 8) if module == 6 else (23, 20, 0x20)
            if (stop.kind != "breakpoint" or binary.hex(m.read(0x30, 8)) != "0004000000001014" or
                binary.hex(m.read(168, 2)) != "%x00a" % module or binary.hex(m.read(0x280, 4)) != "12345678" or
                m.read(target, 8) != expected or log[offset:offset + 8] != expected or
                log[offset + parity_offset:offset + parity_offset + 1] != bytes([parity]) or
                not int(binary.hex(log[offset + flag_offset:offset + flag_offset + 1]), 16) & flag):
                fail("%s SE/DE %d bank %d data lane %d: %s %s, CE %s, FD0 %s" %
                     (model, module, int(odd), lane, stop.kind, stop.psw, binary.hex(m.read(168, 2)), binary.hex(log)))
            m.clear_breaks()
            m.break_at(0x1018)
            recovery = m.run(instructions = 8)
            if recovery.kind != "breakpoint" or m.read(0x288, 8) != expected:
                fail("%s SE/DE %d data lane %d remained bad after a clean store" % (model, module, lane))

        for inject in [False, True]:
            m.restore(ready)
            m.clear_breaks()
            m.alter_register(1, address)
            m.alter_register(4, 0x48)
            m.alter_register(5, 0x55)
            m.alter(0x600, binary.decode(("20" if inject else "00") + "01080000008000", "hex"))
            m.alter(0x680, binary.decode("000400000000100e", "hex"))
            # DIAG, SSK, normal DIAG, LPSW, ISK.
            m.alter(0x1000, binary.decode("830006000841830006088200068009510700", "hex"))
            m.alter(0x1108, binary.decode("82000680", "hex"))
            m.break_program(6)
            m.break_at(0x1006)
            written = m.run(instructions = 5)
            if written.kind != "breakpoint":
                fail("%s SE/DE %d could not write key: %s %s" % (model, module, written.kind, written.psw))
            m.restore(m.checkpoint())
            m.clear_breaks()
            if not inject:
                m.break_at(0x1010)
                if m.run(instructions = 8).kind != "breakpoint" or m.registers().gr[5] != "00000048":
                    fail("%s SE/DE %d clean key control failed" % (model, module))
                continue
            for old, operation in [("100e", "SSK"), ("1010", "ISK")]:
                m.break_at(0x1108)
                stop = m.run(instructions = 12)
                log = m.read(0x618, 48)
                if (stop.kind != "breakpoint" or binary.hex(m.read(0x30, 8)) != "000400000000" + old or
                    binary.hex(m.read(168, 2)) != ("%x010" % module if module == 6 and operation == "SSK" else "%x012" % module) or
                    m.registers().gr[5] != "00000055"):
                    fail("%s SE/DE %d %s: %s %s, old %s CE %s FD0 %s" %
                         (model, module, operation, stop.kind, stop.psw, binary.hex(m.read(0x30, 8)),
                          binary.hex(m.read(168, 2)), binary.hex(log)))
                if module == 6:
                    parity_ok = log[13:14] == b"\x09" if operation == "SSK" else log[14:15] == b"\x26"
                    check = log[15:16] == b"\x40"
                else:
                    parity_ok = log[40:41] == b"\x24" if operation == "SSK" else log[41:42] == b"\x24"
                    check = int(binary.hex(log[20:21]), 16) & 0x10
                if not parity_ok or not check:
                    fail("%s SE/DE %d %s did not report the inverted key parity: %s" %
                         (model, module, operation, binary.hex(log)))
            m.alter(0x1108, binary.decode("084182000680", "hex"))  # SSK with normal parity; retry ISK.
            m.clear_breaks()
            m.break_at(0x1010)
            if m.run(instructions = 8).kind != "breakpoint" or m.registers().gr[5] != "00000048":
                fail("%s SE/DE %d key remained bad after a clean SSK" % (model, module))
    print("9020 MCW2 verified all eight data lanes in both banks and the FAA SSK/ISK sequence, including recovery, on 9020D SE2 and 9020E SE2 and DE6.")


def check_mdm_storage_data_check(tape, ioce = False):
    m = faa_mdm(tape)
    m.console(2, type = "1052")
    if ioce:
        reel = binary.builder(capacity = 12)
        reel.append(d405f_scratch_record("11223344"))
        m.tape(0x530, reel.file(), type = "2401", format = "simh")
    if m.run(instructions = 35000000).psw != SDM_READY:
        fail("FAA MDM did not reach the operator wait")
    m.key(2, "REQUEST")
    wait_1052_read(m, device = 2)
    m.break_at(0x14288)
    m.type(2, "A32/L1101/B/")
    stop = m.run(instructions = 15000000)
    if stop.kind != "breakpoint" or stop.psw != "01040000 00014288":
        fail("MDM did not reach the first D11011 routine: %s %s" % (stop.kind, stop.psw))

    # Temporarily assign SE2 and fetch from it with L or with the initial CCW of SIO.
    # The normal MDM assignment for this job maps only SE1.
    original, faulting = "4580F0E047F0", "0D569C000530" if ioce else "0D5658007000"
    faa_correction(m, 0x14288, original, faulting)
    saved_registers = m.registers().gr[5:8]
    m.alter_register(5, 0x12000000)
    m.alter_register(6, 0x82 if ioce else 0x80)
    if ioce:
        saved_caw = m.read(0x48, 4)
        m.alter(0x48, binary.decode("00080100", "hex"))
        m.alter(0x80100, binary.decode("0200200020000004", "hex"))
        m.set_storage_data_parity(0x80101, bad = True)
    else:
        m.alter_register(7, 0x80080)
        m.alter(0x80080, binary.decode("0123456789abcdef", "hex"))
        m.set_storage_data_parity(0x80087, bad = True)
    m.clear_breaks()
    if m.run(instructions = 1).psw != "01040000 0001428A":
        fail("D11011 did not assign SE2 for the faulting access")
    raised = m.run(instructions = 1)
    faa_correction(m, 0x14288, faulting, original)
    for reg, value in enumerate(saved_registers, 5):
        m.alter_register(reg, int(value, 16))
    if ioce:
        m.alter(0x48, saved_caw)
        m.break_program(0x80)
        check = m.run(instructions = 1000)
        if (raised.psw != "01040000 3001428E" or check.kind != "program" or check.detail != "program 0080 at 000008A8" or
            binary.hex(m.read(0x30, 8)) != "010400023001428e" or binary.hex(m.read(352, 6)) != "400000000200" or
            m.read(362, 1) != b"\x16" or
            m.registers().gr[1] != "00000002" or m.tape_position(0x530).position != 0):
            fail("MDM did not identify the SE2 stopped by IOCE 2: %s %s %s" % (check.kind, check.psw, check.detail))
        m.clear_breaks()
    elif (raised.psw != "00000000 0F000844" or binary.hex(m.read(0x30, 8)) != "010400000001428e" or
        binary.hex(m.read(168, 2)) != "200a"):
        fail("MDM native CE data check: %s %s" % (raised.kind, raised.psw))

    m.break_program(1)
    done = m.run(instructions = 170000000 if ioce else 150000000)
    console = [line.strip() for line in m.screens(2)]
    printer = [line.strip() for line in m.output(0x00e)]
    logout = int(binary.hex(m.read(504, 4)), 16)
    element = "IOCE 2" if ioce else "CE 1"
    data = "020020002000000400100100860002fc0010081a20000216" if ioce else "0123456789abcdef00100080840080fc0010080a20000301"
    expected = data + "00" * 24
    reports = [element + " LOGOUT", "END OF LOGOUTS", "SE 2 LOGOUT", "END OF LOGOUTS"] if ioce else [element + " LOGOUT", "SE 2 LOGOUT", "END OF LOGOUTS"]
    completion = ["SEEAP JOB COMPLETE", "SECTION ABORTED D11011", "EOJ  MDM JOB COMPLETE"]
    announcement = [line for line in console if "MCK INT" in line]
    old_psw = "01040002 3001428E" if ioce else "01040000 0001428E"
    headings = [line for line in printer if line.endswith(" LOGOUT") or line == "END OF LOGOUTS"]
    if (done.kind not in ["budget", "wait"] or
        announcement != ["**CE 1 MCK INT " + old_psw] or headings != reports or
        logout != 0xa90 or binary.hex(m.read(logout, 48)) != expected or
        [line for line in console if line in completion] != completion):
        fail("MDM storage recovery: %s %s %s announcement=%s printer=%s pointer=%x console=%s" %
             (done.kind, done.psw, done.detail, announcement, headings, logout, console[-12:]))

    m.clear_breaks()
    m.key(2, "REQUEST")
    wait_1052_read(m, device = 2)
    m.type(2, "A32/L1101/B/")
    clean = m.run(instructions = 20000000)
    repeat = [line.strip() for line in m.screens(2)[len(console):]]
    if (clean.kind not in ["budget", "wait"] or
        repeat != ["A32/L1101/B/", "START   D11011", "T CE1  078      D11011", "EOJ  MDM JOB COMPLETE"]):
        fail("MDM D11011 rerun after storage recovery: %s %s %s" % (clean.kind, clean.psw, repeat))
    print("MDM printed the %s and live SE2 logouts, finished SEEAP, aborted the faulting section, and completed all 78 D11011 routines on a clean rerun" % element)


def check_storage_ioce_data_check():
    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
    reel = binary.builder(capacity = 12)
    reel.append(d405f_scratch_record("11223344"))
    m.tape(0x530, reel.file(), type = "2401", format = "simh")
    m.alter(0, binary.decode("0404000000001000", "hex"))
    m.alter(0x48, binary.decode("00080100", "hex"))
    m.alter(0x68, binary.decode("0000000000001140", "hex"))
    m.alter(0x70, binary.decode("0000000000001100", "hex"))
    m.alter(0x78, binary.decode("0002000000001200", "hex"))
    m.alter(0x240, binary.decode("0406000000001008", "hex"))
    m.alter(0x1000, binary.decode("9c00053082000240", "hex"))
    m.alter(0x1100, binary.decode("58201000", "hex"))  # The CE probes the stopped SE.
    m.alter(0x1140, binary.decode("830002804200100107f4", "hex"))  # FD0, repair CCW byte, retry SIO.
    m.alter(0x280, binary.decode("00fd080020008000", "hex"))
    m.alter(0x80100, binary.decode("0200200020000004", "hex"))
    m.restart(storage_element = 1)
    m.alter_register(1, 0x80100)
    m.alter_register(4, 0x1000)
    initial = m.checkpoint()
    healthy = m.run(instructions = 1000000)
    if (healthy.kind != "disabled-wait" or healthy.psw != "00020000 00001200" or
        m.read(0x2000, 4) != b"\x11\x22\x33\x44" or m.tape_position(0x530).position != 1):
        fail("IOCE 2 healthy CCW: %s %s %s" % (healthy.kind, healthy.psw, binary.hex(m.read(0x40, 8))))

    expected = "020020002000000400100100820002fc0010081a20000316" + "00" * 24
    for masked in [False, True]:
        m.restore(initial)
        if masked:
            m.alter(0, binary.decode("0400000000001000", "hex"))
            m.restart(storage_element = 1)
            m.alter_register(1, 0x80100)
            m.alter_register(4, 0x1000)
        m.set_storage_data_parity(0x80101, bad = True)
        if masked:
            paused = m.run(instructions = 1)
            if not paused.psw.endswith("001004") or m.read(0x30, 8) != b"\x00" * 8:
                fail("masked IOCE check interrupted the CE: %s %s" % (paused.kind, paused.psw))
            pending = m.checkpoint()
            m.restore(initial)
            m.restore(pending)
        m.break_program(0x80)
        stopped = m.run(instructions = 20)
        old = "0406000200001008" if masked else "0404000230001004"
        if (stopped.kind != "program" or stopped.psw != "00000000 00001140" or
            binary.hex(m.read(0x30, 8)) != old or binary.hex(m.read(352, 6)) != "400000000200" or
            m.read(362, 1) != b"\x16" or
            m.read(0x2000, 4) != b"\x00" * 4 or m.tape_position(0x530).position != 0):
            fail("IOCE 2 CCW fault: %s %s %s" % (stopped.kind, stopped.psw, binary.hex(m.read(0x30, 8))))
        m.clear_breaks()
        m.break_at(0x1144)
        capture = m.run(instructions = 1)
        if capture.kind != "breakpoint" or binary.hex(m.read(0x288, 48)) != expected:
            fail("IOCE 2 FD0 capture: %s %s %s" % (capture.kind, capture.psw, binary.hex(m.read(0x288, 48))))
        m.clear_breaks()
        retried = m.run(instructions = 1000000)
        if (retried.kind != "disabled-wait" or retried.psw != "00020000 00001200" or
            m.read(0x2000, 4) != b"\x11\x22\x33\x44" or m.tape_position(0x530).position != 1):
            fail("IOCE 2 retry after FD0: %s %s" % (retried.kind, retried.psw))
    print("IOCE 2 detected bad CCW parity, stopped SE2, and left the tape untouched until the CE collected FD0, repaired the CCW, and retried SIO")


def check_storage_ioce_key_parity():
    for model in ["9020", "9020e"]:
        for operation, address, ccw in [
            ("CCW fetch", 0x80100, "0200200020000004"),
            ("payload store", 0x80800, "0208080020000004"),
            ("payload fetch", 0x80800, "0108080020000004"),
        ]:
            m = emulator.s390(architecture = "s360", model = model, memory = 1 << 20, interval_timer = False, mips = 1)
            records = [d405f_scratch_record("11223344"), d405f_scratch_record("55667788")]
            reel = binary.builder()
            for record in records:
                reel.append(record)
            m.tape(0x530, reel.file(), type = "2401", format = "simh", ring = True)
            if operation == "payload fetch":
                fresh = binary.builder()
                for record in records:
                    fresh.append(record)
                m.tape(0x531, fresh.file(), type = "2401", format = "simh", ring = True)
            target = 0x2000 if operation == "CCW fetch" else 0x80800
            for addr, data in [
                (0, "0404000000000ffe"),
                (0x48, "50080100"),
                (0x68, "0002000000001180"),
                (0x70, "0000000000001100"),
                (0x78, "0002000000001200"),
                (0x240, "0404000000001006"),
                (0x250, "040600000000100e"),
                (0x280, "00fd080020008000"),
                (0x600, "2001080000008000"),
                (0xffe, "01428300060008419c00053082000250"),
                (0x1100, "8300028082000240"),  # Release SE2 without rewriting its key.
                (0x1140, "83000280084107f5"),  # Capture FD0, repair with SSK, retry SIO.
                (0x80100, ccw),
                (target, "41424344"),
            ]:
                m.alter(addr, binary.decode(data, "hex"))
            m.restart(storage_element = 1)
            m.alter_register(2, 0x800)
            m.alter_register(4, 0x20c40806)
            m.break_at(0x1000)
            if m.run(instructions = 4).kind != "breakpoint":
                fail("%s %s could not select CE1 State Zero" % (model, operation))
            m.clear_breaks()
            m.alter_register(1, address)
            m.alter_register(4, 0x58)  # Match the CAW key, including fetch protection.
            m.alter_register(5, 0x1006)
            ready = m.checkpoint()

            m.alter(0x600, binary.decode("0001080000008000", "hex"))
            clean = m.run(instructions = 1000000)
            expected_data = "41424344" if operation == "payload fetch" else "11223344"
            expected_record = "41424344" if operation == "payload fetch" else "11223344"
            if (clean.kind != "disabled-wait" or clean.psw != "00020000 00001200" or
                binary.hex(m.read(0x40, 8)) != "500801080c000000" or
                binary.hex(m.read(target, 4)) != expected_data or
                binary.hex(m.tape_record(0x530, index = 0)) != expected_record):
                fail("%s %s clean key control: %s %s CSW %s" %
                     (model, operation, clean.kind, clean.psw, binary.hex(m.read(0x40, 8))))

            m.restore(ready)
            if operation == "payload fetch":
                # A successful write changed the backing reel shared by the checkpoint.
                m.swap_tape_reels(0x530, 0x531)
            m.break_at(0x1006)
            if m.run(instructions = 30).kind != "breakpoint" or m.read(168, 2) != b"\x20\x12":
                fail("%s %s did not inject SE2 stored-key parity" % (model, operation))
            m.clear_breaks()
            m.alter(0x70, binary.decode("0000000000001140", "hex"))
            m.break_at(0x1144)
            stop = m.run(instructions = 1000000)
            log = m.read(0x288, 48)
            store = operation == "payload store"
            if (stop.kind != "breakpoint" or stop.psw != "00000000 00001144" or
                m.read(0x32, 2) != b"\x00\x02" or binary.hex(m.read(352, 6)) != "400000000000" or
                m.read(362, 1) != b"\x14" or m.read(0x40, 8) != b"\x00" * 8 or
                log[20:21] != b"\x10" or
                int(binary.hex(log[18:20]), 16) & 0x1800 != (0x1000 if store else 0x0800) or
                log[41:42] != b"\xac" or
                m.read(target, 4) != b"ABCD" or m.tape_position(0x530).position != int(store) or
                m.tape_record(0x530, index = 0) != b"\x11\x22\x33\x44"):
                fail("%s %s IOCE key check: %s %s CE %s, IOCE %s, FD0 %s, CSW %s, target %s, tape %s %s" %
                     (model, operation, stop.kind, stop.psw, binary.hex(m.read(0x30, 8)),
                      binary.hex(m.read(352, 12)), binary.hex(log), binary.hex(m.read(0x40, 8)),
                      binary.hex(m.read(target, 4)), m.tape_position(0x530).position,
                      binary.hex(m.tape_record(0x530, index = 0))))
            m.clear_breaks()
            m.break_at(0x1146)
            if m.run(instructions = 2).kind != "breakpoint":
                fail("%s %s clean SSK failed to restore stored-key parity" % (model, operation))
            m.clear_breaks()
            if store:
                # The read lost channel service after starting tape motion.
                # Accept its independent unit status before reading the next record.
                m.alter(0x1146, binary.decode("82000258", "hex"))
                m.alter(0x258, binary.decode("0406000000001150", "hex"))
                m.alter(0x78, binary.decode("0404000000001158", "hex"))
                m.alter(0x1158, binary.decode("070007f5", "hex"))
                m.break_at(0x115a)
                device_end = m.run(instructions = 1000000)
                if device_end.kind != "breakpoint" or m.read(0x44, 2) != b"\x0e\x00":
                    fail("%s store device end: %s %s CSW %s" %
                         (model, device_end.kind, device_end.psw, binary.hex(m.read(0x40, 8))))
                m.clear_breaks()
                m.alter(0x78, binary.decode("0002000000001200", "hex"))
                expected_data = "55667788"
            retried = m.run(instructions = 1000000)
            if (retried.kind != "disabled-wait" or retried.psw != "00020000 00001200" or
                binary.hex(m.read(0x40, 8)) != "500801080c000000" or
                binary.hex(m.read(target, 4)) != expected_data or
                binary.hex(m.tape_record(0x530, index = 0)) != expected_record or
                m.tape_position(0x530).position != (2 if store else 1)):
                fail("%s %s retry after FD0 and SSK: %s %s CSW %s" %
                     (model, operation, retried.kind, retried.psw, binary.hex(m.read(0x40, 8))))
    print("9020D/E IOCE 2 reported stored-key parity during CCW fetch, payload fetch, and payload store. FD0 identified the failing cycle, and clean SSK restored access.")


def check_storage_ioce_command_chain():
    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
    reel = binary.builder(capacity = 24)
    for data in ["11223344", "55667788"]:
        reel.append(d405f_scratch_record(data))
    m.tape(0x530, reel.file(), type = "2401", format = "simh")
    m.alter(0, binary.decode("0404000000001000", "hex"))
    m.alter(0x48, binary.decode("00080100", "hex"))
    m.alter(0x70, binary.decode("0000000000001100", "hex"))
    m.alter(0x78, binary.decode("0002000000001200", "hex"))
    m.alter(0x240, binary.decode("0406000000001008", "hex"))
    m.alter(0x260, binary.decode("00080108", "hex"))
    m.alter(0x280, binary.decode("00fd080020008000", "hex"))
    m.alter(0x1000, binary.decode("9c00053082000240", "hex"))
    # FD0, repair the bad byte, select the second CCW in the CAW, and retry SIO.
    m.alter(0x1100, binary.decode("8300028042001001582002605020004807f4", "hex"))
    m.alter(0x80100, binary.decode("02002000600000040200200420000004", "hex"))
    m.restart(storage_element = 1)
    m.alter_register(1, 0x80108)
    m.alter_register(4, 0x1000)
    m.break_at(0x1004)
    started = m.run(instructions = 2)
    if started.kind != "breakpoint" or started.psw != "04040000 00001004" or m.tape_position(0x530).position != 1:
        fail("IOCE 2 did not start the first tape command: %s %s" % (started.kind, started.psw))
    m.clear_breaks()
    initial = m.checkpoint()
    good = m.run(instructions = 500000)
    data = binary.decode("1122334455667788", "hex")
    if (good.kind != "disabled-wait" or good.psw != "00020000 00001200" or m.read(0x2000, 8) != data or
        m.tape_position(0x530).position != 2 or binary.hex(m.read(0x40, 8)) != "000801100c000000"):
        fail("IOCE 2 healthy command chain: %s %s" % (good.kind, good.psw))

    m.restore(initial)
    m.set_storage_data_parity(0x80109, bad = True)
    m.break_at(0x1104)
    check = m.run(instructions = 500000)
    expected = "020020006000000400100100820002fc0010080a0000035e" + "020020042000000400100100000002008080080a22000006"
    if (check.kind != "breakpoint" or check.psw != "00000000 00001104" or m.tape_position(0x530).position != 1 or
        m.read(0x2000, 4) != data[:4] or m.read(0x2004, 4) != b"\x00" * 4 or m.read(0x40, 8) != b"\x00" * 8 or
        binary.hex(m.read(0x30, 8)) != "0406000200001008" or binary.hex(m.read(352, 6)) != "400000000200" or
        m.read(362, 1) != b"\x16" or
        binary.hex(m.read(0x288, 48)) != expected):
        fail("IOCE 2 deferred command-chain check: %s %s old PSW=%s" % (check.kind, check.psw, binary.hex(m.read(0x30, 8))))
    m.clear_breaks()
    retried = m.run(instructions = 500000)
    if (retried.kind != "disabled-wait" or retried.psw != "00020000 00001200" or m.read(0x2000, 8) != data or
        m.tape_position(0x530).position != 2 or binary.hex(m.read(0x40, 8)) != "000801100c000000"):
        fail("IOCE 2 second command retry: %s %s" % (retried.kind, retried.psw))
    print("IOCE 2 preserved the first tape read on a command-chain parity fault and read the second record after FD0 and CCW repair")


def check_storage_ioce_data_chain():
    payload = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    supplied_ccw = "0200210020000018"
    for mode in ["clean", "fault", "supplied", "short"]:
        contents = payload
        ccws = "02002000800000100200210020000010"
        if mode == "supplied":
            contents = supplied_ccw + payload[16:]
            ccws = "02080108800000080000000000000000"
        elif mode == "short":
            contents = payload[:16]
        m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
        reel = binary.builder()
        reel.append(d405f_scratch_record(contents))
        m.tape(0x530, reel.file(), type = "2401", model = 2, format = "simh")
        m.alter(0, binary.decode("0404000000001000", "hex"))
        m.alter(0x48, binary.decode("00080100", "hex"))
        m.alter(0x70, binary.decode("0000000000001100", "hex"))
        m.alter(0x78, binary.decode("0000000000001200", "hex"))
        m.alter(0x240, binary.decode("0406000000001008040200000000110c", "hex"))
        m.alter(0x280, binary.decode("00fd080020008000", "hex"))
        m.alter(0x1000, binary.decode("9c00053082000240", "hex"))
        m.alter(0x1100, binary.decode("830002804200100182000248", "hex"))  # FD0, STC, LPSW
        for addr in [0x1200, 0x1300, 0x1400]:
            m.alter(addr, binary.decode("07009c00053082000248", "hex"))
        m.alter(0x80100, binary.decode(ccws, "hex"))
        m.restart(storage_element = 1)
        m.alter_register(1, 0x80108)
        m.break_at(0x1004)
        start = m.run(instructions = 2)
        if start.kind != "breakpoint" or start.psw != "04040000 00001004":
            fail("IOCE 2 data chain %s setup: %s %s" % (mode, start.kind, start.psw))
        m.clear_breaks()
        m.break_at(0x1104)
        m.break_at(0x1202)
        if mode != "clean":
            m.set_storage_data_parity(0x80109, bad = True)
        end = m.run(instructions = 1000000)
        first = binary.hex(m.read(0x2000, 16))
        second = binary.hex(m.read(0x2100, 24))
        csw = binary.hex(m.read(0x40, 8))
        if mode != "fault":
            expected = {
                "clean": (payload[:32], payload[32:] + "00" * 8, "000801100c000000"),
                "short": (payload[:16] + "00" * 8, "00" * 24, "000801080c400008"),
                "supplied": ("00" * 16, payload[16:], "000801100c000000"),
            }
            if (end.kind != "breakpoint" or end.psw != "00000000 00001202" or
                (first, second, csw) != expected[mode] or m.read(0x30, 8) != b"\x00" * 8):
                fail("IOCE 2 data chain %s ending: %s %s CSW=%s data=%s %s" % (mode, end.kind, end.psw, csw, first, second))
            if mode == "supplied" and binary.hex(m.read(0x80108, 8)) != supplied_ccw:
                fail("The self-describing tape record did not supply the second CCW")
            continue
        logout = binary.hex(m.read(0x288, 48))
        if (end.kind != "breakpoint" or end.psw != "00000000 00001104" or
            first != payload[:32] or second != "00" * 24 or csw != "00" * 8 or
            binary.hex(m.read(0x30, 8)) != "0406000200001008" or binary.hex(m.read(352, 12)) != "400000000200000000001600" or
            logout[:16] != ccws[:16] or logout[48:64] != ccws[16:]):
            fail("IOCE 2 data-chain check: %s %s CSW=%s FD0=%s" % (end.kind, end.psw, csw, logout))
        m.clear_breaks()
        m.break_at(0x1202)
        overrun = m.run(instructions = 1000000)
        if overrun.kind != "breakpoint" or overrun.psw != "00000000 00001202" or binary.hex(m.read(0x40, 8)) != "000000000e000000":
            fail("2401 read overrun ending: %s %s" % (overrun.kind, overrun.psw))
        m.alter(0x48, binary.decode("00002040", "hex"))
        m.alter(0x78, binary.decode("0000000000001300", "hex"))
        m.alter(0x2040, binary.decode("0400220020000006", "hex"))
        m.clear_breaks()
        m.break_at(0x1302)
        sense = m.run(instructions = 1000000)
        if sense.kind != "breakpoint" or sense.psw != "00000000 00001302" or m.read(0x2200, 1) != b"\x04":
            fail("2401 read overrun Sense: %s %s" % (sense.kind, sense.psw))
        m.alter(0x48, binary.decode("00080118", "hex"))
        m.alter(0x78, binary.decode("0002000000001400", "hex"))
        m.alter(0x80118, binary.decode("27000000600000010808010000000001", "hex"))  # Backspace, TIC to the repaired chain.
        m.clear_breaks()
        retry = m.run(instructions = 1000000)
        if (retry.kind != "disabled-wait" or retry.psw != "00020000 00001400" or
            binary.hex(m.read(0x40, 8)) != "000801100c000000" or binary.hex(m.read(0x2100, 16)) != payload[32:]):
            fail("2401 data-chain retry after FD0: %s %s" % (retry.kind, retry.psw))
    print("IOCE 2 preserved the first input buffer on a data-chain parity check and recovered the record. It also used a tape-supplied CCW and skipped an unreached CCW.")


def check_storage_2314_data_chain():
    count_and_data = "060021002000001008090a0b0c0d0e0f1011121314151617"
    search = "31002200400000050808010000000001"
    for mode in ["clean", "supplied", "fault", "short"]:
        m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
        m.dasd(0x340, type = "2314", cylinders = 203, volser = "SCRTCH")
        m.alter(0, binary.decode("1004000000001000", "hex"))
        m.alter(0x48, binary.decode("00002000", "hex"))
        m.alter(0x70, binary.decode("0000000000001100", "hex"))
        m.alter(0x78, binary.decode("0000000000001200", "hex"))
        m.alter(0x240, binary.decode("1006000000001008100200000000110c", "hex"))
        m.alter(0x280, binary.decode("00fd080020008000", "hex"))
        m.alter(0x1000, binary.decode("9c00034082000240", "hex"))
        m.alter(0x1100, binary.decode("830002804200100182000248", "hex"))
        m.alter(0x1200, binary.decode("07009c00034082000240", "hex"))
        for address in [0x1300, 0x1400]:
            m.alter(address, binary.decode("07009c00034082000248", "hex"))
        # Search and replace the data in the 24-byte IPL1 record of the scratch pack.
        m.alter(0x2000, binary.decode("310022004000000508002000000000010508000000000018", "hex"))
        m.alter(0x2200, binary.decode("0000000001", "hex"))
        m.alter(0x80000, binary.decode(count_and_data, "hex"))
        m.restart(storage_element = 1)
        m.alter_register(1, 0x80118)
        m.break_at(0x1202)
        setup = m.run(instructions = 150000)
        if setup.kind != "breakpoint" or setup.psw != "00000000 00001202" or binary.hex(m.read(0x40, 8)) != "000020180c000000":
            fail("2314 data chain %s scratch record setup: %s %s" % (mode, setup.kind, setup.psw))
        first_ccw = "0600230080000008"
        next_ccw = count_and_data[:16]
        if mode == "supplied":
            first_ccw = "0608011880000008"
            next_ccw = "00" * 8
        elif mode == "short":
            first_ccw = "0600230080000020"
        m.alter(0x40, b"\x00" * 8)
        m.alter(0x48, binary.decode("00080100", "hex"))
        m.alter(0x78, binary.decode("0000000000001300", "hex"))
        m.alter(0x80100, binary.decode(search + first_ccw + next_ccw, "hex"))
        m.clear_breaks()
        m.break_at(0x1206)
        start = m.run(instructions = 2)
        if start.kind != "breakpoint" or start.psw != "00000000 00001206":
            fail("2314 data chain %s read setup: %s %s" % (mode, start.kind, start.psw))
        if mode != "clean":
            m.set_storage_data_parity(0x80119, bad = True)
        m.clear_breaks()
        m.break_at(0x1104)
        m.break_at(0x1302)
        done = m.run(instructions = 100000)
        csw = binary.hex(m.read(0x40, 8))
        first = binary.hex(m.read(0x2300, 32))
        second = binary.hex(m.read(0x2100, 16))
        if mode != "fault":
            expected = {
                "clean": (count_and_data[:16] + "00" * 24, count_and_data[16:], "000801200c000000"),
                "supplied": ("00" * 32, count_and_data[16:], "000801200c000000"),
                "short": (count_and_data + "00" * 8, "00" * 16, "000801180c400008"),
            }
            if (done.kind != "breakpoint" or done.psw != "00000000 00001302" or
                (first, second, csw) != expected[mode] or m.read(0x30, 8) != b"\x00" * 8):
                fail("2314 data chain %s ending: %s %s CSW=%s data=%s %s" % (mode, done.kind, done.psw, csw, first, second))
            if mode == "supplied" and binary.hex(m.read(0x80118, 8)) != count_and_data[:16]:
                fail("The self-describing disk record did not supply the second CCW")
            continue
        logout = binary.hex(m.read(0x288, 48))
        if (done.kind != "breakpoint" or done.psw != "00000000 00001104" or
            csw != "00" * 8 or first != count_and_data[:16] + "00" * 24 or second != "00" * 16 or
            binary.hex(m.read(0x30, 8)) != "1006000100001008" or binary.hex(m.read(352, 12)) != "400000000200000000001600" or
            logout[:16] != first_ccw or logout[48:64] != next_ccw):
            fail("2314 data-chain check: %s %s CSW=%s FD0=%s" % (done.kind, done.psw, csw, logout))
        m.clear_breaks()
        m.break_at(0x1302)
        overrun = m.run(instructions = 100000)
        if overrun.kind != "breakpoint" or overrun.psw != "00000000 00001302" or binary.hex(m.read(0x40, 8)) != "000000000e000000":
            fail("2314 read overrun ending: %s %s" % (overrun.kind, overrun.psw))
        m.alter(0x48, binary.decode("00002040", "hex"))
        m.alter(0x78, binary.decode("0000000000001400", "hex"))
        m.alter(0x2040, binary.decode("0400240020000006", "hex"))
        m.clear_breaks()
        m.break_at(0x1402)
        sense = m.run(instructions = 100000)
        if sense.kind != "breakpoint" or sense.psw != "00000000 00001402" or m.read(0x2400, 1) != b"\x04":
            fail("2314 read overrun Sense: %s %s" % (sense.kind, sense.psw))
        m.alter(0x48, binary.decode("00080100", "hex"))
        m.alter(0x78, binary.decode("0002000000001500", "hex"))
        m.clear_breaks()
        retry = m.run(instructions = 100000)
        if (retry.kind != "disabled-wait" or retry.psw != "00020000 00001500" or
            binary.hex(m.read(0x40, 8)) != "000801200c000000" or binary.hex(m.read(0x2100, 16)) != count_and_data[16:]):
            fail("2314 data-chain retry after FD0: %s %s" % (retry.kind, retry.psw))
    print("2314 data chaining used a disk-supplied CCW, skipped an unreached CCW, and recovered an IOCE parity fault without losing the first buffer.")


def check_storage_live():
    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False)
    m.alter(0, binary.decode("0000000000001000", "hex"))
    m.alter(0x280, binary.decode("00fd080020008000", "hex"))
    m.alter(0x288, b"\x5a" * 48)
    m.alter(0x1000, binary.decode("58201000583010088300028058401000", "hex"))  # L 2; L 3; DIAG X'280'; L 4.
    m.alter(0x80080, binary.decode("0123456789abcdeffedcba9876543210", "hex"))
    m.restart(storage_element = 1)
    m.alter_register(1, 0x80080)
    m.break_at(0x100c)
    captured = m.run(instructions = 5)
    # A27-2734-2 Figure 12-5, two CE fetches from SE2 at store row X'008'.
    expected = "0123456789abcdef00100080800080fc0010080a00000200" + "fedcba987654321000100080000080008080080a02000000"
    if (captured.kind != "breakpoint" or captured.psw != "00000000 0000100C" or
        m.registers().gr[2:4] != ["01234567", "FEDCBA98"] or binary.hex(m.read(0x288, 48)) != expected):
        fail("live FD0 did not capture SE2: %s %s logout=%s" % (captured.kind, captured.psw, binary.hex(m.read(0x288, 48))))
    m.clear_breaks()
    m.break_at(0x1010)
    resumed = m.run(instructions = 2)
    if resumed.kind != "breakpoint" or m.registers().gr[4] != "01234567":
        fail("SE2 did not respond after live FD0: %s %s" % (resumed.kind, resumed.psw))
    print("Live FD0 captured the even and odd SE2 register contents and released SE2 with CC0")


def check_storage_ioce():
    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
    payload = "01020304050607081020304050607080"
    reel = binary.builder()
    reel.append(binary.decode("10000000" + payload + "10000000", "hex"))
    m.tape(0x130, reel.file(), type = "3420", format = "simh")
    m.alter(0, binary.decode("4000000000001000", "hex"))
    m.alter(0x48, binary.decode("00002000", "hex"))
    m.alter(0x78, binary.decode("0000000000001200", "hex"))
    m.alter(0x180, binary.decode("4002000000001008", "hex"))
    m.alter(0x1000, binary.decode("9c00013082000180", "hex"))  # SIO 130; LPSW X'180'.
    m.alter(0x2000, binary.decode("0208008020000010", "hex"))
    m.alter(0x280, binary.decode("00fd080020008000", "hex"))
    m.alter(0x1200, binary.decode("83000280", "hex"))  # DIAG X'280' in the I/O handler.
    m.restart(storage_element = 1)
    initial = m.checkpoint()
    m.break_at(0x1204)
    captured = m.run(instructions = 500000)
    # Figure 12-5 marks the low half on the last IOCE store in each bank.
    expected = "01020304050607080f100080840004fc0010103a0000032c" + "10203040506070800f100080000004008080102a0200002c"
    if (captured.kind != "breakpoint" or captured.psw != "00000000 00001204" or
        binary.hex(m.read(0x40, 8)) != "000020080c000000" or
        binary.hex(m.read(0x80080, 16)) != payload or binary.hex(m.read(0x288, 48)) != expected):
        fail("IOCE FD0 capture at %s %s: %s" % (captured.kind, captured.psw, binary.hex(m.read(0x288, 48))))
    print("Live FD0 captured both SE2 bank stores from IOCE 1, with the low-half marks and address parity")

    # This time only the CCW is in SE2. Log it before input reaches SE1.
    m.restore(initial)
    m.clear_breaks()
    m.alter(0x48, binary.decode("00080080", "hex"))
    m.alter(0x80080, binary.decode("0200220020000010", "hex"))
    m.alter(0x1004, binary.decode("83000280", "hex"))
    m.break_at(0x1008)
    fetched = m.run(instructions = 3)
    fetch_logout = "020022002000001000100080840004fc0010083a00000376" + "00" * 24
    if (fetched.kind != "breakpoint" or fetched.psw != "40000000 00001008" or
        m.read(0x2200, 16) != b"\x00" * 16 or binary.hex(m.read(0x288, 48)) != fetch_logout):
        fail("IOCE CCW fetch capture at %s %s: %s" % (fetched.kind, fetched.psw, binary.hex(m.read(0x288, 48))))
    print("Live FD0 captured the SE2 CCW fetch from IOCE 1 before any tape data transferred")


def check_storage_channel(tape):
    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
    m.tape(0x130, tape, format = "simh", type = "3420")
    m.alter(0, binary.decode("4000000000001000", "hex"))
    m.alter(0x48, binary.decode("00080000", "hex"))
    m.alter(0x78, binary.decode("0002000000001200", "hex"))
    m.alter(0x180, binary.decode("4002000000001008", "hex"))
    m.alter(0x1000, binary.decode("9c00013082000180", "hex"))  # SIO 130; LPSW X'180'.
    read_ccw = binary.decode("0208010020000018", "hex")
    m.alter(0x2000, read_ccw)
    m.alter(0x80000, read_ccw)
    guard = b"\xa5" * 24
    m.alter(0x80100, guard)
    m.restart(storage_element = 1)
    initial = m.checkpoint()
    m.break_at(0x1004)
    start = m.run(instructions = 2)
    if start.kind != "breakpoint" or start.psw != "40000000 00001004" or m.tape_position(0x130).position != 1:
        fail("SIO did not accept the CCW from running SE2: %s %s" % (start.kind, start.psw))

    m.restore(initial)
    m.replay_storage_logout(2, b"\x00" * 48)
    stopped = m.run(instructions = 2)
    if (stopped.kind != "breakpoint" or stopped.psw != "40000000 10001004" or
        binary.hex(m.read(0x40, 8)) != "0000000000210000" or m.tape_position(0x130).position != 0):
        fail("SIO did not reject the CCW in stopped SE2: %s %s CSW=%s" % (stopped.kind, stopped.psw, binary.hex(m.read(0x40, 8))))

    # Restart the same read with the CCW in SE1 and stop at SIO completion.
    m.restore(initial)
    m.alter(0x48, binary.decode("00002000", "hex"))
    start = m.run(instructions = 2)
    if start.kind != "breakpoint" or start.psw != "40000000 00001004" or m.read(0x80100, 24) != guard:
        fail("SIO did not stop before moving the tape data: %s %s" % (start.kind, start.psw))
    m.clear_breaks()
    pending = m.checkpoint()
    payload = m.tape_record(0x130, index = 0)[:24]
    for los, csw, wanted in [(False, "000020080c000000", payload), (True, "000020080c210018", guard)]:
        m.restore(pending)
        if los:
            m.replay_storage_logout(2, b"\x00" * 48)
        done = m.run(instructions = 500000)
        if (done.kind != "disabled-wait" or done.psw != "00020000 00001200" or
            binary.hex(m.read(0x40, 8)) != csw or m.read(0x80100, 24) != wanted):
            fail("tape read with LOS=%s: %s %s CSW=%s" % (los, done.kind, done.psw, binary.hex(m.read(0x40, 8))))
    print("IOCE rejected the stopped-SE CCW with CC1 and status 21, and ended an active read with CSW 000020080C210018 without writing to SE2")


def check_storage_ioce_psa():
    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
    reel = binary.builder()
    reel.append(binary.decode("040000004142434404000000", "hex"))
    m.tape(0x130, reel.file(), type = "3420", format = "simh")
    m.alter(0x80000, binary.decode("4000000000001000", "hex"))
    m.alter(0x80040, binary.decode("a5a5a5a5a5a5a5a50000200011223344", "hex"))
    m.alter(0x80078, binary.decode("0000000000001200", "hex"))
    # BALR 3,0 captures X'1002'; SIO 130; DIAG X'1280'; LPSW X'1300'.
    m.alter(0x1000, binary.decode("05309c0001308300327e820032fe", "hex"))
    m.alter(0x1200, binary.decode("8300327e", "hex"))  # DIAG X'1280' after the IOCE writes the CSW.
    m.alter(0x1280, binary.decode("00fd080020008000", "hex"))
    m.alter(0x1300, binary.decode("400200000000100e", "hex"))
    m.alter(0x2000, binary.decode("0200220020000004", "hex"))
    m.restart(storage_element = 2)
    initial = m.checkpoint()
    m.break_at(0x100a)
    started = m.run(instructions = 4)
    caw = binary.hex(m.read(0x1288, 48))
    if (started.kind != "breakpoint" or started.psw != "40000000 0000100A" or
        binary.hex(m.read(0x80040, 8)) != "a5a5a5a5a5a5a5a5" or m.read(0x2200, 4) != b"\x00" * 4):
        fail("IOCE PSA read setup at %s %s: %s" % (started.kind, started.psw, caw))
    m.clear_breaks()
    m.break_at(0x1204)
    ended = m.run(instructions = 500000)
    csw = binary.hex(m.read(0x1288, 48))
    if (ended.kind != "breakpoint" or ended.psw != "00000000 00001204" or
        binary.hex(m.read(0x80040, 8)) != "000020080c000000" or m.read(0x2200, 4) != b"ABCD"):
        fail("IOCE PSA write setup at %s %s: %s" % (ended.kind, ended.psw, csw))
    idle_even = "000000000000000000000000840000fc0010000000000300"
    caw_odd = "000020001122334400100040000004008080083a020000df"
    csw_even = "000020080c0000000f100040840004fc0010103a000003cf"
    if caw != idle_even + caw_odd or csw != csw_even + caw_odd:
        fail("IOCE PSA logout: CAW=%s CSW=%s" % (caw, csw))
    m.restore(initial)
    m.clear_breaks()
    m.alter(0x80048, binary.decode("00002300", "hex"))  # The initial CCW is invalid.
    m.break_at(0x1006)
    rejected = m.run(instructions = 3)
    if rejected.kind != "breakpoint" or rejected.psw != "40000000 10001006":
        fail("IOCE PSA partial status setup at %s %s" % (rejected.kind, rejected.psw))
    m.clear_breaks()
    m.break_at(0x100a)
    partial = m.run(instructions = 2)
    status = binary.hex(m.read(0x1288, 48))
    if (partial.kind != "breakpoint" or binary.hex(m.read(0x80040, 8)) != "a5a5a5a50020a5a5" or
        status[:40] != "a5a5a5a50020a5a50c100040840004fc0010103a"):
        fail("IOCE PSA partial status logout at %s %s: %s" % (partial.kind, partial.psw, status))
    print("Live FD0 captured the IOCE CAW fetch, full CSW and partial status stores in the CE's PSA in SE2")


def check_storage_output():
    payload = b"A" * 1024
    capture = b"\xa5" * 48
    for mode, csw, record in [
        ("normal", "000020080c000000", payload),
        ("halt", "00002008000003ff", payload[:1]),
        ("los", "000020080c2103ff", payload[:1]),
        ("fd0", "000020080c000000", payload),
    ]:
        m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
        m.tape(0x130, binary.builder().file(), format = "simh", type = "2401", ring = True)
        m.alter(0, binary.decode("4000000000001000", "hex"))
        m.alter(0x48, binary.decode("00002000", "hex"))
        m.alter(0x78, binary.decode("0002000000001200", "hex"))
        m.alter(0x180, binary.decode("4002000000001008", "hex"))
        m.alter(0x1000, binary.decode("9c00013082000180", "hex"))  # SIO 130; LPSW X'180'.
        m.alter(0x2000, binary.decode("0108000020000400", "hex"))
        m.alter(0x80000, payload)
        m.restart(storage_element = 1)
        m.break_at(0x1004)
        start = m.run(instructions = 2)
        if (start.kind != "breakpoint" or start.psw != "40000000 00001004" or
            m.tape_position(0x130).record_count != 0):
            fail("2401 write did not stop before recording: %s %s" % (start.kind, start.psw))
        m.clear_breaks()
        if mode == "halt":
            m.alter(0x1004, binary.decode("9e00013082000180", "hex"))  # HIO 130; LPSW X'180'.
        elif mode in ["los", "fd0"]:
            m.replay_storage_logout(2, capture)
            if mode == "fd0":
                m.alter(0x280, binary.decode("00fd080020008000", "hex"))
                m.alter(0x1004, binary.decode("8300028082000180", "hex"))  # DIAG X'280'; LPSW X'180'.
        done = m.run(instructions = 500000)
        if (done.kind != "disabled-wait" or done.psw != "00020000 00001200" or
            binary.hex(m.read(0x40, 8)) != csw or m.tape_position(0x130).record_count != 1 or
            m.tape_record(0x130, index = 0) != record):
            fail("2401 write %s: %s %s CSW=%s" % (mode, done.kind, done.psw, binary.hex(m.read(0x40, 8))))
        if mode == "fd0" and m.read(0x288, 48) != capture:
            fail("FD0 did not fetch the SE2 logout during the write")
    print("2401 LOS kept the one byte already accepted and reported residual 03FF. FD0 before the next fetch allowed all 1024 bytes.")

    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
    m.tape(0x130, binary.builder().file(), format = "simh", type = "2401", ring = True)
    payload = binary.decode("0001020304050607" + "41" * 1000 + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")
    m.alter(0x80000, payload)
    m.alter(0, binary.decode("4000000000001000", "hex"))
    m.alter(0x48, binary.decode("00002000", "hex"))
    m.alter(0x78, binary.decode("0000000000001200", "hex"))
    m.alter(0x180, binary.decode("4002000000001018", "hex"))
    m.alter(0x200, binary.decode("00080000", "hex"))
    # L 2,X'200'; SIO 130; snapshot the first fetch; LA 1,X'585'; STH 1,0(2); LPSW X'180'.
    m.alter(0x1000, binary.decode("582002009c00013083000280411005854010200082000180", "hex"))
    m.alter(0x2000, binary.decode("0108000020000400", "hex"))
    m.alter(0x280, binary.decode("00fd080020008000", "hex"))
    m.alter(0x1200, binary.decode("83000280", "hex"))  # Snapshot again after I/O completion.
    m.restart(storage_element = 1)
    m.break_at(0x100c)
    first = m.run(instructions = 4)
    first_logout = binary.hex(m.read(0x288, 48))
    if (first.kind != "breakpoint" or first.psw != "40000000 0000100C" or
        m.tape_position(0x130).record_count != 0 or
        first_logout[:16] != "0001020304050607" or first_logout[48:] != "00" * 24):
        fail("2401 first-request FD0 at %s %s: %s" % (first.kind, first.psw, first_logout))
    m.clear_breaks()
    m.break_at(0x1204)
    done = m.run(instructions = 500000)
    final_logout = binary.hex(m.read(0x288, 48))
    if (done.kind != "breakpoint" or done.psw != "00000000 00001204" or
        binary.hex(m.read(0x40, 8)) != "000020080c000000" or
        m.read(0x80000, 2) != b"\x05\x85" or binary.hex(m.tape_record(0x130, index = 0)) != "0085" + binary.hex(payload[2:]) or
        final_logout[:16] != "f0f1f2f3f4f5f6f7" or final_logout[48:64] != "f8f9fafbfcfdfeff"):
        fail("2401 final FD0 at %s %s: %s CSW=%s" % (done.kind, done.psw, final_logout, binary.hex(m.read(0x40, 8))))
    print("2401 wrote the first byte already accepted before STH and the second byte as changed by STH. FD0 captured the accepted source words at selection and completion.")


def check_storage_output_parity():
    for device, address, mask, end_address in [("2401", "0530", "04", "2008"), ("2314", "0340", "10", "2018")]:
        tape = device == "2401"
        dev = int(address, 16)
        payload = bytes(list(range(40 if tape else 80)))
        interrupt_handler = binary.decode("07009c00%s82000248" % address, "hex")
        for bad in [False, True]:
            m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
            if tape:
                m.tape(dev, binary.builder().file(), type = "2401", model = 2, format = "simh", ring = True)
                m.alter(0x2000, binary.decode("0108000020000028", "hex"))
            else:
                m.dasd(dev, type = "2314", cylinders = 203, volser = "SCRTCH")
                m.alter(0x2000, binary.decode("310022004000000508002000000000010508000000000050", "hex"))
                m.alter(0x2200, binary.decode("0000000003", "hex"))
                original_track = m.dasd_track(dev, 0, 0, bytes = 80)
            m.alter(0, binary.decode(mask + "04000000001000", "hex"))
            m.alter(0x48, binary.decode("00002000", "hex"))
            m.alter(0x70, binary.decode("0000000000001100", "hex"))
            m.alter(0x78, binary.decode("0000000000001200", "hex"))
            m.alter(0x240, binary.decode(mask + "06000000001008" + mask + "0200000000110c", "hex"))
            m.alter(0x280, binary.decode("00fd080020008000", "hex"))
            m.alter(0x1000, binary.decode("9c00%s82000240" % address, "hex"))
            # DIAG FD0 saves the SE2 frame. STC restores data parity before LPSW.
            m.alter(0x1100, binary.decode("830002804200100182000248", "hex"))
            m.alter(0x1200, interrupt_handler)
            m.alter(0x1300, interrupt_handler)
            m.alter(0x1400, binary.decode("0700", "hex"))
            m.alter(0x80000, payload)
            m.restart(storage_element = 1)
            m.alter_register(0, 0x19)
            m.alter_register(1, 0x80018)
            m.break_at(0x1004)
            start = m.run(instructions = 2)
            if start.kind != "breakpoint" or start.psw != mask + "040000 00001004":
                fail("%s output setup: %s %s" % (device, start.kind, start.psw))
            if bad:
                m.set_storage_data_parity(0x80019, bad = True)
                m.clear_breaks()
                m.break_at(0x1104)
                check = m.run(instructions = 1000000)
                old_psw = mask + ("06000200001008" if tape else "06000100001008")
                logout = binary.hex(m.read(0x288, 48))
                if (check.kind != "breakpoint" or check.psw != "00000000 00001104" or
                    binary.hex(m.read(0x30, 8)) != old_psw or m.read(0x40, 8) != b"\x00" * 8 or
                    binary.hex(m.read(352, 12)) != "400000000200000000001600" or
                    logout[:16] != binary.hex(payload[16:24]) or logout[48:64] != binary.hex(payload[24:32])):
                    fail("%s output machine check: %s %s FD0=%s" % (device, check.kind, check.psw, logout))
                if (tape and m.tape_position(dev).record_count != 0 or
                    not tape and m.dasd_track(dev, 0, 0, bytes = 80) != original_track):
                    fail("%s wrote to the medium before the device ending" % device)
                m.restore(m.checkpoint())
            m.clear_breaks()
            m.break_at(0x1202)
            end = m.run(instructions = 1000000)
            csw = binary.hex(m.read(0x40, 8))
            expected_csw = "000000000e000000" if bad else "0000" + end_address + "0c000000"
            if end.kind != "breakpoint" or end.psw != "00000000 00001202" or csw != expected_csw:
                fail("%s output ending with bad parity %s: %s %s CSW=%s" % (device, bad, end.kind, end.psw, csw))
            accepted = payload[:24] if bad else payload
            if tape:
                if m.tape_position(dev).record_count != 1 or m.tape_record(dev, index = 0) != accepted:
                    fail("2401 output did not record all accepted bytes")
            else:
                track = m.dasd_track(dev, 0, 0, bytes = 80)
                data = binary.hex(accepted) + "00" * (80 - len(accepted))
                if track[:3] != original_track[:3] or track[3] != "0000000003 kl=4 dl=80 key=VOL1 data=" + data.upper():
                    fail("2314 output did not preserve accepted bytes and zero-fill the record: %s" % track[3])
            if not bad:
                continue
            m.alter(0x48, binary.decode("00002040", "hex"))
            m.alter(0x78, binary.decode("0000000000001300", "hex"))
            m.alter(0x2040, binary.decode("0400210020000006", "hex"))
            m.clear_breaks()
            m.break_at(0x1302)
            sense = m.run(instructions = 100000)
            if sense.kind != "breakpoint" or sense.psw != "00000000 00001302" or m.read(0x2100, 1) != b"\x04":
                fail("%s output overrun Sense: %s %s bytes=%s" % (device, sense.kind, sense.psw, binary.hex(m.read(0x2100, 6))))
            retry_caw = "00002000"
            if tape:
                retry_caw = "00002020"
                m.alter(0x2020, binary.decode("27000000600000010108000020000028", "hex"))
            m.alter(0x48, binary.decode(retry_caw, "hex"))
            m.alter(0x78, binary.decode("0000000000001400", "hex"))
            m.clear_breaks()
            m.break_at(0x1402)
            retry = m.run(instructions = 100000)
            csw = binary.hex(m.read(0x40, 8))
            if retry.kind != "breakpoint" or retry.psw != "00000000 00001402" or csw != "0000" + ("2030" if tape else end_address) + "0c000000":
                fail("%s output retry: %s %s CSW=%s" % (device, retry.kind, retry.psw, csw))
            if tape:
                if m.tape_position(dev).record_count != 1 or m.tape_record(dev, index = 0) != payload:
                    fail("2401 output retry did not restore the full record")
            elif not m.dasd_track(dev, 0, 0, bytes = 80)[3].endswith("data=" + binary.hex(payload).upper()):
                fail("2314 output retry did not restore the full record")
    print("2401 and 2314 parity checks preserved the accepted bytes and logged SE2 before device overrun. Guest Sense and retry restored both records.")


def check_storage_output_chain():
    for device, address, mask, ccw_address in [("2401", "0530", "04", 0x80108), ("2314", "0340", "10", 0x80118)]:
        tape = device == "2401"
        dev = int(address, 16)
        command = "01" if tape else "05"
        for mode in ["clean", "modified", "fault"]:
            m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
            search = ""
            if tape:
                m.tape(dev, binary.builder().file(), type = "2401", model = 2, format = "simh", ring = True)
            else:
                m.dasd(dev, type = "2314", cylinders = 203, volser = "SCRTCH")
                m.alter(0x2200, binary.decode("0000000002", "hex"))
                search = "31002200400000050808010000000001"
            first_ccw = command + "08000080000028"
            second_ccw = command + "08030020000008"
            m.alter(0x80100, binary.decode(search + first_ccw + second_ccw, "hex"))
            m.alter(0x80000, b"A" * 40)
            m.alter(0x80300, b"B" * 8)
            m.alter(0x80400, b"C" * 16)
            m.alter(0, binary.decode(mask + "04000000001000", "hex"))
            m.alter(0x48, binary.decode("00080100", "hex"))
            m.alter(0x70, binary.decode("0000000000001100", "hex"))
            m.alter(0x78, binary.decode("0002000000001200", "hex"))
            m.alter(0x240, binary.decode(mask + "06000000001008" + mask + "02000000001108", "hex"))
            m.alter(0x280, binary.decode("00fd080020008000", "hex"))
            m.alter(0x1000, binary.decode("9c00%s82000240" % address, "hex"))
            m.alter(0x1100, binary.decode("8300028082000248", "hex"))
            m.restart(storage_element = 1)
            m.break_at(0x1004)
            start = m.run(instructions = 2)
            if start.kind != "breakpoint" or start.psw != mask + "040000 00001004":
                fail("%s output chain %s setup: %s %s" % (device, mode, start.kind, start.psw))
            if mode == "fault":
                m.set_storage_data_parity(ccw_address + 1, bad = True)
            elif mode == "modified":
                m.alter(ccw_address, binary.decode(command + "08040020000010", "hex"))
            m.restore(m.checkpoint())
            m.clear_breaks()
            if mode == "fault":
                m.break_at(0x1104)
                fault = m.run(instructions = 1000000)
                old_psw = mask + ("06000200001008" if tape else "06000100001008")
                logout = binary.hex(m.read(0x288, 48))
                if (fault.kind != "breakpoint" or fault.psw != "00000000 00001104" or
                    binary.hex(m.read(0x30, 8)) != old_psw or m.read(0x40, 8) != b"\x00" * 8 or
                    binary.hex(m.read(352, 12)) != "400000000200000000001600" or logout[48:64] != second_ccw):
                    fail("%s output chain check: %s %s FD0=%s" % (device, fault.kind, fault.psw, logout))
                m.clear_breaks()
            end = m.run(instructions = 1000000)
            expected_csw = "000000000e000000" if mode == "fault" else ("000801100c000000" if tape else "000801200c000000")
            csw = binary.hex(m.read(0x40, 8))
            if end.kind != "disabled-wait" or end.psw != "00020000 00001200" or csw != expected_csw:
                fail("%s output chain %s ending: %s %s CSW=%s" % (device, mode, end.kind, end.psw, csw))
            expected = b"A" * 24 if mode == "fault" else b"A" * 40
            expected_hex = binary.hex(expected)
            if mode == "clean":
                expected_hex += "42" * 8
            elif mode == "modified":
                expected_hex += "43" * 16
            if tape:
                if m.tape_position(dev).record_count != 1 or binary.hex(m.tape_record(dev, index = 0)) != expected_hex:
                    fail("2401 output chain %s recorded the wrong bytes" % mode)
            else:
                record = m.dasd_track(dev, 0, 0, bytes = 144)[2]
                if record != "0000000002 kl=4 dl=144 key=IPL2 data=" + expected_hex.upper() + "00" * (144 - len(expected_hex) // 2):
                    fail("2314 output chain %s recorded the wrong bytes: %s" % (mode, record))
    print("2401 and 2314 output chains accepted late CCW address and count changes. Bad CCW parity stopped each write with 24 bytes accepted and overrun status.")


def check_storage_keys():
    failures = []
    for target, stored_key in [("cpu", "08"), ("channel", "08"), ("cpu", "28"), ("channel", "28")]:
        m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False)
        m.tape(0x130, binary.builder().file(), format = "simh", type = "2401", ring = True)
        m.alter(0, binary.decode("4000000000001000", "hex"))
        m.alter(0x48, binary.decode("50080010", "hex"))
        m.alter(0x68, binary.decode("0002000000001234", "hex"))
        m.alter(0x78, binary.decode("0002000000001200", "hex"))
        m.alter(0x180, binary.decode("40500000" + ("0000100e" if target == "cpu" else "00001016"), "hex"))
        m.alter(0x190, binary.decode("405200000000101e", "hex"))
        m.alter(0x200, binary.decode("00080000", "hex"))
        # LA and L supply the storage key and address to SSK; LPSW then selects PSW key 5.
        # The CPU case loads and stores in SE2. The channel case uses CAW key 5 for the CCW and its source.
        m.alter(0x1000, binary.decode("411000%s5820020008128200018058302000503020049c00013082000190" % stored_key, "hex"))
        m.alter(0x80000, binary.decode("41424344a5a5a5a5", "hex"))
        m.alter(0x80010, binary.decode("0108000020000004", "hex"))
        m.restart(storage_element = 1)
        if target == "cpu":
            m.break_at(0x1016)
            m.break_program(4)
            stop = m.run(instructions = 32)
            if stored_key == "08":
                ok = stop.kind == "breakpoint" and m.read(0x80000, 8) == b"ABCDABCD"
            else:
                ok = stop.kind == "program" and stop.psw.endswith("001234") and m.read(0x80004, 4) == b"\xa5" * 4
        elif stored_key == "08":
            stop = m.run(instructions = 500000)
            ok = (stop.kind == "disabled-wait" and stop.psw == "00020000 00001200" and
                  binary.hex(m.read(0x40, 8)) == "500800180c000000" and
                  m.tape_position(0x130).record_count == 1 and m.tape_record(0x130, index = 0) == b"ABCD")
        else:
            m.break_at(0x101a)
            stop = m.run(instructions = 32)
            ok = (stop.kind == "breakpoint" and stop.psw == "40500000 1000101A" and
                  binary.hex(m.read(0x40, 8)) == "0000000000300000" and m.tape_position(0x130).record_count == 0)
        if not ok:
            failures.append("%s key %s: %s %s, CSW=%s" % (target, stored_key, stop.kind, stop.psw, binary.hex(m.read(0x40, 8))))
    if failures:
        fail("9020 storage key comparison: " + "; ".join(failures))
    print("9020 CE and IOCE accepted a zero storage key with fetch protection set and rejected a different nonzero key")


def faa_correction(m, address, original, replacement):
    before = binary.decode(original, "hex")
    after = binary.decode(replacement, "hex")
    if len(after) != len(before) or m.read(address, len(before)) != before:
        fail("diag1.tap: unexpected instruction bytes at %x" % address)
    m.alter(address, after)

def faa_ioce(tape):
    """IPL the IOCE path with the D0010400.SPT monitor selection restored."""
    # D106C100.SPT B034 and B035 accept a zero storage key after a
    # successful store. Test it before each retained PSW-key comparison.
    zero_key_18 = "12774780FBEC5510FE7447F0FB80"
    zero_key_19 = "12774780FCF65510FE7447F0FC8A"
    tape = diagnostic_reel(tape, "D106C1", [
        (0xb7c, "5510FE74", "47F0FFC0"),
        (0xc86, "5510FE74", "47F0FFD0"),
        (0xfc0, "00" * (len(zero_key_18) // 2), zero_key_18),
        (0xfd0, "00" * (len(zero_key_19) // 2), zero_key_19),
    ])
    # D1071100.SPT B012 runs the same storage-key comparison for a store
    # reached through EXECUTE.
    zero_key_17 = "12774780FC945510FE1847F0FC28"
    tape = diagnostic_reel(tape, "D10711", [
        (0xc24, "5510FE18", "47F0FFC0"),
        (0xfc0, "00" * (len(zero_key_17) // 2), zero_key_17),
    ])
    # D1072100.SPT B034/B035 do the RX/RS and SI tests through EXECUTE.
    zero_key_ex_18 = "12774780FC2C5510FEBC47F0FBC0"
    zero_key_ex_19 = "12774780FD3E5510FEBC47F0FCD2"
    tape = diagnostic_reel(tape, "D10721", [
        (0xbbc, "5510FEBC", "47F0FFC0"),
        (0xcce, "5510FEBC", "47F0FFD0"),
        (0xfc0, "00" * (len(zero_key_ex_18) // 2), zero_key_ex_18),
        (0xfd0, "00" * (len(zero_key_ex_19) // 2), zero_key_ex_19),
    ])
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

def start_mdm(tape, model = "9020"):
    """IPL from the reel and stop at the D0D50A entry."""
    m = machine(tape, model = model)
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
    m.clear_breaks()
    return m

def faa_mdm(tape):
    """Restore D0D50A from the FAA listing for both IPL and MDM reload."""
    startup = "A00007E81B33433007EB920007EB45700E8641A9100041BA100047F00088"
    maatr4 = "0C3089300002413391D4A1003000A00007E8920007EB47F0D87C"
    # JMC630 tests the requesting CE and takes the FAA reinitialization delay
    # before returning. The missing branch, LI and DLY do not fit in place.
    recovery = "47100FF60C304430D1604780D1D00B0447F0D1D0"
    updates = [
        (0x0084, "41BA1000", "47F00FA0"),
        (0x0304, "00000000", "45700FC0"),  # MAATR4 call
        (0x0fa0, "00" * (len(startup) // 2), startup),  # SPSB and INGTSE
        (0x0fc0, "00" * (len(maatr4) // 2), maatr4),
        (0x0fe0, "0000000000000000", "9B00500047F0DC86"),  # SIA200 SPCI
        (0x0fe8, "00" * (len(recovery) // 2), recovery),
        (0x3a18, "000000000000", "D503321C0AE8"),  # SKD991 checks the PST before EOJ.
        (0x3fe6, "00000000", "90070548"),  # SKP510 saves the loader's registers.
        (0x40ae, "00000000", "98070548"),  # SKP513
        # SKP600 through SKP630 return the devices used by a section.
        (0x4318, "00000000", "90070548"),
        (0x4374, "0000000000000000", "5040055850600560"),
        (0x43b8, "00000000", "98070548"),
        (0x43de, "00000000", "58400558"),
        (0x588a, "00000000", "98070548"),  # LOT408 restores the loader's registers.
        (0x73c8, "00000000", "47800FE0"),  # SIA074 tests whether to issue SPCI.
        (0xa7e0, "00000000", "41500FC0"),
        (0xe45e, "00000000", "47F00FE8"),
        (0xf0a4, "000000000000", "D227F924B220"),  # SEEAP SPSTCK
        (0xf356, "000000000000", "D227F924B220"),  # SEEAP SPSTAN
        (0xf482, "00000000", "9180B206"),  # SEEAP SWHAT checks the CE1 monitor flag.
    ]
    # The D0D50A record starts at storage address 8.
    return start_mdm(diagnostic_reel(tape, "D0D50A", [(address - 8, before, after) for address, before, after in updates]))

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
        m.key(0x00d, "RUNOUT")
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

def sdm(m, message = LOAD_MESSAGE, budget = 20000000000, step = 2000000, blank = 20, show = True, stop = None, detail_cards = None, valid_cards = None, handle_operator = operator, report_device = None, followup_cards = [], console_input = False):
    """Runs SDM with a load message and returns its results.

    The result holds each section started ("S" lines) with its routine count
    from the "T" line and the routines that reported errors, the sections SDM
    did not run ("RNV"), the console transcript, and all diagnostic errors.
    "ended" is "end-of-job" at SDM EOJ, "stop" at the requested stop text,
    "budget" on exhaustion, or the machine's stop kind on interruption.
    """
    ready = m.psw() == SDM_READY
    if not console_input:
        m.cards(0x00c, [message] + followup_cards + [""] * blank, replace = True)
    if not ready:
        r = m.run(instructions = 200000000)
        if r.psw != SDM_READY:
            fail("sdm: not waiting for the operator: %s %s" % (r.kind, r.psw))
    start = m.instructions()
    seen = len(m.screens(0x01f) if report_device == None else m.output(report_device))
    if console_input:
        m.key(0x01f, "REQUEST")
        wait_1052_read(m)
        m.type(0x01f, message if message.endswith("/") else message + "/")
    else:
        m.interrupt_key()
    spent = 0
    sections, skipped, transcript, errors, current = [], [], [], [], None
    ended = None
    for _ in range(budget // step + 1):
        if spent >= budget or ended:
            break
        r = m.run(instructions = step)
        spent += step
        lines = m.screens(0x01f) if report_device == None else m.output(report_device)
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
            disk_map = current and current["section"] == "D80652" and line.strip().startswith(
                ("* ** ER NONE UNIT ", "* READ HEAD MAP-", "* HEAD NUMBER--- ", "* RD HA RESULT-- "))
            failed_io = line.strip().startswith("DIO SDM ") and "UNSUCCESSFUL AFTER" in line
            if ((words and words[0] == "*" and len(words) > 1 and not disk_map) or
                (words and words[0] in ["ILR", "PNF"]) or line.strip().startswith("RPM SDM ") or failed_io or "COMPARE ERR,CARD NO." in line):
                errors.append(line.strip())
            if stop and stop in line:
                ended = "stop"
                break
            if line.strip() == END_OF_JOB:
                ended = "end-of-job"
                break
            if detail_cards != None and DETAIL_DECK in line:
                m.cards(0x00c, detail_cards, replace = True)
            if "PLACE VALID CDS" in line and (valid_cards != None or detail_cards != None):
                m.cards(0x00c, valid_cards if valid_cards != None else [str(i) for i in range(75)], replace = True)
            reply = handle_operator(m, line, current["section"] if current else None)
            if reply and show:
                print("operator: " + reply)
        seen = len(lines)
        if not ended and (r.kind in ["disabled-wait", "check-stop", "stopped", "breakpoint", "program", "svc"] or r.psw == SDM_READY):
            ended = r.kind
    return {"sections": sections, "skipped": skipped, "transcript": transcript, "errors": errors, "ended": ended or "budget",
            "run": r, "instructions": m.instructions() - start, "time": m.time()}

def check_job(m, section, required, halts = 0):
    lines = [line.strip() for line in m.screens(0x01f)]
    if ([line for line in lines if line.startswith("S   ")] != ["S   " + section] or
        [line for line in lines if line == END_OF_JOB] != [END_OF_JOB] or
        any([line.startswith("* ") for line in lines]) or
        len([line for line in lines if line.startswith("HLT ")]) != halts or
        any([line not in lines for line in required])):
        fail("%s did not finish cleanly (%s)\n%s" % (section, m.psw(), "\n".join(lines[-18:])))

def wait_1052_read(m, device = 0x01f):
    for _ in range(350):
        if "blocked=true" in m.subchannel(device):
            return
        m.run(instructions = 20000)
    fail("1052 did not request keyboard input (%s)\n%s" % (m.psw(), "\n".join(m.screens(device)[-10:])))

def format0_ccw(command, address, flags = "00", count = 0):
    return command + ("000000%x" % address)[-6:] + flags + "00" + ("0000%x" % count)[-4:]

def storage_dump_ipl_cards(payload):
    """Build a 2540 bootstrap for the original level-0 dump payload."""
    origin, entry = 8, 0xf000
    prefix = entry - origin
    if payload.bytes(0, prefix) != b"\x00" * prefix:
        fail("D0CF00 has data below its entry point")
    text = payload.bytes(prefix, payload.size - prefix)

    # The IPL PSW and the first two format-0 CCWs occupy card columns 1–24.
    # The reader loads a control card, then executes its CCWs via TIC.
    # Alternate two buffers so reading the next control card leaves the
    # currently executing chain intact. Both buffers are above the payload.
    buffers = [0x11000, 0x11050]
    card_size = 80
    reads_per_control = 8
    bootstrap = "000000000000" + ("%x" % entry)
    bootstrap += format0_ccw("02", buffers[0], "60", card_size) + format0_ccw("08", buffers[0])
    deck = [binary.decode(bootstrap + "00" * (card_size - len(bootstrap) // 2), "hex")]
    stride = card_size * reads_per_control
    for group, offset in enumerate(range(0, len(text), stride)):
        control, data = [], []
        for start in range(offset, min(offset + stride, len(text)), card_size):
            chunk = text[start:start + card_size]
            control.append(format0_ccw("02", entry + start, "60", len(chunk)))
            data.append(binary.decode(binary.hex(chunk) + "00" * (card_size - len(chunk)), "hex"))
        if offset + stride < len(text):
            target = buffers[(group + 1) % len(buffers)]
            control.extend([format0_ccw("02", target, "60", card_size), format0_ccw("08", target)])
        else:
            # Restore the 16 bytes occupied by the bootstrap CCWs.
            control.append(format0_ccw("02", origin, "20", 16))
            data.append(b"\x00" * card_size)
        commands = "".join(control)
        deck.append(binary.decode(commands + "00" * (card_size - len(commands) // 2), "hex"))
        deck.extend(data)
    return deck

def start_storage_dump(deck, payload, printer, preserved, console):
    # D0CF0300.SPT specifies disabling the interval timer.
    m = emulator.s390(architecture = "s360", model = "9020", memory = 1 << 20, interval_timer = False, mips = 1)
    if console:
        m.console(0x01f, type = "1052")
    m.unit_record(printer, type = "1403")
    m.unit_record(0x00c, type = "2540R", cards = [])
    m.alter(0x12000, preserved)
    m.cards(0x00c, deck)
    m.ipl(0x00c, clear = False)
    if m.psw() != "0000000C 0000F000" or m.read(8, payload.size) != payload.bytes(0, payload.size):
        fail("2540 IPL did not load the exact D0CF00 payload and entry PSW")
    if m.read(0x12000, len(preserved)) != preserved:
        fail("2540 IPL cleared storage outside the D0CF00 load area")
    m.break_at(0xf0be)
    r = m.run(instructions = 300000)
    registers = m.output(printer)
    if r.kind != "breakpoint" or [line[:6] for line in registers] != ["GR 0-7", "GR 8-F", "FP 0-6"]:
        fail("D0CF00 on %X did not print its registers and wait (%s %s)" % (printer, r.kind, r.psw))
    m.clear_breaks()
    return m, registers

def check_storage_dump_panel(deck, payload, preserved, expected_line, original):
    printer = 0x005
    m, registers = start_storage_dump(deck, payload, printer, preserved, console = False)
    if m.read(0xf28e, 4) != b"\x58\x30\xf7\x44" or m.read(0xf744, 4) != b"\x00\x00\xf7\x50":
        fail("D0CF00 does not point at the cold-start request")
    if original:
        m.break_program(1)
    else:
        # The initial PARAM contains /B. DMSG expects /B/ (D0CF0300.SPT
        # statements 319–326 and 546). Keep the terminator in the
        # payload's zero padding beyond the message and print work areas.
        if m.read(0xf750, 4) != b"\x61\xc2\x00\x00":
            fail("D0CF00 initial PARAM differs from the pinned payload")
        faa_correction(m, 0xfff0, "00000000", "61C26100")
        faa_correction(m, 0xf744, "0000F750", "0000FFF0")
    seen = len(registers)
    for _ in range(1 if original else 2):
        if not original:
            m.break_at(0xf36c)
        m.interrupt_key()
        r = m.run(instructions = 20000000)
        m.clear_breaks()
        printed = m.output(printer)[seen:]
        seen += len(printed)
        if (printed[:1] != ["MEMORY 0"] or [line for line in printed if line == expected_line] != [expected_line] or
            printed[-1:] != ["020000      00000000"]):
            fail("D0CF00 panel dump did not print the default range (%s %s)" % (r.kind, r.psw))
        if original:
            if (r.kind != "program" or not r.psw.endswith("003333") or
                m.read(0x28, 4) != b"\x00\x04\x00\x01" or m.read(0xf3e8, 6) != b"\xf0" * 6):
                fail("D0CF00 original cold request did not reproduce its message parser overrun")
            print("D0CF00 printed the default range, then overwrote its converter and entered program-check wait 3333.")
        elif r.kind != "breakpoint" or not r.psw.endswith("00F36C"):
            fail("D0CF00 panel dump did not finish at the operator wait (%s %s)" % (r.kind, r.psw))
    if not original:
        print("D0CF00 completed two operator-interrupt dumps without a 1052 and returned to its wait after each.")

def check_storage_dump(tape, show = False, panel_original = False):
    """Exercise the original D0CF00 payload with the timer disabled."""
    records = archive.simh(library_reel(tape)).records
    headers = [index for index, header in library_headers(records) if header[8:16] == "D0CF0000"]
    if len(headers) != 1:
        fail("expected one original D0CF00 header")
    payload = records[headers[0] + 1].data
    if payload.size != 65535 or payload.bytes(0xeff8, 10) != binary.decode("50f0000041f0000005f0", "hex"):
        fail("unexpected D0CF00 payload or entry")

    deck = storage_dump_ipl_cards(payload)
    preserved = b"0123456789ABCDEF" * 2
    expected_dump = []
    for address, data in [("00F000", payload.bytes(0xeff8, 32)), ("012000", preserved)]:
        dump_hex = binary.hex(data).upper()
        words = [dump_hex[i:i + 8] for i in range(0, len(dump_hex), 8)]
        expected_dump.extend(["MEMORY 0", address + "      " + "  ".join(words[:4]) + "      " + "  ".join(words[4:])])
    check_storage_dump_panel(deck, payload, preserved, expected_dump[-1], panel_original)
    if panel_original:
        return
    printers = [base + offset for base in [0x005, 0x00b] for offset in [0, 0x400, 0x800, 0xc00]]
    for printer in printers:
        m, registers = start_storage_dump(deck, payload, printer, preserved, console = True)

        error = "ERR IN INPUT MESSAGE."
        for command, valid in [("/0X,F01F/B/", False), ("/0F000,F01F.12000,1201F/B/", True)]:
            console_start = len(m.screens(0x01f))
            m.key(0x01f, "REQUEST")
            wait_1052_read(m)
            m.type(0x01f, command)
            m.break_at(0xf36c)
            r = m.run(instructions = 500000)
            m.clear_breaks()
            if r.kind != "breakpoint":
                fail("D0CF00 on %X did not return to its input wait after %s (%s %s)" % (printer, command, r.kind, r.psw))
            # Finish any outstanding console/printer mechanical completion.
            settled = m.run(instructions = 50000)
            if settled.psw != "89040000 0000F36C":
                fail("D0CF00 on %X left its operator wait after %s (%s)" % (printer, command, settled.psw))
            console = [line.strip() for line in m.screens(0x01f)[console_start:]]
            printed = m.output(printer)[len(registers):]
            if valid:
                if printed != expected_dump or error in console:
                    fail("D0CF00 on %X did not print both requested ranges exactly once: %s / %s" %
                         (printer, printed, console))
            elif printed or [line for line in console if line == error] != [error]:
                fail("D0CF00 on %X did not reject malformed input: %s / %s" % (printer, printed, console))
        # The level-0 handler retains the last range's bounds.
        m.break_at(0xf0c6)
        m.interrupt_key()
        triggered = m.run(instructions = 100)
        if triggered.kind != "breakpoint" or m.read(0x1a, 2) != b"\x00\x40":
            fail("D0CF00 on %X did not take the operator interrupt: %s %s old=%s" % (printer, triggered.kind, triggered.psw, binary.hex(m.read(0x18, 8))))
        m.clear_breaks()
        repeated = m.run(instructions = 500000)
        repeated_dump = m.output(printer)[len(registers) + len(printed):]
        if not repeated.psw.endswith("00F36C") or repeated_dump != expected_dump[-2:]:
            fail("D0CF00 on %X after the operator interrupt at %s printed %s" %
                 (printer, repeated.psw, repeated_dump[:6]))
        if show:
            address = ("000%X" % printer)[-3:]
            print("D0CF00 on %s preserved storage on card IPL, printed both console ranges and repeated the last range after the operator interrupt" % address)
            print("\n".join(registers + printed))

def start_1052(tape, section, prompt):
    m = machine(tape)
    m.ipl(0x130)
    start = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,00E,130/L" + section + "/B",
                budget = 90000000, step = 20000, stop = prompt, show = False)
    if start["ended"] != "stop" or start["errors"]:
        fail("D%s: 1052 diagnostic did not reach its operator prompt" % section)
    return m

def check_1052_operator(tape, show = False):
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
    if show:
        print("\n".join(m.screens(0x01f)))
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
    if show:
        print("\n".join(m.screens(0x01f)))
    check_job(m, "D66531", ["T   D66531 08 ROUTINES RUN"])

def check_d66542_operator(tape, mode):
    m = machine(tape)
    m.ipl(0x130)
    m.break_at(0x811a)
    start = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,01F,130/L6654/B",
                budget = 30000000, step = 100000, show = False, handle_operator = lambda m, line, section: None)
    if start["ended"] != "breakpoint" or start["errors"] or m.read(0x8000, 3) != b"\xd6\x65\x42":
        fail("D66542 did not reach its first console selection (%s %s, preface %s)" %
             (start["ended"], start["run"].psw, binary.hex(m.read(0x8000, 4))))
    m.clear_breaks()
    if mode != "cancel-original":
        # D6654200.SPT statements 78, 85, 89, 106 and 120 test a
        # single status bit. Mask 1 takes the branch when the bit is set.
        for address, target in [(0x8168, "F1E4"), (0x8184, "F1C4"), (0x8194, "F118"), (0x81c8, "F0E8"), (0x81fc, "F208")]:
            faa_correction(m, address, "4740" + target, "4710" + target)
    m.trace_io(skip = [0x130, 0x00c, 0x00e], quiet_polls = True)

    if mode.startswith("cancel"):
        wait_1052_read(m)
        m.type(0x01f, "CANCELED", cancel = True)
        stopped = m.run(instructions = 600000)
        endings = [event.split("interrupt 001F csw ", 1)[1].split()[0]
                   for event in m.events() if "interrupt 001F csw " in event]
        if endings != ["000082A0090000F8", "0000000004000000"]:
            fail("D66542 CANCEL ending status: %s" % endings)
        reading = "blocked=true" in m.subchannel(0x01f)
        if mode == "cancel-original":
            if reading or not stopped.psw.endswith("00813A") or m.read(0x8184, 4) != b"\x47\x40\xf1\xc4":
                fail("D66542 original CANCEL did not reproduce the missed restart")
            print("D66542 original CANCEL received Unit Exception and Device End but left the keyboard locked.")
            return
        if not reading:
            fail("D66542 did not reopen the keyboard after CANCEL (%s)" % stopped.psw)
        m.type(0x01f, "VALID")
        m.run(instructions = 12000000)
        check_job(m, "D66542", ["T   D66542 02 ROUTINES RUN"])
        writes = [event.split("001F cmds [89 ", 1)[1].split("]", 1)[0]
                  for event in m.events() if "001F cmds [89 " in event]
        if writes != ["n=5 st=0C E5C1D3C9C4"]:
            fail("D66542 did not echo exactly the replacement input: %s" % writes)
        print("D66542 canceled one inquiry, echoed the replacement text and completed both routines.")
        return

    not_ready = mode == "not-ready"
    sense, status = ("40", "0200") if not_ready else ("10", "0A00")
    if not_ready:
        m.key(0x01f, "NOT READY")
    else:
        wait_1052_read(m)
        m.break_at(0x8200)
        m.type(0x01f, "BAD", parity_error = True)
        pending = m.run(instructions = 100000)
        if pending.kind != "breakpoint" or m.read(0x8344, 4) != b"\x0a\x00\x00\xfd":
            fail("D66542 did not wait for Device End after the keyboard parity check")
        m.clear_breaks()
    m.break_at(0x8218)
    sensed = m.run(instructions = 3000000)
    if sensed.kind != "breakpoint" or m.read(0x834a, 1) != binary.decode(sense, "hex"):
        fail("D66542 did not receive sense %s (%s %s)" % (sense, sensed.kind, sensed.psw))
    if not not_ready:
        endings = [event.split("interrupt 001F csw ", 1)[1].split()[0]
                   for event in m.events() if "interrupt 001F csw " in event]
        if endings != ["000082A00A0000FD", "0000000004000000", "000082B00C000000"]:
            fail("D66542 keyboard parity status sequence: %s" % endings)
    m.clear_breaks()
    if not_ready:
        m.key(0x01f, "READY")
    m.run(instructions = 35000000)
    lines = [line.strip() for line in m.screens(0x01f)]
    if (lines[-2:] != ["T   D66542 02 ROUTINES RUN", END_OF_JOB] or
        [line for line in lines if line.startswith("* ")] != ["* SD0 D66542 01 00822E 01F"] or
        "SENSE IS " + sense not in lines or "STATUS IS " + status not in lines):
        fail("D66542 did not report the injected console fault: %s" % lines[-10:])
    print("D66542 reported sense %s and status %s for the injected %s and reached SDM end of job." %
          (sense, status, "Not Ready condition" if not_ready else "keyboard parity fault"))

def printer_operator(m, line, section):
    if section == "D63514":
        if line.strip() == "MAKE NOT READY":
            m.key(0x00e, "NOT READY")
            return "made printer not ready"
        if line.strip() == "MAKE UNAVAILABLE":
            m.key(0x00e, "UNAVAILABLE")
            return "made printer unavailable"
        if line.strip() == "MAKE AVAILABLE, RESTORE, READY":
            for key in ["AVAILABLE", "RESTORE", "READY"]:
                m.key(0x00e, key)
            return "made printer available, restored carriage, and readied printer"
    return operator(m, line, section)

def observe_printer_carriage(observations):
    def handle(m, line, section):
        prompt = line.strip()
        if section == "D63514" and (prompt.startswith("OBSERVE") or prompt == "END OF RTN"):
            observations.append(m.carriage_position(0x00e))
        return printer_operator(m, line, section)
    return handle

def tape_ring_operator(m, line, section):
    if section == "D405E1":
        if "REMOVE FILE PROT RINGS" in line:
            m.key(0x3f0, "REMOVE FILE PROTECT RING")
            return "removed file protect ring from 3F0"
        if "AFTER REPLACING FP RINGS" in line:
            m.key(0x3f0, "INSERT FILE PROTECT RING")
            return "replaced file protect ring on 3F0"
    return operator(m, line, section)

def finish_d63564_reset(m, events, input_device):
    endings = [event.split("interrupt 000E csw ", 1)[1].split()[0]
               for event in events if "interrupt 000E csw " in event]
    if (endings != ["00008D7008000000", "0000000004000000"] or
        m.read(0x8040, 8) != binary.decode("00008D700C000000", "hex") or m.read(0x8004, 4) != bytes([0] * 4)):
        fail("D63564 did not preserve both separated printer endings after the switch reset: %s" % endings)
    # The current section CSW merges the two interrupts recorded while
    # the monitor read the reset message. Continue via its existing
    # Device End completion path only after verifying that sequence.
    faa_correction(m, 0x87d4, "0AD0A001", "47F0F82A")
    m.clear_breaks()
    m.trace_io(on = False)
    m.run(instructions = 120000000)
    check_job(m, "D63564", ["CHAN 9 DETECTED OK", "CHAN 12 DETECTED OK", "T   D63564 03 ROUTINES RUN"], halts = 1)
    print("D63564 applied the %s reset and completed after separate Channel End and Device End interrupts" % input_device)

def check_d63564_reset(tape, mode):
    m = machine(tape)
    m.ipl(0x130)
    corrected = mode.endswith("-restored")
    card_input = mode.startswith("card")
    early = mode.startswith("card-early")
    assignment = "A,00C/I,01F,01F,01F,130" if card_input else "I,01F,01F,01F,130/W,00C"
    res = sdm(m, message = "E/A,01F/A,00E/" + assignment + "/SS6356.2/L6356/B",
              budget = 60000000, step = 100000, stop = "HLT D63564", show = not corrected)
    if res["ended"] != "stop" or res["errors"]:
        fail("D63564 did not reach the loop setup")
    m.run(instructions = 2000000)
    m.key(0x01f, "REQUEST")
    wait_1052_read(m)
    m.type(0x01f, "I,00C,01F,01F,130/B" if card_input else "B")
    m.run(instructions = 12000000 if early else 20000000)
    if card_input:
        reader = m.reader_stackers(0x00c)
        m.cards(0x00c, ["RS6356.2/"], replace = True, ready = False)
        if "pending=false" not in m.subchannel(0x00c):
            fail("loading the card unexpectedly posted reader status")
        m.trace_io(skip = [0x130, 0x01f])
        m.interrupt_key()
        m.run(instructions = 180000)
        ends = [e for e in m.events() if "interrupt 000C csw " in e or "interrupt 000E csw " in e]
        card_end = [e.split(" csw ")[1].split()[0] for e in ends if "interrupt 000C " in e]
        if card_end != ["000002F008000000", "0000000004000000"]:
            fail("D63564 did not observe both card-read endings: " + str(card_end))
        if corrected:
            m.break_at(0x87cc)
            stop = m.run(instructions = 35000000)
            if (stop.kind != "breakpoint" or m.reader_stackers(0x00c)[0] != reader[0] + 1 or
                "RS6356.2/" not in [line.strip() for line in m.screens(0x01f)]):
                fail("D63564 did not reach the recovered printer status after applying the card")
            finish_d63564_reset(m, ends, "card")
            return
        m.trace_io(on = False)
        m.run(instructions = 120000000)
        lines = [line.strip() for line in m.screens(0x01f)]
        if m.reader_stackers(0x00c)[0] != reader[0] + 1 or m.read(0x8004, 4) != bytes([0] * 4) or "RS6356.2/" not in lines:
            fail("SDM did not read and apply the reset card")
        if early:
            if "DEVICE END" not in lines or END_OF_JOB in lines:
                fail("D63564 did not reproduce the early card release error")
        else:
            check_job(m, "D63564", ["CHAN 9 DETECTED OK", "CHAN 12 DETECTED OK", "T   D63564 03 ROUTINES RUN"], halts = 1)
        print("\n".join(ends + lines[-6:]))
        return
    m.trace_io(skip = [0x130, 0x01f, 0x00c])
    m.key(0x01f, "REQUEST")
    wait_1052_read(m)
    channel_end = [e for e in m.events() if "002026 interrupt 000E csw 00008D7008000000" in e]
    if len(channel_end) != 1 or binary.hex(m.read(0x40, 8)) != "00008d7008000000":
        fail("D63564 late reset did not deliver Channel End during console input")
    m.break_at(0x87cc)
    m.type(0x01f, "RS6356.2/")
    result = m.run(instructions = 35000000)
    device_end = [e for e in m.events() if "002026 interrupt 000E csw 0000000004000000" in e]
    if (result.kind != "breakpoint" or result.psw[-8:] != "B00087CC" or
        binary.hex(m.read(0x40, 8)) != "0000000004000000" or len(device_end) != 1 or
        m.read(0x8004, 4) != bytes([0] * 4)):
        fail("D63564 late reset did not return to the reported Device End check")
    if corrected:
        finish_d63564_reset(m, m.events(), "console")
        return
    print(channel_end[0])
    print(device_end[0])
    m.clear_breaks()
    m.trace_io(on = False)
    m.run(instructions = 120000000)
    lines = [line.strip() for line in m.screens(0x01f)]
    if ([line for line in lines if line.startswith("* ")] != ["* SD0 D63564 03 0087DC 00E"] or
        "DEVICE END" not in lines):
        fail("D63564 late reset: %s\n%s" % (m.psw(), "\n".join(lines[-14:])))
    print("\n".join(lines[-8:]))
    print("D63564 late reset: %s, EOJ=%s, %s" % (m.psw(), END_OF_JOB in lines, m.subchannel(0x00e)))
    return

def check_d63534_dualing(tape):
    m = machine(tape, printer_dualing = True)
    m.ipl(0x130)
    m.break_at(0x8e20)
    result = sdm(m, message = "E/A,01F/A6312000E/I,01F,01F,01F,130/W,00C/L6353/B",
                  budget = 150000000, step = 100000, show = False)
    if result["ended"] != "breakpoint" or result["errors"]:
        fail("D63534 did not reach the first dualing print: %s %s" % (result["run"].psw, result["errors"]))
    pair = "00008FF8080000000000000004000000"
    if m.read(0x8ff8, 16) != binary.decode(pair, "hex") or m.registers().gr[14:] != ["00009000", "00008000"]:
        fail("D63534's expected CSWs or their base registers changed")
    faa_correction(m, 0x9fe0, "00" * 16, pair)
    faa_correction(m, 0x8e2e, "FFF8", "EFE0")
    faa_correction(m, 0x8e44, "FFF8", "EFE0")
    m.clear_breaks()
    start = len(m.output(0x00e))
    m.run(instructions = 150000000)
    check_job(m, "D63534", ["T   D63534 08 ROUTINES RUN"])
    impressions = m.output(0x00e)[start:start + 2]
    if impressions != ["%<#@", "%<#@"]:
        fail("D63534 dualing did not print identical translated and untranslated inputs: %s" % impressions)
    print("D63534 verified both dualing prints and their Device End comparisons")


def check_d805e4_background(tape, mdm = False):
    # D805E400.SPT specifies BALL after the monitor and control-unit tests.
    restored = diagnostic_reel(tape, "D805E4", [
        (0x238, "4740F292", "4710F292"),
        (0x2a2, "4740F2A8", "4710F2A8"),
    ])
    m = faa_mdm(restored) if mdm else machine(restored)
    for device, label in [(0x340, "D805E4"), (0x341, "SEEK")]:
        m.dasd(device, type = "2314", cylinders = 203, volser = label)
    warning = "WARNING  340 IS THE WRITE-READ FILE. ENTER B/ TO CONTINUE"
    m.event_limit(65536)
    m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e, 2], quiet_polls = True)
    if mdm:
        m.console(2, type = "1052")
        ready = m.run(instructions = 35000000)
        if ready.psw != SDM_READY:
            fail("D805E4 MDM did not wait for an operator request")
        m.key(2, "REQUEST")
        m.run(instructions = 10000000)
        if "MDM D/E REVISION 0A READY CD017 SIMPLEX" not in [line.strip() for line in m.screens(2)]:
            fail("D805E4 MDM did not prompt for a load message")
        m.type(2, "A32/A80000340/A80000341/L805E,340,341/B/")
        m.run(instructions = 50000000)
        before = [line.strip() for line in m.screens(2)]
        if warning not in before or before[-1:] != ["HLT D805E4"]:
            fail("D805E4 MDM did not ask to continue the read/write workload: %s" % before[-14:])
        m.key(2, "REQUEST")
        m.run(instructions = 10000000)
        m.type(2, "B/")
        m.run(instructions = 250000000)
        after = [line.strip() for line in m.screens(2)[len(before):]]
        if (after[-2:] != ["T CE1  001      D805E4", "EOJ  MDM JOB COMPLETE"] or
            any([line.startswith(("*", "HLT ", "RNV ")) for line in after])):
            fail("D805E4 did not complete the MDM workload: %s" % after[-14:])
        check_d805e4_disk_activity(m, "MDM")
        return

    m.ipl(0x130)
    result = sdm(m, message = "E/A,01F/A80000340/A80000341/I,01F,01F,01F,130/L805E/B",
                 budget = 1250000000, step = 1000000, show = False)
    reports = [line.strip() for line in result["transcript"]]
    if (result["ended"] != "end-of-job" or result["skipped"] or result["errors"] or
        [(entry["section"], entry["routines"]) for entry in result["sections"]] != [("D805E4", "01")] or
        warning not in reports):
        fail("D805E4 did not complete the dual-drive workload: %s %s" % (result["run"].psw, reports[-14:]))
    check_d805e4_disk_activity(m, "SDM")

def check_d805e4_disk_activity(m, monitor):
    events = m.events()
    if not events or len(events) >= 65536:
        fail("D805E4 I/O trace reached its limit")
    commands = {}
    for event in events:
        if ("SIO 0341 " in event or "resume 0341 " in event) and "cmds [" in event:
            for command in event.split("cmds [", 1)[1].split("] ->", 1)[0].split("]["):
                commands[command[:2]] = commands.get(command[:2], 0) + 1
    usage = m.dasd_usage()
    if (commands != {"07": 500, "1A": 500} or
        usage[0x340]["read"] != [(3900, 3919)] or usage[0x340]["written"] != [(3900, 3919)] or
        usage[0x341]["read"] or usage[0x341]["written"]):
        fail("D805E4 disk activity differed: 341 commands=%s, 340 read=%s, written=%s" %
             (commands, usage[0x340]["read"], usage[0x340]["written"]))
    print("D805E4 %s read and wrote all 20 tracks on cylinder 195 of 340 and completed 500 seek-and-check pairs on 341" % monitor)

def check_d80683_retry(tape, mdm = False):
    m = faa_mdm(tape) if mdm else machine(tape)
    console, base = (2, 0x13000) if mdm else (0x01f, 0x8000)
    for slot in range(9):
        m.dasd(0x340 + slot, type = "2314", cylinders = 203, volser = "SLOT%d" % slot)
        if slot:
            m.key(0x340 + slot, "REMOVE ID PLUG")
    if mdm:
        m.console(console, type = "1052")
        if m.run(instructions = 35000000).psw != SDM_READY:
            fail("MDM D80683 did not wait for the operator")
        m.key(console, "REQUEST")
        m.run(instructions = 10000000)
        if "MDM D/E REVISION 0A READY CD017 SIMPLEX" not in [line.strip() for line in m.screens(console)]:
            fail("MDM D80683 did not prompt for a load message")
        m.type(console, "A32/A80000340/L8068,340/SS8068.14.1/B/")
        m.break_at(base + 0x1098)
        mismatch = m.run(instructions = 150000000)
    else:
        m.ipl(0x130)
        m.break_at(base + 0x1098)
        selection = sdm(m, message = "E/A,01F/A,00E/A80000340/I,01F,01F,00E,130/SS8068.14.1/L8068/B",
                        budget = 150000000, step = 100000, show = False)
        mismatch = selection["run"]
    reports = [line.strip() for line in m.screens(console)]
    if (mismatch.kind != "breakpoint" or
        not all([line in reports for line in ["PUT PLUG 0 IN PHYSICAL DRIVE A", "ERROR ON DRIVE B"]])):
        fail("D80683 did not report the deliberate drive B mismatch: %s" % reports[-12:])

    m.clear_breaks()
    # Retry at LA/ST to recreate the Sense CAW after monitor output.
    faa_correction(m, base + 0x1098, "4710D004", "4710FFFC")
    m.move_2314_plug(0x340, 0x341)
    m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e, 2], quiet_polls = True)
    m.break_at(base + 0x101e)
    fixed = m.run(instructions = 8000000)
    sense_caw = ("00000000%x" % (base + 0xe8))[-8:].upper()
    sensed = [event for event in m.events()
              if "SIO 0340 caw " + sense_caw + " cmds [04 " in event and "000000400100" in event]
    if fixed.kind != "breakpoint" or not sensed or m.read(base + 4, 1) != b"\x40":
        fail("D80683 did not recover the drive B Sense comparison: %s %s" % (fixed.psw, m.screens(console)[-12:]))
    # Switch 1 deliberately keeps repeating after a successful comparison.
    m.alter(base + 4, b"\x00")
    m.clear_breaks()
    m.trace_io(on = False)
    for slot in range(2, 9):
        letter = "ABCDEFGHJ"[slot]
        prompt = "PUT PLUG 0 IN PHYSICAL DRIVE " + letter
        for _ in range(500):
            if prompt in [line.strip() for line in m.screens(console)]:
                break
            m.run(instructions = 100000)
        if prompt not in [line.strip() for line in m.screens(console)]:
            fail("D80683 did not request drive %s: %s" % (letter, m.screens(console)[-12:]))
        m.move_2314_plug(0x340, 0x340 + slot)
    m.run(instructions = 100000000)
    reports = [line.strip() for line in m.screens(console)]
    expected_end = ["T CE1  002      D80683", "EOJ  MDM JOB COMPLETE"] if mdm else ["T   D80683 02 ROUTINES RUN", END_OF_JOB]
    expected_error = (["* D80683 06 014084 1 340"] if mdm else
                      ["* SD0 D80683 06 009084 340", "* SNS BYTE 4 RECVD 00", "* SNS BYTE 4 EXPTD X1"])
    errors = [line for line in reports if line.startswith(("*", "HLT ", "RNV "))]
    if (reports[-2:] != expected_end or errors not in [expected_error, expected_error * 2] or
        any([line.startswith("ERROR ON DRIVE ") and line != "ERROR ON DRIVE B" for line in reports])):
        fail("D80683 did not finish after the restored retry: %s %s" % (reports[-2:], errors))
    print("D80683 %s retried Sense, verified drives B through J, and reached end of job" % ("MDM" if mdm else "SDM"))

def check_d806a5_mdm_allocation(tape):
    records = archive.simh(library_reel(tape)).records
    payloads = [index + 1 for index, header in library_headers(records) if header[8:16] == "D806A500"]
    if len(payloads) != 1:
        fail("expected one D806A5 library section")
    payload = records[payloads[0]].data
    directory = archive.ibm9020_rld(records[payloads[0] + 1].data)
    if directory.id != 0xd806a503 or len(directory.entries) != 33:
        fail("unexpected D806A5 relocation dictionary")

    m = faa_mdm(tape)
    m.console(2, type = "1052")
    m.dasd(0x340, type = "2314", cylinders = 203, volser = "FAA902", read_only = True)
    m.run(instructions = 35000000)
    m.key(2, "REQUEST")
    wait_1052_read(m, device = 2)
    m.type(2, "A32/A80000340/L806A,340/D.001.041/B/")
    origin, old_base, base = 0x1000, 0x13000, 0x54000
    ready = "READY PACK OR POP ID PLUG"
    m.run(instructions = 12000000)
    if (ready not in [line.strip() for line in m.screens(2)] or
        m.read(base, 4) != b"\xd8\x06\xa5\x00" or
        m.read(base + 0x100, 8) != binary.decode("0000100000041000", "hex") or
        m.read(base + 0xbe8, 4) != binary.decode("08013BE0", "hex")):
        fail("MDM did not relocate D806A5 with the expected Define Storage range and stale channel chain")

    before = m.checkpoint()
    m.key(0x340, "REMOVE ID PLUG")
    m.key(0x340, "INSERT ID PLUG")
    m.run(instructions = 6000000)
    if (m.dasd_usage()[0x340]["read"] != [(0, 0)] or
        "ERROR NUMBER E101" not in [line.strip() for line in m.screens(2)]):
        fail("D806A5 stale-address control did not stop on the first track")
    m.restore(before)

    # CAMS55 rebases the initial PSW after moving the section. The other
    # constants still have the result of the original tape load at X'13000'.
    corrections = {}
    for entry in directory.entries:
        offset = entry.address - origin
        width = entry.width
        modulus = 1 << (8 * width)
        raw = int(binary.hex(payload.bytes(offset, width)), 16)
        sign = -1 if entry.subtract else 1
        stale = (raw + sign * (old_base - origin)) % modulus
        expected = (raw + sign * (base - origin)) % modulus
        actual = int(binary.hex(m.read(base + offset, width)), 16)
        if offset == 0x15:
            if actual != expected:
                fail("MDM did not rebase the D806A5 initial PSW")
        elif actual != stale or offset in corrections:
            fail("unexpected D806A5 address constant at offset %x" % offset)
        else:
            corrections[offset] = binary.decode(("0" * (width * 2) + "%x" % expected)[-width * 2:], "hex")
    if len(corrections) != 32:
        fail("unexpected number of stale D806A5 address constants")
    for offset, replacement in corrections.items():
        m.alter(base + offset, replacement)

    m.key(0x340, "REMOVE ID PLUG")
    m.key(0x340, "INSERT ID PLUG")
    for _ in range(40):
        m.run(instructions = 500000)
        lines = [line.strip() for line in m.screens(2)]
        if len([line for line in lines if line == ready]) == 2:
            break
    usage = m.dasd_usage()[0x340]
    if (lines[-1] != ready or "STARTING VOL ID FAA902 ON DRIVE 340" not in lines or
        "TOTAL OF 0000 BAD TRACKS" not in lines or usage["read"] != [(0, 4059)] or usage["written"] or
        any([line.startswith(("ERROR NUMBER", "HA RD")) for line in lines])):
        fail("relocated D806A5 did not scan the complete read-only pack: %s %s" % (usage["read"], lines[-10:]))

    m.key(2, "REQUEST")
    wait_1052_read(m, device = 2)
    m.type(2, "F/")
    end = m.run(instructions = 8000000)
    if end.kind != "disabled-wait" or "D806A TERMINATED REIPL TO CONTINUE" not in [line.strip() for line in m.screens(2)]:
        fail("relocated D806A5 did not terminate on F/: %s %s" % (end.kind, end.psw))
    print("D806A5 scanned 4060 read-only tracks after MDM Define Storage relocated it and its address constants were rebased")

def model50_diagnostic_machine(tape):
    m = emulator.s390(architecture = "s360", model = "50", memory = 128 << 10, mips = 1, start = "1985-08-30T12:00:00Z")
    m.console(0x01f, type = "1052")
    m.tape(0x130, tape, format = "simh", type = "2415", ring = False)
    m.tape(0x131, tape.slice(0, 0), format = "simh", type = "2415", ring = False)
    m.ipl(0x130)
    return m

def diagnostic_reel(tape, section, updates, expected_table = None):
    records = archive.simh(library_reel(tape)).records
    indices = [i for i, header in library_headers(records) if header[8:14] == section]
    if len(indices) != 1:
        fail("expected one %s tape section" % section)
    payload = records[indices[0] + 1]
    if expected_table != None:
        offset, table = expected_table
        if payload.data.bytes(offset, len(table)) != table:
            fail("unexpected %s original result table" % section)
    reel = binary.builder(capacity = tape.size)
    copied = 0
    for offset, original, replacement in updates:
        original, replacement = binary.decode(original, "hex"), binary.decode(replacement, "hex")
        position = payload.offset + 4 + offset
        if position < copied or len(original) != len(replacement) or payload.data.bytes(offset, len(original)) != original:
            fail("unexpected %s bytes for reel correction at record offset %x" % (section, offset))
        reel.append(tape.bytes(copied, position - copied))
        reel.append(replacement)
        copied = position + len(original)
    reel.append(tape.bytes(copied, tape.size - copied))
    return reel.file()

def restore_d11792_storage_keys(tape):
    # The pinned D11792 omits the acceptance of a zero storage key after
    # a successful TS. Restore it from the FAA listing's routines 10, 11,
    # 14 and 15. R9 already holds the masked PSW key for the error report
    # and, with fetch protection, R8 holds the masked storage key.
    return diagnostic_reel(tape, "D11792", [
        (0x620, "18215420FF301837", "12374780F6DA1829"),
        (0x764, "18215420FF301837", "12374780F81A1829"),
        (0x9e6, "5910FF144780FAAA18215420FF301837", "12994780FAAA12884780FAAA18291837"),
        (0xb42, "5910FF144780FC0618215420FF301837", "12994780FC0612884780FC0618291837"),
    ])

def check_model65_channel(tape):
    # Keep the original channel programs and comparisons. Routines 55/56
    # compare against untouched zero storage after a protection check, and
    # routines 57/61 expect protection check on the protected CCW fetch.
    reel = diagnostic_reel(tape, "D30542", [
        (0x1a46, "4190E72C", "41901F80"),  # R1 = X'A000'
        (0x1a54, "0C000000", "0C100000"),
        (0x1adc, "41901800", "41901F80"),
        (0x1b04, "0C000000", "0C100000"),
        (0x1c04, "00200000", "00100000"),
        (0x1f64, "00200000", "00100000"),
    ], expected_table = (0x2f80, b"\x00" * 40))
    reel = diagnostic_reel(reel, "D31544", [
        (0x2068, "41901C40", "41904F80"),  # R4 = X'A000'
        (0x2078, "0C000000", "0C100000"),
        (0x210a, "41904800", "41904F80"),
        (0x213c, "0C000000", "0C100000"),
        (0x2200, "00300000", "00100000"),
        (0x25d4, "00300000", "00100000"),
    ], expected_table = (0x2f80, b"\x00" * 80))
    # D3052100.SPT XSTATB. Start I/O accepts the reader's pending Device
    # End with Busy set (GA22-6821-8, Start I/O condition 2).
    reel = diagnostic_reel(reel, "D30521", [(0x994, "0400", "1400")])
    # Type A selects the Model 65 SSM expectation. The 9020 jobs cover
    # D31534 and the seven D30533 routines that require MACH storage.
    for punch, scratch, assignments, selection, expected, required in [
        (True, [], "A,00E/A6B00000D/", "L3051/L3052/L3054",
         [("D30511", "0C"), ("D30521", "08"), ("D30542", "29")], []),
        (True, [], "A6B00000D/", "L3053", [("D30533", "10")],
         ["ROUTINES 17 TO 23 BYPASSED (PRINTER NOT ASSIGNED TO SECTION BY DM)"]),
        (False, [0x3f0, 0x3f1], "A400003F0/A400003F1/", "L3151.3152/L3154",
         [("D31512", "0D"), ("D31522", "09"), ("D31544", "2B")], []),
    ]:
        m = machine(reel, model = "65", punch = punch, scratch_tapes = scratch)
        m.ipl(0x130)
        result = sdm(m, message = "A/A,01F/" + assignments + "I,01F,01F,01F,130/" + selection + "/B",
                     budget = 300000000, step = 100000, blank = 150 if punch else 20, show = False)
        actual = [(section["section"], section["routines"]) for section in result["sections"]]
        transcript = [line.strip() for line in result["transcript"]]
        if (result["ended"] != "end-of-job" or result["errors"] or result["skipped"] or actual != expected or
            any([line not in transcript for line in required])):
            fail("Model 65 channel %s failed: %s, %s, %s, %s" %
                 (selection, result["ended"], actual, result["skipped"], transcript[-12:]))
        print("Model 65 channel %s completed %s under type-A SDM" %
              (selection, ", ".join([section + " (" + routines + " routines)" for section, routines in actual])))

def check_d635f2_device_end(tape):
    for switches, commands, character in [
        ("00000000", ["09"] + ["01"] * 9 + ["09"], None),
        ("00000004", ["09"] * 11, None),
        ("00000001", ["09"] * 11, "H"),
        ("0000C102", ["09"] * 11, "A"),
    ]:
        m = machine(tape)
        m.carriage_tape(0x00e, [[1]] + [[]] * 65)
        m.ipl(0x130)
        m.trace_io(skip = [0x130, 0x01f, 0x00c], quiet_polls = True)
        m.break_at(0x817a)
        load_card = "E/A,01F/A,00E/I,01F,01F,01F,130/S635F." + switches + "/L635F/B"
        entry = sdm(m, message = load_card, budget = 20000000, step = 100000, show = False)
        if (entry["ended"] != "breakpoint" or entry["errors"] or entry["skipped"] or
            m.read(0x8000, 8) != binary.decode("D635F201" + switches, "hex") or m.read(0x8044, 1) != b"\x08"):
            fail("D635F2 did not reach the expected Channel End: %s %s" % (entry["ended"], entry["run"].psw))
        m.clear_breaks()
        m.run(instructions = 1)
        m.break_at(0x817a)
        de = m.run(instructions = 2000000)
        if de.kind != "breakpoint" or m.read(0x8044, 1) != b"\x04":
            fail("D635F2 did not receive Device End separately: %s %s" % (de.kind, de.psw))
        m.clear_breaks()
        if switches == "00000000":
            before = m.checkpoint()
            original = m.run(instructions = 1)
            if original.psw[-6:] != "00817E":
                fail("D635F2 original branch did not return to the wait path")
            m.run(instructions = 10000000)
            check_job(m, "D635F2", ["T   D635F2 01 ROUTINES RUN"])
            if len(m.output(0x00e)) != 1:
                fail("D635F2 original branch did not time out after one impression")
            m.restore(before)
        # D635F200.SPT 97–99. Reach CONT on Device End (TM CC3).
        faa_correction(m, 0x817a, "4740F182", "4710F182")
        m.run(instructions = 1)
        if m.psw()[-6:] != "008182":
            fail("D635F2 corrected Device End did not continue printing")
        for _ in commands[1:]:
            m.break_at(0x8182)
            next_line = m.run(instructions = 2000000)
            if next_line.kind != "breakpoint" or m.read(0x8044, 1) != b"\x04":
                fail("D635F2 stopped printing before Device End: %s %s" % (next_line.kind, next_line.psw))
            m.clear_breaks()
            m.run(instructions = 1)
        impressions = [event.split(" cmd ")[1][:2] for event in m.events() if "printer 000E impression " in event]
        output = m.output(0x00e)
        carriage = m.carriage_position(0x00e).line
        advances = len([command for command in commands if command == "09"])
        if (impressions != commands or len(output) != len(commands) or carriage != 1 + advances or
            character != None and output != [character * 132] * len(commands)):
            fail("D635F2 incorrect impressions or spacing: %s, %d lines, carriage at %d" % (impressions, len(output), carriage))
        m.key(0x00e, "NOT READY")
        m.run(instructions = 5000000)
        check_job(m, "D635F2", ["T   D635F2 01 ROUTINES RUN"])
        if m.output(0x00e) != output:
            fail("D635F2 printed after the operator stopped the 1403")
        print("D635F2 switches %s printed %d impressions with %d line advances, then stopped and reached EOJ" %
              (switches, len(commands), advances))

def check_model50_cpu(tape, system):
    records = archive.simh(library_reel(tape)).records
    # Redirect only routine 85's compare/report operands to APK1 and
    # replace routine 90's expected product with the 2050G result.
    restored = diagnostic_reel(tape, "D11020", [
        (0x5bf0, "D500F2E0F238", "D500F2E0F480"),
        (0x5c04, "D200FFE8F238", "D200FFE8F480"),
        (0x6efa, "2325752C", "0025752C"),
    ], expected_table = (0x480, binary.decode("1C2D3C4D5C6D7C8D", "hex")))
    m = model50_diagnostic_machine(restored)
    result = sdm(m, message = system + "/A,01F/I,01F,01F,01F,130/L1100.119F/B",
                 budget = 2000000000, step = 100000, show = False, console_input = True)
    expected = [header[8:14] for _, header in library_headers(records) if header[8:14].startswith("D11")]
    if (len(expected) != 63 or result["ended"] != "end-of-job" or result["errors"] or result["skipped"] or
        [section["section"] for section in result["sections"]] != expected or
        any([not section["routines"] or section["routines"] == "00" for section in result["sections"]])):
        fail("Model 50 system %s CPU suite did not pass: %s, %d sections, %s" %
             (system, result["ended"], len(result["sections"]), result["errors"]))
    print("Model 50 system %s completed 63 CPU sections with model-specific decimal expectations" % system)

LATE_EOT_DRIVES = {
    "2415-nrzi": ("2415", 0, 9, "00"),
    "2415-pe": ("2415", 0, 9, "0C"),
    "2415-seven": ("2415", 0, 7, "01"),
    "2401-4": ("2401", 4, 9, "0C"),
    "2401-5": ("2401", 5, 9, "0C"),
    "2401-6": ("2401", 6, 9, "0C"),
    "2420-7": ("2420", 0, 9, "0C"),
}

def check_d405e1_late_eot(tape, drive):
    tape_type, model, tracks, option = LATE_EOT_DRIVES[drive]
    m = machine(tape)
    m.tape(0x3f0, tape.slice(0, 0), type = tape_type, model = model, tracks = tracks,
           pe_only = option == "0C", eot_inches = 600)
    m.ipl(0x130)
    m.event_limit(8192)
    m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
    trace_anchor = m.events()[0]

    def operator_for_drive(machine, line, section):
        if line.strip() == "S   D405E1":
            # The final backspace moves over one record beyond the
            # reflector. These transports retain Tape Indicate there.
            faa_correction(machine, 0x88bc, "08000400", "08002500")
        return tape_ring_operator(machine, line, section)

    result = sdm(m, message = "E/A,01F/A40" + option + "03F0/I,01F,01F,01F,130/SS405E.5.7/L405E/B",
                 budget = 100000000, step = 100000, show = False, handle_operator = operator_for_drive)
    if (result["ended"] != "end-of-job" or result["errors"] or result["skipped"] or
        [(s["section"], s["routines"]) for s in result["sections"]] != [("D405E1", "05")] or
        any(["SKIP-SNSW" in line for line in result["transcript"]])):
        fail("D405E1 %s did not finish both EOT and ring checks: %s %s" % (drive, result["ended"], result["errors"]))
    events = m.events()
    erases = [i for i, event in enumerate(events) if "0088C0 SIO 03F0 " in event and "cmds [17 " in event]
    if not events or events[0] != trace_anchor or len(erases) != 1:
        fail("D405E1 %s final erase trace was incomplete" % drive)
    before = [event for event in events[:erases[0]] if "SIO 03F0 " in event and "cmds [" in event]
    after = [event for event in events[erases[0] + 1:] if "interrupt 03F0 csw " in event]
    if (not before or "cmds [27 " not in before[-1] or not after or
        "interrupt 03F0 csw 0000000025000000" not in after[0]):
        fail("D405E1 %s did not retain Tape Indicate after backspacing beyond the reflector: %s" % (drive, after[:2]))
    print("D405E1 %s retained Tape Indicate after one backspace and completed both EOT and ring checks" % drive)

def position_2415_peer_reels(m):
    size = b"\x50\xc3\x00\x00"
    data = binary.decode("25" * 50000, "hex")
    for drive, count in [(0x3f0, 16), (0x3f1, 12)]:
        scratch = binary.builder(capacity = (len(data) + 8) * count + 4)
        for _ in range(count):
            scratch.append(size)
            scratch.append(data)
            scratch.append(size)
        scratch.append(b"\x00\x00\x00\x00")
        m.tape(drive, scratch.file(), type = "2415", format = "simh")
    # Issue Forward Space File on each reel and poll Test I/O until it
    # ends before IPL clears this setup program and loads the original reel.
    m.storage_load([
        (0, binary.decode("0000000000000800", "hex")),
        (0x48, binary.decode("00000200", "hex")),
        (0x200, binary.decode("3f00020000000001", "hex")),
        (0x800, binary.decode("9c0003f09d0003f0477008049c0003f19d0003f14770081082000820", "hex")),
        (0x820, binary.decode("0002000000000818", "hex")),
    ])
    ready = m.run(instructions = 150000000)
    positions = [m.tape_position(drive).position for drive in [0x3f0, 0x3f1]]
    if ready.kind != "disabled-wait" or positions != [17, 13]:
        fail("2415 scratch positioning failed: %s %s, positions %s" % (ready.kind, ready.psw, positions))

def check_d40604_scope(tape):
    m = machine(tape)
    m.tape(0x3f0, tape.slice(0, 0), type = "2415")
    m.ipl(0x130)
    m.break_at(0x8e28)
    start = sdm(m, message = "E/A,01F/A400003F0/I,01F,01F,01F,130/SS4060.0.3/L4060/B",
                budget = 100000000, step = 100000, show = False)
    stopped = start["run"]
    if m.read(0x8004, 4) != b"\x90\x00\x00\x00":
        fail("D40604 did not receive switches 0 and 3 from SDM")
    loops = [(1, 0x8e28, 0x8c22), (2, 0x951e, 0x8e4c), (3, 0x969e, 0x955c), (4, 0x978a, 0x96c6)]
    for index, (routine, test_pc, repeat_pc) in enumerate(loops):
        if (stopped.kind != "breakpoint" or int(stopped.psw[-6:], 16) != test_pc or
            m.read(test_pc, 4) != b"\x91\x80\xf0\x04"):
            fail("D40604 did not reach routine %d's switch test: %s %s" % (routine, stopped.kind, stopped.psw))
        m.alter(0x8004, b"\x90")
        m.clear_breaks()
        m.break_at(repeat_pc)
        taken = m.run(instructions = 2)
        if taken.kind != "breakpoint" or int(taken.psw[-6:], 16) != repeat_pc:
            fail("D40604 routine %d did not take the return: %s %s" % (routine, taken.kind, taken.psw))
        m.clear_breaks()
        m.break_at(test_pc)
        repeated = m.run(instructions = 1000000000)
        if repeated.kind != "breakpoint" or int(repeated.psw[-6:], 16) != test_pc or m.read(0x8004, 1) != b"\x90":
            fail("D40604 did not repeat routine %d with switch 0 held: %s %s" % (routine, repeated.kind, repeated.psw))
        m.alter(0x8004, b"\x10")
        m.clear_breaks()
        m.break_at(test_pc + 8)
        exit_path = m.run(instructions = 2)
        if exit_path.kind != "breakpoint" or int(exit_path.psw[-6:], 16) != test_pc + 8 or m.read(test_pc + 8, 2) != b"\x0a\xd6":
            fail("D40604 did not reach SVC D6 after clearing switch 0")
        print("D40604 %X repeated at %X with switch 0 on and exited via %X after panel STORE" % (test_pc, repeat_pc, test_pc + 8))
        m.clear_breaks()
        if index + 1 < len(loops):
            m.break_at(loops[index + 1][1])
            stopped = m.run(instructions = 1000000000)
    m.run(instructions = 150000000)
    check_job(m, "D40604", ["T   D40604 07 ROUTINES RUN"])
    print("D40604 reached SDM end of job after the last panel STORE")


def check_d40604_creep_loop(tape, sweeps, tracks, converter, reuse_mark = False):
    m = machine(tape)
    m.tape(0x3f0, tape.slice(0, 0), type = "2415", tracks = tracks, converter = converter)
    m.ipl(0x130)
    m.break_at(0x955c)
    run = sdm(m, message = "E/A,01F/A400003F0/I,01F,01F,01F,130/SS4060.3/L4060/B",
              budget = 1200000000, step = 1000000, show = False)
    if run["ended"] != "breakpoint" or run["errors"]:
        fail("D40604 did not reach the creep test: %s" % run["run"].psw)
    first = m.tape_position(0x3f0)
    following = []
    for index in range(first.next_mark + 1, first.record_count):
        record = m.tape_record(0x3f0, index = index)
        following.append("mark" if record == None else str(len(record)))
    m.clear_breaks()
    m.break_at(0x969e)
    normal = m.run(instructions = 150000000)
    if normal.kind != "breakpoint" or m.read(0x969e, 4) != b"\x91\x80\xf0\x04":
        fail("D40604 did not finish the first creep sweep: %s" % normal.psw)
    if reuse_mark:
        # Backspace one file through CMDIME before the usual loop branch.
        # The following Forward Space File can then reuse the same mark.
        faa_correction(m, 0xaff0, "00" * 10, "45B0F80C2F0447F0E55C")
        faa_correction(m, 0x96a2, "4710E55C", "4710DFF0")
    restart = m.tape_position(0x3f0)
    print("D40604 creep entry: %d of %d records, next mark %s" % (first.position, first.record_count, first.next_mark))
    print("D40604 records following the initial mark:", ", ".join(following))
    print("D40604 creep restart: %d of %d records, next mark %s" % (restart.position, restart.record_count, restart.next_mark))
    m.alter(0x8004, b"\x90")
    for sweep in range(2, sweeps + 1):
        m.clear_breaks()
        m.break_at(0x955c)
        loop = m.run(instructions = 30000000 if reuse_mark else 2)
        if loop.kind != "breakpoint":
            fail("D40604 did not branch back into the creep test: %s %s" % (loop.kind, loop.psw))
        if reuse_mark:
            positioned = m.tape_position(0x3f0)
            if positioned.position != first.next_mark or positioned.next_mark != first.next_mark:
                fail("D40604 did not backspace to the creep mark: %s" % positioned)
        if restart.next_mark == None and not reuse_mark:
            m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
        m.clear_breaks()
        m.break_at(0x95d6)
        replay = m.run(instructions = 50000000)
        registers = m.registers().gr
        if replay.kind != "breakpoint" or registers[9] != "00000019" or registers[2] != "00000000":
            if restart.next_mark == None:
                print("\n".join([event for event in m.events() if "cmds [3F " in event or "interrupt 03F0 " in event][-5:]))
            fail("D40604 creep sweep %d changed: %s, R2 %s, R9 %s" % (sweep, replay.psw, registers[2], registers[9]))
        m.clear_breaks()
        m.break_at(0x969e)
        repeated = m.run(instructions = 150000000)
        if repeated.kind != "breakpoint":
            fail("D40604 did not complete creep sweep %d: %s" % (sweep, repeated.psw))
        restart = m.tape_position(0x3f0)
        print("D40604 after sweep %d: %d of %d records, next mark %s" % (sweep, restart.position, restart.record_count, restart.next_mark))
    m.alter(0x8004, b"\x10")
    m.clear_breaks()
    m.run(instructions = 150000000)
    check_job(m, "D40604", ["T   D40604 07 ROUTINES RUN"])
    print("D40604 completed %d creep sweeps and reached EOJ after clearing switch 0" % sweeps)

def check_d40604_negative_creep(tape):
    m = machine(tape)
    m.tape(0x3f0, tape.slice(0, 0), type = "2415")
    m.ipl(0x130)
    m.break_at(0x9676)
    entry = sdm(m, message = "E/A,01F/A400003F0/I,01F,01F,01F,130/SS4060.3/L4060/B",
                budget = 1500000000, step = 1000000, show = False)
    if entry["ended"] != "breakpoint" or entry["errors"] or m.read(0x9676, 2) != b"\x18\x13":
        fail("D40604 did not reach the expected creep total conversion")
    m.clear_breaks()
    before = m.checkpoint()
    # Supply a negative scaled total at the conversion point after the
    # tape-motion steps. Both variants use the same measured prefix.
    m.alter_register(3, (-123000000) & 0xffffffff)
    m.break_program(1)
    fault = m.run(instructions = 2000000)
    if fault.kind != "program" or fault.detail != "program 0001 at 00009698":
        fail("D40604 negative-creep control did not execute the inline descriptor: %s %s" % (fault.kind, fault.detail))
    m.clear_breaks()
    m.restore(before)
    m.alter_register(3, (-123000000) & 0xffffffff)
    faa_correction(m, 0x968c, "47F0E698", "47F0E694")
    m.run(instructions = 150000000)
    check_job(m, "D40604", ["CREEP IS - 1.23 INCHES -LOWEST", "T   D40604 07 ROUTINES RUN"])
    print("D40604 printed the controlled negative creep value and reached end of job")

def check_d40604_velocity(tape):
    for model, option, early_drop in [(3, "30", "00.28"), (6, "3C", "00.29")]:
        m = machine(tape)
        m.tape(0x3f0, tape.slice(0, 0), type = "2401", model = model)
        m.ipl(0x130)
        result = sdm(m, message = "E/A,01F/A40" + option + "03F0/I,01F,01F,01F,130/SS4060.4/L4060/B",
                     budget = 300000000, step = 100000, show = False)
        if result["ended"] != "end-of-job" or result["errors"] or result["skipped"]:
            fail("D40604 Model %d did not reach end of job: %s at %s, console %s" %
                 (model, result["ended"], result["run"].psw, result["transcript"][-12:]))
        # The SIO-to-DE measurements differ by one microsecond on this profile.
        # D40604 truncates its ratio to one decimal place.
        velocity = [line.strip() for line in result["transcript"] if line.strip().startswith("FWD VEL IS ")]
        if velocity not in [["FWD VEL IS %s PERCENT OF BKWD VEL" % value] for value in ["0099.9", "0100.0"]]:
            fail("D40604 Model %d velocity comparison: %s" % (model, velocity))
        check_job(m, "D40604", ["MOD 3/6 EARLY DROP OF GO ON WRITE IS %s MS." % early_drop, "T   D40604 07 ROUTINES RUN"])
        print("D40604 Model %d measured %s and %s ms early Go drop and completed all seven routines" %
              (model, velocity[0], early_drop))

def check_d40604_go_drop(tape, model):
    m = machine(tape)
    m.tape(0x3f0, tape.slice(0, 0), type = "2401", model = model)
    m.ipl(0x130)
    compare = 0x8ea6
    m.break_at(compare)
    option = "30" if model == 3 else "3C"
    load_card = "E/A,01F/A40" + option + "03F0/I,01F,01F,01F,130/SS4060.3.4/L4060/B"
    run = sdm(m, message = load_card, budget = 150000000, step = 100000, show = False)
    if run["ended"] != "breakpoint" or run["errors"]:
        fail("D40604 did not reach the go-down routine: %s" % run["run"].psw)
    # D4060400 statement 1384, S 1,COUNT1.
    if m.read(compare, 4) != b"\x5b\x10\xd4\x9c" or m.registers().gr[13] != "0000A000":
        fail("unexpected D40604 count-comparison instruction or base register")
    samples = [[], []]
    go_down = []
    at = run["run"]
    for index in range(22):
        if at.kind != "breakpoint" or int(at.psw[-6:], 16) != compare:
            fail("D40604 did not reach the go-down comparison: %s" % at.psw)
        early = int(binary.hex(m.read(0x8112, 1)), 16) & 8 != 0
        samples[0 if early else 1].append((int(m.registers().gr[1], 16), int(binary.hex(m.read(0xa49c, 4)), 16)))
        if index in [0, 11]:
            event_start = len(m.events())
            m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
        if index in [1, 12]:
            m.trace_io(on = False)
            preceding_end = None
            for event in m.events()[event_start:]:
                if "interrupt 03F0 csw " in event and "0C000000 " in event:
                    preceding_end = int(event.split("tod=")[1], 16)
                elif "SIO 03F0 " in event and ("cmds [1F " in event or "cmds [3F " in event) and preceding_end != None:
                    now = int(event.split("tod=")[1], 16)
                    go_down.append(("minimum" if early else "20 ms", event.split("cmds [")[1][:2], now - preceding_end))
                    preceding_end = None
        m.clear_breaks()
        m.run(instructions = 1)
        if index < 21:
            m.break_at(compare)
            at = m.run(instructions = 20000000)
    if [len(rows) for rows in samples] != [11, 11]:
        fail("D40604 did not measure both go-down intervals: %s" % samples)
    if any([early[0] != settled[0] or early[1] <= settled[1] for early, settled in zip(samples[0], samples[1])]):
        fail("D40604 did not distinguish immediate from settled Read→FSF while keeping Write→WTM fixed: %s" % samples)
    for label, rows in zip(["minimum", "20 ms"], samples):
        print("Model %d D40604 at %X, %s (Write→WTM, Read→FSF) BCTR counts: %s" % (model, compare, label, rows))
    print("Model %d D40604 (pass, next CCW, microseconds from prior ending status to SIO): %s" % (model, go_down))

def continue_d40604_timing_error(m, operation, retry):
    m.clear_breaks()
    m.break_at(0x8b86)
    if m.run(instructions = 2).kind != "breakpoint":
        fail("D40604 did not take the timing-error print path with switch 7 clear")
    m.clear_breaks()
    m.run(instructions = 12000000)
    lines = [line.strip() for line in m.screens(0x01f)]
    if operation + " ERROR, LOOP OR B/ TO CHECK NEXT DRIVE." not in lines or lines[-1] != "HLT D40604 01 000400DA40008B8E":
        fail("D40604 did not halt after printing the timing error: %s" % lines[-8:])
    if retry:
        m.alter(0x8004, b"\x11")
    m.break_at(0x8b8e)
    m.key(0x01f, "REQUEST")
    wait_1052_read(m)
    m.type(0x01f, "B/")
    arrived = m.run(instructions = 20000000)
    if arrived.kind != "breakpoint" or m.read(0x8b8e, 8) != m.read(0x8b7e, 8):
        fail("D40604 did not reach the second switch decision after B/: %s" % arrived.psw)
    m.clear_breaks()

def check_d40604_error_loop(tape, mode):
    m = machine(tape)
    m.tape(0x3f0, tape.slice(0, 0), type = "2415")
    m.tape(0x3f1, tape.slice(0, 0), type = "2415")
    m.ipl(0x130)
    m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
    initial_switches = "SS4060.3.7/" if mode == "error-loop" else "SS4060.3/"
    m.break_at(0x8c18)
    result = sdm(m, message = "E/A,01F/A400003F0/A400003F1/I,01F,01F,01F,130/" + initial_switches + "L4060/B",
                 budget = 30000000, step = 100000, show = False)
    if result["run"].kind != "breakpoint" or m.registers().gr[12] != "000003F0":
        fail("D40604 did not start its timing routine: %s" % result["run"].psw)
    # Two marks precede the first timing record in the write chain.
    m.tape_write_checks(0x3f0, index = 2, count = 1)
    m.clear_breaks()
    m.break_at(0x8b7e)
    stop = m.run(instructions = 50000000)
    first_switch = b"\x11" if mode == "error-loop" else b"\x10"
    if (stop.kind != "breakpoint" or m.read(0x8004, 1) != first_switch or
        m.read(0x8b7e, 8) != b"\x91\x01\xf0\x04\x47\x10\xfc\x18" or
        not any(["interrupt 03F0 csw 000099700E000000" in event for event in m.events()])):
        fail("D40604 did not reach the timing decision after the injected write check: %s" % stop.psw)
    m.clear_breaks()
    if mode != "error-loop":
        continue_d40604_timing_error(m, "WRT ", retry = mode == "error-resume")
    if mode != "error-next":
        m.break_at(0x8c18)
        if m.run(instructions = 2).kind != "breakpoint" or m.registers().gr[12] != "000003F0":
            fail("D40604 did not restart timing on the same drive with switch 7 set")
        m.clear_breaks()
        m.break_at(0x8b7e)
        retry = m.run(instructions = 70000000)
        if (retry.kind != "breakpoint" or m.registers().gr[12] != "000003F0" or
            not any(["interrupt 03F0 csw 000099E00E000000" in event for event in m.events()])):
            fail("D40604 timing retry changed after the one-shot write check: %s" % retry.psw)
        m.alter(0x8004, b"\x10")
        print("D40604 %s returned to timing on 3F0 and encountered a read check on the damaged record" % mode)
        continue_d40604_timing_error(m, "READ", retry = False)
    m.break_at(0x8b96)
    if m.run(instructions = 2).kind != "breakpoint":
        fail("D40604 did not take the next-drive path with switch 7 clear")
    m.clear_breaks()
    m.break_at(0x8c18)
    next_drive = m.run(instructions = 20000000)
    if next_drive.kind != "breakpoint" or m.registers().gr[12] != "000003F1":
        fail("D40604 did not reach the timing routine on the second drive: %s" % next_drive.psw)
    m.clear_breaks()
    m.run(instructions = 1200000000)
    lines = [line.strip() for line in m.screens(0x01f)]
    expected_errors = ["* SD0 D40604 01 00830A", "* SD0 D40604 01 0083E0"]
    expected_errors += ["* SD0 D40604 01 008B88 3F0"] * (2 if mode == "error-resume" else 1)
    if END_OF_JOB not in lines or [line for line in lines if line.startswith("* ")] != expected_errors:
        fail("D40604 did not complete on the second drive after the expected errors: %s" % lines[-12:])
    print("D40604 honored B/ with switch 7 clear, tested 3F1, and reached SDM end of job")


def check_d40604_ready_change(m, message, repeat_drop):
    m.break_at(0x8194)
    start = sdm(m, message = message, budget = 30000000, step = 100000, show = False)
    if start["ended"] != "breakpoint" or m.registers().gr[12] != "000003F0":
        fail("D40604 did not start its Sense chain on 3F0: %s" % start["run"].psw)
    m.key(0x3f0, "RESET")
    m.clear_breaks()
    m.run(instructions = 12000000)
    lines = [line.strip() for line in m.screens(0x01f)]
    if ("DRIVE 3F0 NOT RDY. CORRECT, B/ TO CONT." not in lines or
        not any([line.startswith("HLT D40604 0A ") for line in lines])):
        fail("D40604 did not halt after the drive dropped Ready during Sense: %s" % lines[-8:])
    m.key(0x3f0, "START")
    m.run(instructions = 250000)
    m.key(0x01f, "REQUEST")
    wait_1052_read(m)
    m.type(0x01f, "B/")
    if repeat_drop:
        m.break_at(0x8194)
        retry = m.run(instructions = 10000000)
        if retry.kind != "breakpoint" or m.registers().gr[12] != "000003F0":
            fail("D40604 did not repeat the Sense chain on 3F0: %s" % retry.psw)
        m.key(0x3f0, "RESET")
        m.clear_breaks()
    m.run(instructions = 2200000000)
    lines = [line.strip() for line in m.screens(0x01f)]
    drives = [line.split()[2] for line in lines if line.startswith("TESTING DRIVE") and "TR," in line]
    abandoned = "STILL NOT RDY. ABANDONING THIS DRIVE" in lines
    if (abandoned != repeat_drop or drives != (["3F1."] if repeat_drop else ["3F0.", "3F1."]) or
        END_OF_JOB not in lines or any([line.startswith("* ") for line in lines])):
        fail("D40604 did not finish the ready-change path: %s" % lines[-12:])
    print("D40604 %s 3F0 after a Ready drop during Sense and reached end of job" % ("abandoned" if repeat_drop else "recovered"))

def check_d40604_drive_prompt(tape, condition, kind):
    m = machine(tape)
    not_ready = condition == "not-ready"
    drop_ready = condition in ["drop-ready", "drop-ready-again"]
    model = 2 if kind == "2401" else 0
    option = {"2415": "00", "2401": "20", "2420": "4C"}[kind]
    m.tape(0x3f0, tape.slice(0, 0), type = kind, model = model, ring = not_ready or drop_ready)
    m.tape(0x3f1, tape.slice(0, 0), type = kind, model = model)
    m.ipl(0x130)
    message = "E/A,01F/A40%s03F0/A40%s03F1/I,01F,01F,01F,130/SS4060.3/L4060/B" % (option, option)
    if drop_ready:
        check_d40604_ready_change(m, message, repeat_drop = condition == "drop-ready-again")
        return
    if not_ready:
        m.key(0x3f0, "RESET")
        m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
        m.break_at(0x8c18)
        run = sdm(m, message = message, budget = 30000000, step = 100000, show = False)
        if (run["ended"] != "breakpoint" or m.registers().gr[12] != "000003F1" or
            run["errors"] != ["* SD0 D40604 0A 0081A4"] or
            "CAN'T GET CC0 ON SENSE, DRIVE 3F0" not in [line.strip() for line in run["transcript"]] or
            not any(["SIO 03F0 caw 000098D0 cmds [0B f=40 n=1 st=02" in event for event in m.events()])):
            fail("D40604 did not report the rejected %s selection: %s" % (kind, run["transcript"][:12]))
        m.clear_breaks()
        m.run(instructions = 1200000000)
        if END_OF_JOB not in [line.strip() for line in m.screens(0x01f)]:
            fail("D40604 did not finish after moving to the ready drive")
        print("D40604 rejected 3F0 on the initial mode set, tested 3F1, and reached end of job")
        return
    correct = condition == "insert-ring"
    run = sdm(m, message = message, budget = 30000000, step = 100000, stop = "HLT D40604", show = False)
    if (run["ended"] != "stop" or run["errors"] or
        "DRIVE 3F0 FILE PROTECTED. CORRECT, B/ TO CONT." not in [line.strip() for line in run["transcript"]]):
        fail("D40604 did not halt for a write ring: %s" % run["transcript"][:12])
    m.run(instructions = 3000000)
    if correct:
        m.key(0x3f0, "INSERT FILE PROTECT RING")
        m.run(instructions = 250000)
    m.key(0x01f, "REQUEST")
    wait_1052_read(m)
    m.type(0x01f, "B/")
    m.break_at(0x8c18)
    resumed = m.run(instructions = 25000000)
    expected_drive = "000003F0" if correct else "000003F1"
    if resumed.kind != "breakpoint" or m.registers().gr[12] != expected_drive:
        fail("D40604 did not start timing on %s after %s: %s" % (expected_drive, condition, resumed.psw))
    m.clear_breaks()
    m.run(instructions = 2000000000)
    lines = [line.strip() for line in m.screens(0x01f)]
    abandoned = "STILL FILE PROTECTED, ABANDONING THIS DRIVE"
    drives = [line.split()[2] for line in lines if line.startswith("TESTING DRIVE") and "TR," in line]
    if ((abandoned in lines) == correct or drives != (["3F0.", "3F1."] if correct else ["3F1."]) or
        END_OF_JOB not in lines or any([line.startswith("* ") for line in lines])):
        fail("D40604 did not finish its %s operator path: %s" % (condition, lines[-12:]))
    print("D40604 %s 3F0 after B/ and reached end of job" % ("tested" if correct else "abandoned"))

def check_d40604_protected_reel(tape):
    m = machine(tape)
    m.tape(0x3f0, tape.slice(0, 0), type = "2415")
    m.ipl(0x130)
    check_2415_read_only(m, restored = True)

def check_2415_read_only(m, restored = False):
    prefix = "E/A,01F/A400003F0/I,01F,01F,01F,130/"
    seed = sdm(m, message = prefix + "L4060/B", budget = 1000000000, step = 100000, show = False)
    if (seed["ended"] != "end-of-job" or seed["errors"] or seed["skipped"] or
        [(s["section"], s["routines"]) for s in seed["sections"]] != [("D40604", "07")]):
        fail("D40604 failed to write its read-only fixture")
    m.key(0x3f0, "REMOVE FILE PROTECT RING")
    m.key(0x130, "REWIND")
    m.ipl(0x130, clear = True)
    m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
    if restored:
        m.event_limit(65536)
        before = [m.tape_record(0x3f0, index = i) for i in range(m.tape_position(0x3f0).record_count)]
        console_start = len(m.screens(0x01f))
        m.break_at(0x97fc)
        latch = sdm(m, message = prefix + "SS4060.1/L4060/B",
                    budget = 100000000, step = 100000, show = False)
        if latch["ended"] != "breakpoint" or latch["errors"] or m.read(0x8004, 4) != b"\x40\x00\x00\x00":
            fail("D40604 did not reach the file-protect latch")
        # D4060400.SPT clears and tests X'40' in PGMSW+1.
        faa_correction(m, 0x97fc, "9602F110", "9640F111")
        m.clear_breaks()
        result = m.run(instructions = 100000000)
        lines = [line.strip() for line in m.screens(0x01f)[console_start:]]
        skipped = "FILE PROT DRIVE - THIS ROUTINE WILL NOT RUN"
        after = [m.tape_record(0x3f0, index = i) for i in range(m.tape_position(0x3f0).record_count)]
        io = [event for event in m.events() if ("SIO 03F0 " in event or "resume 03F0 " in event) and "cmds [" in event]
        commands = [part[:2] for event in io for part in event.split("[")[1:]]
        if ("TIMING ROUTINE" not in lines or
            [line for line in lines if line == skipped] != [skipped] * 3 or
            lines[-2:] != ["T   D40604 07 ROUTINES RUN", END_OF_JOB] or
            any([line.startswith("* ") for line in lines])):
            fail("D40604 did not finish the protected-reel job: %s %s" % (result.psw, lines[-16:]))
        if ("37" not in commands or "2F" not in commands or
            any([cmd in ["01", "17", "1F"] for cmd in commands]) or before != after):
            fail("D40604 protected-reel I/O: commands=%s, records match=%s" % (sorted({cmd: True for cmd in commands}.keys()), before == after))
        print("D40604 reached SDM end of job on the 2415 with its write ring removed. Three write-dependent routines were skipped.")
        return
    start = len(m.screens(0x01f))
    m.break_at(0x8e3c)
    run = sdm(m, message = prefix + "SS4060.1/L4060/B", budget = 100000000, step = 100000, show = False)
    stopped = run["run"]
    if (stopped.kind != "breakpoint" or int(stopped.psw[-6:], 16) != 0x8e3c or
        m.read(0x8004, 4) != b"\x40\x00\x00\x00" or
        m.read(0x8e3c, 8) != b"\x91\x40\xf1\x11\x47\x80\xfe\x4c"):
        fail("D40604 did not reach the expected read-only guard: %s %s" % (stopped.kind, stopped.psw))
    if m.registers().gr[-1] != "00008000" or m.read(0x8110, 2) != b"\xc6\x00":
        fail("D40604 file-protect state differed at the guard")
    m.clear_breaks()
    m.break_at(0x8e4c)
    branch = m.run(instructions = 2)
    if branch.kind != "breakpoint" or int(branch.psw[-6:], 16) != 0x8e4c:
        fail("unexpected read-only guard destination: %s %s" % (branch.kind, branch.psw))
    m.clear_breaks()
    m.run(instructions = 30000000)
    lines = [line.strip() for line in m.screens(0x01f)[start:]]
    mark = [event for event in m.events() if "SIO 03F0 " in event and "cmds [1F " in event]
    if (len(mark) != 1 or "st=02" not in mark[0] or "CMD REJ" not in lines or
        "* SD0 D40604 02 00830A" not in lines or "* SD0 D40604 02 0083E0" not in lines or
        "ABANDONING DRIVE 3F0" not in lines or "T   D40604 05 ROUTINES RUN" not in lines or
        END_OF_JOB not in lines):
        fail("unexpected D40604 read-only result: %s" % lines[-16:])
    print("D40604 entered its write path in read-only mode. The file-protected 2415 rejected Write Tape Mark.")
    print(mark[0])


def start_card_to_tape(tape):
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
    return m, card


def start_ctc_restart(tape):
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
    m.clear_breaks()
    return m


def read_raw_deck(file):
    cards = []
    for line in binary.text(file.bytes(0, file.size)).splitlines():
        if not line.startswith("~raw") or len(line) != 324:
            fail("expected ~raw followed by 80 four-digit octal punch patterns")
        payload = line[4:]
        cards.append(binary.decode("".join([("0%x" % int(payload[i:i + 2], 8))[-2:] for i in range(0, 320, 2)]), "hex"))
    if not cards:
        fail("empty diagnostic card deck")
    return cards

def published_s370_machine(tape, unit_record_output):
    m = emulator.s390(architecture = "s370", memory = 128 << 10, byte_mux_subchannels = 32,
                      mips = 1, start = "1985-08-30T12:00:00Z")
    m.console(0x01f, type = "1052")
    m.unit_record(0x00c, type = "2540R", cards = [])
    if unit_record_output:
        m.unit_record(0x00d, type = "2540P", reader = 0x00c)
        m.unit_record(0x00e, type = "1403")
    m.tape(0x130, tape, type = "2401", format = "simh", ring = False)
    m.tape(0x131, tape.slice(0, 0), type = "2401")
    m.ipl(0x130)
    return m

def main(args):
    if list(args) == ["rkm"]:
        check_9020e_rkm()
        return
    if list(args) == ["dau-configuration"]:
        check_9020e_dau_configuration()
        return
    if list(args) == ["display-contention"]:
        check_9020e_display_contention()
        return
    if list(args) == ["rcu-outboard"]:
        check_9020e_rcu_outboard()
        return
    if list(args) == ["display-wrap"]:
        check_9020e_display_wrap()
        return
    if list(args) == ["sum-parity"]:
        check_9020_sum_parity()
        return
    if list(args) == ["scan-address-parity"]:
        check_9020_scan_address_parity()
        return
    if list(args) == ["mark-parity"]:
        check_9020_mark_parity()
        return
    if list(args) == ["count-logout"]:
        check_9020_count_logout()
        return
    if list(args) == ["defeat-interleave"]:
        check_9020e_defeat_interleave()
        check_9020_ioce_defeat_interleave()
        check_9020_diag_timer()
        return
    if list(args) == ["display-logout"]:
        check_9020e_display_logout()
        return
    if list(args) == ["display-storage"]:
        check_9020e_display_storage()
        return
    if list(args) == ["rcu-configuration"]:
        check_9020e_rcu()
        return
    if list(args) == ["storage-9020a-formatter"]:
        check_9020a_formatter_storage(source())
        return
    if list(args) == ["storage-stop"]:
        check_storage_stop()
        return
    if list(args) == ["storage-live"]:
        check_storage_live()
        return
    if list(args) == ["storage-data-check"]:
        check_storage_data_check()
        return
    if list(args) == ["storage-configuration"]:
        check_9020_configuration()
        check_9020_configuration_links()
        return
    if list(args) == ["tape-configuration"]:
        check_9020_control_configuration("TCU")
        return
    if list(args) == ["disk-configuration"]:
        check_9020_control_configuration("SCU")
        return
    if list(args) == ["storage-mdm-data-check"]:
        check_mdm_storage_data_check(source())
        return
    if list(args) == ["storage-mdm-ioce-check"]:
        check_mdm_storage_data_check(source(), ioce = True)
        return
    if list(args) == ["storage-ioce-data-check"]:
        check_storage_ioce_data_check()
        return
    if list(args) == ["storage-ioce-key-parity"]:
        check_storage_ioce_key_parity()
        return
    if list(args) == ["storage-ioce-command-chain"]:
        check_storage_ioce_command_chain()
        return
    if list(args) == ["storage-ioce-data-chain"]:
        check_storage_ioce_data_chain()
        return
    if list(args) == ["storage-2314-data-chain"]:
        check_storage_2314_data_chain()
        return
    if list(args) == ["storage-ioce"]:
        check_storage_ioce()
        return
    if list(args) == ["storage-channel"]:
        check_storage_channel(source())
        return
    if list(args) == ["storage-output"]:
        check_storage_output()
        return
    if list(args) == ["storage-output-parity"]:
        check_storage_output_parity()
        return
    if list(args) == ["storage-output-chain"]:
        check_storage_output_chain()
        return
    if list(args) == ["storage-ioce-psa"]:
        check_storage_ioce_psa()
        return
    if list(args) == ["storage-keys"]:
        check_storage_keys()
        return
    if list(args) == ["storage-keys-diag"]:
        m = machine(restore_d11792_storage_keys(source()))
        m.ipl(0x130)
        result = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,01F,130/L1179/B", budget = 40000000, show = False)
        sections = [(section["section"], section["routines"]) for section in result["sections"]]
        if result["ended"] != "end-of-job" or sections != [("D11792", "0F")] or result["errors"] or result["skipped"]:
            fail("D11792 restored storage-key test: %s %s %s" % (result["ended"], sections, result["errors"][:12]))
        print("D11792 completed all 15 routines with the FAA zero-storage-key checks restored")
        return
    if args and args[0] == "reel-identity":
        if len(args) > 2:
            fail("usage: s370_diag.star reel-identity [local-tape-image]")
        s370 = "https://raw.githubusercontent.com/rcornwell/S370/236dbbe468667aca6a1e4c6b1c677784aa5adc90/testprogs/diag1.tap"
        candidate = open(args[1]) if len(args) == 2 else http_file([s370], size = SIZE, cache_bytes = 16 << 20)
        sha256 = binary.hex(digest(candidate))
        print("Tape size=%d SHA-256=%s matches pinned microsim360 reel=%s" %
              (candidate.size, sha256, candidate.size == SIZE and sha256 == SHA256))
        return
    if args and args[0] in ["faa-listing", "faa-lines"]:
        by_line = args[0] == "faa-lines"
        if by_line and len(args) != 4:
            fail("usage: s370_diag.star faa-lines section-prefix first-line last-line")
        if len(args) < 3:
            fail("usage: s370_diag.star faa-listing section-prefix text...")
        url = "https://bitsavers.trailing-edge.com/pdf/ibm/9020/faa/FAA_9020_Diagnostics_Source_Code.zip"
        bundle = http_file([url], size = 10540014, cache_bytes = 16 << 20)
        listings, matches = 0, 0
        for entry in archive.zip(bundle).files:
            name = entry.name.replace("\\", "/").split("/")[-1].upper()
            if not name.startswith(args[1].upper()) or not name.endswith(".SPT"):
                continue
            listings += 1
            for number, line in enumerate(entry.read().split("\n"), 1):
                if (int(args[2]) <= number and number <= int(args[3]) if by_line else
                    any([term.upper() in line.upper() for term in args[2:]])):
                    matches += 1
                    if by_line or matches <= 40:
                        print("%s:%d %s" % (name, number, line.strip()))
        print("%d listings read, %d matching lines" % (listings, matches))
        return
    tape = source()
    if args and args[0] == "storage-dump":
        if len(args) > 2 or len(args) == 2 and args[1] != "panel-original":
            fail("usage: s370_diag.star storage-dump [panel-original]")
        check_storage_dump(tape, show = True, panel_original = len(args) == 2)
        return
    if args and args[0] == "s370-published":
        if len(args) < 2 or len(args) > 3 or args[1] not in ["go-nogo", "punch"] or (len(args) == 3 and args[1] != "punch"):
            fail("usage: s370_diag.star s370-published go-nogo | punch [raw-card-deck]")
        select_punch = args[1] == "punch"
        m = published_s370_machine(tape, unit_record_output = select_punch)
        declaration = "A,00E/A6B00000D/" if select_punch else ""
        selection = "L6251" if select_punch else "L1101"
        res = sdm(m, message = "E/A,01F/" + declaration + "I,01F,01F,01F,130/" + selection + "/B",
                  budget = 200000000, step = 100000, blank = 501 if select_punch else 20)
        print("S370 published addresses and 32 multiplexor subchannels, %s: %s, sections=%s, errors=%s" %
              (args[1], res["ended"], res["sections"], res["errors"]))
        expected = ("D62511", "06") if select_punch else ("D11011", "4E")
        if res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or [(s["section"], s["routines"]) for s in res["sections"]] != [expected]:
            fail("published S370 configuration did not complete " + expected[0])
        if select_punch:
            cards = m.output(0x00d, raw = True)
            print("Punch output: %d cards" % len(cards))
            if len(cards) != 336 or binary.hex(cards[-1]) != "40" * 80:
                fail("D62511 did not produce the diagnostic detail deck")
            if len(args) == 3:
                m = published_s370_machine(tape, unit_record_output = True)
                stackers = []
                def observe_reader(m, line, section):
                    if section == "D62620" and ("PLACE VALID CDS" in line or "SHD HAVE 0025 CDS IN R1" in line):
                        stackers.append(m.reader_stackers(0x00c))
                    return operator(m, line, section)
                reader = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,01F,130/L6262/B",
                             budget = 200000000, step = 100000, detail_cards = cards[-257:-1],
                             valid_cards = read_raw_deck(open(args[2])), handle_operator = observe_reader)
                if (reader["ended"] != "end-of-job" or reader["errors"] or reader["skipped"] or
                    [(s["section"], s["routines"]) for s in reader["sections"]] != [("D62620", "02")] or
                    len(stackers) != 2 or [stackers[1][i] - stackers[0][i] for i in range(3)] != [25, 25, 25]):
                    fail("published S370 configuration did not complete D62620")
        return
    if args and args[0] == "2415-seven-track":
        if len(args) > 2 or (len(args) == 2 and args[1] != "motion"):
            fail("usage: s370_diag.star 2415-seven-track [motion]")
        motion = len(args) == 2
        for converter, option in [(True, "01"), (False, "00")]:
            m = machine(tape)
            m.tape(0x3f0, tape.slice(0, 0), type = "2415", tracks = 7, converter = converter)
            m.ipl(0x130)
            selection = "SS4060.3.4/L4060" if motion else "L4058.405D"
            res = sdm(m, message = "E/A,01F/A40" + option + "03F0/I,01F,01F,01F,130/" + selection + "/B",
                      budget = 1200000000 if motion else 300000000, step = 100000)
            print("2415 seven tracks converter=%s, %s: errors=%s, skipped=%s" %
                  (converter, res["ended"], res["errors"], res["skipped"]))
            if motion:
                lines = [line.strip() for line in res["transcript"]]
                if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                    [(s["section"], s["routines"]) for s in res["sections"]] != [("D40604", "07")] or
                    not any(["7 TR, NRZI MODE, MODEL 0" in line for line in lines]) or
                    "CREEP IS + 0.00 INCHES -LOWEST" not in lines or
                    not any([line.startswith("FWD READ REINSTRUCT TIME IS") for line in lines])):
                    fail("D40604 seven-track 2415 motion did not complete as configured")
                continue
            expected = [("D40581", "06"), ("D40591", "05"), ("D405A1", "04"),
                        ("D405B1", "04"), ("D405C1", "03"), ("D405D1", "05")]
            units = [line for line in res["transcript"] if line.strip().startswith("UNITS RUN 03F0")]
            skips = [line.strip() for line in res["transcript"] if "SKIP RTN-" in line]
            expected_skips = ["SKIP RTN-DC AVAIL"] if converter else ["SKIP RTN-NO DC"] * 9
            if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                [(s["section"], s["routines"]) for s in res["sections"]] != expected or
                len(units) != len(expected) or skips != expected_skips):
                fail("2415 seven-track sections or converter paths differed from the expected selection")
        return
    if list(args) == ["tape-motion-velocity"]:
        check_d40604_velocity(tape)
        return
    if args and args[0] == "tape-motion-go-drop":
        if len(args) != 2 or args[1] not in ["3", "6"]:
            fail("usage: s370_diag.star tape-motion-go-drop 3|6")
        check_d40604_go_drop(tape, int(args[1]))
        return
    if args and args[0] == "tape-motion-model":
        if len(args) not in [2, 3] or args[1] not in ["1", "2", "3", "4", "5", "6", "7"]:
            fail("usage: s370_diag.star tape-motion-model MODEL (1 through 7) [compatible|dual-nrzi|dual-pe]")
        model = int(args[1])
        variant = args[2] if len(args) == 3 else ""
        compatible = variant == "compatible"
        dual = variant in ["dual-nrzi", "dual-pe"]
        if (compatible and model not in [1, 2, 3]) or (dual and model not in [4, 5, 6]) or (variant and not compatible and not dual):
            fail("invalid tape option for Model %d: %s" % (model, variant))
        speed_model = 4 if model == 7 else (model - 1) % 3 + 1
        pe = model >= 4 and variant != "dual-nrzi"
        option = "%d%s" % (speed_model, "8" if dual else ("C" if pe else "0"))
        heading = "P.E. MODE" if pe else "NRZI MODE"
        switches = "2.3.4" if variant == "dual-pe" else "3.4"
        for tracks in ([9] if model >= 4 else [9, 7]):
            m = machine(tape)
            m.tape(0x3f0, tape.slice(0, 0), type = "2420" if model == 7 else "2401", model = 0 if model == 7 else model, tracks = tracks,
                   converter = tracks != 7, dual_density = dual, mode_compatible = compatible)
            m.ipl(0x130)
            run = sdm(m, message = "E/A,01F/A40" + option + "03F0/I,01F,01F,01F,130/SS4060." + switches + "/L4060/B",
                      budget = 650000000, step = 100000, show = False)
            lines = [line.strip() for line in run["transcript"]]
            if (run["ended"] != "end-of-job" or run["errors"] or run["skipped"] or
                [(s["section"], s["routines"]) for s in run["sections"]] != [("D40604", "07")] or
                not any([("%d TR, %s" % (tracks, heading)) in line for line in lines]) or
                not any([line in lines for line in ["TIME TO EXECUTE ONE BCTR IS 00.99 USEC", "TIME TO EXECUTE ONE BCTR IS 01.00 USEC"]]) or
                "CREEP IS + 0.00 INCHES -LOWEST" not in lines):
                print("\n".join(lines[:26]))
                fail("D40604 did not complete on model %d, %d tracks: %s %s" % (model, tracks, run["ended"], run["errors"]))
            for line in lines:
                if line.startswith(("TESTING DRIVE 3F0. ", "FWD VEL", "TIME TO EXECUTE ONE BCTR", "MOD 3/6 EARLY DROP", "EARLY START", "FWD READ REINSTRUCT TIME", "BWD READ REINSTRUCT TIME", "CREEP IS", "T   D40604")):
                    print(line)
        return
    if len(args) in [2, 3, 4] and args[0] == "tape-motion-loops":
        if args[1] in ["scope-creep", "scope-creep-reuse"]:
            sweeps = int(args[2]) if len(args) >= 3 else 2
            format = args[3] if len(args) == 4 else "9"
            if sweeps < 2 or format not in ["7", "7-no-converter", "9"]:
                fail("scope-creep requires at least two sweeps and 7, 7-no-converter, or 9 tracks")
            check_d40604_creep_loop(tape, sweeps, int(format[0]), format != "7-no-converter", reuse_mark = args[1] == "scope-creep-reuse")
            return
        if len(args) != 2:
            fail("only scope-creep takes a sweep count")
        if args[1] == "negative-creep":
            check_d40604_negative_creep(tape)
            return
        if args[1] == "scope":
            check_d40604_scope(tape)
            return
        if args[1] in ["error-loop", "error-resume", "error-next"]:
            check_d40604_error_loop(tape, args[1])
            return
        fail("usage: s370_diag.star tape-motion-loops scope|scope-creep [sweeps [tracks]]|scope-creep-reuse [sweeps [tracks]]|negative-creep|error-loop|error-resume|error-next")
    if args and args[0] == "tape-eot-write-error":
        if len(args) > 2 or (len(args) == 2 and args[1] != "not-ready"):
            fail("usage: s370_diag.star tape-eot-write-error [not-ready]")
        if len(args) == 2:
            m = machine(tape)
            m.tape(0x3f0, tape.slice(0, 0), type = "2401", model = 2, eot_inches = 18)
            m.ipl(0x130)
            m.break_at(0x878a)
            entry = sdm(m, message = "E/A,01F/A402003F0/I,01F,01F,01F,130/SS405E.5.6.7/L405E/B",
                        budget = 100000000, step = 100000)
            if (entry["ended"] != "breakpoint" or entry["errors"] or
                m.read(0x878a, 4) != b"\x9c\x00\xc0\x00" or m.tape_position(0x3f0).position != 0):
                fail("D405E1 did not reach the first write before its EOT loop")
            m.key(0x3f0, "RESET")
            m.clear_breaks()
            m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
            for _ in range(250):
                m.run(instructions = 100000)
                lines = [line.strip() for line in m.screens(0x01f)]
                if any([line.startswith("HLT D405E1 83") for line in lines]):
                    break
            attempts = [event for event in m.events() if "SIO 03F0 " in event and "cmds [01 " in event]
            sense = [event for event in m.events() if "resume 03F0 cmds [04 " in event]
            if (len(attempts) != 1 or "st=02" not in attempts[0] or
                len(sense) != 1 or "402003000000" not in sense[0] or m.tape_position(0x3f0).record_count != 0 or
                "* SD0 D405E1 80 008600 3F0" not in lines or "TU NOT RDY" not in lines or
                not any([line.startswith("HLT D405E1 83") for line in lines])):
                fail("D405E1 not-ready write did not take the expected abort: %s" % lines[-18:])
            print("\n".join(lines[1:]))
            print(attempts[0])
            print(sense[0])
            m.key(0x3f0, "START")
            m.run(instructions = 2000000)
            m.key(0x01f, "REQUEST")
            m.run(instructions = 2000000)
            m.type(0x01f, "B")
            for _ in range(400):
                m.run(instructions = 100000)
                lines = [line.strip() for line in m.screens(0x01f)]
                if END_OF_JOB in lines:
                    break
            if END_OF_JOB not in lines or m.tape_position(0x3f0).record_count != 0:
                fail("D405E1 did not reach end of job after the not-ready abort: %s" % lines[-18:])
            print("D405E1 reached EOJ after readying the drive and continuing from routine 83")
            return
        for switches in ["5.7", "5.6.7"]:
            m = machine(tape)
            m.tape(0x3f0, tape.slice(0, 0), type = "2401", model = 2, eot_inches = 18)
            m.tape_write_checks(0x3f0, index = 0, count = 1)
            m.ipl(0x130)
            m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
            print("D405E1 scratch write check with switches " + switches)
            run = sdm(m, message = "E/A,01F/A402003F0/I,01F,01F,01F,130/SS405E." + switches + "/L405E/B",
                      budget = 150000000, step = 100000, handle_operator = tape_ring_operator)
            csws = [event.split(" csw ", 1)[1].split()[0] for event in m.events() if "interrupt 03F0 csw " in event]
            reported = ["* SD0 D405E1 80 00843C 3F0", "*  EXP FIN STS  0C00"] if switches == "5.6.7" else []
            if (run["ended"] != "end-of-job" or run["errors"] != reported or run["skipped"] or
                [(section["section"], section["routines"]) for section in run["sections"]] != [("D405E1", "05")] or
                [csw for csw in csws if csw.startswith("00008C98")] != ["00008C980E000000", "00008C980D000000"]):
                fail("D405E1 write error handling changed: %s %s" % (run["ended"], run["errors"]))
            print("Scratch drive CSWs:", csws)
            print("D405E1 completion:", run["ended"], run["errors"])
        return
    if args and args[0] == "tape-motion-drive":
        kind = args[2] if len(args) == 3 else "2415"
        if (len(args) not in [2, 3] or kind not in ["2401", "2415", "2420"] or
            args[1] not in ["not-ready", "drop-ready", "drop-ready-again", "insert-ring", "leave-protected"]):
            fail("usage: s370_diag.star tape-motion-drive not-ready|drop-ready|drop-ready-again|insert-ring|leave-protected [2401|2415|2420]")
        check_d40604_drive_prompt(tape, args[1], kind)
        return
    if args and args[0] in ["2401-commands", "2420-commands"]:
        kind = args[0][:4]
        model_arg = len(args) in [3, 4] and kind == "2401" and args[2] in ["1", "2", "3", "4", "5", "6"]
        seven = model_arg and len(args) == 4 and args[2] in ["1", "2", "3"] and args[3] == "7"
        if (len(args) > 2 and not model_arg) or (len(args) == 4 and not seven):
            fail("usage: s370_diag.star 2401-commands [SDM-selection [MODEL (1 through 6) [7 (Models 1–3)]]] | 2420-commands [SDM-selection]")
        selection = args[1] if len(args) >= 2 else "L4050.4055"
        model = int(args[2]) if model_arg else (2 if kind == "2401" else 0)
        m = machine(tape)
        eot = selection == "SS405E.5.7/L405E"
        m.tape(0x3f0, tape.slice(0, 0), type = kind, model = model, tracks = 7 if seven else 9, eot_inches = 600 if eot else 0)
        m.ipl(0x130)
        trace_tie = kind == "2401" and selection.startswith("L4050")
        if trace_tie:
            m.event_limit(65536)
            anchor = m.events()[0]
        if selection == "L4056" or trace_tie:
            m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
        # D4050–D4057 uses X'40' as its seven-track working flag.
        # Use its PE-only declaration for the 2420 functional control.
        option = "00" if kind == "2401" else "0C"
        if model_arg:
            option = "%d%s" % ((model - 1) % 3 + 1, "C" if model >= 4 else ("1" if seven else "0"))
        run = sdm(m, message = "E/A,01F/A40" + option + "03F0/I,01F,01F,01F,130/" + selection + "/B",
                  budget = 300000000, step = 100000, handle_operator = tape_ring_operator)
        if trace_tie:
            events = m.events()
            if events[0] != anchor:
                fail("the Request TIE command trace reached its limit")
            tie = [event for event in events if "03F0 " in event and ("cmds [1B " in event or "][1B " in event)]
            print("2401 Request Track in Error command count: %d" % len(tie))
            print("\n".join(tie[:8]))
        if selection == "L4056":
            events = m.events()
            halts = [event for event in events if "008A5E HIO 03F0 " in event]
            if model_arg and (len(halts) != 1 or "HIO 03F0 cc 2 " not in halts[0]):
                fail("D40563 did not halt an active write on the 2401 Model %d: %s" % (model, halts))
            for event in halts:
                print(event)
            for i, event in enumerate(events):
                if "HIO 03F0 cc 0" in event and "n=8176" in events[i - 1]:
                    write_end = int(events[i - 1].split("tod=")[1], 16)
                    halt = int(event.split("tod=")[1], 16)
                    print("D40563 routine 51 issued Halt I/O %d us after the write completed" % (halt - write_end))
        if run["ended"] != "end-of-job" or run["errors"] or run["skipped"]:
            fail("%s %s: %s %s, errors=%s, skipped=%s" % (kind, selection, run["ended"], run["run"].psw, run["errors"], run["skipped"]))
        if selection == "L4050.4055":
            expected = ["16", "10", "0E", "0E", "12", "16"]
            if [(s["section"], s["routines"]) for s in run["sections"]] != [("D405%d1" % i, count) for i, count in enumerate(expected)]:
                fail(kind + " did not complete all six selected sections")
        return
    if args and args[0] in ["2415-sense", "2415-commands"]:
        trace = args[0] == "2415-commands"
        positioned = trace and list(args[1:]) == ["L4053", "peer-positioned"]
        peer = positioned or trace and len(args) == 3 and args[2] == "peer"
        seven = trace and len(args) == 3 and args[2] == "seven"
        pe_only = trace and len(args) == 3 and args[2] == "pe-only"
        dual = trace and len(args) == 3 and args[2] == "dual"
        multiplex = trace and len(args) == 3 and args[2] == "multiplex" and args[1] == "L4056"
        read_only = trace and len(args) == 3 and args[2] in ["read-only", "read-only-restored"] and args[1] == "L4060"
        if (trace and len(args) != 2 and not (peer or seven or pe_only or dual or multiplex or read_only)) or (not trace and len(args) != 1):
            fail("usage: s370_diag.star 2415-sense | 2415-commands SDM-selection [peer|peer-positioned (L4053)|seven|pe-only|dual|multiplex (L4056)|read-only (L4060)|read-only-restored (L4060)]")
        selection = args[1] if trace else "L4050.4057"
        test_eot = selection == "SS405E.5.7/L405E"
        m = machine(tape)
        if positioned:
            position_2415_peer_reels(m)
        else:
            m.tape(0x030 if multiplex else 0x3f0, tape.slice(0, 0), type = "2415",
                   tracks = 7 if seven else 9, pe_only = pe_only, dual_density = dual, eot_inches = 600 if test_eot else 0)
            if peer:
                m.tape(0x3f1, tape.slice(0, 0), type = "2415")
        m.ipl(0x130)
        if read_only:
            check_2415_read_only(m, restored = args[2] == "read-only-restored")
            return
        if trace:
            m.event_limit(65536)
            m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
            trace_anchor = m.events()[0]
        option = "0C" if pe_only else ("08" if dual else ("01" if seven else "00"))
        address = "0030" if multiplex else "03F0"
        load_card = "E/A,01F/A40" + option + address + "/" + ("A400003F1/" if peer else "") + "I,01F,01F,01F,130/"
        res = sdm(m, message = load_card + selection + "/B",
                  budget = 1000000000 if trace and not peer else 300000000,
                  step = 100000, handle_operator = tape_ring_operator)
        if trace:
            events = m.events()
            if not events or events[0] != trace_anchor:
                fail("trace reached its event limit")
            counts_by_drive = {address: {}}
            if peer:
                counts_by_drive["03F1"] = {}
            for event in events:
                if "cmds [" not in event:
                    continue
                for drive, counts in counts_by_drive.items():
                    if "resume " + drive + " " not in event and "SIO " + drive + " " not in event:
                        continue
                    for command in event.split("cmds [", 1)[1].split("] ->", 1)[0].split("]["):
                        opcode = command[:2]
                        counts[opcode] = counts.get(opcode, 0) + 1
            counts = counts_by_drive[address]
            print("2415 %s, %s, command counts %s" % (selection, res["ended"], sorted(counts.items())))
            if peer:
                print("2415 03F1 command counts %s" % sorted(counts_by_drive["03F1"].items()))
                if selection == "L4053" and (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                    [(s["section"], s["routines"]) for s in res["sections"]] != [("D40531", "0E")] or
                    not any(["UNITS RUN 03F0  03F1" in line for line in res["transcript"]]) or
                    any([drive.get("07") != 2 or drive.get("17") != 1 for drive in counts_by_drive.values()])):
                    fail("D40531 did not complete rewind and erase on both 2415 drives")
            if positioned:
                rewind_starts = []
                rewind_ends = []
                for drive in ["03F0", "03F1"]:
                    starts = [i for i, event in enumerate(events) if "SIO " + drive + " " in event and "cmds [07 " in event]
                    if not starts:
                        fail("D40531 did not start rewind on " + drive)
                    ends = [i for i in range(starts[0] + 1, len(events)) if "device end " + drive + " -> dev 04" in events[i]]
                    if not ends:
                        fail("D40531 did not observe rewind Device End on " + drive)
                    rewind_starts.append(starts[0])
                    rewind_ends.append(ends[0])
                if max(rewind_starts) >= min(rewind_ends):
                    fail("D40531 completed its first rewind before starting the second")
                print("D40531 overlapped rewinds on the shared 2415 controller:")
                for i in sorted(rewind_starts + rewind_ends):
                    print(events[i])
            if seven and selection == "L4058":
                density_reads = [event for event in events if "03F0 cmds [0C f=30 n=4000 " in event]
                endings = [event.split(" -> dev ", 1)[1].split(" tod=", 1)[0] for event in density_reads]
                if (endings != ["0E ch 00 ccw 008DC8 resid 3000", "0E ch 00 ccw 008DC8 resid 2085"] or
                    res["ended"] != "end-of-job" or res["errors"]):
                    fail("D40581 partial-record reads changed: %s %s" % (endings, res["errors"]))
                for event in density_reads:
                    print(event)
            motion_status = [e for e in events if ("SIO 03F0 " in e and "cmds [0F " in e) or
                             "interrupt 03F0 csw 00000000" in e]
            print("\n".join(motion_status[-10:]))
            if multiplex:
                halt_events = [event for event in events if "HIO 0030 " in event]
                if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                    [(s["section"], s["routines"]) for s in res["sections"]] != [("D40563", "0C")] or
                    not any(["UNITS RUN 0030" in line for line in res["transcript"]]) or counts.get("01") != 1 or
                    len(halt_events) != 1 or "00899C HIO 0030 cc 1 " not in halt_events[0]):
                    fail("D40563 multiplexor Halt I/O differed from the documented selection")
                print(halt_events[0])
            if selection == "L4056" and not multiplex:
                halt_events = [i for i, event in enumerate(events) if "008A5E HIO 03F0 " in event]
                if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                    [(s["section"], s["routines"]) for s in res["sections"]] != [("D40563", "0C")] or
                    len(halt_events) != (2 if dual else 1)):
                    fail("D40563 did not execute the working selector Halt I/O routine")
                print("D40563 Halt I/O trace:")
                for i in halt_events:
                    halt = events[i:i + 4]
                    first_csw = halt[1].split("interrupt 03F0 csw ")[-1].split(" ")[0] if len(halt) == 4 else ""
                    if (len(halt) != 4 or "HIO 03F0 cc 2 " not in halt[0] or
                        not first_csw.startswith("00008DD00000") or int(first_csw[-4:], 16) not in range(1, 8192) or
                        "device end 03F0 -> dev 0C" not in halt[2] or
                        "interrupt 03F0 csw 000000000C000000" not in halt[3]):
                        fail("D40563 selector Halt I/O did not deliver the two expected interrupts")
                    print("\n".join(halt))
            if test_eot or selection == "SS405E.7/L405E":
                expected = ["cmds [0F ", "csw 0000000026000000", "csw 0000000004000000", "csw 0000000004000000"]
                unload_start = [i for i, event in enumerate(motion_status) if "cmds [0F " in event]
                unload_status = motion_status[unload_start[0]:] if unload_start else []
                if (res["ended"] != "end-of-job" or (res["errors"] and not test_eot) or res["skipped"] or counts.get("0F") != 1 or
                    [(s["section"], s["routines"]) for s in res["sections"]] != [("D405E1", "05")] or
                    len(unload_status) != len(expected) or
                    any([status not in event for status, event in zip(expected, unload_status)])):
                    fail("D405E1 did not complete the 2415 unload and operator-ready sequence")
                travel = [event for event in events if "rewind unload 03F0 estimated travel " in event]
                if len(travel) != 1:
                    fail("D405E1 did not report the unload travel estimate")
                before = int(travel[0].split("tod=")[1], 16)
                manual_ready = int(unload_status[2].split("tod=")[1], 16)
                print("%s; first operator-ready interrupt after %d us" % (travel[0], manual_ready - before))
            if test_eot:
                if pe_only:
                    senses = [event.split("cmds [04 ", 1)[1].split("]")[0].split()[-1]
                              for event in events if "resume 03F0 cmds [04 " in event]
                    ready_senses = [sense for sense in senses if len(sense) == 12 and int(sense[2:4], 16) & 0x40]
                    if not ready_senses or any([int(sense[6:8], 16) & 4 == 0 for sense in ready_senses]):
                        fail("D405E1 sense did not identify the ready 2415 as phase encoded: %s" % senses)
                    print("D405E1 PE Sense bytes: %s" % senses)
                if any(["SKIP-SNSW" in line for line in res["transcript"]]):
                    fail("D405E1 skipped an enabled switch path")
                exceptions = []
                for event in events[:events.index(unload_status[0])]:
                    if "interrupt 03F0 csw " not in event:
                        continue
                    csw = event.split("interrupt 03F0 csw ", 1)[1].split(" ", 1)[0]
                    if int(csw[8:10], 16) & 1:
                        exceptions.append(csw)
                print("D405E1 unit exception CSWs on 3F0: %s" % exceptions)
                if [csw[8:10] for csw in exceptions] != ["0D", "25", "25", "0D", "25"]:
                    fail("D405E1 did not observe the expected 2415 end-of-tape status through the final erase")
                if res["errors"] != ["* SD0 D405E1 80 00843C 3F0", "*  EXP FIN STS  0400", "* SD0 D405E1 80 0088E4 3F0"]:
                    fail("D405E1 end-of-tape outcome differed from the known routine 80 comparison: %s" % res["errors"])
                fail("D405E1 routine 80 expects the 2415 to clear Tape Indicate before crossing the marker backward")
            if selection in ["L4060", "SS4060.2/L4060", "SS4060.2.3.4/L4060"] and not peer:
                lines = [line.strip() for line in res["transcript"]]
                if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                    [(s["section"], s["routines"]) for s in res["sections"]] != [("D40604", "07")] or
                    "CREEP IS + 0.00 INCHES -LOWEST" not in lines):
                    fail("D40604 did not complete the 2415 motion and creep checks")
                if pe_only or (dual and selection != "L4060"):
                    if (not any(["P.E. MODE" in line for line in lines]) or
                        not any([line.startswith("CREASE TAPE SINGLE SHOT IS") for line in lines]) or
                        counts.get("CB", 0) != 0):
                        fail("D40604 did not exercise the PE motion selection")
                mini = selection == "SS4060.2.3.4/L4060"
                tail = [line.split()[0] for line in lines if line.startswith(("0050.0 ", "5000.0 "))]
                if tail != (["0050.0"] if mini else ["0050.0", "5000.0"]):
                    fail("D40604 produced unexpected gap graph rows: %s" % tail)
                for prefix in ["TIME TO EXECUTE ONE BCTR IS", "FWD READ REINSTRUCT TIME IS", "BWD READ REINSTRUCT TIME IS"]:
                    if any([line.startswith(prefix) for line in lines]) != mini:
                        fail("D40604 computed-data selection differed for %s" % prefix)
                if mini and not any([line in lines for line in ["TIME TO EXECUTE ONE BCTR IS 00.99 USEC", "TIME TO EXECUTE ONE BCTR IS 01.00 USEC"]]):
                    fail("D40604 measured unexpected CPU timing in PE mode")
            pe_pass = "SS4056.4/SS4057.4/L4056.4057"
            if (pe_only or dual) and selection in ["L4056.4057", pe_pass]:
                pe_selected = selection == pe_pass
                expected = [("D40563", "06"), ("D40571", "02")] if pe_selected else [("D40563", "0C"), ("D40571", "04")]
                units = [line.strip() for line in res["transcript"] if line.strip().startswith("UNITS RUN 03F0")]
                densities = ["P E"] if pe_only or pe_selected else ["NRZI", "P E"]
                if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                    [(s["section"], s["routines"]) for s in res["sections"]] != expected or
                    len(units) != 2 * len(densities) or
                    any([not line.endswith(density) for line, density in zip(units, densities * 2)]) or
                    counts.get("C3", 0) != (19 if dual else 0) or
                    counts.get("CB", 0) != (19 if dual and not pe_selected else 0)):
                    fail("D4056/D4057 issued unexpected density commands or did not finish")
            early_modes = {
                "L4050.4055": (0, ["16", "10", "0E", "0E", "12", "16"], 337, 346),
                "SS4050.3/SS4051.3/SS4052.3/L4050.4052": (0, ["0C", "09", "08"], 0, 265),
                "SS4050.4/SS4051.4/SS4052.4/L4050.4052": (0, ["0B", "08", "07"], 256, 0),
                "SS4053.3/SS4054.3/SS4055.3/L4053.4055": (3, ["08", "0A", "0C"], 0, 81),
                "SS4053.4/SS4054.4/SS4055.4/L4053.4055": (3, ["07", "09", "0B"], 81, 0),
            }
            if dual and selection in early_modes or pe_only and selection == "L4050.4055":
                first, routines, pe_count, nrzi_count = early_modes[selection]
                expected = [("D405%d1" % (first + i), count) for i, count in enumerate(routines)]
                densities = []
                if dual and nrzi_count:
                    densities.append("NRZI")
                if pe_only or pe_count:
                    densities.append("P E")
                units = [line.strip() for line in res["transcript"] if line.strip().startswith("UNITS RUN 03F0")]
                expected_modes = densities * len(expected)
                if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                    [(s["section"], s["routines"]) for s in res["sections"]] != expected or
                    len(units) != len(expected_modes) or
                    any([not line.endswith(density) for line, density in zip(units, expected_modes)]) or
                    counts.get("C3", 0) != (pe_count if dual else 0) or
                    counts.get("CB", 0) != (nrzi_count if dual else 0)):
                    fail("D4050-D4055 issued unexpected mode commands or did not finish")
            if res["ended"] != "end-of-job":
                print(res["run"].psw, m.subchannel(0x3f0))
                if peer:
                    print(m.subchannel(0x3f1))
                    print(m.disassemble(int(res["run"].psw[-6:], 16), 5))
                print("\n".join(events[-5:]))
            return
        expected = [("D40501", "16"), ("D40511", "10"), ("D40521", "0E"), ("D40531", "0E"),
                    ("D40541", "12"), ("D40551", "16"), ("D40563", "0C"), ("D40571", "04")]
        if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
            [(s["section"], s["routines"]) for s in res["sections"]] != expected):
            fail("2415 did not complete all selected tape sections")
        bad = binary.builder(capacity = 18)
        bad.append(binary.decode("020000803344020000800000000000000000", "hex"))
        m = machine(tape)
        m.tape(0x3f0, bad.file(), type = "2415", format = "simh")
        m.ipl(0x130)
        res = sdm(m, message = load_card + "S4156.80000000/L4156/B", budget = 60000000, step = 100000)
        if (res["ended"] != "end-of-job" or res["skipped"] or len(res["errors"]) != 1 or
            not res["errors"][0].startswith("* *3F0 STA2 S 084003000000 ") or
            [(s["section"], s["routines"]) for s in res["sections"]] != [("D41560", "01")]):
            fail("D41560 did not observe the 2415 sense byte after data check")
        return
    if args and args[0] == "disk-background":
        if len(args) > 2 or (len(args) == 2 and args[1] != "mdm"):
            fail("usage: s370_diag.star disk-background [mdm]")
        check_d805e4_background(tape, mdm = len(args) == 2)
        return
    if args and args[0] == "model50-cpu-restored":
        if len(args) > 2 or (len(args) == 2 and args[1] not in ["A", "D", "E"]):
            fail("usage: s370_diag.star model50-cpu-restored [A|D|E]")
        check_model50_cpu(tape, args[1] if len(args) == 2 else "A")
        return
    if args and args[0] in ["model30-reader", "model30-print", "model30-print-wide", "model30-print-timing", "model30-decimal", "model50-decimal", "model50-cpu"]:
        model50 = args[0] in ["model50-decimal", "model50-cpu"]
        decimal_probe = args[0] in ["model30-decimal", "model50-decimal"]
        if len(args) > 3 or (args[0] == "model50-decimal" and len(args) > 2):
            fail("usage: s370_diag.star model50-decimal [A|D|E] | model50-cpu [SDM-selection [A|D|E]] | model30-decimal [65|generic-1m] | model30-reader|model30-print|model30-print-wide|model30-print-timing [SDM-selection [memory-KiB]]")
        system = "E"
        if model50:
            memory, cpu_model = 128, "50"
            system_arg = 1 if decimal_probe else 2
            if len(args) > system_arg:
                system = args[system_arg]
            if system not in ["A", "D", "E"]:
                fail("model50: SDM system must be A, D, or E")
        else:
            memory = int(args[2]) if len(args) == 3 else 64
            cpu_model = ""
            if decimal_probe and len(args) > 1:
                if list(args[1:]) not in [["65"], ["generic-1m"]]:
                    fail("usage: s370_diag.star model30-decimal [65|generic-1m]")
                memory = 1024
                cpu_model = "65" if args[1] == "65" else ""
        print_job = args[0] in ["model30-print", "model30-print-wide", "model30-print-timing"]
        print_timing = args[0] == "model30-print-timing"
        if model50:
            m = model50_diagnostic_machine(tape)
        else:
            m = emulator.s390(architecture = "s360", model = cpu_model, memory = memory << 10, mips = 1, start = "1985-08-30T12:00:00Z")
            m.tape(0x130, tape, format = "simh", type = "2415", ring = False)
            m.tape(0x131, tape.slice(0, 0), format = "simh", type = "2415")
            m.console(0x01f, type = "1052")
            m.unit_record(0x00c, type = "1442", cards = [])
            if print_job:
                m.unit_record(0x00e, type = "1443", columns = 144 if args[0] == "model30-print-wide" else 120)
            m.ipl(0x130)
        if print_timing:
            m.trace_io(skip = [0x130, 0x131, 0x00c, 0x01f], quiet_polls = True)
        prefix = system + ("/A,01F/A,00E/I,01F,00E,00E,130/" if print_job else "/A,01F/I,01F,01F,01F,130/")
        selection = "L1102" if decimal_probe else (args[1] if len(args) >= 2 else ("L1100.119F" if model50 else "L1101"))
        if decimal_probe:
            m.break_at(0xdbd2)
        budget = 2000000000 if (model50 and not decimal_probe) or selection == "L1100.119F" else 100000000
        res = sdm(m, message = prefix + selection + "/B", budget = budget, step = 100000,
                  report_device = 0x00e if print_job else None, console_input = model50)
        if args[0] == "model50-cpu":
            print("2050G with SDM system %s: %s, %d sections, %d error records, unavailable=%s, PSW %s" %
                  (system, res["ended"], len(res["sections"]), len(res["errors"]), res["skipped"], res["run"].psw))
            return
        if print_timing:
            # The report appears at Channel End. Let the last buffered line
            # finish printing before measuring the Device End intervals.
            m.run(instructions = 300000)
            transfers = [event for event in m.events() if "resume 000E cmds [09 " in event]
            completions = [event for event in m.events() if "device end 000E -> dev 04 " in event]
            if len(transfers) < 4 or len(transfers) != len(completions):
                fail("expected a Device End for each 1443 print command")
            for transfer, completion in zip(transfers, completions):
                count = int(transfer.split(" n=")[1].split(" ")[0])
                start = int(transfer.split("tod=")[1], 16)
                end = int(completion.split("tod=")[1], 16)
                if end - start + (count + 1) * 10 != 250000:
                    fail("1443 rated cycle differed for %d-byte line: %d us after Channel End" % (count, end - start))
            print("1443 standard bar: %d lines at 250000 us per channel selection-to-Device-End cycle" % len(transfers))
        if decimal_probe:
            stop = res["run"]
            cases = [(0xdbd2, 0xfa), (0xe932, 0xfc), (0xe99e, 0xfc), (0xea0a, 0xfc), (0xee68, 0xfc)]
            destinations = {
                "": ["1c", "222c", "222c", "222c", "2323232c"],
                "50": ["1c", "002c", "002c", "002c", "0025752c"],
                "65": ["ff", "002c", "002c", "002c", "2325752c"],
            }
            for index, (address, opcode) in enumerate(cases):
                if stop.kind != "breakpoint" or int(stop.psw[-6:], 16) != address:
                    fail("D11020 did not reach decimal instruction at %x" % address)
                word = int(binary.hex(m.read(address, 6)), 16)
                if word >> 40 != opcode:
                    fail("D11020 decimal instruction changed at %x" % address)
                registers = m.registers().gr
                dst = int(registers[(word >> 28) & 15], 16) + ((word >> 16) & 4095)
                src = int(registers[(word >> 12) & 15], 16) + (word & 4095)
                dst_len, src_len = ((word >> 36) & 15) + 1, ((word >> 32) & 15) + 1
                before = binary.hex(m.read(dst, dst_len))
                operand = binary.hex(m.read(src, src_len))
                m.clear_breaks()
                m.break_program(7)
                fault = m.run(instructions = 1)
                after = binary.hex(m.read(dst, dst_len))
                if fault.kind != "program" or m.read(0x2a, 2) != b"\x00\x07":
                    fail("D11020 did not signal Data Exception at %x" % address)
                if after != destinations[cpu_model][index]:
                    fail("Unexpected decimal exception result at %x: %s" % (address, after))
                print("D11020 opcode %x at %x, destination at %x %s -> %s, source at %x %s, data exception 0007" %
                      (opcode, address, dst, before, after, src, operand))
                if index + 1 < len(cases):
                    m.clear_breaks()
                    m.break_at(cases[index + 1][0])
                    stop = m.run(instructions = 20000000)
            m.clear_breaks()
            m.break_at(0x81b0)
            cleanup = m.run(instructions = 30000000)
            if (cleanup.kind != "breakpoint" or m.read(0x81b0, 4) != b"\x08\x66\x0a\xd5" or
                m.registers().gr[6] != "00014000"):
                fail("D11020 did not reach its final storage-key cleanup")
            m.clear_breaks()
            m.break_program(5)
            cleanup = m.run(instructions = 1)
            if (cleanup.kind == "program") != (memory == 64):
                fail("D11020 storage-key cleanup gave an unexpected addressing result")
            m.clear_breaks()
            for _ in range(12):
                m.run(instructions = 5000000)
                lines = [line.strip() for line in m.screens(0x01f)]
                if END_OF_JOB in lines:
                    break
            reports = [line for line in lines if line.startswith(("* SD0", "* PGM"))]
            compare_errors = {"": ["85", "8B", "8B", "8C", "90"], "50": ["85", "90"], "65": []}
            expected_reports = ["* SD0 D11020 %s 008CDE" % rt for rt in compare_errors[cpu_model]]
            if memory == 64:
                expected_reports.append("* PGM D11020 97 01040005500081B2")
            if reports != expected_reports or "T   D11020 47 ROUTINES RUN" not in lines or END_OF_JOB not in lines:
                fail("D11020 final reports differed: %s %s" % (reports, lines[-4:]))
            if model50:
                for line in reports:
                    print(line)
            print("D11020 reached SDM end of job with 47 hex routines and %d error reports" % len(reports))
            return
        trace_switches = {}
        for bypass in [False, True]:
            for long_format in [False, True]:
                for single in [False, True]:
                    switches = (".1" if bypass else "") + (".2" if long_format else "") + (".5" if single else "") + ".6"
                    mask = (0x40 if bypass else 0) | (0x20 if long_format else 0) | (4 if single else 0) | 2
                    trace_switches["SS1102" + switches + "/L1102"] = bytes([mask])
        if selection in trace_switches:
            m.break_at(0x8bfe)
            r = m.run(instructions = 30000000)
            if (r.kind != "breakpoint" or m.read(0x8004, 1) != trace_switches[selection] or
                binary.hex(m.read(0x8bfe, 12)) != "9201fc0b1b11411100030ad0"):
                fail("D11020 did not reach the inspected microtrace dispatch site")
            m.clear_breaks()
            for _ in range(500):
                lines = [line.strip() for line in m.screens(0x01f)]
                if END_OF_JOB in lines:
                    break
                m.run(instructions = 5000000)
            reports = [line for line in lines if line.startswith("* SD0")]
            first = "* SD0 D11020 4F 008CDE"
            if (not reports or reports[0] != first or END_OF_JOB not in lines or
                "T   D11020 47 ROUTINES RUN" not in lines):
                fail("D11020 forced trace did not exercise the report path and reach end of job")
            row = lines.index(first)
            if lines[row + 1].split("REC RESULTS ")[-1] != lines[row + 2].split("EXP RESULTS ")[-1]:
                fail("D11020 first forced report did not show equal move results")
            output = "\n".join(lines[lines.index("S   D11020"):lines.index(END_OF_JOB) + 1])
            print("Report digest", binary.hex(digest(bytes(output))))
            print("D11020 forced reporting reached end of job with %d SD0 reports" % len(reports))
            return
        if selection == "SS1102.0/L1102":
            if res["ended"] != "budget" or res["errors"] or m.read(0x8004, 1) != b"\x80":
                fail("D11020 did not retain the scope-loop switch")
            m.break_at(0x8a42)
            m.break_at(0x8f92)
            turn = m.run(instructions = 30000000)
            if turn.kind != "breakpoint":
                fail("D11020 did not take its scope-loop return branch")
            print("D11020 scope-loop return at " + turn.psw[-6:])
            m.clear_breaks()
            m.alter(0x8004, b"\x00")
            for _ in range(30):
                m.run(instructions = 5000000)
                lines = [line.strip() for line in m.screens(0x01f)]
                if END_OF_JOB in lines:
                    break
            reports = [line.split()[3] for line in lines if line.startswith("* SD0")]
            if reports != ["85", "8B", "8B", "8C", "90"] or END_OF_JOB not in lines or "T   D11020 47 ROUTINES RUN" not in lines:
                fail("D11020 did not finish after leaving its scope loop")
            print("Clearing switch 0 resumed D11020 through SDM end of job")
            return
        if selection == "SS1102.3/L1102":
            lines = [line.strip() for line in res["transcript"]]
            reports = [line for line in lines if line.startswith("* SD0")]
            mismatch = "* SD0 D11020 85 008CDE"
            if len(reports) < 2 or any([line != mismatch for line in reports]) or END_OF_JOB in lines:
                fail("D11020 did not repeat its first decimal mismatch under switch 3")
            if m.read(0x8004, 1) != b"\x10":
                fail("D11020 loop switch has an unexpected value")
            m.alter(0x8004, b"\x00")
            for _ in range(24):
                m.run(instructions = 5000000)
                lines = [line.strip() for line in m.screens(0x01f)]
                if END_OF_JOB in lines:
                    break
            later = [line.split()[3] for line in lines if line.startswith("* SD0") and line != mismatch]
            if later != ["8B", "8B", "8C", "90"] or END_OF_JOB not in lines or "T   D11020 47 ROUTINES RUN" not in lines:
                fail("D11020 did not finish remaining routines after clearing switch 3: %s" % lines[-10:])
            print("D11020 repeated routine 85, then reached EOJ after clearing switch 3")
            return
        if len(args) >= 2:
            print("Model 30 peripheral layout, %s, PSW %s, errors %s" % (res["ended"], res["run"].psw, res["errors"]))
            return
        if res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or [(s["section"], s["routines"]) for s in res["sections"]] != [("D11011", "4E")]:
            fail("D11011 did not complete after 1442 SDM input")
        return
    if len(args) == 1 and args[0] == "2415-ipl":
        for memory, scratch_ring in [(64 << 10, True), (128 << 10, False)]:
            m = emulator.s390(architecture = "s360", memory = memory, mips = 1, start = "1985-08-30T12:00:00Z")
            m.tape(0x130, tape, format = "simh", type = "2415", ring = False)
            m.tape(0x131, tape.slice(0, 0), format = "simh", type = "2415", ring = scratch_ring)
            m.console(0x01f, type = "1052")
            m.event_limit(8192)
            m.trace_io(quiet_polls = True)
            m.ipl(0x130)
            if m.run(instructions = 30000000).psw != SDM_READY:
                fail("2415 IPL did not reach SDM's input wait")
            reads = [line for line in m.events() if "resume 0130 cmds [02 " in line]
            selection = [(12, "1FFF0021D0B01400"), (12, "D0B01400"), (12, "D0B01403"),
                         (12, "8FFF0071D0C00C00"), (36863, "D0C00C00")]
            indices = [i for i, line in enumerate(reads) if selection[0][1] in line]
            if len(indices) != 1 or not all(["n=%d st=0C %s" % pair in reads[indices[0] + i]
                                              for i, pair in enumerate(selection)]):
                fail("unexpected 2415 monitor selection at %d KiB: %s" % (memory // 1024, reads[-6:]))
            m.trace_io(False)
            m.key(0x01f, "REQUEST")
            wait_1052_read(m)
            m.type(0x01f, "E/A,01F/I,01F,01F,01F,130/L1101/B/")
            for _ in range(60):
                m.run(instructions = 1000000)
                if END_OF_JOB in [line.strip() for line in m.screens(0x01f)]:
                    break
            check_job(m, "D11011", ["T   D11011 4E ROUTINES RUN"])
            print("2415 IPL with %d KiB: D11011 completed 78 routines from 1052 input" % (memory // 1024))
        return
    if args and args[0] == "model65-cpu":
        if (len(args) > 3 or (len(args) >= 2 and args[1] not in ["128", "256", "512", "768", "1024"]) or
            (len(args) == 3 and args[2] != "2401")):
            fail("usage: s370_diag.star model65-cpu [128|256|512|768|1024 (KiB) [2401]]")
        memory = int(args[1]) if len(args) >= 2 else 1024
        boot_2401 = len(args) == 3
        m = machine(tape, model = "65", memory = memory << 10, boot_2401 = boot_2401)
        m.ipl(0x130)
        res = sdm(m, message = "E/A,01F/I,01F,01F,01F,130/L1100.119F/B",
                  budget = 800000000, step = 100000, stop = "* SD0")
        if res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or len(res["sections"]) != 63:
            fail("Model 65 CPU sections: %s, errors=%s, skipped=%s" % (res["ended"], res["errors"], res["skipped"]))
        for section in res["sections"]:
            if not section["routines"] or int(section["routines"], 16) == 0:
                fail("no completed routines in " + section["section"])
        print("Model 65 with %d KiB and a %s library drive completed all 63 CPU sections" % (memory, "2401 Model 2" if boot_2401 else "3420"))
        return
    if args and args[0] == "selector-ssm":
        if len(args) > 2 or len(args) == 2 and args[1] not in ["A", "D", "E"]:
            fail("usage: s370_diag.star selector-ssm [A|D|E]")
        monitor = args[1] if len(args) == 2 else "E"
        profiles = [("65", "ff0403f000009960")]
        if monitor in ["D", "E"]:
            profiles.append(("9020", "ff0403f00000825c"))
        for model, saved_psw in profiles:
            m = machine(tape, model = model, scratch_tapes = [0x3f0, 0x3f1])
            m.ipl(0x130)
            m.break_at(0x995c)
            res = sdm(m, message = monitor + "/A,01F/A400003F0/A400003F1/I,01F,01F,01F,130/L3151/B",
                      budget = 60000000, step = 100000, show = False)
            if res["ended"] != "breakpoint" or res["run"].psw[-8:] != "0000995C" or res["errors"]:
                fail("D31512 did not reach the pending-interrupt SSM")
            srt = int(binary.hex(m.read(0x200, 4)), 16)
            system_type = binary.hex(m.read(srt - 1, 1))
            if system_type != {"A": "01", "D": "04", "E": "05"}[monitor] or binary.hex(m.read(0x995c, 8)) != "8000fc2c4550f25c":
                fail("D31512 monitor profile or SSM/BAL sequence changed")
            m.clear_breaks()
            m.history(keep = 8)
            m.run(instructions = 5)
            actual = binary.hex(m.read(0x38, 8))
            if actual != saved_psw:
                fail("D31512 %s: expected I/O old PSW %s, got %s" % (model, saved_psw, actual))
            print("%s: monitor system type X'%s', I/O old PSW %s" % (model, system_type, actual))
            print("\n".join(m.history()))
            if monitor == "A":
                m.run(instructions = 80000000)
                check_job(m, "D31512", ["T   D31512 0D ROUTINES RUN"])
                print("D31512 completed all 0D routines under the type-A monitor selection")
        return
    if list(args) == ["channel", "65", "restored"]:
        check_model65_channel(tape)
        return
    if len(args) == 1 and args[0] == "channel-protection":
        for model in ["65", "9020"]:
            for section, routines, scratch, assignment, fetch_status in [
                ("D30542", "29", [], "A,00E/", "00200000"),
                ("D31544", "2B", [0x3f0], "A400003F0/", "00300000"),
            ]:
                m = machine(tape, model = model, scratch_tapes = scratch)
                m.ipl(0x130)
                message = "E/A,01F/" + assignment + "I,01F,01F,01F,130/L" + section[1:5] + "/B"
                res = sdm(m, message = message, budget = 60000000, step = 100000, show = False)
                if res["ended"] != "end-of-job" or res["skipped"] or [(r["section"], r["routines"]) for r in res["sections"]] != [(section, routines)]:
                    fail("%s %s did not complete the expected section" % (model, section))
                errors = [line.strip() for line in res["errors"]]
                observed = []
                for i, line in enumerate(errors):
                    if line.startswith("*     " + section + " "):
                        observed.append((line.split()[2], errors[i + 1], errors[i + 2]))
                expected = []
                if model == "65":
                    for routine in ["55", "56"]:
                        expected.extend([(routine, "* EXPD--0C000000", "* ACTL--0C100000"),
                                         (routine, "* EXPD--C9D5E3C5", "* ACTL--00000000")])
                    for routine in ["57", "61"]:
                        expected.append((routine, "* EXPD--" + fetch_status, "* ACTL--00100000"))
                if observed != expected or len(errors) != 4 * len(expected):
                    fail("%s %s: unexpected channel protection results %s" % (model, section, errors))
                print("%s %s: %s routines, EOJ, %d expected mismatch reports" % (model, section, routines, len(observed)))
                for result in observed:
                    print("  %s %s %s" % result)
        return
    if args and args[0] == "channel":
        if len(args) not in [2, 3] or args[1] not in ["65", "9020"] or len(args) == 3 and args[2] not in ["A", "D", "E"]:
            fail("usage: s370_diag.star channel 65|9020 [A|D|E]")
        monitor = args[2] if len(args) == 3 else "E"
        for scratch, assignments, selection in [
            ([], "A,00E/", "L3051/L3054"),
            ([0x3f0, 0x3f1], "A400003F0/A400003F1/", "L3151.3154"),
        ]:
            m = machine(tape, model = args[1], scratch_tapes = scratch)
            m.ipl(0x130)
            message = monitor + "/A,01F/" + assignments + "I,01F,01F,01F,130/" + selection + "/B"
            print("SDM load card " + message)
            res = sdm(m, message = message, budget = 300000000, step = 100000)
            print("channel %s: %s, %d error records, unavailable=%s" %
                  (args[1], res["ended"], len(res["errors"]), res["skipped"]))
        return
    if args and args[0] == "catalog":
        if len(args) == 3 and args[1] == "unreported":
            headers = library_headers(archive.simh(library_reel(tape)).records)
            starts = [line.split()[1] for line in open(args[2]).read().split("\n")
                      if line.strip().startswith("S   ") and len(line.split()) == 2]
            seen = {section: True for section in starts}
            catalog = [data[8:16] for _, data in headers]
            ids = {entry[:6]: True for entry in catalog}
            if len(ids) != len(catalog) or not starts or any([section not in ids for section in seen]):
                fail("cannot match transcript section starts uniquely to this catalog")
            missing = [entry for entry in catalog if entry[:6] not in seen]
            print("%d catalog entries, %d start lines, %d distinct starts, %d without a start line" %
                  (len(catalog), len(starts), len(seen), len(missing)))
            print(" ".join(missing))
            return
        if len(args) == 3 and args[1] == "payloads":
            prefix = args[2].upper()
            records = archive.simh(library_reel(tape)).records
            for index, header in library_headers(records):
                if header[8:16].startswith(prefix):
                    payload = records[index + 1].data
                    print("%s payload record %d, %d bytes" % (header[8:16], index + 1, payload.size))
            return
        if len(args) > 2:
            fail("usage: s370_diag.star catalog [section-prefix] | catalog unreported transcript | catalog payloads section-prefix")
        prefix = args[1].upper() if len(args) == 2 else ""
        headers = library_headers(archive.simh(library_reel(tape)).records)
        sections = [data[8:16] for _, data in headers if data[8:16].startswith(prefix)]
        print("%d matching sections out of %d catalog entries" % (len(sections), len(headers)))
        for section in sections:
            print(section)
        return
    if len(args) == 1 and args[0] == "ipl-headers":
        check_ipl_headers(tape)
        return
    if len(args) in [3, 4] and args[0] == "formatter-check":
        element = int(args[1])
        mode = args[2]
        profile = args[3] if len(args) == 4 else "00E"
        if element not in [0, 1, 2, 3] or mode not in FORMATTER_SWITCHES or profile not in ["00E", "01F", "1052-only"]:
            fail("usage: formatter-check element long|short|switch27|switch28|switch30|routine|section-handler|short-base-control|short-data-control|short-restored|long-restored|storage|storage-mcw [00E|01F|1052-only]")
        check_formatter(tape, element, mode, profile)
        return
    if len(args) == 1 and args[0] == "formatter-devices":
        records = archive.simh(library_reel(tape)).records
        long_entries = []
        for header_index, entry_id, prologue in [(23, "d0d10700", "900f9080"), (32, "d0d70400", "470090e6900f9080")]:
            header = records[header_index].data
            payload = records[header_index + 1].data
            count = int(binary.hex(header.bytes(0, 2)), 16)
            if (binary.hex(header.bytes(4, 4)) != entry_id or count != payload.size or
                payload.bytes(230, len(prologue) // 2) != binary.decode(prologue, "hex")):
                fail("long formatter header or entry differs for %s" % entry_id)
            long_entries.append((entry_id, count))
        for dev in ["00E", "01F"]:
            m = machine(tape)
            m.ipl(0x130)
            if m.run(instructions = 30000000).psw != SDM_READY:
                fail("SDM startup failed")
            # LM 9,10,SHTBSE followed by BAL 7,230(9), then restored bases.
            dispatch = binary.decode("989a9528457900e6989a0b74", "hex")
            if m.read(0x5488, len(dispatch)) != dispatch:
                fail("short dispatch offset %s" % binary.hex(m.read(0x5480, 32)))
            if m.read(0x7000, 4095) != records[30].data.bytes(0, 4095):
                fail("startup target differs from the resident tape payload")
            run = sdm(m, message = "E/A,01F/A,00E/I,01F,01F," + dev + ",130/SW.00001000/L1101/B",
                      budget = 30000000, step = 100000, show = False)
            if (run["ended"] != "end-of-job" or run["errors"] or run["skipped"] or
                [section["section"] for section in run["sections"]] != ["D11011"]):
                fail("formatter device setup: %s" % run)
            # MC16 computes both long bases and copies the first into the read CCW.
            setup = binary.decode("582004885a200dec502095205a20048050209524", "hex")
            count_and_read = binary.decode("d201951e0b5841609518452094a8", "hex")
            long_call = binary.decode("989a9520457900e6", "hex")
            if (m.read(0x529a, len(setup)) != setup or m.read(0x52b6, 6) != binary.decode("d20295199521", "hex") or
                m.read(0x537c, len(count_and_read)) != count_and_read or m.read(0x5498, 8) != long_call):
                fail("unexpected SDM long formatter loader instructions")
            read_base = int(binary.hex(m.read(0x488, 4)), 16) + int(binary.hex(m.read(0xdec, 4)), 16)
            if dev == "00E":
                for entry_id, count in long_entries:
                    print("%s long read would span %x–%x with entry %x" %
                          (entry_id, read_base, read_base + count - 1, read_base + 230))
            pointer = int(binary.hex(m.read(0x694, 2)), 16)
            udt = binary.hex(m.read(pointer, 4))
            if udt != {"00E": "6311000e", "01F": "6600001f"}[dev]:
                fail("unexpected secondary-output UDT: %s" % udt)
            short_base = int(binary.hex(m.read(0x5528, 4)), 16)
            target = short_base + 230
            if (target != 0x78e6 or m.read(target, 16) != b"\x00" * 16 or
                m.read(0x5528, 4) != records[18].data.bytes(0x5528 - 8, 4) or
                m.read(0x70e6, 8) != binary.decode("470090e6900f9080", "hex")):
                fail("short formatter setup differs from original reel")
            print("secondary %s UDT %x %s; short target %x %s; formatter code at 70e6" %
                  (dev, pointer, udt, target, binary.hex(m.read(target, 16))))
        m = machine(tape)
        m.ipl(0x130)
        if m.run(instructions = 30000000).psw != SDM_READY:
            fail("SDM startup failed")
        m.cards(0x00c, ["E/A,01F/A,00E/I,01F,01F,00E,130/SW.00001000/L1101/B"], replace = True)
        m.watch(0x78e6, 1)
        m.interrupt_key()
        r = m.run(instructions = 30000000)
        if (r.kind != "watch" or r.psw != "00040000 00001D62" or
            m.registers().gr[2:5] != ["000078E6", "000000AA", "00000000"] or
            m.read(0x1d5e, 4) != binary.decode("42420000", "hex") or
            m.read(0x381, 3) != b"\x00\x78\x00"):
            fail("unexpected writer at short formatter target: %s %s" % (r.kind, r.psw))
        print("SDM clears 7800–798F as loader scratch; STC at 1D5E overwrote 78E6")
        m.watch(0, 0)
        return
    if len(args) == 2 and args[0] == "ioce-original" and args[1] == "individual-loads":
        headers = library_headers(archive.simh(library_reel(tape)).records)
        entries = [data[8:16] for _, data in headers if data[1:4] == "FFF" and "D1003000" <= data[8:16] and data[8:16] <= "D1075000"]
        if len(entries) != 66:
            fail("unexpected IDM section catalog")
        for entry in entries:
            m = machine(tape, element = "ioce", memory = 128 << 10)
            m.ipl(0x130)
            selection = entry[1:5]
            res = sdm(m, message = "A/A,01F/A,00E/I,01F,01F,01F,130/L" + selection + "/B",
                      budget = 100000000, step = 100000, show = False)
            if res["ended"] != "end-of-job" or res["sections"] or res["errors"] != ["ILR " + selection + "00"]:
                fail("%s direct load: %s, %s, %s" % (entry, res["ended"], res["sections"], res["errors"]))
            print("%s L%s %s EOJ" % (entry, selection, res["errors"][0]))
        return
    if args and args[0] == "ioce-original":
        m = machine(tape, element = "ioce", memory = 128 << 10)
        m.ipl(0x130)
        m.break_at(0x2b6)
        r = m.run(instructions = 9000000)
        records = archive.simh(library_reel(tape)).records
        if (r.kind != "breakpoint" or m.read(0x1164, 12) != records[7].data.bytes(0, 12) or
            m.registers().gr[2] != "00000008"):
            fail("unexpected IOCE tape header or search count before selection")
        print("IOCE received record 7 intact, with eight search iterations available")
        m.clear_breaks()
        m.break_at(0x2c6)
        r = m.run(instructions = 9000000)
        if r.kind != "breakpoint":
            fail("IOCE did not reach Go/No-Go monitor selection: " + r.psw)
        print("IOCE GR1=%s CE indicator=%s, %s" %
              (m.registers().gr[1], binary.hex(m.read(0x384, 4)), m.disassemble(0x2c6, 1)[0]))
        m.clear_breaks()
        for address in [0x32a, 0x32e, 0x332, 0x336, 0x33a, 0x33e, 0x346]:
            r = m.run(instructions = 1)
            if not r.psw.endswith(("000000" + ("%x" % address).upper())[-6:]):
                fail("unexpected loader selection at %s, expected %x" % (r.psw, address))
        header = m.registers().gr[1]
        idm = binary.hex(m.read(0x374, 4)).upper()
        hardcore = binary.hex(m.read(0x3d8, 4)).upper()
        if header != hardcore or header == idm:
            fail("IOCE loader header comparison changed")
        print("LDNXT selected %s (hardcore), IDM comparison operand %s" % (header, idm))
        r = m.run(instructions = 65000000)
        if r.psw != SDM_READY:
            fail("IOCE did not reach SDM: " + r.psw)
        res = sdm(m, message = "A/A,01F/A,00E/I,01F,01F,01F,130/L2101/L2740/B",
                  budget = 100000000, step = 100000)
        print("SDM IOCE flag=%s, %s, sections=%s, errors=%s" %
              (binary.hex(m.read(0x206, 1)), res["ended"], res["sections"], res["errors"]))
        return
    if list(args) == ["faa-mdm-allocation"]:
        check_d806a5_mdm_allocation(tape)
        return
    if args and args[0] == "faa-mdm-disk":
        if len(args) > 2 or (len(args) == 2 and args[1] not in ["retry", "restore-caw", "retry-restored"]):
            fail("usage: s370_diag.star faa-mdm-disk [retry|restore-caw|retry-restored]")
        retry = len(args) == 2
        if retry and args[1] == "retry-restored":
            check_d80683_retry(tape, mdm = True)
            return
        m = faa_mdm(tape)
        m.dasd(0x340, type = "2314", cylinders = 203, volser = "DIAG01")
        if retry:
            m.dasd(0x341, type = "2314", cylinders = 203, volser = "DIAG02")
            m.key(0x341, "REMOVE ID PLUG")
        m.console(2, type = "1052")
        r = m.run(instructions = 35000000)
        if r.psw != SDM_READY:
            fail("FAA MDM did not reach the operator wait")
        m.key(2, "REQUEST")
        m.run(instructions = 10000000)
        ready = "MDM D/E REVISION 0A READY CD017 SIMPLEX"
        if ready not in [line.strip() for line in m.screens(2)]:
            fail("FAA MDM did not prompt for a load message")
        m.type(2, "A32/A80000340/L8068,340/" + ("SS8068.14.1/" if retry else "") + "B/")
        m.run(instructions = 30000000)
        lines = [line.strip() for line in m.screens(2)]
        if not retry:
            if lines[-3:] != ["START   D80683", "T CE1  001      D80683", "EOJ  MDM JOB COMPLETE"]:
                fail("FAA MDM did not complete the default D80683 routine: %s" % lines[-12:])
            print("\n".join(lines[-3:]))
            return
        if "PUT PLUG 0 IN PHYSICAL DRIVE A" not in lines:
            fail("FAA MDM did not enter D80683 routine 6: %s" % lines[-12:])
        m.break_at(0x14098)
        r = m.run(instructions = 120000000)
        lines = [line.strip() for line in m.screens(2)]
        if r.kind != "breakpoint" or "ERROR ON DRIVE B" not in lines or "SNS BYTE 4 RECVD 00" not in lines:
            fail("FAA MDM did not reach the D80683 mismatch retry: %s" % lines[-12:])
        m.clear_breaks()
        m.move_2314_plug(0x340, 0x341)
        # Let the immediate retry encounter the drive's startup busy.
        # Observe the next retry after the diagnostic has printed again.
        m.break_at(0x14098)
        r = m.run(instructions = 10000000)
        if r.kind != "breakpoint" or not r.psw.endswith("014098"):
            fail("FAA MDM did not return to the retry after drive startup")
        m.clear_breaks()
        caw_address = int(m.registers().prefix, 16) + 0x48
        caw = int(binary.hex(m.read(caw_address, 4)), 16)
        command = binary.hex(m.read(caw & 0xffffff, 1))
        restore_caw = args[1] == "restore-caw"
        if restore_caw:
            if m.read(0x130e8, 1) != b"\x04":
                fail("D80683's Sense CCW was not at 130E8")
            m.alter(caw_address, b"\x00\x01\x30\xe8")
        m.event_limit(256)
        m.trace_io(skip = [0x130, 2], quiet_polls = True)
        m.break_at(0x14008)
        r = m.run(instructions = 10000)
        if restore_caw:
            sensed = [event for event in m.events() if "014004 SIO 0340 caw 000130E8 cmds [04 " in event]
            if r.kind != "breakpoint" or not sensed:
                fail("FAA MDM retry after restoring CAW: %s %s %s" % (r.kind, r.psw, m.events()[-4:] + [binary.hex(m.read(caw_address, 4))]))
            if "000000400100" not in sensed[-1]:
                fail("Sense did not return physical drive B: %s" % sensed[-1])
            print(sensed[-1])
            return
        rejected = [event for event in m.events()
                    if "014004 SIO 0340 caw 0007FC88 cmds [89 f=20 n=21 st=02" in event]
        if r.kind != "breakpoint" or not r.psw.endswith("014008") or caw == 0x130e8 or not rejected:
            fail("FAA MDM retry did not reproduce the stale CAW after drive correction: %x %s %s" % (caw, r.psw, m.events()[-6:]))
        print("FAA MDM retry: stale CAW %x, command byte %s" % (caw, command))
        print(rejected[-1])
        return
    if args and args[0] == "mdm":
        if len(args) > 2 or (len(args) == 2 and args[1] not in ["65", "9020"]):
            fail("usage: s370_diag.star mdm [65|9020]")
        model = args[1] if len(args) == 2 else "9020"
        record = archive.simh(library_reel(tape)).records[27]
        operand = binary.decode("d6039dbc30e147f0", "hex")
        if (record.offset != 187118 or record.data.bytes(0, 4) != b"\xd0\xd5\x0a\x00" or
            record.data.bytes(0x78, 8) != binary.decode("41a9100041ba1000", "hex") or record.data.bytes(0x5958, 8) != operand):
            fail("unexpected D0D50A load record")
        m = start_mdm(tape, model = model)
        m.console(2, type = "1052")
        if m.read(0x5960, 8) != operand:
            fail("D0D50A operand differs from its load record at entry")
        m.watch(0x5960, 8)
        m.break_at(0xd6a)
        r = m.run(instructions = 35000000)
        if (r.kind != "breakpoint" or r.psw[-6:] != "000D6A" or
            m.read(0x5960, 8) != operand or m.registers().gr[9] != "00005000"):
            fail("unexpected D0D50A path to the first LPSW")
        print("D0D50A record 27, payload X'5958': %s, unchanged at X'5960' through LPSW" % binary.hex(operand))
        m.watch(0, 0)
        m.clear_breaks()
        m.history(keep = 12)
        r = m.run(instructions = 35000000)
        if r.kind != "idle" or r.psw != "D6039DBC 30E147F0" or m.screens(2):
            fail("D0D50A startup behavior changed on model %s: %s %s" % (model, r.kind, r.psw))
        print("D0D50A model %s: %s %s, console=%s" % (model, r.kind, r.psw, m.screens(2)[-8:]))
        print("\n".join(m.history()))
        return
    if len(args) == 1 and args[0] == "dual-dau-sdm":
        m = machine(tape)
        m.dau(0x20, peer = 0x420)
        m.ipl(0x130)
        res = sdm(m, message = "E/A,01F/I,01F,01F,01F,130/AB0020021/AB0020421/LB0A1,021,421/B",
                  budget = 90000000, step = 100000)
        lines = [line.strip() for line in res["transcript"]]
        if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
            [(s["section"], s["routines"]) for s in res["sections"]] != [("DB0A10", "01")] or
            "SECT. DB0A1 TERMINATED SECTION RUNS ONLY WITH MONITER-MDM" not in lines):
            fail("DB0A10 did not reproduce the original SDM monitor rejection")
        return
    if args and args[0] == "card-to-tape":
        m, _ = start_card_to_tape(tape)
        m.break_at(0x862e)
        r = m.run(instructions = 35000000)
        print("D70F12 %s %s, CSW %s" % (r.kind, r.psw, binary.hex(m.read(0x40, 8))))
        if r.kind != "breakpoint" or int(r.psw[-6:], 16) != 0x862e:
            fail("D70F12 missed the first Sense status branch")
        records = archive.simh(library_reel(tape)).records
        headers = [i for i, data in library_headers(records) if data[8:14] == "D70F12"]
        if len(headers) != 1:
            fail("expected one D70F12 library entry")
        payload = records[headers[0] + 1].data
        code = m.read(0x8622, 24)
        offset = 0x8622 - 0x8000
        if payload.bytes(offset, len(code)) != code:
            fail("loaded status tests differ from the library payload")
        print("Tape record %d + %x: %s" % (headers[0] + 1, offset, binary.hex(code)))
        print("\n".join(m.disassemble(0x8622, 6)))
        m.clear_breaks()
        for address in [0x862e, 0x8632, 0x8636]:
            if int(r.psw[-6:], 16) != address:
                fail("unexpected status path at %s" % r.psw)
            after = m.run(instructions = 1)
            print("D70F12 PSW %s -> %s" % (r.psw, after.psw))
            r = after
        retry = m.run(instructions = 1)
        print("D70F12 fallthrough takes %s" % retry.psw)
        print("\n".join(m.disassemble(int(retry.psw[-6:], 16), 4)))
        m.break_at(0x85d6)
        resume = m.run(instructions = 30000000)
        print("SVC 216 return: %s %s, timer %s" %
              (resume.kind, resume.psw, binary.hex(m.read(0x50, 4))))
        if resume.kind == "breakpoint":
            print("\n".join(m.disassemble(0x85d6, 4)))
            m.clear_breaks()
            for _ in range(2):
                resume = m.run(instructions = 1)
                print("D70F12 timer check: %s" % resume.psw)
            m.break_at(0x85f6)
            expired = m.run(instructions = 200000000)
            print("D70F12 timeout exit: %s %s, limit %s, timer %s" %
                  (expired.kind, expired.psw, m.registers().gr[1], binary.hex(m.read(0x50, 4))))
            if expired.kind == "breakpoint":
                m.clear_breaks()
                m.run(instructions = 2000000)
                print("\n".join(m.screens(0x01f)[-8:]))
        return
    if list(args) == ["printer-overlay", "device-end-restored"]:
        check_d635f2_device_end(tape)
        return
    if args and args[0] == "printer-overlay":
        if len(args) > 2 or (len(args) == 2 and args[1] != "all"):
            fail("usage: s370_diag.star printer-overlay [all]")
        exhaustive = len(args) == 2
        # Code groups from the PN character table printed by the guest.
        characters = {0x5f: "¬"}
        for first, group in [(0x4b, ".<(+|&"), (0x5b, "$*);"), (0x60, "-/"),
                             (0x6b, ",%_>?"), (0x7a, ":#@'=\""), (0xc1, "ABCDEFGHI"),
                             (0xd1, "JKLMNOPQR"), (0xe2, "STUVWXYZ"), (0xf0, "0123456789")]:
            for i in range(len(group)):
                characters[first + i] = group[i]
        for value in (range(256) if exhaustive else [0xc1, 0xf1, 0]):
            code = ("0%x" % value)[-2:].upper()
            character = characters.get(value, "")
            m = machine(tape)
            # The chain-clean utility needs top of form for the chained instructions.
            m.carriage_tape(0x00e, [[1]] + [[]] * 65)
            m.ipl(0x130)
            res = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,01F,130/S635F.0000" + code + "02/L635F/B",
                      budget = 20000000, step = 100000, show = not exhaustive)
            lines = m.output(0x00e)
            if res["ended"] != "end-of-job" or res["errors"] or res["skipped"]:
                fail("D635F2 overlay did not reach EOJ cleanly")
            if character and lines != [character * 132]:
                fail("D635F2 overlay %s expected %s in all 132 columns, received %s" % (code, character, lines))
            if not character and (len(lines) != 5 or not lines[0].startswith("THE CHARACTER YOU HAVE SELECTED IS INVALID") or
                                  "L635F/S635F.0000XX02/B/" not in lines[1] or not lines[2].startswith("HEX CHARACTERS") or
                                  not lines[3].strip().startswith("BCDEF") or not lines[4].startswith("PN  CHARACTERS")):
                fail("D635F2 did not print the invalid-character instructions")
            if not exhaustive:
                print("D635F2 overlay %s: %s" % (code, "\n".join(lines)))
        if exhaustive:
            print("D635F2 verified all 132 columns for %d codes and rejection for %d codes" %
                  (len(characters), 256 - len(characters)))
        return
    if args and args[0] == "console-exerciser":
        if len(args) != 2 or args[1] not in ["cancel", "cancel-original", "keyboard-parity", "not-ready"]:
            fail("usage: s370_diag.star console-exerciser cancel|cancel-original|keyboard-parity|not-ready")
        check_d66542_operator(tape, args[1])
        return
    if args and args[0] == "console-ribbon":
        if len(args) != 2 or args[1] not in ["present", "absent"]:
            fail("usage: s370_diag.star console-ribbon present|absent")
        installed = args[1] == "present"
        m = machine(tape, console_ribbon = installed)
        m.ipl(0x130)
        prompt = "DEPRESS REQ.IF NOT"
        res = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,00E,130/SS6652.0.6/L6652/B",
                  budget = 100000000, step = 100000, stop = prompt, show = False)
        if res["ended"] != "stop" or res["errors"]:
            fail("D66521 did not reach its ribbon prompt")
        # The complete prompt enters the transcript while the carrier is
        # still typing. Allow the full character cycles and carrier return.
        m.run(instructions = 6000000)
        if installed:
            m.key(0x01f, "REQUEST")
        else:
            m.key(0x01f, "NOT READY")
            m.key(0x01f, "READY")
        for _ in range(100):
            m.run(instructions = 500000)
            if any([line.strip() == END_OF_JOB for line in m.screens(0x01f)]):
                break
        lines = m.screens(0x01f)
        prompts = [i for i, line in enumerate(lines) if prompt in line]
        if len(prompts) != 1:
            fail("D66521 did not print exactly one ribbon prompt")
        start = prompts[0]
        end = [i for i, line in enumerate(lines) if line.strip() == "T   D66521 06 ROUTINES RUN"]
        expected = [
            "RIBBON SHIFT DOWN,SINGLE FEED",
            "RIBBON UP,DOUBLE FEED", "",
            "RIBBON DOWN,DOUBLE FEED", "",
            "RIBBON UP,SINGLE FEED",
            "RIBBON DOWN,SINGLE FEED",
        ] * 2 + ["SECT.2 ROUT.6 NO ERROR"] if installed else []
        if len(end) != 1 or [line.strip() for line in lines[start + 1:end[0]]] != expected:
            fail("D66521: unexpected ribbon output: %s" % lines[start + 1:])
        check_job(m, "D66521", ["T   D66521 06 ROUTINES RUN"])
        print("\n".join(lines[start:]))
        return
    if len(args) == 2 and args[0] == "printer-loops" and args[1] in ["late", "late-restored", "card", "card-early", "card-early-restored"]:
        check_d63564_reset(tape, args[1])
        return
    if len(args) == 1 and args[0] == "printer-loops":
        for selection, mask, reset, command in [
            ("SS6356.0", "80000000", "RS6356.0/", "0B"),
            ("SS6356.2", "20000000", "RS6356.2/", "09"),
            ("S6356.00010000", "00010000", "RS6356.15/", "01"),
        ]:
            m = machine(tape)
            m.ipl(0x130)
            explicit_command = command == "01"
            stop = "CHAN 12 DETECTED OK" if explicit_command else "HLT D63564"
            res = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,01F,130/W,00C/" + selection + "/L6356/B",
                      budget = 80000000, step = 100000, stop = stop)
            if res["ended"] != "stop" or res["errors"]:
                fail("D63564 did not reach the loop setup")
            if not explicit_command:
                m.run(instructions = 2000000)
                m.key(0x01f, "REQUEST")
                wait_1052_read(m)
                m.type(0x01f, "B")
            m.run(instructions = 10000000)
            if binary.hex(m.read(0x8004, 4)) != mask or END_OF_JOB in [line.strip() for line in m.screens(0x01f)]:
                fail("D63564 did not retain the selected switch in its loop")
            m.trace_io(skip = [0x130, 0x01f, 0x00c])
            m.run(instructions = 300000)
            transfers = [line for line in m.events() if " 000E cmds [" + command + " " in line]
            if len(transfers) < 2:
                fail("D63564 did not repeat printer command " + command)
            if explicit_command:
                impressions = [line.split(" impression ")[1].split() for line in m.events() if "printer 000E impression " in line]
                output = m.output(0x00e)
                pairs = 0
                for first, second in zip(impressions, impressions[1:]):
                    if first[2] != "01" or second[2] != "09":
                        continue
                    first_index, second_index = int(first[0]), int(second[0])
                    if second_index != first_index + 1 or first[3:7] != second[3:7] or first[8] != "0" or second[8] != "1":
                        fail("D63564 did not overprint before advancing one line")
                    failed, overprint = output[first_index - 1], output[second_index - 1]
                    column = failed.find("FAILED")
                    if column < 0 or overprint[column:column + 6] != "XXXXXX" or "SPACE SUPPRESS OK" not in overprint or failed.find("/") != overprint.find("/"):
                        fail("D63564 space-suppress impressions did not align")
                    pairs += 1
                if pairs < 2:
                    fail("D63564 did not repeat complete space-suppress pairs")
                print("D63564: %d space-suppress pairs overprinted on the same line before feeding" % pairs)
            m.trace_io(on = False)
            m.run(instructions = 9700000 if explicit_command else 1700000)
            m.key(0x01f, "REQUEST")
            wait_1052_read(m)
            m.type(0x01f, reset)
            m.run(instructions = 120000000)
            if m.read(0x8004, 4) != bytes([0] * 4):
                fail("D63564 operator reset did not clear the switch word")
            check_job(m, "D63564", ["CHAN 9 DETECTED OK", "CHAN 12 DETECTED OK", "T   D63564 03 ROUTINES RUN"], halts = 1)
            print("%s: observed %d printer commands X'%s', then %s released the loop and SDM reached EOJ" %
                  (selection, len(transfers), command, reset))
        return
    if len(args) == 1 and args[0] == "dual-2821":
        m = machine(tape)
        m.unit_record(0x028, type = "1403")
        m.unit_record_switch([(0x028, 0x428)])
        m.ipl(0x130)
        m.cards(0x00c, ["E/A,01F/A63000028/A63000428/I,01F,01F,01F,130/L6AA0,028,428/B"] + [""] * 20, replace = True)
        if m.run(instructions = 200000000).psw != SDM_READY:
            fail("D6AA00 SDM did not reach initial input wait")
        m.trace_io(skip = [0x130, 0x01f, 0x00c])
        m.interrupt_key()
        m.watch(0x75c, 1)  # 428 UDT CSW's device-status byte
        m.break_at(0x8574)
        m.history(keep = 4)
        updates = []
        for _ in range(80):
            result = m.run(instructions = 1000000)
            if result.kind == "watch":
                updates.append((binary.hex(m.read(0x75c, 1)), binary.hex(m.read(0x40, 8)), m.history()[-1]))
            if result.kind == "breakpoint":
                break
        endings = [e.split(" csw ")[1].split()[0] for e in m.events() if "interrupt 0428 csw " in e]
        section_csw = binary.hex(m.read(0x8040, 8))
        if (result.kind != "breakpoint" or section_csw != "0000000024000000" or
            endings[-2:] != ["0000000020000000", "0000000004000000"] or
            [entry[:2] for entry in updates[-2:]] != [("20", endings[-2]), ("24", endings[-1])] or
            not updates[-1][2].startswith("00000C40 96041000")):
            fail("D6AA00 did not reproduce the SDM status merge before the section test")
        for status, hardware_csw, instruction in updates[-2:]:
            print("0428 hardware CSW %s, SDM table status %s after %s" % (hardware_csw, status, instruction))
        print("D6AA00 at %s: section CSW %s" % (m.psw(), section_csw))

        m = machine(tape)
        m.unit_record(0x028, type = "1403")
        m.unit_record(0x029, type = "2540R", cards = ["2821 DIAGNOSTICS"] * 16)
        m.unit_record(0x02a, type = "2540P", reader = 0x029)
        m.unit_record(0x02b, type = "1403")
        m.unit_record(0x02c, type = "1403")
        m.unit_record_switch([(0x028 + i, 0x428 + i) for i in range(5)])
        m.ipl(0x130)
        sdm(m, message = "E/A,01F/I,01F,01F,01F,130/A63000028/A63000428/A62000029/A62000429/",
            budget = 5000000, step = 100000, show = False)
        for message in [
            "A6B00002A/A6B00042A/A6300002B/A6300042B/A6300002C/A6300042C/",
            "L6AA0,028,428,029,429,02A,42A,02B,42B,02C,42C/B/",
        ]:
            m.key(0x01f, "REQUEST")
            wait_1052_read(m)
            m.type(0x01f, message)
            if message.startswith("A"):
                m.run(instructions = 3000000)
        m.trace_io(skip = [0x130, 0x01f, 0x00c])
        for _ in range(5):
            m.break_at(0x8574)
            result = m.run(instructions = 120000000)
            if result.kind != "breakpoint":
                fail("D6AA00 did not reach the expected error handler")
            m.clear_breaks()
            if _ == 3:
                # Observe the section's reader-release wait after routine 09.
                reader_wait = False
                for attempt in range(64):
                    m.break_at(0x83c2)
                    wait = m.run(instructions = 20000000)
                    m.clear_breaks()
                    if wait.kind != "breakpoint":
                        fail("D6AA00 did not reach SVC D8")
                    if (m.read(0x923e, 1) == b"\x10" and m.registers().gr[12] == "00000029" and
                        m.read(0x91b0, 1) == b"\x14"):
                        reader_wait = True
                        break
                    m.run(instructions = 1)
                if not reader_wait:
                    fail("reader release wait missing")
                if m.read(0x83c2, 2) != b"\x0a\xd8" or m.read(0x3b4, 1) != b"\x00":
                    fail("unexpected reader wait instruction or PST mask")
                if (binary.hex(m.read(0x6b4, 4)) != "00900090" or
                    binary.hex(m.read(0x750, 16)) != "63000428cc000fff0000000020000000"):
                    fail("SDM did not queue the 428 control-unit end before the reader wait")
                print("029 release waits via SVC D8 at 83C2, PST mask 00")
                continue
            if m.read(0x923e, 1) == b"\x10":
                break
            m.run(instructions = 1)
        expected = ["resume 002C cmds [74 ", "interrupt 002C csw 000091B80C000088",
                    "resume 0028 cmds [14 ", "interrupt 0028 csw 000091B80C000088",
                    "interrupt 0428 csw 0000000020000000"]
        # The reader's release is issued, but its completion has yet to
        # interrupt when the diagnostic checks the unsolicited 428 status.
        relevant = [e for e in m.events() if " cmds [" in e or " interrupt " in e][-6:]
        if (len(relevant) != 6 or any([needle not in e for needle, e in zip(expected, relevant)]) or
            "resume 0029 cmds [14 " not in relevant[-1] or m.read(0x923e, 1) != b"\x10" or
            binary.hex(m.read(0x8038, 16)) != "00040428400083c40000000020000000"):
            fail("D6AA00 routine 10 interrupt order changed")
        # SCH1 enables interrupts for one instruction before disabling them again.
        if ("FF040000 0000102A interrupt 0428" not in relevant[-2] or
            binary.hex(m.read(0x1022, 12)) != "800006144700d02680000616" or
            binary.hex(m.read(0x614, 3)) != "ff0000"):
            fail("unexpected SDM interrupt mask at the routine 10 control-unit end")
        if (binary.hex(m.read(0x6b4, 4)) != "ffffffff" or
            binary.hex(m.read(0x750, 16)) != "63000428c8000fff0000000020000000"):
            fail("SDM did not remove the 428 status from its interrupt queue")
        print("SDM queue at reader wait: first=last=0090 (428 Control Unit End); empty at error handler")
        print("D6AA00 routine 10, test 3:")
        print("\n".join(relevant))
        for device, status in [("0029", "0C000054"), ("002A", "0C000054"),
                               ("002B", "0C000088"), ("002C", "0C000088")]:
            m.run(instructions = 1)
            m.break_at(0x8574)
            result = m.run(instructions = 20000000)
            m.clear_breaks()
            csw = "000091B8" + status
            observed = binary.hex(m.read(0x803a, 2)).upper()
            interrupts = [e for e in m.events() if " interrupt " in e and " csw " in e]
            if (result.kind != "breakpoint" or observed != device or
                binary.hex(m.read(0x8040, 8)).upper() != csw or
                "interrupt " + device + " csw " + csw not in interrupts[-1]):
                fail("D6AA00 routine 10 interrupt mismatch at device " + device)
            print("D6AA00 error handler received device %s CSW %s" % (observed, csw))
        m.trace_io(on = False)
        m.run(instructions = 120000000)
        lines = [line.strip() for line in m.screens(0x01f)]
        errors = [line.split()[3] for line in lines if line.startswith("* SD0 D6AA00 ")]
        if ("S   D6AA00" not in lines or "T   D6AA00 17 ROUTINES RUN" not in lines or END_OF_JOB not in lines or
            errors != ["08", "08", "09", "09", "10", "10", "10", "10", "10"]):
            fail("D6AA00 original SDM results changed: " + str(errors))
        print("\n".join(lines))
        return
    if len(args) == 1 and args[0] == "printer-switch":
        switched_commands = ["F4", "D4", "B4", "94", "74", "54", "34", "14"]
        for ucs, installed, switch28, address, impressions in [
            (False, False, False, "008", 175),
            (False, True, True, "008", 167),
            (False, True, True, "308", 167),
            (True, False, False, "008", 172),
            (True, True, False, "008", 172),
            (True, True, True, "308", 164),
        ]:
            m = machine(tape)
            m.unit_record(0x008, type = "1403", ucs = ucs)
            m.carriage_tape(0x008, CE_TAPE)
            if installed:
                m.unit_record_switch([(0x008, 0x308)])
            m.ipl(0x130)
            option = "10" if ucs else "00"
            selection = "SS6352.28/L6352" if switch28 else "L6352"
            res = sdm(m, message = "E/A,01F/A63" + option + "0" + address + "/I,01F,01F,01F,130/W,00C/" + selection + "/B",
                      budget = 60000000, step = 100000, show = False)
            lines = [line.strip() for line in res["transcript"]]
            output = m.output(0x008)
            if (res["ended"] != "end-of-job" or res["skipped"] or len(output) != impressions or
                [(section["section"], section["routines"]) for section in res["sections"]] != [("D63523", "07")] or
                binary.hex(m.read(0x8004, 4)) != ("00000008" if switch28 else "00000000") or
                (installed and m.output(0x308) != output)):
                fail("D63523: unexpected completion at " + address)
            rejected_by_test = [line.split()[1][:2] for line in lines if line.startswith("CCW ")]
            expected = switched_commands if installed and not switch28 else []
            if rejected_by_test != expected or len(res["errors"]) != 2 * len(expected):
                fail("D63523: unexpected command tests at " + address + ": " + str(rejected_by_test))
            print("D63523 %s: UCS=%s, second path=%s, switch 28=%s, %d impressions, %d command mismatches" %
                  (address, ucs, installed, switch28, impressions, len(expected)))
        return
    if len(args) == 1 and args[0] == "printer-ripple":
        results = []
        for option, switch24, dualing, impressions in [
            ("00", False, False, 256),
            ("12", False, False, 512),
            ("12", True, False, 512),
            ("12", True, True, 512),
        ]:
            m = machine(tape, printer_dualing = dualing)
            m.ipl(0x130)
            selection = "SS6354.24/L6354" if switch24 else "L6354"
            res = sdm(m, message = "E/A,01F/A63" + option + "000E/I,01F,01F,01F,130/W,00C/" + selection + "/B",
                      budget = 300000000, step = 100000, show = False)
            output = m.output(0x00e)
            if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                [(s["section"], s["routines"]) for s in res["sections"]] != [("D63543", "02")] or
                len(output) != impressions or (m.printer_ucs(0x00e) != None) != (option == "12") or
                binary.hex(m.read(0x8004, 4)) != ("00000080" if switch24 else "00000000")):
                fail("D63543: unexpected ripple result for option %s, switch 24=%s, dualing=%s" % (option, switch24, dualing))
            results.append(output)
        switch_effect = len([1 for before, after in zip(results[1], results[2]) if before != after])
        if switch_effect != 64:
            fail("D63543 switch 24 did not change the expected ripple impressions")
        changes = {}
        for before, after in zip(results[2], results[3]):
            if len(before) != len(after):
                fail("D63543 dualing changed the print width")
            for original, dualed in zip(before.elems(), after.elems()):
                if original != dualed:
                    pair = (original, dualed)
                    changes[pair] = changes.get(pair, 0) + 1
        expected = {("(", "%"): 256, (")", "<"): 256, ("'", "@"): 256, ("=", "#"): 256}
        if changes != expected:
            fail("D63543: unexpected dualed characters " + str(changes))
        print("D63543: 256 basic and 512 UCS impressions; switch 24 changed 64 lines; each of four duals was observed 256 times")
        return
    if len(args) == 1 and args[0] == "printer-ucs":
        # The original section repeats each built-in 60-byte chain image
        # four times to fill the 240-byte UCS buffer.
        pn = ("f1f2f3f4f5f6f7f8f9f0e7e861e2e3e4e5e64f7a6d7f6b7e" +
              "d1d2d3d4d5d6d7d8d960e94dc1c2c3c4c5c6c7c8c94e4b5d6c5b5c7b507c4c5e5f7d6f6e")
        hn = ("f1f2f3f4f5f6f7f8f9f07e7d61e2e3e4e5e6e7e8e9506b4d" +
              "d1d2d3d4d5d6d7d8d9605b5cc1c2c3c4c5c6c7c8c94e4b5df1f2f3f4f5f6f7f8f9f07e7d")
        # Rotate the PN chain by one position to distinguish the operator
        # image from both built-in selections while retaining its glyphs.
        custom = pn[2:] + pn[:2]
        for option, image, abort in [
            ("00", "", ""),
            ("11", pn, ""),
            ("12", hn, ""),
            ("13", custom, ""),
            ("13", custom[:60], "CHAIN IMAGE NOT LOADED VIA E PATCH"),
            ("13", "", "CHAIN IMAGE NOT LOADED VIA E PATCH"),
            ("10", "", "I/O OPTIONS DID NOT DEFINE 1403 CHAIN"),
        ]:
            m = machine(tape)
            m.ipl(0x130)
            observations = []
            def handle(m, line, section):
                if section == "D63564" and line.strip() == "MAKE PRNTR RDY":
                    m.carriage_tape(0x00e, CE_TAPE)
                    m.key(0x00e, "RESTORE")
                    m.key(0x00e, "READY")
                    observations.append(m.carriage_position(0x00e).line)
                    return "installed the test carriage tape and restored to channel 1"
                if section == "D63564" and line.strip().startswith("HLT ") and option == "13" and image:
                    # EPATCH is the 240-byte operator data area addressed
                    # by the CLC and MVC at the option-13 branch.
                    area = 0x9c00
                    data = (image if abort else image * 4).upper()
                    if binary.hex(m.read(0x8192, 6)) != "d503ec00fd90" or m.read(area, 240) != bytes([0] * 240):
                        fail("D63564 EPATCH area or program layout changed")
                    m.run(instructions = 2000000)
                    for offset in range(0, len(data) // 2, 30):
                        m.key(0x01f, "REQUEST")
                        wait_1052_read(m)
                        m.type(0x01f, "E%X.1E.%s/" % (area + offset, data[offset * 2:(offset + 30) * 2]))
                        m.run(instructions = 3000000)
                    if binary.hex(m.read(area, 240)) != data.lower() + "0" * (480 - len(data)):
                        fail("SDM did not store the operator's custom chain image")
                    operator(m, line, section)
                    return "entered the custom chain on the 1052 and continued with B"
                return operator(m, line, section)
            res = sdm(m, message = "E/A,01F/A63" + option + "000E/I,01F,01F,01F,130/W,00C/L6356/B",
                      budget = 150000000, step = 100000, handle_operator = handle)
            lines = [line.strip() for line in res["transcript"]]
            completed = "01" if abort else "03"
            if (res["ended"] != "end-of-job" or res["skipped"] or observations != [1] or
                [(s["section"], s["routines"]) for s in res["sections"]] != [("D63564", completed)]):
                fail("D63564 option " + option + " did not complete its expected routines")
            ucs = m.printer_ucs(0x00e)
            expected_ucs = binary.decode(image * 4, "hex") if image and not abort else None
            if ucs != expected_ucs:
                fail("D63564 option " + option + " loaded an unexpected UCS buffer")
            if abort:
                if abort not in lines or len(res["errors"]) != 2 or res["errors"][-1].strip() != "*  SECTION ABORTED" or m.output(0x00e):
                    fail("D63564 option " + option + " did not abort before printing")
            elif (res["errors"] or "CHAN 9 DETECTED OK" not in lines or "CHAN 12 DETECTED OK" not in lines or
                  len(m.output(0x00e)) != 68 or m.carriage_position(0x00e).lines_advanced != (291 if image else 225)):
                fail("D63564 option " + option + " did not finish the expected carriage operations")
        return
    if list(args) == ["printer-manual", "dualing-restored"]:
        check_d63534_dualing(tape)
        return
    if args and args[0] == "printer-manual":
        if len(args) != 2 or args[1] not in ["carriage", "dualing"]:
            fail("usage: s370_diag.star printer-manual carriage|dualing")
        dualing = args[1] == "dualing"
        m = machine(tape, printer_dualing = dualing)
        m.ipl(0x130)
        device = "A6312000E" if dualing else "A,00E"
        selection = "L6353" if dualing else "SS6351.5/L6351"
        observations = []
        res = sdm(m, message = "E/A,01F/" + device + "/I,01F,01F,01F,130/W,00C/" + selection + "/B",
                  budget = 150000000, step = 100000, handle_operator = observe_printer_carriage(observations))
        print("%s, sections=%s, errors=%s" % (res["ended"], res["sections"], res["errors"]))
        if not dualing:
            if len(observations) != 4:
                fail("D63514 did not issue all three carriage observations")
            advances = [observations[i + 1].lines_advanced - observations[i].lines_advanced for i in range(3)]
            print("D63514 observed carriage advances: %s" % advances)
            if advances != [0, 0, len(CE_TAPE)]:
                fail("D63514 manual carriage observations differ from expected motion")
            if res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or "END OF RTN" not in [line.strip() for line in res["transcript"]]:
                fail("D63514 did not complete its manual carriage routine")
        return
    if args and args[0] == "channel-restart":
        m = start_ctc_restart(tape)
        print("Restart setup " + m.disassemble(0x97dc, 1)[0])
        print("R7/R8 before saving ATR", m.registers().gr[7:9])
        m.break_at(0x9420)
        r = m.run(instructions = 80000000)
        print("\n".join(m.screens(0x01f)[-12:]))
        print("DA0515 %s %s, restart PSW=%s" % (r.kind, r.psw, binary.hex(m.read(0, 8))))
        return
    if args and args[0] == "faa-mdm-tape-id":
        if len(args) > 2 or (len(args) == 2 and args[1] != "inline"):
            fail("usage: s370_diag.star faa-mdm-tape-id [inline]")
        inline = len(args) == 2
        check_mdm_tape_id(tape, inline)
        return
    if args and args[0] == "tape-dump-selection":
        values = ["1122", "3344", "5566", "7788", "99AA"]
        reel = binary.builder(capacity = 58)
        for value in values:
            reel.append(binary.decode("02000000" + value + "02000000", "hex"))
        reel.append(b"\x00\x00\x00\x00\x00\x00\x00\x00")
        for switches, count in [("04000002", 4), ("05000002", 1), ("07000002", 3)]:
            m = machine(tape)
            m.tape(0x3f0, reel.file(), type = "2401", format = "simh")
            m.ipl(0x130)
            res = sdm(m, message = "E/A,01F/A400003F0/I,01F,01F,01F,130/S4156." + switches + "/L4156/B",
                      budget = 60000000, step = 100000, show = False)
            lines = [line.strip() for line in res["transcript"]]
            records = [line for line in lines if line.startswith("RECORD NUMBER ")]
            data = [line.split()[1].upper() for line in lines if line.startswith("000000 ")]
            expected = ["RECORD NUMBER 0000000%d  BYTE COUNT 0002" % (i + 2) for i in range(count)]
            if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                records != expected or data != values[1:1 + count]):
                fail("D41560 %s: unexpected dump (%s %s %s %s)" % (switches, res["ended"], res["errors"], records, data))
            print("D41560 switch word %s: %s" % (switches, data))
        # SIMH flags the two-byte record as a recoverable data error.
        bad = binary.builder(capacity = 18)
        bad.append(binary.decode("020000803344020000800000000000000000", "hex"))
        for switches, print_record in [("80000000", True), ("C0000000", False)]:
            m = machine(tape)
            m.tape(0x3f0, bad.file(), type = "2401", format = "simh")
            m.ipl(0x130)
            res = sdm(m, message = "E/A,01F/A400003F0/I,01F,01F,01F,130/S4156." + switches + "/L4156/B",
                      budget = 60000000, step = 100000, show = False)
            lines = [line.strip() for line in res["transcript"]]
            data = [line.split()[1] for line in lines if line.startswith("000000 ")]
            expected_data = ["3344"] if print_record else []
            if (res["ended"] != "end-of-job" or res["skipped"] or len(res["errors"]) != 1 or
                not res["errors"][0].startswith("* *3F0 STA2 S 08") or "DATA CHECK" not in lines or
                len([line for line in lines if line == "001 ERRORS ENCOUNTERED ON TAPE NO"]) != 2 or data != expected_data):
                fail("D41560 %s: unexpected data-check handling: %s" % (switches, lines[-18:]))
            print("D41560 switch word %s: one data check, printed bytes=%s" % (switches, data))
        for reselect in [False, True]:
            m = machine(tape)
            for drive, values in [(0x3f0, ["1122"]), (0x3f1, ["3344", "5566"] if reselect else ["3344"])]:
                scratch = binary.builder(capacity = 28)
                for value in values:
                    scratch.append(binary.decode("02000000" + value + "02000000", "hex"))
                scratch.append(b"\x00\x00\x00\x00\x00\x00\x00\x00")
                m.tape(drive, scratch.file(), type = "2401", format = "simh")
            m.ipl(0x130)
            halts = []
            def continue_dump(m, line, section):
                if line.strip().startswith("HLT D41560"):
                    halts.append(line)
                    if len(halts) == 2 and reselect:
                        m.key(0x01f, "REQUEST")
                        m.run(instructions = 2000000)
                        m.type(0x01f, "S4156.05000002/B")
                        return "selected only the second record on drive 3F1"
                return operator(m, line, section)
            res = sdm(m, message = "E/A,01F/A400003F0/A400003F1/I,01F,01F,01F,130/SS4156.4/L4156/B",
                      budget = 100000000, step = 100000, show = False, handle_operator = continue_dump)
            lines = [line.strip() for line in res["transcript"]]
            dumps = [line.split()[1] for line in lines if line.startswith("000000 ")]
            eofs = [line.split()[5] for line in lines if line.startswith("END OF FILE - DEVICE ")]
            second = "5566" if reselect else "3344"
            if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                dumps != ["1122", second] or eofs != ["3F0", "3F0", "3F1", "3F1"] or len(halts) != 2 or
                "RE-ENTER SENSE MESSAGE FOR DESIRED DUMP CONFIGURATION" not in lines):
                fail("D41560 next-tape selection: %s" % lines)
            print("D41560 next tape: 3F0=%s, 3F1=%s, reselected=%s" % (dumps[0], dumps[1], reselect))
        return
    if args and args[0] == "reader-timing":
        if len(args) not in [2, 3] or (len(args) == 3 and args[2] not in ["ready", "mismatch", "delay"]):
            fail("usage: s370_diag.star reader-timing raw-card-deck [ready|mismatch|delay]")
        ready_test = len(args) == 3
        mismatch = ready_test and args[2] == "mismatch"
        delay_test = ready_test and args[2] == "delay"
        punch = machine(tape, punch = True)
        punch.ipl(0x130)
        punched = sdm(punch, message = "E/A,01F/A,00E/A6B00000D/I,01F,01F,01F,130/L6251/B",
                      budget = 100000000, step = 100000, show = False)
        cards = punch.output(0x00d, raw = True)
        if punched["ended"] != "end-of-job" or punched["errors"] or len(cards) != 336:
            fail("D62511 did not produce the detail deck for the reader")
        details = cards[-257:-1]
        valid = read_raw_deck(open(args[1]))
        if ready_test:
            if mismatch:
                details = details[:32] + [details[33]] + details[33:]
            variants = ["SS6263.24/", "SS6263.25/", "SS6263.26/", "SS6263.28/"] if delay_test else [""] if mismatch else ["", "SS6263.13/"]
            for switches in variants:
                m = machine(tape)
                m.ipl(0x130)
                def stop_reader(m, line, section):
                    if delay_test and DETAIL_DECK in line:
                        m.event_limit(8192)
                        m.trace_io(skip = [0x130, 0x01f, 0x00e], quiet_polls = True)
                    if "MAKE 2501 RDR NOT RDY" in line:
                        m.key(0x00c, "STOP")
                        m.trace_io(skip = [0x130, 0x01f, 0x00e])
                        return "stopped the reader"
                    if line.strip() == "END RT. 5":
                        m.trace_io(on = False)
                    return operator(m, line, section)
                res = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,01F,130/" + switches + "L6263/B",
                          budget = 200000000, step = 100000, detail_cards = details, valid_cards = valid,
                          show = False, handle_operator = stop_reader)
                lines = [line.strip() for line in res["transcript"]]
                if delay_test:
                    reads = [int(e.split("tod=")[-1], 16) for e in m.events() if "resume 000C cmds [02 f=20 n=80 st=0C " in e]
                    gaps = [later - earlier for earlier, later in zip(reads, reads[1:])]
                    if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                        [(s["section"], s["routines"]) for s in res["sections"]] != [("D62630", "06")] or
                        "END RT. 6" not in lines or len(reads) != 256):
                        fail("D62630 did not finish the selected delayed card comparison")
                    # The loaded section omits the fixed DLY macros in the FAA listing.
                    fixed_dispatch = ("9180f00747e0ffc89104f0044710fdc847f0fdb4"
                                      + "9140f00747e0ffdc9104f0044710fdc847f0fdb4"
                                      + "9104f0044710fdc847f0fdb4")
                    if binary.hex(m.read(0x8fb4, 52)) != fixed_dispatch:
                        fail("D62630 fixed-delay dispatch differs from the inspected reel")
                    if switches == "SS6263.28/":
                        if m.read(0x8fac, 4) != b"\x0a\xd8\x0a\xd8":
                            fail("D62630 final delay does not call the SDM delay service twice")
                        warning = "VARIABLE DELAY SELECTED,THERE WILL BE A DELAY OF TWENTY SECONDS BETWEEN"
                        if (warning not in lines or "THE READING OF THE LAST  SIX CARDS" not in lines or
                            not all([gap < 100000 for gap in gaps[:-6]]) or
                            not all([20000000 <= gap and gap < 20200000 for gap in gaps[-6:]])):
                            fail("D62630 did not delay the last six card reads by twenty seconds")
                        print("D62630 variable delay: six final reads separated by about 20.08 seconds")
                    else:
                        milliseconds = {"SS6263.24/": 16, "SS6263.25/": 25, "SS6263.26/": 50}[switches]
                        if ("%d MSECONDS DELAY SELECTED" % milliseconds not in lines or
                            not all([62000 <= gap and gap < 62300 for gap in gaps])):
                            fail("D62630 fixed-delay selection changed its report or observed reader cadence")
                        print("D62630 %d ms setting: observed read cadence %d us" % (milliseconds, gaps[0]))
                    continue
                if mismatch:
                    report = "COMPARE ERR,CARD NO. 20, HEX, IN PRESTK.STA."
                    columns = []
                    for column in range(80):
                        number = ("0" + str(column + 1))[-2:]
                        actual = ("%x" % (0x21 + column)).upper()
                        expected = ("%x" % (0x20 + column)).upper()
                        columns.append("%s   %s   %s" % (number, actual, expected))
                    if (res["ended"] != "end-of-job" or res["skipped"] or res["errors"] != [report] or
                        [(s["section"], s["routines"]) for s in res["sections"]] != [("D62630", "06")] or
                        "COL. ACT. EXP." not in lines or
                        lines[lines.index("COL. ACT. EXP.") + 1:][:80] != columns or "END RT. 6" not in lines):
                        fail("D62630 did not report the substituted detail card and all 80 differences")
                    print(report)
                    print("D62630 reported all 80 column differences and reached SDM end of job")
                    return
                selected = switches != ""
                not_ready = [e for e in m.events() if "TIO 000C cc 1 csw 0000000002000000" in e]
                if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                    [(s["section"], s["routines"]) for s in res["sections"]] != [("D62630", "06")] or
                    ("MAKE 2501 RDR NOT RDY" in lines) != selected or ("END RT. 5" in lines) != selected or
                    bool(not_ready) != selected or "END RT. 6" not in lines):
                    fail("D62630 did not complete the expected ready/compare path: %s" % lines[-16:])
                print("D62630 %s: not-ready test %s, detail-card compare and SDM end of job reached" %
                      (switches or "default", "ran" if selected else "bypassed"))
            return
        for burst in [False, True]:
            m = machine(tape, punch = True)
            m.ipl(0x130)
            stackers, prompts = [], []
            def observe(m, line, section):
                if "BURST MODE SW ON" in line:
                    prompts.append(line.strip())
                    if burst:
                        m.key(0x00c, "BURST MODE")
                if "PLACE VALID CDS" in line or "SHD HAVE 0025 CDS IN R1" in line:
                    stackers.append(m.reader_stackers(0x00c))
                return operator(m, line, section)
            res = sdm(m, message = "E/A,01F/A,00E/I,01F,01F,01F,130/SS6262.2/L6262/B",
                      budget = 200000000, step = 100000, detail_cards = details, valid_cards = valid,
                      show = False, handle_operator = observe)
            if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                [(s["section"], s["routines"]) for s in res["sections"]] != [("D62620", "02")] or
                prompts != ["IF THIS TST USED FOR TIMING TURN BURST MODE SW ON IN CNTROL UNIT"] or len(stackers) != 2):
                fail("D62620 did not complete the reader timing test")
            advances = [stackers[1][i] - stackers[0][i] for i in range(3)]
            if advances != [25, 25, 25]:
                fail("D62620 reader timing test sent %s cards to the stackers" % advances)
            print("D62620 %s: stackers %s, SDM end of job" % ("burst" if burst else "multiplex", advances))
        return
    if args and args[0] == "punch-timing":
        if len(args) > 2 or (len(args) == 2 and args[1] != "burst"):
            fail("usage: s370_diag.star punch-timing [burst]")
        burst = len(args) == 2
        m = machine(tape, punch = True)
        m.ipl(0x130)
        prompt = "IF THIS TST USED FOR TIMING TURN BURST MODE SW ON IN CNTROL UNIT"
        res = sdm(m, message = "E/A,01F/A,00E/A6B00000D/I,01F,01F,01F,130/L6251/B",
                  budget = 100000000, step = 100000, stop = prompt, show = False)
        if res["ended"] != "stop" or res["errors"]:
            fail("D62511 did not reach the ripple timing prompt")
        if burst:
            m.key(0x00d, "BURST MODE")
        m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
        seen = len(m.screens(0x01f))
        readied = False
        for _ in range(80):
            m.run(instructions = 100000)
            lines = m.screens(0x01f)[seen:]
            if any(["DO NPRO,PLACE BLANK CDS IN PUNCH HOPPER,MAKE RDY" in line for line in lines]):
                operator(m, "DO NPRO,PLACE BLANK CDS IN PUNCH HOPPER,MAKE RDY", "D62511")
                readied = True
                break
        if not readied:
            fail("D62511 did not request a fresh punch hopper before timing")
        m.run(instructions = 1500000)
        channel_ends = [e for e in m.events() if "interrupt 000D csw 00008FF808000000" in e]
        device_ends = [e for e in m.events() if "device end 000D -> dev 04" in e]
        delays = [int(de.split("tod=")[-1], 16) - int(ce.split("tod=")[-1], 16)
                  for ce, de in zip(channel_ends, device_ends)]
        if len(delays) < 4 or not all([delay == 200000 for delay in delays]):
            fail("D62511 did not show the expected split Channel End and Device End: %s" % delays)
        print("D62511 %s: %d punch transfers had Device End 200000 us after Channel End" %
              ("burst" if burst else "multiplex", len(delays)))
        m.trace_io(on = False)
        for _ in range(150):
            m.run(instructions = 500000)
            lines = [line.strip() for line in m.screens(0x01f)]
            if END_OF_JOB in lines:
                break
        if (END_OF_JOB not in lines or "T   D62511 06 ROUTINES RUN" not in lines or
            any([line.startswith("*") for line in lines]) or m.punch_stackers(0x00d) != (285, 25, 25)):
            fail("D62511 failed to complete the ripple test in the selected transfer mode")
        return
    if args and args[0] == "punch-card-loop":
        if len(args) != 1:
            fail("usage: s370_diag.star punch-card-loop")
        m = machine(tape, punch = True)
        m.ipl(0x130)
        res = sdm(m, message = "E/A,01F/A,00E/A6B00000D/I,01F,01F,01F,130/SS6251.5/L6251/B",
                  budget = 100000000, step = 100000, stop = "HLT D62511 06")
        prompt = "ENTER CARD NO.,IN HEX,INTO STORAGE LOC. 0080FD"
        halts = [line.strip() for line in res["transcript"] if line.strip().startswith("HLT D62511 06 ")]
        if (res["ended"] != "stop" or res["errors"] or res["skipped"] or len(halts) != 1 or
            prompt not in [line.strip() for line in res["transcript"]]):
            fail("D62511 did not ask for a card number")
        before = len(m.output(0x00d, raw = True))
        m.alter(0x80fd, b"\x31")
        m.run(instructions = 2000000)
        operator(m, halts[0], "D62511")
        m.run(instructions = 1500000)
        cards = m.output(0x00d, raw = True)[before:]
        expected = bytes(range(0x31, 0x31 + 80))
        if len(cards) < 3 or not all([card == expected for card in cards]) or m.read(0x8004, 1) != b"\x04":
            fail("D62511 did not repeatedly punch the selected card")
        m.alter(0x8004, b"\x00")
        m.run(instructions = 5000000)
        lines = [line.strip() for line in m.screens(0x01f)]
        final_cards = m.output(0x00d, raw = True)[before:]
        if (END_OF_JOB not in lines or "T   D62511 06 ROUTINES RUN" not in lines or
            any([line.startswith("*") for line in lines]) or len(final_cards) > len(cards) + 1 or
            not all([card == expected for card in final_cards])):
            fail("D62511 did not exit the card loop cleanly")
        print("D62511 punched %d copies of card X'31' and reached SDM end of job after clearing switch 5" % len(final_cards))
        return
    if args and args[0] == "punch-switches":
        if len(args) != 1:
            fail("usage: s370_diag.star punch-switches")
        titles = ["RT.1 NOT RDY.TST", "RT.2 RDY TST", "RT.3 BSY TST", "RT.4 CMND.TST",
                  "RT.5 STACKER ESLECT", "RT.6 RIPPLE PCH TEST"]
        for switches, printed, ripple in [("", [], True), ("SS6251.2/", titles, True), ("SS6251.2.14/", titles[:-1], False)]:
            m = machine(tape, punch = True)
            m.ipl(0x130)
            res = sdm(m, message = "E/A,01F/A,00E/A6B00000D/I,01F,01F,01F,130/" + switches + "L6251/B",
                      budget = 100000000, step = 100000, show = False)
            lines = [line.strip() for line in res["transcript"]]
            stackers = m.punch_stackers(0x00d)
            if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
                [(s["section"], s["routines"]) for s in res["sections"]] != [("D62511", "06")] or
                [line for line in lines if line.startswith("RT.")] != printed or
                ("IF THIS TST USED FOR TIMING TURN BURST MODE SW ON IN CNTROL UNIT" in lines) != ripple or
                stackers != ((285, 25, 25) if ripple else (28, 25, 25))):
                fail("D62511 option selection did not match %s: %s" % (switches, lines))
            print("D62511 %s: %d titles, ripple %s, stackers %s, SDM end of job" %
                  (switches or "default", len(printed), "ran" if ripple else "bypassed", stackers))
        return
    if args and args[0] == "disk-track-loop":
        if len(args) > 2 or (len(args) == 2 and args[1] not in ["limits", "bad", "transient", "move-retry", "soft-halt", "hard-report", "hard-halt", "error-loop", "unplug", "unplug-sio", "unplug-loop", "scope"]):
            fail("usage: s370_diag.star disk-track-loop [limits|bad|transient|move-retry|soft-halt|hard-report|hard-halt|error-loop|unplug|unplug-sio|unplug-loop|scope]")
        move_retry = len(args) == 2 and args[1] == "move-retry"
        error_loop = len(args) == 2 and args[1] == "error-loop"
        soft_halt = len(args) == 2 and args[1] == "soft-halt"
        transient = soft_halt or move_retry or (len(args) == 2 and args[1] == "transient")
        hard_halt = len(args) == 2 and args[1] == "hard-halt"
        hard_report = hard_halt or (len(args) == 2 and args[1] == "hard-report")
        bad = transient or hard_report or error_loop or (len(args) == 2 and args[1] == "bad")
        m = machine(tape)
        m.dasd(0x340, type = "2314", cylinders = 203, volser = "DIAG01", read_only = True)
        m.ipl(0x130)
        mode = args[1] if len(args) == 2 else ""
        switches = {
            "soft-halt": "SS806A.5.9.11/",
            "hard-halt": "SS806A.5.9.14/",
            "hard-report": "SS806A.9.14/",
            "bad": "SS806A.9/",
            "transient": "SS806A.9/",
            "move-retry": "SS806A.9.10/",
            "error-loop": "SS806A.9.12/",
            "unplug": "",
            "unplug-sio": "",
            "unplug-loop": "SS806A.1/",
            "scope": "",
        }.get(mode, "SS806A.13/")
        res = sdm(m, message = "E/A,01F/A80000340/I,01F,01F,01F,130/SW.00000400/" + switches + "L806A/B",
                  budget = 15000000, step = 100000, stop = "READY PACK OR POP ID PLUG")
        if res["ended"] != "stop" or res["errors"]:
            fail("D806A5 did not request a pack for single-track testing")
        m.run(instructions = 100000)
        if bad:
            expected_switches = {
                "soft-halt": b"\x04\x50",
                "hard-halt": b"\x04\x42",
                "hard-report": b"\x00\x42",
                "error-loop": b"\x00\x48",
                "move-retry": b"\x00\x60",
            }.get(mode, b"\x00\x40")
            if m.read(0x8004, 2) != expected_switches:
                fail("D806A5 did not load the requested track-error switches")
            m.dasd_r0_read_checks(0x340, 7, 3, 10000 if error_loop else 1 if transient else 10)
        m.key(0x340, "REMOVE ID PLUG")
        m.key(0x340, "INSERT ID PLUG")
        if mode in ["unplug", "unplug-sio", "unplug-loop", "scope"]:
            selection = 0x8464 if mode in ["unplug", "unplug-loop"] else 0x8478
            m.break_at(selection)
            starting = "STARTING VOL ID DIAG01 ON DRIVE 340"
            for _ in range(20):
                r = m.run(instructions = 8000000)
                if r.kind != "breakpoint" or int(r.psw[-6:], 16) != selection:
                    fail("D806A5 did not reach its drive selection")
                if starting in [line.strip() for line in m.screens(0x01f)]:
                    break
                m.clear_breaks()
                m.run(instructions = 1)
                m.break_at(selection)
            if starting not in [line.strip() for line in m.screens(0x01f)] or "pending=false" not in m.subchannel(0x340):
                fail("D806A5 did not reach an idle drive selection after identifying the pack")
            if mode == "unplug-loop" and m.read(0x8004, 1) != b"\x40":
                fail("D806A5 did not load hardware-error loop switch 1")
            m.clear_breaks()
            if mode == "scope":
                m.alter(0x8004, b"\x80")
                caw = m.read(0x48, 4)
                read_before = m.dasd_usage()[0x340]["read"]
                for _ in range(3):
                    m.run(instructions = 1)
                    m.break_at(selection)
                    r = m.run(instructions = 1000000)
                    if r.kind != "breakpoint" or m.read(0x48, 4) != caw:
                        fail("D806A5 scope did not revisit Start I/O with its original CAW")
                    m.clear_breaks()
                if m.dasd_usage()[0x340]["read"] != read_before:
                    fail("D806A5 advanced the scan with the scope switch still set")
                m.alter(0x8004, b"\x00")
                for _ in range(120):
                    m.run(instructions = 500000)
                    lines = [line.strip() for line in m.screens(0x01f)]
                    if "EVALUATION COMPLETE VOL DIAG01 DRIVE 340" in lines:
                        break
                usage = m.dasd_usage()[0x340]
                if ("EVALUATION COMPLETE VOL DIAG01 DRIVE 340" not in lines or
                    [line for line in lines if line.startswith("* ")] != ["* TOTAL OF 0000 BAD TRACKS"] or
                    usage["read"] != [(0, 4059)] or usage["written"]):
                    fail("D806A5 did not finish the scan after clearing switch 0")
                print("D806A5 repeated Start I/O three times, then completed the full scan after clearing switch 0")
                return
            m.key(0x340, "REMOVE ID PLUG")
            if mode == "unplug-sio":
                m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e])
                m.run(instructions = 18)
                selections = [line for line in m.events() if "SIO 0340" in line or "TIO 0340" in line]
                m.trace_io(on = False)
                if (len(selections) < 2 or "008478 SIO 0340 cc 3" not in selections[0] or
                    not all(["008464 TIO 0340 cc 3" in line for line in selections[1:]])):
                    fail("D806A5 did not retry rejected Start I/O using Test I/O: %s" % selections)
                print("Start I/O condition code 3 was followed by repeated Test I/O condition code 3")
            m.run(instructions = 30000000)
            lines = [line.strip() for line in m.screens(0x01f)]
            if ("ERROR NUMBER E002" not in lines or "ERROR NUMBER E003" in lines or "ERR 23 ON SNS" not in lines or
                "JOB ABORTED ON VOL DIAG01 DRIVE 340" not in lines or
                lines[-1] != "READY PACK OR POP ID PLUG"):
                fail("D806A5 did not abort the disconnected pack evaluation: %s" % lines[-18:])
            if mode == "unplug-loop" and len([line for line in lines if line == "ERROR NUMBER E002"]) != 1:
                fail("D806A5 switch 1 disconnect behavior changed")
            print("ERROR NUMBER E002")
            print("JOB ABORTED ON VOL DIAG01 DRIVE 340")
            m.dasd_usage(reset = True)
            m.key(0x340, "INSERT ID PLUG")
            for _ in range(120):
                m.run(instructions = 500000)
                lines = [line.strip() for line in m.screens(0x01f)]
                if "EVALUATION COMPLETE VOL DIAG01 DRIVE 340" in lines:
                    break
            if (len([line for line in lines if line == starting]) != 2 or
                "EVALUATION COMPLETE VOL DIAG01 DRIVE 340" not in lines or
                "* TOTAL OF 0000 BAD TRACKS" not in lines or
                m.dasd_usage()[0x340]["read"] != [(0, 4059)] or m.dasd_usage()[0x340]["written"]):
                fail("D806A5 did not complete a new evaluation after reinserting the plug: %s" % lines[-18:])
            print("D806A5 accepted the reinserted plug and completed the entire pack scan")
            return
        if bad:
            if move_retry or mode == "transient":
                m.event_limit(8192)
                m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
                for _ in range(60):
                    m.run(instructions = 250000)
                    if any(["SOFT ERR TRK " in line for line in m.screens(0x01f)]):
                        break
                m.trace_io(on = False)
                moves = [line for line in m.events() if "resume 0340 " in line and "ch 20 ccw 008CA0 " in line]
                if (len(moves) != (9 if move_retry else 0) or
                    binary.hex(m.read(0x8c90, 16)) != "07008e3c4000000603008c9800000000"):
                    fail("D806A5 switch 10 did not select the expected relocation chain")
                if move_retry:
                    print("D806A5 used the relocation chain on all nine retries")
            if error_loop:
                failure = "7/3: read R0: injected count field data check"
                for _ in range(60):
                    m.run(instructions = 500000)
                    if len([e for e in m.dasd_errors(0x340).errors if e == failure]) >= 4:
                        break
                before = m.dasd_errors(0x340)
                m.run(instructions = 1000000)
                after = m.dasd_errors(0x340)
                if (m.dasd_usage()[0x340]["read"] != [(0, 142)] or
                    len([e for e in before.errors if e == failure]) < 4 or
                    after.commands <= before.commands or after.errors[-4:] != [failure] * 4):
                    fail("D806A5 did not hold on the error track under switch 12: %s" % after.errors[-8:])
                print("D806A5 continued retrying track 143 without reading the next track")
                m.alter(0x8005, b"\x40")
            for _ in range(120):
                m.run(instructions = 500000)
                lines = [line.strip() for line in m.screens(0x01f)]
                if "EVALUATION COMPLETE VOL DIAG01 DRIVE 340" in lines:
                    break
            row = "007    0007 0003                XX     0880   1"
            usage = m.dasd_usage()[0x340]
            if "EVALUATION COMPLETE VOL DIAG01 DRIVE 340" not in lines or usage["written"]:
                fail("D806A5 did not complete the read-only pack evaluation")
            burst = "BURST CHECK ERROR ON TRACK 00070003"
            if ([line for line in lines if line.startswith("BURST CHECK ERROR ON TRACK ")] !=
                ([burst] if soft_halt or hard_report else [])):
                fail("D806A5 error switches did not produce the expected burst-check diagnostic")
            if soft_halt or hard_report:
                if any([line.startswith("HLT ") for line in lines]):
                    fail("D806A5 track-error halt behavior changed")
                print(burst + " (SDM continued without an operator halt)")
            if transient:
                if ([line for line in lines if line.startswith("SOFT ERR TRK ")] != ["SOFT ERR TRK 00070003"] or
                    "* TOTAL OF 0000 BAD TRACKS" not in lines or usage["read"] != [(0, 4059)] or row in lines):
                    fail("D806A5 did not report and recover from exactly one soft track error: %s" % lines[-24:])
                print("SOFT ERR TRK 00070003")
                print("* TOTAL OF 0000 BAD TRACKS")
                print("EVALUATION COMPLETE VOL DIAG01 DRIVE 340")
                return
            if ("* TOTAL OF 0001 BAD TRACKS" not in lines or "HEAD 03" not in lines or row not in lines or
                usage["read"] != [(0, 142), (144, 4059)]):
                fail("D806A5 did not report exactly the injected bad track: %s %s" % (usage, lines[-24:]))
            print("* TOTAL OF 0001 BAD TRACKS")
            print(row)
            print("EVALUATION COMPLETE VOL DIAG01 DRIVE 340")
            return
        m.run(instructions = 8000000)
        lines = [line.strip() for line in m.screens(0x01f)]
        halts = [line for line in lines if line.startswith("HLT D806A5 01 ")]
        if len(halts) != 1 or "REF A - ENTER HEX TRACK ADDR" not in lines:
            fail("D806A5 did not halt for a track address")
        operand = binary.hex(m.read(0x8000, 0x800)).find("000000ff000000ff")
        if operand < 0 or operand % 8 != 0:
            fail("D806A5 operator-entry operand missing")
        address = 0x8000 + operand // 2
        m.dasd_usage(reset = True)
        if len(args) == 2 and args[1] == "limits":
            commands = m.dasd_errors(0x340).commands
            for attempt, entry in enumerate(["0000700000014000", "000cb00000003000"], 1):
                m.alter(address, binary.decode(entry, "hex"))
                operator(m, halts[-1], "D806A5")
                m.run(instructions = 8000000)
                lines = [line.strip() for line in m.screens(0x01f)]
                halts = [line for line in lines if line.startswith("HLT D806A5 01 ")]
                rejected = [line for line in lines if line == "CYL OR HD ERR - REENTER"]
                prompts = [line for line in lines if line == "REF A - ENTER HEX TRACK ADDR"]
                if (len(halts) != attempt + 1 or len(rejected) != attempt or len(prompts) != attempt + 1 or
                    m.dasd_errors(0x340).commands != commands):
                    fail("D806A5 did not reject invalid track address before issuing disk I/O: %s" % lines[-12:])
                print(rejected[-1])
        m.alter(address, binary.decode("0000700000003000", "hex"))
        operator(m, halts[-1], "D806A5")
        m.run(instructions = 8000000)
        before = m.dasd_errors(0x340).commands
        m.run(instructions = 1000000)
        usage = m.dasd_usage()[0x340]
        if (usage["read"] != [(143, 143)] or usage["written"] or
            m.dasd_errors(0x340).commands <= before or m.read(0x8005, 1) != b"\x04"):
            fail("D806A5 did not repeatedly scan the selected track")
        m.alter(0x8005, b"\x00")
        m.run(instructions = 12000000)
        lines = [line.strip() for line in m.screens(0x01f)]
        if ("EVALUATION COMPLETE VOL DIAG01 DRIVE 340" not in lines or
            [line for line in lines if line.startswith("* ")] != ["* TOTAL OF 0000 BAD TRACKS"] or
            lines[-1] != "READY PACK OR POP ID PLUG" or m.dasd_usage()[0x340]["read"] != [(143, 143)]):
            fail("D806A5 did not finish the requested track after clearing switch 13")
        m.key(0x01f, "REQUEST")
        wait_1052_read(m)
        m.type(0x01f, "F/")
        end = m.run(instructions = 8000000)
        if end.kind != "disabled-wait" or "D806A TERMINATED REIPL TO CONTINUE" not in [line.strip() for line in m.screens(0x01f)]:
            fail("D806A5 did not honor F/ after the track evaluation")
        print("D806A5 repeated cylinder 7 head 3, reported zero bad tracks, and terminated after F/")
        return
    if args and args[0] == "disk-zone":
        if len(args) > 2 or (len(args) == 2 and args[1] not in ["short", "retry", "stop-tio", "stop-sio", "stop-seek", "stop-reverse", "stop-resume", "stop-reverse-resume"]):
            fail("usage: s370_diag.star disk-zone [short|retry|stop-tio|stop-sio|stop-seek|stop-reverse|stop-resume|stop-reverse-resume]")
        retry = len(args) == 2 and args[1] == "retry"
        short = retry or (len(args) == 2 and args[1] == "short")
        stopped = len(args) == 2 and args[1].startswith("stop-")
        reverse = stopped and args[1].startswith("stop-reverse")
        resume = stopped and args[1].endswith("-resume")
        seek_call = 0x8ef2 if reverse else 0x8f20
        m = machine(tape)
        m.dasd(0x340, type = "2314", cylinders = 180 if short else 203, volser = "DIAG01")
        m.ipl(0x130)
        if stopped:
            m.break_at(seek_call)
        if retry:
            m.break_at(0x903a)
        res = sdm(m, message = "E/A,01F/A,00E/A80000340/I,01F,01F,00E,130/SS8069.7" + (".5" if resume else "") + "/L8069/B",
                  budget = 1000000000 if short else 100000000, step = 500000, show = not short,
                  followup_cards = ["S8069.41000000/B", "S8069.01000000/B"] if retry else [])
        if retry:
            if (res["ended"] != "breakpoint" or not res["run"].psw.endswith("00903A") or
                m.dasd_errors(0x340).errors != ["20/0: invalid seek address 000000B40000"] or
                m.read(0x8004, 1) != b"\x01"):
                fail("D80692 did not reach its first short-pack error")
            m.clear_breaks()
            m.interrupt_key()
            m.break_at(0x8f3e)
            r = m.run(instructions = 20000000)
            if r.kind != "breakpoint" or not r.psw.endswith("008F3E") or m.read(0x8004, 1) != b"\x41":
                fail("D80692 did not reach its switch 1 test")
            counter = m.registers().gr[1]
            m.clear_breaks()
            m.run(instructions = 1)
            m.break_at(0x8f3e)
            r = m.run(instructions = 20000000)
            if (r.kind != "breakpoint" or not r.psw.endswith("008F3E") or m.registers().gr[1] != counter or
                m.dasd_errors(0x340).errors != ["20/0: invalid seek address 000000B40000"] * 2):
                fail("D80692 did not repeat the same failing seek without decrementing the counter")
            m.clear_breaks()
            m.interrupt_key()
            lines = []
            for _ in range(100):
                m.run(instructions = 10000000)
                lines = [line.strip() for line in m.screens(0x01f)]
                if END_OF_JOB in lines:
                    break
            reports = [line for line in lines if line.startswith("* ** ER ")]
            if (END_OF_JOB not in lines or "T   D80692 02 ROUTINES RUN" not in lines or
                m.read(0x8004, 1) != b"\x01" or any(["UIO" in line for line in lines]) or
                reports != ["* ** ER 1620 UNIT 340,ADRS 00903A", "* ** ER 1615 UNIT 340,ADRS 00903A"] * 41 or
                m.dasd_errors(0x340).errors != ["20/0: invalid seek address 000000B40000"] * 41):
                fail("D80692 did not complete the zone test after clearing switch 1")
            print("D80692 repeated one failing seek, then reached SDM end of job after clearing switch 1")
            return
        if short:
            disk_errors = m.dasd_errors(0x340).errors
            unit_check = "* ** ER 1620 UNIT 340,ADRS 00903A"
            mismatch = "* ** ER 1615 UNIT 340,ADRS 00903A"
            reports = [line for line in res["errors"] if line.startswith("* ** ER ")]
            if (res["ended"] != "end-of-job" or res["skipped"] or
                [(s["section"], s["routines"]) for s in res["sections"]] != [("D80692", "02")] or
                reports != [unit_check, mismatch] * 40 or
                disk_errors != ["20/0: invalid seek address 000000B40000"] * 40):
                fail("D80692 short-pack run did not produce the expected cylinder 180 failures")
            print("\n".join(res["errors"][:5]))
            print("D80692 reported 40 unit-check and address-mismatch pairs and reached SDM end of job")
            return
        if stopped:
            if res["ended"] != "breakpoint" or int(res["run"].psw[-6:], 16) != seek_call:
                fail("D80692 did not reach its seek call")
            m.clear_breaks()
            if reverse:
                # The first call positions from cylinder zero; the next moves back from 22.
                m.run(instructions = 1)
                m.break_at(seek_call)
                r = m.run(instructions = 2000000)
                if r.kind != "breakpoint" or int(r.psw[-6:], 16) != seek_call:
                    fail("D80692 did not reach its reverse seek")
                m.clear_breaks()
            if args[1] == "stop-seek" or reverse or resume:
                m.run(instructions = 150)
                if "blocked=true" not in m.subchannel(0x340):
                    fail("D80692 did not start its chained seek")
                m.key(0x340, "STOP")
                m.run(instructions = 8000000)
                lines = [line.strip() for line in m.screens(0x01f)]
                error = "* ** ER 1612 UNIT 340,ADRS 00903A"
                location = "* WAS AT CYL 022 HD 00,SEEK TO CYL 020 HD 00" if reverse else "* WAS AT CYL 020 HD 00,SEEK TO CYL 022 HD 00"
                if (error not in lines or location not in lines or
                    not any(["CSW 00 0090B0 0E" in line and line.endswith("00001000") for line in lines])):
                    fail("D80692 did not detect the drive going not-ready during a seek: %s" % lines[-8:])
                print(error)
                if resume:
                    m.run(instructions = 8000000)
                    halts = [line.strip() for line in m.screens(0x01f) if line.strip().startswith("HLT D80692 02 ")]
                    if len(halts) != 1:
                        fail("D80692 did not halt under switch 5")
                    m.key(0x340, "START")
                    m.run(instructions = 61000000)
                    operator(m, halts[0], "D80692")
                    m.run(instructions = 8000000)
                    lines = [line.strip() for line in m.screens(0x01f)]
                    halts = [line for line in lines if line.startswith("HLT D80692 02 ")]
                    mismatch = "* ** ER 1613 UNIT 340,ADRS 00903A"
                    if len(halts) != 2 or mismatch not in lines or location + ",HA READ CYL 255 HD 99" not in lines:
                        fail("D80692 did not report the interrupted seek's missing home address: %s" % lines[-12:])
                    operator(m, halts[1], "D80692")
                    m.run(instructions = 100000000)
                    lines = [line.strip() for line in m.screens(0x01f)]
                    if (END_OF_JOB not in lines or "T   D80692 02 ROUTINES RUN" not in lines or
                        [line for line in lines if line.startswith("* ** ER ")] != [error, mismatch]):
                        fail("D80692 did not finish after recovering from the interrupted seek: %s" % lines[-12:])
                    print(mismatch)
                    print("D80692 resumed after both operator halts and reached SDM end of job")
                return
            sio = args[1] == "stop-sio"
            if sio:
                m.break_at(0x823a)
                r = m.run(instructions = 1000)
                if r.kind != "breakpoint" or not r.psw.endswith("00823A"):
                    fail("D80692 did not reach Start I/O after Test I/O")
                m.clear_breaks()
            m.key(0x340, "STOP")
            m.run(instructions = 8000000)
            lines = [line.strip() for line in m.screens(0x01f)]
            error = "* ** ER  %s,SECT 4,RT 2 UNIT 340,ADRS 0082D8" % ("11 ERROR ON SIO" if sio else "01 ERROR ON TIO")
            if error not in lines or not any([line.endswith("SNS 01000000 00000000 00000000 00001000") for line in lines]):
                fail("D80692 did not report intervention required and not ready: %s" % lines[-8:])
            print(error)
            m.key(0x340, "START")
            m.run(instructions = 68000000)
            lines = [line.strip() for line in m.screens(0x01f)]
            if (END_OF_JOB not in lines or "T   D80692 02 ROUTINES RUN" not in lines or
                "UIO SDM 12    0000000004000000 340" not in lines or
                [line for line in lines if line.startswith("* ** ER ")] != [error]):
                fail("D80692 did not exit and receive drive-ready Device End: %s" % lines[-8:])
            print("D80692 reached SDM end of job and received drive-ready Device End")
            return
        if (res["ended"] != "end-of-job" or res["errors"] or res["skipped"] or
            [(s["section"], s["routines"]) for s in res["sections"]] != [("D80692", "02")] or
            any(["AVG ACCESS TIME" in line for line in res["transcript"]]) or
            m.dasd_errors(0x340).commands != 1600):
            fail("D80692 did not complete the switch 7 zone-logic path")
        print("D80692 zone-logic path completed 1600 disk commands and reached SDM end of job")
        return
    if args and args[0] == "disk-timing-limit":
        if len(args) > 2 or (len(args) == 2 and args[1] not in ["2", "3"]):
            fail("usage: s370_diag.star disk-timing-limit [2|3]")
        delay = int(args[1]) if len(args) == 2 else 40
        m = machine(tape)
        m.dasd(0x340, type = "2314", cylinders = 203, volser = "DIAG01", seek_extra_ms = delay)
        m.ipl(0x130)
        res = sdm(m, message = "E/A,01F/A,00E/A80000340/I,01F,01F,00E,130/L8069/B",
                  budget = 800000000, step = 500000)
        expected = []
        routines = "01"
        if delay == 2:
            if "AVG ACCESS TIME WITHIN  TOLERANCE" not in [line.strip() for line in res["transcript"]]:
                fail("D80692 did not report an in-tolerance average with 2 ms additional seek delay")
        else:
            average, minimum, maximum = ("60.6", " 28.4", "126.3") if delay == 3 else ("97.4", " 65.4", "163.3")
            expected = [
                "* AVG ACCESS TIME EXCEEDS TOLERANCE FOR A  SCU  %s MS" % average,
                "* ** ER 1603 UNIT 340,ADRS 008AA4",
                "* ACCESS TIME FOR A MIN FWD SK EXCEEDS TOLERANCE " + minimum,
                "*                   MIN REV SK EXCEEDS TOLERANCE " + minimum,
                "*                   MAX FWD SK EXCEEDS TOLERANCE " + maximum,
                "*                   MAX REV SK EXCEEDS TOLERANCE " + maximum,
            ]
            routines = "02"
        if (res["ended"] != "end-of-job" or res["skipped"] or res["errors"] != expected or
            [(section["section"], section["routines"]) for section in res["sections"]] != [("D80692", routines)]):
            fail("D80692 did not report the expected seek timing errors: %s" % res["errors"])
        return
    if args and args[0] == "disk-timing-loop":
        if len(args) != 1:
            fail("usage: s370_diag.star disk-timing-loop")
        m = machine(tape)
        m.dasd(0x340, type = "2314", cylinders = 203, volser = "DIAG01")
        m.ipl(0x130)
        within = "AVG ACCESS TIME WITHIN  TOLERANCE"
        if m.run(instructions = 30000000).psw != SDM_READY:
            fail("SDM did not reach the operator prompt")
        m.cards(0x00c, ["E/A,01F/A,00E/A80000340/I,01F,01F,00E,130/SS8069.3/L8069/B",
                        "S8069.00000000/B"])
        m.interrupt_key()
        lines = []
        for _ in range(50000):
            m.run(instructions = 10000)
            lines = [line.strip() for line in m.screens(0x01f)]
            if len([line for line in lines if line == within]) >= 2:
                break
        if (len([line for line in lines if line == within]) != 2 or END_OF_JOB in lines or
            any([line.startswith("*") for line in lines])):
            fail("D80692 did not repeat its timing check cleanly: %s" % lines[-12:])
        print(within)
        if m.read(0x8004, 1) != b"\x10":
            fail("D80692 did not retain section switch 3")
        m.interrupt_key()
        for _ in range(100):
            m.run(instructions = 5000000)
            lines = [line.strip() for line in m.screens(0x01f)]
            if END_OF_JOB in lines:
                break
        if (m.read(0x8004, 1) != b"\x00" or END_OF_JOB not in lines or "T   D80692 01 ROUTINES RUN" not in lines or
            any([line.startswith("*") or "UIO" in line for line in lines])):
            fail("D80692 did not finish after clearing section switch 3: %s" % lines[-12:])
        print("D80692 exited the timing loop after reading the switch-clear card")
        return
    if args and args[0] == "disk-options":
        last_cylinder = len(args) == 3 and args[1] == "12" and args[2] == "last"
        invalid_cylinder = len(args) == 3 and args[1] == "12" and args[2] in ["invalid", "invalid-console"]
        alignment_cylinders = [1, 71, 72, 73, 74, 75, 117, 118, 119, 199]
        protected = len(args) in [3, 4] and args[1] == "12" and args[2] == "protected"
        if protected and len(args) == 4 and int(args[3]) not in alignment_cylinders:
            fail("select an alignment cylinder from %s" % alignment_cylinders)
        retry_and_halt = len(args) == 3 and args[1] == "14" and args[2] == "retry-halt"
        if list(args[1:]) == ["14", "retry-restored"]:
            check_d80683_retry(tape)
            return
        retry_mismatch = retry_and_halt or (len(args) == 3 and args[1] == "14" and args[2] == "retry")
        continue_mismatch = len(args) == 3 and args[1] == "14" and args[2] == "continue"
        halt_mismatch = len(args) == 3 and args[1] == "14" and args[2] == "mismatch"
        mismatch = retry_mismatch or halt_mismatch or continue_mismatch
        if (len(args) != 2 and not protected and not mismatch and not invalid_cylinder and not last_cylinder) or args[1] not in ["9", "12", "13", "14"]:
            fail("usage: s370_diag.star disk-options 9|12 [protected [cylinder]|last|invalid|invalid-console]|13|14 [mismatch|retry|retry-restored|retry-halt|continue]")
        m = machine(tape)
        m.dasd(0x340, type = "2314", cylinders = 203, volser = "DIAG01")
        if args[1] == "13":
            m.dasd(0x341, type = "2314", cylinders = 203, volser = "DIAG02")
        if args[1] == "14":
            for slot in range(1, 9):
                m.dasd(0x340 + slot, type = "2314", cylinders = 203, volser = "SLOT%d" % slot)
                m.key(0x340 + slot, "REMOVE ID PLUG")
        m.ipl(0x130)
        switches = args[1] + (".1" if retry_mismatch else "")
        if halt_mismatch or retry_and_halt:
            switches += ".5"
        res = sdm(m, message = "E/A,01F/A,00E/A80000340/I,01F,01F,00E,130/SS8068." + switches + "/L8068/B",
                  budget = 8000000, step = 100000, show = False, handle_operator = lambda m, line, section: None)
        expected = {
            "9": "RTN 2 - TO CHECK DSU POWER OFF-ON WHILE CPU IS RUNNING",
            "12": "STOP,SET CYL IN REG 1,START",
            "13": "STARTING PHASE 2",
            "14": "PUT PLUG 0 IN PHYSICAL DRIVE A",
        }[args[1]]
        if (res["ended"] != "budget" or res["skipped"] or res["errors"] or
            [s["section"] for s in res["sections"]] != ["D80683"] or
            expected not in [line.strip() for line in res["transcript"]]):
            fail("D80683 did not reach the expected optional routine under switch " + args[1])
        print("\n".join(res["transcript"][-24:]))
        print(res["ended"], res["run"].psw, res["sections"])
        if args[1] == "14":
            expected_errors = ["* SD0 D80683 06 009084 340", "* SNS BYTE 4 RECVD 00", "* SNS BYTE 4 EXPTD X1"] if mismatch else []
            for slot in range(1, 9):
                prompt = "PUT PLUG 0 IN PHYSICAL DRIVE " + "ABCDEFGHJ"[slot]
                for _ in range(500):
                    if prompt in [line.strip() for line in m.screens(0x01f)]:
                        break
                    m.run(instructions = 100000)
                if prompt not in [line.strip() for line in m.screens(0x01f)]:
                    fail("D80683 did not reach %s: %s" % (prompt, m.screens(0x01f)[-12:]))
                if mismatch and slot == 1:
                    if retry_mismatch:
                        m.break_at(0x9082)
                        before = m.run(instructions = 50000000)
                        if before.kind != "breakpoint" or not before.psw.endswith("009082"):
                            fail("D80683 did not reach the mismatch print service")
                        original_caw = m.read(0x48, 4)
                        sense_caw = int(binary.hex(original_caw), 16)
                        if m.read(sense_caw, 1) != b"\x04":
                            fail("D80683 CAW was not pointing to Sense before error reporting")
                        m.clear_breaks()
                        m.watch(0x48, 4)
                        caw_store = m.run(instructions = 10000000)
                        m.watch(0, 0)
                        if caw_store.kind != "watch" or m.read(0x48, 4) == original_caw:
                            fail("SDM did not overwrite the Sense CAW during its print service")
                        print("SDM print CAW write at " + caw_store.psw[-6:])
                        m.break_at(0x9098)
                    r = m.run(instructions = 50000000)
                    lines = [line.strip() for line in m.screens(0x01f)]
                    halts = [line for line in lines if line.startswith("HLT D80683 06 ")]
                    if ("ERROR ON DRIVE B" not in lines or
                        [line for line in lines if line.startswith("*")] != expected_errors):
                        fail("D80683 did not report the wrong drive: %s" % lines[-12:])
                    print("\n".join(expected_errors + halts))
                    if retry_mismatch:
                        if r.kind != "breakpoint" or not r.psw.endswith("009098") or halts:
                            fail("D80683 did not reach the switch 1 retry branch")
                        m.clear_breaks()
                        target = int(m.registers().gr[13], 16) + 4
                        m.break_at(target)
                        r = m.run(instructions = 10)
                        if r.kind != "breakpoint" or int(r.psw[-6:], 16) != target:
                            fail("D80683 did not branch back to the Sense I/O instruction")
                        m.clear_breaks()
                        m.move_2314_plug(0x340, 0x341)
                        m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
                        caw = binary.hex(m.read(0x48, 4))
                        m.run(instructions = 8000000)
                        reused = [line for line in m.events() if "SIO 0340 caw 000002D8 cmds [09 " in line]
                        if caw != "000002d8" or not reused:
                            fail("D80683 retry did not reproduce the stale message CAW: %s" % caw)
                        print("D80683 retry reused the SDM print CAW at 02D8:")
                        print(reused[0])
                        print("CAW before the mismatch report was %x (Sense)" % sense_caw)
                        if not retry_and_halt:
                            return
                        m.break_at(0x9094)
                        r = m.run(instructions = 10000000)
                        if r.kind != "breakpoint" or m.read(0x8004, 1) != b"\x44":
                            fail("D80683 did not reach the loop switch test with switches 1 and 5 set")
                        m.alter(0x8004, b"\x04")
                        m.clear_breaks()
                        m.run(instructions = 1000000)
                        lines = [line.strip() for line in m.screens(0x01f)]
                        halts = [line for line in lines if line.startswith("HLT D80683 06 ")]
                        errors = [line for line in lines if line.startswith("*")]
                        if len(halts) != 1 or len(errors) < 6 or errors != expected_errors * (len(errors) // 3):
                            fail("D80683 did not halt after clearing the loop switch: %s" % lines[-12:])
                        expected_errors = errors
                        operator(m, halts[0], "D80683")
                        print("Cleared switch 1, halted under switch 5 and resumed with B")
                        continue
                    if halt_mismatch:
                        if len(halts) != 1:
                            fail("D80683 did not halt under switch 5")
                        m.move_2314_plug(0x340, 0x341)
                        operator(m, halts[0], "D80683")
                    elif halts or "PUT PLUG 0 IN PHYSICAL DRIVE C" not in lines:
                        fail("D80683 did not advance after the mismatch with switches 1 and 5 off")
                else:
                    m.move_2314_plug(0x340, 0x340 + slot)
                print(prompt)
            m.run(instructions = 50000000)
            lines = [line.strip() for line in m.screens(0x01f)]
            if (END_OF_JOB not in lines or "T   D80683 02 ROUTINES RUN" not in lines or
                [line for line in lines if line.startswith("*")] != expected_errors):
                fail("D80683 physical drive logging did not finish cleanly: %s" % lines[-12:])
            if retry_and_halt:
                print("D80683 finished drives C through J after leaving the retry loop and reached SDM end of job")
            elif continue_mismatch:
                print("D80683 advanced after the drive B mismatch without a restart and reached SDM end of job")
            elif halt_mismatch:
                print("D80683 resumed after the drive B mismatch and reached SDM end of job")
            else:
                print("D80683 verified physical slots A through J and reached SDM end of job")
        if args[1] == "13":
            tracks = [(100, 119), (3900, 3919)]
            usage = m.dasd_usage()[0x340]
            if usage["written"] != tracks or usage["read"] != tracks or m.dasd_errors(0x340).errors:
                fail("D80683 format/read did not cover every track on cylinders 5 and 195: %s" % usage)
            for cylinder in [5, 195]:
                for head in range(20):
                    records = m.dasd_track(0x340, cylinder, head)
                    if len(records) != 1 or not records[0].endswith("00 kl=0 dl=7000 key="):
                        fail("D80683 did not leave a 7000-byte record zero on cylinder %d head %d" % (cylinder, head))
            print("D80683 formatted and read all 40 tracks on cylinders 5 and 195")
            m.break_at(0x8df8)
            r = m.run(instructions = 2000000)
            if r.kind != "breakpoint":
                fail("D80683 did not reach the next phase 2 read")
            m.clear_breaks()
            m.key(0x340, "STOP")
            m.break_at(0x8e72)
            r = m.run(instructions = 100000)
            if r.kind != "breakpoint" or not r.psw.endswith("008E72"):
                fail("D80683 did not enter the not-ready Test I/O loop")
            m.clear_breaks()
            m.dasd_usage(reset = True)
            m.key(0x341, "STOP")
            m.exchange_2314_packs(0x340, 0x341)
            if m.dasd_errors(0x340).physical_slot != 0x341 or m.dasd_errors(0x341).physical_slot != 0x340:
                fail("D80683 pack and plug exchange did not change physical slots")
            m.key(0x340, "START")
            m.run(instructions = 64000000)
            usage = m.dasd_usage()[0x340]
            if (usage["read"] != tracks or usage["written"] or
                m.dasd_usage()[0x341]["read"] or
                any([line.strip().startswith("*") for line in m.screens(0x01f)])):
                fail("D80683 did not resume readback after drive restart: %s" % usage)
            print("D80683 resumed readback of all 40 tracks in the second physical slot")
            m.key(0x01f, "REQUEST")
            wait_1052_read(m)
            m.type(0x01f, "F/")
            m.run(instructions = 8000000)
            lines = [line.strip() for line in m.screens(0x01f)]
            if (END_OF_JOB not in lines or "T   D80683 02 ROUTINES RUN" not in lines or
                any([line.startswith("*") for line in lines])):
                fail("D80683 interchangeability run did not finish after F/: %s" % lines[-12:])
            print("D80683 reached SDM end of job after F/")
            # Reload from the original tape with both switches and the same pack.
            m.key(0x130, "REWIND")
            m.ipl(0x130)
            m.dasd_usage(reset = True)
            readback = sdm(m, message = "E/A,01F/A,00E/A80000340/I,01F,01F,00E,130/SS8068.11.13/L8068/B",
                           budget = 8000000, step = 100000, show = False)
            usage = m.dasd_usage()[0x340]
            if (readback["ended"] != "budget" or readback["errors"] or readback["skipped"] or
                [s["section"] for s in readback["sections"]] != ["D80683"] or
                "STARTING PHASE 2" not in [line.strip() for line in readback["transcript"]] or
                usage["read"] != tracks or usage["written"]):
                fail("D80683 phase 2-only reload did not read the formatted pack without writes: %s" % usage)
            seen = len(m.screens(0x01f))
            m.key(0x01f, "REQUEST")
            wait_1052_read(m)
            m.type(0x01f, "F/")
            m.run(instructions = 8000000)
            lines = [line.strip() for line in m.screens(0x01f)[seen:]]
            if (END_OF_JOB not in lines or "T   D80683 02 ROUTINES RUN" not in lines or
                any([line.startswith("*") for line in lines]) or m.dasd_usage()[0x340]["written"]):
                fail("D80683 phase 2-only reload did not finish without writes: %s" % lines)
            print("D80683 phase 2-only reload read all 40 tracks without writes and reached SDM end of job")
        if args[1] == "9":
            m.key(0x340, "STOP")
            m.run(instructions = 10000)
            m.key(0x340, "START")
            r = m.run(instructions = 64000000)
            lines = [line.strip() for line in m.screens(0x01f)]
            prompt = "RTN 3A - TO CHECK DSU NOT READY STATUS"
            if prompt not in lines or any([line.startswith("*") for line in lines]):
                fail("D80683 did not complete the power cycle: %s %s %s" % (r.kind, r.psw, lines[-12:]))
            print(prompt)
            halt = None
            for _ in range(10):
                m.run(instructions = 1000000)
                halts = [line.strip() for line in m.screens(0x01f) if line.strip().startswith("HLT D80683 03 ")]
                if halts:
                    halt = halts[0]
                    break
            if halt == None:
                fail("D80683 did not halt for the drive stop")
            m.key(0x340, "STOP")
            operator(m, halt, "D80683")
            m.run(instructions = 12000000)
            lines = [line.strip() for line in m.screens(0x01f)]
            prompt = "RTN 3B - TO CHECK DSU READY STATUS"
            if prompt not in lines or any([line.startswith("*") for line in lines]):
                fail("D80683 failed the stopped-drive check: %s" % lines[-12:])
            print(prompt)
            m.key(0x340, "START")
            m.run(instructions = 61000000)
            m.interrupt_key()
            m.run(instructions = 8000000)
            lines = [line.strip() for line in m.screens(0x01f)]
            if (END_OF_JOB not in lines or "T   D80683 03 ROUTINES RUN" not in lines or
                any([line.startswith("*") for line in lines])):
                fail("D80683 did not complete all three selected routines: %s" % lines[-12:])
            print("D80683 completed three routines and reached SDM end of job")
        if args[1] == "12":
            if m.registers().gr[1:3] != ["000000FF", "000000FF"]:
                fail("D80683 did not pause for the operator's cylinder number")
            cylinder = int(args[3]) if protected and len(args) == 4 else 1 if protected else 202 if last_cylinder else 42
            if invalid_cylinder:
                m.alter_register(1, 203)
                m.run(instructions = 2000000)
                lines = [line.strip() for line in m.screens(0x01f)]
                expected = "* ** ER 3901 WR HA 0000CB0000 RD HA C5C5C5C5C5 UNIT 340,ADRS 008C6C"
                if expected not in lines or m.dasd_usage()[0x340]["written"]:
                    fail("D80683 did not report the out-of-range home address on head 0")
                print(expected)
                m.break_at(0x8c44)
                for _ in range(100):
                    r = m.run(instructions = 1000000)
                    lines = [line.strip() for line in m.screens(0x01f)]
                    if len([line for line in lines if line == "* SNS 400000410000"]) >= 20:
                        break
                reports = [line for line in lines if line.startswith("* ** ER 3901")][:20]
                heads = [("0" + ("%x" % head).upper())[-2:] for head in range(20)]
                if (reports != [expected.replace("CB0000", "CB00" + head) for head in heads] or
                    len([line for line in lines if line == "* SNS 400000410000"]) < 20 or m.dasd_usage()[0x340]["written"]):
                    fail("D80683 did not report all 20 invalid home addresses without writes")
                if m.read(0x8005, 1) != b"\x08":
                    fail("D80683 did not retain section switch 12")
                for _ in range(6):
                    if r.kind == "breakpoint":
                        break
                    r = m.run(instructions = 100000000)
                if r.kind != "breakpoint" or not r.psw.endswith("008C44"):
                    fail("D80683 end of pass: %s %s %s" % (r.kind, r.psw, m.screens(0x01f)[-4:]))
                m.clear_breaks()
                m.key(0x01f, "REQUEST")
                wait_1052_read(m)
                m.type(0x01f, "F/" if args[2] == "invalid-console" else "S8068.00000000/B")
                for _ in range(100):
                    m.run(instructions = 1000000)
                    lines = [line.strip() for line in m.screens(0x01f)]
                    if END_OF_JOB in lines:
                        break
                if (END_OF_JOB not in lines or m.dasd_usage()[0x340]["written"] or
                    any(["UIO" in line for line in lines]) or
                    (args[2] == "invalid" and m.read(0x8005, 1) != b"\x00")):
                    fail("D80683 did not release the invalid cylinder job: %s" % lines[-8:])
                print("Cylinder 203 rejected on all 20 heads, no tracks written, reached end of job")
                return
            m.alter_register(1, cylinder)
            if protected:
                m.run(instructions = 8000000)
                lines = [line.strip() for line in m.screens(0x01f)]
                halts = [line for line in lines if line.startswith("HLT D80683 04 ")]
                if (len(halts) != 1 or "ENTER  B/ MSG TO CONTINUE." not in lines or
                    not any([line.startswith("WARNING YOU HAVE SELECTED") for line in lines]) or
                    m.dasd_usage()[0x340]["written"]):
                    fail("D80683 did not halt before writing the protected cylinder: %s" % lines[-12:])
                print(halts[0])
                operator(m, halts[0], "D80683")
            if protected:
                for _ in range(100):
                    m.run(instructions = 1000000)
                    halts = [line for line in m.screens(0x01f) if line.strip().startswith("HLT D80683 04 ")]
                    if len(halts) == 2 and m.psw() == "FF040000 000011A8":
                        break
            else:
                m.run(instructions = 2000000)
            if m.dasd_usage()[0x340]["written"] != [(cylinder * 20, cylinder * 20 + 19)]:
                fail("D80683 did not write all 20 heads of cylinder %d" % cylinder)
            m.key(0x01f, "REQUEST")
            wait_1052_read(m)
            m.type(0x01f, "F/")
            m.run(instructions = 8000000)
            lines = [line.strip() for line in m.screens(0x01f)]
            if (END_OF_JOB not in lines or "T   D80683 02 ROUTINES RUN" not in lines or
                any([line.startswith("*") for line in lines])):
                fail("D80683 did not complete after the operator entered F/: %s" % lines[-12:])
            print("D80683 verified cylinder %d and reached SDM end of job after F/" % cylinder)
        return
    if args and args[0] == "disk-unplugged":
        if len(args) > 2 or (len(args) == 2 and args[1] not in ["retry", "halt"]):
            fail("usage: s370_diag.star disk-unplugged [retry|halt]")
        option = args[1] if len(args) == 2 else ""
        retry = option == "retry"
        switches = {"": "", "retry": ".8", "halt": ".5"}[option]
        m = machine(tape)
        m.dasd(0x340, type = "2314", cylinders = 203, volser = "DIAG01")
        m.ipl(0x130)
        m.break_at(0x8272)
        res = sdm(m, message = "E/A,01F/A,00E/A80000340/I,01F,01F,00E,130/SS8065.2" + switches + "/L8065/B",
                  budget = 4000000, step = 100000)
        if res["ended"] != "breakpoint" or res["errors"]:
            fail("D80652 failed before the Start I/O subroutine loop")
        m.clear_breaks()
        m.key(0x340, "REMOVE ID PLUG")
        if option == "halt":
            m.break_svc(0xda)
        r = m.run(instructions = 4000000)
        error = "* ** ER  03 ERROR ON TIO,SECT 0,RT 4 UNIT 340,ADRS 0082AC"
        if error not in [line.strip() for line in m.screens(0x01f)] or (not retry and not r.psw.endswith("002026")):
            fail("D80652 did not report the routine 4 Test I/O error after plug removal")
        print(error)
        if option == "halt":
            m.key(0x340, "INSERT ID PLUG")
            r = m.run(instructions = 4000000)
            if r.kind != "svc":
                fail("D80652 did not invoke the SDM halt service under switch 5")
            m.clear_breaks()
            m.run(instructions = 4000000)
            halts = [line.strip() for line in m.screens(0x01f) if line.strip().startswith("HLT ")]
            if len(halts) != 1 or not halts[0].startswith("HLT D80652 04 "):
                fail("D80652 did not report its routine 4 operator halt")
            print(halts[0])
            operator(m, halts[0], "D80652")
            m.break_at(0x830a)
            r = m.run(instructions = 4000000)
            if r.kind != "breakpoint" or not r.psw.endswith("00830A"):
                fail("SDM B did not resume D80652 from the operator halt")
            print("SDM B resumed D80652 to routine exit at 830A")
            return
        m.key(0x340, "INSERT ID PLUG")
        m.break_at(0x823a)
        m.break_at(0x830a)
        r = m.run(instructions = 4000000)
        expected = 0x823a if retry else 0x830a
        if r.kind != "breakpoint" or int(r.psw[-6:], 16) != expected:
            fail("D80652 recovery took the wrong branch for switch 8")
        print("After plug reinsertion: %s %s" % (r.kind, r.psw))
        if retry:
            m.clear_breaks()
            m.break_at(0x8272)
            r = m.run(instructions = 4000000)
            if r.kind != "breakpoint" or not r.psw.endswith("008272"):
                fail("D80652 did not return to the Start I/O loop after retry")
        return
    if args and args[0] == "disk-missing-channel":
        if len(args) != 1:
            fail("usage: s370_diag.star disk-missing-channel")
        for channel_present, switches in [(False, ""), (False, "SS8065.1/"), (True, ""), (True, "SS8065.1/")]:
            m = machine(tape)
            if channel_present:
                m.dasd(0x341, type = "2314", cylinders = 203, volser = "DIAG01")
            m.ipl(0x130)
            res = sdm(m, message = "E/A,01F/A,00E/A80000340/I,01F,01F,00E,130/" + switches + "L8065/B",
                      budget = 4000000, step = 100000)
            print(channel_present, switches, res["ended"], res["run"].psw, res["sections"], res["errors"])
            if (res["ended"] != "end-of-job" or res["skipped"] or
                res["sections"] != [{"section": "D80652", "errors": ["01"], "routines": "01"}] or
                res["errors"] != ["* SD0 D80652 01 00857C 340"] or
                "CONDITION CODE 3" not in [line.strip() for line in res["transcript"]]):
                fail("D80652 missing-channel result changed with switches %s" % switches)
            if channel_present and m.dasd_errors(0x341).commands != 0:
                fail("D80652 addressed the unselected drive at 341")
        return
    if args and args[0] == "disk-loops":
        if len(args) != 1:
            fail("usage: s370_diag.star disk-loops")
        # The original D80652 tests the section switch at these sites.
        for switch, address in [(0, 0x864e), (1, 0x8664), (2, 0x8272), (3, 0x866c)]:
            m = machine(tape)
            m.dasd(0x340, type = "2314", cylinders = 203, volser = "DIAG01")
            m.ipl(0x130)
            res = sdm(m, message = "E/A,01F/A,00E/A80000340/I,01F,01F,00E,130/SS8065.%d/L8065/B" % switch,
                      budget = 4000000, step = 100000, show = False)
            if (res["ended"] != "budget" or res["errors"] or res["skipped"] or
                [(s["section"], s["routines"]) for s in res["sections"]] != [("D80652", None)]):
                fail("D80652 did not remain active under switch %d" % switch)
            print("\n".join(m.disassemble(address, 2)))
            for _ in range(3):
                m.break_at(address)
                hit = m.run(instructions = 100000)
                if hit.kind != "breakpoint" or int(hit.psw[-6:], 16) != address:
                    fail("D80652 switch %d did not revisit %x" % (switch, address))
                m.clear_breaks()
                m.run(instructions = 1)
            print("D80652 switch %d revisited %x three times" % (switch, address))
        return
    if args and args[0] == "disk-switches":
        if len(args) != 1:
            fail("usage: s370_diag.star disk-switches")
        for switches, show_titles, show_results in [("", False, False), ("SS8065.6/", True, False),
                                                     ("SS8065.7/", False, True), ("SS8065.6.7/", True, True)]:
            m = machine(tape)
            m.dasd(0x340, type = "2314", cylinders = 203, volser = "DIAG01")
            m.ipl(0x130)
            res = sdm(m, message = "E/A,01F/A,00E/A80000340/I,01F,01F,00E,130/" + switches + "L8065/B",
                      budget = 60000000, step = 125000, show = False)
            print("D80652 switches %s: %s, sections=%s, errors=%s" %
                  (switches, res["ended"], res["sections"], res["errors"]))
            lines = [line.strip() for line in res["transcript"]]
            titles = [line for line in lines if line.startswith(("2314 DIAGNOSTIC TEST", "SECT 0,RT 1-", "D8065  RT "))]
            results = [line for line in lines if line.startswith("*")]
            heads = "00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19"
            expected_results = ["* ** ER NONE UNIT 340,ADRS 008C5C", "* READ HEAD MAP-",
                                "* HEAD NUMBER--- " + heads, "* RD HA RESULT-- " + heads] if show_results else []
            if (res["ended"] != "end-of-job" or res["skipped"] or res["errors"] or
                [(s["section"], s["routines"]) for s in res["sections"]] != [("D80652", "07")] or
                len(titles) != (8 if show_titles else 0) or results != expected_results):
                fail("D80652 report did not match the selected switches")
            print("\n".join(titles + results))
        return
    if args and args[0] == "disk-build":
        if len(args) > 2 or (len(args) == 2 and args[1] not in ["80", "40", "20", "E0", "gates"]):
            fail("usage: s370_diag.star disk-build [80|40|20|E0|gates]")
        trace_gates = len(args) == 2 and args[1] == "gates"
        switches = args[1] if len(args) == 2 and not trace_gates else "E0"
        m = machine(tape)
        m.tape(0x3f0, tape, type = "2401", format = "simh")
        m.dasd(0x350, type = "2314", cylinders = 203, volser = "FAA902")
        m.ipl(0x130)
        if trace_gates:
            m.break_at(0x8122)
        res = sdm(m, message = "E/A,01F/A,00E/A400003F0/A80000350/I,01F,01F,00E,130/S8150." + switches + "000000/L8150/B",
                  budget = 80000000, step = 100000)
        if trace_gates:
            records = archive.simh(library_reel(tape)).records
            headers = [i for i, data in library_headers(records) if data[8:16] == "D8150400"]
            if len(headers) != 1:
                fail("expected one D8150400 library entry")
            header = headers[0]
            payload = records[header + 1].data
            stop = res["run"]
            for address in [0x8122, 0x8306, 0x8944]:
                if address != 0x8122:
                    m.break_at(address)
                    stop = m.run(instructions = 1000000)
                if stop.kind != "breakpoint" or int(stop.psw[-6:], 16) != address:
                    fail("D81504 missed branch at %x: %s" % (address, stop))
                offset = address - 4 - 0x8000
                code = m.read(address - 4, 8)
                if payload.bytes(offset, 8) != code:
                    fail("loaded D81504 instructions differ from the reel at %x" % address)
                print("Tape record %d + %x: %s" % (header + 1, offset, binary.hex(code)))
                m.clear_breaks()
                after = m.run(instructions = 1)
                print("D81504 branch at %x: PSW %s -> %s" % (address, stop.psw, after.psw))
            return
        print("D81504: %s, sections=%s, errors=%s" % (res["ended"], res["sections"], res["errors"]))
        print("Section switches " + binary.hex(m.read(0x8004, 4)))
        print("Disk usage", m.dasd_usage()[0x350])
        for mask, address in [("80", 0x8122), ("40", 0x8306), ("20", 0x8944)]:
            if switches == "E0" or switches == mask:
                print("D81504 switch %s, TM and branch at %x: %s" %
                      (mask, address - 4, binary.hex(m.read(address - 4, 8))))
        return
    if args and args[0] == "tape-ring-late":
        if len(args) != 2 or args[1] not in LATE_EOT_DRIVES:
            fail("usage: s370_diag.star tape-ring-late " + "|".join(LATE_EOT_DRIVES.keys()))
        check_d405e1_late_eot(tape, args[1])
        return
    if args and args[0] == "tape-ring":
        if len(args) > 2 or (len(args) == 2 and args[1] not in ["eot", "pe-eot"]):
            fail("usage: s370_diag.star tape-ring [eot|pe-eot]")
        pe = len(args) == 2 and args[1] == "pe-eot"
        m = machine(tape)
        # Switch 5 writes until the physical end-of-tape marker is sensed.
        m.tape(0x3f0, tape.slice(0, 0), type = "2401", model = 5 if pe else 0, eot_inches = 600)
        m.ipl(0x130)
        switches = "5.7" if len(args) == 2 else "7"
        option = "0C" if pe else "00"
        res = sdm(m, message = "E/A,01F/A40" + option + "03F0/I,01F,01F,01F,130/SS405E." + switches + "/L405E/B",
                  budget = 80000000, step = 100000, handle_operator = tape_ring_operator)
        print("%s, sections=%s, errors=%s" % (res["ended"], res["sections"], res["errors"]))
        if res["ended"] != "end-of-job" or res["errors"] or res["skipped"]:
            fail("D405E1 did not finish cleanly")
        if [(s["section"], s["routines"]) for s in res["sections"]] != [("D405E1", "05")]:
            fail("unexpected D405E1 completion")
        if len(args) == 2 and any(["SKIP-SNSW" in line for line in res["transcript"]]):
            fail("D405E1 skipped a requested switch path")
        return
    if args and args[0] == "tape-manual":
        if len(args) < 2 or len(args) > 3 or args[1] not in ["creep", "timing", "gap-counts", "switches"]:
            fail("usage: s370_diag.star tape-manual creep|timing|gap-counts|switches [step]")
        m = machine(tape, scratch_tapes = [0x3f0])
        m.ipl(0x130)
        motion = args[1] != "switches"
        timing = args[1] == "timing"
        counts = args[1] == "gap-counts"
        selection = "L4060" if motion else "SS405E.5.7/L405E"
        if motion:
            m.break_program(9 if timing or counts else 1)
            m.history(keep = 20)
        if counts:
            m.break_at(0x91dc)
        res = sdm(m, message = "E/A,01F/A400003F0/I,01F,01F,01F,130/" + selection + "/B",
                  budget = 300000000, step = int(args[2]) if len(args) == 3 else 100000)
        if counts:
            r = res["run"]
            for sample in range(5):
                if r.kind != "breakpoint":
                    fail("D40604 did not reach the gap comparison")
                gr = m.registers().gr
                print("D40604 gap counts: separate=%s chained=%s sum-so-far=%s" %
                      (gr[1], binary.hex(m.read(0xa49c, 4)), gr[3]))
                if sample == 0:
                    m.trace_io(skip = [0x130, 0x01f, 0x00c, 0x00e], quiet_polls = True)
                if sample == 1:
                    reads = [event for event in m.events() if "03F0 " in event and
                             ("cmds [02 " in event or "][02 " in event)]
                    print("\n".join(reads[-6:]))
                    m.trace_io(on = False)
                m.clear_breaks()
                m.break_program(9)
                m.run(instructions = 1)
                m.break_at(0x91dc if sample < 4 else 0x91f2)
                r = m.run(instructions = 30000000)
            if r.kind != "breakpoint":
                fail("D40604 did not reach the final divide")
            print("D40604 measured path dividend: " + "".join(m.registers().gr[2:4]))
            return
        print("%s, %s, sections=%s, errors=%s" %
              (res["ended"], res["run"].psw, res["sections"], res["errors"]))
        if motion and res["ended"] == "program":
            print("program old PSW " + binary.hex(m.read(0x18, 8)))
            print("\n".join(m.history()))
            if timing:
                print("D40604 divide operand at A454: " + binary.hex(m.read(0xa454, 4)))
        else:
            print(m.disassemble(int(res["run"].psw[-6:], 16), 4))
        print(m.subchannel(0x3f0))
        return
    if args and args[0] == "tape-density":
        if len(args) > 2 or len(args) == 2 and args[1] not in ["2415", "2415-pe-only"]:
            fail("usage: s370_diag.star tape-density [2415|2415-pe-only]")
        slow = len(args) == 2
        pe_only = slow and args[1] == "2415-pe-only"
        cases = [("SS405F.4/", ["P E"]), ("", ["NRZI", "P E"]), ("SS405F.3.4/", ["NRZI", "P E"])]
        if pe_only:
            cases = [("", ["P E"]), ("SS405F.4/", ["P E"])]
        for selection, densities in cases:
            m = machine(tape)
            m.tape(0x3f0, tape.slice(0, 0), type = "2415" if slow else "2401", dual_density = not pe_only, pe_only = pe_only)
            m.ipl(0x130)
            option = "0C" if pe_only else ("08" if slow else "04")
            res = sdm(m, message = "E/A,01F/A40%s03F0/I,01F,01F,01F,130/%sL405F/B" % (option, selection),
                      budget = 1500000000 if slow else 300000000, step = 100000)
            if res["ended"] != "end-of-job" or res["errors"] or res["skipped"]:
                fail("D405F1 did not finish cleanly")
            if [(s["section"], s["routines"]) for s in res["sections"]] != [("D405F1", "01")]:
                fail("unexpected D405F1 completion")
            passes = [line.strip() for line in res["transcript"] if " START " in line]
            expected = ["03F0 START %s PASS *%s" % (operation, density) for density in densities for operation in ["WRT", "RDF", "RDB"]]
            if passes != expected:
                fail("D405F1 selected unexpected passes: %s" % passes)
        return
    if args and args[0] == "tape-errors":
        if len(args) > 2 or len(args) == 2 and args[1] != "2415-pe-only":
            fail("usage: s370_diag.star tape-errors [2415-pe-only]")
        pe_only = len(args) == 2
        kind = "2415" if pe_only else "2401"
        option = "0C" if pe_only else "00"
        read_cases = [("clean", "3.8"), ("compare", "3.8"), ("compare", "3.8.11"),
                      ("length", "3.8.10"), ("data-check", "3.8.10"), ("data-check", "3.8")]
        if pe_only:
            read_cases = [("data-check", "4.8.10"), ("data-check", "4.8")]
        for fault, switches in read_cases:
            m = machine(tape)
            m.tape(0x3f0, d405f_scratch_reel(fault), type = kind, format = "simh", pe_only = pe_only)
            m.ipl(0x130)
            print("D405F1 scratch reel %s, switches %s" % (fault, switches))
            res = sdm(m, message = "E/A,01F/A40%s03F0/I,01F,01F,01F,130/SS405F.%s/L405F/B" % (option, switches),
                      budget = 1000000000 if pe_only else 300000000, step = 100000)
            lines = [line.strip() for line in res["transcript"]]
            if res["ended"] != "end-of-job" or res["skipped"] or [(s["section"], s["routines"]) for s in res["sections"]] != [("D405F1", "01")]:
                fail("D405F1 %s: unexpected completion" % fault)
            if "ORIGIN WAS 03F0" not in lines or ("END RDB-ORIGIN WAS 03F0" in lines) != (fault != "length"):
                fail("D405F1 %s: unexpected read sequence" % fault)
            if fault == "clean":
                if res["errors"] or any([" ERRS " in line or "RETRIES FAIL" in line for line in lines]):
                    fail("D405F1 clean scratch reel reported errors")
            elif fault == "compare":
                first = "ACT FF0102030405060708090A0B0C0D0E0F"
                second = "ACT FF1112131415161718191A1B1C1D1E1F"
                actual = [line for line in lines if line.startswith("ACT ")]
                expected = [first, second, second, first] if switches.endswith(".11") else [first, second]
                totals = [line for line in lines if "COMP ERRS" in line]
                if actual != expected or len(res["errors"]) != len(expected) or totals != ["RDF COMP ERRS 000001", "RDB COMP ERRS 000001"]:
                    fail("D405F1 switch 11: unexpected compare reports")
            elif fault == "length":
                incorrect_length = [line for line in lines if line.endswith(" ILI")]
                if incorrect_length != ["REC 0001 ILI", "REC 0002 ILI"] or "DELETED-ILI" not in lines or "03F0 START RDB PASS *NRZI" in lines or len(res["errors"]) != 4:
                    fail("D405F1 did not delete the unit on consecutive incorrect-length reads")
            else:
                reports = [line for line in lines if line.startswith("SNS 08 ")]
                expected_count = 10 if switches.endswith(".10") else 0
                retries = [line for line in lines if "RETRIES FAIL" in line]
                totals = [line for line in lines if "READ ERRS" in line]
                if (len(reports) != expected_count or len(res["errors"]) != expected_count or
                    retries != ["5 RDF RETRIES FAIL-REC 0001", "5 RDB RETRIES FAIL-REC 0001"] or
                    totals != ["RDF READ ERRS 00005", "RDB READ ERRS 00005"]):
                    fail("D405F1 switch 10: unexpected data-check reports")
                if pe_only and expected_count and reports != ["SNS 08  40  03  04  00  00"] * 5 + ["SNS 08  40  03  06  00  00"] * 5:
                    fail("D405F1 PE-only read did not report the expected direction and density sense")
        # A write data check advances over the damaged record so that
        # D405F1 can backspace, erase a gap, and retry the same record.
        for mode, density in ([("4", "P E")] if pe_only else [("3", "NRZI"), ("4", "P E")]):
            for count, total in [(1, "00001"), (5, "00005")]:
                m = machine(tape)
                m.tape(0x3f0, tape.slice(0, 0), type = kind, dual_density = not pe_only, pe_only = pe_only)
                m.tape_write_checks(0x3f0, index = 1, count = count)
                m.ipl(0x130)
                res = sdm(m, message = "E/A,01F/A40%s03F0/I,01F,01F,01F,130/SS405F.%s.10/L405F/B" % (option if pe_only else "04", mode),
                          budget = 1500000000 if pe_only else 300000000, step = 100000)
                lines = [line.strip() for line in res["transcript"]]
                exhausted = count == 5
                has_reads = all(["03F0 START %s PASS *%s" % (op, density) in lines for op in ["RDF", "RDB"]])
                if (res["ended"] != "end-of-job" or res["skipped"] or len(res["errors"]) != count or
                    len([line for line in lines if line.startswith("SNS 08 ")]) != count or
                    "TOTAL WRT ERRS-" + total not in lines or
                    ("DELETE-5 WRT RETRIES FAIL-REC 0001" in lines) != exhausted or
                    "DELETE-WRT RETRY SIO FAIL-REC 0001" in lines or has_reads == exhausted or
                    ("END RDB-ORIGIN WAS 03F0" in lines) == exhausted):
                    fail("D405F1 %s: unexpected result after %d write data checks" % (density, count))
                if pe_only and [line for line in lines if line.startswith("SNS 08 ")] != ["SNS 08  44  03  04  00  00"] * count:
                    fail("D405F1 PE-only write did not report the expected write and density sense")
        if pe_only:
            return
        # A close EOT marker makes the first data write and the retry
        # positioning chain report unit exception on the scratch drive.
        m = machine(tape)
        m.tape(0x3f0, tape.slice(0, 0), type = "2401", eot_inches = 1)
        m.ipl(0x130)
        res = sdm(m, message = "E/A,01F/A400003F0/I,01F,01F,01F,130/SS405F.3.10/L405F/B",
                  budget = 60000000, step = 100000)
        lines = [line.strip() for line in res["transcript"]]
        if (res["ended"] != "end-of-job" or res["skipped"] or len(res["errors"]) != 2 or
            "DELETE-WRT RETRY SIO FAIL-REC 0001" not in lines or "TOTAL WRT ERRS-00001" not in lines or
            "03F0 START RDF PASS *NRZI" in lines):
            fail("D405F1 did not delete the unit after a failed write retry chain")
        return
    if len(args) == 1 and args[0] == "tape-read-only":
        for density, mode_switch in [("NRZI", "3"), ("P E", "4")]:
            m = machine(tape, scratch_tapes = [0x3f0], dual_density = True, boot_2401 = True)
            for pass_type in ["write", "read-only", "ring removed"]:
                if pass_type != "write":
                    m.key(0x130, "REMOVE FILE PROTECT RING")
                if pass_type == "ring removed":
                    m.key(0x3f0, "REMOVE FILE PROTECT RING")
                m.ipl(0x130)
                switches = mode_switch + (".8" if pass_type == "read-only" else "")
                res = sdm(m, message = "E/A,01F/A400403F0/I,01F,01F,01F,130/SS405F.%s/L405F/B" % switches,
                          budget = 300000000, step = 100000)
                lines = [line.strip() for line in res["transcript"]]
                protected = pass_type == "ring removed"
                expected_errors = ["* SD0 D405F1 84 0083DE 3F0"] if protected else []
                if res["ended"] != "end-of-job" or [line.strip() for line in res["errors"]] != expected_errors or res["skipped"]:
                    fail("D405F1 %s %s did not finish with the expected status" % (density, pass_type))
                if [(s["section"], s["routines"]) for s in res["sections"]] != [("D405F1", "01")]:
                    fail("unexpected D405F1 completion")
                if ("UNIT FILE PROTECTED - WRT PASS DELETED" in lines) != protected:
                    fail("D405F1 did not recognize the expected ring state")
                if any(["START WRT" in line for line in lines]) != (pass_type == "write"):
                    fail("D405F1 selected the wrong write pass")
                for operation in (["WRT"] if pass_type == "write" else []) + ["RDF", "RDB"]:
                    if "03F0 START %s PASS *%s" % (operation, density) not in lines:
                        fail("D405F1 did not complete %s %s" % (density, operation))
                if "ORIGIN WAS 03F0" not in lines or "END RDB-ORIGIN WAS 03F0" not in lines:
                    fail("D405F1 did not read the original reel in both directions")
        return
    if args and args[0] == "tape-interchange":
        if len(args) > 2 or len(args) == 2 and args[1] not in ["pe", "pe-model5"]:
            fail("usage: s370_diag.star tape-interchange [pe|pe-model5]")
        pe = len(args) == 2
        model = 5 if pe and args[1] == "pe-model5" else 0
        m = machine(tape)
        for address in [0x3f0, 0x3f1]:
            m.tape(address, tape.slice(0, 0), type = "2401", model = model, dual_density = pe)
        m.ipl(0x130)
        prompt = "INTERCHANGE UNITS-BEGIN"
        options = "04" if pe else "00"
        switches = "4.9" if pe else "9"
        res = sdm(m, message = "E/A,01F/A40%s03F0/A40%s03F1/I,01F,01F,01F,130/SS405F.%s/L405F/B" % (options, options, switches),
                  budget = 500000000, step = 100000, stop = prompt, show = False)
        if res["ended"] != "stop" or res["errors"]:
            fail("D405F1 did not reach the reel interchange")
        m.run(instructions = 2000000)
        m.swap_tape_reels(0x3f0, 0x3f1)
        m.key(0x01f, "REQUEST")
        m.run(instructions = 2000000)
        m.type(0x01f, "B")
        for _ in range(160):
            m.run(instructions = 1000000)
            if len([line for line in m.screens(0x01f) if prompt in line]) == 2:
                break
        lines = [line.strip() for line in m.screens(0x01f)]
        first = lines.index(prompt)
        if len([line for line in lines if line == prompt]) != 2:
            fail("D405F1 did not reach the second interchange prompt")
        # Each drive must read the other drive’s origin in both directions.
        forward, backward = [], []
        drive = ""
        for line in lines[first + 1:]:
            if "START RDF PASS" in line or "START RDB PASS" in line:
                drive = line.split()[0]
            if line.startswith("ORIGIN WAS "):
                forward.append((drive, line.split()[-1]))
            if line.startswith("END RDB-ORIGIN WAS "):
                backward.append((drive, line.split()[-1]))
        if pe:
            for dev in ["03F0", "03F1"]:
                for operation in ["RDF", "RDB"]:
                    if "%s START %s PASS *P E" % (dev, operation) not in lines[first + 1:]:
                        fail("D405F1 did not compare PE data after interchange on " + dev)
        crossed = [("03F0", "03F1"), ("03F1", "03F0")]
        if forward != crossed or backward != crossed:
            fail("D405F1: unexpected read origins: forward=%s backward=%s" % (forward, backward))
        m.run(instructions = 2000000)
        m.key(0x01f, "REQUEST")
        m.run(instructions = 2000000)
        m.type(0x01f, "RS405F.9/B")
        m.run(instructions = 22000000)
        print("\n".join(m.screens(0x01f)))
        # Both halts are intentional in this job.
        lines = [line.strip() for line in m.screens(0x01f)]
        if any([line.startswith("*") or "DELETE-" in line for line in lines]) or "T   D405F1 01 ROUTINES RUN" not in lines or END_OF_JOB not in lines:
            fail("D405F1 did not complete the interchange job cleanly")
        return
    if args and args[0] == "tape-eot":
        if len(args) < 2 or len(args) > 3 or args[1] not in ["s360", "9020"] or (len(args) == 3 and args[2] != "compare"):
            fail("usage: s370_diag.star tape-eot s360|9020 [compare]")
        m = machine(tape, model = "" if args[1] == "s360" else "9020")
        m.tape(0x3f0, tape.slice(0, 0), type = "2401", eot_inches = 600)
        m.ipl(0x130)
        compare = len(args) == 3
        if compare:
            m.break_at(0x8690)
        res = sdm(m, message = "E/A,01F/A400003F0/I,01F,01F,01F,130/SW.00000400/L4061/B",
                  budget = 40000000, step = 100000)
        if compare:
            instruction = binary.hex(m.read(0x8690, 10))
            regs = m.registers()
            if res["ended"] != "breakpoint" or regs.gr[2:4] != ["00000000", "00000000"] or instruction != "d212f31ef25147f0fb36":
                fail("D40610 did not reach the original compare fallthrough with equal operands")
            matches = []
            for record in archive.simh(library_reel(tape)).records:
                if record.tape_mark:
                    break
                offset = binary.hex(record.data.bytes()).find(instruction)
                if offset >= 0:
                    matches.append((record.offset, offset // 2))
            if len(matches) != 1:
                fail("D40610 compare fallthrough bytes are not unique on the original library")
            print("D40610: equal registers at X'8690', bytes %s, SIMH record offset and payload offset %s" % (instruction, matches[0]))
            m.clear_breaks()
            for _ in range(400):
                m.run(instructions = 100000)
                lines = [line.strip() for line in m.screens(0x01f)]
                if END_OF_JOB in lines:
                    break
            expected = ["* SD0 D40610 01 008BA4 3F0", "SENSE COMPARE ERROR", "EXPECTED CSW    000083780C000000",
                        "RECEIVED CSW    000083780C000000", "EXPECTED SENSE  004003000000", "RECEIVED SENSE  004003000000",
                        "TAPE REWINDING -- END OF TAPE SENSED.", END_OF_JOB]
            if any([line not in lines for line in expected]):
                fail("D40610 did not report the false compare error and then rewind")
            print("\n".join(expected))
            return
        print("D40610 (%s): %s, %s, errors=%s" % (args[1], res["ended"], res["sections"], res["errors"]))
        return
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
    if args and args[0] == "inspect":
        if len(args) > 2 or (len(args) == 2 and args[1] not in ["tail", "tail-read"]):
            fail("usage: s370_diag.star inspect [tail|tail-read]")
        # Retain positionable damage for inspection; report it explicitly.
        # archive.simh defaults to strict validation for other consumers.
        records = archive.simh(tape, strict = False).records
        if len(args) == 2 and args[1] == "tail-read":
            broken = [(i, record) for i, record in enumerate(records) if record.framing_error]
            if len(broken) != 1:
                fail("expected one damaged record on the pinned image")
            index, record = broken[0]
            files = len([r for r in records[:index] if r.tape_mark])
            m = machine(tape, memory = 128 << 10, model = "65", boot_2401 = True)
            # Space past the exact count of file marks before the damaged
            # block, then use Read and Sense on the original protected reel.
            m.storage_load([
                (0, b"\x00\x00\x00\x00\x00\x00\x08\x00"),
                (0x48, b"\x00\x00\x02\x00"),
                (0x200, binary.decode("3f00020000000001" +
                                      "0200100020007fff" +
                                      "0000020800000218" +
                                      "040002a000000006", "hex")),
                (0x800, bytes([0x41, 0x10, files >> 8, files & 0xff])),
                (0x804, binary.decode("9c0001309d0001304770080846100804" +
                                      "d203004802109c0001309d0001304770081e" +
                                      "d20702980040d203004802149c0001309d00013047700836" +
                                      "82000850", "hex")),
                (0x850, b"\x00\x02\x00\x00\x00\x00\x08\x42"),
            ])
            m.break_at(0x814)
            positioned = m.run(instructions = 150000000)
            if positioned.kind != "breakpoint" or m.tape_position(0x130).position != index:
                fail("FSF did not reach the damaged record: %s %s" % (positioned.kind, positioned.psw))
            m.clear_breaks()
            read = m.run(instructions = 1000000)
            csw = binary.hex(m.read(0x298, 8))
            sense_csw = binary.hex(m.read(0x40, 8))
            sense = binary.hex(m.read(0x2a0, 6))
            print("2401 after %d file marks: damaged record at %d, Read CSW %s, Sense CSW %s, Sense %s" %
                  (files, record.offset, csw, sense_csw, sense))
            if (read.kind != "disabled-wait" or m.tape_position(0x130).position != index + 1 or
                csw != "000002100e007fff" or sense_csw != "000002200c000000" or not sense.startswith("08")):
                fail("damaged original record did not return data check without transferring data")
            return
        if len(args) == 2:
            end = LIBRARY_TAPE_MARK + 8
            tail = [r for r in records if r.offset >= end]
            payloads = [r for r in tail if r.data != None]
            print("Reel after its two library tape marks: %d bytes, %d further marks, %d payloads" %
                  (tape.size - end, len([r for r in tail if r.tape_mark]), len(payloads)))
            for record in payloads:
                payload = record.data
                sha256 = binary.hex(digest(payload))
                matches = [i for i, earlier in enumerate(records)
                           if earlier.offset < end and earlier.data != None and earlier.data.size == payload.size and
                           binary.hex(digest(earlier.data)) == sha256]
                print("Offset %d, %d bytes, SHA-256 %s, earlier exact matches %s" %
                      (record.offset, payload.size, sha256, matches))
                data = binary.hex(payload.bytes())
                library = binary.hex(tape.bytes(0, end))
                offset = 0
                for _ in range(16):
                    remaining = data[offset * 2:]
                    nonzero = remaining.lstrip("0")
                    start = offset + (len(remaining) - len(nonzero)) // 2
                    if start > offset:
                        print("Payload bytes %d–%d are zero" % (offset, start - 1))
                    if not nonzero:
                        offset = start
                        break
                    sig = data[start * 2:(start + 32) * 2]
                    match = library.find(sig)
                    if match < 0 or match % 2:
                        print("Unmatched payload bytes starting at %d: %s" % (start, sig))
                        break
                    original_start = match // 2
                    size = min(end - original_start, payload.size - start)
                    # Compare the maximal prefix anchored by the signature.
                    longer = size + 1
                    shorter = len(sig) // 2
                    for _ in range(32):
                        if longer - shorter == 1:
                            break
                        span = (longer + shorter) // 2
                        if data[start * 2:(start + span) * 2] == library[match:match + span * 2]:
                            shorter = span
                        else:
                            longer = span
                    offset = start + shorter
                    print("Payload bytes %d–%d match original library bytes %d–%d" %
                          (start, offset - 1, original_start, original_start + shorter - 1))
                if offset != payload.size:
                    fail("Unclassified tail payload bytes after %d" % offset)
                if record.framing_error:
                    print(record.framing_error)
            return
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
