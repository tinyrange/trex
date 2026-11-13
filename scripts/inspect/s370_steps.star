"""Shared stepping for System/370 probes on emulator.s390.

Steps: ipl=DEV[:LOADPARM], run=N, until=DEV:TEXT, type=DEV:TEXT, request=DEV,
key=DEV:KEY, screen=DEV, screens=DEV[:N], regs, events=N, unknown, programs,
interrupts, history=N, show-history=N, dis=ADDR[:N], break=ADDR,
read=ADDR:LEN, vread=ADDR:LEN (primary virtual), watch=ADDR[:LEN], trace_io, output=DEV, deck=DEV:CARD|CARD..., track=DEV:CYL:HEAD (hex), sch=DEV.
"""

def _until(m, dev, text, budget, step = 2000000):
    spent = 0
    r = None
    while spent < budget:
        r = m.run(instructions = step)
        spent += step
        if text in m.screen(dev):
            return "found after %d (%s %s)" % (spent, r.kind, r.psw)
        if r.kind in ["disabled-wait", "check-stop", "stopped"]:
            break
    return "NOT FOUND (%s %s)" % (r.kind, r.psw)

def run_steps(m, steps):
    """Runs probe steps against an emulator.s390 machine."""
    for step in steps:
        key, _, value = step.partition("=")
        if key == "ipl":
            dev, _, parm = value.partition(":")
            m.ipl(int(dev, 16), loadparm = parm)
        elif key == "run":
            r = m.run(instructions = int(value))
            print("run: %s %s psw=%s %d instr time=%s" % (r.kind, r.detail, r.psw, r.instructions, m.time()))
        elif key == "until":
            dev, _, text = value.partition(":")
            print("until: " + _until(m, int(dev, 16), text, 200000000))
        elif key == "type":
            dev, _, text = value.partition(":")
            m.type(int(dev, 16), text)
        elif key == "request":
            m.key(int(value, 16), "REQUEST")
        elif key == "key":
            dev, _, k = value.partition(":")
            m.key(int(dev, 16), k)
        elif key == "screen":
            print(m.screen(int(value, 16)))
        elif key == "screens":
            dev, _, n = value.partition(":")
            for s in m.screens(int(dev, 16))[-int(n or "5"):]:
                print("----")
                print(s)
        elif key == "regs":
            r = m.registers()
            print("psw " + r.psw + " prefix " + r.prefix)
            print("gr " + " ".join(r.gr))
            print("cr " + " ".join(r.cr))
            print("ar " + " ".join(r.ar))
        elif key == "events":
            for e in m.events()[-int(value):]:
                print(e)
        elif key == "unknown":
            print(m.unknown())
        elif key == "programs":
            print(m.program_counts())
        elif key == "interrupts":
            print(m.interrupts())
        elif key == "history":
            m.history(keep = int(value))
        elif key == "show-history":
            print("\n".join(m.history()[-int(value):]))
        elif key == "dis":
            a, _, n = value.partition(":")
            print("\n".join(m.disassemble(int(a, 16), int(n or "16"))))
        elif key == "vdis":
            a, _, n = value.partition(":")
            print("\n".join(m.disassemble(int(a, 16), int(n or "16"), virtual = True)))
        elif key == "break_reg":
            # break_reg=ADDR:R:VALUE runs to ADDR until GR R holds VALUE.
            a, r, want = value.split(":")
            m.break_at(int(a, 16))
            for _ in range(100000):
                res = m.run(instructions = 1000000000)
                if res.kind != "breakpoint" or int(m.registers().gr[int(r)], 16) == int(want, 16):
                    break
            m.clear_breaks()
            print("break_reg: %s %s" % (res.kind, res.detail))
        elif key == "break_mem":
            # break_mem=ADDR:R:OFF:HEX runs to ADDR until the virtual
            # storage at GR R + OFF holds HEX.
            a, r, off, want = value.split(":")
            want = binary.decode(want, "hex")
            m.break_at(int(a, 16))
            for _ in range(100000):
                res = m.run(instructions = 1000000000)
                if res.kind != "breakpoint":
                    break
                at = int(m.registers().gr[int(r)], 16) + int(off, 16)
                if m.read(at, len(want), virtual = True) == want:
                    break
            m.clear_breaks()
            print("break_mem: %s %s" % (res.kind, res.detail))
        elif key == "watch_value":
            # watch_value=ADDR:HEX runs until a store leaves HEX at ADDR.
            a, want = value.split(":")
            want = binary.decode(want, "hex")
            m.watch(int(a, 16), len(want))
            for _ in range(100000):
                res = m.run(instructions = 1000000000)
                if res.kind != "watch" or m.read(int(a, 16), len(want)) == want:
                    break
            print("watch_value: %s %s" % (res.kind, res.detail))
        elif key == "until_pci":
            # until_pci=DEV[:TEXT] runs until DEV's channel program pauses
            # after a PCI CCW with TEXT (e.g. "ccw=F566") in its status.
            dev, _, text = value.partition(":")
            was = False
            for _ in range(2000000):
                m.run(instructions = 300)
                st = m.subchannel(int(dev, 16))
                now = "pci=true" in st
                if now and not was and text in st:
                    break
                was = now
            print("until_pci: " + m.subchannel(int(dev, 16)))
        elif key == "until_resume":
            # until_resume=DEV runs in small steps until DEV's PCI pause ends.
            for _ in range(2000000):
                if "pci=true" not in m.subchannel(int(value, 16)):
                    break
                m.run(instructions = 50)
            print("until_resume: " + m.subchannel(int(value, 16)))
        elif key == "ccws":
            # ccws=ADDR:N prints N doublewords of real storage as CCWs.
            a, _, n = value.partition(":")
            for i in range(int(n or "16")):
                print("%X %s" % (int(a, 16) + 8 * i, binary.hex(m.read(int(a, 16) + 8 * i, 8))))
        elif key == "clear_breaks":
            m.clear_breaks()
        elif key == "break_program":
            m.break_program(int(value, 16))
        elif key == "break":
            m.break_at(int(value, 16))
        elif key == "translate":
            print("%s -> %X" % (value, m.translate(int(value, 16))))
        elif key == "vread":
            a, _, n = value.partition(":")
            print(binary.hex(m.read(int(a, 16), int(n, 16), virtual = True)))
        elif key == "read":
            a, _, n = value.partition(":")
            print(binary.hex(m.read(int(a, 16), int(n, 16))))
        elif key == "watch":
            a, _, n = value.partition(":")
            m.watch(int(a, 16), int(n or "1", 16))
        elif key == "dasd_errors":
            e = m.dasd_errors(int(value, 16))
            print("%s commands=%d writes=%d errors=%s" % (value, e.commands, e.writes, e.errors))
        elif key == "sch":
            print(m.subchannel(int(value, 16)))
        elif key == "track":
            dev, c, h = value.split(":")
            print("\n".join(m.dasd_track(int(dev, 16), int(c, 16), int(h, 16))))
        elif key == "deck":
            dev, _, text = value.partition(":")
            m.cards(int(dev, 16), text.split("|"))
        elif key == "output":
            print("\n".join(m.output(int(value, 16))))
        elif key == "ucb":
            # MVS UCB common segment: +1 X'FF' identifier, +4 device number.
            dev = int(value, 16)
            for a in m.find(bytes([dev >> 8, dev & 0xff]), limit = 100000):
                if a >= 4 and m.read(a - 3, 1) == b"\xff":
                    print("%X %s" % (a - 4, binary.hex(m.read(a - 4, 48))))
        elif key == "findhex":
            pat, _, ctx = value.partition(":")
            for a in m.find(binary.decode(pat, "hex"), limit = 200):
                b = max(a - int(ctx or "16"), 0)
                print("%X %s" % (b, binary.hex(m.read(b, 2 * int(ctx or "16") + 16))))
        elif key == "reply":
            # reply=DEV:MSGID:TEXT finds the outstanding reply for MSGID
            # with D R,L on console DEV and answers it.
            dev, msgid, text = value.split(":", 2)
            d = int(dev, 16)
            m.type(d, "D R,L")
            m.key(d, "ENTER")
            m.run(instructions = 300000000)
            rid = ""
            for line in m.screen(d).split("\n"):
                words = line.split()
                for i in range(len(words) - 1):
                    if words[i + 1] == msgid and words[i].startswith("*") and words[i][1:].isdigit():
                        rid = words[i][1:]
            if not rid:
                fail("reply: no outstanding " + msgid)
            m.type(d, "R %s,%s" % (rid, text))
            m.key(d, "ENTER")
            print("reply: %s %s %s" % (rid, msgid, text))
        elif key == "event_limit":
            m.event_limit(int(value))
        elif key == "trace_io":
            m.trace_io(skip = [int(d, 16) for d in value.split(",") if d])
        else:
            fail("unknown step " + step)
