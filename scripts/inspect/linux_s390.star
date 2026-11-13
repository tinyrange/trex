"""Steps the Debian lenny s390 storage load on emulator.s390 for investigation.

Run: go run ./cmd/trex scripts/inspect/linux_s390.star [dasd] STEP...
Steps: run=N (instructions), until=TEXT, cmd=TEXT, messages, regs, events=N,
unknown, programs, interrupts, history=N (enable), show-history=N, dis=ADDR[:N], profile=N,
break=ADDR, sym=ADDR[,ADDR], read=ADDR:LEN, trace_io, dasd_errors=DEV.
"""

load("//scripts/images:debian_s390.star", "dasd_image", "image", "symbols")

def _symbol(table, address):
    lo, hi = 0, len(table)
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if table[mid][0] <= address:
            lo = mid
        else:
            hi = mid
    return "%s+%X" % (table[lo][1], address - table[lo][0])

def main(args):
    table = None
    m = emulator.s390(memory = 128 << 20, start = "2012-01-01T00:00:00Z")
    if args and args[0] == "dasd":
        # Root on an LDL 3390 at 0200.
        args = args[1:]
        built = dasd_image()
        m.dasd(0x200, ldl = built["root"], cylinders = built["cylinders"])
    else:
        built = image()
    m.storage_load(built["images"])
    for step in args:
        key, _, value = step.partition("=")
        if key == "run":
            r = m.run(instructions = int(value))
            print("run: %s %s psw=%s %d instr %ss time=%s" % (r.kind, r.detail, r.psw, r.instructions, str(r.seconds)[:5], m.time()))
        elif key == "until":
            for _ in range(1000):
                r = m.run(instructions = 10000000)
                if value in "\n".join(m.messages()) or r.kind not in ["budget", "idle"]:
                    break
            print("until: %s psw=%s time=%s" % (r.kind, r.psw, m.time()))
        elif key == "sym":
            if table == None:
                table = symbols()
            for a in value.split(","):
                print("%s %s" % (a, _symbol(table, int(a, 16) & 0x7fffffff)))
        elif key == "trace_io":
            m.trace_io()
        elif key == "dasd_errors":
            print(m.dasd_errors(int(value, 16)).errors)
        elif key == "cmd":
            m.command(value)
        elif key == "messages":
            print("\n".join(m.messages()[-int(value or "60"):]))
        elif key == "regs":
            r = m.registers()
            print("psw " + r.psw + " prefix " + r.prefix)
            print("gr " + " ".join(r.gr))
            print("cr " + " ".join(r.cr))
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
            print(m.disassemble(int(a, 16), int(n or "16")))
        elif key == "profile":
            if value == "on":
                m.profile(on = True)
            else:
                print("\n".join(m.profile(top = int(value))))
        elif key == "break":
            m.break_at(int(value, 16))
        elif key == "read":
            a, _, n = value.partition(":")
            print(m.read(int(a, 16), int(n, 16)))
        else:
            fail("unknown step " + step)
