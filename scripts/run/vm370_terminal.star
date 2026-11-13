"""Runs VM/370 Release 6 with its consoles in a web browser and,
optionally, on a tn3270 port.

The public-domain starter system is restored from its DDR tapes onto fresh
3330s and CP is cold started, exactly as the vm370 smoke does; the 3277s
are then enabled. Served: the 3215 operator console at 01F (a line-mode
console: type CP operator commands), 3277 displays at 040 and 041 (log on
MAINT with password CPCMS, then IPL 190 for CMS) and the hardware system
console. Everything lives only in memory.

Usage: trex -serve 127.0.0.1:8370 scripts/run/vm370_terminal.star ESSENTIALS.tar.gz VMREL6.ddr.aws.bz2 CPR6L0.ddr.aws.bz2 [tn3270=ADDRESS] [state=PATH]
With state=PATH the machine resumes from that checkpoint when it exists and
is saved there on Ctrl-C, SIGTERM or the page's Save button.
"""

load("//scripts/inspect:vm370_lib.star", "machine")

OPERATOR = 0x01F

def _until(m, text, budget, seen = 0):
    spent = 0
    r = None
    while spent < budget:
        r = m.run(instructions = 2000000)
        spent += 2000000
        if m.screen(OPERATOR).count(text) > seen:
            return
        if r.kind in ["disabled-wait", "check-stop", "stopped"]:
            break
    fail("vm370: %r not seen on the operator console (%s)\n%s" % (text, r.kind, m.screen(OPERATOR)))

def _operator(m, line, expect, budget = 200000000):
    seen = m.screen(OPERATOR).count(expect)
    m.type(OPERATOR, line)
    _until(m, expect, budget, seen = seen)

def main(args):
    usage = "usage: vm370_terminal.star ESSENTIALS.tar.gz VMREL6.ddr.aws.bz2 CPR6L0.ddr.aws.bz2 [tn3270=ADDRESS] [state=PATH]"
    if len(args) < 3:
        fail(usage)
    tn3270, state = "", ""
    for arg in args[3:]:
        if arg.startswith("tn3270="):
            tn3270 = arg[len("tn3270="):]
        elif arg.startswith("state="):
            state = arg[len("state="):]
        else:
            fail(usage)
    m = machine(open(args[0]), open(args[1]), open(args[2]))
    if state and exists(state):
        print("resuming from " + state)
        m.restore(open(state))
        return m.web_terminals(tn3270 = tn3270, state = state)
    print("restoring VM/370 from its DDR tapes and cold starting CP")
    m.ipl(0x580)
    _until(m, "ENTER CARD READER ADDRESS OR CONTROL STATEMENTS", 20000000)
    for tape, dasd, volser in [("581", "131", "VMREL6"), ("582", "132", "CPR6L0")]:
        _operator(m, "input %s 3420" % tape, "ENTER:")
        _operator(m, "output %s 3330 %s" % (dasd, volser), "ENTER:")
        before = m.screen(OPERATOR).count("END OF RESTORE")
        m.type(OPERATOR, "restore all")
        _until(m, "END OF RESTORE", 600000000, seen = before)
    m.ipl(0x131)
    _until(m, "CHANGE TOD CLOCK", 50000000)
    _operator(m, "NO", "START ((COLD|WARM|CKPT|FORCE) (DRAIN))|(SHUTDOWN)")
    _operator(m, "COLD", "DMKCPI957I")
    _operator(m, "ENABLE ALL", "ENABLE ALL")
    return m.web_terminals(tn3270 = tn3270, state = state)
