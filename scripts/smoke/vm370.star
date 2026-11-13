"""VM/370 Release 6 installs from its DDR tapes and runs CMS on System/370.

Run: go run ./cmd/trex scripts/smoke/vm370.star OUT ESSENTIALS.tar.gz VMREL6.ddr.aws.bz2 CPR6L0.ddr.aws.bz2
The public-domain Release 6 starter system: the essentials tarball holds the
IPLable stand-alone DDR tape; the two DDR tapes are read in place through
bzip2 and AWS. Fresh machine: IPL DDR from tape 580, restore VMREL6 and
CPR6L0 onto newly initialized 3330s (131, 132), IPL CP from 131, cold start,
enable the 3277s, log on MAINT at 040, IPL CMS and list the S disk.
Proof: CMS answers QUERY SEARCH with the 190 S disk and LISTFILE lists CMS
modules from it. OUT.png is the 3277 screen; OUT.txt the operator console
and terminal transcript.
"""

load("//scripts/inspect:vm370_lib.star", "machine")

OPERATOR = 0x01F
TERMINAL = 0x040

def _until(m, dev, text, budget, step = 2000000, seen = 0):
    """Runs until text appears on the device more than seen times."""
    spent = 0
    r = None
    while spent < budget:
        r = m.run(instructions = step)
        spent += step
        if m.screen(dev).count(text) > seen:
            return
        if r.kind in ["disabled-wait", "check-stop", "stopped"]:
            break
    fail("vm370: %r not seen on %X (%s %s)\n%s" % (text, dev, r.kind, r.psw, m.screen(dev)))

def _operator(m, line, expect, budget = 200000000):
    seen = m.screen(OPERATOR).count(expect)
    m.type(OPERATOR, line)
    _until(m, OPERATOR, expect, budget, seen = seen)

def _terminal(m, line, expect, budget = 100000000):
    seen = m.screen(TERMINAL).count(expect)
    if line != None:
        m.type(TERMINAL, line)
    m.key(TERMINAL, "ENTER")
    _until(m, TERMINAL, expect, budget, seen = seen)

def main(args):
    if len(args) != 4:
        fail("usage: vm370.star OUT ESSENTIALS.tar.gz VMREL6.ddr.aws.bz2 CPR6L0.ddr.aws.bz2")
    out = args[0]
    m = machine(open(args[1]), open(args[2]), open(args[3]))

    # Stand-alone DDR restores both system volumes.
    m.ipl(0x580)
    _until(m, OPERATOR, "ENTER CARD READER ADDRESS OR CONTROL STATEMENTS", 20000000)
    for tape, dasd, volser in [("581", "131", "VMREL6"), ("582", "132", "CPR6L0")]:
        _operator(m, "input %s 3420" % tape, "ENTER:")
        _operator(m, "output %s 3330 %s" % (dasd, volser), "ENTER:")
        before = m.screen(OPERATOR).count("END OF RESTORE")
        m.type(OPERATOR, "restore all")
        _until(m, OPERATOR, "RESTORING " + volser, 20000000)
        for _ in range(100):
            if m.screen(OPERATOR).count("END OF RESTORE") > before:
                break
            m.run(instructions = 5000000)
        if m.screen(OPERATOR).count("END OF RESTORE") <= before or "DMKDDR7" in m.screen(OPERATOR):
            fail("vm370: restore of %s failed\n%s" % (volser, m.screen(OPERATOR)))

    # CP from the restored system residence volume.
    m.ipl(0x131)
    _until(m, OPERATOR, "CHANGE TOD CLOCK", 50000000)
    _operator(m, "NO", "START ((COLD|WARM|CKPT|FORCE) (DRAIN))|(SHUTDOWN)")
    _operator(m, "COLD", "DMKCPI957I")
    _operator(m, "ENABLE ALL", "ENABLE ALL")

    # A user on a 3277: the logo clears to CP READ.
    _until(m, TERMINAL, "VM/370 ONLINE", 20000000)
    _terminal(m, None, "CP READ")
    _terminal(m, "LOGON MAINT", "ENTER PASSWORD:")
    _terminal(m, "CPCMS", "LOGON AT")
    _terminal(m, "IPL 190", "CMS VERSION 6.0")
    _terminal(m, None, "R;")
    _terminal(m, "QUERY SEARCH", "R;")
    screen = m.screen(TERMINAL)
    if "190" not in screen or " S " not in screen:
        fail("vm370: QUERY SEARCH did not list the S disk\n" + screen)
    m.key(TERMINAL, "CLEAR")
    m.run(instructions = 5000000)

    # LISTFILE pages through the S disk; CLEAR continues past MORE....
    m.type(TERMINAL, "LISTFILE * MODULE S")
    m.key(TERMINAL, "ENTER")
    modules = []
    shot = None
    for _ in range(20):
        m.run(instructions = 10000000)
        screen = m.screen(TERMINAL)
        for line in screen.split("\n"):
            f = line.split()
            if len(f) == 3 and f[1] == "MODULE" and f[2] == "S2" and f[0] not in modules:
                modules.append(f[0])
        if shot == None:
            shot = m.screenshot(TERMINAL)
        if "R;" in screen:
            break
        if "MORE..." in screen or "HOLDING" in screen:
            m.key(TERMINAL, "CLEAR")
    for name in ["ACCESS", "COPYFILE", "DDR", "EDIT", "LISTFILE"]:
        if name not in modules:
            fail("vm370: LISTFILE did not list %s MODULE: %s" % (name, modules))

    write(out + ".png", shot)
    write(out + ".txt", "== operator 01F ==\n" + m.screen(OPERATOR) + "\n== LISTFILE * MODULE S ==\n" + "\n".join(modules) + "\n")
    print("works: VM/370 R6 installed from DDR tapes; CMS 6.0 lists %d modules on its S disk; virtual %s, %d instructions" % (len(modules), m.time(), m.instructions()))
