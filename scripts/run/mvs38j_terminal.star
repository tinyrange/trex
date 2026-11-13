"""Runs MVS 3.8j (Turnkey 3) with its consoles in a web browser and,
optionally, on a tn3270 port.

The pinned public-domain Turnkey 3 media is cached once; the machine IPLs
mvsres at 148, NIP is answered CLPA, JES2 is cold started with FORMAT and
the master console is put in roll mode, exactly as the mvs38j smoke does.
Served: TSO terminals at 0C0-0C2 (log on with "LOGON IBMUSER"), the master
console at 010, the alternate console at 011, the 3215 at 009, the card
reader at 00C (paste a job deck to submit it), printers at 00E and 00F, the
punch at 00D and the hardware system console.

Usage: trex -serve 127.0.0.1:8380 scripts/run/mvs38j_terminal.star [cache=DIR] [tn3270=ADDRESS] [state=PATH]
With state=PATH the machine resumes from that checkpoint when it exists and
is saved there on Ctrl-C, SIGTERM or the page's Save button.
"""

load("//scripts/images:mvs38j_turnkey.star", "iso")
load("//scripts/inspect:mvs38j_lib.star", "machine")

CONSOLE = 0x010

def _log(m):
    return "\n".join(m.screens(CONSOLE))

def _until(m, check, budget, what, step = 20000000):
    spent = 0
    while spent < budget:
        m.run(instructions = step)
        spent += step
        if check():
            return
    fail("mvs38j: %s not seen\n%s" % (what, m.screen(CONSOLE)))

def _reply(m, text, expect, budget = 1000000000):
    m.run(instructions = 20000000)
    m.type(CONSOLE, text)
    m.key(CONSOLE, "ENTER")
    _until(m, lambda: expect in _log(m), budget, expect)

def main(args):
    cache, tn3270, state = "local/media-cache", "", ""
    for arg in args:
        if arg.startswith("cache="):
            cache = arg[len("cache="):]
        elif arg.startswith("tn3270="):
            tn3270 = arg[len("tn3270="):]
        elif arg.startswith("state="):
            state = arg[len("state="):]
        else:
            fail("usage: mvs38j_terminal.star [cache=DIR] [tn3270=ADDRESS] [state=PATH]")
    m = machine(iso(cache = cache))
    devices = [0x0C0, 0x0C1, 0x0C2, 0x010, 0x011, 0x009, 0x00C, 0x00E, 0x00F, 0x00D]
    if state and exists(state):
        print("resuming from " + state)
        m.restore(open(state))
        return m.web_terminals(devices = devices, tn3270 = tn3270, state = state)
    print("IPLing MVS 3.8j and cold starting JES2")
    m.ipl(0x148)
    _until(m, lambda: "IEA101A SPECIFY SYSTEM PARAMETERS" in m.screen(CONSOLE), 200000000, "IEA101A")
    _reply(m, "R 0,CLPA", "$HASP479")
    _reply(m, "R 00,Y", "$HASP085 JES2 TERMINATION COMPLETE")
    _reply(m, "S JES2,,,PARM='FORMAT,COLD,NOREQ'", "$HASP436")
    _reply(m, "R 01,Y", "IEE041I THE SYSTEM LOG IS NOW ACTIVE", budget = 2000000000)
    _reply(m, "K S,DEL=R", "IEE163I MODE= R")
    print("MVS is up; VTAM shows the TSO logon screen on 0C0 shortly")
    return m.web_terminals(devices = devices, tn3270 = tn3270, state = state)
