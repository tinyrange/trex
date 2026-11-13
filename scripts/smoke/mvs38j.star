"""MVS 3.8j (Turnkey 3) IPLs on System/370 and runs a batch job.

Run: go run ./cmd/trex scripts/smoke/mvs38j.star OUT [cache=local/media-cache]
The pinned public-domain Turnkey 3 media is cached once (512 MB) and its
compressed CKD volumes are read in place from the ISO. Fresh machine: IPL
mvsres at 148, reply CLPA to NIP on the 3270 master console at 010, JES2 is
cold started with FORMAT, the console is put in roll mode, and an IEBGENER job is submitted through the card
reader at 00C. Then IBMUSER logs on to TSO at the local 3277 at 0C0 and
runs TIME.
Proof: JES2 reports the job started and ended, and the line the job copied
from its SYSIN appears in the printed SYSOUT on 00E, and TSO answers TIME with its CPU and session times. OUT.png is
the master console, OUT-tso.png the TSO terminal; OUT.txt the console log and printed job output.
"""

load("//scripts/images:mvs38j_turnkey.star", "iso")
load("//scripts/inspect:mvs38j_lib.star", "machine")

CONSOLE = 0x010
TERMINAL = 0x0C0
READER = 0x00C
PRINTER = 0x00E
PROOF = "HELLO FROM MVS 3.8J ON TREX"

JOB = [
    "//HELLO    JOB  CLASS=A,MSGCLASS=A",
    "//STEP1    EXEC PGM=IEBGENER",
    "//SYSPRINT DD   SYSOUT=A",
    "//SYSIN    DD   DUMMY",
    "//SYSUT2   DD   SYSOUT=A",
    "//SYSUT1   DD   *",
    PROOF,
    "/*",
    "//",
]

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
    # Each expected message is issued once, in response to this reply.
    # Let the console program finish preparing its input area first.
    m.run(instructions = 20000000)
    m.type(CONSOLE, text)
    m.key(CONSOLE, "ENTER")
    _until(m, lambda: expect in _log(m), budget, expect)

def main(args):
    if len(args) < 1:
        fail("usage: mvs38j.star OUT [cache=DIR]")
    out = args[0]
    cache = "local/media-cache"
    for a in args[1:]:
        if a.startswith("cache="):
            cache = a[len("cache="):]
    m = machine(iso(cache = cache))
    m.ipl(0x148)
    _until(m, lambda: "IEA101A SPECIFY SYSTEM PARAMETERS" in m.screen(CONSOLE), 200000000, "IEA101A")
    _reply(m, "R 0,CLPA", "$HASP479")
    # A fresh checkpoint: JES2 cannot warm start, so it is cold started and
    # its spool and checkpoint are formatted.
    _reply(m, "R 00,Y", "$HASP085 JES2 TERMINATION COMPLETE")
    _reply(m, "S JES2,,,PARM='FORMAT,COLD,NOREQ'", "$HASP436")
    _reply(m, "R 01,Y", "IEE041I THE SYSTEM LOG IS NOW ACTIVE", budget = 2000000000)
    # Roll mode lets held messages scroll off the full message area.
    _reply(m, "K S,DEL=R", "IEE163I MODE= R")

    m.cards(READER, JOB)
    _until(m, lambda: PROOF in "\n".join(m.output(PRINTER)), 30000000000, "printed job output", step = 200000000)
    _until(m, lambda: "$HASP395 HELLO" in _log(m), 30000000000, "$HASP395 HELLO ENDED", step = 200000000)

    # TSO: VTAM shows its logon screen on the local 3277 once it is up.
    _until(m, lambda: "Logon ===>" in m.screen(TERMINAL), 30000000000, "VTAM logon screen", step = 200000000)
    m.type(TERMINAL, "LOGON IBMUSER")
    m.key(TERMINAL, "ENTER")
    _until(m, lambda: "READY" in m.screen(TERMINAL), 5000000000, "TSO READY", step = 50000000)
    m.type(TERMINAL, "TIME")
    m.key(TERMINAL, "ENTER")
    _until(m, lambda: "CPU-" in m.screen(TERMINAL), 2000000000, "TSO TIME output", step = 50000000)
    tso = m.screen(TERMINAL)
    if "IBMUSER LOGON IN PROGRESS" not in tso:
        fail("mvs38j: no TSO logon\n" + tso)

    log = _log(m)
    printed = [l for l in m.output(PRINTER) if "HELLO" in l]
    write(out + ".png", m.screenshot(CONSOLE))
    write(out + "-tso.png", m.screenshot(TERMINAL))
    write(out + ".txt", "== master console 010 ==\n" + log + "\n== printer 00E (HELLO lines) ==\n" + "\n".join(printed) + "\n== TSO 0C0 ==\n" + tso + "\n")
    for line in log.split("\n"):
        if "HASP373 HELLO" in line or "HASP395 HELLO" in line:
            print(line.strip())
    for line in tso.split("\n"):
        if "CPU-" in line:
            print(line.strip())
    print("works: MVS 3.8j IPLed, JES2 cold started, job HELLO ran and IBMUSER logged on to TSO; virtual %s, %d instructions" % (m.time(), m.instructions()))
