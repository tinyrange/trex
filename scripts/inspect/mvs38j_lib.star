"""MVS 3.8j Turnkey 3 machine on emulator.s390 in System/370 mode.

Devices follow the Turnkey's Hercules configuration: 3215 at 009, 3270
consoles at 010 and 011, readers, punches and printers, and every system
volume at the address in its file name (the CKD image names its device type).
"""

load("//scripts/images:mvs38j_turnkey.star", "iso")

VOLUMES = ["mvsres.148", "smp001.149", "smp002.14a", "smp003.14b", "smp004.14c",
           "work00.140", "start1.150", "spool0.151", "hasp00.152",
           "page00.160", "page01.161", "page02.162", "work01.170", "work02.180",
           "work03.190", "mvscat.191", "pub000.240", "mvsdlb.248", "pub002.280",
           "sort01.131", "sort02.132", "sort03.133", "sort04.134", "sort05.135", "sort06.136"]

# The Turnkey's year-2000 changes display a clock year 19yy as 20yy (the
# 1985 clock shows as 2085). Earlier clock years are not used: the system
# then resets the clock.
def machine(fs = None, memory = 16 << 20, start = "1985-01-01T08:00:00Z"):
    if fs == None:
        fs = iso()
    m = emulator.s390(memory = memory, architecture = "s370", start = start)
    m.console(0x009, type = "3215")
    for dev in [0x010, 0x011, 0x0C0, 0x0C1, 0x0C2]:
        m.console(dev)
    m.unit_record(0x00C, type = "3505")
    m.unit_record(0x10C, type = "3505")
    m.unit_record(0x00D, type = "3525")
    m.unit_record(0x10D, type = "3525")
    m.unit_record(0x00E, type = "1403")
    m.unit_record(0x00F, type = "1403")
    m.unit_record(0x30E, type = "1403")
    for name in VOLUMES:
        m.dasd(int(name.split(".")[1], 16), fs.find("/dasd/" + name))
    return m
