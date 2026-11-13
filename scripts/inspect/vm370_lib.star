"""VM/370 Release 6 machine on emulator.s390 in System/370 mode.

The real I/O configuration follows DMKRIO of the Release 6 starter system:
3215 console at 01F, 3277 displays at 040-041, unit-record devices at
00C-00E, 3330s at 130-13F and 3420 tapes at 580-58F.
"""

def machine(essentials, vmrel6, cpr6l0):
    tar = archive.tar(archive.gzip(essentials))
    ddr = tar.find("/essentials/dmkddr.aws")
    if ddr == None:
        fail("vm370: essentials tarball has no dmkddr.aws")
    m = emulator.s390(memory = 2 << 20, architecture = "s370", start = "1985-08-30T12:00:00Z")
    m.console(0x01F, type = "3215")
    m.console(0x040)
    m.console(0x041)
    m.unit_record(0x00C, type = "2540R")
    m.unit_record(0x00D, type = "2540P")
    m.unit_record(0x00E, type = "1403")
    m.tape(0x580, ddr)
    m.tape(0x581, archive.bzip2(vmrel6))
    m.tape(0x582, archive.bzip2(cpr6l0))
    m.dasd(0x131, type = "3330", cylinders = 404, volser = "VMREL6")
    m.dasd(0x132, type = "3330", cylinders = 404, volser = "CPR6L0")
    return m
