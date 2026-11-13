"""Debian lenny 31-bit Linux mounts its root file system from an emulated 3390.

Run: go run ./cmd/trex scripts/smoke/linux_s390_dasd.star [OUT]
The 3390 at 0200 is built natively in the Linux disk layout (LNX1 label,
twelve 4K blocks per track) with an ext2 file system in its partition. The
initramfs loads dasd_mod, dasd_eckd_mod and ext2 from the kernel package and
switches root to /dev/dasda1.
Proof: the root init reports /dev/dasda1 mounted on / with the identity file
written natively, and a line written by the guest to the disk reads back.
"""

load("//scripts/images:debian_s390.star", "dasd_image")

def _until(m, check, budget, step = 10000000):
    r = None
    for _ in range(budget // step):
        r = m.run(instructions = step)
        lines = m.messages()
        if check(lines):
            return lines
        text = "\n".join(lines)
        if "Kernel panic" in text or "TREX_FAIL" in text or r.kind in ["disabled-wait", "check-stop", "stopped"]:
            break
    fail("linux_s390_dasd: stopped (%s %s)\n%s" % (r.kind, r.psw, "\n".join(m.messages()[-40:])))

def main(args):
    built = dasd_image()
    m = emulator.s390(memory = 128 << 20, start = "2012-01-01T00:00:00Z")
    m.dasd(0x200, ldl = built["root"], cylinders = built["cylinders"])
    m.storage_load(built["images"])
    _until(m, lambda lines: "TREX_DASD_ROOT /dev/dasda1 / ext2" in lines, 1000000000)
    _until(m, lambda lines: "TREX_IDENTITY native-ext2-on-3390" in lines and lines[-1].startswith("/ #"), 50000000)
    m.command("echo written-$((40+2)) > /etc/proof; busybox sync; busybox cat /etc/proof")
    lines = _until(m, lambda lines: "written-42" in lines, 200000000)
    if len(m.dasd_errors(0x200).errors) != 0:
        fail("linux_s390_dasd: DASD errors %s" % m.dasd_errors(0x200).errors)
    if args:
        write(args[0] + ".png", m.screenshot())
        write(args[0] + ".txt", "\n".join(lines) + "\n")
    print("\n".join([l for l in lines if "dasd" in l.lower() or l.startswith("TREX")][-12:]))
    print("works: Debian lenny Linux %s mounts ext2 root from an emulated 3390 and writes to it; %d DASD writes" % (built["release"], m.dasd_errors(0x200).writes))
