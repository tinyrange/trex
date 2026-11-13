"""Debian lenny 31-bit Linux boots on the native ESA/390 emulator to a shell.

Run: go run ./cmd/trex scripts/smoke/linux_s390.star [OUT]
Needs the pinned archive.debian.org packages; no QEMU, no extracted host files.
The kernel and a native-built BusyBox initramfs are placed in storage as the
service processor's load does; the console is the hardware system console.
Proof: init reports s390 and the kernel release, and a shell command's
computed output line (absent from its echo) appears. OUT.png and OUT.txt are
the console screenshot and transcript.
"""

load("//scripts/images:debian_s390.star", "image")

def _until(m, check, budget, step = 10000000):
    spent = 0
    r = None
    for _ in range(budget // step):
        r = m.run(instructions = step)
        lines = m.messages()
        if check(lines):
            return lines
        text = "\n".join(lines)
        if "Kernel panic" in text or "Oops" in text or r.kind in ["disabled-wait", "check-stop", "stopped"]:
            break
    fail("linux_s390: stopped (%s %s)\n%s" % (r.kind, r.psw, "\n".join(m.messages()[-40:])))

def main(args):
    built = image()
    m = emulator.s390(memory = 128 << 20, start = "2012-01-01T00:00:00Z")
    m.storage_load(built["images"])
    banner = "TREX_LINUX_READY s390 " + built["release"]
    _until(m, lambda lines: banner in lines, 400000000)
    _until(m, lambda lines: lines[-1] == "/ #", 50000000)
    m.command("echo TREX_$((6*7))_$(busybox uname -m)")
    lines = _until(m, lambda lines: "TREX_42_s390" in lines, 100000000)
    for line in lines:
        if "Oops" in line or "Segmentation fault" in line or "BUG" in line:
            fail("linux_s390: console reports " + line)
    if len(args) > 0:
        write(args[0] + ".png", m.screenshot())
        write(args[0] + ".txt", "\n".join(lines) + "\n")
    print("\n".join(lines[-8:]))
    print("works: Debian lenny Linux %s (31-bit) on ESA/390 runs a BusyBox shell; virtual %s, %d instructions" % (built["release"], m.time(), m.instructions()))
