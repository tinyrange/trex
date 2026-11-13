"""Runs 31-bit Debian lenny Linux on the native ESA/390 emulator with its
console in a web browser.

The kernel and BusyBox initramfs are built and loaded as the linux_s390
smoke does. The console is the hardware system console, served as a
line-mode console: type shell commands into it.

Usage: trex -serve 127.0.0.1:8390 scripts/run/linux_s390_terminal.star [state=PATH]
With state=PATH the machine resumes from that checkpoint when it exists and
is saved there on Ctrl-C, SIGTERM or the page's Save button.
"""

load("//scripts/images:debian_s390.star", "image")

def main(args):
    state = ""
    for arg in args:
        if arg.startswith("state="):
            state = arg[len("state="):]
        else:
            fail("usage: linux_s390_terminal.star [state=PATH]")
    m = emulator.s390(memory = 128 << 20, start = "2012-01-01T00:00:00Z")
    if state and exists(state):
        print("resuming from " + state)
        m.restore(open(state))
    else:
        print("loading the Debian lenny kernel and initramfs")
        built = image()
        m.storage_load(built["images"])
    return m.web_terminals(state = state)
