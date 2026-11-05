"""Build the native Win16 endpoint entirely in memory."""

def compile_win16(trex_root = ".", windows3 = False, computer_use = False, display_agent = False, configuration_agent = False, resize_helper = False):
    if resize_helper:
        if computer_use or display_agent or configuration_agent:
            fail("resize_helper requires a separate executable")
        display_agent = True
    if computer_use and windows3:
        fail("computer-use callback currently targets Windows 1.01 only")
    if int(computer_use) + int(display_agent) + int(configuration_agent) > 1:
        fail("computer_use, display_agent and configuration_agent select separate native endpoints")
    if configuration_agent and not windows3:
        fail("configuration_agent requires the protected-mode Windows 3 executable format")
    target = "windows3/8086" if windows3 else "windows/8086"
    source = directory()
    source.write("/go.mod", "module winext\n\ngo 1.25\n")
    for name in ["msdos.rtg", "bios_8086.rtg"]:
        source.write("/backends/" + name, open(trex_root + "/renvo/backends/" + name))
    backend = open(trex_root + "/scripts/guest/windows_extension/win16.rtg").read()
    if resize_helper:
        # NE modules are identified by resident name, not their DOS filename.
        backend = backend.replace("TREXEXT", "TREXRES")
    source.write("/backends/win16.rtg", backend)
    for name in ["win16.rtgasm", "manifest.go", "display.go"] + (["computer.go", "input.go"] if computer_use else []) + (["displayagent.go", "display_resize.go"] if display_agent else []) + (["configuration.go"] if configuration_agent else []):
        source.write("/agent/" + name, open(trex_root + "/scripts/guest/windows_extension/" + name))
    native = open(trex_root + "/scripts/guest/windows_extension/win16.go").read()
    # Keep the original file endpoint's direct dispatch: its real-mode code
    # segment is already near 64 KiB, even a Go forwarding wrapper is costly.
    if not computer_use and not display_agent and not configuration_agent:
        native = native.replace("dispatchCall()", "dispatch()")
    if resize_helper:
        # The production helper has no serial transport dependency. The
        # observation endpoint never participates in applying a display mode.
        native = native[:native.index("func main() {")] + "func main() {\n\tsegment = dataSegment()\n\tfor !stopped {\n\t\tsegment = dataSegment()\n\t\tpump()\n\t\tpollDisplayResize()\n\t\tdisplayYield()\n\t}\n}\n"
    source.write("/agent/win16.go", native)
    for name in ["core.go", "protocol.go"]:
        source.write("/agent/" + name, open(trex_root + "/scripts/guest/dos_extension/" + name))
    extra = " -tags computer_use" if computer_use else (" -tags display_agent" if display_agent else (" -tags configuration_agent" if configuration_agent else ""))
    source.write("/Makefile", "all:\n\trenvo -backend /backends/win16.rtg -t %s -arena-size 512 -o agent.exe%s ./agent\n" % (target, extra))
    result = renvo.make(source, target = target, output = "agent.exe")
    if not result.ok:
        fail(result.diagnostic)
    return result.binary
