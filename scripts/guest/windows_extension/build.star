"""Build the native Win16 endpoint entirely in memory."""

def compile_win16(trex_root = ".", windows3 = False, computer_use = False):
    if computer_use and windows3:
        fail("computer-use callback currently targets Windows 1.01 only")
    target = "windows3/8086" if windows3 else "windows/8086"
    source = directory()
    source.write("/go.mod", "module winext\n\ngo 1.25\n")
    for name in ["msdos.rtg", "bios_8086.rtg"]:
        source.write("/backends/" + name, open(trex_root + "/renvo/backends/" + name))
    source.write("/backends/win16.rtg", open(trex_root + "/scripts/guest/windows_extension/win16.rtg"))
    for name in ["win16.rtgasm", "manifest.go"] + (["computer.go", "input.go"] if computer_use else []):
        source.write("/agent/" + name, open(trex_root + "/scripts/guest/windows_extension/" + name))
    native = open(trex_root + "/scripts/guest/windows_extension/win16.go").read()
    # Keep the original file endpoint's direct dispatch: its real-mode code
    # segment is already near 64 KiB, even a Go forwarding wrapper is costly.
    if not computer_use:
        native = native.replace("dispatchCall()", "dispatch()")
    source.write("/agent/win16.go", native)
    for name in ["core.go", "protocol.go"]:
        source.write("/agent/" + name, open(trex_root + "/scripts/guest/dos_extension/" + name))
    extra = " -tags computer_use" if computer_use else ""
    source.write("/Makefile", "all:\n\trenvo -backend /backends/win16.rtg -t %s -arena-size 512 -o agent.exe%s ./agent\n" % (target, extra))
    result = renvo.make(source, target = target, output = "agent.exe")
    if not result.ok:
        fail(result.diagnostic)
    return result.binary
