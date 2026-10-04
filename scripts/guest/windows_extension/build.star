"""Build the native Win16 endpoint entirely in memory."""

def compile_win16(trex_root = ".", windows3 = False):
    target = "windows3/8086" if windows3 else "windows/8086"
    source = directory()
    source.write("/go.mod", "module winext\n\ngo 1.25\n")
    for name in ["msdos.rtg", "bios_8086.rtg"]:
        source.write("/backends/" + name, open(trex_root + "/renvo/backends/" + name))
    source.write("/backends/win16.rtg", open(trex_root + "/scripts/guest/windows_extension/win16.rtg"))
    for name in ["win16.go", "win16.rtgasm", "manifest.go"]:
        source.write("/agent/" + name, open(trex_root + "/scripts/guest/windows_extension/" + name))
    for name in ["core.go", "protocol.go"]:
        source.write("/agent/" + name, open(trex_root + "/scripts/guest/dos_extension/" + name))
    source.write("/Makefile", "all:\n\trenvo -backend /backends/win16.rtg -t %s -arena-size 512 -o agent.exe ./agent\n" % target)
    result = renvo.make(source, target = target, output = "agent.exe")
    if not result.ok:
        fail(result.diagnostic)
    return result.binary
