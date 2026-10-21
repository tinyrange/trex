"""Build a native PE endpoint entirely in memory."""
def compile_pe(trex_root = ".", architecture = "386", early_nt = False):
    if architecture not in ["386", "amd64", "arm64"]:
        fail("unsupported Windows agent architecture " + architecture)
    source = directory()
    source.write("/go.mod", "module winext\n\ngo 1.25\n")
    for name in ["main.go", "manifest.go"]:
        source.write("/agent/" + name, open(trex_root + "/scripts/guest/windows_extension/win32/" + name))
    source.write("/agent/protocol.go", open(trex_root + "/scripts/guest/dos_extension/protocol.go"))
    target = "windows/" + architecture
    backend = ""
    if early_nt:
        if architecture != "386":
            fail("early NT requires a native 386 agent")
        for name in ["x86_32.rtg"]:
            source.write("/backends/" + name, open(trex_root + "/renvo/backend/definitions/" + name))
        source.write("/backends/nt31.rtg", open(trex_root + "/scripts/guest/windows_extension/nt31.rtg"))
        backend = "-backend /backends/nt31.rtg "
    source.write("/Makefile", "all:\n\trenvo %s-t %s -arena-size 1048576 -windows-gui -o agent.exe ./agent\n" % (backend, target))
    result = renvo.make(source, target = target, output = "agent.exe")
    if not result.ok:
        fail(result.diagnostic)
    return result.binary
