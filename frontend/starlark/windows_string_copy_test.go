package starlarkfrontend

import "testing"

func TestKernelBoundedStringCopyTerminates(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def check(condition):
    if not condition:
        fail("bounded string copy check failed")
def exercise(architecture, wide):
    machine = emulator.machine(architecture=architecture, code=b"\xc3")
    machine.use(kernel32_plugin())
    encoding = "utf16le" if wide else "ascii"
    unit = 2 if wide else 1
    function = machine.resolve_export("kernel32.dll", name="lstrcpynW" if wide else "lstrcpynA")
    source = machine.allocate(value=binary.encode("FlexModule%", encoding=encoding, nul=True))
    for count in [0, 1, 11, 12, 20]:
        output = machine.allocate(value=b"\xaa"*64)
        result = machine.call(function, args=[output, source, count])
        check(result.reason == "return" and result.value == output)
        expected = binary.encode("FlexModule%"[:count-1], encoding=encoding, nul=True) if count else b""
        check(machine.read(output, len(expected)) == expected)
        check(machine.read(output+len(expected), unit) == b"\xaa"*unit)
    if wide:
        # A capacity is measured in UTF-16 units even inside a surrogate pair.
        source = machine.allocate(value=b"\x3d\xd8\x00\xde\x00\x00")
        output = machine.allocate(value=b"\xaa"*8)
        machine.call(function, args=[output, source, 2])
        check(machine.read(output, 6) == b"\x3d\xd8\x00\x00\xaa\xaa")
exercise("x86", False)
exercise("x86", True)
exercise("amd64", False)
exercise("amd64", True)
`)
}
