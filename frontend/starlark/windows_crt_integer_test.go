package starlarkfrontend

import "testing"

func TestCRTWideInt64ConversionAndReturnABI(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def check(condition):
    if not condition:
        fail("_wtoi64 check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture, code=b"\xc3")
    machine.use(msvcrt_plugin())
    function = machine.resolve_export("msvcrt.dll", name="_wtoi64")
    errno = machine.call(machine.resolve_export("msvcrt.dll", name="_errno")).value
    for text, expected, error in [
        (" \t+4294967299tail", 4294967299, 55),
        ("-4294967297", -4294967297, 55),
        ("9223372036854775807", (1<<63)-1, 55),
        ("-9223372036854775808", -(1<<63), 55),
        ("999999999999999999999999", (1<<63)-1, 34),
        ("-999999999999999999999999", -(1<<63), 34),
        ("+invalid", 0, 55), ("0x10", 0, 55), ("", 0, 55),
        (None, 0, 22),
    ]:
        source = machine.allocate(value=binary.encode(text, encoding="utf16le", nul=True)) if text != None else 0
        machine.write(errno, binary.u32le(55))
        result = machine.call(function, args=[source])
        check(result.reason == "return")
        actual = result.value
        if machine.pointer_size == 4:
            actual |= machine.get_register("edx") << 32
        check(actual == expected & ((1<<64)-1))
        check(machine.read_u32le(errno) == error)
exercise("x86")
exercise("amd64")
`)
}
