package starlarkfrontend

import "testing"

func TestCRTLocaleDataAndAccessorsShareStorage(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin", "msvcrt_plugin")
def check(condition):
    if not condition:
        fail("CRT locale data check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture, code=b"\xc3")
    machine.use([kernel32_plugin(), msvcrt_plugin()])
    def call(module, name, args=[]):
        result = machine.call(machine.resolve_export(module, name=name), args=args)
        check(result.reason == "return")
        return result.value
    for name in ["__setlc_active", "__unguarded_readlc_active"]:
        address = machine.resolve_export("msvcrt.dll", name=name)
        accessor = "_" + name + ("_add_func" if "unguarded" in name else "_func")
        check(call("msvcrt.dll", accessor) == (0 if name == "__setlc_active" else address))
        check(machine.read_u32le(address) == 0)
        check(call("kernel32.dll", "InterlockedIncrement", [address]) == 1)
        check(call("msvcrt.dll", accessor) == (1 if name == "__setlc_active" else address))
        check(machine.read_u32le(address) == 1)
    for name in ["__lc_codepage", "__lc_collate_cp"]:
        address = machine.resolve_export("msvcrt.dll", name=name)
        check(machine.read_u32le(address) == 1252)
        machine.write(address, binary.u32le(932))
        check(call("msvcrt.dll", "_" + name + "_func") == 932)
    handles = machine.resolve_export("msvcrt.dll", name="__lc_handle")
    check(call("msvcrt.dll", "___lc_handle_func") == handles)
    machine.write(handles+4, binary.u32le(0x409))
    check(machine.read_u32le(call("msvcrt.dll", "___lc_handle_func")+4) == 0x409)
exercise("x86")
exercise("amd64")
`)
}
