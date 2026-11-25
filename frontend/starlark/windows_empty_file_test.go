package starlarkfrontend

import "testing"

func TestCreatedEmptyFileCanBeReadBeforeFirstWrite(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def check(value):
    if not value:
        fail("empty file read check failed")
def exercise(architecture, disposition):
    machine=emulator.machine(architecture=architecture,code=b"\xc3")
    machine.use(kernel32_plugin())
    def call(name,args):
        result=machine.call(machine.resolve_export("kernel32.dll",name=name),args=args)
        check(result.reason=="return")
        return result.value
    name=machine.allocate(value=b"C:\\empty.dat\x00")
    handle=call("CreateFileA",[name,0xc0000000,3,0,disposition,0,0])
    check(handle != (1 << (machine.pointer_size*8))-1)
    out=machine.allocate(value=b"\xaa"*16)
    check(call("GetFileSizeEx",[handle,out])==1 and machine.read_u64le(out)==0)
    check(call("ReadFile",[handle,out,4,out+8,0])==1)
    check(machine.read_u32le(out+8)==0)
    check(call("WriteFile",[handle,out,4,out+8,0])==1)
    check(call("SetFilePointer",[handle,0,0,0])==0)
    check(call("ReadFile",[handle,out,8,out+8,0])==1)
    check(machine.read_u32le(out+8)==4)
exercise("x86",1)
exercise("x86",4)
exercise("amd64",1)
exercise("amd64",4)
`)
}
