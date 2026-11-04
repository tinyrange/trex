package starlarkfrontend

import "testing"

func TestNativeProcessorInformation(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    k=kernel32_plugin(version={"processor_features":[2,6,8,10]})
    m.use(k)
    query=m.resolve_export("ntdll.dll",name="NtQuerySystemInformation")
    zw=m.resolve_export("ntdll.dll",name="ZwQuerySystemInformation")
    output=m.allocate(value=b"X"*80)
    length=m.allocate(size=4)
    k.state["last_error"]=123
    r=m.call(query,args=[1,output,11,length])
    if r.reason!="return" or r.value!=0xc0000004 or m.read_u32le(length)!=12 or m.read(output,80)!=b"X"*80: fail("processor sizing/atomicity")
    r=m.call(zw,args=[1,0,12,length])
    if r.reason!="return" or r.value!=0xc0000005: fail("processor NULL output")
    r=m.call(query,args=[1,output,12,0])
    if r.reason!="return" or r.value or m.read(output+12,68)!=b"X"*68: fail("processor guards/optional ReturnLength")
    if m.read_u16le(output)!=(9 if arch=="amd64" else 0) or m.read_u16le(output+2)!=6 or m.read_u16le(output+4)!=0 or m.read_u16le(output+6)!=1: fail("processor architecture/level/count")
    if m.read_u32le(output+8)!=0x12082: fail("PF indices confused with KF bits")
    win=m.allocate(size=48)
    r=m.call(m.resolve_export("kernel32.dll",name="GetNativeSystemInfo"),args=[win])
    if r.reason!="return" or m.read_u16le(win)!=m.read_u16le(output): fail("native/Win32 architecture disagreement")
    m.write(output,b"X"*80)
    size=64 if arch=="amd64" else 44
    r=m.call(query,args=[0,output,size-1,length])
    if r.reason!="return" or r.value!=0xc0000004 or m.read_u32le(length)!=size or m.read(output,80)!=b"X"*80: fail("basic sizing/atomicity: "+str([arch,r.reason,r.detail,m.read_u32le(length)]))
    r=m.call(zw,args=[0,output,size,length])
    if r.reason!="return" or r.value or m.read(output+size,80-size)!=b"X"*(80-size): fail("basic guard")
    start=32 if arch=="amd64" else 28
    if m.read_pointer(output+start)!=0x10000 or m.read_pointer(output+start+m.pointer_size)!=(0x7ffffffeffff if arch=="amd64" else 0x7ffeffff) or m.read_pointer(output+start+2*m.pointer_size)!=1: fail("basic pointer widths")
    if m.read(output+start+3*m.pointer_size,1)!=b"\x01" or k.state["last_error"]!=123: fail("basic count/native last error")
exercise("x86")
exercise("amd64")
`)
}
