package starlarkfrontend

import "testing"

func TestNativeClassicETWAliasesAndHandleWidths(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "event_log_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(event_log_plugin())
    def call(module,name,args):
        r=m.call(m.resolve_export(module,name=name),args=args)
        if r.reason!="return": fail(name+": "+r.detail)
        return r.value
    control=m.allocate(value=b"G"*16)
    out=m.allocate(value=b"X"*16)
    mof=m.allocate(value=binary.encode("provider.dll",encoding="utf16le",nul=True))
    if call("ntdll.dll","EtwRegisterTraceGuidsW",[0,0,control,0,0,mof,0,out])!=0: fail("native trace registration")
    handle=m.read_u64le(out)
    if not handle or m.read(out+8,8)!=b"X"*8: fail("REGHANDLE width/guard")
    args=[handle] if arch=="amd64" else [handle & 0xffffffff,handle>>32]
    for name in ["EtwGetTraceEnableFlags","EtwGetTraceEnableLevel"]:
        if call("ntdll.dll",name,args)!=0: fail("disabled provider enabled")
    if call("advapi32.dll","UnregisterTraceGuids",args)!=0: fail("aliases did not share provider ownership")
    if call("ntdll.dll","EtwUnregisterTraceGuids",args)!=6: fail("released provider admitted")
    if call("advapi32.dll","RegisterTraceGuidsA",[0,0,control,0,0,0,0,out])!=0: fail("ANSI trace registration")
    handle=m.read_u64le(out)
    args=[handle] if arch=="amd64" else [handle & 0xffffffff,handle>>32]
    if call("ntdll.dll","EtwUnregisterTraceGuids",args)!=0: fail("reverse alias ownership")
    before=m.read(out,16)
    if call("ntdll.dll","EtwRegisterTraceGuidsW",[0,0,control,65537,0,0,0,out])!=87 or m.read(out,16)!=before: fail("invalid registration changed output")
    # Modern provider calls also carry REGHANDLE in one x64 argument, two x86 words.
    if call("ntdll.dll","EtwEventRegister",[control,0,0,out])!=0: fail("EventRegister")
    handle=m.read_u64le(out)
    args=[handle] if arch=="amd64" else [handle & 0xffffffff,handle>>32]
    if call("ntdll.dll","EtwEventSetInformation",args+[2,0,0])!=0: fail("modern alias provider ownership")
    if call("ntdll.dll","EtwEventEnabled",args+[0])!=0: fail("disabled modern provider")
    if call("advapi32.dll","EventUnregister",args)!=0 or call("ntdll.dll","EtwEventUnregister",args)!=6: fail("EventUnregister native handle")
exercise("x86")
exercise("amd64")
`)
}
