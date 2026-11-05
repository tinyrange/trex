package starlarkfrontend

import "testing"

func TestUCRTFormattingAndExitTablesAcrossArchitectures(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "msvcrt_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    crt=msvcrt_plugin()
    m.use(crt)
    def call(module,name,args):
        r=m.call(m.resolve_export(module,name=name),args=args)
        if r.reason!="return":fail(name+": "+r.detail)
        return r.value
    runtime="api-ms-win-crt-runtime-l1-1-0.dll"
    table=m.allocate(size=3*m.pointer_size)
    if call(runtime,"_initialize_onexit_table",[table])!=0:fail("initialize")
    if call(runtime,"_register_onexit_function",[table,m.entry])!=0:fail("register")
    if call(runtime,"_execute_onexit_table",[table])!=0:fail("execute")
    if len([x for x in crt.state["actions"] if x.get("callback")==m.entry])!=1:fail("callback not run")
    text=m.allocate(value=binary.encode("Example",encoding="utf16le",nul=True))
    va=m.allocate(size=m.pointer_size)
    m.write_pointer(va,text)
    fmt=m.allocate(value=binary.encode("CLSID\\%s",encoding="utf16le",nul=True))
    buffer=m.allocate(value=b"Z"*80)
    def format(capacity,options=36):
        args=([options,0] if m.pointer_size==4 else [options])+[buffer,capacity,fmt,0,va]
        return call("api-ms-win-crt-stdio-l1-1-0.dll","__stdio_common_vswprintf",args)
    if format(30)!=13 or m.read_cstring(buffer,encoding="utf16le")!="CLSID\\Example":fail("wide format ABI")
    if format(5)!=0xffffffff or m.read_cstring(buffer,encoding="utf16le")!="CLSI":fail("truncation")
    if m.read(buffer+10,2)!=b"\\\x00":fail("truncation wrote outside capacity")
    m.write(buffer,b"ZZ")
    if format(0)!=0xffffffff or m.read(buffer,2)!=b"ZZ":fail("zero size")
    r=m.call(m.resolve_export("api-ms-win-crt-stdio-l1-1-0.dll",name="__stdio_common_vswprintf"),args=([0,0] if m.pointer_size==4 else [0])+[buffer,5,fmt,0,va])
    if r.reason!="plugin" or "unsupported UCRT" not in r.detail:fail("unsupported option accepted")
exercise("x86")
exercise("amd64")
`)
}
