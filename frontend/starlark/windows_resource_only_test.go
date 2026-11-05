package starlarkfrontend

import "testing"

func TestWindowsResourceOnlyCrossArchitecture(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin", "resource_plugin", "user32_plugin")
# An executable entry that would trap must never run for a resource-only load.
base=binary.concat([windows.pe32_executable(b"\xcc", {"entry":0}, [])])
def string_block():
    block=binary.builder()
    for index in range(16):
        text={3:"Resource snowman ☃",4:"A😀B"}.get(index,"")
        encoded=binary.encode(text,encoding="utf16le")
        block.u16le(len(encoded)//2)
        block.append(encoded)
    return block
block=string_block()
image=windows.pe(base).with_resources([dict(type="#6",name="#1",lang="#1033",data=block.bytes())])
def exercise(architecture):
    m=emulator.machine(architecture=architecture,code=b"\xc3")
    kernel=kernel32_plugin(files={"C:/Windows/en-US/test.dll.mui":image})
    m.use(kernel)
    m.use(resource_plugin(base,kernel=kernel))
    m.use(user32_plugin(base,kernel=kernel))
    def call(module,name,args):
        result=m.call(m.resolve_export(module,name=name),args=args)
        if result.reason!="return": fail(name+": "+result.reason+" "+result.detail)
        return result.value
    name=m.allocate(value=binary.encode("C:/Windows/en-US/test.dll.mui",encoding="utf16le",nul=True))
    before_modules=len(m.modules)
    handle=call("kernel32.dll","LoadLibraryExW",[name,0,0x20])
    if not handle or not handle&2 or len(m.modules)!=before_modules: fail("resource load used executable loader")
    if call("kernel32.dll","LoadLibraryExW",[name,0,0x20])!=handle: fail("resource handle not retained")
    out=m.allocate(value=b"G"*128)
    count=call("api-ms-win-core-libraryloader-l1-1-0.dll","LoadStringW",[handle,3,out,64])
    if count!=18 or m.read_cstring(out,encoding="utf16le")!="Resource snowman ☃": fail("cross-ISA LoadString failed: "+str((architecture,count,m.read(out,48),kernel.state["resource_modules"])))
    m.write(out,b"G"*128)
    if call("user32.dll","LoadStringW",[handle,4,out,3])!=2 or m.read(out,8)!=b"A\x00=\xd8\x00\x00GG":
        fail("LoadStringW did not truncate in WCHAR units at surrogate boundary")
    resource=call("kernel32.dll","FindResourceW",[handle,1,6])
    if not resource or call("kernel32.dll","SizeofResource",[handle,resource])!=len(block.bytes()): fail("FindResource did not bind resource-only handle")
    if call("kernel32.dll","GetModuleHandleW",[name])!=0: fail("resource-only module leaked into executable inventory")
    if call("kernel32.dll","FreeLibrary",[handle])!=1: fail("resource release failed")
    if call("user32.dll","LoadStringW",[handle,3,out,64])!=18: fail("first release invalidated retained handle")
    if call("kernel32.dll","FreeLibrary",[handle])!=1: fail("final resource release failed")
    if call("user32.dll","LoadStringW",[handle,3,out,64])!=0: fail("unloaded string table remained visible")
    if call("kernel32.dll","FindResourceW",[handle,1,6])!=0: fail("unloaded resources remained visible")
    if call("kernel32.dll","FreeLibrary",[handle])!=0: fail("double resource release succeeded")
    missing=m.allocate(value=binary.encode("C:/absent/test.dll.mui",encoding="utf16le",nul=True))
    if call("kernel32.dll","LoadLibraryExW",[missing,0,0x20])!=0: fail("resource path incorrectly reduced to basename")
exercise("x86")
exercise("amd64")
`)
}
