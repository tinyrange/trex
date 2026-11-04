package starlarkfrontend

import "testing"

func TestNativeRegistryKeyInformation(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:registry.star", "registry_plugin", "registry_handles_plugin")
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    source=windows.hive(windows.hive_from_patches("SOFTWARE",[
        dict(key="/Meta",name="",type="REG_BINARY",value=b"abc"),
        dict(key="/Meta",name="V😀",type="REG_DWORD",value=9),
    ],keys=[{"key":"/Meta","class":binary.encode("cΩ",encoding="utf16le")},
            {"key":"/Meta/Long😀","class":binary.encode("AB😀",encoding="utf16le")},
            {"key":"/Meta/x"}]))
    r=registry_plugin(hives={"SOFTWARE":source})
    k=kernel32_plugin()
    m.use([r,k,registry_handles_plugin(r,k)])
    def call(name,args):
        result=m.call(m.resolve_export("ntdll.dll" if name.startswith("Nt") else "advapi32.dll",name=name),args=args)
        if result.reason!="return": fail(name+": "+result.detail)
        return result.value
    def wide(s): return m.allocate(value=binary.encode(s,encoding="utf16le",nul=True))
    out=m.allocate(size=8)
    buf=m.allocate(value=b"G"*96)
    size=m.allocate(value=b"G"*8)
    root=0xffffffff80000002 if arch=="amd64" else 0x80000002
    def open_key(access):
        if call("RegOpenKeyExW",[root,wide("Meta"),0,access,out]): fail("open")
        return m.read_pointer(out)
    key=open_key(1)
    hi=0xaaaaaaaa00000000 if arch=="amd64" else 0
    def query(handle,capacity,status,required=48,cls=2):
        m.write(buf,b"G"*96)
        m.write(size,b"G"*8)
        result=call("NtQueryKey",[handle,hi|cls,buf,hi|capacity,size])
        if result!=status: fail("status: "+hex(result))
        if m.read_u32le(size)!=required or m.read(size+4,4)!=b"G"*4: fail("result length")
    for n in [0,1,43]:
        query(key,n,0xc0000023)
        if m.read(buf,96)!=b"G"*96: fail("short header changed output")
    for n in [44,45,47,48,96]:
        query(key,n,0 if n>=48 else 0x80000005)
        expected=[0,44,4,2,12,8,2,6,4]
        if [m.read_u32le(buf+i) for i in range(8,44,4)]!=expected: fail("full metadata")
        used=min(n,48)
        if m.read(buf+44,used-44)!=source.find("/Meta").class_bytes[:used-44]: fail("class")
        if m.read(buf+used,96-used)!=b"G"*(96-used): fail("output guard")
    # Cached information remains its distinct 40-byte ABI (36 data bytes).
    query(key,40,0,40,4)
    if [m.read_u32le(buf+i) for i in range(8,36,4)]!=[0,2,12,2,6,4,8]: fail("cached metadata")
    # Query access is not implied by enumeration. Denial changes no output.
    readonly=open_key(8)
    m.write(buf,b"G"*96)
    m.write(size,b"G"*8)
    if call("NtQueryKey",[readonly,2,buf,96,size])!=0xc0000022: fail("query access")
    if m.read(buf,96)!=b"G"*96 or m.read(size,8)!=b"G"*8: fail("denied output")
    # Overlay edits are reflected, not stale source counts/maxima.
    if call("RegDeleteKeyW",[root,wide("Meta"+chr(92)+"Long😀")]): fail("delete child")
    if call("RegCreateKeyExW",[root,wide("Meta"+chr(92)+"new"),0,0,0,0x2001f,0,out,0]): fail("create child")
    query(key,96,0)
    if m.read_u32le(buf+20)!=2 or m.read_u32le(buf+24)!=6 or m.read_u32le(buf+28)!=0: fail("overlay metadata")
    # Truly classless keys report no class bytes and no synthetic string.
    new_key=m.read_pointer(out)
    query(new_key,96,0,44)
    if m.read_u32le(buf+12)!=0xffffffff or m.read_u32le(buf+16)!=0: fail("empty class")
    if m.read(buf+44,52)!=b"G"*52: fail("empty class guard")
    if call("NtClose",[key]): fail("close")
    m.write(size,b"G"*8)
    if call("NtQueryKey",[key,2,buf,96,size])!=0xc0000008 or m.read(size,8)!=b"G"*8: fail("invalid handle")
exercise("x86")
exercise("amd64")
`)
}
