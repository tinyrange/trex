package starlarkfrontend

import "testing"

func TestRegistryDuplicateHandleLifetime(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:registry.star", "registry_plugin", "registry_handles_plugin")
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
load("@stdlib//windows/selfreg:transactions.star", "registry_transactions_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    r=registry_plugin(values=[dict(hive="SOFTWARE",key="/Dup",name="Value",type="REG_DWORD",value=7)])
    k=kernel32_plugin()
    tx=registry_transactions_plugin(r,k)
    m.use([r,k,registry_handles_plugin(r,k),tx])
    def call(module,name,args):
        result=m.call(m.resolve_export(module,name=name),args=args)
        if result.reason!="return": fail(name+": "+result.detail)
        return result.value
    def wide(text): return m.allocate(value=binary.encode(text,encoding="utf16le",nul=True))
    root=0xffffffff80000002 if arch=="amd64" else 0x80000002
    process=(1<<(8*m.pointer_size))-1
    out=m.allocate(value=b"G"*16)
    path=wide("Dup")
    name=wide("Value")
    value=m.allocate(size=4)
    size=m.allocate(value=binary.u32le(4))
    def open_key(access):
        if call("advapi32.dll","RegOpenKeyExW",[root,path,0,access,out]): fail("open")
        return m.read_pointer(out)
    def query(key,expected,status=0):
        m.write_u32le(size,4)
        if call("advapi32.dll","RegQueryValueExW",[key,name,0,0,value,size])!=status: fail("query status")
        if status==0 and m.read_u32le(value)!=expected: fail("query value")
    def duplicate(key,options=2):
        m.write(out,b"G"*16)
        # Desired access is ignored with DUPLICATE_SAME_ACCESS.
        if call("kernel32.dll","DuplicateHandle",[process,key,process,out,0xffffffff,0,options])!=1: fail("duplicate")
        if m.read(out+m.pointer_size,16-m.pointer_size)!=b"G"*(16-m.pointer_size): fail("output guard")
        result=m.read_pointer(out)
        if result==key: fail("same handle")
        return result
    ordinary=open_key(0x20019)
    copy=duplicate(ordinary)
    if call("advapi32.dll","RegCloseKey",[ordinary]): fail("close original")
    query(copy,7)
    if call("ntdll.dll","NtDeleteKey",[copy])!=0xc0000022: fail("duplicate elevated access")
    moved=duplicate(copy,3)
    query(copy,0,6)
    query(moved,7)
    if call("ntdll.dll","NtClose",[copy])!=0xc0000008: fail("closed source resurrected")
    # Bad handle must leave caller output untouched.
    m.write(out,b"G"*16)
    if call("kernel32.dll","DuplicateHandle",[process,copy,process,out,0,0,2])!=0 or m.read(out,16)!=b"G"*16: fail("bad duplicate output")
    if call("kernel32.dll","GetLastError",[])!=6: fail("bad handle status")
    # Unsupported inheritance/access modes stop before allocating or closing.
    count=r.state["next_handle"]
    result=m.call(m.resolve_export("kernel32.dll",name="DuplicateHandle"),args=[process,moved,process,out,0,1,3])
    if result.reason!="plugin" or r.state["next_handle"]!=count or m.read(out,16)!=b"G"*16: fail("unsupported mutation")
    query(moved,7)
    # Duplicates share transaction visibility, never the ordinary overlay.
    if call("ntdll.dll","NtCreateTransaction",[out,0x1f003f,0,0,0,1,0,0,0,0]): fail("begin")
    owner=m.read_pointer(out)
    if call("advapi32.dll","RegOpenKeyTransactedW",[root,path,0,0x2001f,out,owner,0]): fail("open tx")
    key=m.read_pointer(out)
    txcopy=duplicate(key,3)
    if call("advapi32.dll","RegCloseKey",[key])!=6: fail("tx close-source not closed")
    m.write_u32le(value,19)
    if call("advapi32.dll","RegSetValueExW",[txcopy,name,0,4,value,4]): fail("tx write")
    query(txcopy,19)
    query(moved,7)
    if call("ntdll.dll","NtCommitTransaction",[owner,1]): fail("commit")
    query(moved,19)
    if call("ntdll.dll","NtClose",[txcopy]): fail("close tx duplicate")
    if call("ntdll.dll","NtClose",[txcopy])!=0xc0000008: fail("double close tx duplicate")
    # Deleting and recreating a pathname does not retarget old duplicates.
    writable=open_key(0xf003f)
    old=duplicate(writable)
    if call("ntdll.dll","NtDeleteKey",[writable]): fail("delete")
    deletedcopy=duplicate(old)
    if call("advapi32.dll","RegCreateKeyExW",[root,path,0,0,0,0x2001f,0,out,0]): fail("recreate")
    for key in [writable,old,deletedcopy,moved]:
        query(key,0,1018)
        if call("ntdll.dll","NtClose",[key]): fail("close deleted")
exercise("x86")
exercise("amd64")
`)
}

func TestNativeRegistryDuplicateObject(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:registry.star", "registry_plugin", "registry_handles_plugin")
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
load("@stdlib//windows/selfreg:transactions.star", "registry_transactions_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    r=registry_plugin(values=[dict(hive="SOFTWARE",key="/Dup",name="Value",type="REG_DWORD",value=7)])
    k=kernel32_plugin()
    tx=registry_transactions_plugin(r,k)
    m.use([r,k,registry_handles_plugin(r,k),tx])
    def call(module,name,args):
        result=m.call(m.resolve_export(module,name=name),args=args)
        if result.reason!="return": fail(name+": "+result.detail)
        return result.value
    def wide(text): return m.allocate(value=binary.encode(text,encoding="utf16le",nul=True))
    process=(1<<(8*m.pointer_size))-1
    garbage=1<<32 if arch=="amd64" else 0
    out=m.allocate(value=b"G"*16)
    path=wide("Dup")
    root=0xffffffff80000002 if arch=="amd64" else 0x80000002
    if call("advapi32.dll","RegOpenKeyExW",[root,path,0,0x2011f,out]): fail("open")
    original=m.read_pointer(out)
    if r.state["handle_access"][original]!=0x2001f: fail("view selector leaked into grant")
    def duplicate(handle,access,options=0,api="NtDuplicateObject"):
        m.write(out,b"G"*16)
        if call("ntdll.dll",api,[process,handle,process,out,garbage|access,garbage,garbage|options]): fail("native duplicate")
        if m.read(out+m.pointer_size,16-m.pointer_size)!=b"G"*(16-m.pointer_size): fail("native output guard")
        return m.read_pointer(out)
    call("kernel32.dll","SetLastError",[91])
    reduced=duplicate(original,8)
    if k.state["last_error"]!=91 or r.state["handle_access"][reduced]!=8: fail("native status or access")
    # Enumeration-only duplicate must not gain query/write rights.
    text=m.allocate(value=binary.encode("Value",encoding="utf16le"))
    name=m.allocate(size=16)
    m.write_u16le(name,10); m.write_u16le(name+2,10)
    m.write_pointer(name+(8 if arch=="amd64" else 4),text)
    data=m.allocate(value=binary.u32le(19))
    needed=m.allocate(size=4)
    if call("ntdll.dll","NtQueryValueKey",[reduced,name,2,out,16,needed])!=0xc0000022: fail("query escalation")
    if call("ntdll.dll","NtSetValueKey",[reduced,name,0,4,data,4])!=0xc0000022: fail("write escalation")
    copied=duplicate(reduced,0xffffffff,2,api="ZwDuplicateObject")
    if r.state["handle_access"][copied]!=8: fail("same access ignored")
    moved=duplicate(copied,0,3)
    if r.state["handle_access"][moved]!=8 or call("ntdll.dll","NtClose",[copied])!=0xc0000008: fail("close source")
    m.write(out,b"G"*16)
    if call("ntdll.dll","NtDuplicateObject",[process,copied,process,out,0,0,0])!=0xc0000008 or m.read(out,16)!=b"G"*16: fail("bad handle output")
    before=r.state["next_handle"]
    for access,attrs,options in [(2,0,0),(0x80000000,0,0),(0,2,3),(0,0,4)]:
        result=m.call(m.resolve_export("ntdll.dll",name="NtDuplicateObject"),args=[process,reduced,process,out,access,attrs,options])
        if result.reason!="plugin" or r.state["next_handle"]!=before or m.read(out,16)!=b"G"*16 or r.state["handles"][reduced]==None: fail("unsupported mutation")
    # Duplication must preserve the exact transacted view and reduced rights.
    if call("ntdll.dll","NtCreateTransaction",[out,0x1f003f,0,0,0,1,0,0,0,0]): fail("begin")
    owner=m.read_pointer(out)
    if call("advapi32.dll","RegOpenKeyTransactedW",[root,path,0,0x2001f,out,owner,0]): fail("open tx")
    key=m.read_pointer(out)
    txcopy=duplicate(key,2,1)
    if call("ntdll.dll","NtSetValueKey",[txcopy,name,0,4,data,4]): fail("transacted duplicate write")
    if r.get_value("SOFTWARE","/Dup","Value")!=7: fail("escaped transaction")
    if call("ntdll.dll","NtCommitTransaction",[owner,1]): fail("commit")
    if r.get_value("SOFTWARE","/Dup","Value")!=19: fail("lost duplicate write")
    if call("ntdll.dll","NtClose",[txcopy]): fail("close transacted duplicate")
    for key in [original,reduced,moved]:
        if call("ntdll.dll","NtClose",[key]): fail("close key")
exercise("x86")
exercise("amd64")
`)
}
