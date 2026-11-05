package starlarkfrontend

import "testing"

func TestNativeRegistryTransactionIsolation(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:registry.star", "registry_plugin")
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
load("@stdlib//windows/selfreg:transactions.star", "registry_transactions_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    r=registry_plugin(values=[dict(hive="SOFTWARE",key="/Tx",name="Value",type="REG_DWORD",value=1)])
    k=kernel32_plugin()
    tx=registry_transactions_plugin(r,k)
    m.use([r,k,tx])
    def call(module,name,args):
        result=m.call(m.resolve_export(module,name=name),args=args)
        if result.reason!="return": fail(name+": "+result.detail)
        return result.value
    def wide(text): return m.allocate(value=binary.encode(text,encoding="utf16le",nul=True))
    root=0xffffffff80000002 if arch=="amd64" else 0x80000002
    garbage=0xdeadbeef00000000 if arch=="amd64" else 0
    output=m.allocate(value=b"X"*16)
    keyout=m.allocate(value=b"X"*16)
    path=wide("Tx")
    name=wide("Value")
    data=m.allocate(value=binary.u32le(2))
    size=m.allocate(value=binary.u32le(4))
    query=m.allocate(size=4)
    def begin():
        m.write(output,b"X"*16)
        if call("ntdll.dll","NtCreateTransaction",[output,0x1f003f,0,0,0,garbage|1,garbage,garbage,0,0]): fail("create transaction")
        if m.read(output+m.pointer_size,16-m.pointer_size)!=b"X"*(16-m.pointer_size): fail("transaction handle guard")
        return m.read_pointer(output)
    def open_tx(owner,path):
        m.write(keyout,b"X"*16)
        if call("api-ms-win-core-registry-l2-1-0.dll","RegOpenKeyTransactedW",[root,path,0,0x2001f,keyout,owner,0]): fail("open transacted key")
        if m.read(keyout+m.pointer_size,16-m.pointer_size)!=b"X"*(16-m.pointer_size): fail("key handle guard")
        return m.read_pointer(keyout)
    def set_value(key,value):
        m.write_u32le(data,value)
        if call("advapi32.dll","RegSetValueExW",[key,name,0,4,data,4]): fail("set value")
    def query_value(key,expected):
        m.write_u32le(size,4)
        if call("advapi32.dll","RegQueryValueExW",[key,name,0,0,query,size]) or m.read_u32le(query)!=expected: fail("query transaction visibility")
    if call("advapi32.dll","RegOpenKeyExW",[root,path,0,0x2001f,keyout]): fail("ordinary key")
    ordinary=m.read_pointer(keyout)
    owner=begin()
    key=open_tx(owner,path)
    set_value(key,2)
    query_value(key,2)
    query_value(ordinary,1)
    if r.patches() or r.get_value("SOFTWARE","/Tx","Value")!=1: fail("uncommitted effects escaped")
    newpath=wide("Tx\\New")
    if call("advapi32.dll","RegCreateKeyTransactedW",[root,newpath,0,0,0,0x2001f,0,keyout,0,owner,0]): fail("transaction create")
    newkey=m.read_pointer(keyout)
    if call("advapi32.dll","RegOpenKeyExW",[root,newpath,0,0x20019,keyout])!=2: fail("uncommitted key visible")
    if call("ntdll.dll","NtCommitTransaction",[owner,1]): fail("commit")
    query_value(ordinary,2)
    if call("advapi32.dll","RegOpenKeyExW",[root,newpath,0,0x20019,keyout]): fail("committed key missing")
    for handle in [key,newkey,owner]:
        if call("ntdll.dll","NtClose",[handle]): fail("close committed handle")
    if call("ntdll.dll","NtClose",[owner])!=0xc0000008: fail("double close")
    # A rollback never changes parent values or its reported effects.
    before=r.effects()
    owner=begin()
    key=open_tx(owner,path)
    set_value(key,3)
    if call("ntdll.dll","NtRollbackTransaction",[owner,1]): fail("rollback")
    query_value(ordinary,2)
    if r.effects()!=before: fail("rollback effects escaped")
    if call("advapi32.dll","RegCloseKey",[key]) or call("kernel32.dll","CloseHandle",[owner])!=1: fail("rollback close")
    owner=begin()
    key=open_tx(owner,path)
    set_value(key,4)
    if call("kernel32.dll","CloseHandle",[owner])!=1: fail("implicit rollback close")
    if r.effects()!=before: fail("close published an active transaction")
    # Do not overwrite an intervening ordinary writer at commit.
    owner=begin()
    key=open_tx(owner,path)
    set_value(key,5)
    set_value(ordinary,6)
    result=m.call(m.resolve_export("ntdll.dll",name="NtCommitTransaction"),args=[owner,1])
    if result.reason!="plugin" or "concurrent registry writes" not in result.detail: fail("unmodeled concurrent writer admitted")
    query_value(ordinary,6)
    if call("ntdll.dll","NtRollbackTransaction",[owner,1]): fail("rollback after rejected commit")
    # Unsupported options fail before allocating a handle or touching output.
    m.write(output,b"X"*16)
    count=len(tx.state["transactions"])
    result=m.call(m.resolve_export("ntdll.dll",name="NtCreateTransaction"),args=[output,0x1f003f,0,0,0,2,0,0,0,0])
    if result.reason!="plugin" or m.read(output,16)!=b"X"*16 or len(tx.state["transactions"])!=count: fail("unsupported transaction changed state")
exercise("x86")
exercise("amd64")
`)
}
