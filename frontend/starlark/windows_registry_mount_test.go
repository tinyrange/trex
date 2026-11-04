package starlarkfrontend

import "testing"

func TestNativeRegistryStaticHiveMounts(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:registry.star", "registry_plugin")
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
load("@stdlib//windows/selfreg:transactions.star", "registry_transactions_plugin")
def exercise(arch):
    sd=windows.compile_sddl("O:SYG:SYD:(A;CI;KA;;;SY)")
    cls=binary.encode("ProfileΩ",encoding="utf16le")
    source=windows.hive(windows.hive_from_patches("NTUSER",[
        dict(key="/",name="Identity",type="REG_DWORD",value=42),
        dict(key="/Settings",name="Value",type="REG_DWORD",value=7),
    ],keys=[dict(key="/",security=sd,**{"class":cls}),dict(key="/Settings",security=sd)]))
    base=windows.hive(windows.hive_from_patches("DEFAULT",[
        dict(key="/",name="Identity",type="REG_DWORD",value=99),
        dict(key="/@users/Template",name="Hidden",type="REG_DWORD",value=99),
        dict(key="/@users/Template/HiddenChild",name="Hidden",type="REG_DWORD",value=99),
    ]))
    requests=[]
    def create(machine,request):
        requests.append(request)
        return {key:sd for key in request["missing_keys"]}
    mounts=[dict(hive="DEFAULT",key="/@users/Template",source=source),dict(hive="DEFAULT",key="/@users/Other",source=source)]
    r=registry_plugin(hives={"DEFAULT":base},mounts=mounts,on_create_key=create)
    # Caller record/list mutation cannot change the installed namespace.
    mounts[0]["key"]="/@users/Wrong"
    mounts.clear()
    k=kernel32_plugin()
    tx=registry_transactions_plugin(r,k)
    m=emulator.machine(architecture=arch,code=b"\xc3")
    def install(machine): pass
    m.use([r,k,tx,emulator.plugin(install,name="mount.observer",state=dict(requests=requests))])
    def call(name,args):
        result=m.call(m.resolve_export("ntdll.dll" if name.startswith("Nt") else "advapi32.dll",name=name),args=args)
        if result.reason!="return": fail(name+": "+result.detail)
        return result.value
    def wide(text): return m.allocate(value=binary.encode(text,encoding="utf16le",nul=True))
    out=m.allocate(value=b"G"*16)
    buf=m.allocate(value=b"G"*256)
    size=m.allocate(size=8)
    def native_open(path,status=0):
        raw=binary.encode(path,encoding="utf16le")
        name=m.allocate(size=16 if arch=="amd64" else 8)
        m.write_u16le(name,len(raw)); m.write_u16le(name+2,len(raw))
        m.write_pointer(name+(8 if arch=="amd64" else 4),m.allocate(value=raw))
        oa=m.allocate(size=48 if arch=="amd64" else 24)
        m.write_u32le(oa,48 if arch=="amd64" else 24)
        m.write_pointer(oa+(16 if arch=="amd64" else 8),name)
        m.write_u32le(oa+(24 if arch=="amd64" else 12),0x40)
        m.write(out,b"G"*16)
        if call("NtOpenKey",[out,0x2001f,oa])!=status: fail("native mount open: "+path)
        if m.read(out+m.pointer_size,16-m.pointer_size)!=b"G"*(16-m.pointer_size): fail("handle guard")
        if status and m.read(out,16)!=b"G"*16: fail("missing open changed output")
        return m.read_pointer(out) if not status else 0
    path=chr(92).join(["","REGISTRY","USER","tEmPlAtE"])
    handle=native_open(path)
    native_open(path+chr(92)+"HiddenChild",0xc0000034)
    native_open(path+"Sibling",0xc0000034)
    native_open(chr(92).join(["","REGISTRY","USER","Wrong"]),0xc0000034)
    if call("NtQueryKey",[handle,2,buf,256,size]): fail("mounted metadata")
    if m.read_u32le(buf+16)!=len(cls) or m.read(buf+44,len(cls))!=cls or m.read_u32le(buf+20)!=1: fail("source root metadata replaced by namespace parent")
    if m.read_u64le(buf)!=source.find([]).last_write_time: fail("source timestamp")
    if r.get_value("DEFAULT","/@users/template","Identity")!=42 or r.get_value("DEFAULT","/","Identity")!=99: fail("source isolation")
    if r.get_value("DEFAULT","/@users/template","Hidden")!=None: fail("underlying namespace leaked through mount")
    if r.effects()!=dict(keys=[],key_deletions=[],values=[],value_deletions=[]): fail("mount reported writes")
    # Native writes to one mount never mutate the immutable source or its sibling.
    data=m.allocate(value=binary.u32le(84))
    if call("RegSetValueExW",[handle,wide("Identity"),0,4,data,4]): fail("mounted write")
    if r.get_value("DEFAULT","/@users/template","Identity")!=84 or r.get_value("DEFAULT","/@users/Other","Identity")!=42 or source.find([]).values["Identity"]!=42: fail("write isolation")
    if call("RegCreateKeyExW",[handle,wide("New"),0,0,0,0x2001f,0,out,0]): fail("mounted create")
    if requests[-1]["parent_security"]!=sd or requests[-1]["parent_key"].lower()!="/@users/template": fail("mount source parent security: "+str(requests[-1])+" expected "+str(sd))
    # Transaction forks retain mount sources but not uncommitted child changes.
    if call("NtCreateTransaction",[out,0x1f003f,0,0,0,1,0,0,0,0]): fail("begin")
    owner=m.read_pointer(out)
    result=m.call(m.resolve_export("advapi32.dll",name="RegOpenKeyTransactedW"),args=[handle,wide("Settings"),0,0x2001f,out,owner,0])
    if result.reason!="return" or result.value: fail("mounted transaction open")
    private=m.read_pointer(out)
    if call("RegSetValueExW",[private,wide("Value"),0,4,data,4]): fail("mounted transaction write")
    if r.get_value("DEFAULT","/@users/template/Settings","Value")!=7: fail("private write escaped")
    if call("NtCommitTransaction",[owner,1]): fail("commit")
    if r.get_value("DEFAULT","/@users/template/Settings","Value")!=84 or source.find("/Settings").values["Value"]!=7: fail("commit/source isolation")
    # A descendant may be removed; an entire static mount or ancestor cannot.
    if call("RegDeleteKeyW",[handle,wide("Settings")]): fail("mounted descendant deletion")
    native_open(path+chr(92)+"Settings",0xc0000034)
    before=r.effects()
    users=native_open(chr(92).join(["","REGISTRY","USER"]))
    for key,subkey in [(users,"Template"),(0x80000003,"")]:
        result=m.call(m.resolve_export("advapi32.dll",name="RegDeleteTreeW"),args=[key,wide(subkey)])
        if result.reason!="plugin" or "static hive mount" not in result.detail or r.effects()!=before: fail("mount boundary deletion was not atomic: "+str(result))
    r.reset()
    handle=native_open(path)
    if r.get_value("DEFAULT","/@users/template/Settings","Value")!=7 or r.get_value("DEFAULT","/@users/template","Identity")!=42 or r.effects()!=dict(keys=[],key_deletions=[],values=[],value_deletions=[]): fail("reset lost mounted source")
exercise("x86")
exercise("amd64")
`)
}
