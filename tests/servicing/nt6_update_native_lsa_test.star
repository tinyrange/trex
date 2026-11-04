"""Servicing LSA source parsing, native ABI and independent ownership controls."""
load("//tests:testing.star","case","equal","raises","suite")
load("@stdlib//windows/servicing:native_lsa.star","read_servicing_policy","servicing_lsa_plugin")
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
load("@stdlib//windows:security.star","sid")

def _string(text):
    data=binary.encode(text,encoding="utf16le")
    return binary.concat([binary.u16le(len(data)),binary.u16le(len(data)+2),binary.u32le(8),data,b"\x00\x00"]).bytes()

def _fixture(joined=False,changes={}):
    values=dict(PolAcDmN=_string("Machine😀"),PolAcDmS=sid(5,[21,11,22,33]),
        PolPrDmN=_string("DOMAIN" if joined else "WORKGROUP"),PolPrDmS=sid(5,[21,44,55,66]) if joined else b"",
        PolDnDDN=_string("domain.example") if joined else b"",PolDnTrN=_string("example") if joined else b"",PolDnDmG=b"G"*16 if joined else b"\x00"*16)
    values.update(changes)
    return windows.hive(windows.hive_from_patches("SECURITY",[dict(key="/Policy/"+k,name="",type=0,value=v) for k,v in values.items()]))

def test_policy_source_bounds():
    p=read_servicing_policy(_fixture())
    equal(p["account_name"],"Machine😀")
    equal(p["account_sid"],sid(5,[21,11,22,33]))
    equal(p["primary_sid"],b"")
    for name,data in [("PolAcDmN",b"x"),("PolAcDmN",binary.concat([binary.u16le(20),binary.u16le(20),binary.u32le(8),b"x"]).bytes()),("PolAcDmN",_string("a"+chr(0)+"b")),("PolAcDmS",binary.concat([b"\x01\xff",b"\x00"*6]).bytes()),("PolDnDmG",b"G"*15)]:
        equal(testing.attempt(read_servicing_policy,args=[_fixture(changes={name:data})]).ok,False)
    raises(servicing_lsa_plugin,args=[_fixture(),None],message="explicit query authority")

def _exercise(arch,joined):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    k=kernel32_plugin()
    lsa=servicing_lsa_plugin(_fixture(joined),True)
    m.use([k,lsa])
    p=m.pointer_size
    def call(name,args):
        result=m.call(m.resolve_export("advapi32.dll",name=name),args=args)
        equal(result.reason,"return")
        return result.value
    def text(at):
        size=m.read_u16le(at)
        equal(m.read_u16le(at+2),size+2)
        ptr=m.read_pointer(at+(8 if p==8 else 4))
        equal(m.read(ptr+size,2),b"\x00\x00")
        return binary.text(m.read(ptr,size),encoding="utf16le")
    attrs=m.allocate(size=48 if p==8 else 24)
    m.write_u32le(attrs,48 if p==8 else 24)
    if p==8: m.write(attrs+4,b"PAD!") # Padding is not an attribute.
    slot=m.allocate(value=b"G"*16)
    k.state["last_error"]=91
    equal(call("LsaOpenPolicy",[0,attrs,2,slot]),0xc0000022)
    equal(m.read(slot,16),b"G"*16)
    equal(call("LsaOpenPolicy",[0,attrs,0,slot]),0)
    denied=m.read_pointer(slot)
    m.write(slot,b"G"*16)
    equal(call("LsaQueryInformationPolicy",[denied,5,slot]),0xc0000022)
    equal(m.read(slot,16),b"G"*16)
    equal(call("LsaClose",[denied]),0)
    equal(call("LsaOpenPolicy",[0,attrs,1,slot]),0)
    handle=m.read_pointer(slot)
    equal(m.read(slot+p,16-p),b"G"*(16-p))
    equal(call("LsaQueryInformationPolicy",[handle,5,slot]),0)
    account=m.read_pointer(slot)
    equal(text(account),"Machine😀")
    string_size=16 if p==8 else 8
    equal(m.read(m.read_pointer(account+string_size),24),sid(5,[21,11,22,33]))
    equal(call("LsaQueryInformationPolicy",[handle,12,slot]),0)
    dns=m.read_pointer(slot)
    equal(text(dns),"DOMAIN" if joined else "WORKGROUP")
    equal(text(dns+string_size),"domain.example" if joined else "")
    equal(text(dns+2*string_size),"example" if joined else "")
    equal(m.read(dns+3*string_size,16),b"G"*16 if joined else b"\x00"*16)
    domain=m.read_pointer(dns+3*string_size+16)
    if joined: equal(m.read(domain,24),sid(5,[21,44,55,66]))
    else: equal(domain,0)
    equal(call("LsaClose",[handle]),0)
    equal(call("LsaClose",[handle]),0xc0000008)
    # Results outlive the policy handle and are freed independently.
    equal(text(account),"Machine😀")
    m.write(slot,b"G"*16)
    equal(call("LsaQueryInformationPolicy",[handle,5,slot]),0xc0000008)
    equal(m.read(slot,16),b"G"*16)
    equal(call("LsaFreeMemory",[slot]),0xc000000d)
    equal(call("LsaFreeMemory",[account]),0)
    equal(call("LsaFreeMemory",[account]),0xc000000d)
    equal(call("LsaFreeMemory",[dns]),0)
    equal(lsa.state["handles"],{})
    equal(lsa.state["buffers"],{})
    equal(k.state["last_error"],91)
    denied_lsa=servicing_lsa_plugin(_fixture(),False)
    m.use(denied_lsa)
    equal(call("LsaOpenPolicy",[0,attrs,1,slot]),0xc0000022)
    equal(m.read(slot,16),b"G"*16)

def test_native_policy_abi():
    for arch in ["x86","amd64"]:
        for joined in [False,True]: _exercise(arch,joined)

TEST_SUITE=suite("nt6/update-servicing-lsa",[
    case("source bounds",test_policy_source_bounds),
    case("ABI and ownership",test_native_policy_abi),
])
