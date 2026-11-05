package starlarkfrontend

import "testing"

func TestTargetAPISetLoaderHostAndProcedureIdentity(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin", "security_plugin")
def exercise(architecture):
    m=emulator.machine(architecture=architecture,code=b"\xc3")
    schema_data=binary.builder(capacity=512)
    schema_data.reserve(512)
    schema_data.patch_u32le(0,6)
    schema_data.patch_u32le(4,512)
    schema_data.patch_u32le(12,1)
    schema_data.patch_u32le(16,28)
    schema_data.patch_u32le(20,52)
    schema_data.patch_u32le(24,31)
    contract="api-ms-win-security-sddl-l1-1-0"
    encoded=binary.encode(contract,encoding="utf16le")
    schema_data.patch_u32le(32,80)
    schema_data.patch_u32le(36,len(encoded))
    schema_data.patch_u32le(40,len(encoded)-4)
    schema_data.patch_u32le(44,60)
    schema_data.patch_u32le(48,1)
    schema_data.patch_u32le(72,160)
    host=binary.encode("sechost.dll",encoding="utf16le")
    schema_data.patch_u32le(76,len(host))
    # A schema fixture includes the genuine hash index, not just entry names.
    hash=0
    hash_text=binary.view(binary.encode(contract.rsplit("-",1)[0],encoding="ascii"))
    for index in range(len(hash_text)):
        hash=(hash*31+hash_text[index])&0xffffffff
    schema_data.patch_u32le(52,hash)
    schema_data.patch_u32le(56,0)
    schema_data.patch(80,encoded)
    schema_data.patch(160,host)
    namespace=windows.api_set_namespace(schema_data.bytes())
    inspected=windows.api_set_namespace(file=binary.concat([schema_data.bytes()]))
    if inspected["version"] != namespace.version or inspected["flags"] != namespace.flags or inspected["hash_factor"] != namespace.hash_factor:
        fail("API-set inspection and loader headers disagree")
    if inspected["contracts"] != namespace.contracts or dict(inspected)["contracts"] != namespace.contracts:
        fail("API-set inspection mapping lost contracts")
    binding=inspected["contracts"][0]
    if binding["name"] != contract or binding["hosts"] != [{"flags":0,"alias":"","host":"sechost.dll"}]:
        fail("API-set inspection lost host binding")
    if inspected.resolve(contract) != "sechost.dll": fail("file keyword lost resolver")
    duplicate=testing.attempt(windows.api_set_namespace,args=[schema_data.bytes()],kwargs={"file":schema_data.bytes()})
    missing=testing.attempt(windows.api_set_namespace)
    if duplicate.ok or missing.ok: fail("API-set input ambiguity accepted")
    controls={"stop":True}
    def observe(machine,query):
        if query["kind"]=="procedure" and not query["found"] and controls["stop"]:
            fail("declared export needs an implementation before native failure")
    kernel=kernel32_plugin(virtual_modules=["kernel32.dll","sechost.dll"],api_set_namespace=namespace,on_loader_lookup=observe)
    m.use([kernel,security_plugin(kernel=kernel)])
    dll=m.allocate(value=binary.encode(contract+".dll",encoding="ascii",nul=True))
    result=m.call(m.resolve_export("kernel32.dll",name="LoadLibraryExA"),args=[dll,0,0])
    if result.reason!="return" or not result.value: fail("schema host could not be loaded")
    handle=result.value
    host_name=m.allocate(value=b"sechost.dll\x00")
    if m.call(m.resolve_export("kernel32.dll",name="GetModuleHandleA"),args=[host_name]).value!=handle: fail("contract fabricated a separate module identity")
    function=m.allocate(value=b"ConvertStringSecurityDescriptorToSecurityDescriptorW\x00")
    resolved=m.call(m.resolve_export("kernel32.dll",name="GetProcAddress"),args=[handle,function])
    if resolved.reason!="return" or not resolved.value or resolved.value!=m.resolve_export("sechost.dll",name="ConvertStringSecurityDescriptorToSecurityDescriptorW"): fail("schema host did not resolve the actual security implementation")
    sddl=m.allocate(value=binary.encode("O:SYG:SYD:P(A;;FA;;;SY)",encoding="utf16le",nul=True))
    out=m.allocate(value=b"G"*(m.pointer_size+4))
    length=m.allocate(value=b"G"*8)
    converted=m.call(resolved.value,args=[sddl,1,out,length])
    if converted.reason!="return" or converted.value!=1 or m.read(out+m.pointer_size,4)!=b"GGGG" or m.read(length+4,4)!=b"GGGG": fail("host SDDL conversion did not preserve output guards")
    if m.read(m.read_pointer(out),m.read_u32le(length))!=windows.compile_sddl("O:SYG:SYD:P(A;;FA;;;SY)"): fail("host conversion fabricated descriptor bytes")
    missing=m.allocate(value=b"LateCapability\x00")
    paused=m.call(m.resolve_export("kernel32.dll",name="GetProcAddress"),args=[handle,missing])
    if paused.reason!="plugin" or "declared export" not in paused.detail: fail("observer allowed native zero-return exception path")
    def capability(event): return 73
    m.provide_export(capability,module="sechost.dll",name="LateCapability",argc=0)
    controls["stop"]=False
    resumed=m.run()
    if resumed.reason!="return" or not resumed.value or m.call(resumed.value,args=[]).value!=73: fail("pending native lookup could not resume after capability installation")
    unknown=m.allocate(value=b"api-ms-win-not-in-schema-l1-1-0.dll\x00")
    if m.call(m.resolve_export("kernel32.dll",name="LoadLibraryA"),args=[unknown]).value: fail("namespace invented a host for an unknown contract")
exercise("x86")
exercise("amd64")
`)
}
