package starlarkfrontend

import "testing"

func TestCNGOwnedStreamingHashes(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:crypto.star", "bcrypt_hash_plugin")
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def exercise(architecture):
    m=emulator.machine(architecture=architecture,code=b"\xc3")
    kernel=kernel32_plugin()
    bcrypt=bcrypt_hash_plugin()
    m.use([kernel,bcrypt])
    create=m.resolve_export("bcrypt.dll",name="BCryptCreateHash")
    update=m.resolve_export("bcrypt.dll",name="BCryptHashData")
    finish=m.resolve_export("bcrypt.dll",name="BCryptFinishHash")
    destroy=m.resolve_export("bcrypt.dll",name="BCryptDestroyHash")
    get=m.resolve_export("bcrypt.dll",name="BCryptGetProperty")
    length=m.allocate(value=binary.encode("HashDigestLength",encoding="utf16le",nul=True))
    output=m.allocate(value=b"G"*64)
    required=m.allocate(value=b"R"*8)
    slot=m.allocate(value=b"H"*16)
    data=m.allocate(value=b"abc")
    padding=0xdeadbeef00000000 if architecture=="amd64" else 0
    kernel.state["last_error"]=71
    for algorithm,want in [(0x31,"a9993e364706816aba3e25717850c26c9cd0d89d"),(0x41,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]:
        size=len(want)//2
        result=m.call(get,args=[algorithm,length,0,0,required,0])
        if result.reason!="return" or result.value or m.read_u32le(required)!=4 or m.read(required+4,4)!=b"RRRR": fail("CNG property size query lost width or guard")
        result=m.call(get,args=[algorithm,length,output,3,required,0])
        if result.value!=0xc0000023 or m.read(output,64)!=b"G"*64: fail("short CNG property buffer was partially written")
        result=m.call(get,args=[algorithm,length,output,padding|4,required,padding])
        if result.value or m.read_u32le(output)!=size or m.read(output+4,4)!=b"GGGG": fail("CNG digest length differs from actual algorithm")
        result=m.call(create,args=[algorithm,slot,0,padding,0,padding,padding])
        if result.reason!="return" or result.value or m.read(slot+m.pointer_size,16-m.pointer_size)!=b"H"*(16-m.pointer_size): fail("CNG creation lost pointer width or ownership")
        handle=m.read_pointer(slot)
        if m.call(update,args=[handle,0,0,0]).value or m.call(update,args=[handle,data,1,0]).value or m.call(update,args=[handle,data+1,padding|2,padding]).value: fail("CNG streaming hash input failed")
        m.write(output,b"G"*64)
        if m.call(finish,args=[handle,output,size-1,0]).value!=0xc000000d or m.read(output,64)!=b"G"*64: fail("failed finish consumed hash or changed output")
        result=m.call(finish,args=[handle,output,padding|size,padding])
        if result.reason!="return" or result.value or binary.hex(m.read(output,size))!=want or m.read(output+size,4)!=b"GGGG": fail("CNG digest is not the incremental SHA result")
        if m.call(update,args=[handle,data,1,0]).value!=0xc0000008 or m.call(finish,args=[handle,output,size,0]).value!=0xc0000008: fail("non-reusable hash retained update authority after finish")
        if m.call(destroy,args=[handle]).value or m.call(destroy,args=[handle]).value!=0xc0000008: fail("CNG destroy lost exact ownership")
        m.write(output,b"G"*64)
    if bcrypt.state["hashes"] or bcrypt.state["objects"] or kernel.state["last_error"]!=71: fail("CNG leaked owned hash state or changed Win32 LastError")
exercise("x86")
exercise("amd64")
`)
}

func TestCNGCallerOwnedObjectBoundsAndLifetime(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:crypto.star", "bcrypt_hash_plugin")
def exercise(architecture):
    m=emulator.machine(architecture=architecture,code=b"\xc3")
    bcrypt=bcrypt_hash_plugin()
    m.use(bcrypt)
    create=m.resolve_export("bcrypt.dll",name="BCryptCreateHash")
    destroy=m.resolve_export("bcrypt.dll",name="BCryptDestroyHash")
    buffer=m.allocate(value=b"G"*400)
    slot=m.allocate(value=b"H"*16)
    result=m.call(create,args=[0x41,slot,buffer,255,0,0,0])
    if result.value!=0xc0000023 or bcrypt.state["hashes"] or m.read(buffer,400)!=b"G"*400 or m.read(slot,16)!=b"H"*16:
        fail("undersized opaque hash object was published or written")
    result=m.call(create,args=[0x41,slot,buffer,384,0,0,0])
    if result.reason!="return" or result.value or m.read(buffer+256,144)!=b"G"*144: fail("caller object overran its measured footprint")
    handle=m.read_pointer(slot)
    before=len(bcrypt.state["hashes"])
    result=m.call(create,args=[0x41,slot,buffer+128,256,0,0,0])
    if result.reason!="plugin" or len(bcrypt.state["hashes"])!=before or m.read_pointer(slot)!=handle:
        fail("overlapping live object was admitted or partially replaced")
    data=m.allocate(value=b"abc")
    if m.call(m.resolve_export("bcrypt.dll",name="BCryptHashData"),args=[handle,data,3,0]).value: fail("caller-buffer hash lost owned state")
    digest=m.allocate(value=b"D"*40)
    result=m.call(m.resolve_export("bcrypt.dll",name="BCryptFinishHash"),args=[handle,digest,32,0])
    if result.value or binary.hex(m.read(digest,32))!="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" or m.read(digest+32,8)!=b"D"*8: fail("caller-buffer digest differs from SHA256")
    if m.call(destroy,args=[handle]).value or bcrypt.state["objects"] or bcrypt.state["hashes"]: fail("destroy retained caller-object ownership")
    m.write(buffer,b"R"*400)
    if m.call(create,args=[0x41,slot,buffer,256,0,0,0]).value: fail("destroyed caller buffer could not be reused")
    if m.call(destroy,args=[m.read_pointer(slot)]).value: fail("reused object could not be destroyed")
    m.write(buffer,b"caller memory remains allocated")
exercise("x86")
exercise("amd64")
`)
}
