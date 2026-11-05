package starlarkfrontend

import (
	"encoding/binary"
	"go.starlark.net/starlark"
	"testing"
)

func TestPCToImageUsesMappedExtent(t *testing.T) {
	// Minimal PE32+ with a 4 KiB header/section gap and one executable section.
	image := make([]byte, 0x400)
	put16 := func(o int, v uint16) { binary.LittleEndian.PutUint16(image[o:], v) }
	put32 := func(o int, v uint32) { binary.LittleEndian.PutUint32(image[o:], v) }
	copy(image, "MZ")
	put32(0x3c, 0x80)
	copy(image[0x80:], "PE\x00\x00")
	put16(0x84, 0x8664)
	put16(0x86, 1)
	put16(0x94, 0xf0)
	put16(0x96, 0x22)
	o := 0x98
	put16(o, 0x20b)
	put32(o+16, 0x1000)
	binary.LittleEndian.PutUint64(image[o+24:], 0x140000000)
	put32(o+32, 0x1000)
	put32(o+36, 0x200)
	put32(o+56, 0x2000)
	put32(o+60, 0x200)
	put32(o+108, 16)
	s := o + 0xf0
	copy(image[s:], ".text")
	put32(s+8, 1)
	put32(s+12, 0x1000)
	put32(s+16, 0x200)
	put32(s+20, 0x200)
	put32(s+36, 0x60000020)
	image[0x200] = 0xc3
	for _, input := range []starlark.Bytes{relocatablePE32TestImage(t, 0x200000), starlark.Bytes(image)} {
		thread, globals, err := newStarlarkRuntime("-")
		if err != nil {
			t.Fatal(err)
		}
		globals["image"] = input
		_, err = starlark.ExecFile(thread, "pc-image.star", `
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin","environment_plugin")
load("@stdlib//windows/emulation:abi.star","process_layout")
def check(ok):
    if not ok:
        fail("PC-to-image extent/ABI")
m=emulator.machine(image=image,image_name="native.exe")
env=environment_plugin(module_paths={"native.exe":"C:"+chr(92)+"Native.exe"})
m.use([kernel32_plugin(),env])
check(m.pointer_size!=8 or (m.get_register("cs")==0x33 and m.get_register("ss")==0x2b))
image_record=[item for item in m.modules if item.primary][0]
base=image_record.base
size=image_record.image_size
check(size>0)
peb=env.state["peb"]
p=process_layout(m.pointer_size)["peb"]
check(m.read_pointer(peb+p["ImageBaseAddress"])==base)
ldr=m.read_pointer(peb+p["Ldr"])
head=ldr+(0x10 if m.pointer_size==8 else 0x0c)
entry=m.read_pointer(head)
check(entry!=head and m.read_pointer(entry)==head and m.read_pointer(entry+m.pointer_size)==head)
check(m.read_pointer(entry+6*m.pointer_size)==base)
names=0x48 if m.pointer_size==8 else 0x24
check(m.read_cstring(m.read_pointer(entry+names+m.pointer_size),encoding="utf16le")=="C:"+chr(92)+"Native.exe")
check(m.read_cstring(m.read_pointer(entry+names+3*m.pointer_size),encoding="utf16le")=="Native.exe")
# Append a real mapped image and ensure all loader links retain their identity.
late=binary.builder()
late.append(image)
optional=binary.read_u32le(image,0x3c)+24
patch=late.patch_u64le if m.pointer_size==8 else late.patch_u32le
patch(optional+(24 if m.pointer_size==8 else 28),0x200000000 if m.pointer_size==8 else 0x600000)
second=m.load_module(image=late.file(),name="late.dll")
env.state["refresh_modules"](m)
check(m.read_pointer(head)==entry)
next_entry=m.read_pointer(entry)
check(next_entry!=head and m.read_pointer(next_entry)==head)
check(m.read_pointer(next_entry+m.pointer_size)==entry and m.read_pointer(head+m.pointer_size)==next_entry)
check(m.read_pointer(next_entry+6*m.pointer_size)==second.base)
check(m.read_pointer(peb+p["ImageBaseAddress"])==base)
# The modeled prefix is not the whole PEB. Late process fields must remain
# in its allocation, never alias growing loader records or later heap data.
peb_mapping=[item for item in m.mappings if item.start==peb][0]
shim_offset=0x2d8 if m.pointer_size==8 else 0x1e8
check(peb_mapping.size>=shim_offset+m.pointer_size)
poison=m.allocate(value=b"Z"*4096)
check(m.read_pointer(peb+shim_offset)==0)
check(m.read(peb+0x100,shim_offset+m.pointer_size-0x100)==b"\x00"*(shim_offset+m.pointer_size-0x100))
out=m.allocate(value=b"\xaa"*(m.pointer_size+4))
heap=m.allocate(size=64)
api=m.resolve_export("ntdll.dll",name="RtlPcToFileHeader")
module_api=m.resolve_export("kernel32.dll",name="GetModuleHandleExW")
def verify():
    for address,want in [(base,base),(base+size-1,base),(base-1,0),(base+size,0),(heap,0)]:
        r=m.call(api,args=[address,out])
        check(r.reason=="return" and r.value==want)
        check(m.read_pointer(out)==want)
        check(m.read(out+m.pointer_size,4)==b"\xaa"*4)
        r=m.call(module_api,args=[6,address,out])
        check(r.reason=="return" and r.value==(1 if want else 0))
verify()
def verify_image_queries():
    image_query=m.resolve_export("ntdll.dll",name="NtQueryVirtualMemory")
    query_size=24 if m.pointer_size==8 else 12
    query_out=m.allocate(value=b"\xaa"*(query_size+8))
    query_length=m.allocate(size=m.pointer_size)
    process=(1<<(8*m.pointer_size))-1
    r=m.call(image_query,args=[process,base+size-1,6,query_out,query_size-1,query_length])
    check(r.reason=="return" and r.value==0xc0000004 and m.read_pointer(query_length)==query_size)
    check(m.read(query_out,query_size+8)==b"\xaa"*(query_size+8))
    r=m.call(image_query,args=[process,base+size-1,6,query_out,query_size,query_length])
    check(r.reason=="return" and r.value==0)
    check(m.read_pointer(query_out)==base and m.read_pointer(query_out+m.pointer_size)==size)
    check(m.read_u32le(query_out+2*m.pointer_size)==0)
    check(m.read(query_out+query_size,8)==b"\xaa"*8)
    # Late modules use their own mapped extent, not the primary image's size.
    r=m.call(image_query,args=[process,second.base,6,query_out,query_size,0])
    check(r.reason=="return" and r.value==0 and m.read_pointer(query_out)==second.base)
    before=m.read(query_out,query_size+8)
    r=m.call(image_query,args=[123,base,6,query_out,query_size,query_length])
    check(r.reason=="return" and r.value==0xc0000008 and m.read(query_out,query_size+8)==before)
    # Unknown allocation/class must fail explicitly rather than forge image facts.
    def invalid_queries():
        for address,kind in [(heap,6),(base,0)]:
            r=m.call(image_query,args=[process,address,kind,query_out,query_size,query_length])
            check(r.reason!="return" and m.read(query_out,query_size+8)==before)
    invalid_queries()
verify_image_queries()
`, globals)
		if err != nil {
			if e, ok := err.(*starlark.EvalError); ok {
				t.Fatal(e.Backtrace())
			}
			t.Fatal(err)
		}
	}
}
