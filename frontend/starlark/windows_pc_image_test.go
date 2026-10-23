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
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
def check(ok):
    if not ok:
        fail("PC-to-image extent/ABI")
m=emulator.machine(image=image,image_name="native.exe")
m.use(kernel32_plugin())
image_record=[item for item in m.modules if item.primary][0]
base=image_record.base
size=image_record.image_size
check(size>0)
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
`, globals)
		if err != nil {
			if e, ok := err.(*starlark.EvalError); ok {
				t.Fatal(e.Backtrace())
			}
			t.Fatal(err)
		}
	}
}
