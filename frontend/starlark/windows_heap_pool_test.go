package starlarkfrontend

import "testing"

func TestKernelSmallHeapObjectsUseBoundedSlabs(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def exercise(architecture):
    m=emulator.machine(architecture=architecture,code=b"\xc3",memory_limit=8<<20)
    kernel=kernel32_plugin()
    m.use(kernel)
    alloc=m.resolve_export("kernel32.dll",name="HeapAlloc")
    free=m.resolve_export("kernel32.dll",name="HeapFree")
    resize=m.resolve_export("kernel32.dll",name="HeapReAlloc")
    size=m.resolve_export("kernel32.dll",name="HeapSize")
    heap=m.call(m.resolve_export("kernel32.dll",name="HeapCreate"),args=[0,0,0]).value
    pointers=[]
    for index in range(20000):
        result=m.call(alloc,args=[heap,8,10])
        if result.reason!="return" or not result.value or result.value%16: fail("small heap allocation exhausted or lost alignment")
        pointers.append(result.value)
        m.write_u32le(result.value,index)
    for index in [0,1,4095,4096,19999]:
        if m.read_u32le(pointers[index])!=index or m.read_u32le(pointers[index]+4)!=0: fail("live heap objects overlap or zero initialization failed")
    if m.call(free,args=[1,0,pointers[0]]).value!=0 or m.read_u32le(pointers[0])!=0: fail("wrong heap released an object")
    m.write(pointers[0],b"X"*10)
    if m.call(free,args=[heap,0,pointers[0]]).value!=1: fail("valid free failed")
    zero=m.call(alloc,args=[heap,8,10]).value
    if zero!=pointers[0] or m.read(zero,10)!=b"\x00"*10: fail("free slot reuse did not honor zero memory")
    m.write(zero,b"abcdefghij")
    grown=m.call(resize,args=[heap,8,zero,30])
    if grown.reason!="return" or not grown.value or m.read(grown.value,30)!=binary.encode("abcdefghij"+"\x00"*20,encoding="ascii"): fail("reallocation lost prefix or zero extension")
    if m.call(size,args=[heap,0,grown.value]).value!=30: fail("heap size exposed slot capacity")
    small=m.call(resize,args=[heap,0x10,grown.value,31])
    if small.reason!="return" or small.value!=grown.value: fail("bounded in-place resize moved the object")
    failed=m.call(resize,args=[heap,0x10,grown.value,33])
    if failed.reason!="return" or failed.value or m.call(size,args=[heap,0,grown.value]).value!=31: fail("in-place failure changed existing object")
    if m.call(m.resolve_export("kernel32.dll",name="HeapDestroy"),args=[heap]).value!=1: fail("heap destroy failed")
    if kernel.state["allocations"] or kernel.state["heap_arenas"] or kernel.state["heap_slot_owners"]: fail("destroy retained owned slab objects")
    if testing.attempt(m.read,args=[grown.value,1]).ok: fail("destroy retained mapped slab memory")
exercise("x86")
exercise("amd64")
`)
}
