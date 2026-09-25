package starlarkfrontend

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"

	binaryapi "github.com/tinyrange/trex/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestFullPathNameWideCapacityAndFilePart(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def check(condition):
    if not condition:
        fail("GetFullPathNameW check failed")
machine = emulator.machine(architecture="x86",code=b"\xc3")
machine.use(kernel32_plugin(module_path="C:\\Games\\GW2\\Gw2.exe"))
source = machine.allocate(value=binary.encode("..\\GW2\\Gw2.dat",encoding="utf16le",nul=True))
output = machine.allocate(value=b"\xaa"*128)
part = machine.allocate(size=4)
function = machine.resolve_export("kernel32.dll",name="GetFullPathNameW")
small = machine.call(function,args=[source,1,output,part])
check(small.reason == "return" and small.value == 21)
check(machine.read(output,4) == b"\xaa"*4)
result = machine.call(function,args=[source,64,output,part])
check(result.reason == "return" and result.value == 20)
check(machine.read_cstring(output,encoding="utf16le") == "C:\\Games\\GW2\\Gw2.dat")
check(machine.read_cstring(machine.read_pointer(part),encoding="utf16le") == "Gw2.dat")
`)
}

func TestCompletionPortPacketsAndFileReads(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def check(condition):
    if not condition:
        fail("completion port check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    machine.use(kernel32_plugin(files={"C:\\input.bin":b"payload"}))
    def call(name,args):
        result = machine.call(machine.resolve_export("kernel32.dll",name=name),args=args)
        check(result.reason == "return")
        return result.value
    port = call("CreateIoCompletionPort",[(1 << (machine.pointer_size*8))-1,0,0,0])
    check(port != 0)
    output = machine.allocate(size=32)
    key = 0x12345678 if architecture == "x86" else 0x123456789abcdef0
    check(call("PostQueuedCompletionStatus",[port,17,key,0x9876]) == 1)
    checkpoint = machine.checkpoint() if architecture == "x86" else None
    check(call("GetQueuedCompletionStatus",[port,output,output+8,output+16,0]) == 1)
    check(machine.read_u32le(output) == 17 and machine.read_pointer(output+8) == key and machine.read_pointer(output+16) == 0x9876)
    check(call("GetQueuedCompletionStatus",[port,output,output+8,output+16,0]) == 0)
    check(machine.read_pointer(output+16) == 0 and call("GetLastError",[]) == 258)
    if checkpoint != None:
        machine.restore(checkpoint)
        check(call("GetQueuedCompletionStatus",[port,output,output+8,output+16,0]) == 1)
    path = machine.allocate(value=b"C:\\input.bin\x00")
    file = call("CreateFileA",[path,0x80000000,1,0,3,0x40000000,0])
    check(call("CreateIoCompletionPort",[file,port,key,0]) == port)
    overlapped = machine.allocate(size=32)
    data = machine.allocate(size=7)
    check(call("ReadFile",[file,data,7,0,overlapped]) == 1)
    check(machine.read(data,7) == b"payload")
    check(call("GetQueuedCompletionStatus",[port,output,output+8,output+16,0]) == 1)
    check(machine.read_u32le(output) == 7 and machine.read_pointer(output+8) == key and machine.read_pointer(output+16) == overlapped)
exercise("x86")
exercise("amd64")
`)
}

func TestMemorySocketSetupAndCompletionPort(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin", "winsock_plugin")
def check(condition):
    if not condition:
        fail("memory socket setup check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    kernel = kernel32_plugin()
    network = winsock_plugin(kernel=kernel)
    machine.use([kernel,network])
    def call(ordinal,args):
        result = machine.call(machine.resolve_export("ws2_32.dll",ordinal=ordinal),args=args)
        check(result.reason == "return")
        return result.value
    socket = call(23,[2,1,6])
    other = call(23,[2,1,6])
    value = machine.allocate(value=b"\x01\x00\x00\x00")
    check(call(10,[socket,0x8004667e,value]) == 0)
    check(network.state["sockets"][socket]["nonblocking"])
    check(call(21,[socket,0xffff,0x80,value,4]) == 0)
    check(network.state["sockets"][socket]["linger"] == [1,0])
    check(call(21,[socket,0xffff,0x80,value,3]) == 0xffffffff)
    check(call(111,[]) == 10014)
    address = machine.allocate(size=16)
    machine.write_u16le(address,2)
    check(call(2,[socket,address,16]) == 0)
    check(call(2,[other,address,16]) == 0)
    local = network.state["sockets"][socket]["local_address"]
    check(local[2:4] != b"\x00\x00")
    check(local != network.state["sockets"][other]["local_address"])
    check(call(2,[socket,address,16]) == 0xffffffff)
    check(call(111,[]) == 10022)
    create = machine.resolve_export("kernel32.dll",name="CreateIoCompletionPort")
    result = machine.call(create,args=[socket,0,123,0])
    check(result.reason == "return" and result.value != 0)
    check(network.state["sockets"][socket]["completion_key"] == 123)
    check(machine.call(create,args=[socket,result.value,456,0]).value == 0)
exercise("x86")
exercise("amd64")
`)
}

func TestConnectExMemoryTransportAndRefusal(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin", "winsock_plugin")
def check(condition):
    if not condition:
        fail("ConnectEx check failed")
def exercise(architecture,accept):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    kernel = kernel32_plugin()
    peers = []
    def connect(ip,port,server):
        check(ip == b"\x7f\x00\x00\x01" and port == 80)
        peers.append(server)
        return True
    network = winsock_plugin(kernel=kernel,connect=connect if accept else None)
    machine.use([kernel,network])
    def call(ordinal,args):
        result = machine.call(machine.resolve_export("ws2_32.dll",ordinal=ordinal),args=args)
        check(result.reason == "return")
        return result.value
    socket = call(23,[2,1,6])
    address = machine.allocate(value=b"\x02\x00\x00\x50\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00")
    check(call(2,[socket,address,16]) == 0)
    create = machine.resolve_export("kernel32.dll",name="CreateIoCompletionPort")
    port = machine.call(create,args=[socket,0,123,0]).value
    output = machine.allocate(size=64)
    guid = machine.allocate(value=b"\xb9\x07\xa2\x25\xf3\xdd\x60\x46\x8e\xe9\x76\xe5\x8c\x74\x06\x3e")
    ioctl = machine.resolve_export("ws2_32.dll",name="WSAIoctl")
    check(machine.call(ioctl,args=[socket,0xc8000006,guid,16,output,machine.pointer_size,output+8,0,0]).value == 0)
    check(machine.read_u32le(output+8) == machine.pointer_size)
    function = machine.read_pointer(output)
    data = machine.allocate(value=b"request")
    overlapped = machine.allocate(size=32)
    result = machine.call(function,args=[socket,address,16,data,7,output+8,overlapped])
    check(result.reason == "return" and result.value == 0)
    if not accept:
        check(call(111,[]) == 10061 and len(peers) == 0)
        check(network.state["sockets"][socket]["channel"] == None)
        return
    check(call(111,[]) == 997)
    check(machine.call(machine.resolve_export("kernel32.dll",name="GetLastError")).value == 997)
    check(peers[0].read_available() == b"request")
    check(machine.read_u32le(output+8) == 7)
    dequeue = machine.resolve_export("kernel32.dll",name="GetQueuedCompletionStatus")
    check(machine.call(dequeue,args=[port,output+16,output+24,output+32,0]).value == 1)
    check(machine.read_u32le(output+16) == 7)
    check(machine.read_pointer(output+24) == 123 and machine.read_pointer(output+32) == overlapped)
    check(call(19,[socket,data,7,0]) == 7)
    check(peers[0].read_available() == b"request")
    read = machine.resolve_export("kernel32.dll",name="ReadFile")
    buffer = machine.allocate(size=16)
    check(machine.call(read,args=[socket,buffer,16,0,overlapped]).value == 0)
    check(kernel.state["last_error"] == 997)
    check(machine.call(dequeue,args=[port,output+16,output+24,output+32,0]).value == 0)
    peers[0].write(b"reply")
    check(machine.call(dequeue,args=[port,output+16,output+24,output+32,0]).value == 1)
    check(machine.read(buffer,5) == b"reply" and machine.read_u32le(output+16) == 5)
    check(machine.call(read,args=[socket,buffer,16,0,overlapped]).value == 0)
    check(call(3,[socket]) == 0)
    check(machine.call(dequeue,args=[port,output+16,output+24,output+32,0]).value == 0)
    check(kernel.state["last_error"] == 995)
    check(machine.read_pointer(output+32) == overlapped)
    check(machine.read_u32le(overlapped) == 0xc0000120)
    check(peers[0].read_available() == b"")
    peers[0].close()
exercise("x86",True)
exercise("amd64",True)
exercise("x86",False)
`)
}

func TestMemoryChannelCooperativeWrites(t *testing.T) {
	architectureScript(t, `
client,server = channel.memory_pair(maximum=4)
def check(condition):
    if not condition:
        fail("cooperative channel write failed")
check(client.write_available(b"abcd") == 4 and client.write_available(b"e") == None)
check(server.read_available() == b"abcd" and client.write_available(b"e") == 1)
server.close()
check(client.write_available(b"f") == -1)
client.close()
`)
}

func TestAsyncDNSCompletionDispatchesToWindow(t *testing.T) {
	thread, globals, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	globals["image"] = &starfile.Bytes{Name: "dns-client", Data: []byte(syntheticRegistryClientPE(t))}
	_, err = starlark.ExecFile(thread, "async-dns.star", `
load("@stdlib//windows/selfreg:win32.star", "user32_plugin", "winsock_plugin")
def check(condition):
    if not condition:
        fail("asynchronous DNS completion check failed")
machine = emulator.x86(code=b"\xc3")
ui = user32_plugin(image)
network = winsock_plugin(hosts={"asset.test":[b"\x7f\x00\x00\x01"]},user_interface=ui)
machine.use([ui,network])
procedure = machine.allocate(value=b"\x8b\x44\x24\x08\xc2\x10\x00",executable=True)
ui.state["classes"]["fixture"] = {"atom":1,"procedure":procedure}
ui.state["windows"][0xe000] = {"class":"fixture","longs":{}}
name = machine.allocate(value=b"ASSET.test.\x00")
output = machine.allocate(size=1024)
dns = machine.resolve_export("ws2_32.dll",ordinal=103)
task = machine.call(dns,args=[0xe000,0x8001,name,output,1024])
check(task.reason == "return" and task.value != 0)
check(machine.read_cstring(machine.read_pointer(output)) == "ASSET.test.")
check(machine.read_u16le(output+8) == 2 and machine.read_u16le(output+10) == 4)
addresses = machine.read_pointer(output+12)
check(machine.read(machine.read_pointer(addresses),4) == b"\x7f\x00\x00\x01")
message = machine.allocate(size=28)
peek = machine.resolve_export("user32.dll",name="PeekMessageW")
check(machine.call(peek,args=[message,0,0,0,1]).value == 1)
check(machine.read_u32le(message+8) == task.value and machine.read_u32le(message+12) >> 16 == 0)
dispatch = machine.resolve_export("user32.dll",name="DispatchMessageW")
result = machine.call(dispatch,args=[message])
check(result.reason == "return" and result.value == 0x8001)
machine.call(dns,args=[0xe000,0x8001,name,output,1])
check(ui.state["messages"][-1]["lparam"] >> 16 == 10055)
`, globals)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWorkerWaitDoesNotRecursivelyAdvanceOtherThreads(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def check(condition):
    if not condition:
        fail("cooperative worker wait check failed")
machine = emulator.x86(code=b"\xc3")
kernel = kernel32_plugin()
machine.use(kernel)
event = machine.call(machine.resolve_export("kernel32.dll",name="CreateEventW"),args=[0,1,0,0]).value
wait = machine.resolve_export("kernel32.dll",name="WaitForSingleObject")
code = binary.builder()
code.append(b"\x6a\x32\x68")
code.u32le(event)
code.append(b"\xb8")
code.u32le(wait)
code.append(b"\xff\xd0\xeb\xf0")
entry = machine.allocate(value=code.bytes(),executable=True)
create = machine.resolve_export("kernel32.dll",name="CreateThread")
machine.call(create,args=[0,0,entry,0,0,0])
machine.call(create,args=[0,0,entry,0,0,0])
check(kernel.state["tick_count"] == 0)
check(len(kernel.state["threads"]) == 2)
check(all([t["state"] == "waiting" and t["wait"]["deadline"] == 50 for t in kernel.state["threads"]]))
`)
}

func TestMemoryChannelsRestoreWithEmulatorCheckpoint(t *testing.T) {
	architectureScript(t, `
def check(condition):
    if not condition:
        fail("channel checkpoint check failed")
def install(machine):
    pass
machine = emulator.x86(code=b"\xc3")
client, server = channel.memory_pair(maximum=16)
state = {"client":client,"server":server}
machine.use(emulator.plugin(install,state=state))
check(server.read_available() == None)
client.write(b"request")
checkpoint = machine.checkpoint()
check(server.read_available() == b"request")
server.write(b"reply")
server.close()
check(client.read_available() == b"reply")
check(client.read_available() == b"")
machine.restore(checkpoint)
check(server.read_available() == b"request")
check(client.read_available() == None)
server.close()
check(client.read_available() == b"")
`)
}

func TestLargeVirtualFileBoundedReadAndSeek(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def check(v):
    if not v: fail("large file range check failed")
size = (13 << 30) + 100
source = binary.extents(size,[(size-4,b"tail")])
machine = emulator.machine(architecture="x86",code=b"\xc3")
kernel = kernel32_plugin(files={"C:\\large.dat":source})
machine.use(kernel)
def call(name,args):
    r=machine.call(machine.resolve_export("kernel32.dll",name=name),args=args)
    check(r.reason == "return")
    return r.value
name=machine.allocate(value=b"C:\\large.dat\x00")
handle=call("CreateFileA",[name,0x80000000,1,0,3,0,0])
out=machine.allocate(size=16)
check(call("GetFileSizeEx",[handle,out]) == 1)
check(machine.read_u64le(out) == size)
check(call("SetFilePointer",[handle,0xfffffffc,0,2]) == (size-4)&0xffffffff)
check(call("ReadFile",[handle,out,8,out+8,0]) == 1)
check(machine.read(out,4) == b"tail" and machine.read_u32le(out+8) == 4)
check("data" not in kernel.state["paths"]["c:\\large.dat"])
`)
}

func TestWriteProcessMemoryRestoresCodeProtection(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def check(condition):
    if not condition:
        fail("WriteProcessMemory check failed")
def exercise(architecture):
    machine = emulator.machine(architecture=architecture,code=b"\xc3")
    machine.use(kernel32_plugin())
    target = machine.allocate(value=b"\xb8\x01\x00\x00\x00\xc3", writable=False, executable=True)
    source = machine.allocate(value=b"\xb8\x63\x00\x00\x00\xc3")
    written = machine.allocate(value=b"\xaa"*(machine.pointer_size+4))
    write = machine.resolve_export("kernel32.dll",name="WriteProcessMemory")
    process = (1 << (machine.pointer_size*8))-1
    result = machine.call(write,args=[process,target,source,6,written])
    check(result.reason == "return" and result.value == 1)
    check(machine.read_pointer(written) == 6)
    check(machine.read(written+machine.pointer_size,4) == b"\xaa"*4)
    check(machine.call(target).value == 99)
    previous = machine.protect(target,6,readable=True,writable=False,executable=True)
    check(all([r.readable and not r.writable and r.executable for r in previous]))
    machine.write(source,b"\xb8\x02\x00\x00\x00\xc3")
    result = machine.call(write,args=[123,target,source,6,written])
    check(result.reason == "return" and result.value == 0)
    check(machine.call(target).value == 99)
exercise("x86")
exercise("amd64")
`)
}

func TestX86SListPushPop(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin")
def check(condition):
    if not condition:
        fail("SList check failed")
machine = emulator.machine(architecture="x86",code=b"\xc3")
machine.use(kernel32_plugin())
head = machine.allocate(value=b"\xaa"*8,alignment=8)
first = machine.allocate(size=8,alignment=8)
second = machine.allocate(size=8,alignment=8)
initialize = machine.resolve_export("kernel32.dll",name="InitializeSListHead")
push = machine.resolve_export("kernel32.dll",name="InterlockedPushEntrySList")
pop = machine.resolve_export("kernel32.dll",name="InterlockedPopEntrySList")
check(machine.call(initialize,args=[head]).reason == "return")
check(machine.call(pop,args=[head]).value == 0)
check(machine.call(push,args=[head,first]).value == 0)
check(machine.call(push,args=[head,second]).value == first)
check(machine.read_u16le(head+4) == 2)
check(machine.read_u16le(head+6) == 2)
checkpoint = machine.checkpoint()
check(machine.call(pop,args=[head]).value == second)
check(machine.call(pop,args=[head]).value == first)
check(machine.call(pop,args=[head]).value == 0)
check(machine.read_u16le(head+4) == 0)
machine.restore(checkpoint)
check(machine.call(pop,args=[head]).value == second)
`)
}

func TestRaiseExceptionContinuationCleansArguments(t *testing.T) {
	thread, globals, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	_, err = starlark.ExecFile(thread, "raise-continuation.star", `
load("@stdlib//windows/selfreg:exception.star", "exception_plugin")
# Push a sentinel, four RaiseException arguments, CALL through IAT, return sentinel.
code = b"\x68\x78\x56\x34\x12\x6a\x00\x6a\x00\x6a\x00\x68\x88\x13\x6d\x40\xff\x15\x00\x00\x00\x00\x58\xc3"
image = windows.pe32_executable(code,{"entry":0},[{"offset":18,"label":"iat:KERNEL32.dll:RaiseException"}],imports={"KERNEL32.dll":["RaiseException"]})
machine = emulator.x86(image=image,fs_base=0x7ffb0000)
handler = machine.allocate(value=b"\x31\xc0\xc2\x10\x00",executable=True)
frame = machine.allocate(size=16)
machine.write_u32le(frame,0xffffffff)
machine.write_u32le(frame+4,handler)
machine.write_u32le(machine.segment_base("fs"),frame)
machine.use(exception_plugin())
result = machine.call(machine.entry)
def check():
    if result.reason != "return" or result.value != 0x12345678:
        fail("RaiseException corrupted continuation: %s %s value=%s" % (result.reason,result.detail,hex(result.value)))
check()
`, globals)
	if err != nil {
		t.Fatal(err)
	}
}

func testStarlarkStringDict(values map[string]starlark.Value) *starlark.Dict {
	dict := starlark.NewDict(len(values))
	for name, value := range values {
		_ = dict.SetKey(starlark.String(name), value)
	}
	return dict
}

type resourceSnapshotCountingFile struct {
	*starfile.Bytes
	reads int
}

func (f *resourceSnapshotCountingFile) ReadAt(p []byte, offset int64) (int, error) {
	f.reads++
	return f.Bytes.ReadAt(p, offset)
}

func TestResourcePluginSharesSnapshotForResourcesAndMessages(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:win32.star")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(syntheticRegistryClientPE(t))
	primary := &resourceSnapshotCountingFile{Bytes: &starfile.Bytes{Name: "primary", Data: data}}
	dependency := &resourceSnapshotCountingFile{Bytes: &starfile.Bytes{Name: "dependency", Data: data}}
	files := testStarlarkStringDict(map[string]starlark.Value{"dependency.dll": dependency})
	_, err = starlark.Call(thread, module["resource_plugin"], starlark.Tuple{primary}, []starlark.Tuple{
		{starlark.String("module_files"), files},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []*resourceSnapshotCountingFile{primary, dependency} {
		if file.reads != 1 {
			t.Errorf("%s: read %d times, want one owned snapshot shared by both parsers", file.String(), file.reads)
		}
	}
}

func TestRunnerSharesOwnedImageSnapshotsAcrossMetadataPlugins(t *testing.T) {
	thread, predeclared, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	primary := &resourceSnapshotCountingFile{Bytes: &starfile.Bytes{Name: "primary", Data: []byte(relocatablePE32TestImage(t, 0x200000))}}
	dependency := &resourceSnapshotCountingFile{Bytes: &starfile.Bytes{Name: "dependency", Data: []byte(relocatablePE32TestImage(t, 0x300000))}}
	predeclared["primary"] = primary
	predeclared["dependency"] = dependency
	_, err = starlark.ExecFile(thread, "snapshot-sharing.star", `
load("@stdlib//windows/emulation:runner.star", "run")
def execute(machine):
    return machine.call(machine.resolve_export("kernel32.dll", name="GetTickCount"), args=[])
def check():
    for unused in range(2):
        result = run(primary, "primary.dll", modules={"dependency.dll": dependency}, execute=execute)
        if result["result"].reason != "return":
            fail("runner did not return")
check()
`, predeclared)
	if err != nil {
		if evaluation, ok := err.(*starlark.EvalError); ok {
			t.Fatal(evaluation.Backtrace())
		}
		t.Fatal(err)
	}
	for _, file := range []*resourceSnapshotCountingFile{primary, dependency} {
		if file.reads != 2 {
			t.Errorf("%s: read %d times, want one owned snapshot per run", file.String(), file.reads)
		}
	}
}

func TestSelfregGUIDAndStaticPolicies(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	facts, err := thread.Load(thread, "@stdlib//windows/selfreg:facts.star")
	if err != nil {
		t.Fatal(err)
	}
	rawValue, err := starlark.Call(thread, facts["guid_bytes"], starlark.Tuple{starlark.String("{F414C260-6AC0-11CF-B6D1-00AA00BBBB58}")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := binaryapi.BytesForValue(rawValue)
	if err != nil {
		t.Fatal(err)
	}
	wantRaw := []byte{0x60, 0xc2, 0x14, 0xf4, 0xc0, 0x6a, 0xcf, 0x11, 0xb6, 0xd1, 0x00, 0xaa, 0x00, 0xbb, 0xbb, 0x58}
	if !bytes.Equal(raw, wantRaw) {
		t.Fatalf("GUID bytes = %x, want %x", raw, wantRaw)
	}

	script, err := thread.Load(thread, "@stdlib//windows/selfreg:script.star")
	if err != nil {
		t.Fatal(err)
	}
	classes := starlark.NewList([]starlark.Value{
		starlark.String("{F414C260-6AC0-11CF-B6D1-00AA00BBBB58}"),
		starlark.String("{F414C262-6AC0-11CF-B6D1-00AA00BBBB58}"),
	})
	patchesValue, err := starlark.Call(thread, script["script_engine_registry_patches"], starlark.Tuple{
		starlark.String(`C:\WINDOWS\system32\jscript.dll`), starlark.String("JScript"), classes, starlark.String("JScript.Encode"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	patches := patchesValue.(*starlark.List)
	if patches.Len() != 16 {
		t.Fatalf("script registration emitted %d patches, want 16", patches.Len())
	}
	if got := selfregPatchValue(t, patches, "/Classes/JScript.Encode/CLSID", "(default)"); got != "{F414C262-6AC0-11CF-B6D1-00AA00BBBB58}" {
		t.Fatalf("encoded class = %q", got)
	}
}

func TestScriptMetadataDoesNotSuppressNativeRegistration(t *testing.T) {
	thread, predeclared, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	// Export the synthetic registry writer as a DLL registrar. No proprietary
	// script engine bytes are needed to test execution policy.
	data := []byte(syntheticRegistryClientPE(t))
	pe := int(binary.LittleEndian.Uint32(data[0x3c:]))
	optional := pe + 24
	sections := optional + int(binary.LittleEndian.Uint16(data[pe+20:]))
	last := sections + (int(binary.LittleEndian.Uint16(data[pe+6:]))-1)*40
	raw := int(binary.LittleEndian.Uint32(data[last+20:]))
	va := binary.LittleEndian.Uint32(data[last+12:])
	exportOffset := len(data)
	exportRVA := va + uint32(exportOffset-raw)
	data = append(data, make([]byte, 512)...)
	binary.LittleEndian.PutUint32(data[last+8:], uint32(len(data)-raw))
	binary.LittleEndian.PutUint32(data[last+16:], uint32(len(data)-raw))
	alignment := binary.LittleEndian.Uint32(data[optional+32:])
	imageEnd := va + uint32(len(data)-raw)
	binary.LittleEndian.PutUint32(data[optional+56:], (imageEnd+alignment-1)&^(alignment-1))
	binary.LittleEndian.PutUint32(data[optional+96:], exportRVA)
	binary.LittleEndian.PutUint32(data[optional+100:], 128)
	export := data[exportOffset:]
	for offset, value := range map[int]uint32{16: 1, 20: 1, 24: 1, 28: exportRVA + 40, 32: exportRVA + 44, 36: exportRVA + 48, 40: binary.LittleEndian.Uint32(data[optional+16:]), 44: exportRVA + 50} {
		binary.LittleEndian.PutUint32(export[offset:], value)
	}
	copy(export[50:], "DllRegisterServer\x00")
	predeclared["image"] = &starfile.Bytes{Name: "script.dll", Data: data}
	// Supply already-derived script metadata, independently of PE class-table
	// recognition. The real runner must still execute the exported registrar.
	originalLoad := thread.Load
	thread.Load = func(thread *starlark.Thread, module string) (starlark.StringDict, error) {
		if module == ":script.star" {
			return starlark.ExecFile(thread, "script-facts.star", `
def script_engine_patches(file, module, pe=None):
    return [{"hive":"SOFTWARE", "key":"/Classes/TestScript", "name":"(default)", "type":"REG_SZ", "value":"metadata"}]
`, nil)
		}
		return originalLoad(thread, module)
	}
	_, err = starlark.ExecFile(thread, "script-registration.star", `
load("@stdlib//windows/selfreg:policy.star", "registration_patches")
def check():
    static = registration_patches(image, "script.dll", execute=False)
    if static["execution"] != None or not any([p["key"] == "/Classes/TestScript" for p in static["patches"]]):
        fail("test did not provide the static script metadata control")
    result = registration_patches(image, "script.dll")
    if result["execution"] == None:
        fail("static script metadata suppressed the native registrar")
    if not any([p["key"].lower() == "/classes/example" and p["name"] == "Greeting" and p["value"] == "hello" for p in result["patches"]]):
        fail("native script registration writes were not retained")
check()
`, predeclared)
	if err != nil {
		if evaluation, ok := err.(*starlark.EvalError); ok {
			t.Fatal(evaluation.Backtrace())
		}
		t.Fatal(err)
	}
}

func TestTypeLibPolicyConsumesParsedFacts(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:typelib.star")
	if err != nil {
		t.Fatal(err)
	}
	typeInfo := starlark.NewDict(4)
	for name, value := range map[string]starlark.Value{
		"guid": starlark.String("{CCCCCCCC-DDDD-EEEE-FFFF-AAAAAAAAAAAA}"), "name": starlark.String("Control"),
		"kind": starlark.MakeInt(5), "flags": starlark.MakeInt(0x22),
	} {
		_ = typeInfo.SetKey(starlark.String(name), value)
	}
	library := starlark.NewDict(8)
	for name, value := range map[string]starlark.Value{
		"guid": starlark.String("{A5064420-D541-11D4-9523-00B0D022CA64}"), "name": starlark.String("ExampleLib"),
		"major": starlark.MakeInt(2), "minor": starlark.MakeInt(3), "lcid": starlark.MakeInt(0x409),
		"flags": starlark.MakeInt(1), "syskind": starlark.MakeInt(1), "types": starlark.NewList([]starlark.Value{typeInfo}),
	} {
		_ = library.SetKey(starlark.String(name), value)
	}
	selected := starlark.NewDict(1)
	_ = selected.SetKey(starlark.String("{A5064420-D541-11D4-9523-00B0D022CA64}"), starlark.True)
	patchesValue, err := starlark.Call(thread, module["typelib_patches"], starlark.Tuple{
		starlark.NewList([]starlark.Value{library}), starlark.String(`C:\WINDOWS\system32\control.ocx`), selected, starlark.NewDict(0),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	patches := patchesValue.(*starlark.List)
	if got := selfregPatchValue(t, patches, "/Classes/TypeLib/{A5064420-D541-11D4-9523-00B0D022CA64}/2.3/HELPDIR", "(default)"); got != `C:\WINDOWS\system32` {
		t.Fatalf("type library help directory = %q", got)
	}
	if got := selfregPatchValue(t, patches, "/Classes/CLSID/{CCCCCCCC-DDDD-EEEE-FFFF-AAAAAAAAAAAA}/Control", "(default)"); got != "" {
		t.Fatalf("control marker = %q", got)
	}
}

func TestREGINSTPolicyUsesGenericINFParser(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:reginst.star")
	if err != nil {
		t.Fatal(err)
	}
	source := `[Install]
AddReg=Classes
[Classes]
HKCR,"CLSID\%CLSID%\InProcServer32",,%EXPAND%,"%SYS_MOD_PATH%"
[Strings]
CLSID="{ECD4FC4D-521C-11D0-B792-00A0C90312E1}"
EXPAND=0x00020000
`
	value, err := starlark.Call(thread, module["reginst_resource_patches"], starlark.Tuple{
		starlark.String(source), starlark.String(`C:/WINDOWS/system32/example.dll`),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	patches := value.(*starlark.List)
	if patches.Len() != 1 {
		t.Fatalf("REGINST emitted %d patches, want 1", patches.Len())
	}
	if got := selfregPatchValue(t, patches, "/Classes/CLSID/{ECD4FC4D-521C-11D0-B792-00A0C90312E1}/InProcServer32", "(default)"); got != `C:\WINDOWS\system32\example.dll` {
		t.Fatalf("REGINST module path = %q", got)
	}
}

func TestREGINSTPolicyExpandsModulePathAliases(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:reginst.star")
	if err != nil {
		t.Fatal(err)
	}
	source := `[Install]
AddReg=Classes
[Classes]
HKCR,"CLSID\%CLSID%\InProcServer32",,,"%_MOD_PATH%"
HKCR,"CLSID\%CLSID%\LocalServer32",,,"%MOD_PATH%"
[Strings]
CLSID="{AE24FDAE-03C6-11D1-8B76-0080C744F389}"
`
	value, err := starlark.Call(thread, module["reginst_resource_patches"], starlark.Tuple{
		starlark.String(source), starlark.String(`C:\WINDOWS\system32\scrobj.dll`),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	patches := value.(*starlark.List)
	for _, key := range []string{
		"/Classes/CLSID/{AE24FDAE-03C6-11D1-8B76-0080C744F389}/InProcServer32",
		"/Classes/CLSID/{AE24FDAE-03C6-11D1-8B76-0080C744F389}/LocalServer32",
	} {
		if got := selfregPatchValue(t, patches, key, "(default)"); got != `C:\WINDOWS\system32\scrobj.dll` {
			t.Fatalf("%s = %q", key, got)
		}
	}
}

func selfregPatchValue(t *testing.T, patches *starlark.List, key, name string) string {
	t.Helper()
	for index := 0; index < patches.Len(); index++ {
		patch := patches.Index(index).(*starlark.Dict)
		keyValue, _, _ := patch.Get(starlark.String("key"))
		nameValue, _, _ := patch.Get(starlark.String("name"))
		if keyValue.String() != starlark.String(key).String() || nameValue.String() != starlark.String(name).String() {
			continue
		}
		value, _, _ := patch.Get(starlark.String("value"))
		text, ok := starlark.AsString(value)
		if !ok {
			t.Fatalf("patch %s %s value is %s", key, name, value.Type())
		}
		return text
	}
	t.Fatalf("missing patch %s %s", key, name)
	return ""
}

func TestRegistryPluginCapturesEmulatedRegistration(t *testing.T) {
	image := syntheticRegistryClientPE(t)
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:registry.star")
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := starlark.Call(thread, module["registry_plugin"], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	machineValue, err := emulatorX86Builtin(nil, nil, nil, []starlark.Tuple{{starlark.String("image"), image}})
	if err != nil {
		t.Fatal(err)
	}
	machine := machineValue.(*emulatorX86)
	if _, err := machine.UseBuiltin(thread, nil, starlark.Tuple{plugin}, nil); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.Run(thread)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("emulation stopped with %s: %s", got, recordString(t, result, "detail"))
	}
	patchesMethod, _ := plugin.(starlark.HasAttrs).Attr("patches")
	patchesValue, err := starlark.Call(thread, patchesMethod.(starlark.Callable), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	patches := patchesValue.(*starlark.List)
	if patches.Len() != 1 {
		t.Fatalf("captured %d patches, want 1: %v", patches.Len(), patches)
	}
	patch := patches.Index(0).(*starlark.Dict)
	for name, want := range map[string]string{
		"hive": "SOFTWARE", "key": "/Classes/Example", "name": "Greeting", "type": "REG_SZ", "value": "hello",
	} {
		value, _, _ := patch.Get(starlark.String(name))
		got, ok := starlark.AsString(value)
		if !ok || got != want {
			t.Fatalf("patch %s = %v, want %q", name, value, want)
		}
	}
	keysMethod, _ := plugin.(starlark.HasAttrs).Attr("keys")
	keysValue, err := starlark.Call(thread, keysMethod.(starlark.Callable), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := keysValue.(*starlark.List)
	if keys.Len() != 1 {
		t.Fatalf("captured %d created keys, want 1: %v", keys.Len(), keys)
	}
	key := keys.Index(0).(*starlark.Dict)
	for name, want := range map[string]string{"hive": "SOFTWARE", "key": "/Classes/Example"} {
		value, _, _ := key.Get(starlark.String(name))
		got, ok := starlark.AsString(value)
		if !ok || got != want {
			t.Fatalf("created key %s = %v, want %q", name, value, want)
		}
	}
}

func TestKernelLoadLibraryActivatesPreMappedModule(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:win32.star")
	if err != nil {
		t.Fatal(err)
	}
	machineValue, err := emulatorX86Builtin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("image"), syntheticLoadLibraryClientPE(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	machine := machineValue.(*emulatorX86)
	loadedValue, err := machine.LoadModuleBuiltin(nil, nil, starlark.Tuple{
		relocatablePE32TestImage(t, 0x200000), starlark.String("deferred.dll"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	loadedBase := recordUint32(t, loadedValue.(*starlarkRecord), "base")
	var requested []string
	onLoad := starlark.NewBuiltin("on_module_load", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("on_module_load", args, kwargs, "name", &name); err != nil {
			return nil, err
		}
		requested = append(requested, name)
		return starlark.MakeUint64(uint64(loadedBase)), nil
	})
	plugin, err := starlark.Call(thread, module["kernel32_plugin"], nil, []starlark.Tuple{
		{starlark.String("on_module_load"), onLoad},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.UseBuiltin(thread, nil, starlark.Tuple{plugin}, nil); err != nil {
		t.Fatal(err)
	}
	resultValue, err := machine.Run(thread)
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("emulation stopped with %s: %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != loadedBase {
		t.Fatalf("LoadLibraryA returned %#x, want %#x", got, loadedBase)
	}
	if len(requested) != 1 || requested[0] != "deferred.dll" {
		t.Fatalf("module-load callbacks = %v, want [deferred.dll]", requested)
	}
}

func TestKernelCurrentDirectoryTracksGuestDirectories(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:win32.star")
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := starlark.Call(thread, module["kernel32_plugin"], nil, []starlark.Tuple{
		{starlark.String("module_path"), starlark.String(`C:\WINDOWS\TEMP\SETUP.EXE`)},
		{starlark.String("directories"), starlark.NewList([]starlark.Value{starlark.String(`C:\WINDOWS\TEMP`), starlark.String(`C:\PROGRAM FILES`)})},
		{starlark.String("files"), testStarlarkStringDict(map[string]starlark.Value{`C:\WINDOWS\TEMP\sample.bin`: starlark.Bytes("sample")})},
	})
	if err != nil {
		t.Fatal(err)
	}
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	if _, err := machine.UseBuiltin(thread, nil, starlark.Tuple{plugin}, nil); err != nil {
		t.Fatal(err)
	}
	allocate := func(data []byte) uint32 {
		value, err := machine.AllocateBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("value"), starlark.Bytes(data)}})
		if err != nil {
			t.Fatal(err)
		}
		address, _ := value.(starlark.Int).Uint64()
		return uint32(address)
	}
	call := func(name string, args ...uint32) uint32 {
		address := machine.ResolveExport("kernel32.dll", name, 0, 0)
		value, err := machine.CallAddress(thread, address, args)
		if err != nil {
			t.Fatal(err)
		}
		result := value.(*starlarkRecord)
		if got := recordString(t, result, "reason"); got != "return" {
			t.Fatalf("%s stopped with %s: %s", name, got, recordString(t, result, "detail"))
		}
		return recordUint32(t, result, "value")
	}

	buffer := allocate(make([]byte, 260))
	if got, want := call("GetCurrentDirectoryA", 260, buffer), uint32(len(`C:\WINDOWS\TEMP`)); got != want {
		t.Fatalf("GetCurrentDirectoryA = %d, want %d", got, want)
	}
	stored, err := machine.ReadMemory(buffer, len(`C:\WINDOWS\TEMP`)+1, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(stored), "C:\\WINDOWS\\TEMP\x00"; got != want {
		t.Fatalf("current directory = %q, want %q", got, want)
	}
	next := allocate([]byte("C:\\PROGRAM FILES\x00"))
	if got := call("SetCurrentDirectoryA", next); got != 1 {
		t.Fatalf("SetCurrentDirectoryA = %d, want TRUE", got)
	}
	if got, want := call("GetCurrentDirectoryA", 260, buffer), uint32(len(`C:\PROGRAM FILES`)); got != want {
		t.Fatalf("GetCurrentDirectoryA after set = %d, want %d", got, want)
	}
	label := allocate(make([]byte, 32))
	serial := allocate(make([]byte, 4))
	maximumComponent := allocate(make([]byte, 4))
	flags := allocate(make([]byte, 4))
	filesystem := allocate(make([]byte, 32))
	if got := call("GetVolumeInformationA", 0, label, 32, serial, maximumComponent, flags, filesystem, 32); got != 1 {
		t.Fatalf("GetVolumeInformationA(NULL) = %d, want TRUE", got)
	}
	path := allocate([]byte("C:\\WINDOWS\\TEMP\\sample.bin\x00"))
	file := call("_lopen", path, 0)
	if file == 0xffffffff {
		t.Fatal("_lopen returned HFILE_ERROR")
	}
	if got := call("_llseek", file, 2, 0); got != 2 {
		t.Fatalf("_llseek = %d, want 2", got)
	}
	if got := call("_lclose", file); got != 0 {
		t.Fatalf("_lclose = %#x, want 0", got)
	}
}

func TestShellSHGetMallocReturnsOLEAllocator(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:win32.star")
	if err != nil {
		t.Fatal(err)
	}
	ole, err := starlark.Call(thread, module["ole32_plugin"], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	malloc, err := ole.(starlark.HasAttrs).Attr("state")
	if err != nil {
		t.Fatal(err)
	}
	shell, err := starlark.Call(thread, module["shell32_plugin"], nil, []starlark.Tuple{{starlark.String("malloc"), malloc}})
	if err != nil {
		t.Fatal(err)
	}
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	if _, err := machine.UseBuiltin(thread, nil, starlark.Tuple{starlark.NewList([]starlark.Value{ole, shell})}, nil); err != nil {
		t.Fatal(err)
	}
	outputValue, err := machine.AllocateBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("size"), starlark.MakeInt(4)}})
	if err != nil {
		t.Fatal(err)
	}
	output64, _ := outputValue.(starlark.Int).Uint64()
	address := machine.ResolveExport("shell32.dll", "SHGetMalloc", 0, 0)
	value, err := machine.CallAddress(thread, address, []uint32{uint32(output64)})
	if err != nil {
		t.Fatal(err)
	}
	result := value.(*starlarkRecord)
	if got := recordUint32(t, result, "value"); got != 0 {
		t.Fatalf("SHGetMalloc returned %#x, want S_OK", got)
	}
	stored, err := machine.ReadMemory(uint32(output64), 4, 'r')
	if err != nil {
		t.Fatal(err)
	}
	allocator := uint32(stored[0]) | uint32(stored[1])<<8 | uint32(stored[2])<<16 | uint32(stored[3])<<24
	if allocator == 0 {
		t.Fatal("SHGetMalloc returned a null allocator")
	}
}

func TestCommonControlsPropertySheetDispatchesWizardPages(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:win32.star")
	if err != nil {
		t.Fatal(err)
	}
	common, err := starlark.Call(thread, module["common_controls_plugin"], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	image := relocatablePE32TestImage(t, 0x200000)
	user, err := starlark.Call(thread, module["user32_plugin"], starlark.Tuple{&starfile.Bytes{Name: "user32-test", Data: []byte(image)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The page procedure returns TRUE for WM_INITDIALOG and each notification.
	machine := newRawX86TestMachine(t, starlark.Bytes("\xb8\x01\x00\x00\x00\xc2\x10\x00"), nil)
	if _, err := machine.UseBuiltin(thread, nil, starlark.Tuple{starlark.NewList([]starlark.Value{common, user})}, nil); err != nil {
		t.Fatal(err)
	}
	allocateWords := func(words ...uint32) uint32 {
		data := make([]byte, len(words)*4)
		for index, word := range words {
			data[index*4] = byte(word)
			data[index*4+1] = byte(word >> 8)
			data[index*4+2] = byte(word >> 16)
			data[index*4+3] = byte(word >> 24)
		}
		value, err := machine.AllocateBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("value"), starlark.Bytes(data)}})
		if err != nil {
			t.Fatal(err)
		}
		address, _ := value.(starlark.Int).Uint64()
		return uint32(address)
	}
	entryValue, err := machine.Attr("entry")
	if err != nil {
		t.Fatal(err)
	}
	entry64, _ := entryValue.(starlark.Int).Uint64()
	page := allocateWords(48, 0, 0x1234, 101, 0, 0, uint32(entry64), 0, 0, 0, 0, 0)
	header := allocateWords(52, 0, 0, 0x1234, 0, 0, 1, 0, page, 0, 0, 0, 0)
	address := machine.ResolveExport("comctl32.dll", "PropertySheetA", 0, 0)
	value, err := machine.CallAddress(thread, address, []uint32{header})
	if err != nil {
		t.Fatal(err)
	}
	result := value.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("PropertySheetA stopped with %s: %s", got, recordString(t, result, "detail"))
	}
	if got := recordUint32(t, result, "value"); got != 1 {
		t.Fatalf("PropertySheetA = %#x, want 1", got)
	}
}

func TestUserClassModuleAndCRTWCSNCat(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:win32.star")
	if err != nil {
		t.Fatal(err)
	}
	image := relocatablePE32TestImage(t, 0x200000)
	user, err := starlark.Call(thread, module["user32_plugin"], starlark.Tuple{&starfile.Bytes{Name: "user32-test", Data: []byte(image)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := starlark.Call(thread, module["msvcrt_plugin"], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	machine := newRawX86TestMachine(t, starlark.Bytes("\xb8\x01\x00\x00\x00\xc2\x10\x00"), nil)
	if _, err := machine.UseBuiltin(thread, nil, starlark.Tuple{starlark.NewList([]starlark.Value{user, crt})}, nil); err != nil {
		t.Fatal(err)
	}
	allocate := func(data []byte) uint32 {
		value, err := machine.AllocateBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("value"), starlark.Bytes(data)}})
		if err != nil {
			t.Fatal(err)
		}
		address, _ := value.(starlark.Int).Uint64()
		return uint32(address)
	}
	call := func(module, name string, args ...uint32) uint32 {
		address := machine.ResolveExport(module, name, 0, 0)
		if address == 0 {
			t.Fatalf("missing semantic export %s!%s", module, name)
		}
		value, err := machine.CallAddress(thread, address, args)
		if err != nil {
			t.Fatal(err)
		}
		result := value.(*starlarkRecord)
		if got := recordString(t, result, "reason"); got != "return" {
			t.Fatalf("%s!%s stopped with %s: %s", module, name, got, recordString(t, result, "detail"))
		}
		return recordUint32(t, result, "value")
	}

	entryValue, err := machine.Attr("entry")
	if err != nil {
		t.Fatal(err)
	}
	entry64, _ := entryValue.(starlark.Int).Uint64()
	className := allocate(append([]byte("WMP Test Window"), 0))
	windowClass := make([]byte, 48)
	windowClass[0] = 48
	windowClass[40] = byte(className)
	windowClass[41] = byte(className >> 8)
	windowClass[42] = byte(className >> 16)
	windowClass[43] = byte(className >> 24)
	// A non-pointer small icon handle proves RegisterClassExA reads the class
	// name from offset 40 rather than the trailing hIconSm field at offset 44.
	windowClass[44] = 2
	windowClass[45] = 0xd0
	if got := call("user32.dll", "RegisterClassExA", allocate(windowClass)); got == 0 {
		t.Fatal("RegisterClassExA returned no class atom")
	}
	dialog := call("user32.dll", "CreateDialogParamA", 0x1234, 101, 0, uint32(entry64), 0)
	child := call("user32.dll", "GetDlgItem", dialog, 1001)
	if got := call("user32.dll", "GetClassLongA", child, 0xfffffff0); got != 0x1234 {
		t.Fatalf("GetClassLongA(GCL_HMODULE) = %#x, want %#x", got, uint32(0x1234))
	}
	if got := call("user32.dll", "MessageBoxA", 0, 0, 0, 4); got != 6 {
		t.Fatalf("MessageBoxA(MB_YESNO) = %d, want IDYES", got)
	}
	destinationData := make([]byte, 128)
	copy(destinationData, selfregUTF16Bytes("Media "))
	destination := allocate(destinationData)
	source := allocate(append(selfregUTF16Bytes("Player"), 0, 0))
	if got := call("msvcrt.dll", "wcsncat", destination, source, 3); got != destination {
		t.Fatalf("wcsncat returned %#x, want destination %#x", got, destination)
	}
	stored, err := machine.ReadMemory(destination, len(selfregUTF16Bytes("Media Pla"))+2, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if want := append(selfregUTF16Bytes("Media Pla"), 0, 0); !bytes.Equal(stored, want) {
		t.Fatalf("wcsncat output = %x, want %x", stored, want)
	}
}

func TestRegistryPluginSHDeleteOrphanKeyDeletesOnlyEmptyKey(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:registry.star")
	if err != nil {
		t.Fatal(err)
	}
	keys := starlark.NewList([]starlark.Value{testStarlarkStringDict(map[string]starlark.Value{
		"hive": starlark.String("SOFTWARE"), "key": starlark.String("/Empty"),
	})})
	values := starlark.NewList([]starlark.Value{testStarlarkStringDict(map[string]starlark.Value{
		"hive": starlark.String("SOFTWARE"), "key": starlark.String("/Occupied"),
		"name": starlark.String("Value"), "type": starlark.String("REG_SZ"), "value": starlark.String("present"),
	})})
	plugin, err := starlark.Call(thread, module["registry_plugin"], nil, []starlark.Tuple{
		{starlark.String("keys"), keys}, {starlark.String("values"), values},
	})
	if err != nil {
		t.Fatal(err)
	}
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	if _, err := machine.UseBuiltin(thread, nil, starlark.Tuple{plugin}, nil); err != nil {
		t.Fatal(err)
	}
	allocate := func(data []byte) uint32 {
		value, err := machine.AllocateBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("value"), starlark.Bytes(data)}})
		if err != nil {
			t.Fatal(err)
		}
		address, _ := value.(starlark.Int).Uint64()
		return uint32(address)
	}
	call := func(module, name string, args ...uint32) uint32 {
		address := machine.ResolveExport(module, name, 0, 0)
		if address == 0 {
			t.Fatalf("missing semantic export %s!%s", module, name)
		}
		value, err := machine.CallAddress(thread, address, args)
		if err != nil {
			t.Fatal(err)
		}
		result := value.(*starlarkRecord)
		if got := recordString(t, result, "reason"); got != "return" {
			t.Fatalf("%s!%s stopped with %s: %s", module, name, got, recordString(t, result, "detail"))
		}
		return recordUint32(t, result, "value")
	}
	const hkeyLocalMachine = uint32(0x80000002)
	empty := allocate([]byte("Empty\x00"))
	occupied := allocate([]byte("Occupied\x00"))
	if got := call("shlwapi.dll", "SHDeleteOrphanKeyA", hkeyLocalMachine, empty); got != 0 {
		t.Fatalf("SHDeleteOrphanKeyA(empty) = %d, want ERROR_SUCCESS", got)
	}
	if got := call("shlwapi.dll", "SHDeleteOrphanKeyA", hkeyLocalMachine, occupied); got != 0 {
		t.Fatalf("SHDeleteOrphanKeyA(occupied) = %d, want ERROR_SUCCESS", got)
	}
	output := allocate(make([]byte, 4))
	if got := call("advapi32.dll", "RegOpenKeyA", hkeyLocalMachine, empty, output); got != 2 {
		t.Fatalf("RegOpenKeyA(empty) = %d, want ERROR_FILE_NOT_FOUND", got)
	}
	if got := call("advapi32.dll", "RegOpenKeyA", hkeyLocalMachine, occupied, output); got != 0 {
		t.Fatalf("RegOpenKeyA(occupied) = %d, want ERROR_SUCCESS", got)
	}
}

func TestKernelPluginModelsNativeHeapAndResourceAPIs(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:win32.star")
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := starlark.Call(thread, module["kernel32_plugin"], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	if _, err := machine.UseBuiltin(thread, nil, starlark.Tuple{plugin}, nil); err != nil {
		t.Fatal(err)
	}
	call := func(name string, args ...uint32) uint32 {
		address := machine.ResolveExport("ntdll.dll", name, 0, 0)
		value, err := machine.CallAddress(thread, address, args)
		if err != nil {
			t.Fatal(err)
		}
		result := value.(*starlarkRecord)
		if got := recordString(t, result, "reason"); got != "return" {
			t.Fatalf("%s stopped with %s: %s", name, got, recordString(t, result, "detail"))
		}
		return recordUint32(t, result, "value")
	}

	heap := call("RtlCreateHeap", 0, 0, 0, 0, 0, 0)
	if heap == 0 {
		t.Fatal("RtlCreateHeap returned null")
	}
	allocation := call("RtlAllocateHeap", heap, 0, 32)
	if allocation == 0 {
		t.Fatal("RtlAllocateHeap returned null")
	}
	if got := call("RtlSizeHeap", heap, 0, allocation); got != 32 {
		t.Fatalf("RtlSizeHeap = %d, want 32", got)
	}
	if got := call("RtlFreeHeap", heap, 0, allocation); got != 1 {
		t.Fatalf("RtlFreeHeap = %d, want TRUE", got)
	}
	if got := call("RtlDestroyHeap", heap); got != 0 {
		t.Fatalf("RtlDestroyHeap = %#x, want null", got)
	}

	resourceValue, err := machine.AllocateBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("size"), starlark.MakeInt(56)},
	})
	if err != nil {
		t.Fatal(err)
	}
	resource64, _ := resourceValue.(starlark.Int).Uint64()
	resource := uint32(resource64)
	call("RtlInitializeResource", resource)
	if got := call("RtlAcquireResourceExclusive", resource, 1); got != 1 {
		t.Fatalf("RtlAcquireResourceExclusive = %d, want TRUE", got)
	}
	call("RtlReleaseResource", resource)
	if got := call("RtlAcquireResourceShared", resource, 1); got != 1 {
		t.Fatalf("RtlAcquireResourceShared = %d, want TRUE", got)
	}
	call("RtlReleaseResource", resource)
	call("RtlDeleteResource", resource)
}

func TestRegistryPluginMapsHKLMSoftwareToSoftwareHiveRoot(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:registry.star")
	if err != nil {
		t.Fatal(err)
	}
	value, err := starlark.Call(thread, module["_join_key"], starlark.Tuple{
		starlark.Tuple{starlark.String("SOFTWARE"), starlark.String("/")},
		starlark.String(`Software\Microsoft\MMC`),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := value.(starlark.Tuple)
	if got, _ := starlark.AsString(result[1]); got != "/Microsoft/MMC" {
		t.Fatalf("HKLM Software path = %q, want /Microsoft/MMC", got)
	}
}

func TestRPCProxyPluginParsesProxyFileInfo(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	registryModule, err := thread.Load(thread, "@stdlib//windows/selfreg:registry.star")
	if err != nil {
		t.Fatal(err)
	}
	rpcModule, err := thread.Load(thread, "@stdlib//windows/selfreg:rpcrt.star")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := starlark.Call(thread, registryModule["registry_plugin"], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rpc, err := starlark.Call(thread, rpcModule["rpc_proxy_plugin"], starlark.Tuple{registry, starlark.String(`C:\WINDOWS\system32\proxy.dll`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	if _, err := machine.UseBuiltin(thread, nil, starlark.Tuple{starlark.NewList([]starlark.Value{registry, rpc})}, nil); err != nil {
		t.Fatal(err)
	}
	allocate := func(data []byte) uint32 {
		value, err := machine.AllocateBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("value"), starlark.Bytes(data)}})
		if err != nil {
			t.Fatal(err)
		}
		address, _ := value.(starlark.Int).Uint64()
		return uint32(address)
	}
	words := func(values ...uint32) []byte {
		data := make([]byte, len(values)*4)
		for index, value := range values {
			data[index*4] = byte(value)
			data[index*4+1] = byte(value >> 8)
			data[index*4+2] = byte(value >> 16)
			data[index*4+3] = byte(value >> 24)
		}
		return data
	}

	iid := allocate([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	clsid := allocate([]byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01})
	name := allocate([]byte("ITest\x00"))
	proxyVtbl := allocate(words(0, iid))
	proxyVtbls := allocate(words(proxyVtbl, 0))
	names := allocate(words(name, 0))
	info := allocate(words(proxyVtbls, 0, names, 0, 0, 2<<16|1))
	files := allocate(words(info, 0))
	address := machine.ResolveExport("rpcrt4.dll", "NdrDllRegisterProxy", 0, 0)
	resultValue, err := machine.CallAddress(thread, address, []uint32{0, files, clsid})
	if err != nil {
		t.Fatal(err)
	}
	result := resultValue.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("reason = %q, detail = %s", got, recordString(t, result, "detail"))
	}
	patchesMethod, _ := registry.(starlark.HasAttrs).Attr("patches")
	patchesValue, err := starlark.Call(thread, patchesMethod.(starlark.Callable), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	patches := patchesValue.(*starlark.List)
	if patches.Len() != 5 {
		t.Fatalf("captured %d patches, want 5: %v", patches.Len(), patches)
	}
	interfacePatch := patches.Index(3).(*starlark.Dict)
	key, _, _ := interfacePatch.Get(starlark.String("key"))
	if got, _ := starlark.AsString(key); got != "/Classes/Interface/{33221100-5544-7766-8899-AABBCCDDEEFF}" {
		t.Fatalf("interface key = %q", got)
	}

	otherCLSID := allocate([]byte{0x11, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01})
	output := allocate(words(0xdeadbeef))
	address = machine.ResolveExport("rpcrt4.dll", "NdrDllGetClassObject", 0, 0)
	resultValue, err = machine.CallAddress(thread, address, []uint32{otherCLSID, iid, output, files, clsid, 0})
	if err != nil {
		t.Fatal(err)
	}
	result = resultValue.(*starlarkRecord)
	if got := recordUint32(t, result, "value"); got != 0x80040111 {
		t.Fatalf("NdrDllGetClassObject mismatch result = %#x, want CLASS_E_CLASSNOTAVAILABLE", got)
	}
	stored, err := machine.ReadMemory(output, 4, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, []byte{0, 0, 0, 0}) {
		t.Fatalf("NdrDllGetClassObject output = %x, want zero", stored)
	}
}

func TestOLE32CoCreateInstanceExMarshalsMultipleInterfaces(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:win32.star")
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := starlark.Call(thread, module["ole32_plugin"], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	if _, err := machine.UseBuiltin(thread, nil, starlark.Tuple{plugin}, nil); err != nil {
		t.Fatal(err)
	}
	allocate := func(data []byte) uint32 {
		value, err := machine.AllocateBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("value"), starlark.Bytes(data)}})
		if err != nil {
			t.Fatal(err)
		}
		address, _ := value.(starlark.Int).Uint64()
		return uint32(address)
	}
	words := func(values ...uint32) []byte {
		data := make([]byte, len(values)*4)
		for index, value := range values {
			data[index*4] = byte(value)
			data[index*4+1] = byte(value >> 8)
			data[index*4+2] = byte(value >> 16)
			data[index*4+3] = byte(value >> 24)
		}
		return data
	}

	gitClass := allocate([]byte{0x23, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46})
	gitIID := allocate([]byte{0x46, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46})
	unsupportedIID := allocate([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	results := allocate(words(gitIID, 0xdeadbeef, 0xdeadbeef, unsupportedIID, 0xdeadbeef, 0xdeadbeef))
	address := machine.ResolveExport("ole32.dll", "CoCreateInstanceEx", 0, 0)
	if address == 0 {
		t.Fatal("missing semantic CoCreateInstanceEx export")
	}
	value, err := machine.CallAddress(thread, address, []uint32{gitClass, 0, 1, 0, 2, results})
	if err != nil {
		t.Fatal(err)
	}
	result := value.(*starlarkRecord)
	if got := recordString(t, result, "reason"); got != "return" {
		t.Fatalf("CoCreateInstanceEx stopped with %s: %s", got, recordString(t, result, "detail"))
	}
	stored, err := machine.ReadMemory(results, 24, 'r')
	if err != nil {
		t.Fatal(err)
	}
	if got := recordUint32(t, result, "value"); got != 0x00080012 {
		state, _ := plugin.(starlark.HasAttrs).Attr("state")
		t.Fatalf("CoCreateInstanceEx returned %#x, want CO_S_NOTALLINTERFACES; MULTI_QI = %x; state = %s", got, stored, state)
	}
	if pointer := uint32(stored[4]) | uint32(stored[5])<<8 | uint32(stored[6])<<16 | uint32(stored[7])<<24; pointer == 0 {
		t.Fatal("supported MULTI_QI entry has a null interface")
	}
	if hr := uint32(stored[8]) | uint32(stored[9])<<8 | uint32(stored[10])<<16 | uint32(stored[11])<<24; hr != 0 {
		t.Fatalf("supported MULTI_QI HRESULT = %#x, want S_OK", hr)
	}
	if pointer := uint32(stored[16]) | uint32(stored[17])<<8 | uint32(stored[18])<<16 | uint32(stored[19])<<24; pointer != 0 {
		t.Fatalf("unsupported MULTI_QI interface = %#x, want null", pointer)
	}
	if hr := uint32(stored[20]) | uint32(stored[21])<<8 | uint32(stored[22])<<16 | uint32(stored[23])<<24; hr != 0x80004002 {
		t.Fatalf("unsupported MULTI_QI HRESULT = %#x, want E_NOINTERFACE", hr)
	}
}

func TestOLE32HGlobalStreamGrowsAndReturnsCurrentHandle(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "@stdlib//windows/selfreg:win32.star")
	if err != nil {
		t.Fatal(err)
	}
	kernel, err := starlark.Call(thread, module["kernel32_plugin"], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := starlark.Call(thread, module["ole32_plugin"], nil, []starlark.Tuple{
		{starlark.String("kernel"), kernel},
	})
	if err != nil {
		t.Fatal(err)
	}
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	if _, err := machine.UseBuiltin(thread, nil, starlark.Tuple{starlark.NewList([]starlark.Value{kernel, plugin})}, nil); err != nil {
		t.Fatal(err)
	}
	allocate := func(data []byte) uint32 {
		value, err := machine.AllocateBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("value"), starlark.Bytes(data)}})
		if err != nil {
			t.Fatal(err)
		}
		address, _ := value.(starlark.Int).Uint64()
		return uint32(address)
	}
	call := func(address uint32, args ...uint32) *starlarkRecord {
		value, err := machine.CallAddress(thread, address, args)
		if err != nil {
			t.Fatal(err)
		}
		result := value.(*starlarkRecord)
		if got := recordString(t, result, "reason"); got != "return" {
			t.Fatalf("call %#x stopped with %s: %s", address, got, recordString(t, result, "detail"))
		}
		return result
	}
	readU32 := func(address uint32) uint32 {
		data, err := machine.ReadMemory(address, 4, 'r')
		if err != nil {
			t.Fatal(err)
		}
		return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	}

	output := allocate(make([]byte, 4))
	create := machine.ResolveExport("ole32.dll", "CreateStreamOnHGlobal", 0, 0)
	if got := recordUint32(t, call(create, 0, 1, output), "value"); got != 0 {
		t.Fatalf("CreateStreamOnHGlobal returned %#x", got)
	}
	stream := readU32(output)
	vtable := readU32(stream)
	write := readU32(vtable + 4*4)
	payload := []byte("growing stream payload")
	payloadAddress := allocate(payload)
	written := allocate(make([]byte, 4))
	if got := recordUint32(t, call(write, stream, payloadAddress, uint32(len(payload)), written), "value"); got != 0 {
		t.Fatalf("IStream::Write returned %#x", got)
	}
	if got := readU32(written); got != uint32(len(payload)) {
		t.Fatalf("IStream::Write wrote %d bytes, want %d", got, len(payload))
	}
	handleOutput := allocate(make([]byte, 4))
	getHandle := machine.ResolveExport("ole32.dll", "GetHGlobalFromStream", 0, 0)
	if got := recordUint32(t, call(getHandle, stream, handleOutput), "value"); got != 0 {
		t.Fatalf("GetHGlobalFromStream returned %#x", got)
	}
	handle := readU32(handleOutput)
	stored, err := machine.ReadMemory(handle, len(payload), 'r')
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, payload) {
		t.Fatalf("HGLOBAL contents = %q, want %q", stored, payload)
	}
}

func TestCryptoRegistrationPluginParsesPublicStructures(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	registryModule, err := thread.Load(thread, "@stdlib//windows/selfreg:registry.star")
	if err != nil {
		t.Fatal(err)
	}
	cryptoModule, err := thread.Load(thread, "@stdlib//windows/selfreg:crypto.star")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := starlark.Call(thread, registryModule["registry_plugin"], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cryptoPlugin, err := starlark.Call(thread, cryptoModule["crypto_registration_plugin"], starlark.Tuple{
		registry, starlark.String(`C:\WINDOWS\system32\example.dll`),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	machine := newRawX86TestMachine(t, starlark.Bytes("\xc3"), nil)
	if _, err := machine.UseBuiltin(thread, nil, starlark.Tuple{cryptoPlugin}, nil); err != nil {
		t.Fatal(err)
	}
	allocate := func(data []byte) uint32 {
		value, err := machine.AllocateBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("value"), starlark.Bytes(data)}})
		if err != nil {
			t.Fatal(err)
		}
		address, _ := value.(starlark.Int).Uint64()
		return uint32(address)
	}
	words := func(values ...uint32) []byte {
		data := make([]byte, len(values)*4)
		for index, value := range values {
			data[index*4] = byte(value)
			data[index*4+1] = byte(value >> 8)
			data[index*4+2] = byte(value >> 16)
			data[index*4+3] = byte(value >> 24)
		}
		return data
	}
	call := func(module, name string, args ...uint32) *starlarkRecord {
		address := machine.ResolveExport(module, name, 0, 0)
		if address == 0 {
			t.Fatalf("missing semantic export %s!%s", module, name)
		}
		value, err := machine.CallAddress(thread, address, args)
		if err != nil {
			t.Fatal(err)
		}
		result := value.(*starlarkRecord)
		if got := recordString(t, result, "reason"); got != "return" {
			t.Fatalf("%s!%s stopped with %s: %s", module, name, got, recordString(t, result, "detail"))
		}
		return result
	}

	guid := allocate([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	dll := allocate(selfregUTF16Bytes("EXAMPLE.DLL\x00"))
	trustFunction := allocate(selfregUTF16Bytes("TrustInitialize\x00"))
	trustInfo := make([]byte, 4+8*12)
	copy(trustInfo, words(uint32(len(trustInfo))))
	copy(trustInfo[4:], words(12, dll, trustFunction))
	call("wintrust.dll", "WintrustAddActionID", guid, 0, allocate(trustInfo))
	usage := allocate([]byte("1.3.6.1.5.5.7.3.3\x00"))
	defaultUsage := allocate(words(20, guid, 0, 0, 0))
	result := call("wintrust.dll", "WintrustAddDefaultForUsage", usage, defaultUsage)
	if got := recordUint32(t, result, "value"); got != 1 {
		t.Fatalf("WintrustAddDefaultForUsage returned %d, want 1", got)
	}

	sipFunction := allocate(selfregUTF16Bytes("SIPIsMyFileType\x00"))
	sipInfo := make([]byte, 0x2c)
	copy(sipInfo, words(0x2c, guid, dll, 0, sipFunction))
	call("crypt32.dll", "CryptSIPAddProvider", allocate(sipInfo))

	oidFunction := allocate([]byte("CryptDllDecodeObject\x00"))
	oid := allocate([]byte("1.2.3.4\x00"))
	override := allocate([]byte("DecodeExample\x00"))
	call("crypt32.dll", "CryptRegisterOIDFunction", 1, oidFunction, oid, dll, override)
	crlFlags := allocate(words(3))
	result = call("crypt32.dll", "CertGetCRLFromStore", 0, 0, 0, crlFlags)
	if got := recordUint32(t, result, "value"); got != 0 {
		t.Fatalf("CertGetCRLFromStore returned %#x, want no CRL", got)
	}

	patchesMethod, _ := registry.(starlark.HasAttrs).Attr("patches")
	patchesValue, err := starlark.Call(thread, patchesMethod.(starlark.Callable), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	patches := patchesValue.(*starlark.List)
	guidText := "{33221100-5544-7766-8899-AABBCCDDEEFF}"
	if got := selfregPatchValue(t, patches, "/Microsoft/Cryptography/Providers/Trust/Initialization/"+guidText, "$Function"); got != "TrustInitialize" {
		t.Fatalf("trust function = %q", got)
	}
	if got := selfregPatchValue(t, patches, "/Microsoft/Cryptography/OID/EncodingType 0/CryptSIPDllIsMyFileType/"+guidText, "FuncName"); got != "SIPIsMyFileType" {
		t.Fatalf("SIP function = %q", got)
	}
	if got := selfregPatchValue(t, patches, "/Microsoft/Cryptography/OID/EncodingType 1/CryptDllDecodeObject/1.2.3.4", "FuncName"); got != "DecodeExample" {
		t.Fatalf("OID override = %q", got)
	}
}

func syntheticRegistryClientPE(t *testing.T) starlark.Bytes {
	t.Helper()
	section := make([]byte, 0)
	fixups := starlark.NewList(nil)
	push := func(value uint32) {
		section = append(section, 0x68, byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
	}
	fixup := func(prefix []byte, label string) {
		section = append(section, prefix...)
		offset := len(section)
		section = append(section, 0, 0, 0, 0)
		if err := fixups.Append(peFixupValue(t, offset, label)); err != nil {
			t.Fatal(err)
		}
	}

	fixup([]byte{0x68}, "disposition")
	fixup([]byte{0x68}, "result")
	for range 5 {
		push(0)
	}
	fixup([]byte{0x68}, "key")
	push(0x80000000)
	fixup([]byte{0xff, 0x15}, "iat:ADVAPI32.dll:RegCreateKeyExW")
	push(uint32(len(selfregUTF16Bytes("hello\x00"))))
	fixup([]byte{0x68}, "data")
	push(1)
	push(0)
	fixup([]byte{0x68}, "name")
	fixup([]byte{0xff, 0x35}, "result")
	fixup([]byte{0xff, 0x15}, "iat:ADVAPI32.dll:RegSetValueExW")
	section = append(section, 0xc3)

	labels := starlark.NewDict(5)
	_ = labels.SetKey(starlark.String("entry"), starlark.MakeInt(0))
	for name, data := range map[string][]byte{
		"key": selfregUTF16Bytes("Example\x00"), "name": selfregUTF16Bytes("Greeting\x00"), "data": selfregUTF16Bytes("hello\x00"),
		"result": make([]byte, 4), "disposition": make([]byte, 4),
	} {
		_ = labels.SetKey(starlark.String(name), starlark.MakeInt(len(section)))
		section = append(section, data...)
	}
	imports := starlark.NewDict(1)
	_ = imports.SetKey(starlark.String("ADVAPI32.dll"), starlark.NewList([]starlark.Value{
		starlark.String("RegCreateKeyExW"), starlark.String("RegSetValueExW"),
	}))
	value, err := callWindowsRuntime(t, "pe32_executable", starlark.Tuple{starlark.Bytes(section), labels, fixups}, []starlark.Tuple{
		{starlark.String("imports"), imports},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value.(starlark.Bytes)
}

func syntheticLoadLibraryClientPE(t *testing.T) starlark.Bytes {
	t.Helper()
	section := []byte{
		0x68, 0, 0, 0, 0,
		0xff, 0x15, 0, 0, 0, 0,
		0xc3,
	}
	labels := starlark.NewDict(2)
	_ = labels.SetKey(starlark.String("entry"), starlark.MakeInt(0))
	_ = labels.SetKey(starlark.String("module"), starlark.MakeInt(len(section)))
	section = append(section, "deferred.dll\x00"...)
	fixups := starlark.NewList([]starlark.Value{
		peFixupValue(t, 1, "module"),
		peFixupValue(t, 7, "iat:KERNEL32.dll:LoadLibraryA"),
	})
	imports := starlark.NewDict(1)
	_ = imports.SetKey(starlark.String("KERNEL32.dll"), starlark.NewList([]starlark.Value{
		starlark.String("LoadLibraryA"),
	}))
	value, err := callWindowsRuntime(t, "pe32_executable", starlark.Tuple{starlark.Bytes(section), labels, fixups}, []starlark.Tuple{
		{starlark.String("imports"), imports},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value.(starlark.Bytes)
}

func selfregUTF16Bytes(value string) []byte {
	units := utf16.Encode([]rune(value))
	output := make([]byte, len(units)*2)
	for index, unit := range units {
		output[index*2] = byte(unit)
		output[index*2+1] = byte(unit >> 8)
	}
	return output
}
