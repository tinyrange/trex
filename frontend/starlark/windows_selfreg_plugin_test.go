package starlarkfrontend

import (
	"bytes"
	"testing"
	"unicode/utf16"

	binaryapi "github.com/tinyrange/trex/binary"
	"go.starlark.net/starlark"
)

func testStarlarkStringDict(values map[string]starlark.Value) *starlark.Dict {
	dict := starlark.NewDict(len(values))
	for name, value := range values {
		_ = dict.SetKey(starlark.String(name), value)
	}
	return dict
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
