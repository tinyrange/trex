package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestCBSInitialComponentsBaselineJoin(t *testing.T) {
	source := `
name = "Parent~31bf3856ad364e35~amd64~~10.0.26100.1"
manifest = b'<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Parent" version="10.0.26100.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package><update name="Feature"><component><assemblyIdentity name="Payload" version="10.0.1.2" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" type="win32" versionScope="nonSxS"/></component><driver><assemblyIdentity name="Payload" version="10.0.1.2" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" type="win32" versionScope="nonSxS"/></driver></update><update name="Empty"/></package></assembly>'
index = make_index([dict(manifest=manifest,intended_state=0)])
payload = make_source(manifest,"Feature")
identity = b'PAYLOAD, Culture=none, Type=WIN32, Version=10.0.1.2, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=AMD64, versionScope=NonSxS'
def check():
    values = dict(appid=identity)
    deployments = {"key": values}
    if index.initial_component_states(deployments,[name])[name] != {"feature":[0,0],"empty":[]}:
        fail("absent join")
    for prefix, expected in [("p!",32),("s!",64),("i!",112)]:
        values[prefix+"arbitrary"] = payload
        result = index.initial_component_states(deployments,[name])
        if result[name]["feature"] != [expected,expected]:
            fail("source precedence", result)
    old = result
    values.pop("i!arbitrary")
    if index.initial_component_states(deployments,[name])[name]["feature"] != [64,64] or old[name]["feature"] != [112,112]:
        fail("baseline/result isolation")
    if index.initial_component_states(deployments,[name.lower()])[name.lower()]["feature"] != [0,0]:
        fail("primary binding must be case-sensitive")
    values["appid"] = b'PAYLOAD, Culture=none, Type=other, Version=10.0.1.2, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=AMD64, versionScope=NonSxS'
    if index.initial_component_states(deployments,[name])[name]["feature"] != [0,0]:
        fail("type was discarded")
    values["appid"] = identity
    return deployments
baseline = check()
`
	globals, err := starlark.ExecFile(&starlark.Thread{Name: t.Name()}, "initial.star", source, starlark.StringDict{
		"make_index": starlark.NewBuiltin("make_index", cbsUpdateIndexBuiltin), "make_source": starlark.NewBuiltin("make_source", cbsDeploymentSourceDataBuiltin),
	})
	if err != nil {
		t.Fatal(err)
	}
	fn, err := globals["index"].(starlark.HasAttrs).Attr("initial_component_states")
	if err != nil {
		t.Fatal(err)
	}
	call := func(d starlark.Value, names starlark.Value) error {
		_, err := starlark.Call(&starlark.Thread{}, fn.(starlark.Callable), starlark.Tuple{d, names}, nil)
		return err
	}
	names := starlark.NewList([]starlark.Value{globals["name"]})
	fields := starlark.NewDict(2)
	_ = fields.SetKey(starlark.String("appid"), globals["identity"])
	_ = fields.SetKey(starlark.String("p!bad"), starlark.Bytes("invalid"))
	bad := starlark.NewDict(1)
	_ = bad.SetKey(starlark.String("bad"), fields)
	if call(bad, names) == nil {
		t.Fatal("malformed source accepted")
	}
	if call(globals["baseline"], starlark.NewList([]starlark.Value{globals["name"], globals["name"]})) == nil {
		t.Fatal("duplicate package accepted")
	}
	baseline := globals["baseline"].(*starlark.Dict)
	value, _, _ := baseline.Get(starlark.String("key"))
	duplicates := starlark.NewDict(2)
	if err := duplicates.SetKey(starlark.String("first"), value); err != nil {
		t.Fatal(err)
	}
	if err := duplicates.SetKey(starlark.String("second"), value); err != nil {
		t.Fatal(err)
	}
	if call(duplicates, names) == nil {
		t.Fatal("ambiguous deployment accepted")
	}
}
