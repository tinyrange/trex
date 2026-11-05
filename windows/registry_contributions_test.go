package windows_test

import (
	"strings"
	"testing"

	binaryapi "github.com/tinyrange/trex/binary/star"
	"github.com/tinyrange/trex/windows"
	"go.starlark.net/starlark"
)

func registryCollectorScript(t *testing.T, source string) (starlark.StringDict, error) {
	t.Helper()
	return starlark.ExecFile(&starlark.Thread{Name: "registry-collector-test"}, "fixture.star", source,
		starlark.StringDict{"xml": binaryapi.Builtins()["xml"], "collect": windows.Builtins()["registry_contributions"], "mapper": windows.Builtins()["registry_path_mapper"]})
}

const registryCollectorPrelude = `
resolve = mapper([(r"\registry\machine\software", 3)])
def expand(value, architecture):
    return value.replace("$(fixture)", architecture)
def row(body, side="after", owner=0, architecture="amd64"):
    root = xml('<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><registryKeys><registryKey keyName="HKLM\u005cSoftware\u005cFixture">'+body+'</registryKey></registryKeys></assembly>').root
    return dict(root=root, side=side, owner=owner, architecture=architecture)
`

func TestRegistryContributionsPreserveOrderAndRawData(t *testing.T) {
	globals, err := registryCollectorScript(t, registryCollectorPrelude+`
body = '<registryValue name="Word" valueType="REG_DWORD" value="-1"/><registryValue name="List" valueType="REG_MULTI_SZ" value="&quot;A&quot;,&quot;&quot;,&quot;B&quot;"/><registryValue name="Empty" valueType="REG_MULTI_SZ" value=""/><registryValue name="Quoted" valueType="REG_MULTI_SZ" value="&quot;&quot;"/><registryValue name="None" valueType="REG_NONE" value="$(unresolved)"/><registryValue name="$(fixture)" valueType="REG_SZ" value="É😀"/>'
inputs = [row(body, "before", 7), row(body, "after", 2), row(body, "after", 9)]
r = collect(inputs, resolve, expand, key_prefix="")
g = r["groups"]
prefix = ("system", r"\registry\machine\software\fixture")
assertions = [
    g[prefix+("word",)] == [[(7,4,b"\xff\xff\xff\xff","false","",False)],[(2,4,b"\xff\xff\xff\xff","false","",False),(9,4,b"\xff\xff\xff\xff","false","",False)]],
    g[prefix+("list",)][0][0][2] == b"A\x00\x00\x00B\x00\x00\x00\x00\x00",
    g[prefix+("empty",)][0][0][2:] == (b"\x00\x00\x00\x00","false","",True),
    g[prefix+("quoted",)][0][0][2:] == (b"\x00\x00\x00\x00","false","",False),
    g[prefix+("none",)][0][0][2] == b"",
    g[prefix+("amd64",)][0][0][2] == b"\xc9\x00\x3d\xd8\x00\xde\x00\x00",
    r["keys"][prefix] == [r"\Registry\Machine\Software\Fixture",True,True],
]
# Returned mutable projections do not alias later invocations or the XML.
g[prefix+("word",)][1].clear()
fresh = collect(inputs, resolve, expand)
assertions.append(len(fresh["groups"][prefix+("word",)][1]) == 2)
# Side-specific architecture is a decoding/path-cache input.
x86 = collect([row(body, "after", 0, "x86")], resolve, expand)
assertions.append(("system",r"\registry\machine\software\wow6432node\fixture","x86") in x86["groups"])
`)
	if err != nil {
		t.Fatal(err)
	}
	for assertion := range globals["assertions"].(*starlark.List).Elements() {
		if assertion != starlark.True {
			t.Fatal("collector invariant failed:", globals["assertions"])
		}
	}
}

func TestRegistryContributionsArchitectureIsResolvedOnlyForKeys(t *testing.T) {
	_, err := registryCollectorScript(t, registryCollectorPrelude+`
root = xml('<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><file name="managed.dll"/></assembly>').root
collect([dict(root=root,architecture="msil",side="after",owner=0)],resolve,expand)
`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = registryCollectorScript(t, registryCollectorPrelude+`collect([row('',architecture="msil")],resolve,expand)`)
	if err == nil || !strings.Contains(err.Error(), "unsupported registry architecture") {
		t.Fatal("key bypassed mapper validation:", err)
	}
}

func TestRegistryContributionsRejectBeforeReturningPartialResults(t *testing.T) {
	tests := []struct{ code, want string }{
		{`collect([row('<registryValue name="x" valueType="REG_DWORD" value="4294967296"/>')],resolve,expand)`, "invalid DWORD"},
		{`collect([row('<registryValue name="x" valueType="REG_SZ" value="x" extra="x"/>')],resolve,expand)`, "unsupported registry value preparation attributes"},
		{`collect([row('<registryValue name="x" name="y" valueType="REG_SZ" value="x"/>')],resolve,expand)`, "duplicate attribute"},
		{`collect([row('<registryValue xmlns:q="foreign" q:name="x" valueType="REG_SZ" value="x"/>')],resolve,expand)`, "unsupported attribute namespace"},
		{`collect([row('<registryValue name="x" valueType="REG_SZ" value="x"><child/></registryValue>')],resolve,expand)`, "unsupported registryValue content"},
		{`collect([row('<securityDescriptor name="missing"/>')],resolve,expand)`, "unresolved runtime registry security reference"},
		{`collect([row('')],resolve,expand,max_records=1)`, "record bound"},
		{`collect([row('')],resolve,expand,max_bytes=1)`, "byte bound"},
		{`collect([row('')],resolve,expand,max_records=0)`, "invalid limits"},
		{`collect([row('')],resolve,expand,max_bytes=268435457)`, "invalid limits"},
		{`collect([dict(root={},side="after",owner=0,architecture="amd64")],resolve,expand)`, "binary.xml_node"},
		{`collect([row('')],lambda k,a: {},expand)`, "missing argument"},
		{`collect([row('<registryValue name="$(fixture)" valueType="REG_SZ" value="x"/>')],resolve,lambda v,a: [])`, "NUL-free string"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			_, err := registryCollectorScript(t, registryCollectorPrelude+tc.code)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}
}

func TestRegistryContributionsKeySecurityIsLocalAndOrdered(t *testing.T) {
	globals, err := registryCollectorScript(t, registryCollectorPrelude+`
def secured(sddl, side, owner, architecture):
    header = '<trustInfo><security><accessControl><securityDescriptorDefinitions><securityDescriptorDefinition name="local" sddl="'+sddl+'"/></securityDescriptorDefinitions></accessControl></security></trustInfo>'
    body = '<registryKeys><registryKey keyName="HKLM\u005cSoftware\u005cFixture" owner="true"><securityDescriptor name="local"/></registryKey><registryKey keyName="HKLM\u005cSoftware\u005cEmpty"/></registryKeys>'
    root = xml('<assembly xmlns="urn:schemas-microsoft-com:asm.v3">'+header+body+'</assembly>').root
    return dict(root=root, side=side, owner=owner, architecture=architecture)
inputs = [secured("D:(A;;KA;;;SY)","before",7,"amd64"),secured("D:(A;;KR;;;SY)","after",7,"amd64"),secured("D:","after",2,"x86")]
r = collect(inputs,resolve,expand,key_prefix="not-a-match",capture_key_records=True)
rows = r["key_records"]
assertions = [
    r["keys"] == {},
    r["groups"] == {},
    len(rows[7]) == 4,
    [v[0] for v in rows[7]] == ["before","before","after","after"],
    rows[7][0][1:] == ("system",r"\Registry\Machine\Software\Fixture",dict(keyName=r"HKLM\Software\Fixture",owner="true"),"D:(A;;KA;;;SY)"),
    rows[7][2][4] == "D:(A;;KR;;;SY)",
    rows[7][1][4] == None,
    rows[2][0][2] == r"\Registry\Machine\Software\WOW6432Node\Fixture",
    "key_records" not in collect(inputs,resolve,expand),
]
rows[7][0][3]["owner"] = "false"
assertions.append(collect(inputs,resolve,expand,capture_key_records=True)["key_records"][7][0][3]["owner"] == "true")
`)
	if err != nil {
		t.Fatal(err)
	}
	for assertion := range globals["assertions"].(*starlark.List).Elements() {
		if assertion != starlark.True {
			t.Fatal("key capture invariant failed:", globals["assertions"])
		}
	}
}
