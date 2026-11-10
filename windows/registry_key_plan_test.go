package windows_test

import (
	binaryapi "github.com/tinyrange/trex/binary/star"
	"github.com/tinyrange/trex/windows"
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestRegistryKeyPlanRejectsInvalidContracts(t *testing.T) {
	prefix := registryCollectorPrelude + `
r = collect([row('')],resolve,expand,capture_key_records=True,compact_key_records=True)["key_records"]
families = [(1,None,b"after")]
def compile(text): return b"descriptor"
def matches(before,after): return True
`
	cases := []struct{ code, want string }{
		{`collect([row('')],resolve,expand,compact_key_records=True)`, "requires capture_key_records"},
		{`plan({},families,{},compile,matches)`, "registry_key_records"},
		{`plan(r,[],{},compile,matches)`, "no family bucket"},
		{`plan(r,[(1,None,None)],{},compile,matches)`, "no component identity"},
		{`plan(r,[(1,None,{})],{},compile,matches)`, "identities"},
		{`plan(r,[(-1,None,b"after")],{},compile,matches)`, "family bucket"},
		{`plan(r,[(1,None)],{},compile,matches)`, "families require"},
		{`plan(r,families,{"path":True},compile,matches)`, "(scope,path)"},
		{`plan(r,families,{("system",r"\registry\machine\software\fixture"):1},compile,matches)`, "invalid registry value change"},
		{`plan(r,families,{("system",r"\registry\machine\software"):True},compile,matches)`, "no corresponding admitted key"},
		{`plan(r,families,{},compile,lambda a,b: None)`, "must return bool"},
		{`result=plan(r,families,{},compile,matches)
result["system"][r"\registry\machine\software\fixture"]["security_flags"]=0`, "does not support item assignment"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			_, err := starlark.ExecFile(&starlark.Thread{Name: "compact-registry-contract"}, "fixture.star", prefix+tc.code,
				starlark.StringDict{"xml": binaryapi.Builtins()["xml"], "collect": windows.Builtins()["registry_contributions"], "mapper": windows.Builtins()["registry_path_mapper"], "plan": windows.Builtins()["registry_key_plan"]})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
