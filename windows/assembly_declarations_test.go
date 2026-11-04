package windows_test

import (
	binaryapi "github.com/tinyrange/trex/binary/star"
	"github.com/tinyrange/trex/windows"
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

const declarationFixture = `
root = xml(r'''<assembly xmlns="urn:schemas-microsoft-com:asm.v3" xmlns:x="foreign">
 <assemblyIdentity processorArchitecture="amd64"/><x:assemblyIdentity processorArchitecture="ignored"/>
 <file name="one" destinationName="" compress="false"><gac/><securityDescriptor name="local"/><link destination="$(runtime.system32)\one"/><x:link/></file>
 <file name="two"><x:gac/><link destination="two"><x:child/></link></file>
 <file/>
 <directories><directory destinationPath="raw" owner="true"><securityDescriptor name="local"/></directory><unknown/><x:directory/></directories>
 <trustInfo><security><accessControl><securityDescriptorDefinitions><securityDescriptorDefinition name="local" sddl="(inherit)" operationHint="replace"/></securityDescriptorDefinitions></accessControl></security></trustInfo>
 <memberships><categoryMembership><id name="category" typeName="raw" version="1" publicKeyToken="token"/><id name="duplicate"/></categoryMembership></memberships>
</assembly>''').root
r = collect(root)
`

func declarationScript(source string) (starlark.StringDict, error) {
	return starlark.ExecFile(&starlark.Thread{Name: "assembly-declarations"}, "fixture.star", source, starlark.StringDict{"xml": binaryapi.Builtins()["xml"], "collect": windows.Builtins()["assembly_declarations"]})
}
func TestAssemblyDeclarationsPreserveRawNamespaceAndOrder(t *testing.T) {
	globals, err := declarationScript(declarationFixture + `
checks = [
 r.architectures == ("amd64",), r.managed_assembly,
 [f.name for f in r.files] == ["one","two",None],
 r.files[0].destination_name == "", r.files[1].destination_name == None,
 r.files[0].compress == "false", r.files[1].compress == "true",
 len(r.files[0].links) == 1, not r.files[0].links[0].has_content, r.files[1].links[0].has_content,
 r.files[0].security_references[0].name == "local",
 [d.tag for d in r.directories] == ["directory","unknown"],
 r.directories[0].security_references[0].name == "local",
 r.security_definitions[0].sddl == "(inherit)", r.security_definitions[0].operation_hint == "replace",
 len(r.memberships[0]) == 2, r.memberships[0][1].name == "duplicate",
]
`)
	if err != nil {
		t.Fatal(err)
	}
	for item := range globals["checks"].(*starlark.List).Elements() {
		if item != starlark.True {
			t.Fatal(globals["checks"])
		}
	}
	for _, mutation := range []string{`r.directories[0].attributes.clear()`, `r.directories[0].attributes[0]["value"]="changed"`} {
		if _, err := declarationScript(declarationFixture + mutation); err == nil || !strings.Contains(err.Error(), "frozen") {
			t.Fatal("mutable projection", err)
		}
	}
	for _, source := range []string{`collect({})`, `collect(xml('<assembly xmlns="foreign"/>').root)`} {
		if _, err := declarationScript(source); err == nil {
			t.Fatal("invalid declaration source accepted")
		}
	}
}
