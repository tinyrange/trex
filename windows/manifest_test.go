package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestAssemblyManifestClosurePolicyInspection(t *testing.T) {
	const text = `<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="component"/><deployment impact="patch"/><dependency discoverable="no" resourceType="Resources"><dependentAssembly dependencyType="prerequisite"><assemblyIdentity name="resource" language="*"/></dependentAssembly></dependency><dependency><dependentAssembly><assemblyIdentity name="policy"/><bindingRedirect xmlns="urn:schemas-microsoft-com:asm.v1" oldVersion="1.0.0.0-2.0.0.0" newVersion="2.0.0.0"/></dependentAssembly></dependency></assembly>`
	_, err := starlark.ExecFile(&starlark.Thread{}, "manifest.star", `
def check():
    m = parse(source)
    if len(m.deployment) != 1 or m.deployment[0].name != "impact" or m.deployment[0].value != "patch":
        fail("deployment impact lost")
    r = m.references[0]
    if r.kind != "dependentAssembly" or r.dependency_type != "prerequisite" or r.resource_type != "Resources":
        fail("dependency policy lost")
    if not any([a.name == "discoverable" and a.value == "no" for a in r.attributes]):
        fail("dependency attributes lost")
    if len(r.binding_redirects) != 0 or len(m.references[1].binding_redirects) != 1 or m.references[1].binding_redirects[0].new_version != "2.0.0.0":
        fail("binding redirect lost")
    if parse(b'<assembly><assemblyIdentity name="component"/></assembly>').deployment != None:
        fail("absent deployment became present")
    if parse(b'<assembly><assemblyIdentity name="component"/><deployment/></assembly>').deployment != []:
        fail("empty deployment became absent")
check()
`, starlark.StringDict{"parse": Builtins()["assembly_manifest"], "source": starlark.Bytes(text)})
	if err != nil {
		t.Fatal(err)
	}
}
