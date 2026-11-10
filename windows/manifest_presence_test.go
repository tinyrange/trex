package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestAssemblyManifestPresenceIsConservativeAndViewOwned(t *testing.T) {
	const source = `<assembly xmlns="urn:schemas-microsoft-com:asm.v3" xmlns:f="urn:foreign">
      <assemblyIdentity name="Example"/>
      <file name="a.dll"><f:gac/><gac/><ngen/><wrapper><nested/></wrapper></file>
      <file name="b.dll"><gac/></file>
      <f:migration/><memberships/>
    </assembly>`
	_, err := starlark.ExecFile(&starlark.Thread{}, "presence.star", `
def check():
    first = parse(source)
    if first.file_elements != ["gac", "ngen", "wrapper"]:
        fail("lost direct child, duplicate retained, or nested child included", first.file_elements)
    if first.top_level != ["file", "migration", "memberships"]:
        fail("presence incorrectly treated namespace as admission", first.top_level)
    first.file_elements.append("local edit")
    second = parse(source)
    if "local edit" in second.file_elements:
        fail("projection mutation corrupted immutable parse")
    if second.files[0].name != "a.dll" or second.files[1].name != "b.dll":
        fail("presence filtering changed file declarations")
check()
`, starlark.StringDict{"parse": Builtins()["assembly_manifest"], "source": starlark.Bytes(source)})
	if err != nil {
		t.Fatal(err)
	}
}
