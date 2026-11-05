package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestAssemblyManifestDigestObservation(t *testing.T) {
	const source = `<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="component"/><file name="plain" hash="AABB" hashalg="SHA256"/><file name="nested"><hash xmlns="urn:schemas-microsoft-com:asm.v2"><d:Transforms xmlns:d="http://www.w3.org/2000/09/xmldsig#"><d:Transform Algorithm="unknown-transform"/></d:Transforms><DigestMethod xmlns="http://www.w3.org/2000/09/xmldsig#" Algorithm="unknown-digest"/><DigestValue xmlns="http://www.w3.org/2000/09/xmldsig#"> raw-value </DigestValue></hash></file></assembly>`
	_, err := starlark.ExecFile(&starlark.Thread{}, "digest.star", `
def check():
    m = parse(source)
    if m.files[0].digest != None or m.files[0].hash != "aabb":
        fail("attribute digest observation changed")
    d = m.files[1].digest
    if d.algorithm != "unknown-digest" or d.transforms != ["unknown-transform"] or d.value != " raw-value ":
        fail("nested digest declaration lost or interpreted")
check()
`, starlark.StringDict{"parse": Builtins()["assembly_manifest"], "source": starlark.Bytes(source)})
	if err != nil {
		t.Fatal(err)
	}
}
