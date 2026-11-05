package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestCBSDeploymentSourceDataBuiltin(t *testing.T) {
	_, err := starlark.ExecFile(&starlark.Thread{Name: t.Name()}, "source.star", `
mum='<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Package" version="10.0.1.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"/><package><update name="Exact"><applicable><updateComponent elevate="build"><assemblyIdentity name="A"/><assemblyIdentity name="B"/></updateComponent></applicable></update></package></assembly>'
s=decode(encode(mum,"exact"))
def check():
    if s.secondary!=b"9" or s.primary!="Package~31bf3856ad364e35~amd64~~10.0.1.1.Exact" or s.update!="Exact":
        fail("source metadata binding lost framing, flags or declared spelling")
check()
`, starlark.StringDict{"encode": starlark.NewBuiltin("cbs_deployment_source_data", cbsDeploymentSourceDataBuiltin), "decode": starlark.NewBuiltin("cbs_deployment_source", cbsDeploymentSourceBuiltin)})
	if err != nil {
		t.Fatal(err)
	}
}
