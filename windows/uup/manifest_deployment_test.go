package uup

import (
	"strings"
	"testing"
)

func TestManifestDeploymentScopeAndAttributes(t *testing.T) {
	text := `<assembly xmlns="urn:schemas-microsoft-com:asm.v3" xmlns:x="urn:extension"><assemblyIdentity name="component"/><deployment impact="patch" x:impact="not-native"/><x:deployment impact="install"/><extension><deployment impact="install"/></extension></assembly>`
	m, err := ParseAssemblyManifest(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if m.Deployment == nil || len(m.Deployment.Attributes) != 2 {
		t.Fatalf("lost deployment declaration: %+v", m.Deployment)
	}
	if m.Deployment.Attributes[0] != (ManifestAttribute{Name: "impact", Value: "patch"}) || m.Deployment.Attributes[1] != (ManifestAttribute{Namespace: "urn:extension", Name: "impact", Value: "not-native"}) {
		t.Fatalf("lost qualified attributes: %+v", m.Deployment.Attributes)
	}
	for _, body := range []string{`<deployment/><deployment/>`, `<deployment impact="patch"/><deployment impact="install"/>`} {
		if _, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="component"/>` + body + `</assembly>`)); err == nil {
			t.Fatal("accepted ambiguous deployment policy")
		}
	}
	for _, body := range []string{"", `<deployment/>`} {
		m, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="component"/>` + body + `</assembly>`))
		if err != nil || (m.Deployment != nil) != (body != "") {
			t.Fatalf("absent versus empty declaration: %+v, %v", m, err)
		}
	}
}
