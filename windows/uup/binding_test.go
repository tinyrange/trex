package uup

import (
	"strings"
	"testing"
)

func TestPublisherPolicyBindingIsNotInstallDependency(t *testing.T) {
	const text = `<assembly xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity type="win32-policy" name="policy.8.0.Microsoft.VC80.CRT" version="8.0.50727.9680" processorArchitecture="x86" publicKeyToken="1fc8b3b9a1e18e3b"/><dependency><dependentAssembly><assemblyIdentity type="win32" name="Microsoft.VC80.CRT" processorArchitecture="x86" publicKeyToken="1fc8b3b9a1e18e3b"/><bindingRedirect oldVersion="8.0.41204.256-8.0.50608.0" newVersion="8.0.50727.9680"/><bindingRedirect oldVersion="8.0.50727.42-8.0.50727.9680" newVersion="8.0.50727.9680"/></dependentAssembly></dependency></assembly>`
	manifest, err := ParseAssemblyManifest(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.References) != 1 || len(manifest.References[0].BindingRedirects) != 2 || manifest.References[0].Identity.Version != "" {
		t.Fatalf("%+v", manifest.References)
	}
	for _, invalid := range []string{
		strings.Replace(text, "<dependentAssembly>", `<dependentAssembly dependencyType="install">`, 1),
		strings.Replace(text, `oldVersion="8.0.41204.256-8.0.50608.0"`, `oldVersion="8.0.50608.0-8.0.41204.256"`, 1),
		strings.Replace(text, `newVersion="8.0.50727.9680"`, `newVersion="*"`, 1),
	} {
		if _, err := ParseAssemblyManifest(strings.NewReader(invalid)); err == nil {
			t.Fatal("accepted malformed policy")
		}
	}
}
