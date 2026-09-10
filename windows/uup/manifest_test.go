package uup

import (
	"strings"
	"testing"
)

func TestParseAssemblyManifestPackageDependencies(t *testing.T) {
	manifest, err := ParseAssemblyManifest(strings.NewReader(`<?xml version="1.0"?><assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0">
<assemblyIdentity name="Composition-Core-Package" version="10.0.26100.9168" processorArchitecture="amd64" language="neutral" buildType="release" publicKeyToken="31bf3856ad364e35"/>
<package><update><package><assemblyIdentity name="Composition-Core-merged-Package" version="10.0.26100.9168" processorArchitecture="amd64" language="neutral" buildType="release" publicKeyToken="31bf3856ad364e35"/></package></update>
<update><component><assemblyIdentity name="microsoft-windows-directcomposition" version="10.0.26100.8972" processorArchitecture="amd64" language="neutral" buildType="release" publicKeyToken="31bf3856ad364e35"/></component></update></package></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Identity.Name != "Composition-Core-Package" || len(manifest.References) != 2 {
		t.Fatalf("manifest = %#v", manifest)
	}
	if manifest.References[0].Kind != "package" || manifest.References[1].Kind != "component" {
		t.Fatalf("references = %#v", manifest.References)
	}
	if manifest.Identity.StableKey() == manifest.References[0].Identity.StableKey() {
		t.Fatal("distinct identities have the same stable key")
	}
}

func TestParseAssemblyManifestRejectsDuplicateRootIdentity(t *testing.T) {
	_, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="a"/><assemblyIdentity name="b"/></assembly>`))
	if err == nil {
		t.Fatal("expected duplicate root identity rejection")
	}
}

func TestParseAssemblyManifestRetainsRegistryAppend(t *testing.T) {
	// Windows 11 LocalSessionManager contributes to an existing shared group.
	manifest, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="LocalSessionManager"/><registryKeys><registryKey keyName="HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Svchost"><registryValue name="DcomLaunch" valueType="REG_MULTI_SZ" value="&quot;LSM&quot;" operationHint="append"/></registryKey></registryKeys></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.RegistryValues) != 1 || manifest.RegistryValues[0].OperationHint != "append" || manifest.RegistryValues[0].Value != `"LSM"` {
		t.Fatalf("registry append semantics lost: %#v", manifest.RegistryValues)
	}
}

func TestParseAssemblyManifestRetainsEmptyRegistryKeys(t *testing.T) {
	manifest, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="a"/>
<registryKeys>
<registryKey keyName="HKEY_LOCAL_MACHINE\Software\Empty"/>
<registryKey keyName="HKEY_LOCAL_MACHINE\Software\WithDefault"><registryValue valueType="REG_SZ" value=""/></registryKey>
<registryKey keyName="HKEY_CURRENT_USER\Software\Empty"></registryKey>
</registryKeys></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`HKEY_LOCAL_MACHINE\Software\Empty`, `HKEY_LOCAL_MACHINE\Software\WithDefault`, `HKEY_CURRENT_USER\Software\Empty`}
	if len(manifest.RegistryKeys) != len(want) {
		t.Fatalf("keys = %#v", manifest.RegistryKeys)
	}
	for index, key := range want {
		if manifest.RegistryKeys[index] != key {
			t.Fatalf("key %d = %q, want %q", index, manifest.RegistryKeys[index], key)
		}
	}
	if len(manifest.RegistryValues) != 1 || manifest.RegistryValues[0].KeyName != want[1] || manifest.RegistryValues[0].Name != "" || manifest.RegistryValues[0].Value != "" {
		t.Fatalf("empty key confused with empty default value: %#v", manifest.RegistryValues)
	}
	if _, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="a"/><registryKey/></assembly>`)); err == nil {
		t.Fatal("accepted registry key without a name")
	}
}

func TestParseAssemblyManifestRetainsOfflineEffects(t *testing.T) {
	manifest, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="a"/><file name="target.dll" sourceName="source.dll" sourcePath="build" destinationPath="$(runtime.system32)\drivers\" hash="01" hashalg="SHA1"><link destination="$(runtime.system32)\target-link.dll"/></file><registryKeys><registryKey keyName="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Version"><registryValue name="KVB" valueType="REG_DWORD" value="0x1"/></registryKey></registryKeys></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 1 || manifest.Files[0].SourceName != "source.dll" || manifest.Files[0].DestinationPath != `$(runtime.system32)\drivers\` || len(manifest.Files[0].Links) != 1 || manifest.Files[0].Links[0] != `$(runtime.system32)\target-link.dll` {
		t.Fatalf("files = %#v", manifest.Files)
	}
	if len(manifest.Files[0].Attributes) != 6 || manifest.Files[0].Attributes[0].Name != "name" {
		t.Fatalf("file attributes = %#v", manifest.Files[0].Attributes)
	}
	if len(manifest.RegistryValues) != 1 || manifest.RegistryValues[0].KeyName != `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Version` || manifest.RegistryValues[0].Value != "0x1" {
		t.Fatalf("registry = %#v", manifest.RegistryValues)
	}
	if strings.Join(manifest.TopLevel, ",") != "file,registryKeys" {
		t.Fatalf("top level = %#v", manifest.TopLevel)
	}
}

func TestParseAssemblyManifestRetainsDependencySemantics(t *testing.T) {
	manifest, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="a"/><dependency resourceType="Resources" discoverable="no"><dependentAssembly dependencyType="prerequisite"><assemblyIdentity name="a.resources" language="*"/></dependentAssembly></dependency></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.References) != 1 || manifest.References[0].Kind != "dependentAssembly" || manifest.References[0].DependencyType != "prerequisite" || manifest.References[0].ResourceType != "Resources" {
		t.Fatalf("references = %#v", manifest.References)
	}
	if len(manifest.References[0].Attributes) != 3 {
		t.Fatalf("reference attributes = %#v", manifest.References[0].Attributes)
	}
}

func TestParseAssemblyManifestRetainsInstallResourceSelector(t *testing.T) {
	manifest, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="a"/><dependency resourceType="Resources"><dependentAssembly dependencyType="install"><assemblyIdentity name="a.Resources" language="*"/></dependentAssembly></dependency></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.References) != 1 || manifest.References[0].DependencyType != "install" || manifest.References[0].ResourceType != "Resources" || manifest.References[0].Identity.Language != "*" {
		t.Fatalf("references = %#v", manifest.References)
	}
}

func TestParseAssemblyManifestRetainsPackageApplicabilitySemantics(t *testing.T) {
	manifest, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="root"/><package><parent disposition="detect" integrate="separate"><assemblyIdentity name="edition"/></parent><update><package contained="true" integrate="hidden"><assemblyIdentity name="edition-language"/></package></update></package></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.References) != 2 {
		t.Fatalf("references = %#v", manifest.References)
	}
	parent, child := manifest.References[0], manifest.References[1]
	if parent.Kind != "parent" || parent.Disposition != "detect" || parent.Integrate != "separate" {
		t.Fatalf("parent = %#v", parent)
	}
	if child.Kind != "package" || !child.Contained || child.Integrate != "hidden" {
		t.Fatalf("child = %#v", child)
	}
}
