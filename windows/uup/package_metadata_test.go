package uup

import (
	"reflect"
	"strings"
	"testing"
)

func TestPackageMetadataScope(t *testing.T) {
	m, err := ParseAssemblyManifest(strings.NewReader(`<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="aggregate"/>
 <package identifier="KB1" releaseType="Security Update" restart="possible" permanence="permanent" xmlns:x="urn:extension" x:permanence="uninterpreted">
 <update name="wrapper"><package integrate="hidden"><assemblyIdentity name="wrapper"/></package></update>
 </package></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	want := []ManifestAttribute{{Name: "identifier", Value: "KB1"}, {Name: "releaseType", Value: "Security Update"}, {Name: "restart", Value: "possible"}, {Name: "permanence", Value: "permanent"}, {Namespace: "xmlns", Name: "x", Value: "urn:extension"}, {Namespace: "urn:extension", Name: "permanence", Value: "uninterpreted"}}
	if m.Package == nil || !reflect.DeepEqual(m.Package.Attributes, want) {
		t.Fatalf("root package = %#v", m.Package)
	}
	if len(m.References) != 1 || m.References[0].Integrate != "hidden" {
		t.Fatalf("nested reference = %#v", m.References)
	}
	retained := packagePlanMetadata(m)
	if !reflect.DeepEqual(retained.Package, m.Package) {
		t.Fatal("package policy lost during planning")
	}
}

func TestPackageMetadataRejectsDuplicate(t *testing.T) {
	_, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="a"/><package/><package/></assembly>`))
	if err == nil {
		t.Fatal("accepted ambiguous root package policy")
	}
}

func TestPackageMetadataExcludesForeignDeclaration(t *testing.T) {
	m, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="a"/><package xmlns="urn:extension" permanence="permanent"/></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	if m.Package != nil {
		t.Fatal("foreign declaration became CBS package policy")
	}
}

func TestPackageParentGroupsAndReferenceAttributes(t *testing.T) {
	m, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="p"/><package>
 <parent disposition="detect"><assemblyIdentity name="a"/><assemblyIdentity name="b"/></parent>
 <parent integrate="separate"><assemblyIdentity name="c"/></parent>
 <update name="one"><package integrate="hidden" contained="false"><assemblyIdentity name="d"/></package></update>
 <update name="two"><package integrate="hidden"><assemblyIdentity name="e"/></package></update>
 </package></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.PackageParents) != 2 || len(m.References) != 5 {
		t.Fatalf("parent groups = %#v, references = %#v", m.PackageParents, m.References)
	}
	for i, want := range []int{1, 1, 2, 0, 0} {
		if m.References[i].ParentGroup != want {
			t.Fatalf("reference %d group=%d, want %d", i, m.References[i].ParentGroup, want)
		}
	}
	if !reflect.DeepEqual(m.References[3].Attributes, []ManifestAttribute{{Name: "integrate", Value: "hidden"}, {Name: "contained", Value: "false"}}) {
		t.Fatal("explicit containment lost")
	}
	if !reflect.DeepEqual(m.References[4].Attributes, []ManifestAttribute{{Name: "integrate", Value: "hidden"}}) {
		t.Fatal("default containment changed into explicit false")
	}
	if !reflect.DeepEqual(packagePlanMetadata(m).PackageParents, m.PackageParents) {
		t.Fatal("parent groups lost during planning")
	}
}
