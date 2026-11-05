package uup

import (
	"strings"
	"testing"
)

func TestPackageUpdateConditionsAndOwnershipSurvivePlanning(t *testing.T) {
	input := `<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="package" version="2.0" processorArchitecture="amd64" publicKeyToken="token"/><package>
 <update name="IIS-Certificate-ServerCommon"><applicable disposition="detect"><detectUpdate><parent name="IIS-Certificate"/></detectUpdate></applicable><component><assemblyIdentity name="deployment" version="2.0" processorArchitecture="amd64" publicKeyToken="token"/></component></update>
 <update name="OptionalFeature"><selectable default="false"><detectNone/></selectable><package integrate="liberate"><assemblyIdentity name="child" version="2.0"/></package></update>
 <parent><assemblyIdentity name="edition" version="1.0"/></parent></package></assembly>`
	m, err := ParseAssemblyManifest(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.PackageUpdates) != 2 || len(m.References) != 3 {
		t.Fatalf("lost update context: %+v", m)
	}
	if m.References[0].UpdateName != "IIS-Certificate-ServerCommon" || m.References[1].UpdateName != "OptionalFeature" || m.References[2].UpdateName != "" {
		t.Fatal("update context leaked across siblings", m.References)
	}
	first := m.PackageUpdates[0].Conditions[0]
	if first.Namespace != "urn:schemas-microsoft-com:asm.v3" || first.Name != "applicable" || first.Attributes[0].Value != "detect" || first.Children[0].Children[0].Attributes[0].Value != "IIS-Certificate" {
		t.Fatalf("lost condition tree: %+v", first)
	}
	if m.PackageUpdates[1].Conditions[0].Attributes[0].Value != "false" {
		t.Fatal("lost selectable default")
	}
	retained := packagePlanMetadata(m)
	if len(retained.PackageUpdates) != 2 || retained.References[0].UpdateName != m.References[0].UpdateName {
		t.Fatal("plan stripped update applicability/ownership")
	}
}

func TestPackageUpdateConditionLimits(t *testing.T) {
	prefix := `<assembly><assemblyIdentity name="package" version="1.0"/><package><update name="feature"><applicable>`
	suffix := `</applicable></update></package></assembly>`
	for _, body := range []string{strings.Repeat("<and>", maximumManifestDepth) + strings.Repeat("</and>", maximumManifestDepth), "uninterpreted expression"} {
		if _, err := ParseAssemblyManifest(strings.NewReader(prefix + body + suffix)); err == nil {
			t.Fatal("accepted unbounded or uninterpreted condition")
		}
	}
}
