package uup

import (
	"strings"
	"testing"

	windowsupdate "github.com/tinyrange/trex/windows/update"
)

func TestParseAndPlanEdition(t *testing.T) {
	database, err := Parse(strings.NewReader(`<CompDB Name="Build~amd64~Desktop~professional~en-us" BuildArch="amd64" OSVersion="10.0.26100.1"><Features><Feature FeatureID="professional_en-us"><Packages><Package ID="Microsoft-Windows-Foundation-Package"/><Package ID="Language-Package"/><Package ID="Sense-Package"/></Packages></Feature></Features><Packages><Package ID="Microsoft-Windows-Foundation-Package"><Payload><PayloadItem Path="UUP\Foundation.esd" PayloadHash="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" PayloadSize="250" PayloadType="Canonical"/></Payload></Package><Package ID="Language-Package"><Payload><PayloadItem Path="payload.esd" PayloadSize="123" PayloadType="Canonical"/></Payload></Package><Package ID="Sense-Package"><Payload><PayloadItem Path="Sense.cab" PayloadSize="50" PayloadType="Canonical"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	if database.Architecture != "amd64" || database.Packages[1].Payload[0].Size != 123 {
		t.Fatalf("database = %#v", database)
	}
	_, err = PlanEdition(database, []windowsupdate.File{
		{Name: "professional_en-us.esd", Size: 100},
		{Name: "Foundation.esd", Size: 200, DigestSHA256: strings.Repeat("02", 32)},
		{Name: "Foundation.esd", Size: 250, DigestSHA256: strings.Repeat("01", 32)},
		{Name: "Sense.cab", Size: 50},
	}, "Professional", "en-US")
	if err == nil || !strings.Contains(err.Error(), "Language-Package") {
		t.Fatalf("error = %v", err)
	}
}

func TestPlanEditionClassifiesRequiredApplicationPayloads(t *testing.T) {
	database, err := Parse(strings.NewReader(`<CompDB Name="target"><Features><Feature FeatureID="edition"><Packages><Package ID="codec"/></Packages></Feature></Features><Packages><Package ID="codec"><Payload><PayloadItem Path="codec.msixbundle" PayloadSize="20" PayloadType="Canonical"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanEdition(database, []windowsupdate.File{{Name: "professional_en-us.esd", Size: 10}, {Name: "codec.msixbundle", Size: 20}}, "professional", "en-us")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Applications) != 1 || plan.Applications[0].Name != "codec.msixbundle" || plan.TotalSize != 30 {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestPlanEditionCatalogFollowsFeatureDependencies(t *testing.T) {
	root, err := Parse(strings.NewReader(`<CompDB Name="target" BuildArch="amd64"><Features><Feature FeatureID="edition" FMID="MSDN" Group="Edition" Type="Desktop"><Dependencies><Feature FeatureID="neutral" FMID="MSDN" Group="Base" Type="Required"/></Dependencies><Packages><Package ID="edition-package"/></Packages></Feature></Features><Packages><Package ID="edition-package"><Payload><PayloadItem Path="edition.esd" PayloadSize="20" PayloadType="Canonical"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	neutral, err := Parse(strings.NewReader(`<CompDB Name="neutral" BuildArch="amd64"><Features><Feature FeatureID="neutral" FMID="MSDN" Group="Base" Type="Desktop"><Packages><Package ID="neutral-package"/></Packages></Feature></Features><Packages><Package ID="neutral-package"><Payload><PayloadItem Path="neutral.esd" PayloadSize="30" PayloadType="Canonical"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanEditionCatalog(root, []*Database{root, neutral}, []windowsupdate.File{
		{Name: "professional_en-us.esd", Size: 10}, {Name: "edition.esd", Size: 20}, {Name: "neutral.esd", Size: 30},
	}, "professional", "en-us")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.References) != 2 || plan.TotalSize != 60 {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestPlanEditionCatalogTreatsOmittedDependencyQualifiersAsUnspecified(t *testing.T) {
	root, err := Parse(strings.NewReader(`<CompDB Name="target"><Features><Feature FeatureID="edition"><Dependencies><Feature FeatureID="store" FMID="MSDN" Group="Apps" Type="Optional"/></Dependencies></Feature></Features></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Parse(strings.NewReader(`<CompDB Name="store"><Features><Feature FeatureID="store" FMID="MSDN" Group="Apps" Type="Desktop"/></Features></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanEditionCatalog(root, []*Database{root, store}, []windowsupdate.File{{Name: "professional_en-us.esd", Size: 10}}, "professional", "en-us"); err != nil {
		t.Fatal(err)
	}
}

func TestPlanEditionCatalogRejectsUnresolvedFeatureDependency(t *testing.T) {
	root, err := Parse(strings.NewReader(`<CompDB Name="target"><Features><Feature FeatureID="edition"><Dependencies><Feature FeatureID="missing" FMID="MSDN" Group="Base" Type="Desktop"/></Dependencies></Feature></Features></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanEditionCatalog(root, []*Database{root}, []windowsupdate.File{{Name: "professional_en-us.esd", Size: 10}}, "professional", "en-us"); err == nil {
		t.Fatal("expected unresolved feature dependency")
	}
}

func TestParseAcceptsNamelessBuildUpdateCompDB(t *testing.T) {
	database, err := Parse(strings.NewReader(`<CompDB Type="BuildUpdate" BuildArch="amd64" OSVersion="10.0.26100.1"/>`))
	if err != nil {
		t.Fatal(err)
	}
	if database.Name != "" || database.Type != "BuildUpdate" {
		t.Fatalf("database = %#v", database)
	}
}

func TestPlanEditionCatalogSkipsOptionalDependencies(t *testing.T) {
	root, err := Parse(strings.NewReader(`<CompDB Name="target"><Features><Feature FeatureID="edition"><Dependencies><Feature FeatureID="optional-app" Type="Optional"/></Dependencies></Feature></Features></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanEditionCatalog(root, []*Database{root}, []windowsupdate.File{{Name: "professional_en-us.esd", Size: 10}}, "professional", "en-us"); err != nil {
		t.Fatal(err)
	}
}

func TestPlanEditionCatalogRejectsUnknownDependencyType(t *testing.T) {
	root, err := Parse(strings.NewReader(`<CompDB Name="target"><Features><Feature FeatureID="edition"><Dependencies><Feature FeatureID="other" Type="Surprising"/></Dependencies></Feature></Features></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanEditionCatalog(root, []*Database{root}, []windowsupdate.File{{Name: "professional_en-us.esd", Size: 10}}, "professional", "en-us"); err == nil || !strings.Contains(err.Error(), "unknown dependency type") {
		t.Fatalf("error = %v", err)
	}
}

func TestPlanEditionRejectsAmbiguousMetadataIdentity(t *testing.T) {
	database, err := Parse(strings.NewReader(`<CompDB Name="target"/>`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = PlanEdition(database, []windowsupdate.File{
		{Name: "professional_en-us.esd", Size: 10, DigestSHA256: "one"},
		{Name: "professional_en-us.esd", Size: 11, DigestSHA256: "two"},
	}, "professional", "en-us")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("error = %v", err)
	}
}
