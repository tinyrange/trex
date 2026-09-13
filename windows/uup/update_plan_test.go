package uup

import (
	"strings"
	"testing"

	windowsupdate "github.com/tinyrange/trex/windows/update"
)

func TestPlanUpdateStagesClassifiesAndOrdersScopes(t *testing.T) {
	eku, err := Parse(strings.NewReader(`<CompDB Name="eku" Type="BuildUpdate" BuildArch="amd64" OSVersion="10.0.26100.1" TargetOSVersion="10.0.26100.2"><Features><Feature FeatureID="eku" Type="GDR"><Packages><Package ID="p"/></Packages></Feature></Features><Packages><Package ID="p"><Payload><PayloadItem Path="u.cab" PayloadSize="10" PayloadType="PSFX"/><PayloadItem Path="u-baseless.cab" PayloadSize="11" PayloadType="ExpressCab"/><PayloadItem Path="u.psf" PayloadSize="12" PayloadType="ExpressPSF"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	setup, err := Parse(strings.NewReader(`<CompDB Name="setup" Type="BuildUpdate" BuildArch="amd64"><Features><Feature FeatureID="setup" Type="SetupDynamicUpdate"><Packages><Package ID="s"/></Packages></Feature></Features><Packages><Package ID="s"><Payload><PayloadItem Path="s.cab" PayloadSize="13" PayloadType="Canonical"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	files := []windowsupdate.File{{Name: "u.cab", Size: 10}, {Name: "u-baseless.cab", Size: 11}, {Name: "u.psf", Size: 12}, {Name: "s.cab", Size: 13}}
	plan, err := PlanUpdateStages([]*Database{setup, eku}, files, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 2 || plan[0].Scope != "installed-os" || plan[1].Scope != "setup" || len(plan[0].Payloads) != 3 {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestPlanUpdateStagesRejectsMissingPayload(t *testing.T) {
	database, err := Parse(strings.NewReader(`<CompDB Name="update" Type="BuildUpdate"><Features><Feature FeatureID="f" Type="GDR"><Packages><Package ID="p"/></Packages></Feature></Features><Packages><Package ID="p"><Payload><PayloadItem Path="missing.cab" PayloadSize="10" PayloadType="Canonical"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanUpdateStages([]*Database{database}, nil, ""); err == nil || !strings.Contains(err.Error(), "unresolved payload") {
		t.Fatalf("error = %v", err)
	}
}

func TestPlanUpdateStagesRejectsUnknownFeatureScope(t *testing.T) {
	database, err := Parse(strings.NewReader(`<CompDB Name="update" Type="BuildUpdate"><Features><Feature FeatureID="f" Type="Mystery"><Packages><Package ID="p"/></Packages></Feature></Features><Packages><Package ID="p"><Payload><PayloadItem Path="u.cab" PayloadSize="10" PayloadType="Canonical"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = PlanUpdateStages([]*Database{database}, []windowsupdate.File{{Name: "u.cab", Size: 10}}, "")
	if err == nil || !strings.Contains(err.Error(), "unsupported feature type") {
		t.Fatalf("error = %v", err)
	}
}

func TestPlanUpdateStagesResolvesLogicalMSUMember(t *testing.T) {
	database, err := Parse(strings.NewReader(`<CompDB Name="lcu" Type="BuildUpdate"><Features><Feature FeatureID="lcu" Type="GDR"><Packages><Package ID="p"/></Packages></Feature></Features><Packages><Package ID="p"><Payload><PayloadItem Path="Windows11.0-KB1-x64.wim" PayloadSize="20" PayloadType="ExpressCab"/><PayloadItem Path="Windows11.0-KB1-x64.psf" PayloadSize="30" PayloadType="ExpressPSF"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	container := windowsupdate.File{Name: "Windows11.0-KB1-x64.msu", Size: 100, DigestSHA256: "container"}
	plan, err := PlanUpdateStagesFromSources([]*Database{database}, []UpdatePayloadSource{
		{Container: container, Member: "/Windows11.0-KB1-x64.wim", Name: "Windows11.0-KB1-x64.wim", Size: 20},
		{Container: container, Member: "/Windows11.0-KB1-x64.psf", Name: "Windows11.0-KB1-x64.psf", Size: 30},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || len(plan[0].Payloads) != 2 || plan[0].Payloads[0].Source.Container.Name != container.Name || plan[0].Payloads[0].Source.Member == "" {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestPlanUpdateStagesRejectsAmbiguousContainerMembers(t *testing.T) {
	database, err := Parse(strings.NewReader(`<CompDB Name="lcu" Type="BuildUpdate"><Features><Feature FeatureID="lcu" Type="GDR"><Packages><Package ID="p"/></Packages></Feature></Features><Packages><Package ID="p"><Payload><PayloadItem Path="payload.wim" PayloadSize="20" PayloadType="ExpressCab"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	sources := []UpdatePayloadSource{
		{Container: windowsupdate.File{Name: "one.msu"}, Member: "/payload.wim", Name: "payload.wim", Size: 20},
		{Container: windowsupdate.File{Name: "two.msu"}, Member: "/payload.wim", Name: "payload.wim", Size: 20},
	}
	_, err = PlanUpdateStagesFromSources([]*Database{database}, sources, "")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("error = %v", err)
	}
}

func TestPlanUpdateStagesSelectsExpressRepresentationOverPSFXAlternative(t *testing.T) {
	database, err := Parse(strings.NewReader(`<CompDB Name="update" Type="BuildUpdate"><Features><Feature FeatureID="f" Type="GDR"><Packages><Package ID="p"/></Packages></Feature></Features><Packages><Package ID="p"><Payload><PayloadItem Path="metadata.cab" PayloadSize="10" PayloadType="ExpressCab"/><PayloadItem Path="records.psf" PayloadSize="11" PayloadType="ExpressPSF"/><PayloadItem Path="fallback.cab" PayloadSize="12" PayloadType="PSFX"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanUpdateStages([]*Database{database}, []windowsupdate.File{{Name: "metadata.cab", Size: 10}, {Name: "records.psf", Size: 11}, {Name: "fallback.cab", Size: 12}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if plan[0].Representation != "express" {
		t.Fatalf("representation = %q", plan[0].Representation)
	}
	selected := 0
	for _, payload := range plan[0].Payloads {
		if payload.Selected {
			selected++
			if payload.Role == "psfx-cab" {
				t.Fatal("PSFX alternative selected with complete express representation")
			}
		}
	}
	if selected != 2 {
		t.Fatalf("selected payloads = %d", selected)
	}
}

func TestOrderUpdateStagesFollowsCheckpointAndContainerDependencies(t *testing.T) {
	stage := func(id, kind, input, target, container string) UpdateStagePlan {
		return UpdateStagePlan{
			FeatureID: id, FeatureType: kind, Scope: "installed-os", OSVersion: input, TargetOSVersion: target,
			Payloads: []UpdatePayload{{Selected: true, Source: UpdatePayloadSource{Container: windowsupdate.File{Name: container, DigestSHA256: container}}}},
		}
	}
	ordered, err := orderUpdateStages([]UpdateStagePlan{
		stage("ssu-new", "ServicingStackUpdate", "10.0.26100.1", "10.0.26100.9156", "new.msu"),
		stage("lcu-old", "CumulativeUpdate", "10.0.26100.1", "10.0.26100.1742", "old.msu"),
		stage("lcu-new", "CumulativeUpdate", "10.0.26100.1742", "10.0.26100.9168", "new.msu"),
		stage("ssu-old", "ServicingStackUpdate", "10.0.26100.1", "10.0.26100.1738", "old.msu"),
		stage("ekb", "GDR", "10.0.26100.1", "10.0.26100.6717", "ekb.cab"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ssu-old", "lcu-old", "ekb", "ssu-new", "lcu-new"}
	for index := range want {
		if ordered[index].FeatureID != want[index] {
			t.Fatalf("order[%d] = %q, want %q", index, ordered[index].FeatureID, want[index])
		}
	}
	if len(ordered[4].Dependencies) != 2 {
		t.Fatalf("lcu-new dependencies = %#v", ordered[4].Dependencies)
	}
}

func TestPlanUpdateStagesFollowsRequiredFeatureDependency(t *testing.T) {
	producer, err := Parse(strings.NewReader(`<CompDB Name="producer" Type="BuildUpdate"><Features><Feature FeatureID="ssu" Type="ServicingStackUpdate"><Packages><Package ID="s"/></Packages></Feature></Features><Packages><Package ID="s"><Payload><PayloadItem Path="s.cab" PayloadSize="10" PayloadType="Canonical"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := Parse(strings.NewReader(`<CompDB Name="consumer" Type="BuildUpdate"><Features><Feature FeatureID="lcu" Type="CumulativeUpdate"><Dependencies><Feature FeatureID="ssu" Type="Required"/></Dependencies><Packages><Package ID="l"/></Packages></Feature></Features><Packages><Package ID="l"><Payload><PayloadItem Path="l.cab" PayloadSize="11" PayloadType="Canonical"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanUpdateStages([]*Database{consumer, producer}, []windowsupdate.File{{Name: "s.cab", Size: 10}, {Name: "l.cab", Size: 11}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 2 || plan[0].FeatureID != "ssu" || plan[1].FeatureID != "lcu" || len(plan[1].Dependencies) != 1 || plan[1].Dependencies[0].Kind != "feature-required" {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestPlanUpdateStagesRejectsUnreferencedPayloadPackage(t *testing.T) {
	database, err := Parse(strings.NewReader(`<CompDB Name="update" Type="BuildUpdate"><Features><Feature FeatureID="f" Type="GDR"><Packages><Package ID="used"/></Packages></Feature></Features><Packages><Package ID="used"><Payload><PayloadItem Path="used.cab" PayloadSize="10" PayloadType="Canonical"/></Payload></Package><Package ID="lost"><Payload><PayloadItem Path="lost.cab" PayloadSize="11" PayloadType="Canonical"/></Payload></Package></Packages></CompDB>`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = PlanUpdateStages([]*Database{database}, []windowsupdate.File{{Name: "used.cab", Size: 10}, {Name: "lost.cab", Size: 11}}, "")
	if err == nil || !strings.Contains(err.Error(), "unreferenced") {
		t.Fatalf("error = %v", err)
	}
}
