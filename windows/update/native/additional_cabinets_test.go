package native

import (
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func TestAdditionalCabinetsAdmission(t *testing.T) {
	payload := &starfile.Bytes{Name: "update.cab", Data: []byte("cabinet")}
	dict := starlark.NewDict(2)
	if err := dict.SetKey(starlark.String("NetFx"), payload); err != nil {
		t.Fatal(err)
	}
	if _, err := unpackAdditionalCabinets(dict, false); err == nil {
		t.Fatal("accepted outside servicing mode")
	}
	got, err := unpackAdditionalCabinets(dict, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := dict.SetKey(starlark.String("Second"), payload); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].feature != "NetFx" || got[0].file != payload {
		t.Fatal("caller mutation changed captured input")
	}
	for _, name := range []string{"", " padded", "slash/name", "back\\name", "line\nname", "nul\x00name"} {
		bad := starlark.NewDict(1)
		if err := bad.SetKey(starlark.String(name), payload); err != nil {
			t.Fatal(err)
		}
		if _, err := unpackAdditionalCabinets(bad, true); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	if err := dict.SetKey(starlark.String("NETFX"), payload); err != nil {
		t.Fatal(err)
	}
	if _, err := unpackAdditionalCabinets(dict, true); err == nil {
		t.Fatal("accepted case-colliding IDs")
	}
	for _, value := range []starlark.Value{starlark.String("path.cab"), &starfile.Bytes{}} {
		bad := starlark.NewDict(1)
		if err := bad.SetKey(starlark.String("NetFx"), value); err != nil {
			t.Fatal(err)
		}
		if _, err := unpackAdditionalCabinets(bad, true); err == nil {
			t.Fatal("accepted non-file or empty input")
		}
	}
}

func TestAdditionalCabinetsStageOrderAndIsolation(t *testing.T) {
	original := make([]uup.UpdateStagePlan, 2, 8)
	original[0].FeatureID, original[1].FeatureID = "SSU", "LCU"
	got, err := appendAdditionalStages(original, []additionalCabinet{{feature: "NetFx"}, {feature: "Other"}})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"SSU", "LCU", "NetFx", "Other"} {
		if got[i].FeatureID != want {
			t.Fatalf("stage %d: %q", i, got[i].FeatureID)
		}
		if i >= 2 && got[i].Scope != "installed-os" {
			t.Fatal("wrong scope")
		}
	}
	got[0].FeatureID = "changed"
	if original[0].FeatureID != "SSU" {
		t.Fatal("shared stage slice")
	}
	for _, extra := range [][]additionalCabinet{{{feature: "lcu"}}, {{feature: "NetFx"}, {feature: "NETFX"}}} {
		if _, err := appendAdditionalStages(original, extra); err == nil {
			t.Fatal("accepted duplicate stage")
		}
	}
}
