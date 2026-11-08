package native

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
	"testing"
)

func TestAdditionalMSUsRejectInvalidContainersAndStageCollisions(t *testing.T) {
	payload := &starfile.Bytes{Name: "update.msu", Data: []byte("MSWIM\x00truncated")}
	input := starlark.NewDict(1)
	if err := input.SetKey(starlark.String("CatalogLCU"), payload); err != nil {
		t.Fatal(err)
	}
	if _, err := unpackAdditionalMSUs(input, false); err == nil {
		t.Fatal("accepted outside servicing-only mode")
	}
	stages, err := unpackAdditionalMSUs(input, true)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := uup.NewStageMetadataCache(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openAdditionalStage(stages[0], cache); err == nil {
		t.Fatal("accepted truncated catalog container")
	}
	if _, err := appendAdditionalStages([]uup.UpdateStagePlan{{FeatureID: "cataloglcu"}}, stages); err == nil {
		t.Fatal("accepted collision with an existing catalog stage")
	}
	if _, err := appendAdditionalStages(nil, append(stages, additionalCabinet{feature: "CATALOGlcu", file: payload})); err == nil {
		t.Fatal("accepted cross-format stage collision")
	}
}

func TestAdditionalStageOrderRequiresCompletePermutation(t *testing.T) {
	input := []additionalCabinet{{feature: "NET"}, {feature: "SSU"}, {feature: "LCU", msu: true}}
	order := starlark.NewList([]starlark.Value{starlark.String("SSU"), starlark.String("LCU"), starlark.String("NET")})
	got, err := orderAdditionalStages(input, order)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].feature != "SSU" || got[1].feature != "LCU" || !got[1].msu || got[2].feature != "NET" || input[0].feature != "NET" {
		t.Fatalf("incorrect mixed-format ordering: %+v", got)
	}
	for _, names := range [][]string{{"SSU"}, {"SSU", "LCU", "SSU"}, {"SSU", "LCU", "unknown"}} {
		var values []starlark.Value
		for _, name := range names {
			values = append(values, starlark.String(name))
		}
		if _, err := orderAdditionalStages(input, starlark.NewList(values)); err == nil {
			t.Fatalf("accepted invalid ordering %v", names)
		}
	}
}
