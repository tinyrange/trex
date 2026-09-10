package native

import (
	"testing"

	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func TestInspectServicingFilesMetadataOnly(t *testing.T) {
	plans := []uup.StageEffectPlan{{Files: []uup.StageFileEffect{
		{SourceName: `component\BOOT.STL`, SourceMode: "payload", StorePath: "/Windows/WinSxS/boot.stl"},
		{SourceName: "other", Destinations: []string{`$(runtime.bootdrive)\Boot\other`}},
		{SourceName: "ignored"},
	}}, {Files: []uup.StageFileEffect{{SourceName: "component/boot.stl"}}}}
	for _, limit := range []int{0, 1, 100} {
		value, err := inspectServicingFiles(plans, []string{"first", "second"}, "boot.stl", "$(RUNTIME.BOOTDRIVE)/", limit)
		if err != nil {
			t.Fatal(err)
		}
		record := value.(starlark.HasAttrs)
		total, _ := record.Attr("total")
		if total.String() != "3" {
			t.Fatalf("total = %s", total)
		}
		entries, _ := record.Attr("files")
		files := entries.(*starlark.List)
		if files.Len() != min(limit, 3) {
			t.Fatalf("files = %d", files.Len())
		}
		truncated, _ := record.Attr("truncated")
		if truncated.Truth() != starlark.Bool(limit < 3) {
			t.Fatalf("truncated = %v", truncated)
		}
		if files.Len() > 0 {
			file := files.Index(0).(starlark.HasAttrs)
			feature, _ := file.Attr("feature_id")
			if feature != starlark.String("first") {
				t.Fatal("lost plan order")
			}
			for _, attr := range file.AttrNames() {
				if attr == "data" {
					t.Fatal("metadata inspection exposed reconstructed data")
				}
			}
		}
	}
	for _, limit := range []int{-1, 1001} {
		if _, err := inspectServicingFiles(plans, []string{"first", "second"}, "boot.stl", "", limit); err == nil {
			t.Fatal("accepted invalid output limit")
		}
	}
	if _, err := inspectServicingFiles(plans, nil, "boot.stl", "", 1); err == nil {
		t.Fatal("accepted mismatched stage metadata")
	}
	if _, err := inspectServicingFiles(plans, []string{"first", "second"}, "", "", 1); err == nil {
		t.Fatal("accepted unfiltered inspection")
	}
}
