package native

import (
	"testing"

	"github.com/tinyrange/trex/windows/uup"
)

func TestSelectServicingFiles(t *testing.T) {
	files := []uup.StageFileEffect{
		{SourceName: `component\a`, SourceMode: "payload"},
		{SourceName: `component\b`, SourceMode: "installed"},
		{SourceName: `component\b`, SourceMode: "predecessor"},
	}
	all, err := selectServicingFiles(files, nil)
	if err != nil || len(all) != 3 {
		t.Fatalf("all: %d, %v", len(all), err)
	}
	selected, err := selectServicingFiles(files, []string{"COMPONENT/b", `component\b`})
	if err != nil || len(selected) != 2 {
		t.Fatalf("selected: %d, %v", len(selected), err)
	}
	if selected[0].SourceMode != "installed" || selected[1].SourceMode != "predecessor" {
		t.Fatal("changed plan order or lost a planned occurrence")
	}
	if _, err := selectServicingFiles(files, []string{"component/missing"}); err == nil {
		t.Fatal("missing selector reported an empty success")
	}
}
