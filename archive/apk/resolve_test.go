package apk

import (
	"slices"
	"strings"
	"testing"
)

func TestResolveAlpineProvidersAndConstraints(t *testing.T) {
	pkg := func(name, version string, provided, depends []string, priority int) Package {
		return Package{"main", Record{Name: name, Version: version, Provides: provided, Dependencies: depends, ProviderPriority: priority}}
	}
	client := pkg("client", "1.1-r0", nil, []string{"so:libexample.so.1", "tool~2.3", "!legacy"}, 0)
	available := []Package{
		client, pkg("broken", "1.0-r0", []string{"so:libexample.so.1"}, []string{"legacy"}, 10),
		pkg("working", "1.0-r0", []string{"so:libexample.so.1"}, []string{"libc>=1.2.5"}, 0),
		pkg("legacy", "1.0-r0", nil, nil, 0),
		pkg("tool", "2.4-r0", nil, nil, 0), pkg("tool", "2.3.4-r0", nil, nil, 0),
	}
	base := []Package{{Record: Record{Name: "libc", Version: "1.2.5-r1"}}}
	selected, err := Resolve(available, base, []string{client.ID()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, p := range selected {
		ids = append(ids, p.ID())
	}
	want := []string{client.ID(), "main/tool=2.3.4-r0", "main/working=1.0-r0"}
	if !slices.Equal(ids, want) {
		t.Fatalf("got %v, want %v", ids, want)
	}
	if _, err := Resolve(available, nil, []string{"main/client=0.1-r0"}, nil); err == nil || !strings.Contains(err.Error(), "no longer") {
		t.Fatalf("expected missing exact version, got %v", err)
	}
}
