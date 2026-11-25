package uup

import (
	"bytes"
	"context"
	"reflect"
	"testing"
)

type assemblyRecordCache map[[32]byte][]byte

func (c assemblyRecordCache) GetOrBuild(_ context.Context, key [32]byte, _ int64, build func() ([]byte, error)) ([]byte, error) {
	if record, ok := c[key]; ok {
		return record, nil
	}
	record, err := build()
	if err == nil {
		c[key] = record
	}
	return record, err
}

func TestAssemblyManifestCacheRoundTrip(t *testing.T) {
	source := `<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Sample" version="1.0.0.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package identifier="Sample" releaseType="Update"><update name="optional"><selectable><detectUpdate name="feature"/></selectable></update></package><file name="sample.dll" destinationPath="system32"/></assembly>`
	want, err := ParseAssemblyManifestBytes([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	store := assemblyRecordCache{}
	cache := NewManifestCache(context.Background(), store)
	first, err := cache.Parse(source)
	if err != nil || len(store) != 1 || !reflect.DeepEqual(first, want) {
		t.Fatalf("cold parse differs from source, %v", err)
	}
	next, err := NewManifestCache(context.Background(), store).Parse(source)
	if err != nil || !reflect.DeepEqual(next, want) {
		t.Fatalf("packed parse differs from source, %v", err)
	}
	for _, record := range store {
		encoded, err := packAssemblyManifest(next)
		if err != nil || !bytes.Equal(encoded, record) {
			t.Fatalf("manifest encoding changed on round trip, %v", err)
		}
		if _, err := unpackAssemblyManifest(record[:len(record)-1]); err == nil {
			t.Fatal("truncated manifest record accepted")
		}
	}
}

func TestCBSPhasePlanCacheRoundTrip(t *testing.T) {
	store := assemblyRecordCache{}
	ctx := context.Background()
	identity := AssemblyIdentity{Name: "Sample", Version: "1.0.0.0"}
	want := &CBSPhasePlan{
		StagePackages: []string{"Sample"},
		Actions:       []CBSDeploymentAction{{Package: identity, Deployment: identity, UpdateName: "update", Stage: true, Action: 3}},
		Executions: []CBSOrdinaryExecution{{
			Identity: identity, IntendedState: 0x70,
			Updates: map[string]uint32{"update": 0x70}, DirtyUpdates: map[string]bool{},
			UpdateStarts: map[string]CBSOrdinaryUpdateStart{"update": {HasDeployments: true}},
		}},
		Admissions: 1, PackageNames: map[string]string{identity.ExactKey(): "Sample"},
	}
	calls := 0
	build := func() (*CBSPhasePlan, error) { calls++; return want, nil }
	for _, key := range [][32]byte{{1}, {1}, {2}} {
		got, err := LoadCBSPhasePlan(ctx, store, key, build)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("phase plan changed on round trip: %v, %v", got, err)
		}
	}
	if calls != 2 {
		t.Fatalf("builder calls = %d, want one per source identity", calls)
	}
}
