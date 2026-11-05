package uup

import (
	"fmt"
	"testing"
)

func TestDeploymentOwnershipPreservesSourcesAndResidentClosure(t *testing.T) {
	id := func(name string) AssemblyIdentity {
		return AssemblyIdentity{Name: name, Version: "10.0.1.2", Language: "neutral", ProcessorArchitecture: "amd64", PublicKeyToken: "token"}
	}
	a, b, shared, leaf := id("active"), id("staged"), id("resident"), id("leaf")
	plan := StageAssemblyPlan{
		DeploymentSources: []PlannedDeploymentSource{{Deployment: a, Package: id("p1"), UpdateName: "on"}, {Deployment: a, Package: id("p2"), UpdateName: "also-on"}, {Deployment: b, Package: id("p1"), UpdateName: "off", StagedOnly: true}},
		Components:        []PlannedComponent{{Identity: a, Stem: "a", InstallDependencies: []AssemblyIdentity{shared}}, {Identity: b, Stem: "b", InstallDependencies: []AssemblyIdentity{shared}, StagedOnly: true}},
	}
	calls := 0
	resident := func(identity AssemblyIdentity) (PlannedComponent, error) {
		calls++
		switch identity.Name {
		case shared.Name:
			return PlannedComponent{Identity: shared, Stem: "shared", InstallDependencies: []AssemblyIdentity{leaf}}, nil
		case leaf.Name:
			return PlannedComponent{Identity: leaf, Stem: "leaf", InstallDependencies: []AssemblyIdentity{shared}}, nil
		default:
			return PlannedComponent{}, fmt.Errorf("unexpected %s", identity.Name)
		}
	}
	groups, err := ResolveDeploymentOwnership(plan, resident)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(groups) != 2 || len(groups[0].Sources) != 2 || len(groups[0].Components) != 3 || len(groups[1].Components) != 3 || !groups[1].Sources[0].StagedOnly {
		t.Fatalf("calls=%d groups=%+v", calls, groups)
	}
	if _, err := ResolveDeploymentOwnership(plan, nil); err == nil {
		t.Fatal("ignored missing resident")
	}
	if _, err := ResolveDeploymentOwnership(plan, func(AssemblyIdentity) (PlannedComponent, error) {
		return PlannedComponent{Identity: a, Stem: "foreign"}, nil
	}); err == nil {
		t.Fatal("accepted foreign resident")
	}
}

func TestOwnershipPrunesOnlyInapplicableResidentBranch(t *testing.T) {
	root := AssemblyIdentity{Name: "root"}
	optional := AssemblyIdentity{Name: "optional"}
	plan := StageAssemblyPlan{DeploymentSources: []PlannedDeploymentSource{{Deployment: root}}, Components: []PlannedComponent{{Identity: root, Stem: "root", InstallDependencies: []AssemblyIdentity{optional}}}}
	groups, err := ResolveDeploymentOwnership(plan, func(AssemblyIdentity) (PlannedComponent, error) {
		return PlannedComponent{}, fmt.Errorf("missing prerequisite: %w", ErrInapplicableComponent)
	})
	if err != nil || len(groups) != 1 || len(groups[0].Components) != 1 {
		t.Fatalf("%+v %v", groups, err)
	}
	if _, err := ResolveDeploymentOwnership(plan, func(AssemblyIdentity) (PlannedComponent, error) {
		return PlannedComponent{}, fmt.Errorf("missing manifest")
	}); err == nil {
		t.Fatal("missing install edge was silently pruned")
	}
}
