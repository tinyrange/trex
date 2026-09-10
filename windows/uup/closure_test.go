package uup

import "testing"

func testIdentity(name, version string) AssemblyIdentity {
	return AssemblyIdentity{Name: name, Version: version, ProcessorArchitecture: "amd64", Language: "neutral", PublicKeyToken: "31bf", BuildType: "release"}
}

func testManifest(path string, identity AssemblyIdentity, references ...AssemblyReference) NamedAssemblyManifest {
	return NamedAssemblyManifest{Path: path, Manifest: &AssemblyManifest{Identity: identity, References: references}}
}

func TestResolveAssemblyClosureUsesInstalledRootsAndReferences(t *testing.T) {
	oldRoot := testIdentity("root", "1.0.0.0")
	newRoot := testIdentity("root", "2.0.0.0")
	child := testIdentity("child", "2.0.0.0")
	component := testIdentity("component", "2.0.0.0")
	closure, err := ResolveAssemblyClosure(
		[]AssemblyIdentity{oldRoot}, nil,
		[]NamedAssemblyManifest{
			testManifest("root.mum", newRoot, AssemblyReference{Kind: "package", Identity: child}),
			testManifest("child.mum", child, AssemblyReference{Kind: "component", Identity: component}),
		},
		[]NamedAssemblyManifest{testManifest("component.manifest", component)},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(closure.Packages) != 2 || len(closure.Components) != 1 {
		t.Fatalf("closure = %#v", closure)
	}
}

func TestResolveAssemblyClosureRejectsMissingReference(t *testing.T) {
	oldRoot := testIdentity("root", "1")
	newRoot := testIdentity("root", "2")
	missing := testIdentity("missing", "2")
	_, err := ResolveAssemblyClosure([]AssemblyIdentity{oldRoot}, nil, []NamedAssemblyManifest{
		testManifest("root.mum", newRoot, AssemblyReference{Kind: "package", Identity: missing}),
	}, nil)
	if err == nil {
		t.Fatal("expected unresolved reference rejection")
	}
}

func TestResolveAssemblyClosureDoesNotDowngradeInstalledPackage(t *testing.T) {
	installed := testIdentity("root", "3")
	target := testIdentity("root", "2")
	closure, err := ResolveAssemblyClosure([]AssemblyIdentity{installed}, nil, []NamedAssemblyManifest{testManifest("root.mum", target)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(closure.Packages) != 0 {
		t.Fatalf("closure = %#v", closure)
	}
}
