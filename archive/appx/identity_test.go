package appx

import "testing"

func TestPublishedIdentity(t *testing.T) {
	i := Identity{Name: "Microsoft.WindowsTerminal", Publisher: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US", Version: "1.24.12741.0", Architecture: "x64"}
	if got := i.PublisherID(); got != "8wekyb3d8bbwe" {
		t.Fatal(got)
	}
	a := Archive{Kind: "package", Identity: i}
	if got := a.FullName(); got != "Microsoft.WindowsTerminal_1.24.12741.0_x64__8wekyb3d8bbwe" {
		t.Fatal(got)
	}
	a.Kind = "bundle"
	a.Identity.Version = "3001.24.12741.0"
	if got := a.FullName(); got != "Microsoft.WindowsTerminal_3001.24.12741.0_neutral_~_8wekyb3d8bbwe" {
		t.Fatal(got)
	}
	if i.FamilyName() != "Microsoft.WindowsTerminal_8wekyb3d8bbwe" {
		t.Fatal(i.FamilyName())
	}
}
