package uup

import (
	"strings"
	"testing"
)

func TestCSIIdentityStrictParsing(t *testing.T) {
	text := "Microsoft-Windows-IIS-IISCertificateMappingAuthentication, Culture=neutral, Version=10.0.26100.7920, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=NonSxS"
	id, err := parseCSIIdentity([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "Microsoft-Windows-IIS-IISCertificateMappingAuthentication" || id.Version != "10.0.26100.7920" || id.VersionScope != "NonSxS" {
		t.Fatalf("lost identity: %+v", id)
	}
	for _, bad := range []string{"", text + "\x00", text + ", Version=1.2.3.4", text + ", FuturePolicy=maybe", strings.Replace(text, ", Culture=neutral", "", 1), strings.Replace(text, "10.0.26100.7920", "10.0.1", 1), text + ", Type=", string([]byte{255})} {
		if _, err := parseCSIIdentity([]byte(bad)); err == nil {
			t.Fatalf("accepted malformed identity %q", bad)
		}
	}
	typed, err := parseCSIIdentity([]byte(text + ", Type=win32"))
	if err != nil || len(typed.Attributes) != 1 || typed.Attributes[0].Value != "win32" {
		t.Fatal(typed, err)
	}
}

func TestExactComponentInventorySeparatesAbbreviationCollisions(t *testing.T) {
	// These two real WinSxS names share an abbreviation and version but have
	// different full identities and hashes. Neither may stand in for the other.
	const prefix = "amd64_microsoft-windows-i..ppingauthentication_31bf3856ad364e35_10.0.26100.7920_none_"
	makeComponent := func(name, hash string) manifestPath {
		filename := prefix + hash + ".manifest"
		component, err := ParseComponentManifestName(filename)
		if err != nil {
			t.Fatal(err)
		}
		id := component.Identity
		id.Name = name
		return manifestPath{Path: filename, Identity: id, Component: component}
	}
	client := makeComponent("Microsoft-Windows-IIS-ClientCertificateMappingAuthentication", "5a73d8108218d44a")
	iis := makeComponent("Microsoft-Windows-IIS-IISCertificateMappingAuthentication", "98b072312f1e0202")
	state, err := newExactAssemblyImageState(nil, []manifestPath{client, iis})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []manifestPath{client, iis} {
		future := want.Identity
		future.Version = "10.0.26100.9711"
		got, found := state.latestInstalledComponent(future)
		if !found || got.Component.Stem != want.Component.Stem {
			t.Fatalf("wrong predecessor: %+v %v", got, found)
		}
		if !state.hasInstalledComponent(want.Identity) || state.hasInstalledComponent(future) {
			t.Fatal("lost exact version constraint")
		}
	}
	onlyClient, err := newExactAssemblyImageState(nil, []manifestPath{client})
	if err != nil {
		t.Fatal(err)
	}
	if onlyClient.hasInstalledComponent(iis.Identity) {
		t.Fatal("abbreviation satisfied a different prerequisite")
	}
	if _, found := onlyClient.latestInstalledComponent(iis.Identity); found {
		t.Fatal("abbreviation selected foreign predecessor")
	}
	newer := iis
	newer.Identity.Version = "10.0.26100.9711"
	newer.Component.Stem = "new-iis"
	state.rememberExactComponent(newer)
	got, found := state.latestInstalledComponent(iis.Identity)
	if !found || got.Component.Stem != "new-iis" {
		t.Fatal("prior stage identity was not retained")
	}
	got, _ = state.latestInstalledComponent(client.Identity)
	if got.Component.Stem != client.Component.Stem {
		t.Fatal("prior stage contaminated another family")
	}
}
