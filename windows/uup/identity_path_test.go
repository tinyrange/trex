package uup

import "testing"

func TestComponentPathAbbreviationMatchesOmittedNameRun(t *testing.T) {
	candidate, err := ParseComponentManifestName("amd64_system.diagnostics...writertracelistener_b03f5f7f11d50a3a_4.0.15920.100_none_a01f5ff131c87fea.manifest")
	if err != nil {
		t.Fatal(err)
	}
	wanted := AssemblyIdentity{Name: "System.Diagnostics.TextWriterTraceListener", Version: "4.0.15920.100", ProcessorArchitecture: "amd64", Language: "neutral", PublicKeyToken: "b03f5f7f11d50a3a"}
	if !componentPathMayMatch(candidate, wanted) {
		t.Fatalf("%q did not match %q", candidate.Identity.Name, wanted.Name)
	}
}

func TestComponentPathAbbreviationMatchesCanonicalizedSpaces(t *testing.T) {
	candidate, err := ParseComponentManifestName("amd64_microsoft-windows-s..configurationengine_31bf3856ad364e35_10.0.26100.1150_none_a01f5ff131c87fea.manifest")
	if err != nil {
		t.Fatal(err)
	}
	wanted := AssemblyIdentity{Name: "Microsoft-Windows-Security-Security Configuration Engine", Version: "10.0.26100.1150", ProcessorArchitecture: "amd64", Language: "neutral", PublicKeyToken: "31bf3856ad364e35"}
	if !componentPathMayMatch(candidate, wanted) {
		t.Fatalf("%q did not match %q", candidate.Identity.Name, wanted.Name)
	}
}

func TestComponentPathAbbreviationMatchesCanonicalizedParentheses(t *testing.T) {
	candidate, err := ParseComponentManifestName("amd64_microsoft-windows-b..filesystemscore_31bf3856ad364e35_10.0.26100.1_none_a01f5ff131c87fea.manifest")
	if err != nil {
		t.Fatal(err)
	}
	wanted := AssemblyIdentity{Name: "Microsoft-Windows-Base Technologies-File Systems (Core)", Version: "10.0.26100.1", ProcessorArchitecture: "amd64", Language: "neutral", PublicKeyToken: "31bf3856ad364e35"}
	if !componentPathMayMatch(candidate, wanted) {
		t.Fatalf("%q did not match %q", candidate.Identity.Name, wanted.Name)
	}
}

func TestComponentPathMatchesAbbreviatedNameAndLocale(t *testing.T) {
	candidate, err := ParseComponentManifestName("amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_5.82.26100.1591_uz-..-uz_0fbfb1c9f2926e3e.manifest")
	if err != nil {
		t.Fatal(err)
	}
	wanted := AssemblyIdentity{Name: "Microsoft.Windows.Common-Controls.Resources", Version: "5.82.26100.1591", ProcessorArchitecture: "amd64", Language: "uz-Latn-UZ", PublicKeyToken: "6595b64144ccf1df"}
	if !componentPathMayMatch(candidate, wanted) {
		t.Fatalf("candidate = %#v, wanted = %#v", candidate, wanted)
	}
}

func TestComponentPathMatchesUnabbreviatedCanonicalName(t *testing.T) {
	candidate, err := ParseComponentManifestName("amd64_microsoft-windows-wdf-usermodelibrary_31bf3856ad364e35_10.0.26100.1591_none_f4a95a899b0cfa49.manifest")
	if err != nil {
		t.Fatal(err)
	}
	wanted := AssemblyIdentity{Name: "Microsoft-Windows-WDF-Usermode Library", Version: "10.0.26100.1591", ProcessorArchitecture: "amd64", Language: "neutral", PublicKeyToken: "31bf3856ad364e35"}
	if !componentPathMayMatch(candidate, wanted) {
		t.Fatalf("candidate = %#v, wanted = %#v", candidate, wanted)
	}
	if componentCanonicalKey(candidate.Identity) != componentCanonicalKey(wanted) {
		t.Fatalf("canonical keys differ: %q != %q", componentCanonicalKey(candidate.Identity), componentCanonicalKey(wanted))
	}
}

func TestComponentPathMatchesWildcardDependencyLanguage(t *testing.T) {
	candidate, err := ParseComponentManifestName("amd64_microsoft.windows.isolationautomation.proxystub_6595b64144ccf1df_1.0.0.0_none_f4a95a899b0cfa49.manifest")
	if err != nil {
		t.Fatal(err)
	}
	wanted := AssemblyIdentity{Name: "Microsoft.Windows.IsolationAutomation.ProxyStub", Version: "1.0.0.0", ProcessorArchitecture: "amd64", Language: "*", PublicKeyToken: "6595b64144ccf1df"}
	if !componentPathMayMatch(candidate, wanted) || !assemblyIdentityMatches(candidate.Identity, wanted) {
		t.Fatalf("candidate = %#v, wanted = %#v", candidate, wanted)
	}
}
