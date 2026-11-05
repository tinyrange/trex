package uup

import (
	"strings"
	"testing"
)

func TestCSIWinnerFamilyKeyNative(t *testing.T) {
	for _, tc := range []struct{ identity, want string }{
		{"dual_1394.inf, Culture=neutral, Type=dualModeDriver, Version=10.0.26100.1150, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS", "amd64_dual_1394.inf_31bf3856ad364e35_none_342cbcda1751ed79"},
		{"policy.8.0.Microsoft.VC80.CRT, Culture=neutral, Type=win32-policy, Version=8.0.50727.9680, PublicKeyToken=1fc8b3b9a1e18e3b, ProcessorArchitecture=x86", "x86_policy.8.0.microsoft.vc80.crt_1fc8b3b9a1e18e3b_none_e8a8ec119a3821e7"},
		{"Composition-Core-merged-Deployment-LanguagePack, Culture=en-US, Version=10.0.26100.9278, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS", "amd64_composition-core-me..oyment-languagepack_31bf3856ad364e35_en-us_82e0b9dff1af0be0"},
	} {
		got, err := CSIWinnerFamilyKey([]byte(tc.identity))
		if err != nil || got != tc.want {
			t.Fatalf("%s: %s %v", tc.identity, got, err)
		}
		id, _ := parseCSIIdentity([]byte(tc.identity))
		newer := strings.Replace(tc.identity, "Version="+id.Version, "Version=20.1.2.3", 1)
		same, err := CSIWinnerFamilyKey([]byte(newer))
		if err != nil || same != got {
			t.Fatalf("version affected family: %s %v", same, err)
		}
	}
}

func TestCSIKeyFormPartNativeScanning(t *testing.T) {
	for _, tc := range []struct {
		input string
		limit int
		want  string
	}{
		{"A (B)+C_!", 8, "abc_"},
		{"abcdefgh", 8, "abcdefgh"},
		{"abcdefghi", 8, "abc..ghi"},
		// Native scanning fills both ends before seeing this punctuation.
		{"abcd()efgh", 8, "abc..fgh"},
		{"(abcdefgh)", 8, "abcdefgh"},
		{"abc()def", 8, "abcdef"},
		{"!()", 8, ""},
	} {
		if got := csiKeyFormPart(tc.input, tc.limit); got != tc.want {
			t.Fatalf("%q: %q != %q", tc.input, got, tc.want)
		}
	}
}

func TestCSIWinnerFamilyKeyRejectsUnsupported(t *testing.T) {
	base := "Example, Culture=neutral, Version=1.2.3.4, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"
	for _, bad := range []string{
		strings.Replace(base, "Example", "Exämple", 1),
		strings.Replace(base, "Example", "../Example", 1),
		strings.Replace(base, "amd64", "invented", 1),
		strings.Replace(base, "31bf3856ad364e35", "not-a-token", 1),
		base + ", typeName=Custom",
	} {
		if _, err := CSIWinnerFamilyKey([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
