package uup

import (
	"fmt"
	"testing"
)

func TestCSIIdentityHashNativeFixtures(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"0074283ce7ee52524aaa00edcf95464e, Culture=neutral, Version=4.0.15920.100, PublicKeyToken=b77a5c561934e089, ProcessorArchitecture=amd64, versionScope=NonSxS", "3fb84cbf20555c08"},
		{"Microsoft-Windows-IIS-ClientCertificateMappingAuthentication, Culture=neutral, Version=10.0.26100.7920, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=NonSxS", "5a73d8108218d44a"},
		{"Microsoft-Windows-IIS-IISCertificateMappingAuthentication, Culture=neutral, Version=10.0.26100.7920, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=NonSxS", "98b072312f1e0202"},
		{"HyperV-Compute-EventLog, Culture=neutral, Version=10.0.26100.8328, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=NonSxS", "7ba4854d722b50c1"},
	} {
		id, err := parseCSIIdentity([]byte(tc.text))
		if err != nil {
			t.Fatal(err)
		}
		hash, err := csiIdentityHash(id, false)
		if err != nil || fmt.Sprintf("%016x", hash) != tc.want {
			t.Fatalf("%s: %016x %v", id.Name, hash, err)
		}
		family, err := csiIdentityHash(id, true)
		if err != nil {
			t.Fatal(err)
		}
		id.Version = "10.0.26100.9711"
		other, err := csiIdentityHash(id, true)
		if err != nil || family != other {
			t.Fatal("family hash changed with version")
		}
	}
	for _, text := range []string{"unsupported-\u00e9", "\u212A"} {
		if _, err := csiTextHash(text); err == nil {
			t.Fatal("approximated non-ASCII case folding")
		}
	}
}
