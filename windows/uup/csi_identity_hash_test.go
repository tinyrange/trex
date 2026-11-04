package uup

import "testing"

func TestHashCSIIdentityNativeFamilyKeys(t *testing.T) {
	for _, tc := range []struct {
		text              string
		component, family uint64
	}{
		{"0074283ce7ee52524aaa00edcf95464e, Culture=neutral, Version=4.0.15920.100, PublicKeyToken=b77a5c561934e089, ProcessorArchitecture=amd64, versionScope=NonSxS", 0x3fb84cbf20555c08, 0x5a18b21987f88500},
		{"Microsoft-Windows-Kernel32, Culture=neutral, Version=10.0.26100.9444, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=NonSxS", 0x2f8379ba064efb69, 0xb8cd4325e211ffa2},
	} {
		for _, omit := range []bool{false, true} {
			want := tc.component
			if omit {
				want = tc.family
			}
			got, err := HashCSIIdentity([]byte(tc.text), omit)
			if err != nil || got != want {
				t.Fatalf("%s omit=%v: %016x want %016x: %v", tc.text, omit, got, want, err)
			}
		}
	}
	// Family hashes require the full canonical identity too. Do not hash a
	// lossy WinSxS key or quietly approximate non-ASCII identity folding.
	for _, bad := range []string{"amd64_microsoft-..kernel32_31bf3856ad364e35", "Kernelé, Culture=neutral, Version=10.0.1.2, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64"} {
		if _, err := HashCSIIdentity([]byte(bad), true); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}
