package windows

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAppxFrameworkACLNativeGrants(t *testing.T) {
	parent, _ := hex.DecodeString("020034000200000000031400ff011f0001010000000000051200000000021800a900120001020000000000052000000020020000")
	// Captured Windows 11 inbox VCLibs file grants: ALL APPLICATION PACKAGES,
	// ALL RESTRICTED APPLICATION PACKAGES, then Users, each read/execute.
	native, _ := hex.DecodeString("00101800a9001200010200000000000f020000000100000000101800a9001200010200000000000f020000000200000000101800a900120001020000000000052000000021020000")
	for _, kind := range []string{"root", "directory", "file"} {
		got, err := appxPackageACL(parent, "Microsoft.Services.Store.Engagement_8wekyb3d8bbwe", kind, true)
		if err != nil {
			t.Fatal(err)
		}
		_, entries, err := ParseACL(got)
		if err != nil {
			t.Fatal(err)
		}
		flags := byte(3)
		if kind == "directory" {
			flags = 19
		}
		if kind == "file" {
			flags = 16
		}
		for i := 0; i < 3; i++ {
			want := append([]byte(nil), native[i*24:(i+1)*24]...)
			want[1] = flags
			if !bytes.Equal(entries[i].Data, want) {
				t.Fatalf("%s grant %d: %x != %x", kind, i, entries[i].Data, want)
			}
		}
		// No broad write grant; service/admin inheritance still follows the parent.
		if entries[3].Mask != 0x1f01ff {
			t.Fatal("SYSTEM inheritance lost")
		}
	}
}
