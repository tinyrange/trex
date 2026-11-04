package uup

import "testing"

func TestCSIFileDestinationName(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{`dir\leaf.dll`, "leaf.dll"}, {`dir\nested\`, `dir\nested`},
		{`leaf.dll`, "leaf.dll"}, {`dir/leaf.dll`, "dir/leaf.dll"}, {`\`, ""}, {"", ""},
	} {
		got, err := CSIFileDestinationName(AssemblyFile{Name: tc.name})
		if err != nil || got != tc.want {
			t.Errorf("%q: got %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
	f := AssemblyFile{Name: `dir\source.dll`, Attributes: []ManifestAttribute{{Name: "destinationName", Value: "renamed.dll"}}}
	if got, err := CSIFileDestinationName(f); err != nil || got != "renamed.dll" {
		t.Fatalf("override: %q, %v", got, err)
	}
	f.Attributes[0].Value = ""
	if got, err := CSIFileDestinationName(f); err != nil || got != "" {
		t.Fatalf("present empty override: %q, %v", got, err)
	}
	f.Attributes[0].Namespace = "foreign"
	if got, err := CSIFileDestinationName(f); err != nil || got != "source.dll" {
		t.Fatalf("foreign attribute: %q, %v", got, err)
	}
	f.Attributes = []ManifestAttribute{{Name: "destinationName"}, {Name: "destinationName"}}
	if _, err := CSIFileDestinationName(f); err == nil {
		t.Fatal("duplicate override accepted")
	}
}

func TestCSIFileDirectoryMacroArchitecture(t *testing.T) {
	// Native PSEUDO_ARCH bytes: amd64=0900ffff, msil=0800ffff,
	// x86=0000ffff, wow64/amd64.x86=09000000. MSIL stays native.
	for _, arch := range []string{"amd64", "msil", "data", "", "x86", "wow64", "amd64.x86"} {
		want := uint32(37)
		if arch == "x86" || arch == "wow64" || arch == "amd64.x86" {
			want = 41
		}
		got, err := CSIFileDirectoryMacro("AMD64", arch, "Runtime.System32")
		if err != nil || got != want {
			t.Errorf("%s: got %d, %v; want %d", arch, got, err, want)
		}
	}
	for _, tc := range []struct {
		arch, macro string
		want        uint32
	}{
		{"amd64", "runtime.programFiles", 38}, {"wow64", "runtime.programFiles", 42},
		{"msil", "runtime.commonFiles", 43}, {"x86", "runtime.commonFiles", 44},
		{"amd64", "runtime.syswow64", 41}, {"wow64", "runtime.drivers", 0xe0000},
		{"amd64", "runtime.wbem", 0x70000}, {"wow64", "runtime.wbem", 0xf0000},
		{"amd64", "runtime.userProfile", 0x110000}, {"wow64", "runtime.userProfile", 0x110000},
		{"amd64", "runtime.programFilesX86", 42}, {"amd64", "runtime.systemroot", 36},
	} {
		got, err := CSIFileDirectoryMacro("amd64", tc.arch, tc.macro)
		if err != nil || got != tc.want {
			t.Errorf("%s/%s: got %d, %v; want %d", tc.arch, tc.macro, got, err, tc.want)
		}
	}
	for _, tc := range [][3]string{
		{"arm64", "amd64", "runtime.system32"}, {"amd64", "arm64", "runtime.system32"},
		{"amd64", "neutral", "runtime.system32"}, {"amd64", "amd64", "runtime.unknown"},
		{"amd64", "amd64", "Runtime.ſystem32"}, {"amd64", "amd64", "$(runtime.system32)"},
		{"amd64", "amd64", "runtime.system32\x00"},
	} {
		if _, err := CSIFileDirectoryMacro(tc[0], tc[1], tc[2]); err == nil {
			t.Errorf("unsupported policy accepted: %q", tc)
		}
	}
}

func TestCSIFileAttributesPresenceAndTokens(t *testing.T) {
	if got, err := CSIFileAttributes(AssemblyFile{}); err != nil || got != 0xa0 {
		t.Fatalf("absent attributes: %#x, %v", got, err)
	}
	for _, tc := range []struct {
		value string
		want  uint32
	}{
		{"", 0}, {" \t\r\n", 0}, {"hidden system readOnly", 7},
		{"system readOnly", 5}, {"readOnly hidden", 3},
		{"READONLY readonly\tHidden", 3},
		{"archive temporary offline notContentIndexed", 0x3120},
	} {
		got, err := CSIFileAttributes(AssemblyFile{Attributes: []ManifestAttribute{{Name: "attributes", Value: tc.value}}})
		if err != nil || got != tc.want {
			t.Errorf("%q: %#x, %v; want %#x", tc.value, got, err, tc.want)
		}
	}
	for _, value := range []string{"normal", "directory", "compressed", "readOnly,hidden", "hidden\vsystem", "hidden\fsystem", "hidden\u00a0system", "hidden\x00"} {
		if _, err := CSIFileAttributes(AssemblyFile{Attributes: []ManifestAttribute{{Name: "attributes", Value: value}}}); err == nil {
			t.Errorf("unsupported attributes accepted: %q", value)
		}
	}
	foreign := AssemblyFile{Attributes: []ManifestAttribute{{Namespace: "foreign", Name: "attributes", Value: "hidden"}}}
	if got, err := CSIFileAttributes(foreign); err != nil || got != 0xa0 {
		t.Fatalf("foreign attribute: %#x, %v", got, err)
	}
	duplicate := AssemblyFile{Attributes: []ManifestAttribute{{Name: "attributes"}, {Name: "attributes", Value: "hidden"}}}
	if _, err := CSIFileAttributes(duplicate); err == nil {
		t.Fatal("duplicate attributes accepted")
	}
}
