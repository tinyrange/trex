package uup

import (
	"encoding/base64"
	"strings"
	"testing"
)

func mofTestDigest(b byte) *AssemblyFileDigest {
	return &AssemblyFileDigest{Algorithm: assemblyDigestNamespace + "sha256", Transforms: []string{assemblyIdentityTransform}, Value: base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{b}), 32)))}
}

func TestCSIFileHashesEqual(t *testing.T) {
	a := AssemblyFile{Digest: mofTestDigest(1)}
	legacyA, legacyB := strings.Repeat("ab", 20), strings.Repeat("cd", 20)
	tests := []struct {
		name        string
		left, right AssemblyFile
		equal, bad  bool
	}{
		{"nested match", a, a, true, false},
		{"nested mismatch", a, AssemblyFile{Digest: mofTestDigest(2)}, false, false},
		{"no hashes", AssemblyFile{}, AssemblyFile{}, false, false},
		{"one hash", a, AssemblyFile{}, false, false},
		{"legacy case", AssemblyFile{Hash: legacyA, HashAlgorithm: "SHA1"}, AssemblyFile{Hash: strings.ToUpper(legacyA), HashAlgorithm: "SHA1"}, true, false},
		{"legacy veto", AssemblyFile{Digest: mofTestDigest(1), Hash: legacyA, HashAlgorithm: "SHA1"}, AssemblyFile{Digest: mofTestDigest(1), Hash: legacyB, HashAlgorithm: "SHA1"}, false, false},
		{"nested veto", AssemblyFile{Digest: mofTestDigest(1), Hash: legacyA, HashAlgorithm: "SHA1"}, AssemblyFile{Digest: mofTestDigest(2), Hash: legacyA, HashAlgorithm: "SHA1"}, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eq, err := CSIFileHashesEqual(tc.left, tc.right)
			if eq != tc.equal || (err != nil) != tc.bad {
				t.Fatalf("equal=%v err=%v", eq, err)
			}
		})
	}
	for _, kind := range []string{"algorithm", "transform", "extra transform", "invalid value"} {
		b := AssemblyFile{Digest: mofTestDigest(1)}
		switch kind {
		case "algorithm":
			b.Digest.Algorithm = "unknown"
		case "transform":
			b.Digest.Transforms = []string{"unknown"}
		case "extra transform":
			b.Digest.Transforms = append(b.Digest.Transforms, assemblyIdentityTransform)
		case "invalid value":
			b.Digest.Value = "!"
		}
		if _, err := CSIFileHashesEqual(a, b); err == nil {
			t.Errorf("accepted %s", kind)
		}
	}
	b := AssemblyFile{Digest: mofTestDigest(1)}
	b.Digest.Transforms = nil
	if eq, err := CSIFileHashesEqual(a, b); eq || err != nil {
		t.Fatalf("different transform presence: %v %v", eq, err)
	}
	// Native string comparison is not a comparison after base64 normalization.
	b = AssemblyFile{Digest: mofTestDigest(1)}
	b.Digest.Value += "\n"
	if eq, err := CSIFileHashesEqual(a, b); eq || err != nil {
		t.Fatalf("normalized digest text: %v %v", eq, err)
	}
}

func mofTestManifest() *AssemblyManifest {
	return &AssemblyManifest{MOFs: []AssemblyMOF{{Name: `$(runtime.wbem)\Provider.mof`, UninstallPresent: true, Uninstall: `$(runtime.wbem)\remove.mof`}}, Files: []AssemblyFile{{Name: "provider.MOF", Digest: mofTestDigest(1)}, {Name: "remove.mof", Digest: mofTestDigest(2)}}}
}

func TestCSIMOFEquivalent(t *testing.T) {
	for _, tc := range []struct {
		name       string
		change     func(*AssemblyManifest)
		equal, bad bool
	}{
		{"file name case", func(m *AssemblyManifest) { m.Files[0].Name = "PROVIDER.mof" }, true, false},
		{"declaration case", func(m *AssemblyManifest) { m.MOFs[0].Name = `$(runtime.wbem)\provider.mof` }, false, false},
		{"primary hash", func(m *AssemblyManifest) { m.Files[0].Digest = mofTestDigest(3) }, false, false},
		// Native's uninstall branch intentionally rechecks the primary file.
		{"uninstall payload not compared", func(m *AssemblyManifest) { m.Files[1].Digest = mofTestDigest(3) }, true, false},
		{"uninstall declaration", func(m *AssemblyManifest) { m.MOFs[0].Uninstall = "other.mof" }, false, false},
		{"uninstall presence", func(m *AssemblyManifest) { m.MOFs[0].UninstallPresent = false }, false, false},
		{"missing file", func(m *AssemblyManifest) { m.Files = m.Files[1:] }, false, false},
		{"missing hash", func(m *AssemblyManifest) { m.Files[0].Digest = nil }, false, false},
		{"ambiguous file", func(m *AssemblyManifest) { m.Files = append(m.Files, m.Files[0]) }, false, true},
		{"count", func(m *AssemblyManifest) { m.MOFs = nil }, false, false},
		{"unknown policy", func(m *AssemblyManifest) { m.MOFs[0].Attributes = []ManifestAttribute{{Name: "future", Value: "yes"}} }, false, true},
		{"non ASCII", func(m *AssemblyManifest) { m.Files[0].Name = "pröv.mof" }, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := mofTestManifest(), mofTestManifest()
			tc.change(b)
			equal, err := CSIMOFEquivalent(a, b)
			if equal != tc.equal || (err != nil) != tc.bad {
				t.Fatalf("equal=%v err=%v", equal, err)
			}
		})
	}
	a, b := mofTestManifest(), mofTestManifest()
	second := AssemblyMOF{Name: "remove.mof"}
	a.MOFs = append(a.MOFs, second)
	b.MOFs = append([]AssemblyMOF{second}, b.MOFs...)
	if equal, err := CSIMOFEquivalent(a, b); equal || err != nil {
		t.Fatalf("order: %v %v", equal, err)
	}
	if equal, err := CSIMOFEquivalent(&AssemblyManifest{}, &AssemblyManifest{}); !equal || err != nil {
		t.Fatalf("empty: %v %v", equal, err)
	}
}

func TestParseAssemblyMOF(t *testing.T) {
	wrap := func(body string) string {
		return `<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="test" version="1.0.0.0"/>` + body + `</assembly>`
	}
	m, err := ParseAssemblyManifest(strings.NewReader(wrap(`<mof name="a.mof"/><mof name="b.mof" uninstallmof=""/>`)))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.MOFs) != 2 || m.MOFs[0].Name != "a.mof" || m.MOFs[0].UninstallPresent || !m.MOFs[1].UninstallPresent {
		t.Fatalf("%+v", m.MOFs)
	}
	for _, body := range []string{`<mof/>`, `<mof name="a" name="b"/>`, `<mof name="a">text</mof>`, `<mof name="a"><child/></mof>`, `<mof name="a">`} {
		if _, err := ParseAssemblyManifest(strings.NewReader(wrap(body))); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
	m, err = ParseAssemblyManifest(strings.NewReader(wrap(`<mof xmlns="other" name="a"/>`)))
	if err != nil || len(m.MOFs) != 0 {
		t.Fatalf("foreign MOF: %v %v", m, err)
	}
}
