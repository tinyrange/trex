package uup

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/tinyrange/trex/archive/wim"
	starfile "github.com/tinyrange/trex/storage/star"
)

type testAssemblyArchive struct {
	files   map[string][]byte
	entries []wim.EntryInfo
	opened  []string
}

func (a *testAssemblyArchive) OpenFile(name string) (starfile.File, error) {
	a.opened = append(a.opened, name)
	if b, ok := a.files[name]; ok {
		return &starfile.Bytes{Name: name, Data: b}, nil
	}
	return nil, fmt.Errorf("missing %s", name)
}
func (a *testAssemblyArchive) List(string) ([]wim.EntryInfo, error) { return a.entries, nil }

func TestBaseAssemblyDescriptorDisambiguatesOnlyInferredNames(t *testing.T) {
	const root = "/image3/Windows/WinSxS/"
	const first = "amd64_component..resources_token_1.0_en-us_first"
	const second = "amd64_component..resources_token_1.0_en-us_second"
	want := []byte("correct resource")
	a := &testAssemblyArchive{
		files:   map[string][]byte{root + first + "/file.pri": []byte("wrong"), root + second + "/file.pri": want},
		entries: []wim.EntryInfo{{Name: first, Directory: true}, {Name: second, Directory: true}},
	}
	d := ContentDescriptor{Name: first + "\\file.pri", Length: int64(len(want)), SHA256: sha256.Sum256(want)}
	if _, err := resolveBaseAssemblyDescriptor(a, "/image3", d); err == nil {
		t.Fatal("explicit conflicting name was ignored")
	}
	if len(a.opened) != 1 {
		t.Fatal("explicit name searched alternatives")
	}
	d.nameHint = true
	got, err := resolveBaseAssemblyDescriptor(a, "/image3", d)
	if err != nil || got.Size() != int64(len(want)) {
		t.Fatalf("hint lookup: %v", err)
	}
	d.SHA256 = sha256.Sum256([]byte("different"))
	if _, err := resolveBaseAssemblyDescriptor(a, "/image3", d); err == nil {
		t.Fatal("accepted a size-only match")
	}
}

func TestBaseAssemblyDescriptorDisambiguatesInstalledVersions(t *testing.T) {
	const first = "amd64_component..payload_token_10.0.26100.1_none_first"
	const alternate = "amd64_component..payload_token_1.0.26100.1_none_second"
	want := []byte("correct resource")
	a := &testAssemblyArchive{files: map[string][]byte{"/image3/Windows/WinSxS/" + alternate + "/file.pri": want}, entries: []wim.EntryInfo{{Name: alternate, Directory: true}}}
	d := ContentDescriptor{Name: first + "\\file.pri", Length: int64(len(want)), SHA256: sha256.Sum256(want), nameHint: true}
	if _, err := resolveBaseAssemblyDescriptor(a, "/image3", d); err != nil {
		t.Fatalf("inferred version hid hash-exact basis: %v", err)
	}
	d.nameHint = false
	if _, err := resolveBaseAssemblyDescriptor(a, "/image3", d); err == nil {
		t.Fatal("explicit version ignored")
	}
}

func TestBaseAssemblyDescriptorDisambiguatesAbbreviatedLanguage(t *testing.T) {
	const first = "amd64_component.resources_token_1.0_sr-..-rs_first"
	const alternate = "amd64_component.resources_token_1.0_sr-..-rs_second"
	want := []byte("correct resource")
	a := &testAssemblyArchive{files: map[string][]byte{"/image3/Windows/WinSxS/" + alternate + "/file.mui": want}, entries: []wim.EntryInfo{{Name: alternate, Directory: true}}}
	d := ContentDescriptor{Name: first + "\\file.mui", Length: int64(len(want)), SHA256: sha256.Sum256(want), nameHint: true}
	if _, err := resolveBaseAssemblyDescriptor(a, "/image3", d); err != nil {
		t.Fatalf("language-only abbreviation hid hash-exact basis: %v", err)
	}
}

func TestBaseAssemblyDescriptorDoesNotCrossFamilyOrFile(t *testing.T) {
	const first = "amd64_component..resources_token_1.0_en-us_first"
	want := []byte("correct resource")
	a := &testAssemblyArchive{files: make(map[string][]byte)}
	for _, stem := range []string{
		"amd64_component..resources_token_1.0_fr-fr_other",
		"x86_component..resources_token_1.0_en-us_other",
		"amd64_different..resources_token_1.0_en-us_other",
		"amd64_component..resources_anothertoken_1.0_en-us_other",
	} {
		a.entries = append(a.entries, wim.EntryInfo{Name: stem, Directory: true})
		a.files["/image3/Windows/WinSxS/"+stem+"/file.pri"] = want
	}
	a.files["/image3/Windows/WinSxS/"+first+"/different.pri"] = want
	d := ContentDescriptor{Name: first + "\\file.pri", Length: int64(len(want)), SHA256: sha256.Sum256(want), nameHint: true}
	if _, err := resolveBaseAssemblyDescriptor(a, "/image3", d); err == nil {
		t.Fatal("unrelated candidate accepted")
	}
	if len(a.opened) != 1 {
		t.Fatal("unrelated candidate opened")
	}
}

func TestBaseAssemblyContentPathPreservesComponentPayloads(t *testing.T) {
	for name, want := range map[string]string{
		"Package_for_test.cat": "/image3/Windows/servicing/Packages/Package_for_test.cat",
		"assembly.manifest":    "/image3/Windows/WinSxS/Manifests/assembly.manifest",
		"amd64_component_token_1.0_none_hash\\adamschema.cat": "/image3/Windows/WinSxS/amd64_component_token_1.0_none_hash/adamschema.cat",
		"amd64_component_token_1.0_none_hash\\app.manifest":   "/image3/Windows/WinSxS/amd64_component_token_1.0_none_hash/app.manifest",
	} {
		got, err := baseAssemblyContentPath("/image3", name)
		if err != nil || got != want {
			t.Fatalf("%q: %q, %v", name, got, err)
		}
	}
}
