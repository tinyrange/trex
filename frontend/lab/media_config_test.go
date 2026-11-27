package labfrontend

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tinyrange/trex/lab"
)

func TestConfiguredMediaDiscovery(t *testing.T) {
	local := t.TempDir()
	mount := filepath.Join(local, "media")
	for _, folder := range []string{"microsoft/windows_2000", "fedora", "private", ".hidden"} {
		if err := os.MkdirAll(filepath.Join(mount, folder), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"microsoft/windows_2000/install.iso", "private/secret.iso"} {
		if err := os.WriteFile(filepath.Join(mount, file), []byte("test media"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"redirect": "private", "microsoft/secret.iso": "../private/secret.iso"} {
		if err := os.Symlink(target, filepath.Join(mount, link)); err != nil {
			t.Fatal(err)
		}
	}
	filename := filepath.Join(local, "lab-media.json")
	config := `{"directory":"media","exclude":["private"],"names":{"microsoft":"Microsoft"},"manifest":"manifest.json"}`
	if err := os.WriteFile(filename, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	var library mediaLibrary
	defer library.close()
	manifest := `{"win2000":{"system":"Microsoft/windows_2000/install.iso"}}`
	if err := os.WriteFile(filepath.Join(local, "manifest.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	media := []lab.Media{{Key: "system", Kind: "file"}}
	catalog := []lab.Recipe{{ID: "win2000", Media: media}}
	if err := library.configure(".", filename, catalog); err != nil {
		t.Fatal(err)
	}
	if got := media[0].Default; got != "Microsoft/windows_2000/install.iso" {
		t.Fatalf("catalog default = %q", got)
	}
	page, err := library.browse("")
	if want := []mediaItem{{"fedora", "fedora", "folder"}, {"Microsoft", "Microsoft", "folder"}}; err != nil || !slices.Equal(page.Items, want) {
		t.Fatalf("discovered media = %+v, %v; want %+v", page.Items, err, want)
	}
	for _, ref := range []string{"private/secret.iso", "redirect/secret.iso", "Microsoft/secret.iso"} {
		if _, closeFile, err := library.open(ref); err == nil {
			closeFile()
			t.Errorf("opened excluded media %q", ref)
		}
	}
	if err := os.WriteFile(filepath.Join(mount, "microsoft/windows_2000/new.iso"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	page, err = library.browse("Microsoft/windows_2000")
	if err != nil || len(page.Items) != 2 || page.Items[1].Ref != "Microsoft/windows_2000/new.iso" {
		t.Fatalf("browse missed newly added media: %+v, %v", page.Items, err)
	}
	if err := library.check(lab.Recipe{}, lab.Media{Kind: "file"}, page.Items[0].Ref); err != nil {
		t.Fatal(err)
	}
}
