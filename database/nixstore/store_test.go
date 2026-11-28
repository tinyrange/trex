package nixstore

import (
	"strings"
	"testing"

	"github.com/tinyrange/trex/database/sqlite"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestBuildRegistersPathsAndReferenceIndexes(t *testing.T) {
	first := "/nix/store/" + strings.Repeat("0", 32) + "-bash"
	second := "/nix/store/" + strings.Repeat("1", 32) + "-libc"
	hash := "sha256:1" + strings.Repeat("0", 50) + "1"
	manifest := second + "\n" + hash + "\n8\n\n0\n" + first + "\n" + hash + "\n16\n\n2\n" + first + "\n" + second + "\n"
	image, err := Build(&starfile.Bytes{Data: []byte(manifest)})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(image, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Rows("ValidPaths", 3)
	wantHash := "sha256:01" + strings.Repeat("00", 30) + "80"
	if err != nil || len(rows) != 2 || rows[0].Values[1] != first || rows[0].Values[2] != wantHash || rows[0].Values[5] != int64(16) {
		t.Fatalf("paths %+v: %v", rows, err)
	}
	rows, err = db.Rows("IndexReference", 3)
	if err != nil || len(rows) != 2 || rows[0].Values[0] != int64(1) || rows[1].Values[0] != int64(2) {
		t.Fatalf("reference index %+v: %v", rows, err)
	}
}

func TestBuildClosureOmitsUnselectedSystems(t *testing.T) {
	root := "/nix/store/" + strings.Repeat("1", 32) + "-system"
	dependency := "/nix/store/" + strings.Repeat("2", 32) + "-shell"
	other := "/nix/store/" + strings.Repeat("3", 32) + "-other-system"
	hash := "sha256:" + strings.Repeat("00", 32)
	record := func(path string, references ...string) string {
		result := path + "\n" + hash + "\n8\n\n0\n"
		if len(references) == 1 {
			result = path + "\n" + hash + "\n8\n\n1\n" + references[0] + "\n"
		}
		return result
	}
	manifest := &starfile.Bytes{Data: []byte(record(other) + record(root, dependency) + record(dependency, dependency))}
	image, paths, err := BuildClosure(manifest, []string{root})
	if err != nil || len(paths) != 2 || paths[0] != root || paths[1] != dependency {
		t.Fatalf("paths %v: %v", paths, err)
	}
	db, err := sqlite.Open(image, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Rows("ValidPaths", 3)
	if err != nil || len(rows) != 2 || rows[0].Values[1] != root || rows[1].Values[1] != dependency {
		t.Fatalf("database has %+v: %v", rows, err)
	}
}
