package inno

import (
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestMissingWildcardRetainsInventory(t *testing.T) {
	for _, presentDirectory := range []bool{false, true} {
		b, _ := fixture(t, false, "{app}/hello.txt")
		entries := []auto.Entry{{Name: "setup.exe", Kind: "file", Reader: &starfile.Bytes{Data: b}}}
		if presentDirectory {
			entries = append(entries, auto.Entry{Name: "extras", Kind: "directory"})
		}
		tree, err := auto.Tree(entries, auto.Options{})
		if err != nil {
			t.Fatal(err)
		}
		root := auto.FromView(tree, "", auto.Options{})
		missing, err := root.Resolve("setup.exe/{app}/extras/*.*")
		if err != nil {
			t.Fatal(err)
		}
		if missing.Reader() != nil {
			t.Fatal("invented payload for missing wildcard")
		}
	}
}
