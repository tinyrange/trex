package cab

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func wrapCab(name string, payload []byte) []byte {
	b := companionFixture(0, "", "", 0, string(payload))
	delta := len(name) - len("whole.txt")
	b = bytes.Replace(b, []byte("whole.txt"), []byte(name), 1)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[36:], uint32(int(binary.LittleEndian.Uint32(b[36:]))+delta))
	binary.LittleEndian.PutUint32(b[44:], uint32(len(payload)))
	return b
}
func TestWrappedCompanionDiscovery(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		var entries []auto.Entry
		for name, data := range companionFiles() {
			entries = append(entries, auto.Entry{Name: "media/wrapper-" + name, Kind: "file", Reader: &starfile.Bytes{Data: wrapCab(strings.ToUpper(name), data)}})
		}
		if duplicate {
			entries = append(entries, auto.Entry{Name: "media/duplicate.cab", Kind: "file", Reader: &starfile.Bytes{Data: wrapCab("TWO.CAB", companionFiles()["two.cab"])}})
		}
		view, err := auto.Tree(entries, auto.Options{})
		if err != nil {
			t.Fatal(err)
		}
		node, err := auto.FromView(view, "", auto.Options{}).Resolve("media/wrapper-one.cab/ONE.CAB/whole.txt")
		if duplicate {
			if err == nil || !strings.Contains(err.Error(), "ambiguous") {
				t.Fatalf("duplicate: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(io.NewSectionReader(node.Reader(), 0, node.Reader().Size()))
		if err != nil || string(got) != "abcdefghi" {
			t.Fatalf("%q %v", got, err)
		}
	}
}
func TestWrappedDiscoveryStaysWithinContainingDirectory(t *testing.T) {
	var entries []auto.Entry
	for name, data := range companionFiles() {
		dir := "other"
		if name == "one.cab" {
			dir = "media"
		}
		entries = append(entries, auto.Entry{Name: dir + "/wrapper-" + name, Kind: "file", Reader: &starfile.Bytes{Data: wrapCab(name, data)}})
	}
	view, err := auto.Tree(entries, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = auto.FromView(view, "", auto.Options{}).Resolve("media/wrapper-one.cab/one.cab/whole.txt"); err == nil {
		t.Fatal("searched outside containing directory")
	}
}
