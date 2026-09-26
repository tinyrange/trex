package udf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
)

type corpusReader struct {
	*os.File
	size int64
}

func (r corpusReader) Size() int64 { return r.size }

func TestVIOSSymbolicLinks(t *testing.T) {
	root := os.Getenv("TREX_NAS_ROOT")
	if root == "" {
		t.Skip("set TREX_NAS_ROOT for optical-media corpus")
	}
	f, err := os.Open(filepath.Join(root, "ibm/ibm_i_7.5_download_set/Virtual_IO_Server_Base_Install_2.2.6.65_Flash_072020_LCD8236306.iso"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	source := corpusReader{f, stat.Size()}
	result, err := auto.Identify(source, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Format != "udf" {
		t.Fatal(result.Format)
	}
	view := result.View
	for _, name := range []string{"nimol", "ioserver_res"} {
		entries, err := view.Entries()
		if err != nil {
			t.Fatal(err)
		}
		view = nil
		for _, entry := range entries {
			if entry.Name == name {
				view = entry.View
			}
		}
		if view == nil {
			t.Fatal("missing", name)
		}
	}
	entries, err := view.Entries()
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, entry := range entries {
		if entry.Name == "mksysb" || entry.Name == "mksysb2" {
			found++
			want := "../../usr/sys/inst.images/mksysb_image"
			if entry.Name == "mksysb2" {
				want += "2"
			}
			if entry.Kind != "symlink" || entry.Reader != nil || entry.Attributes["link"] != want {
				t.Fatal(entry)
			}
			t.Logf("%s -> %s", entry.Name, want)
		}
	}
	if found != 2 {
		t.Fatal(found)
	}
	img, err := newUDFImage(adapter.File(source))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mksysb", "mksysb2"} {
		entry, err := img.lookup("/nimol/ioserver_res/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if entry.typ != 12 || entry.link == "" {
			t.Fatal(entry)
		}
	}
}
