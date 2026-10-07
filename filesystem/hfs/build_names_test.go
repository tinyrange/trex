package hfs

import (
	"bytes"
	"github.com/tinyrange/trex/filesystem/unixfs"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestBuildPOSIXColonCatalogSlash(t *testing.T) {
	r, err := Build([]BuildEntry{{Entry: unixfs.Entry{Path: "folder/Farallon LAN:Modem", Mode: unixfs.Regular | 0644, Data: bytes.NewReader([]byte("driver"))}}}, BuildOptions{Size: 32 << 20, Label: "names"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := Open(starfile.NewReader("test", r), 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range v.Entries {
		if e.Path == "/folder/Farallon LAN%2FModem" {
			found = true
			if string(e.Name) != "Farallon LAN/Modem" {
				t.Fatal(string(e.Name))
			}
		}
	}
	if !found {
		t.Fatal("POSIX colon not represented by native catalog slash")
	}
}
