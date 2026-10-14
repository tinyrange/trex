package mtree

import (
	"strings"
	"testing"
)

func TestMetadataDefaultsHierarchyEscapesAndContinuation(t *testing.T) {
	s := "/set type=file uid=0\n. type=dir inode=2\nApplication\\040Support type=dir\nitem inode=45 \\\n  time=123.000000001\n..\n/unset uid\nlink type=link link=Application\\040Support/item\n..\n"
	e, err := Read(strings.NewReader(s), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(e) != 4 || e[1].Path != "/Application Support" || e[2].Path != "/Application Support/item" || e[2].Attributes["time"] != "123.000000001" || e[2].Attributes["uid"] != "0" || e[3].Attributes["link"] != "Application Support/item" {
		t.Fatalf("entries=%+v", e)
	}
	if _, ok := e[3].Attributes["uid"]; ok {
		t.Fatal("unset default retained")
	}
}

func TestMalformedMetadataAndLimits(t *testing.T) {
	for _, s := range []string{"..\n", "/bad type=file\n", "a/../b type=file\n", "a type=file\na type=dir\n", "a inode=1 inode=2\n", "a\\000 type=file\n", "a\\04 type=file\n", "a type=file \\\n"} {
		if _, err := Read(strings.NewReader(s), 10); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	if _, err := Read(strings.NewReader("a\nb\n"), 1); err == nil {
		t.Fatal("entry bound ignored")
	}
}
