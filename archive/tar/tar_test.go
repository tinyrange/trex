package tararchive

import (
	"archive/tar"
	"bytes"
	"testing"
	"time"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestTarArchiveFilesMetadataAndHardLinks(t *testing.T) {
	var data bytes.Buffer
	writer := tar.NewWriter(&data)
	mtime := time.Unix(1_700_000_000, 0)
	if err := writer.WriteHeader(&tar.Header{Name: "./usr/share/example.txt", Mode: 0640, Uid: 12, Gid: 34, Uname: "user", Gname: "group", Size: 7, ModTime: mtime, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("example")); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: "usr/share/alias.txt", Linkname: "usr/share/example.txt", Typeflag: tar.TypeLink}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: "usr/share/symlink.txt", Linkname: "example.txt", Typeflag: tar.TypeSymlink}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	archive, err := Open(&starfile.Bytes{Name: "fixture.tar", Data: data.Bytes()}, 10)
	if err != nil {
		t.Fatal(err)
	}
	value, ok, err := archive.Get(starlark.String("/usr/share/example.txt"))
	if err != nil || !ok {
		t.Fatalf("Get: value=%v ok=%v err=%v", value, ok, err)
	}
	entry := value.(*Entry)
	if got, _ := entry.Attr("entry_type"); got != starlark.String("file") {
		t.Fatalf("entry_type = %v", got)
	}
	if got, _ := entry.Attr("mtime"); got.String() != "1700000000" {
		t.Fatalf("mtime = %v", got)
	}
	if got, err := starfile.ReadAll(entry); err != nil || string(got) != "example" {
		t.Fatalf("file data = %q, err=%v", got, err)
	}

	alias, ok := archive.lookup("usr/share/alias.txt", 0)
	if !ok {
		t.Fatal("hard link not found")
	}
	if got, err := starfile.ReadAll(alias); err != nil || string(got) != "example" {
		t.Fatalf("hard-link data = %q, err=%v", got, err)
	}
	symlink, ok := archive.lookup("usr/share/symlink.txt", 0)
	if !ok {
		t.Fatal("symbolic link not found")
	}
	if _, err := symlink.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("symbolic link unexpectedly exposed file data")
	}
}
