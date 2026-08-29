package ar

import (
	"bytes"
	"fmt"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestARArchiveEntriesAndMetadata(t *testing.T) {
	var data bytes.Buffer
	data.WriteString("!<arch>\n")
	writeARFixtureMember(t, &data, "debian-binary", []byte("2.0\n"), 0644)
	writeARFixtureMember(t, &data, "control.tar.xz", []byte("control"), 0600)

	archive, err := Open(&starfile.Bytes{Name: "fixture.deb", Data: data.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	value, ok, err := archive.Get(starlark.String("debian-binary"))
	if err != nil || !ok {
		t.Fatalf("Get: value=%v ok=%v err=%v", value, ok, err)
	}
	entry := value.(*arEntryFile)
	if got, err := entry.Attr("mode"); err != nil || got.String() != "420" {
		t.Fatalf("mode = %v, err=%v", got, err)
	}
	if got, err := starfile.ReadAll(entry); err != nil || string(got) != "2.0\n" {
		t.Fatalf("member data = %q, err=%v", got, err)
	}
}

func writeARFixtureMember(t *testing.T, out *bytes.Buffer, name string, data []byte, mode uint64) {
	t.Helper()
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name, 123, 4, 5, mode, len(data))
	if len(header) != 60 {
		t.Fatalf("fixture header length = %d", len(header))
	}
	out.WriteString(header)
	out.Write(data)
	if len(data)&1 != 0 {
		out.WriteByte('\n')
	}
}
