package deb

import (
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestReadControlPreservesContinuationsAndParagraphs(t *testing.T) {
	input := "Package: jq\r\nStatus: install ok installed\r\nDescription: JSON tool\r\n long text\r\n .\r\n\r\nPackage: libjq1\r\n"
	source := &starfile.Bytes{Data: []byte(input)}
	paragraphs, err := ReadControl(source, source.Size())
	if err != nil || len(paragraphs) != 2 {
		t.Fatalf("paragraphs %+v, error %v", paragraphs, err)
	}
	first := paragraphs[0]
	if first.Fields["status"] != "install ok installed" || first.Fields["description"] != "JSON tool\n long text\n ." || !strings.HasPrefix(string(first.Raw), "Package: jq\n") {
		t.Fatalf("first paragraph %+v", first)
	}
	if _, err := ReadControl(source, source.Size()-1); err == nil {
		t.Fatal("accepted a file larger than the byte limit")
	}
	duplicate := &starfile.Bytes{Data: []byte("Package: jq\npackage: libjq1\n")}
	if _, err := ReadControl(duplicate, duplicate.Size()); err == nil {
		t.Fatal("accepted a duplicate field")
	}
}
