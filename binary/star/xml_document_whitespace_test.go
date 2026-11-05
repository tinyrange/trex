package star

import (
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestBinaryXMLDocumentWhitespace(t *testing.T) {
	const source = "<?xml version=\"1.0\"?>\n \t<!--before-->\n<configuration value=\"a&#xA;b\"><runtime/></configuration>\n<!--after-->\t\n"
	value, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(source)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := value.(*binaryXMLDocument)
	data, err := renderXML(doc.prefix, doc.root, doc.suffix, defaultBinaryXMLLimit)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.HasPrefix(text, "<?xml version=\"1.0\"?>\n \t<!--before-->\n<configuration") || !strings.HasSuffix(text, "</configuration>\n<!--after-->\t\n") {
		t.Fatalf("invalid document whitespace: %q", text)
	}
	if !strings.Contains(text, `value="a&#xA;b"`) {
		t.Fatalf("attribute whitespace lost: %q", text)
	}
	if _, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(data)}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := renderXML(doc.prefix, doc.root, doc.suffix, len(data)-1); err == nil {
		t.Fatal("missing size bound")
	}
}
