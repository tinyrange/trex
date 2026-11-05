package star

import (
	"github.com/tinyrange/trex/binary/xmlview"
	"testing"
)

func TestXMLNativeViewOwnershipAndEarlyStop(t *testing.T) {
	data := []byte(`<root xmlns="urn:fixture" flag="owned"><a>A<b>B</b></a><c>C</c></root>`)
	doc, err := parseBinaryXML(data, 256, 1024, false)
	if err != nil {
		t.Fatal(err)
	}
	view := doc.root.XMLView()
	for i := range data {
		data[i] = 'x'
	}
	if view.Name() != "root" || view.Namespace() != "urn:fixture" || view.Text() != "ABC" {
		t.Fatal("lost XML ownership")
	}
	for attribute := range view.Attributes() {
		attribute.Value = "changed"
		break
	}
	if v, ok := view.Attribute("flag", ""); !ok || v != "owned" {
		t.Fatal("attribute exposes mutable storage")
	}
	count := 0
	var retained xmlview.Node
	for child := range view.Children() {
		count++
		retained = child
		break
	}
	if count != 1 || retained.Name() != "a" || retained.Text() != "AB" {
		t.Fatal("child iterator did not stop")
	}
	count = 0
	for range view.Children() {
		count++
	}
	if count != 2 {
		t.Fatal("iteration consumed the immutable view")
	}
}
