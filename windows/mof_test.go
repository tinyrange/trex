package windows

import (
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestParseMOFDeclarations(t *testing.T) {
	source := `
#pragma autorecover
#pragma namespace ("\\\\.\\root\\cimv2")
#include ("base.mof")
Qualifier Key : boolean = false, Scope(property, reference), Flavor(DisableOverride, ToSubclass);
Qualifier Legacy : ToInstance ToSubclass;
[Description("A service"), Dynamic: ToSubclass ToInstance, Association]
class Win32_Service : CIM_Service {
    [Key, DefineValues{"One", "Two"}] string Name;
    [Units("bytes")] uint64 Sizes[] = { 1, 0x10, 18446744073709551615 };
    Widget ref Owner;
    [Implemented] uint32 StartService([In] string Mode = "normal", [Out] uint32 Result[]);
};
instance of Win32_Service as $service {
    Name = "Trex" "Fixture";
    Sizes = { 2, 3 };
    Owner = $owner;
    Embedded = instance of Widget { Name = "nested"; };
    [PropertyContext("local|value"), Dynamic, Provider("RegPropProv")] Optional;
};
`
	document, err := parseMOF(source)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Pragmas) != 3 || len(document.Qualifiers) != 2 || len(document.Classes) != 1 || len(document.Instances) != 1 {
		t.Fatalf("counts = pragmas %d qualifiers %d classes %d instances %d", len(document.Pragmas), len(document.Qualifiers), len(document.Classes), len(document.Instances))
	}
	class := document.Classes[0]
	if class.Name != "Win32_Service" || class.Super != "CIM_Service" || class.Namespace != `\\.\root\cimv2` || len(class.Features) != 4 {
		t.Fatalf("class = %#v", class)
	}
	if len(document.Items) != 7 {
		t.Fatalf("document item count = %d", len(document.Items))
	}
	wantKinds := []string{"pragma", "pragma", "pragma", "qualifier_declaration", "qualifier_declaration", "class", "instance"}
	for index, want := range wantKinds {
		if document.Items[index].Kind != want {
			t.Fatalf("document item %d kind = %q, want %q", index, document.Items[index].Kind, want)
		}
	}
	if got := class.Features[1].Value.Items[2].Unsigned; got != ^uint64(0) {
		t.Fatalf("maximum uint64 = %d", got)
	}
	method := class.Features[3]
	if method.Kind != "method" || len(method.Parameters) != 2 || !method.Parameters[1].Type.Array {
		t.Fatalf("method = %#v", method)
	}
	if got := document.Instances[0].Properties[0].Value.Text; got != "TrexFixture" {
		t.Fatalf("concatenated string = %q", got)
	}
	if got := document.Instances[0].Properties[3].Value.Instance.Class; got != "Widget" {
		t.Fatalf("embedded instance class = %q", got)
	}
	optional := document.Instances[0].Properties[4]
	if optional.Value.Kind != mofValueNull || len(optional.Qualifiers) != 3 || optional.Qualifiers[0].Name != "PropertyContext" {
		t.Fatalf("qualified value-less property = %#v", optional)
	}
}

func TestParseMOFUTF16AndStarlarkView(t *testing.T) {
	source := []byte{0xff, 0xfe}
	for _, r := range `class Example { string Name; };` {
		source = append(source, byte(r), 0)
	}
	value, err := mofBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(source)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	classesValue, err := value.(*mofFile).Attr("classes")
	if err != nil {
		t.Fatal(err)
	}
	classes := classesValue.(*starlark.List)
	if classes.Len() != 1 {
		t.Fatalf("class count = %d", classes.Len())
	}
	name, err := classes.Index(0).(starlark.HasAttrs).Attr("name")
	if err != nil || name != starlark.String("Example") {
		t.Fatalf("name = %v, err = %v", name, err)
	}
	itemsValue, err := value.(*mofFile).Attr("items")
	if err != nil {
		t.Fatal(err)
	}
	items := itemsValue.(*starlark.List)
	if items.Len() != 1 {
		t.Fatalf("item count = %d", items.Len())
	}
	kind, err := items.Index(0).(starlark.HasAttrs).Attr("kind")
	if err != nil || kind != starlark.String("class") {
		t.Fatalf("item kind = %v, err = %v", kind, err)
	}
}

func TestParseMOFNamespaceOrder(t *testing.T) {
	document, err := parseMOF(`#pragma namespace("root\\first")
class First {};
#pragma namespace("root\\second")
instance of Second {};
`)
	if err != nil {
		t.Fatal(err)
	}
	if document.Classes[0].Namespace != `root\first` || document.Instances[0].Namespace != `root\second` {
		t.Fatalf("namespaces = class %q instance %q", document.Classes[0].Namespace, document.Instances[0].Namespace)
	}
	if document.Items[2].Namespace != `root\first` || document.Items[3].Namespace != `root\second` {
		t.Fatalf("ordered namespaces = %#v", document.Items)
	}
}

func TestParseMOFReportsLocation(t *testing.T) {
	_, err := parseMOF("class Broken { string Name };")
	if err == nil || !strings.Contains(err.Error(), `1:28`) || !strings.Contains(err.Error(), `expected ";"`) {
		t.Fatalf("error = %v", err)
	}
}
