package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestWMIMethodOverrideOriginsAndInspectionBounds(t *testing.T) {
	doc, err := parseMOF(`class Root { uint32 Start(); }; class Middle:Root { uint32 start(); uint32 NewMethod([in] string Name); }; class Leaf:Middle { uint32 START(); };`)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := buildWMIRepositoryDocuments([]*mofDocument{doc}, `root\cimv2`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		flags, depth []uint64
	}{
		{"Root", []uint64{0}, []uint64{0}},
		{"Middle", []uint64{32, 0}, []uint64{0, 1}},
		{"Leaf", []uint64{32}, []uint64{0}},
	} {
		layout, err := repo.classLayout(`root\cimv2`, tc.name)
		if err != nil {
			t.Fatal(err)
		}
		methods, err := inspectWMIMethods(layout.definition.raw)
		if err != nil || len(methods) != len(tc.flags) {
			t.Fatalf("%s: %v %v", tc.name, methods, err)
		}
		for i, m := range methods {
			attrs := m.(starlark.HasAttrs)
			for field, want := range map[string]uint64{"flags": tc.flags[i], "depth": tc.depth[i]} {
				value, _ := attrs.Attr(field)
				got, _ := value.(starlark.Int).Uint64()
				if got != want {
					t.Fatalf("%s.%s=%d want %d", tc.name, field, got, want)
				}
			}
		}
		raw := layout.definition.raw
		for n := 0; n < len(raw); n++ {
			if _, err := inspectWMIMethods(raw[:n]); err == nil {
				t.Fatalf("accepted truncated %s at %d", tc.name, n)
			}
		}
	}
}

func TestWMIMethodParameterOrdinalIDs(t *testing.T) {
	doc, err := parseMOF(`class Methods { uint32 Create([in] string First, [in] uint32 Second, [out] string Third, [in,ID(17)] string Explicit); };`)
	if err != nil {
		t.Fatal(err)
	}
	method := doc.Classes[0].Features[0]
	for _, output := range []bool{false, true} {
		raw, err := buildWMIParameterClassPart(method, output, wmiObjectContext{serverName: "EXAMPLE", namespace: `ROOT\CIMV2`})
		if err != nil {
			t.Fatal(err)
		}
		layout, err := inspectWMIParameterObject(raw[4:])
		if err != nil {
			t.Fatal(err)
		}
		properties, _ := layout.(starlark.HasAttrs).Attr("properties")
		expected := map[string]uint64{"First": 0, "Second": 1, "Explicit": 17}
		if output {
			expected = map[string]uint64{"Third": 2}
		}
		for i := 0; i < properties.(*starlark.List).Len(); i++ {
			entry := properties.(*starlark.List).Index(i).(starlark.HasAttrs)
			prop, _ := entry.Attr("property")
			nameValue, _ := prop.(starlark.HasAttrs).Attr("name")
			name, _ := starlark.AsString(nameValue)
			qualifiers, _ := prop.(starlark.HasAttrs).Attr("qualifiers")
			found := false
			for j := 0; j < qualifiers.(*starlark.List).Len(); j++ {
				q := qualifiers.(*starlark.List).Index(j).(starlark.HasAttrs)
				qname, _ := q.Attr("name")
				if qname != starlark.String("ID") {
					continue
				}
				values, _ := q.Attr("values")
				value, _ := values.(*starlark.List).Index(0).(starlark.HasAttrs).Attr("value")
				got, _ := value.(starlark.Int).Uint64()
				want, ok := expected[name]
				if !ok || got != want {
					t.Fatalf("%s ID=%d want %d", name, got, want)
				}
				found = true
			}
			if _, wantID := expected[name]; wantID && !found {
				t.Fatalf("missing ID for %s", name)
			}
		}
	}
}

func TestWMIQualifierFlavorDecoderIndependentBits(t *testing.T) {
	// Raw wire vectors, independent of the serializer's flavor implementation.
	for _, tc := range []struct {
		bit  byte
		name string
	}{{1, "ToInstance"}, {2, "ToSubclass"}, {16, "DisableOverride"}} {
		raw := []byte{0, 0, 0, 0, tc.bit, 11, 0, 0, 0, 0xff, 0xff}
		qualifiers, err := wmiDecodeQualifiers(raw, []byte{0, 'Q', 0})
		if err != nil || len(qualifiers) != 1 || len(qualifiers[0].Flavors) != 1 || qualifiers[0].Flavors[0] != tc.name {
			t.Fatalf("flavor %d: %#v %v", tc.bit, qualifiers, err)
		}
	}
}
