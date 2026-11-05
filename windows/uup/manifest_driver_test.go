package uup

import (
	"reflect"
	"strings"
	"testing"
)

func TestAssemblyDriverDeclarationScoping(t *testing.T) {
	// Driver metadata belongs to the containing reference, not its identity,
	// an INF-looking sibling file, or the preceding/following update.
	m, err := ParseAssemblyManifest(strings.NewReader(`<assembly xmlns="urn:schemas-microsoft-com:asm.v3" xmlns:x="urn:opaque">
      <assemblyIdentity name="Root"/><package>
        <update name="u1"><driver inf="DifferentFromIdentity.inf" ranking="normal" bootCritical="true" x:inf="opaque.inf">
          <assemblyIdentity name="dual_not_the_inf.inf" version="10.0.1.2"/>
          <wrapper><driver inf="nested.inf" ranking="low"><assemblyIdentity name="Nested"/></driver></wrapper>
        </driver></update>
        <update name="u2"><driver inf="second.inf" ranking="high"><assemblyIdentity name="Second"/></driver>
          <component><assemblyIdentity name="NotADriver"/></component></update>
        <update name="u3"><driver><assemblyIdentity name="NoDefaults"/></driver></update>
      </package><file name="misleading.inf"/></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.References) != 5 {
		t.Fatal(m.References)
	}
	want := []struct {
		name, update string
		attrs        []ManifestAttribute
	}{
		{"dual_not_the_inf.inf", "u1", []ManifestAttribute{{Name: "inf", Value: "DifferentFromIdentity.inf"}, {Name: "ranking", Value: "normal"}, {Name: "bootCritical", Value: "true"}, {Namespace: "urn:opaque", Name: "inf", Value: "opaque.inf"}}},
		{"Nested", "u1", []ManifestAttribute{{Name: "inf", Value: "nested.inf"}, {Name: "ranking", Value: "low"}}},
		{"Second", "u2", []ManifestAttribute{{Name: "inf", Value: "second.inf"}, {Name: "ranking", Value: "high"}}},
		{"NotADriver", "u2", nil},
		{"NoDefaults", "u3", nil},
	}
	for i, w := range want {
		r := m.References[i]
		if r.Identity.Name != w.name || r.UpdateName != w.update || !reflect.DeepEqual(r.Attributes, w.attrs) {
			t.Fatalf("reference %d: %+v, want %+v", i, r, w)
		}
	}
}
