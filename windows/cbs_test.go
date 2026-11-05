package windows

import (
	"fmt"
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestCBSPackageOwnersBuiltin(t *testing.T) {
	identity := func(name string) string {
		return fmt.Sprintf(`<assemblyIdentity name="%s" version="10.0.26100.9457" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/>`, name)
	}
	parent := `<assembly xmlns="urn:schemas-microsoft-com:asm.v3">` + identity("Wrapper") + `<package><update name="Optional"><selectable disposition="staged"><detectNone default="false"/></selectable><package>` + identity("Child") + `</package></update></package></assembly>`
	child := `<assembly xmlns="urn:schemas-microsoft-com:asm.v3">` + identity("Child") + `<package/></assembly>`
	context := func(manifest string) *starlark.Dict {
		d := starlark.NewDict(3)
		_ = d.SetKey(starlark.String("manifest"), starlark.Bytes(manifest))
		_ = d.SetKey(starlark.String("intended_state"), starlark.MakeInt(0x70))
		return d
	}
	p := context(parent)
	targets := starlark.NewList([]starlark.Value{starlark.String("Child~31bf3856ad364e35~amd64~~10.0.26100.9457")})
	args := starlark.Tuple{starlark.NewList([]starlark.Value{p, context(child)}), targets}
	v, err := cbsPackageOwnersBuiltin(nil, nil, args, nil)
	if err != nil {
		t.Fatal(err)
	}
	list := v.(*starlark.List)
	if list.Len() != 1 {
		t.Fatal(v)
	}
	word, err := list.Index(0).(starlark.HasAttrs).Attr("value")
	if err != nil || word.String() != "131136" {
		t.Fatal("lost disabled update intent", v, err)
	}
	_ = p.SetKey(starlark.String("intended_state"), starlark.MakeInt(0x50))
	_ = p.SetKey(starlark.String("manifest"), starlark.Bytes(strings.Replace(parent, `default="false"`, `default="true"`, 1)))
	v, err = cbsPackageOwnersBuiltin(nil, nil, args, nil)
	if err != nil {
		t.Fatal(err)
	}
	word, err = v.(*starlark.List).Index(0).(starlark.HasAttrs).Attr("value")
	if err != nil || word.String() != "131152" {
		t.Fatal("lost superseded cap", v, err)
	}
	_ = p.SetKey(starlark.String("intended_state"), starlark.MakeInt(0x70))
	gate := `<customInformation><EnableSelectabilityForEditions><EnableSelectabilityForEdition name="Microsoft-Windows-IoTEnterpriseSEdition"/></EnableSelectabilityForEditions></customInformation>`
	_ = p.SetKey(starlark.String("manifest"), starlark.Bytes(strings.Replace(parent, "</selectable>", gate+"</selectable>", 1)))
	kwargs := []starlark.Tuple{{starlark.String("editions"), starlark.NewList([]starlark.Value{starlark.String("Microsoft-Windows-ProfessionalEdition")})}}
	v, err = cbsPackageOwnersBuiltin(nil, nil, args, kwargs)
	if err != nil {
		t.Fatal(err)
	}
	word, err = v.(*starlark.List).Index(0).(starlark.HasAttrs).Attr("value")
	if err != nil || word.String() != "131184" {
		t.Fatal("lost edition-disabled selector semantics", v, err)
	}
	if _, err := cbsPackageOwnersBuiltin(nil, nil, args, nil); err == nil {
		t.Fatal("accepted missing edition context")
	}
	for _, invalid := range []starlark.Value{starlark.String("Professional"), starlark.NewList([]starlark.Value{starlark.MakeInt(48)}), starlark.NewList([]starlark.Value{starlark.String("")})} {
		if _, err := cbsPackageOwnersBuiltin(nil, nil, args, []starlark.Tuple{{starlark.String("editions"), invalid}}); err == nil {
			t.Fatal("accepted malformed editions", invalid)
		}
	}
	_ = p.SetKey(starlark.String("manifest"), starlark.Bytes(parent))
	// Truthy non-booleans are not explicit feature choices.
	choices := starlark.NewDict(1)
	_ = choices.SetKey(starlark.String("Optional"), starlark.String("false"))
	_ = p.SetKey(starlark.String("choices"), choices)
	if _, err := cbsPackageOwnersBuiltin(nil, nil, args, nil); err == nil {
		t.Fatal("accepted nonboolean feature selection")
	}
	_ = p.SetKey(starlark.String("choices"), starlark.NewDict(0))
	_ = p.SetKey(starlark.String("intended_state"), starlark.MakeUint64(1<<32|0x70))
	if _, err := cbsPackageOwnersBuiltin(nil, nil, args, nil); err == nil {
		t.Fatal("truncated state before validation")
	}
}
