package appx

import (
	"bytes"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestEmbeddedStubReferences(t *testing.T) {
	child := makeZIP(t, fixtureEntry{"AppxManifest.xml", []byte(manifest)})
	member := func(name, stub string) string {
		return fmt.Sprintf(`<b5:Package FileName="%s" Type="application" Architecture="x64" Version="1.2.3.4" Size="%d" IsStub="%s"/>`, name, len(child), stub)
	}
	wrap := func(m string) []byte {
		return makeZIP(t,
			fixtureEntry{"AppxMetadata/AppxBundleManifest.xml", []byte(`<Bundle xmlns:b5="http://schemas.microsoft.com/appx/2019/bundle"><Identity Name="Example.App" Publisher="CN=Example" Version="1.2.3.4"/><Packages>` + m + `</Packages></Bundle>`)},
			fixtureEntry{"AppxMetadata/Stub/app.msix", child}, fixtureEntry{"full.msix", child})
	}
	data := wrap(member(`AppxMetadata\Stub\app.msix`, "true") + member("full.msix", "false"))
	a, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Packages) != 2 || !a.Packages[0].IsStub || a.Packages[1].IsStub || a.Packages[0].Name != "AppxMetadata/Stub/app.msix" {
		t.Fatalf("bad members: %+v", a.Packages)
	}
	if _, err := Open(a.Packages[0].File); err != nil {
		t.Fatal(err)
	}
	value, err := Builtin(nil, nil, starlark.Tuple{&starfile.Bytes{Data: data}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	members, err := value.(starlark.HasAttrs).Attr("packages")
	if err != nil {
		t.Fatal(err)
	}
	flag, err := members.(*starlark.List).Index(0).(starlark.HasAttrs).Attr("is_stub")
	if err != nil || flag != starlark.True {
		t.Fatalf("stub flag: %v, %v", flag, err)
	}
	for _, m := range []string{
		member(`AppxMetadata\Stub\app.msix`, "true") + member("AppxMetadata/Stub/app.msix", "false"),
		member(`AppxMetadata\..\full.msix`, "true"),
		member(`\full.msix`, "true"), member(`C:\full.msix`, "true"),
		member(`missing.msix`, "true"), member(`full.msix`, "maybe"),
	} {
		if _, err := Open(bytes.NewReader(wrap(m))); err == nil {
			t.Fatalf("accepted unsafe/invalid members: %s", m)
		}
	}
}
