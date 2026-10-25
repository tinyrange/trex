package appx

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const manifest = `<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Example.App" Publisher="CN=Example" Version="1.2.3.4" ProcessorArchitecture="x64"/></Package>`

type fixtureEntry struct {
	name string
	data []byte
}

func makeZIP(t *testing.T, entries ...fixtureEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, entry := range entries {
		f, err := w.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
func TestPackageAndNestedBundle(t *testing.T) {
	payload := bytes.Repeat([]byte("payload"), 20000)
	child := makeZIP(t, fixtureEntry{"AppxManifest.xml", []byte(manifest)}, fixtureEntry{"Assets/data.bin", payload})
	bundleXML := fmt.Sprintf(`<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Identity Name="Example.App" Publisher="CN=Example" Version="1.2.3.4"/><Packages><Package Type="application" Architecture="x64" Version="1.2.3.4" FileName="app.msix" Size="%d"/></Packages></Bundle>`, len(child))
	data := makeZIP(t, fixtureEntry{"AppxMetadata/AppxBundleManifest.xml", []byte(bundleXML)}, fixtureEntry{"app.msix", child})
	a, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != "bundle" || len(a.Packages) != 1 {
		t.Fatalf("bad bundle: %+v", a)
	}
	c, err := Open(a.Packages[0].File)
	if err != nil {
		t.Fatal(err)
	}
	if c.Identity.Architecture != "x64" || c.Identity.Name != "Example.App" {
		t.Fatalf("bad identity: %+v", c.Identity)
	}
	got, err := io.ReadAll(io.NewSectionReader(c.Entries[1], 0, c.Entries[1].Size()))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %v", err)
	}
	value, err := Builtin(nil, nil, starlark.Tuple{&starfile.Bytes{Data: data}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	members, err := value.(starlark.HasAttrs).Attr("packages")
	if err != nil || members.(*starlark.List).Len() != 1 {
		t.Fatalf("Starlark members: %v", err)
	}
}
func TestRejectMalformed(t *testing.T) {
	base := fixtureEntry{"AppxManifest.xml", []byte(manifest)}
	for _, name := range []string{"../evil", "/evil", "C:evil", `a\evil`, "a/../evil", "a./evil", "a /evil", "AppxManifest.XML", "a\x00b"} {
		t.Run(name, func(t *testing.T) {
			data := makeZIP(t, base, fixtureEntry{name, []byte("x")})
			if _, err := Open(bytes.NewReader(data)); err == nil {
				t.Fatal("accepted unsafe or duplicate entry")
			}
		})
	}
	for _, entries := range [][]fixtureEntry{
		{{"hello", nil}},
		{{"AppxManifest.xml", []byte(`<Package/>`)}},
		{base, {"dir", nil}, {"dir/file", nil}},
		{{"AppxManifest.xml", bytes.Repeat([]byte("x"), maxManifest+1)}},
		{{"AppxMetadata/AppxBundleManifest.xml", []byte(`<Bundle><Identity Name="x" Publisher="x" Version="1"/><Packages><Package Type="application" FileName="missing.appx" Size="5"/></Packages></Bundle>`)}},
	} {
		if _, err := Open(bytes.NewReader(makeZIP(t, entries...))); err == nil {
			t.Fatal("accepted malformed archive")
		}
	}
	if _, err := Open(bytes.NewReader([]byte("EXPHencrypted"))); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("encrypted: %v", err)
	}
}
func TestPayloadCRC(t *testing.T) {
	data := makeZIP(t, fixtureEntry{"AppxManifest.xml", []byte(manifest)}, fixtureEntry{"data", []byte("PAYLOAD")})
	data[bytes.Index(data, []byte("PAYLOAD"))] ^= 1
	a, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Entries[1].Verify(); err == nil {
		t.Fatal("corrupt payload accepted")
	}
}
