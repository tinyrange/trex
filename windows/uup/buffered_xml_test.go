package uup

import (
	"bytes"
	"encoding/xml"
	"github.com/tinyrange/trex/internal/xmltoken"
	starfile "github.com/tinyrange/trex/storage/star"
	"reflect"
	"strings"
	"testing"
)

func TestBufferedAssemblyMatchesStreaming(t *testing.T) {
	fixtures := []string{
		`<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="example" version="1.2.3.4"/><registryKeys><registryKey keyName="HKEY_LOCAL_MACHINE\Software\Example"><registryValue name="Multi" valueType="REG_MULTI_SZ" value="&quot;a&quot;,&quot;b&quot;"/></registryKey></registryKeys><file name="a.dll"/><package><update name="u"><component><assemblyIdentity name="other" version="1.2.3.4"/></component></update></package></assembly>`,
		`<assembly><assemblyIdentity name="a"/><assemblyIdentity name="b"/></assembly>`,
		`<assembly><assemblyIdentity name="a"/><dependency><dependentAssembly><assemblyIdentity name="b"/></dependentAssembly></dependency></assembly>`,
		`<assembly><assemblyIdentity name="a"/><registryKey/></assembly>`,
		`<assembly><assemblyIdentity name="a"/><file name="x"><hash xmlns="urn:schemas-microsoft-com:asm.v2"><DigestValue xmlns="http://www.w3.org/2000/09/xmldsig#">AA==</DigestValue></hash></file></assembly>`,
		`<assembly><assemblyIdentity name="a"/></bad>`,
	}
	for _, s := range fixtures {
		a, ae := ParseAssemblyManifest(strings.NewReader(s))
		b, be := ParseAssemblyManifestBytes([]byte(s))
		if (ae == nil) != (be == nil) || ae == nil && !reflect.DeepEqual(a, b) {
			t.Fatalf("%s: %v / %v; %#v / %#v", s, ae, be, a, b)
		}
	}
	// Structural limits remain enforced by the shared consumer.
	deep := []byte(`<assembly><assemblyIdentity name="a"/>` + strings.Repeat(`<x>`, maximumManifestDepth+1) + strings.Repeat(`</x>`, maximumManifestDepth+1) + `</assembly>`)
	if _, err := ParseAssemblyManifestBytes(deep); err == nil {
		t.Fatal("depth bound bypassed")
	}
}

func TestBufferedCIXMatchesStreaming(t *testing.T) {
	for _, s := range []string{
		`<Container name="a.psf" type="PSF" length="100" version="1"><Files><File id="1" name="a&amp;b" length="20"><Hash alg="SHA256" value="` + cixHashA + `"/><Delta><Source type="RAW" offset="40" length="20"><Hash alg="SHA256" value="` + cixHashA + `"/></Source></Delta></File></Files></Container>`,
		`<Container type="PSF"><Files><File id="-1"/></Files></Container>`,
		`<Container type="PSF"></Wrong>`,
	} {
		data := []byte(s)
		a, ae := ParseContainerIndex(bytes.NewReader(data))
		b, be := parseContainerIndexFile(&starfile.Bytes{Data: data})
		if (ae == nil) != (be == nil) || ae == nil && !reflect.DeepEqual(a, b) {
			t.Fatalf("%s: %v / %v", s, ae, be)
		}
	}
}

func FuzzBufferedAssembly(f *testing.F) {
	f.Add([]byte(`<assembly><assemblyIdentity name="a"/></assembly>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		a, ae := ParseAssemblyManifest(bytes.NewReader(data))
		b, be := parseAssemblyManifest(xml.NewTokenDecoder(xmltoken.New(data, false)))
		if (ae == nil) != (be == nil) || ae == nil && !reflect.DeepEqual(a, b) {
			t.Fatalf("%q: %v / %v", data, ae, be)
		}
	})
}
