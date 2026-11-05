package uup

import (
	"bytes"
	"strings"
	"testing"
)

func TestCBSDeploymentSourceMetadataNativeOrder(t *testing.T) {
	target := `<assemblyIdentity name="Target" version="10.0.1.1" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"/>`
	uc := func(elevation, targets string) string {
		return `<updateComponent elevate="` + elevation + `">` + targets + `</updateComponent>`
	}
	for _, tc := range []struct{ name, body, want string }{
		{"empty", `<component>` + target + `</component>`, ""},
		{"single", `<applicable>` + uc("build", target) + `</applicable>`, "8"},
		{"alternatives", `<applicable>` + uc("build", target+target) + `</applicable>`, "9"},
		{"revision", `<applicable>` + uc("revision", target) + `</applicable>`, "2"},
		{"distribution", `<applicable>` + uc("distribution", target) + `</applicable>`, "4"},
		{"version", `<applicable>` + uc("version", target) + `</applicable>`, "32"},
		{"install", `<applicable>` + uc("install", target) + `</applicable>`, "128"},
		// Native kind-specific lists put direct updateComponents before nested
		// applicability, even when the nested node was earlier in XML order.
		{"direct before nested", `<applicable><applicable>` + uc("revision", target) + `</applicable>` + uc("build", target+target) + `</applicable>`, "9"},
		{"nested", `<applicable><detectNone/><applicable>` + uc("version", target) + `</applicable></applicable>`, "32"},
		{"first not union", `<applicable>` + uc("revision", target) + uc("build", target+target) + `</applicable>`, "2"},
		{"selectable excluded", `<selectable>` + uc("build", target) + `</selectable>`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := cbsIntentManifest(t, "Package", "neutral", `<update name="Exact.Spelling">`+tc.body+`</update>`)
			data, err := CBSDeploymentSourceData(m, "exact.spelling")
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseCBSDeploymentSource(data)
			if err != nil || string(parsed.Secondary) != tc.want || parsed.Update != "Exact.Spelling" {
				t.Fatal(parsed, err)
			}
			expected, err := marshalCBSDeploymentSource(cbsDeploymentSource{Package: m.Identity, Update: "Exact.Spelling"}, []byte(tc.want))
			if err != nil || !bytes.Equal(data, expected) {
				t.Fatal(data, err)
			}
		})
	}
}

func TestCBSDeploymentSourceMetadataRejectsUnsupported(t *testing.T) {
	for _, body := range []string{
		`<applicable><updateComponent elevate="build"/></applicable>`,
		`<applicable><updateComponent><assemblyIdentity name="T"/></updateComponent></applicable>`,
		`<applicable><updateComponent elevate="future"><assemblyIdentity name="T"/></updateComponent></applicable>`,
		`<applicable><updateComponent elevate="build"><assemblyIdentity/></updateComponent></applicable>`,
		`<applicable><updateComponent elevate="build"><wrong/></updateComponent></applicable>`,
		`<applicable xmlns="foreign"><updateComponent elevate="build"><assemblyIdentity name="T"/></updateComponent></applicable>`,
	} {
		m := cbsIntentManifest(t, "Package", "neutral", `<update name="u">`+body+`</update>`)
		if data, err := CBSDeploymentSourceData(m, "u"); err == nil || data != nil {
			t.Fatal("accepted unsupported source metadata", body)
		}
	}
	m := cbsIntentManifest(t, "Package", "neutral", `<update name="u"/>`)
	if _, err := CBSDeploymentSourceData(m, "missing"); err == nil {
		t.Fatal("accepted missing update")
	}
	m.PackageUpdates = append(m.PackageUpdates, m.PackageUpdates[0])
	if _, err := CBSDeploymentSourceData(m, "u"); err == nil {
		t.Fatal("accepted duplicate update")
	}
	if _, err := CBSDeploymentSourceData(compositionFixture(t, "Component", ""), "u"); err == nil {
		t.Fatal("accepted component MUM")
	}
	node := ManifestCondition{Name: "applicable"}
	for range 130 {
		node = ManifestCondition{Name: "applicable", Children: []ManifestCondition{node}}
	}
	m.PackageUpdates = m.PackageUpdates[:1]
	m.PackageUpdates[0].Conditions = []ManifestCondition{node}
	if _, err := CBSDeploymentSourceData(m, "u"); err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatal(err)
	}
}
