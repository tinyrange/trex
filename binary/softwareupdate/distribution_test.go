package softwareupdate

import (
	"strings"
	"testing"
)

const legacyDistribution = `<installer-gui-script><options hostArchitectures="i386,x86_64"/><title>SU_TITLE</title><auxinfo><dict><key>VERSION</key><string>10.15.7</string><key>BUILD</key><string>19H15</string><key>Unknown</key><array><string>preserved</string></array></dict></auxinfo><script for="installation-check/@script"><![CDATA[throw new Error("do not execute");]]></script><localization><strings language="English">"SU_TITLE" = "macOS \"Example\"";
"SU_VERS" = "10.15.7";</strings></localization></installer-gui-script>`

func TestDistributionLegacyAndModern(t *testing.T) {
	d, err := Distribution(fromString(legacyDistribution))
	if err != nil {
		t.Fatal(err)
	}
	if d["title"] != `macOS "Example"` || d["raw_title"] != "SU_TITLE" || d["version"] != "10.15.7" || d["build"] != "19H15" {
		t.Fatalf("display fields: %v", d)
	}
	scripts := d["scripts"].([]any)
	script := scripts[0].(map[string]any)
	if script["for"] != "installation-check/@script" || !strings.Contains(script["text"].(string), "do not execute") {
		t.Fatal("script not preserved")
	}
	if d["options"].(map[string]any)["hostArchitectures"] != "i386,x86_64" {
		t.Fatal("lost options")
	}
	modern := `<installer-gui-script><title>macOS Example</title><auxinfo><dict><key>macOSProductVersion</key><string>26.0</string><key>macOSProductBuildVersion</key><string>25A123</string><key>VERSION</key><string>fallback</string></dict></auxinfo></installer-gui-script>`
	d, err = Distribution(fromString(modern))
	if err != nil || d["title"] != "macOS Example" || d["version"] != "26.0" || d["build"] != "25A123" {
		t.Fatalf("modern: %v %v", d, err)
	}
}
func TestDistributionRejectsMalformedInput(t *testing.T) {
	for _, raw := range []string{
		`<plist><dict/></plist>`, legacyDistribution + `<extra/>`,
		`<installer-gui-script><auxinfo><string>not a dict</string></auxinfo></installer-gui-script>`,
		`<installer-gui-script><auxinfo><dict/><dict/></auxinfo></installer-gui-script>`,
		`<installer-gui-script><auxinfo><dict/></auxinfo><auxinfo><dict/></auxinfo></installer-gui-script>`,
		`<installer-gui-script><title>A</title><title>B</title></installer-gui-script>`,
		`<installer-gui-script><title>&external;</title></installer-gui-script>`,
		`<installer-gui-script><title><nested/></title></installer-gui-script>`,
		`<installer-gui-script>` + strings.Repeat(`<unknown>`, 129) + strings.Repeat(`</unknown>`, 129) + `</installer-gui-script>`,
		`<installer-gui-script><script><![CDATA[unclosed`,
	} {
		if _, err := Distribution(fromString(raw)); err == nil {
			t.Fatalf("accepted malformed Distribution %.120s", raw)
		}
	}
}
