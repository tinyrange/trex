package star

import (
	"strings"
	"testing"
)

func BenchmarkBinaryXMLContent(b *testing.B) {
	for _, mixed := range []bool{false, true} {
		name, item := "elements", `<update name="feature"><package><assemblyIdentity name="component" version="10.0.26100.1"/></package></update>`
		if mixed {
			name, item = "mixed", `before<item>text &amp; value</item><!--comment--><?action detail?>after`
		}
		b.Run(name, func(b *testing.B) {
			data := []byte(`<root xmlns="urn:test">` + strings.Repeat(item, 4096) + `</root>`)
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				doc, err := parseBinaryXML(data, 256, 1<<20, true)
				if err != nil || doc.root == nil {
					b.Fatalf("parse: %v", err)
				}
			}
		})
	}
}
