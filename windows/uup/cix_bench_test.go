package uup

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"testing"
)

func BenchmarkContainerIndex(b *testing.B) {
	var xml strings.Builder
	xml.WriteString(`<Container name="update.psf" type="PSF" length="5000" version="1"><Files>`)
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&xml, `<File id="%d" name="component_%d/file.dll" length="1"><Hash alg="SHA256" value="%s"/><Delta><Source type="RAW" offset="%d" length="1"><Hash alg="SHA256" value="%s"/></Source></Delta></File>`, i, i, cixHashA, i, cixHashA)
	}
	xml.WriteString(`</Files></Container>`)
	data := xml.String()
	b.Run("stream", func(b *testing.B) {
		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		for b.Loop() {
			if _, err := ParseContainerIndex(strings.NewReader(data)); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("buffered", func(b *testing.B) {
		file := &starfile.Bytes{Data: []byte(data)}
		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if _, err := parseContainerIndexFile(file); err != nil {
				b.Fatal(err)
			}
		}
	})
}
