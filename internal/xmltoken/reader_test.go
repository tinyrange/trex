package xmltoken

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

var corpus = []string{
	"<a x='&amp;&lt;&gt;&quot;&apos;' y='a\r\nb\rc\t d\n'/>\r\n",
	"<a>\r\n  <b/>\r</a>",
	`<?xml version="1.0" encoding="utf-8"?><assembly xmlns="urn:test" xmlns:p="urn:p"><p:file name="foo.dll" size="123"/><empty></empty></assembly>`,
	"<a q='&#xD;&#10;&#9;&amp;&quot;&lt;&gt;&apos;' a='x\r\ny\tz\n'><!-- a --><![CDATA[x\r\ny]]>text &amp; &#x1f600;</a>",
	`<r xmlns:x="u"><x:a xmlns:x="v" x:q="x"/><a xmlns="w"/></r>`,
	`<r><a foo="a&amp;b"/><b plain="yes"/></r>`,
	`<a/><a/>`, `<a a="1"a="2"/>`, `<a a="1" a="2"/>`, `<a:b:c/>`, `<:a/><a:/>`,
	`<a>]]></a>`, `<a><!-- -- --></a>`, `<!DOCTYPE a [<!ENTITY x "x">]><a>&x;</a>`,
	`<a>&#0;</a>`, `<a q="&#xFFFF;"/>`, `<a q="a<b"/>`, `<a q="&unknown;"/>`,
	`<a><b></a>`, `<a`, `<a b=`, `<a></a`, `<a b="x`, `<a / >`, `<a ></ a>`,
	"<a>\x00</a>", "<a q='\x01'/>", "<a>\xff</a>", "<a q='\xff'/>",
	`<a 名="é">💡</a>`, `<?xml version="2.0"?><a/>`, `<?xml encoding="utf-16"?><a/>`,
	`<?xml encoding="iso-8859-1"?><a/>`, `<?test /?> <a/>`, `<!-- /--> <a/>`,
	"\xef\xbb\xbf<a/>", "<a>\r\n</a>after\r", "<a>\v</a>", `<a><b /></a>`,
}

func compare(t testing.TB, data []byte, wrapped bool) {
	t.Helper()
	standard := xml.NewDecoder(bytes.NewReader(data))
	fast := New(data, false)
	var left, right func() (xml.Token, error)
	if wrapped {
		left = standard.Token
		right = xml.NewTokenDecoder(fast).Token
	} else {
		left = standard.RawToken
		right = fast.RawToken
	}
	for i := 0; i <= len(data)*2+2; i++ {
		a, ae := left()
		b, be := right()
		if (ae == nil) != (be == nil) || (ae == io.EOF) != (be == io.EOF) {
			t.Fatalf("wrapped=%v token=%d input=%q errors %v / %v", wrapped, i, data, ae, be)
		}
		if ae != nil {
			return
		}
		// The standard decoder represents zero attributes as a non-nil empty slice.
		if x, ok := a.(xml.StartElement); ok && len(x.Attr) == 0 {
			x.Attr = nil
			a = x
		}
		if x, ok := b.(xml.StartElement); ok && len(x.Attr) == 0 {
			x.Attr = nil
			b = x
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("wrapped=%v token=%d input=%q tokens %#v / %#v", wrapped, i, data, a, b)
		}
	}
	t.Fatal("token reader did not terminate")
}
func TestDifferential(t *testing.T) {
	for i, s := range corpus {
		t.Run(fmt.Sprint(i), func(t *testing.T) { compare(t, []byte(s), false); compare(t, []byte(s), true) })
	}
}
func FuzzDifferential(f *testing.F) {
	for _, s := range corpus {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		compare(t, data, false)
		compare(t, data, true)
	})
}
func TestTokensRetainOwnership(t *testing.T) {
	data := []byte(`<a x="one"/><b x="two"/>`)
	r := New(data, false)
	data[6] = 'X'
	a, err := r.RawToken()
	if err != nil {
		t.Fatal(err)
	}
	for {
		_, err = r.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if a.(xml.StartElement).Attr[0].Value != "one" {
		t.Fatal(a)
	}
}
func BenchmarkTokens(b *testing.B) {
	data := []byte(`<?xml version="1.0" encoding="utf-8"?><assembly xmlns="urn:test">` + strings.Repeat(`<file name="example.dll" destinationPath="$(runtime.system32)" sourceName="example.dll"/><registryValue name="Enabled" valueType="REG_DWORD" value="1"/>`, 200) + `</assembly>`)
	for _, fast := range []bool{false, true} {
		b.Run(fmt.Sprint(fast), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				var read func() (xml.Token, error)
				if fast {
					read = xml.NewTokenDecoder(New(data, false)).Token
				} else {
					read = xml.NewDecoder(bytes.NewReader(data)).Token
				}
				for {
					_, err := read()
					if err == io.EOF {
						break
					}
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
