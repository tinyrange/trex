package uup

import (
	"encoding/xml"
	"github.com/tinyrange/trex/internal/xmltoken"
	"reflect"
	"strings"
	"testing"
)

func TestTypedCIXFileMatchesXMLDecoder(t *testing.T) {
	hash := `<Hash alg="SHA256" value="` + cixHashA + `"/>`
	source := `<Source type="RAW" name="a&amp;b">` + hash + `</Source>`
	for _, body := range []string{
		hash + `<Delta>` + source + `<Basis file="2"/></Delta>`,
		`<Unknown><Hash alg="wrong"/><Delta><Source type="bad"/></Delta></Unknown>` + hash + `<Delta>` + source + `</Delta>`,
		`<Hash alg="SHA256"/><Hash value="` + cixHashA + `"/><Delta>` + source + `</Delta><Delta><Basis length="3">` + hash + `</Basis></Delta>`,
		`<x:Hash xmlns:x="urn:other" alg="SHA256" value="` + cixHashA + `"/><Delta>` + source + `</Delta>`,
	} {
		input := `<File id="1" name="file&amp;name" length="1" time="4" attr="32" xmlns="urn:ContainerIndex">` + body + `</File>`
		var want rawCIXFile
		if err := xml.Unmarshal([]byte(input), &want); err != nil {
			t.Fatal(err)
		}
		for _, d := range []*xml.Decoder{xml.NewDecoder(strings.NewReader(input)), xml.NewTokenDecoder(xmltoken.New([]byte(input), false))} {
			token, err := d.Token()
			if err != nil {
				t.Fatal(err)
			}
			var got rawCIXFile
			if err := decodeCIXFile(d, token.(xml.StartElement), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("typed decoding differs: got%+v want%+v", got, want)
			}
		}
	}
}

func TestTypedCIXRejectsMalformedAndExcessiveChildren(t *testing.T) {
	for _, input := range []string{
		`<File><Delta><Source></Delta></File>`,
		`<File><Unknown><Source></Unknown>`,
		`<File><Delta>` + strings.Repeat(`<Source/>`, defaultCIXMaximumSourcesPerFile+1) + `</Delta></File>`,
		`<File><Delta>` + strings.Repeat(`<Basis/>`, defaultCIXMaximumSourcesPerFile+1) + `</Delta></File>`,
		`<File><Hash value="&undefined;"/></File>`,
	} {
		for _, d := range []*xml.Decoder{xml.NewDecoder(strings.NewReader(input)), xml.NewTokenDecoder(xmltoken.New([]byte(input), false))} {
			token, err := d.Token()
			if err != nil {
				t.Fatal(err)
			}
			var got rawCIXFile
			if err := decodeCIXFile(d, token.(xml.StartElement), &got); err == nil {
				t.Fatalf("accepted invalid CIX: %s", input)
			}
		}
	}
}
