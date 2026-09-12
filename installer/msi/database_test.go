package msi

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestColumnMajorRowsAndNull(t *testing.T) {
	d := &Database{referenceWidth: 2, strings: []string{"", "alpha", "beta"}, streams: map[string]starfile.File{"\u4840Example": &starfile.Bytes{Data: []byte{1, 0, 2, 0, 1, 128, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0x2a, 0, 0, 0x80}}}}
	rows, err := d.decodeTable("Example", []Column{{"Name", 0x2d40}, {"Small", 0x0102}, {"Large", 0x0104}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0]["Name"] != starlark.String("alpha") || rows[1]["Small"] != starlark.None {
		t.Fatal(rows)
	}
	if rows[0]["Small"].String() != "1" || rows[0]["Large"].String() != "-1" || rows[1]["Large"].String() != "42" {
		t.Fatal(rows)
	}
	d.strings = d.strings[:2]
	if _, err := d.decodeTable("Example", []Column{{"Name", 0x2d40}, {"Small", 0x0102}, {"Large", 0x0104}}); err == nil {
		t.Fatal("invalid string reference accepted")
	}
}
func TestPackedStreamName(t *testing.T) {
	if got := decodeName(string([]rune{0x4840, 0x3800 + 63 + (28 << 6), 0x4800 + 55})); got != "\u4840_St" {
		t.Fatal(got)
	}
}
