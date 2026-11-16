package simh

import (
	"bytes"
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func word(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
func record(class byte, data string) []byte {
	w := uint32(class)<<28 | uint32(len(data))
	out := append(word(w), data...)
	if len(data)&1 != 0 {
		out = append(out, 0xa5)
	} // padding is undefined
	return append(out, word(w)...)
}

func TestRecordsMetadataAndLogicalEnd(t *testing.T) {
	img := record(0, "abc")
	img = append(img, word(0)...)
	img = append(img, record(8, "bad")...)
	img = append(img, record(8, "")...)
	img = append(img, record(1, "private")...)
	img = append(img, record(14, "description")...)
	img = append(img, word(0x70000001)...)
	img = append(img, 0xff, 0xff) // half gap followed by a full gap
	img = append(img, word(0xfffffffe)...)
	img = append(img, record(0, "de")...)
	img = append(img, word(0xffffffff)...)
	img = append(img, 1, 2, 3) // EOM hides physically remaining bytes
	file := &starfile.Bytes{Data: img}
	rs, err := Open(file, 11)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 11 || !rs[1].TapeMark || !rs[2].Bad || !rs[3].Bad || rs[3].Data.Size() != 0 || rs[4].Class != 1 || rs[5].Class != 14 || rs[7].Marker != 0xfffeffff || rs[8].Marker != 0xfffffffe || rs[10].Marker != 0xffffffff {
		t.Fatalf("%+v", rs)
	}
	for _, tc := range []struct {
		i    int
		want string
	}{{0, "abc"}, {2, "bad"}, {4, "private"}, {5, "description"}, {9, "de"}} {
		got, err := starfile.ReadAll(rs[tc.i].Data)
		if err != nil || string(got) != tc.want {
			t.Fatalf("record %d: %q %v", tc.i, got, err)
		}
	}
	// Views retain the original input instead of copying record bodies.
	img[4] = 'z'
	got, _ := starfile.ReadAll(rs[0].Data)
	if string(got) != "zbc" {
		t.Fatalf("not a view: %q", got)
	}
	if _, err := Open(file, 10); err == nil {
		t.Fatal("ignored metadata limit")
	}
}

func TestMalformedFraming(t *testing.T) {
	good := record(0, "abc")
	badTrailer := bytes.Clone(good)
	badTrailer[len(badTrailer)-4] ^= 1
	inputs := [][]byte{good[:1], good[:4], good[:7], good[:len(good)-1], badTrailer, word(0xfffe0000), word(0xffff0000), word(0x0fffffff)}
	for _, input := range inputs {
		if _, err := Open(&starfile.Bytes{Data: input}, 10); err == nil {
			t.Fatalf("accepted %x", input)
		}
	}
	if _, err := Open(&starfile.Bytes{}, 0); err == nil {
		t.Fatal("accepted nonpositive limit")
	}
	rs, err := Open(&starfile.Bytes{Data: record(0, "even")}, 1)
	if err != nil || len(rs) != 1 {
		t.Fatalf("physical EOF: %+v %v", rs, err)
	}
}

func TestIndexRetainsPositionableDamage(t *testing.T) {
	damaged := record(0, "broken")
	damaged[len(damaged)-4] = 0
	input := append(record(0, "good"), damaged...)
	input = append(input, record(0, "next")...)
	file := &starfile.Bytes{Data: input}
	if _, err := Open(file, 10); err == nil {
		t.Fatal("strict reader accepted damaged media")
	}
	rs, err := Index(file, 10)
	if err != nil || len(rs) != 3 {
		t.Fatalf("index: %v %v", rs, err)
	}
	if rs[0].FramingError != "" || rs[1].FramingError == "" || rs[2].FramingError != "" {
		t.Fatalf("damage not isolated: %+v", rs)
	}
	got, err := starfile.ReadAll(rs[2].Data)
	if err != nil || string(got) != "next" {
		t.Fatalf("next record: %q %v", got, err)
	}
	if _, err := Index(&starfile.Bytes{Data: input[:len(input)-1]}, 10); err == nil {
		t.Fatal("index accepted unpositionable truncated frame")
	}
}
