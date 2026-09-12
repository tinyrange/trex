package hunk

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func loadFixture() []byte {
	return words(HeaderTag, 0, 2, 0, 1, 1, 100,
		CodeTag, 1, 0x41424344, Reloc32Tag, 1, 1, 0, 0, EndTag,
		BSSTag, 100, EndTag)
}
func TestLoad(t *testing.T) {
	b := loadFixture()
	a, err := OpenLoad(&starfile.Bytes{Data: b}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if a.Header.TableSize != 2 || a.Header.Sizes[1] != 400 || len(a.Units) != 1 || len(a.Units[0].Records) != 5 {
		t.Fatal(a)
	}
	if a.Header.Raw.Size() != 28 || a.Units[0].Raw.Size() != int64(len(b)) {
		t.Fatal("raw framing")
	}
	if _, err := OpenObjects(&starfile.Bytes{Data: b}, 100); err == nil {
		t.Fatal("load accepted as object")
	}
	if _, err := OpenLoad(&starfile.Bytes{Data: objectFixture()}, 100); err == nil {
		t.Fatal("object accepted as load")
	}
	for n := 0; n < len(b); n++ {
		if _, err := OpenLoad(&starfile.Bytes{Data: b[:n]}, 100); err == nil {
			t.Fatal("truncated load", n)
		}
	}
	for _, bad := range [][]byte{
		words(HeaderTag, 0, 0, 0, 0),
		words(HeaderTag, 0, 2, 1, 0),
		words(HeaderTag, 0, 1, 0, 1),
		words(HeaderTag, 0, 1, 0, 0, 1, CodeTag, 2, 0, 0, EndTag),
		words(HeaderTag, 0, 2, 0, 1, 1, 1, CodeTag, 1, 0, EndTag),
		words(HeaderTag, 0, 1, 0, 0, 1, UnitTag, 0, CodeTag, 1, 0, EndTag),
	} {
		if _, err := OpenLoad(&starfile.Bytes{Data: bad}, 100); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
	if _, err := OpenLoad(&starfile.Bytes{Data: b}, 2); err == nil {
		t.Fatal("header metadata limit")
	}
}
func FuzzLoad(f *testing.F) {
	f.Add(loadFixture())
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := OpenLoad(&starfile.Bytes{Data: b}, 1000)
		if err != nil {
			return
		}
		for _, u := range a.Units {
			if _, err := starfile.ReadAll(u.Raw); err != nil {
				t.Fatal(err)
			}
		}
	})
}
