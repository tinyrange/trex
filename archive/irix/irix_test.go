package irix

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"testing"
)

func fixture() (*starfile.Bytes, *starfile.Bytes) {
	image := append([]byte("im001V630P00"), 0, 0, 1, 'a', 0x1f, 0x9d, 0x90, 0x41, 0)
	index := "f 0755 root sys a source/a main.sw.bin sum(65) size(1) off(13) cmpsize(5)\n"
	return &starfile.Bytes{Data: image}, &starfile.Bytes{Data: []byte(index)}
}
func TestImage(t *testing.T) {
	file, index := fixture()
	items, err := ReadIDB(index, 10)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := OpenImage(file, items, "main.sw")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Mode != 0755 || entries[0].Owner != "root" {
		t.Fatal("lost metadata")
	}
	got, err := starfile.ReadAll(entries[0])
	if err != nil || string(got) != "A" {
		t.Fatalf("%q %v", got, err)
	}
}
func TestImageValidation(t *testing.T) {
	for name, replace := range map[string][2]string{"name": {"sys a ", "sys b "}, "offset": {"off(13)", "off(14)"}, "missing": {"size(1)", ""}, "duplicate": {"size(1)", "size(1) size(1)"}} {
		t.Run(name, func(t *testing.T) {
			f, index := fixture()
			index.Data = []byte(strings.ReplaceAll(string(index.Data), replace[0], replace[1]))
			items, err := ReadIDB(index, 10)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OpenImage(f, items, "main.sw"); err == nil {
				t.Fatal("accepted bad index")
			}
		})
	}
	for _, replace := range [][2]string{{"sum(65)", "sum(64)"}, {"size(1)", "size(2)"}} {
		f, index := fixture()
		index.Data = []byte(strings.ReplaceAll(string(index.Data), replace[0], replace[1]))
		items, _ := ReadIDB(index, 10)
		entries, err := OpenImage(f, items, "main.sw")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := starfile.ReadAll(entries[0]); err == nil {
			t.Fatal("accepted wrong decoded metadata")
		}
	}
	f, index := fixture()
	f.Data = append(f.Data, 0)
	items, _ := ReadIDB(index, 10)
	if _, err := OpenImage(f, items, "main.sw"); err == nil {
		t.Fatal("accepted unindexed trailer")
	}
}
func TestIndexLexer(t *testing.T) {
	got, err := words(`f 0644 root sys "a b" source/a image.sw.base config("merge with spaces")`)
	if err != nil || len(got) != 8 || got[4] != "a b" || got[7] != "config(merge with spaces)" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{`f 0644 root sys "a`, "f 0644 root sys a b x(foo", `f 0644 root sys a b x)`, "f 0644 root sys a b \\"} {
		if _, err := words(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestUncompressedSentinel(t *testing.T) {
	image := &starfile.Bytes{Data: append([]byte("im001V630P00"), 0, 0, 1, 'a', 'A')}
	index := &starfile.Bytes{Data: []byte("f 0644 root sys a source/a main.man.base sum(65) size(1) off(13) cmpsize(0)\n")}
	items, err := ReadIDB(index, 10)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := OpenImage(image, items, "main.man")
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(entries[0])
	if err != nil || string(got) != "A" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestSequentialImageWithoutOffsets(t *testing.T) {
	f, index := fixture()
	index.Data = []byte(strings.ReplaceAll(string(index.Data), "off(13)", "f(1149443866)"))
	items, err := ReadIDB(index, 10)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := OpenImage(f, items, "main.sw")
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(entries[0])
	if err != nil || string(got) != "A" || entries[0].Offset != 13 {
		t.Fatalf("%q %v", got, err)
	}
}

func TestDuplicatePathsRetainOffsetIdentity(t *testing.T) {
	image := &starfile.Bytes{Data: append([]byte("im001V630P00"), 0, 0, 1, 'a', 'A', 0, 1, 'a', 'B')}
	index := &starfile.Bytes{Data: []byte("f 0755 root sys a source/b main.sw.base sum(66) size(1) off(17) cmpsize(0)\nf 0644 root sys a source/a main.sw.base sum(65) size(1) off(13) cmpsize(0)\n")}
	items, err := ReadIDB(index, 10)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := OpenImage(image, items, "main.sw")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Source != "source/a" || entries[1].Source != "source/b" {
		t.Fatal("lost duplicate-path identity")
	}
	for i, want := range []string{"A", "B"} {
		got, err := starfile.ReadAll(entries[i])
		if err != nil || string(got) != want {
			t.Fatalf("%q %v", got, err)
		}
	}
}

func TestHeaderlessTapeAndCheckedPadding(t *testing.T) {
	index := &starfile.Bytes{Data: make([]byte, 512)}
	copy(index.Data, "f 0644 bin bin a source/a main.man.base sum(65) size(1) f(123)\n")
	items, err := ReadIDB(index, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"", "im001V405P00\x00"} {
		image := &starfile.Bytes{Data: make([]byte, 512)}
		copy(image.Data, append([]byte(header), 0, 1, 'a', 'A'))
		entries, err := OpenImage(image, items, "main.man")
		if err != nil || len(entries) != 1 {
			t.Fatalf("%q: %v", header, err)
		}
		got, err := starfile.ReadAll(entries[0])
		if err != nil || string(got) != "A" || entries[0].Offset != int64(len(header)) {
			t.Fatalf("%q %v", got, err)
		}
		image.Data[511] = 'X'
		if _, err := OpenImage(image, items, "main.man"); err == nil {
			t.Fatal("accepted nonzero data hidden in tape padding")
		}
		image.Data = image.Data[:511]
		if _, err := OpenImage(image, items, "main.man"); err == nil {
			t.Fatal("accepted unaligned trailer")
		}
	}
	index.Data[511] = 'X'
	if _, err := ReadIDB(index, 10); err == nil {
		t.Fatal("accepted data hidden after index padding")
	}
}

func TestSequentialDuplicatePaths(t *testing.T) {
	image := &starfile.Bytes{Data: []byte{0, 1, 'a', 'A', 0, 1, 'a', 'B'}}
	index := &starfile.Bytes{Data: []byte("f 0644 bin bin a source/a main.sw.base sum(65) size(1) mach(IP4)\nf 0644 bin bin a source/b main.sw.base sum(66) size(1) mach(IP5)\n")}
	items, err := ReadIDB(index, 10)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := OpenImage(image, items, "main.sw")
	if err != nil || len(entries) != 2 {
		t.Fatalf("%v", err)
	}
	for i, want := range []string{"A", "B"} {
		got, err := starfile.ReadAll(entries[i])
		if err != nil || string(got) != want || entries[i].Source != items[i].Source {
			t.Fatalf("occurrence %d: %q %v", i, got, err)
		}
	}
}

func TestEmptyPayloadValidation(t *testing.T) {
	for _, tc := range []struct {
		name, metadata string
		payload        []byte
		valid          bool
	}{
		{"empty", "size(0) sum(0)", nil, true},
		{"wrong checksum", "size(0) sum(1)", nil, false},
		{"compressed empty", "size(0) sum(0) cmpsize(3)", []byte{0x1f, 0x9d, 0x90}, true},
		{"hidden decoded byte", "size(0) sum(0) cmpsize(5)", []byte{0x1f, 0x9d, 0x90, 0x41, 0}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			index := &starfile.Bytes{Data: []byte("f 0644 root sys empty source main.sw.base " + tc.metadata + "\n")}
			items, err := ReadIDB(index, 10)
			if err != nil {
				t.Fatal(err)
			}
			image := &starfile.Bytes{Data: append([]byte{0, 5, 'e', 'm', 'p', 't', 'y'}, tc.payload...)}
			entries, err := OpenImage(image, items, "main.sw")
			if err == nil {
				_, err = starfile.ReadAll(entries[0])
			}
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}
