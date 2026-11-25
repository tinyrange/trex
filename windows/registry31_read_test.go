package windows

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

// Independent layout: padded header/table, spare records, multi-bucket area,
// Windows-1252 text and allocated arena slack. Not emitted by our constructor.
func registry31ReadFixture() []byte {
	data := make([]byte, 320)
	copy(data, "SHCC3.10")
	for off, v := range map[int]uint32{8: 32, 12: 48, 16: 16, 20: 192, 24: 128} {
		binary.LittleEndian.PutUint32(data[off:], v)
	}
	rec := func(idx int, a, b, c, d uint16) {
		off := 48 + idx*8
		for i, v := range []uint16{a, b, c, d} {
			binary.LittleEndian.PutUint16(data[off+i*2:], v)
		}
	}
	rec(0, 0, 4, 0, 0)
	rec(4, 0, 6, 5, 0)
	rec(6, 0, 0, 7, 8)
	copy(data[194:], ".classes")
	copy(data[210:], "Example")
	copy(data[226:], "caf\xe9")
	rec(5, 0, 1, 8, 2)
	rec(7, 0, 1, 7, 18)
	rec(8, 0, 1, 4, 34)
	// Garbage in an unreachable free record must not be mistaken for a key.
	rec(15, 65535, 65535, 65535, 65535)
	return data
}

func TestRegistry31ReadVendorStyleLayout(t *testing.T) {
	entries, err := readRegistry31(registry31ReadFixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[".classes"] != nil || entries[`.classes\Example`] == nil || *entries[`.classes\Example`] != "café" {
		t.Fatalf("entries=%v", entries)
	}
	v, err := registry31EntriesBuiltin(nil, nil, starlark.Tuple{&starfile.Bytes{Data: registry31ReadFixture()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	value, found, err := v.(*starlark.Dict).Get(starlark.String(`.classes\Example`))
	if err != nil || !found || value != starlark.String("café") {
		t.Fatalf("binding=%v %v %v", value, found, err)
	}
}

func TestRegistry31ReadConstructorRoundTrip(t *testing.T) {
	data, err := buildRegistry31(map[string]string{`Example\shell\open\command`: `C:\APP.EXE %1`, "Empty": ""})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := readRegistry31(data)
	if err != nil {
		t.Fatal(err)
	}
	if v := entries[`.classes\Example\shell\open\command`]; v == nil || *v != `C:\APP.EXE %1` {
		t.Fatal(entries)
	}
	if v := entries[`.classes\Empty`]; v == nil || *v != "" {
		t.Fatal("empty value confused with unset")
	}
	if entries[`.classes\Example`] != nil {
		t.Fatal("unset value confused with set")
	}
}

func TestRegistry31ReadMalformed(t *testing.T) {
	original := registry31ReadFixture()
	for n := 0; n < len(original); n++ {
		if _, err := readRegistry31(original[:n]); err == nil {
			t.Fatalf("accepted truncated prefix %d", n)
		}
	}
	cases := []struct {
		name string
		off  int
		v    uint16
	}{
		{"root index", 50, 65535}, {"sibling cycle", 48 + 6*8, 6}, {"child cycle", 48 + 6*8 + 2, 4},
		{"string index", 48 + 6*8 + 4, 65535}, {"string length", 48 + 8*8 + 4, 65535},
		{"string offset", 48 + 8*8 + 6, 65535}, {"key aliases string", 48 + 6*8 + 2, 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := append([]byte(nil), original...)
			binary.LittleEndian.PutUint16(data[tc.off:], tc.v)
			if _, err := readRegistry31(data); err == nil {
				t.Fatal("accepted corrupt registry")
			}
		})
	}
	data := append([]byte(nil), original...)
	binary.LittleEndian.PutUint32(data[20:], 48)
	if _, err := readRegistry31(data); err == nil {
		t.Fatal("accepted overlapping arenas")
	}
	deep, err := buildRegistry31(map[string]string{strings.Repeat(`x\`, 260) + "end": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readRegistry31(deep); err == nil {
		t.Fatal("accepted excessive traversal depth")
	}
}
func FuzzRegistry31Read(f *testing.F) {
	f.Add(registry31ReadFixture())
	f.Add([]byte("SHCC3.10"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = readRegistry31(data) })
}
