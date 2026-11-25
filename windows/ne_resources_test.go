package windows

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func neResourceFixture() []byte {
	data := make([]byte, 512)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 64)
	copy(data[64:], "NE")
	binary.LittleEndian.PutUint16(data[64+0x24:], 64)
	binary.LittleEndian.PutUint16(data[64+0x26:], 96)
	table := data[128:160]
	put := func(off int, v uint16) { binary.LittleEndian.PutUint16(table[off:], v) }
	put(0, 4)
	put(2, 0x8010)
	put(4, 1)
	put(10, 16)
	put(12, 5)
	put(16, 24)
	copy(table[24:], "\x04name")
	version := data[256:336]
	binary.LittleEndian.PutUint16(version, 72)
	binary.LittleEndian.PutUint16(version[2:], 52)
	copy(version[4:], "VS_VERSION_INFO\x00")
	binary.LittleEndian.PutUint32(version[20:], 0xfeef04bd)
	binary.LittleEndian.PutUint32(version[24:], 0x10000)
	binary.LittleEndian.PutUint32(version[28:], 3<<16|11)
	binary.LittleEndian.PutUint32(version[32:], 300<<16)
	binary.LittleEndian.PutUint32(version[36:], 3<<16|10)
	binary.LittleEndian.PutUint32(version[40:], 103<<16|7)
	return data
}

func TestNEResourcesVersionAndNames(t *testing.T) {
	data := neResourceFixture()
	resources, err := neImageResources(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 || resources[0].typ != "#16" || resources[0].name != "name" || len(resources[0].data) != 80 {
		t.Fatalf("resources=%+v", resources)
	}
	v, ok := parseNEFixedVersion(resources[0].data)
	if !ok || v.file != [4]uint16{3, 11, 300, 0} || v.product != [4]uint16{3, 10, 103, 7} {
		t.Fatalf("version=%+v ok=%v", v, ok)
	}
	// Numeric resource identifiers must not be interpreted as string offsets.
	binary.LittleEndian.PutUint16(data[144:], 0x8001)
	resources, err = neImageResources(data)
	if err != nil || resources[0].name != "#1" {
		t.Fatalf("numeric ID: %v %v", resources, err)
	}
	value, err := neResourcesBuiltin(nil, nil, starlark.Tuple{&starfile.Bytes{Name: "fixture.exe", Data: data}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	row := value.(*starlark.List).Index(0).(starlark.HasAttrs)
	version, err := row.Attr("version")
	if err != nil || version == starlark.None {
		t.Fatalf("Starlark version=%v err=%v", version, err)
	}
}

func TestNEResourcesRejectMalformed(t *testing.T) {
	original := neResourceFixture()
	for n := 0; n < 336; n++ {
		if _, err := neImageResources(original[:n]); err == nil {
			t.Fatalf("accepted truncated file at %d", n)
		}
	}
	cases := []struct {
		name  string
		off   int
		value uint16
	}{
		{"alignment", 128, 64}, {"count", 132, 65535}, {"name offset", 144, 1000},
		{"payload offset", 138, 65535}, {"payload length", 140, 65535},
		{"table order", 64 + 0x26, 63}, {"unterminated", 150, 0x8010},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := append([]byte(nil), original...)
			binary.LittleEndian.PutUint16(data[tc.off:], tc.value)
			if _, err := neImageResources(data); err == nil {
				t.Fatal("accepted malformed NE")
			}
		})
	}
	for n := 0; n < 72; n++ {
		if _, ok := parseNEFixedVersion(original[256 : 256+n]); ok {
			t.Fatalf("accepted truncated version at %d", n)
		}
	}
	for _, off := range []int{256, 258, 260, 276} {
		data := append([]byte(nil), original...)
		data[off] ^= 0xff
		if _, ok := parseNEFixedVersion(data[256:336]); ok {
			t.Fatalf("accepted corrupt version field at %d", off)
		}
	}
}

func FuzzNEResources(f *testing.F) {
	f.Add(neResourceFixture())
	f.Add([]byte("MZ"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = neImageResources(data); _, _ = parseNEFixedVersion(data) })
}
