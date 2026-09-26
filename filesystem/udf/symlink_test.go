package udf

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	starfile "github.com/tinyrange/trex/storage/star"
)

func testComponent(kind byte, name []byte) []byte {
	return append([]byte{kind, byte(len(name)), 0, 0}, name...)
}
func testPath(parts ...[]byte) []byte {
	var p []byte
	for _, part := range parts {
		p = append(p, part...)
	}
	return p
}
func testName(name string) []byte { return testComponent(5, append([]byte{8}, name...)) }

func TestSymbolicLinkComponents(t *testing.T) {
	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"parent":      {testPath(testComponent(3, nil), testComponent(3, nil), testName("usr"), testName("image")), "../../usr/image"},
		"absolute":    {testPath(testComponent(2, nil), testName("usr"), testName("image")), "/usr/image"},
		"root":        {testComponent(2, nil), "/"},
		"volume root": {testPath(testComponent(1, nil), testName("x")), "/x"},
		"current":     {testPath(testComponent(4, nil), testName("x"), testComponent(3, nil)), "./x/.."},
		"latin1":      {testComponent(5, []byte{8, 'c', 'a', 'f', 0xe9}), "café"},
		"unicode":     {testComponent(5, []byte{16, 0x4e, 0x2d, 0xd8, 0x3d, 0xde, 0x00}), "中😀"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := udfSymlinkTarget(tc.data)
			if err != nil || got != tc.want {
				t.Fatal(got, err)
			}
		})
	}
}

func TestRejectMalformedLinks(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":            nil,
		"short header":     {5, 1, 0},
		"short identifier": {5, 3, 0, 0, 8, 'a'},
		"unknown type":     testComponent(6, nil),
		"volume agreement": testComponent(1, []byte{8, 'v'}),
		"unexpected root":  testPath(testName("a"), testComponent(2, nil)),
		"special payload":  testComponent(3, []byte{'a'}),
		"empty identifier": testComponent(5, []byte{8}),
		"slash":            testName("a/b"),
		"nul":              testComponent(5, []byte{8, 'a', 0}),
		"compression":      testComponent(5, []byte{7, 'a'}),
		"odd unicode":      testComponent(5, []byte{16, 1}),
		"surrogate":        testComponent(5, []byte{16, 0xd8, 0x3d}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := udfSymlinkTarget(data); err == nil {
				t.Fatal("accepted malformed link")
			}
		})
	}
}

func testUDF() []byte {
	b := make([]byte, 300*2048)
	block := func(n int, tag uint16) []byte {
		p := b[n*2048 : (n+1)*2048]
		binary.LittleEndian.PutUint16(p, tag)
		return p
	}
	longAD := func(p []byte, size, sector uint32) {
		binary.LittleEndian.PutUint32(p, size)
		binary.LittleEndian.PutUint32(p[4:], sector)
	}
	anchor := block(256, 2)
	binary.LittleEndian.PutUint32(anchor[16:], 3*2048)
	binary.LittleEndian.PutUint32(anchor[20:], 257)
	part := block(257, 5)
	binary.LittleEndian.PutUint32(part[188:], 16)
	binary.LittleEndian.PutUint32(part[192:], 240)
	logical := block(258, 6)
	binary.LittleEndian.PutUint32(logical[212:], 2048)
	longAD(logical[248:], 2048, 0)
	binary.LittleEndian.PutUint32(logical[264:], 6)
	binary.LittleEndian.PutUint32(logical[268:], 1)
	copy(logical[440:], []byte{1, 6, 0, 0, 0, 0})
	block(259, 8)
	fsd := block(16, 256)
	longAD(fsd[400:], 2048, 1)
	target := testPath(testComponent(3, nil), testName("usr"), testComponent(5, []byte{8, 'c', 'a', 'f', 0xe9}))
	entry := func(sector int, typ byte, size int, allocation uint16, payload []byte) {
		p := block(sector, 261)
		p[27] = typ
		binary.LittleEndian.PutUint16(p[34:], allocation)
		binary.LittleEndian.PutUint64(p[56:], uint64(size))
		binary.LittleEndian.PutUint32(p[172:], uint32(len(payload)))
		copy(p[176:], payload)
	}
	fid := func(name string, sector uint32) []byte {
		name = "\x08" + name
		p := make([]byte, align4(38+len(name)))
		binary.LittleEndian.PutUint16(p, 257)
		p[19] = byte(len(name))
		longAD(p[20:], 2048, sector)
		copy(p[38:], name)
		return p
	}
	directory := testPath(fid("embedded", 2), fid("external", 3), fid("regular", 5))
	entry(17, 4, len(directory), 3, directory)
	entry(18, 12, len(target), 3, target)
	ads := make([]byte, 8)
	binary.LittleEndian.PutUint32(ads, uint32(len(target)))
	binary.LittleEndian.PutUint32(ads[4:], 4)
	entry(19, 12, len(target), 0, ads)
	copy(b[20*2048:], target)
	entry(21, 5, 5, 3, []byte("hello"))
	return b
}

func TestEmbeddedAndExtentLinksThroughAutoAndEntries(t *testing.T) {
	file := &starfile.Bytes{Data: testUDF()}
	view, err := adapter.Parse(UDFBuiltin, file, auto.Options{MaxEntries: 100})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := view.Entries()
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, entry := range entries {
		if entry.Name == "embedded" || entry.Name == "external" {
			found++
			if entry.Kind != "symlink" || entry.Reader != nil || entry.View != nil || entry.Attributes["link"] != "../usr/café" {
				t.Fatal(entry)
			}
		}
	}
	if found != 2 {
		t.Fatal(found)
	}
	flattened, err := Entries(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range flattened {
		if strings.Contains(entry.Name, "ternal") || entry.Name == "/embedded" {
			if entry.Kind != "symlink" || entry.File != nil {
				t.Fatal(entry)
			}
		}
	}
	img, err := newUDFImage(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"embedded", "external"} {
		entry, err := img.lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (&udfFile{image: img, entry: entry}).ReadAt(make([]byte, 1), 0); err == nil {
			t.Fatal("link payload exposed")
		}
	}
	regular, err := img.lookup("regular")
	if err != nil {
		t.Fatal(err)
	}
	data, err := starfile.ReadAll(&udfFile{image: img, entry: regular})
	if err != nil || string(data) != "hello" {
		t.Fatal(string(data), err)
	}
}

func TestRejectTruncatedEmbeddedLink(t *testing.T) {
	data := testUDF()
	binary.LittleEndian.PutUint64(data[18*2048+56:], 100)
	img, err := newUDFImage(&starfile.Bytes{Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = img.lookup("embedded"); err == nil {
		t.Fatal("accepted short embedded target")
	}
	binary.LittleEndian.PutUint64(data[18*2048+56:], 1<<63)
	if _, err = img.lookup("embedded"); err == nil {
		t.Fatal("accepted overflowing information length")
	}
}

func TestExtendedFileEntryLinkAndShortADPartition(t *testing.T) {
	data := testUDF()
	p := data[18*2048 : 19*2048]
	n := binary.LittleEndian.Uint32(p[172:])
	payload := append([]byte(nil), p[176:176+n]...)
	clear(p[168:])
	binary.LittleEndian.PutUint16(p, 266)
	binary.LittleEndian.PutUint32(p[212:], n)
	copy(p[216:], payload)
	img, err := newUDFImage(&starfile.Bytes{Data: data})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := img.lookup("embedded")
	if err != nil || entry.link != "../usr/café" {
		t.Fatal(entry.link, err)
	}
	// Short descriptors inherit the ICB's partition reference, even when that
	// reference maps to a different physical partition number.
	img.partitionMaps = map[uint16]uint16{1: 7}
	img.partitions = map[uint16]udfPartition{7: {start: 16, length: 240}}
	entry, err = img.readFileEntry(udfExtent{partition: 1, block: 3, length: 2048}, "external")
	if err != nil || entry.link != "../usr/café" {
		t.Fatal(entry.link, err)
	}
}
