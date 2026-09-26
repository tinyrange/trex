package iso9660

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func testBoth(n uint32) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b, n)
	binary.BigEndian.PutUint32(b[4:], n)
	return b
}
func testSU(tag string, payload ...byte) []byte {
	return append([]byte{tag[0], tag[1], byte(len(payload) + 4), 1}, payload...)
}
func testFields(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}
func testPX(mode uint32) []byte {
	return testSU("PX", testFields(testBoth(mode), testBoth(1), testBoth(1000), testBoth(100), testBoth(42))...)
}
func testNM(s string) []byte { return testSU("NM", append([]byte{0}, s...)...) }
func testCE(block, off, size uint32) []byte {
	return testSU("CE", testFields(testBoth(block), testBoth(off), testBoth(size))...)
}
func testRecord(name string, extent, size uint32, flags byte, su ...[]byte) []byte {
	n := 33 + len(name)
	if n%2 != 0 {
		n++
	}
	b := make([]byte, n)
	b[25] = flags
	b[32] = byte(len(name))
	copy(b[33:], name)
	copy(b[2:], testBoth(extent))
	copy(b[10:], testBoth(size))
	b = append(b, testFields(su...)...)
	b[0] = byte(len(b))
	return b
}
func testER(id string) []byte { return testSU("ER", append([]byte{byte(len(id)), 0, 0, 1}, id...)...) }
func testDisc(rr, joliet bool) []byte {
	b := make([]byte, 32*2048)
	descriptor := func(sec int, typ byte) {
		p := b[sec*2048:]
		p[0] = typ
		copy(p[1:], "CD001")
		p[6] = 1
		copy(p[156:], testRecord("\x00", 20, 2048, 2))
	}
	descriptor(16, 1)
	descriptor(17, 255)
	if joliet {
		descriptor(17, 2)
		copy(b[17*2048+88:], "%/E")
		copy(b[17*2048+156:], testRecord("\x00", 21, 2048, 2))
		descriptor(18, 255)
	}
	var rootSU []byte
	if rr {
		rootSU = testFields(testSU("SP", 0xbe, 0xef, 0), testER("RRIP_1991A"), testPX(0040755))
	}
	root := testFields(testRecord("\x00", 20, 2048, 2, rootSU), testRecord("\x01", 20, 2048, 2))
	if rr {
		timestamp := []byte{124, 9, 26, 12, 30, 45, 4}
		root = append(root, testRecord("README.;1", 22, 5, 0, testNM("ReadMe"), testPX(0100755), testSU("TF", append([]byte{2}, timestamp...)...))...)
		root = append(root, testRecord("README2.;1", 22, 5, 0, testNM("readme"), testPX(0100644))...)
		// Both a name and a link component continue into the CE area; the link
		// has a parent component and continues again across an SL record boundary.
		continuation := testFields(testNM("link"), testSU("SL", 0, 0, 3, 'g', 'e', 't', 2, 0))
		copy(b[23*2048+7:], continuation)
		root = append(root, testRecord("LINK.;1", 0, 0, 0, testPX(0120777), testSU("NM", 1, 's', 'y', 'm'), testSU("SL", 1, 4, 0, 1, 3, 't', 'a', 'r'), testCE(23, 7, uint32(len(continuation))))...)
		// A directory relocated for the ISO hierarchy must appear at its CL name,
		// and its actual RE directory entry must be hidden.
		root = append(root, testRecord("DEEP", 0, 0, 0, testNM("deep"), testPX(0040700), testSU("CL", testBoth(24)...))...)
		root = append(root, testRecord("MOVED", 24, 2048, 2, testSU("RE"))...)
		relocated := testFields(testRecord("\x00", 24, 2048, 2, testPX(0040700)), testRecord("FILE.;1", 22, 5, 0, testNM("inside"), testPX(0100600)))
		copy(b[24*2048:], relocated)
	} else {
		root = append(root, testRecord("README.;1", 22, 5, 0)...)
	}
	copy(b[20*2048:], root)
	copy(b[22*2048:], "hello")
	if joliet {
		copy(b[21*2048:], testFields(testRecord("\x00", 21, 2048, 2), testRecord("\x00J\x00o\x00l\x00i\x00e\x00t", 22, 5, 0)))
	}
	return b
}

func TestRockRidgeNamesMetadataLinksAndRelocation(t *testing.T) {
	file := &starfile.Bytes{Data: testDisc(true, true)}
	img, err := newISOImage(file)
	if err != nil {
		t.Fatal(err)
	}
	if !img.rockRidge || img.joliet {
		t.Fatal("Rock Ridge did not take precedence")
	}
	got, err := img.readDir(img.root)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range got {
		names = append(names, entry.name)
	}
	if strings.Join(names, ",") != "/ReadMe,/readme,/symlink,/deep" {
		t.Fatal(names)
	}
	for name, want := range map[string]int64{"ReadMe": 0100755, "readme": 0100644} {
		entry, err := img.lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		if entry.rr.attributes["mode"] != want {
			t.Fatal(name, entry.rr.attributes)
		}
	}
	if _, err := img.lookup("README"); err == nil {
		t.Fatal("case-folded Rock Ridge lookup")
	}
	entry, err := img.lookup("ReadMe")
	if err != nil {
		t.Fatal(err)
	}
	if entry.rr.attributes["mtime"] != time.Date(2024, 9, 26, 11, 30, 45, 0, time.UTC).Unix() {
		t.Fatal(entry.rr.attributes)
	}
	for key, want := range map[string]int64{"uid": 1000, "gid": 100, "nlink": 1, "inode": 42} {
		if entry.rr.attributes[key] != want {
			t.Fatal(key, entry.rr.attributes)
		}
	}
	link, err := img.lookup("symlink")
	if err != nil {
		t.Fatal(err)
	}
	if link.kind() != "symlink" || link.rr.link != "../target/." {
		t.Fatal(link.kind(), link.rr.link)
	}
	if _, err := (&isoFile{image: img, record: link}).ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("link exposed as file data")
	}
	entry, err = img.lookup("deep/inside")
	if err != nil {
		t.Fatal(err)
	}
	data, err := starfile.ReadAll(&isoFile{image: img, record: entry})
	if err != nil || string(data) != "hello" {
		t.Fatal(string(data), err)
	}
	flattened, err := Entries(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range flattened {
		if entry.Name == "/symlink" && (entry.Kind != "symlink" || entry.Link != "../target/." || entry.File != nil) {
			t.Fatal(entry)
		}
	}
	view, err := adapter.Parse(ISO9660Builtin, file, auto.Options{MaxEntries: 100})
	if err != nil {
		t.Fatal(err)
	}
	children, err := view.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range children {
		if child.Name == "ReadMe" && child.Attributes["mode"] != int64(0100755) {
			t.Fatal(child)
		}
		if child.Name == "symlink" && (child.Kind != "symlink" || child.Reader != nil || child.Attributes["link"] != "../target/.") {
			t.Fatal(child)
		}
	}
	if folded, ok := view.(interface{ CaseInsensitive() bool }); ok && folded.CaseInsensitive() {
		t.Fatal("adapter folds Rock Ridge")
	}
}

func TestJolietAndPlainISOKeepExistingLookup(t *testing.T) {
	for _, joliet := range []bool{false, true} {
		t.Run(fmt.Sprint(joliet), func(t *testing.T) {
			img, err := newISOImage(&starfile.Bytes{Data: testDisc(false, joliet)})
			if err != nil {
				t.Fatal(err)
			}
			name := "readme."
			if joliet {
				name = "joliet"
			}
			r, err := img.lookup(name)
			if err != nil {
				t.Fatal(err)
			}
			if r.rr != nil {
				t.Fatal("invented RR metadata")
			}
			value, _, err := img.Get(starlark.String(name))
			if err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 7)
			n, err := value.(starfile.File).ReadAt(b, 0)
			if n != 5 || err != io.EOF || string(b[:5]) != "hello" {
				t.Fatal(n, err, b)
			}
		})
	}
}

func TestSUSPMalformedAndContinuationBounds(t *testing.T) {
	for name, input := range map[string][]byte{
		"short header":         []byte{'N', 'M', 8},
		"short NM":             testSU("NM"),
		"unfinished NM":        testSU("NM", 1, 'a'),
		"unsafe name":          testNM("a/b"),
		"empty name":           testNM(""),
		"short PX":             testSU("PX", 0),
		"short SL":             testSU("SL", 0, 0, 5, 'a'),
		"unfinished SL":        testSU("SL", 1, 0, 1, 'a'),
		"unfinished component": testSU("SL", 0, 1, 1, 'a'),
		"invalid special":      testSU("SL", 0, 4, 1, 'a'),
		"misplaced root":       testSU("SL", 0, 0, 1, 'a', 8, 0),
		"short TF":             testSU("TF", 2, 1),
		"outside CE":           testCE(800, 0, 10),
		"huge CE":              testCE(0, 0, maxSUSPBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			img := &isoImage{file: &starfile.Bytes{Data: make([]byte, 2048)}}
			if _, err := img.parseRockRidge(input); err == nil {
				t.Fatal("accepted malformed record")
			}
		})
	}
	cycle := testCE(0, 0, 28)
	img := &isoImage{file: &starfile.Bytes{Data: cycle}}
	if _, err := img.parseRockRidge(cycle); err == nil {
		t.Fatal("accepted CE cycle")
	}
	mismatch := testPX(0100644)
	mismatch[8]++
	if _, err := img.parseRockRidge(mismatch); err == nil {
		t.Fatal("accepted inconsistent both-endian integer")
	}
}

func TestRockRidgeAbsoluteAndLongTimestamp(t *testing.T) {
	data := testFields(testSU("SL", 0, 8, 0, 0, 3, 'u', 's', 'r', 0, 3, 'b', 'i', 'n'), testSU("TF", append([]byte{0x82}, append([]byte("2024092612304599"), 0xfc)...)...))
	rr, err := (&isoImage{}).parseRockRidge(data)
	if err != nil {
		t.Fatal(err)
	}
	if rr.link != "/usr/bin" || rr.attributes["mtime"] != time.Date(2024, 9, 26, 13, 30, 45, 0, time.UTC).Unix() {
		t.Fatal(rr)
	}
}

func TestSUSPDetectionSkipAndExtensionReference(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprint(unknown), func(t *testing.T) {
			data := testDisc(false, true)
			id := "RRIP_1991A"
			if unknown {
				id = "OTHER_1991A"
			}
			continuation := testER(id)
			copy(data[23*2048:], continuation)
			rootSU := testFields(make([]byte, 14), testSU("SP", 0xbe, 0xef, 14), testCE(23, 0, uint32(len(continuation))), testPX(0040755))
			root := testFields(testRecord("\x00", 20, 2048, 2, rootSU), testRecord("FILE.;1", 22, 5, 0, make([]byte, 14), testNM("native"), testPX(0100644)))
			clear(data[20*2048 : 21*2048])
			copy(data[20*2048:], root)
			img, err := newISOImage(&starfile.Bytes{Data: data})
			if err != nil {
				t.Fatal(err)
			}
			if unknown {
				if img.rockRidge || !img.joliet {
					t.Fatal("unknown extension selected as Rock Ridge")
				}
				return
			}
			if !img.rockRidge || img.suspSkip != 14 {
				t.Fatal("lost SP/CE/ER detection")
			}
			if _, err := img.lookup("native"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRejectTruncatedAndCyclicDirectory(t *testing.T) {
	data := testDisc(true, false)
	// Make the relocated directory refer back to itself through an ordinary
	// directory entry. Entries must reject this instead of recursing forever.
	dir := testFields(testRecord("\x00", 24, 2048, 2, testPX(0040755)), testRecord("LOOP", 24, 2048, 2, testNM("loop"), testPX(0040755)))
	clear(data[24*2048 : 25*2048])
	copy(data[24*2048:], dir)
	if _, err := Entries(&starfile.Bytes{Data: data}); err == nil {
		t.Fatal("accepted cyclic directory tree")
	}
	// A declared record longer than its supplied bytes must not be interpreted.
	if _, err := parseISODirRecord([]byte{255}); err == nil {
		t.Fatal("accepted truncated record")
	}
}
