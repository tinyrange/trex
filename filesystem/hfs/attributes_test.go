package hfs

import (
	"bytes"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
	"unicode/utf16"
)

func attributeKey(id, start uint32, name string, data []byte) []byte {
	u := utf16.Encode([]rune(name))
	b := make([]byte, 14+len(u)*2+len(data))
	be.PutUint16(b, uint16(12+len(u)*2))
	be.PutUint32(b[4:], id)
	be.PutUint32(b[8:], start)
	be.PutUint16(b[12:], uint16(len(u)))
	for i, c := range u {
		be.PutUint16(b[14+2*i:], c)
	}
	copy(b[14+len(u)*2:], data)
	return b
}
func inlineAttribute(id uint32, name string, value []byte) []byte {
	b := make([]byte, 16+len(value))
	be.PutUint32(b, 0x10)
	be.PutUint32(b[12:], uint32(len(value)))
	copy(b[16:], value)
	return attributeKey(id, 0, name, b)
}
func attributeFixture(records ...[]byte) []byte {
	b := plusFixture()
	desc := b[1024+352:]
	be.PutUint64(desc, 1024)
	be.PutUint32(desc[12:], 2)
	be.PutUint32(desc[16:], 40)
	be.PutUint32(desc[20:], 2)
	copy(b[40*512:], tree(records...))
	return b
}
func TestPlusInlineAttributesAndAuto(t *testing.T) {
	b := attributeFixture(inlineAttribute(16, "com.apple.test", []byte{0, 1, 255}), inlineAttribute(2, "directory", []byte("root")))
	v, err := Open(&starfile.Bytes{Data: b}, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"directory", "com.apple.test"} {
		got, err := starfile.ReadAll(v.Entries[i].Xattrs[name])
		want := []byte("root")
		if i == 1 {
			want = []byte{0, 1, 255}
		}
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("attribute %q %x %v", name, got, err)
		}
	}
	node := auto.Open(&starfile.Bytes{Data: b}, "disk", auto.Options{})
	for path, want := range map[string][]byte{"é%2F😀/xattrs/com.apple.test": {0, 1, 255}, "é%2F😀/resource": []byte("res")} {
		n, err := node.Resolve(path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := starfile.ReadAll(n.Reader())
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("auto attribute %x %v", got, err)
		}
	}
	// Root attributes must not replace the directory view and hide children.
	if _, err := node.Resolve("é%2F😀/data"); err != nil {
		t.Fatal(err)
	}
}
func TestPlusForkAttributeOverflow(t *testing.T) {
	data := make([]byte, 88)
	be.PutUint32(data, 0x20)
	fork := data[8:]
	be.PutUint64(fork, 4097)
	be.PutUint32(fork[12:], 9)
	for i := 0; i < 8; i++ {
		be.PutUint32(fork[16+i*8:], uint32(10+2*i))
		be.PutUint32(fork[20+i*8:], 1)
	}
	overflow := make([]byte, 72)
	be.PutUint32(overflow, 0x30)
	be.PutUint32(overflow[8:], 30)
	be.PutUint32(overflow[12:], 1)
	b := attributeFixture(attributeKey(16, 0, "large", data), attributeKey(16, 8, "large", overflow))
	v, err := Open(&starfile.Bytes{Data: b}, 100)
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(v.Entries[1].Xattrs["large"])
	if err != nil || len(got) != 4097 || got[4096] != 9 || got[0] != 1 || got[512] != 2 {
		t.Fatalf("fork attr %d %v", len(got), err)
	}
	// Attribute overflow must not accidentally use the ordinary data-fork tree.
	b = attributeFixture(attributeKey(16, 0, "large", data))
	if _, err := Open(&starfile.Bytes{Data: b}, 100); err == nil {
		t.Fatal("missing independent attribute overflow accepted")
	}
}
func TestPlusRejectAttributeCorruption(t *testing.T) {
	valid := inlineAttribute(16, "a", []byte("test"))
	for name, records := range map[string][][]byte{
		"duplicate":             {valid, valid},
		"missing ID":            {inlineAttribute(999, "a", nil)},
		"truncated":             {valid[:len(valid)-1]},
		"overflow without fork": {attributeKey(16, 1, "a", append([]byte{0, 0, 0, 0x30}, make([]byte, 68)...))},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(&starfile.Bytes{Data: attributeFixture(records...)}, 100); err == nil {
				t.Fatal("accepted malformed attributes")
			}
		})
	}
}
func TestPlusLinksPreserveRawForksAndRejectInvalidTargets(t *testing.T) {
	raw := &starfile.Bytes{Data: []byte("alias")}
	rawRes := &starfile.Bytes{Data: []byte("alias-resource")}
	data := &starfile.Bytes{Data: []byte("inode data")}
	res := &starfile.Bytes{Data: []byte("resource")}
	v := &Volume{Entries: []Entry{
		{ID: 20, Parent: 2, Name: []byte("\x00\x00\x00\x00HFS+ Private Data"), Kind: "directory"},
		{ID: 21, Parent: 20, Name: []byte("iNode123"), Path: "/private/iNode123", Kind: "file", Data: data, Resource: res, Xattrs: map[string]starfile.File{"attr": data}},
		{ID: 22, Parent: 2, Path: "/alias", Kind: "file", FinderInfo: []byte("hlnkhfs+"), Special: 123, Data: raw, Resource: rawRes},
		{ID: 23, Parent: 2, Path: "/link", Kind: "file", Mode: 0120777, Data: &starfile.Bytes{Data: []byte("../target")}},
	}}
	if err := plusLinks(v); err != nil {
		t.Fatal(err)
	}
	e := v.Entries[2]
	if e.Data != data || e.Resource != res || e.RawData != raw || e.RawResource != rawRes || e.Xattrs["attr"] != data || e.Target != "/private/iNode123" {
		t.Fatal("inode alias lost forks/metadata")
	}
	if v.Entries[3].Kind != "symlink" || v.Entries[3].Target != "../target" {
		t.Fatal("symlink not decoded")
	}
	for _, e := range []Entry{
		{Kind: "file", FinderInfo: []byte("hlnkhfs+"), Special: 456},
		{Kind: "file", Mode: 0120777, Data: &starfile.Bytes{Data: []byte("a\x00b")}},
		{Kind: "file", OwnerFlags: 0x20},
	} {
		if err := plusLinks(&Volume{Entries: []Entry{e}}); err == nil {
			t.Fatal("accepted unresolved/compressed/invalid link")
		}
	}
}
