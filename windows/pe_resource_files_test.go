package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type resourceReadCounter struct {
	*starfile.Bytes
	read int
}

func (c *resourceReadCounter) ReadAt(p []byte, off int64) (int, error) {
	c.read += len(p)
	return c.Bytes.ReadAt(p, off)
}
func resourceFileFixture(t *testing.T) []byte {
	t.Helper()
	labels := starlark.NewDict(1)
	_ = labels.SetKey(starlark.String("entry"), starlark.MakeInt(0))
	v, err := pe32ExecutableBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("\x90\xc3"), labels, starlark.NewList(nil)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := peWithResources([]byte(v.(starlark.Bytes)), []peResource{
		{typ: "CABINET", name: "名", lang: "#1033", data: bytes.Repeat([]byte("data"), 1<<20)},
		{typ: "#10", name: "#1", lang: "#0", data: []byte("short")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestPEResourceFilesBorrowWithoutPayloadReads(t *testing.T) {
	data := resourceFileFixture(t)
	counter := &resourceReadCounter{Bytes: &starfile.Bytes{Data: data}}
	entries, err := peResourceFiles(counter)
	if err != nil || len(entries) != 2 {
		t.Fatalf("index: %v", err)
	}
	if counter.read > 65536 {
		t.Fatalf("index read payload: %d", counter.read)
	}
	expected, err := peResources(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		found := false
		for _, old := range expected {
			if e.typ == old.typ && e.name == old.name && e.lang == old.lang {
				found = true
				got := make([]byte, e.size)
				if _, err := io.ReadFull(io.NewSectionReader(counter, e.offset, e.size), got); err != nil || !bytes.Equal(got, old.data) {
					t.Fatalf("resource: %v", err)
				}
			}
		}
		if !found {
			t.Fatalf("missing %+v", e)
		}
	}
	p := &windowsPE{file: counter, cache: make(starlark.StringDict)}
	value, err := p.resourceFilesBuiltin(nil, nil, nil, nil)
	if err != nil || p.materialized != nil {
		t.Fatalf("method materialized PE: %v", err)
	}
	row := value.(*starlark.List).Index(0).(*starlark.Dict)
	resource, _, _ := row.Get(starlark.String("file"))
	file := resource.(starfile.File)
	if _, err := file.WriteAt([]byte{1}, 0); err == nil {
		t.Fatal("mutable resource view")
	}
	if err := row.SetKey(starlark.String("name"), starlark.String("bad")); err == nil {
		t.Fatal("mutable metadata")
	}
}
func TestPEResourceFilesMalformedBoundsAndCycles(t *testing.T) {
	source := resourceFileFixture(t)
	pf, err := pe.NewFile(bytes.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()
	dir := pf.OptionalHeader.(*pe.OptionalHeader32).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
	base, err := peResourceFileOffset(pf, dir.VirtualAddress, dir.Size)
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b[base+20:], 0x80000000) }, // cycle to root
		func(b []byte) {
			binary.LittleEndian.PutUint16(b[base+12:], 65535)
			binary.LittleEndian.PutUint16(b[base+14:], 65535)
		}, // widened count
		func(b []byte) { binary.LittleEndian.PutUint32(b[base+16:], 0xffffffff) }, // name outside directory
		func(b []byte) { binary.LittleEndian.PutUint32(b[base+20:], 0x7fffffff) }, // leaf outside directory
	} {
		data := bytes.Clone(source)
		edit(data)
		if _, err := peResourceFiles(&starfile.Bytes{Data: data}); err == nil {
			t.Fatal("accepted malformed metadata")
		}
	}
	if _, err := peResourceFiles(&starfile.Bytes{Data: source[:base+24]}); err == nil {
		t.Fatal("truncated resource extent")
	}
	if _, err := peResourceFileOffset(pf, 0xfffffff0, 128); err == nil {
		t.Fatal("wrapped RVA extent")
	}
}
