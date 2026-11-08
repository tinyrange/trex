package ckd

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// faultyReader returns its data with a fixed error, or short reads.
type faultyReader struct {
	data  []byte
	err   error
	short bool
}

func (r faultyReader) Size() int64 { return int64(len(r.data)) }
func (r faultyReader) ReadAt(p []byte, off int64) (int, error) {
	n := copy(p, r.data[off:])
	if r.short && n > 0 {
		n--
	}
	return n, r.err
}

func TestBuiltinsPropagateReadErrors(t *testing.T) {
	lib := libpds([][][]byte{{card(eb("A", 1))}}, []struct {
		name   string
		member int
	}{{"A", 0}})
	checksum := errors.New("checksum mismatch")
	for name, r := range map[string]faultyReader{
		"error-with-full-read": {data: lib, err: checksum},
		"short-read":           {data: lib, short: true},
	} {
		for builtin, fn := range map[string]func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error){
			"cms_library": CMSLibraryBuiltin, "cms_unpack": CMSUnpackBuiltin, "cms_module": CMSModuleBuiltin,
			"cms_loadlib": CMSLoadLibraryBuiltin, "cms_csllib": CMSCallableLibraryBuiltin, "object_deck": ObjectDeckBuiltin,
		} {
			_, err := fn(nil, nil, starlark.Tuple{starfile.NewReader("damaged", r)}, nil)
			if err == nil {
				t.Errorf("%s %s: accepted a failed read", builtin, name)
			}
		}
	}
	// A complete read reporting io.EOF is not an error.
	if _, err := CMSLibraryBuiltin(nil, nil, starlark.Tuple{starfile.NewReader("ok", faultyReader{data: lib, err: io.EOF})}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCMSRejectsShortDirectory(t *testing.T) {
	cc := buildCMS(t)
	img := cc.fixture.image(t)
	self := []byte{0, 0, 0, 1, 0, 0, 0, 0, 0xc4, 0xc9, 0xd9, 0xc5, 0xc3, 0xe3, 0xd6, 0xd9}
	at := bytes.Index(img, self)
	if at < 0 {
		t.Fatal("fixture directory FST not found")
	}
	for _, n := range []uint32{0, 1} {
		b := bytes.Clone(img)
		be.PutUint32(b[at+48:], n)
		m, err := OpenCMS(openTest(t, b), 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.Files(100); err == nil || !strings.Contains(err.Error(), "directory declares") {
			t.Fatalf("records %d: %v", n, err)
		}
	}
}

func TestUnpackCMSLimitIncludesRecordPrefix(t *testing.T) {
	v := packed(0xe5, 10, []byte{0xfc, 0x00, 'A', 0xff})
	if _, err := UnpackCMS(v, 2); err == nil {
		t.Fatal("one-byte variable record decoded into 2 bytes")
	}
	if u, err := UnpackCMS(v, 3); err != nil || len(u.Data) != 3 {
		t.Fatal(u, err)
	}
}

func TestLoadLibraryAliasesShareMember(t *testing.T) {
	entry := func(name string, c byte) []byte {
		e := make([]byte, (16+2*int(c&0x1f)+15)&^15)
		copy(e, eb(name, 8))
		e[11] = c
		be.PutUint32(e[12:], 2)
		return e
	}
	var dir []byte
	dir = append(dir, entry("MAIN", 0x0c)...)
	for _, n := range []string{"A1", "A2", "A3"} {
		dir = append(dir, entry(n, 0x8c)...)
	}
	header := make([]byte, 64)
	copy(header, cmsLibraryMagic)
	be.PutUint32(header[8:], uint32(len(dir)))
	be.PutUint32(header[12:], 4)
	copy(header[20:], cmsLibraryMagic)
	be.PutUint16(header[26:], 4)
	data := vstream(header, bytes.Repeat([]byte{0x47}, 100), cmsLibraryDelimiter, dir)
	v, err := CMSLoadLibraryBuiltin(nil, nil, starlark.Tuple{starfile.NewReader("lib", byteFile{bytes.NewReader(data)})}, nil)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := v.(starlark.HasAttrs).Attr("entries")
	list := entries.(*starlark.List)
	if list.Len() != 4 {
		t.Fatalf("%d entries", list.Len())
	}
	var first []byte
	for i := 0; i < list.Len(); i++ {
		d, _ := list.Index(i).(starlark.HasAttrs).Attr("data")
		r := d.(*starfile.ReaderValue)
		b := make([]byte, r.Size())
		if _, err := r.ReadAt(b, 0); err != nil && err != io.EOF {
			t.Fatal(err)
		}
		if i == 0 {
			first = b
		} else if !bytes.Equal(b, first) {
			t.Fatalf("alias %d stream differs", i)
		}
	}
}

// FuzzCMSDirectory replaces the directory block; decoding must not panic.
func FuzzCMSDirectory(f *testing.F) {
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		cc := buildCMS(t)
		copy(cc.fixture.blocks[4], b)
		img := cc.fixture.image(t)
		m, err := OpenCMS(openTest(t, img), 1, 0)
		if err != nil {
			return
		}
		files, err := m.Files(1000)
		if err != nil {
			return
		}
		for _, x := range files {
			_, _ = m.Content(x, 1<<20)
		}
	})
}
