package adapter

import (
	"io"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type unknownLength struct{ scans int }

func (r *unknownLength) Size() int64            { r.scans++; return 3 }
func (*unknownLength) KnownSize() (int64, bool) { return 0, false }
func (*unknownLength) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= 3 {
		return 0, io.EOF
	}
	n := copy(p, "abc"[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestFileAdapterPreservesLazySize(t *testing.T) {
	r := &unknownLength{}
	f := File(r)
	fn, err := f.(starlark.HasAttrs).Attr("bytes")
	if err != nil {
		t.Fatal(err)
	}
	v, err := starlark.Call(&starlark.Thread{}, fn, starlark.Tuple{starlark.MakeInt(0), starlark.MakeInt(2)}, nil)
	if err != nil || v != starlark.Bytes("ab") || r.scans != 0 {
		t.Fatal(v, err, r.scans)
	}
}

type metadataMapping struct {
	*starfile.Record
	values map[string]starlark.Value
}

func (*metadataMapping) Type() string { return "iso" }
func (m *metadataMapping) Get(k starlark.Value) (starlark.Value, bool, error) {
	s, ok := starlark.AsString(k)
	if !ok {
		return nil, false, nil
	}
	v, ok := m.values[s]
	return v, ok, nil
}

type metadataFile struct {
	*starfile.Bytes
	attrs starlark.StringDict
}

func (f *metadataFile) Attr(n string) (starlark.Value, error) {
	if v, ok := f.attrs[n]; ok {
		return v, nil
	}
	return f.Bytes.Attr(n)
}

func TestMappedEntryKindsMetadataAndCase(t *testing.T) {
	file := &metadataFile{Bytes: &starfile.Bytes{Data: []byte("contents")}, attrs: starlark.StringDict{"entry_type": starlark.String("file"), "mode": starlark.MakeInt(0100644), "uid": starlark.MakeInt(1000), "nlink": starlark.MakeInt(2)}}
	// The source still implements Reader, as older filesystem file wrappers do.
	// Its explicit symlink type must suppress payload reading and detection.
	link := &metadataFile{Bytes: &starfile.Bytes{Data: []byte("encoded link")}, attrs: starlark.StringDict{"entry_type": starlark.String("symlink"), "link": starlark.String("Target"), "mode": starlark.MakeInt(0120777)}}
	m := &metadataMapping{Record: starfile.NewRecord(starlark.StringDict{"case_sensitive": starlark.True}), values: map[string]starlark.Value{
		"/": starfile.NewRecord(starlark.StringDict{"files": starlark.NewList([]starlark.Value{starlark.String("/Target"), starlark.String("/Link")})}), "/Target": file, "/Link": link,
	}}
	v, err := Parsed(m, auto.Options{MaxEntries: 100})
	if err != nil {
		t.Fatal(err)
	}
	root := auto.FromView(v, "", auto.Options{})
	n, err := root.Resolve("Target")
	if err != nil {
		t.Fatal(err)
	}
	if n.Summary().Attributes["mode"] != int64(0100644) || n.Summary().Attributes["nlink"] != int64(2) {
		t.Fatal(n.Summary())
	}
	n, err = root.Resolve("Link")
	if err != nil {
		t.Fatal(err)
	}
	if n.Reader() != nil || n.Summary().Kind != "symlink" || n.Summary().Attributes["link"] != "Target" {
		t.Fatal(n.Summary())
	}
	if _, err := root.Resolve("target"); err == nil {
		t.Fatal("case-sensitive filesystem folded a name")
	}
}
