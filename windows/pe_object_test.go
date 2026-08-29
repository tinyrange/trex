package windows

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"testing"

	"go.starlark.net/starlark"
)

func peFixupValue(t *testing.T, offset int, label string) *starlark.Dict {
	t.Helper()
	dict := starlark.NewDict(2)
	_ = dict.SetKey(starlark.String("offset"), starlark.MakeInt(offset))
	_ = dict.SetKey(starlark.String("label"), starlark.String(label))
	return dict
}

type countingPEFile struct {
	*starfile.Bytes
	reads int
}

func (f *countingPEFile) ReadAt(data []byte, offset int64) (int, error) {
	f.reads++
	return f.Bytes.ReadAt(data, offset)
}

func TestPEPointerStringTables(t *testing.T) {
	section := make([]byte, 12)
	section[0] = 0xc3
	labels := starlark.NewDict(3)
	_ = labels.SetKey(starlark.String("entry"), starlark.MakeInt(0))
	fixups := starlark.NewList(nil)
	for index, item := range []struct {
		name string
		text string
	}{{"first", "alpha.dll\x00"}, {"second", "beta.dll\x00"}} {
		offset := len(section)
		_ = labels.SetKey(starlark.String(item.name), starlark.MakeInt(offset))
		section = append(section, item.text...)
		if err := fixups.Append(peFixupValue(t, 4+index*4, item.name)); err != nil {
			t.Fatal(err)
		}
	}
	value, err := pe32ExecutableBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(section), labels, fixups}, nil)
	if err != nil {
		t.Fatal(err)
	}
	source := &countingPEFile{Bytes: &starfile.Bytes{Name: "tables.dll", Data: []byte(value.(starlark.Bytes))}}
	object := &windowsPE{file: source, cache: make(starlark.StringDict)}
	tablesValue, err := object.pointerStringTablesBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("suffix"), starlark.String(".dll")},
	})
	if err != nil {
		t.Fatal(err)
	}
	tables := tablesValue.(*starlark.List)
	if tables.Len() != 1 {
		t.Fatalf("pointer tables = %v, want one table", tables)
	}
	table := tables.Index(0).(*starlark.List)
	if table.Len() != 2 || table.Index(0).(starlark.String).GoString() != "alpha.dll" || table.Index(1).(starlark.String).GoString() != "beta.dll" {
		t.Fatalf("pointer table = %v", table)
	}
	if _, err := object.Attr("info"); err != nil {
		t.Fatal(err)
	}
	dataValue, err := object.Attr("data")
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := dataValue.(starfile.File).ReadAt(buffer, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if source.reads != 1 {
		t.Fatalf("PE source was materialized %d times, want once", source.reads)
	}
}
