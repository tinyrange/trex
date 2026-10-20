package filesystem

import (
	"bytes"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestSetReparsePreservesMetadataAndOwnsPayload(t *testing.T) {
	d := New()
	d.PutFile("/alias.exe", FileRecord{Data: []byte{}, Size: 0})
	d.SetMetadata("/alias.exe", Metadata{FileAttributes: 0x20, HasFileAttributes: true})
	payload := []byte{3, 0, 0, 0, 65, 0, 0, 0}
	if err := d.SetReparse("/alias.exe", 0x8000001b, payload); err != nil {
		t.Fatal(err)
	}
	payload[0] = 9
	m := d.Snapshot().Metadata["/alias.exe"]
	got, err := starfile.ReadAll(m.ReparseData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{3, 0, 0, 0, 65, 0, 0, 0}) || m.ReparseTag != 0x8000001b || m.FileAttributes != 0x20 || !m.HasFileAttributes {
		t.Fatalf("payload=%x metadata=%+v", got, m)
	}
	if err := d.HardLink("/alias.exe", "/other.exe"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetReparse("/other.exe", 0x8000001b, nil); err == nil {
		t.Fatal("accepted multiply linked file")
	}
}

func TestSetReparseRejectsInvalidInput(t *testing.T) {
	d := New()
	d.Mkdir("/dir")
	for _, tc := range []struct {
		name string
		tag  uint32
		size int
	}{
		{"/missing", 0x8000001b, 1}, {"/dir", 0x1b, 1}, {"/dir", 0x80000001, 1}, {"/dir", 0x8000001b, 16377},
	} {
		if err := d.SetReparse(tc.name, tc.tag, make([]byte, tc.size)); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
	f, err := d.Attr("set_reparse")
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []starlark.Int{starlark.MakeInt(-1), starlark.MakeUint64(1 << 32)} {
		if _, err := starlark.Call(&starlark.Thread{}, f, starlark.Tuple{starlark.String("/dir"), tag, starlark.Bytes("")}, nil); err == nil {
			t.Fatalf("accepted tag %s", tag)
		}
	}
	if _, err := starlark.Call(&starlark.Thread{}, f, starlark.Tuple{starlark.String("/dir"), starlark.MakeUint64(0x8000001b), starlark.Bytes("payload")}, nil); err != nil {
		t.Fatal(err)
	}
}
