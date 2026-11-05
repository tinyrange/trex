package filesystem

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestDirectoryPathNamesSnapshotAndAmbiguity(t *testing.T) {
	d := New()
	d.Mkdir("/Empty/Ä")
	d.Mkdir("/windows")
	d.PutFile("/Windows/File", FileRecord{Data: []byte("content"), Size: 7})
	paths := func(lower bool) (*starlark.Dict, error) {
		v, err := d.pathNamesBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("lower"), starlark.Bool(lower)}})
		if err != nil {
			return nil, err
		}
		return v.(*starlark.Dict), nil
	}
	snapshot, err := paths(true)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"/": "/", "/empty": "/Empty", "/empty/ä": "/Empty/Ä", "/windows": "/Windows", "/windows/file": "/Windows/File"} {
		value, found, err := snapshot.Get(starlark.String(key))
		if err != nil || !found || value != starlark.String(want) {
			t.Fatalf("%s: %v %v", key, value, err)
		}
	}
	snapshot.Clear()
	d.PutFile("/windows/file", FileRecord{Data: []byte("other"), Size: 5})
	if _, err := paths(true); err == nil {
		t.Fatal("case collision silently selected an entry")
	}
	exact, err := paths(false)
	if err != nil || exact.Len() != 7 {
		t.Fatalf("exact paths: %v %v", exact, err)
	}
	if snapshot.Len() != 0 {
		t.Fatal("snapshot followed later namespace mutation")
	}
}
