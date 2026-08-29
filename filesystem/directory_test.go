package filesystem

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"testing"

	"go.starlark.net/starlark"
)

func TestVirtualDirectoryFind(t *testing.T) {
	dir := New()
	dir.PutFile(`/Windows/System/example.dll`, FileRecord{Data: []byte("payload"), Size: 7})

	value, err := dir.findBuiltin(nil, nil, starlark.Tuple{starlark.String(`\Windows\System\example.dll`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	file, ok := value.(starfile.File)
	if !ok {
		t.Fatalf("find() = %v, want file", value)
	}
	data := make([]byte, file.Size())
	if _, err := file.ReadAt(data, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if got := string(data); got != "payload" {
		t.Fatalf("find() contents = %q, want payload", got)
	}

	missing, err := dir.findBuiltin(nil, nil, starlark.Tuple{starlark.String(`/missing`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if missing != starlark.None {
		t.Fatalf("find(missing) = %v, want None", missing)
	}
}

func TestVirtualDirectoryFATShortPathUsesSiblingAliases(t *testing.T) {
	dir := New()
	dir.Mkdir(`/Program Files/Windows Media Player`)
	dir.Mkdir(`/Program Files/Windows NT/Accessories`)
	dir.files[`/Program Files/Windows NT/Accessories/wordpad.exe`] = FileRecord{Data: []byte{1}, Size: 1}

	got, err := dir.fatShortPath(`C:\Program Files\Windows NT\Accessories\wordpad.exe`)
	if err != nil {
		t.Fatal(err)
	}
	if want := `C:\PROGRA~1\WINDOW~2\ACCESS~1\WORDPAD.EXE`; got != want {
		t.Fatalf("FAT short path = %q, want %q", got, want)
	}
}

func TestVirtualDirectoryFATShortPathDerivesMissingLeaf(t *testing.T) {
	dir := New()
	got, err := dir.fatShortPath(`C:\missing component.exe`)
	if err != nil {
		t.Fatal(err)
	}
	if want := `C:\MISSIN~1.EXE`; got != want {
		t.Fatalf("missing FAT short path = %q, want %q", got, want)
	}
}

func TestVirtualDirectoryFATShortPathCachesAndInvalidatesIndex(t *testing.T) {
	dir := New()
	dir.Mkdir(`/Program Files`)
	first, err := dir.currentFATShortIndex()
	if err != nil {
		t.Fatal(err)
	}
	second, err := dir.currentFATShortIndex()
	if err != nil {
		t.Fatal(err)
	}
	first["/cache-probe"] = "PROBE"
	if second["/cache-probe"] != "PROBE" {
		t.Fatal("FAT short-name index was rebuilt without a directory mutation")
	}

	dir.Mkdir(`/Program Data`)
	got, err := dir.fatShortPath(`C:\Program Files`)
	if err != nil {
		t.Fatal(err)
	}
	if want := `C:\PROGRA~2`; got != want {
		t.Fatalf("FAT short path after mutation = %q, want %q", got, want)
	}
	third, err := dir.currentFATShortIndex()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := third["/cache-probe"]; ok {
		t.Fatal("FAT short-name index was not invalidated after directory mutation")
	}
}

func TestPortablePathHelpers(t *testing.T) {
	tests := []struct {
		name string
		call func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error)
		want string
	}{
		{name: "base", call: PathBaseBuiltin, want: "kernel32.dll"},
		{name: "dir", call: PathDirBuiltin, want: "/Windows/System32"},
		{name: "ext", call: PathExtBuiltin, want: ".dll"},
		{name: "clean", call: PathCleanBuiltin, want: "/Windows/System32/kernel32.dll"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := test.call(nil, nil, starlark.Tuple{starlark.String(`/Windows/Temp/../System32/kernel32.dll`)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(value.(starlark.String)); got != test.want {
				t.Fatalf("path.%s() = %q, want %q", test.name, got, test.want)
			}
		})
	}
}

func BenchmarkVirtualDirectoryFATShortPathCached(b *testing.B) {
	dir := New()
	for index := range 10000 {
		dir.Mkdir("/Program Files/Component " + starlark.MakeInt(index).String())
	}
	if _, err := dir.fatShortPath(`/Program Files/Component 9999`); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := dir.fatShortPath(`/Program Files/Component 9999`); err != nil {
			b.Fatal(err)
		}
	}
}
