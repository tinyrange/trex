package filesystem

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
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

func TestVirtualDirectoryHardLinkSharesIdentityAndContent(t *testing.T) {
	dir := New()
	dir.PutFile("/Windows/WinSxS/component/file.dll", FileRecord{Data: []byte("updated"), Size: 7})
	dir.PutFile("/Windows/System32/file.dll", FileRecord{Data: []byte("old"), Size: 3})
	if err := dir.HardLink("/Windows/WinSxS/component/file.dll", "/Windows/System32/file.dll"); err != nil {
		t.Fatal(err)
	}
	snapshot := dir.Snapshot()
	store := snapshot.Metadata["/Windows/WinSxS/component/file.dll"].HardLink
	destination := snapshot.Metadata["/Windows/System32/file.dll"].HardLink
	if store == 0 || destination != store {
		t.Fatalf("hard-link identities = store %d destination %d", store, destination)
	}
	if got := string(snapshot.Files["/Windows/System32/file.dll"].Data); got != "updated" {
		t.Fatalf("hard-link destination content = %q", got)
	}
}

func TestVirtualDirectorySetSecurity(t *testing.T) {
	dir := New()
	dir.Mkdir("/secured")
	descriptor := make([]byte, 20)
	descriptor[0] = 1
	descriptor[2] = 0x00
	descriptor[3] = 0x80
	if err := dir.SetSecurity("/secured", descriptor); err != nil {
		t.Fatal(err)
	}
	descriptor[0] = 2
	if got := dir.Snapshot().Metadata["/secured"].SecurityDescriptor; !bytes.Equal(got, append([]byte{1}, descriptor[1:]...)) {
		t.Fatalf("security descriptor = %x", got)
	}
	if err := dir.SetSecurity("/missing", descriptor); err == nil {
		t.Fatal("SetSecurity accepted a missing path")
	}
}

func TestVirtualDirectoryGetSecurity(t *testing.T) {
	dir := New()
	dir.Mkdir("/secured")
	dir.PutFile("/secured/file", FileRecord{Data: []byte("x"), Size: 1})
	get, err := dir.Attr("get_security")
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) (starlark.Value, error) {
		return starlark.Call(&starlark.Thread{}, get, starlark.Tuple{starlark.String(name)}, nil)
	}
	for _, name := range []string{"/secured", "/secured/file"} {
		if got, err := read(name); err != nil || got != starlark.None {
			t.Fatalf("unset security = %v, %v", got, err)
		}
		descriptor := make([]byte, 20)
		descriptor[0], descriptor[3] = 1, 0x80
		if err := dir.SetSecurity(name, descriptor); err != nil {
			t.Fatal(err)
		}
		got, err := read(name)
		if err != nil || got != starlark.Bytes(descriptor) {
			t.Fatalf("security = %v, %v", got, err)
		}
		// Previously returned bytes are independent of subsequent mutations.
		descriptor[2] = 4
		if err := dir.SetSecurity(name, descriptor); err != nil {
			t.Fatal(err)
		}
		if got == starlark.Bytes(descriptor) {
			t.Fatal("returned security changed after replacement")
		}
	}
	if _, err := read("/missing"); err == nil {
		t.Fatal("missing path accepted")
	}
	if got, err := read(`\secured\file`); err != nil || got == starlark.None {
		t.Fatalf("normalized path = %v, %v", got, err)
	}
}

func TestVirtualDirectorySetSecurityUpdatesHardLinkIdentity(t *testing.T) {
	dir := New()
	dir.PutFile("/z/source", FileRecord{Data: []byte("x"), Size: 1})
	dir.PutFile("/unrelated", FileRecord{Data: []byte("x"), Size: 1})
	if err := dir.HardLink("/z/source", "/a/alias"); err != nil {
		t.Fatal(err)
	}
	aliasMetadata := dir.metadata["/a/alias"]
	aliasMetadata.ShortName = "ALIAS~1"
	dir.SetMetadata("/a/alias", aliasMetadata)
	descriptor := make([]byte, 20)
	descriptor[0], descriptor[3] = 1, 0x80
	// The modified path sorts after its alias. A builder must not silently
	// keep the old descriptor merely because that alias was visited first.
	if err := dir.SetSecurity("/z/source", descriptor); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"/z/source", "/a/alias"} {
		if !bytes.Equal(dir.metadata[name].SecurityDescriptor, descriptor) {
			t.Fatalf("security not shared with %s", name)
		}
	}
	if dir.metadata["/a/alias"].ShortName != "ALIAS~1" || len(dir.metadata["/unrelated"].SecurityDescriptor) != 0 {
		t.Fatal("security update changed link-local or unrelated metadata")
	}
	// A subsequent update through another alias reaches every existing link.
	if err := dir.HardLink("/a/alias", "/later"); err != nil {
		t.Fatal(err)
	}
	descriptor[2] = 4
	if err := dir.SetSecurity("/later", descriptor); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dir.metadata["/z/source"].SecurityDescriptor, descriptor) {
		t.Fatal("update through another alias did not reach source")
	}
}

func TestDirectoryHardLinkImportedIDsAndRelease(t *testing.T) {
	dir := New()
	for _, name := range []string{"/imported", "/alias", "/source", "/second", "/third"} {
		dir.PutFile(name, FileRecord{Data: []byte("x"), Size: 1})
	}
	dir.SetMetadata("/imported", Metadata{HardLink: 1})
	dir.SetMetadata("/alias", Metadata{HardLink: 1})
	dir.SetMetadata("/high", Metadata{HardLink: ^uint64(0)})
	if err := dir.HardLink("/source", "/dest"); err != nil {
		t.Fatal(err)
	}
	if got := dir.metadata["/source"].HardLink; got != 2 {
		t.Fatalf("allocated %d, want 2", got)
	}
	// Reapplying metadata must not add an extra reference.
	dir.SetMetadata("/imported", Metadata{HardLink: 1})
	dir.SetMetadata("/imported", Metadata{})
	if err := dir.HardLink("/second", "/dest2"); err != nil {
		t.Fatal(err)
	}
	if got := dir.metadata["/second"].HardLink; got != 3 {
		t.Fatalf("allocated %d while imported alias survives, want 3", got)
	}
	if _, err := dir.removeBuiltin(nil, nil, starlark.Tuple{starlark.String("/alias")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := dir.HardLink("/third", "/dest3"); err != nil {
		t.Fatal(err)
	}
	if got := dir.metadata["/third"].HardLink; got != 1 {
		t.Fatalf("released identity was not reused: %d", got)
	}
	if err := dir.HardLink("/source", "/dest3"); err != nil {
		t.Fatal(err)
	}
	if dir.hardLinkRefs[1] != 1 || dir.hardLinkRefs[2] != 3 {
		t.Fatalf("replacement lost identity references: %v", dir.hardLinkRefs)
	}
	if err := dir.HardLink("/source", "/source"); err != nil {
		t.Fatal(err)
	}
	if dir.hardLinkRefs[2] != 3 {
		t.Fatal("self-link changed reference count")
	}
}

func BenchmarkDirectoryHardLinkAllocation(b *testing.B) {
	for _, size := range []int{1000, 10000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			for iteration := 0; iteration < b.N; iteration++ {
				dir := New()
				for i := 0; i < size; i++ {
					source := fmt.Sprintf("/store/%d", i)
					dir.PutFile(source, FileRecord{Size: 1})
					if err := dir.HardLink(source, fmt.Sprintf("/dest/%d", i)); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
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
