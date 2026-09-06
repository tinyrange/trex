package renvostar

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"renvo.dev/driver"
)

func TestSourceDirectoryChildren(t *testing.T) {
	fs := &sourceFs{dir: filesystem.Snapshot{
		Directories: []string{"/", "/src", "/src/sub", "/src/sub/deeper", "/src2"},
		Files:       map[string]filesystem.FileRecord{"/src/main.go": {}, "/src/sub/helper.go": {}, "/src2/other.go": {}},
	}}
	for _, path := range []string{"src", "./src/", "src/sub/..", "/src"} {
		got, ok := fs.ReadDir(path)
		want := []driver.DirEntry{{Name: "main.go"}, {Name: "sub", IsDir: true}}
		if !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("ReadDir(%q)=%v,%v", path, got, ok)
		}
	}
	if _, ok := fs.ReadDir("/src/main.go"); ok {
		t.Fatal("file listed as directory")
	}
}

func TestCompileFileBackedNestedSources(t *testing.T) {
	dir := filesystem.New()
	dir.Mkdir("src/sub")
	dir.PutFile("src/go.mod", filesystem.FileRecord{Data: []byte("module example.com/hello\n")})
	data := []byte("package main\nimport \"example.com/hello/sub\"\nfunc main() { _ = sub.Value() }\n")
	dir.PutFile("src/main.go", filesystem.FileRecord{File: &starfile.Bytes{Name: "main.go", Data: data}, Size: int64(len(data))})
	dir.PutFile("src/sub/helper.go", filesystem.FileRecord{Data: []byte("package sub\nfunc Value() int { return 42 }\n")})
	result, err := compileModule(dir, "./src/", "windows/386", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !result.result.Ok {
		t.Fatalf("%+v", result.result.Diagnostic)
	}
	if string(result.result.Binary[:2]) != "MZ" {
		t.Fatal("missing executable")
	}
}

type failingFile struct{ starfile.Bytes }

func (*failingFile) ReadAt([]byte, int64) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestSourceReadFailure(t *testing.T) {
	dir := filesystem.New()
	dir.PutFile("main.go", filesystem.FileRecord{File: &failingFile{Bytes: starfile.Bytes{Name: "main.go", Data: []byte("source")}}, Size: 6})
	_, err := compileModule(dir, "main.go", "windows/386", 1<<20)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read failure lost: %v", err)
	}
}

func TestMakeFailureStopsRecipesAndPreservesSource(t *testing.T) {
	dir := filesystem.New()
	dir.PutFile("Makefile", filesystem.FileRecord{Data: []byte("all: bad.exe later.exe\nbad.exe: bad.c\n\trenvo cc bad.c -o bad.exe\nlater.exe: main.c\n\trenvo cc main.c -o later.exe\n")})
	dir.PutFile("bad.c", filesystem.FileRecord{Data: []byte("invalid C syntax")})
	dir.PutFile("main.c", filesystem.FileRecord{Data: []byte("int main(void) { return 0; }")})
	result, err := starlark.Call(&starlark.Thread{}, Builtins()["make"], nil, []starlark.Tuple{{starlark.String("source"), dir}, {starlark.String("target"), starlark.String("windows/386")}})
	if err != nil {
		t.Fatal(err)
	}
	module := result.(*compiledModule)
	if module.result.Ok || len(module.outputs) != 0 {
		t.Fatalf("failed build returned success or outputs: %+v", module)
	}
	if len(dir.Snapshot().Files) != 3 {
		t.Fatal("source tree mutated")
	}
}

func TestMakeRejectsInvalidPlans(t *testing.T) {
	for _, source := range []string{"all: absent.c\n\trenvo cc absent.c -o app\n", "a: b\nb: a\n", "all:\n\tcc main.c -o app\n", "all:\n\trenvo cc main.c -o app; echo bad\n"} {
		dir := filesystem.New()
		dir.PutFile("Makefile", filesystem.FileRecord{Data: []byte(source)})
		result, err := starlark.Call(&starlark.Thread{}, Builtins()["make"], nil, []starlark.Tuple{{starlark.String("source"), dir}, {starlark.String("target"), starlark.String("windows/386")}})
		if err == nil && result.(*compiledModule).result.Ok {
			t.Fatalf("accepted invalid Makefile: %s", source)
		}
	}
}

func TestCCDiagnostics(t *testing.T) {
	dir := filesystem.New()
	dir.PutFile("bad.c", filesystem.FileRecord{Data: []byte("invalid C syntax")})
	result, err := starlark.Call(&starlark.Thread{}, Builtins()["cc"], nil, []starlark.Tuple{{starlark.String("source"), dir}, {starlark.String("input"), starlark.String("bad.c")}, {starlark.String("target"), starlark.String("windows/386")}})
	if err != nil {
		t.Fatal(err)
	}
	module := result.(*compiledModule)
	if module.result.Ok || !strings.Contains(module.result.Diagnostic.Path, "bad.c") {
		t.Fatalf("missing source diagnostic: %+v", module.result)
	}
}

func TestMakeGoRecipeAndOutputIsolation(t *testing.T) {
	dir := filesystem.New()
	dir.PutFile("Makefile", filesystem.FileRecord{Data: []byte("all: app.exe\napp.exe: main.go\n\trenvo -o $@ $<\n")})
	dir.PutFile("main.go", filesystem.FileRecord{Data: []byte("package main\nfunc main() {}\n")})
	value, err := starlark.Call(&starlark.Thread{}, Builtins()["make"], nil, []starlark.Tuple{
		{starlark.String("source"), dir}, {starlark.String("target"), starlark.String("windows/386")},
		{starlark.String("output"), starlark.String("app.exe")}, {starlark.String("arena_size"), starlark.MakeInt(1 << 20)},
	})
	if err != nil {
		t.Fatal(err)
	}
	module := value.(*compiledModule)
	if !module.result.Ok || len(module.outputs) != 1 || !reflect.DeepEqual(module.result.Binary, module.outputs["app.exe"]) {
		t.Fatalf("invalid build result: %+v", module.result)
	}
	if len(dir.Snapshot().Files) != 2 {
		t.Fatal("make mutated the input source directory")
	}
}
