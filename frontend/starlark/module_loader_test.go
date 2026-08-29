package starlarkfrontend

import (
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
	"testing/fstest"

	"go.starlark.net/starlark"
)

func TestModuleLoaderEmbeddedAndCached(t *testing.T) {
	loader, err := newModuleLoader(".", predeclared())
	if err != nil {
		t.Fatal(err)
	}
	thread := &starlark.Thread{Name: "test"}
	thread.Load = loader.Load

	first, err := loader.Load(thread, "@stdlib//:doc.star")
	if err != nil {
		t.Fatal(err)
	}
	second, err := loader.Load(thread, "@stdlib//:doc.star")
	if err != nil {
		t.Fatal(err)
	}
	if first["identity"] != second["identity"] {
		t.Fatal("loader did not return the cached module environment")
	}
	if got, ok := starlark.AsString(first["STDLIB_NAME"]); !ok || got != "trex" {
		t.Fatalf("STDLIB_NAME = %q, %v", got, ok)
	}
}

func TestSelfRegistrationPluginModule(t *testing.T) {
	thread, environment, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	loader := thread.Load
	globals, err := loader(thread, "@stdlib//windows/selfreg:plugins.star")
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := starlark.Call(thread, globals["successful_imports"], starlark.Tuple{
		starlark.String("kernel32"),
		starlark.NewList(nil),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := environment["emulator"]; !ok {
		t.Fatal("emulator namespace missing from module environment")
	}
	name, err := plugin.(starlark.HasAttrs).Attr("name")
	if err != nil || name != starlark.String("kernel32") {
		t.Fatalf("plugin name = %v, %v", name, err)
	}
}

func TestModuleLoaderRelativeWorkspaceLoad(t *testing.T) {
	workspace := fstest.MapFS{
		"lib/value.star": {Data: []byte("VALUE = 42\n")},
		"app/main.star":  {Data: []byte("load(\"../lib/value.star\", \"VALUE\")\nRESULT = VALUE\n")},
	}
	loader := newModuleLoaderFS(workspace, predeclared())
	thread := &starlark.Thread{Name: "test", Load: loader.Load}
	globals, err := loader.Load(thread, "//app:main.star")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := starlark.AsInt32(globals["RESULT"]); err != nil || got != 42 {
		t.Fatalf("RESULT = %d, %v", got, err)
	}
}

func TestModuleLoaderRejectsTraversalAndCycles(t *testing.T) {
	workspace := fstest.MapFS{
		"a.star": {Data: []byte("load(\":b.star\", \"B\")\nA = B\n")},
		"b.star": {Data: []byte("load(\":a.star\", \"A\")\nB = A\n")},
	}
	loader := newModuleLoaderFS(workspace, predeclared())
	thread := &starlark.Thread{Name: "test", Load: loader.Load}
	if _, err := loader.Load(thread, "../../outside.star"); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("traversal error = %v", err)
	}
	if _, err := loader.Load(thread, "//:a.star"); err == nil || !strings.Contains(err.Error(), "module cycle") {
		t.Fatalf("cycle error = %v", err)
	}
}

func TestPublicScriptsLoad(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	var labels []string
	err = fs.WalkDir(os.DirFS("."), "scripts", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(name, ".star") {
			directory, file := path.Split(name)
			labels = append(labels, "//"+strings.TrimSuffix(directory, "/")+":"+file)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range labels {
		if _, err := thread.Load(thread, label); err != nil {
			t.Errorf("load %s: %v", label, err)
		}
	}
}
