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

func TestFreshModuleLoadKeepsRetainedReferencesAndRefreshesDependencies(t *testing.T) {
	workspace := fstest.MapFS{
		"lib/value.star": {Data: []byte("VALUE = 42\n")},
		"app/main.star":  {Data: []byte("load(\"../lib/value.star\", \"VALUE\")\n_PRIVATE = 1\ndef get():\n    return VALUE\n")},
	}
	environment := predeclared()
	loader := newModuleLoaderFS(workspace, environment)
	thread := &starlark.Thread{Name: "test", Load: loader.Load}
	thread.SetLocal(moduleLoaderKey, loader)
	thread.SetLocal(starlarkREPLActive, true)
	old, err := loader.Load(thread, "//app:main.star")
	if err != nil {
		t.Fatal(err)
	}
	workspace["lib/value.star"] = &fstest.MapFile{Data: []byte("VALUE = 99\n")}
	fresh, err := starlark.Call(thread, environment["load_fresh"], starlark.Tuple{starlark.String("//app:main.star")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	exports := fresh.(*starlark.Dict)
	get, _, _ := exports.Get(starlark.String("get"))
	for _, test := range []struct {
		fn   starlark.Value
		want string
	}{{old["get"], "42"}, {get, "99"}} {
		value, err := starlark.Call(thread, test.fn, nil, nil)
		if err != nil || value.String() != test.want {
			t.Fatalf("value=%v err=%v want=%s", value, err, test.want)
		}
	}
	if _, found, _ := exports.Get(starlark.String("_PRIVATE")); found {
		t.Fatal("fresh load exported a private name")
	}
	if err := exports.SetKey(starlark.String("new"), starlark.None); err == nil {
		t.Fatal("fresh exports are mutable")
	}
	// A failed fresh dependency must restore the original loader as well.
	workspace["lib/value.star"] = &fstest.MapFile{Data: []byte("load(\":missing.star\", \"VALUE\")\n")}
	if _, err := loader.LoadFresh(thread, "//app:main.star"); err == nil {
		t.Fatal("missing fresh dependency succeeded")
	}
	cached, err := thread.Load(thread, "//lib:value.star")
	if err != nil || cached["VALUE"].String() != "42" {
		t.Fatalf("original loader was not restored: %v %v", cached, err)
	}
	if _, err := loader.LoadFresh(thread, "//../outside.star"); err == nil {
		t.Fatal("fresh load escaped its workspace")
	}
	thread.SetLocal(starlarkREPLActive, false)
	if _, err := starlark.Call(thread, environment["load_fresh"], starlark.Tuple{starlark.String("//app:main.star")}, nil); err == nil {
		t.Fatal("fresh load accepted execution outside a REPL")
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
