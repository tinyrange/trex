package starlarkfrontend

import (
	"bytes"
	"io/fs"
	"os"
	"strings"
	"testing"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

func TestStarlarkStandardLibrary(t *testing.T) {
	var modules []string
	err := fs.WalkDir(standardLibrary, "stdlib", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(name, ".star") {
			modules = append(modules, strings.TrimPrefix(name, "stdlib/"))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, modulePath := range modules {
		modulePath := modulePath
		t.Run(modulePath, func(t *testing.T) {
			sourcePath := "stdlib/" + modulePath
			source, err := fs.ReadFile(standardLibrary, sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			file, err := syntax.Parse(sourcePath, source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(file.Stmts) == 0 {
				t.Fatal("module must begin with a non-empty docstring")
			}
			if _, ok := starlarkModuleDocstring(file.Stmts[0]); !ok {
				t.Fatal("module must begin with a non-empty docstring")
			}

			thread, _, err := newStarlarkRuntime("-")
			if err != nil {
				t.Fatal(err)
			}
			label := stdlibLabelForPath(modulePath)
			globals, err := thread.Load(thread, label)
			if err != nil {
				t.Fatal(err)
			}
			for name, value := range globals {
				function, ok := value.(*starlark.Function)
				if !ok || strings.HasPrefix(name, "_") || strings.HasPrefix(name, "test_") || strings.HasPrefix(name, "fixture_") {
					continue
				}
				if strings.TrimSpace(function.Doc()) == "" {
					t.Errorf("public function %s has no docstring", name)
				}
			}
		})
	}
}

func TestStarlarkSuites(t *testing.T) {
	thread, _, err := newStarlarkRuntime("test.star")
	if err != nil {
		t.Fatal(err)
	}
	module, err := thread.Load(thread, "//:test.star")
	if err != nil {
		t.Fatal(err)
	}
	main, ok := module["main"].(starlark.Callable)
	if !ok {
		t.Fatal("test.star does not export main")
	}
	if _, err := starlark.Call(thread, main, starlark.Tuple{starlark.Tuple{}}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestStandardLibraryDocumentation(t *testing.T) {
	documentation, err := standardLibraryDocumentation()
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile("docs/starlark/namespaces/reference.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, documentation) {
		t.Fatal("generated Starlark reference is stale; run trex -stdlib-docs")
	}
	for _, required := range []string{"### `help`", "help(value=None) -> None", "### `repl`", "repl() -> None", "### `block.nbd`", "### `binary.xml`", "### `binary.read_u32le`", "binary.read_u32le(source, offset=0) -> int", "### `binary.u32le`", "### `binary.builder` value", "patch_u32le(offset, value)", "### `binary.xml_node` value", "### `runtime.stats`", "runtime.stats() -> record", "report(minimum_coverage=0.95)", "### `vmm.start`", "### `debug.gdb`", "### `windows.kd`", "### `gdb` value", "with_register", "### `vm` value", "### `vmm_machine` value", "### `qemu_device` value", "write_u32le(address, value)"} {
		if !strings.Contains(string(documentation), required) {
			t.Errorf("generated reference omits %q", required)
		}
	}
}
