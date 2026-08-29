package starlarkfrontend

import (
	"strings"
	"testing"
)

func TestPublicNamespaces(t *testing.T) {
	environment := predeclared()
	for _, name := range []string{"archive", "binary", "block", "crypto", "debug", "filesystem", "firmware", "qemu", "vmm", "windows"} {
		if _, ok := environment[name]; !ok {
			t.Errorf("missing public namespace %q", name)
		}
	}
	for _, name := range []string{"compression", "container"} {
		if _, ok := environment[name]; ok {
			t.Errorf("legacy namespace %q remains public", name)
		}
	}
	windows := environment["windows"].(namespace)
	for _, name := range []string{"hive", "pe"} {
		if _, ok := windows.attrs[name]; !ok {
			t.Errorf("missing typed windows constructor %q", name)
		}
	}
	for _, name := range []string{"pe_exports", "pe_info", "pe_patch", "pe_resources"} {
		if _, ok := windows.attrs[name]; ok {
			t.Errorf("flat PE compatibility export %q remains public", name)
		}
	}
	thread, environment, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	_ = thread
	for name := range environment["windows"].(namespace).attrs {
		if strings.HasPrefix(name, "nt5_") {
			t.Errorf("NT5 compatibility export %q remains public", name)
		}
	}
}
