package starlarkfrontend

import (
	"bytes"
	"strings"
	"testing"
)

func TestNativeDocumentationRequiresDescriptions(t *testing.T) {
	if _, err := nativeStarlarkDescription("missing.operation"); err == nil {
		t.Fatal("undocumented operations must fail rather than generate boilerplate")
	}
	var output bytes.Buffer
	if err := writeNativeStarlarkDocumentation(&output); err != nil {
		t.Fatal(err)
	}
	for _, placeholder := range []string{"Native top-level operation.", "Limits and timeout arguments are validated before work begins.", "(...)`"} {
		if strings.Contains(output.String(), placeholder) {
			t.Errorf("reference contains placeholder %q", placeholder)
		}
	}
}

func TestScalarDocumentationDescribesEncoding(t *testing.T) {
	for name, words := range map[string][]string{
		"binary.u32le":      {"32-bit", "unsigned", "little-endian", "4 bytes"},
		"binary.read_i16be": {"16-bit", "signed", "big-endian", "offset"},
		"binary.f64le":      {"64-bit", "IEEE-754", "8 bytes"},
	} {
		description, err := nativeStarlarkDescription(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, word := range words {
			if !strings.Contains(description, word) {
				t.Errorf("%s omits %q: %s", name, word, description)
			}
		}
	}
}
