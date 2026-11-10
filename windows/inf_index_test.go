package windows

import (
	"fmt"
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestINFIndexedSectionsPreserveFoldAndSourceOrder(t *testing.T) {
	root, directives, err := parseINFDirectives("[S]\nA=1\n[ſ]\nB=2\n[Σ]\nC=3\n[ς]\nD=4\n")
	if err != nil {
		t.Fatal(err)
	}
	if root.Len() != 2 || directives.Len() != 8 {
		t.Fatalf("sections=%d directives=%d", root.Len(), directives.Len())
	}
	for _, name := range []string{"s", "S", "ſ", "Σ", "σ", "ς"} {
		section, ok, err := infSection(root, name)
		if err != nil || !ok || section.Len() != 2 {
			t.Fatalf("%q: %v %v", name, section, err)
		}
	}
	// The exact raw spelling of every repeated section is retained.
	for i, name := range []string{"S", "ſ", "Σ", "ς"} {
		if got := directives.Index(i * 2).(starlark.Tuple)[0]; got != starlark.String(name) {
			t.Fatal(got)
		}
	}
	// Do not accidentally make the parse-local index authoritative after a
	// caller changes the exposed JSON namespace.
	root.Delete(starlark.String("S"))
	if _, ok, err := infSection(root, "ſ"); err != nil || ok {
		t.Fatal("stale parsed section")
	}
}

func BenchmarkINFManySections(b *testing.B) {
	var input strings.Builder
	for i := 0; i < 4000; i++ {
		fmt.Fprintf(&input, "[Driver.Section%d]\nValue=%d\n", i, i)
	}
	source := input.String()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := parseINFDirectives(source); err != nil {
			b.Fatal(err)
		}
	}
}
