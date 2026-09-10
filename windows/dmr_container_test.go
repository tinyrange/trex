package windows

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/dmr"
	"go.starlark.net/starlark"
	"testing"
)

func TestDMRContainerBuiltins(t *testing.T) {
	expr := `dmr_container([dmr_alternate_path("C:/A;C:/B"),dmr_alternate_path("C:/A",first_package_family=True),dmr_mutable_paths(["", "C:/Mutable"]),dmr_trailer()])`
	v, err := starlark.Eval(&starlark.Thread{Name: "container"}, "test.star", expr, Builtins())
	if err != nil {
		t.Fatal(err)
	}
	s, err := dmr.ParseContainer(v.(*starfile.Bytes).Data)
	if err != nil || len(s) != 4 {
		t.Fatalf("container: %v", err)
	}
	for i, want := range []string{"C:/A;C:/B", "C:/A"} {
		path, family, err := dmr.ParseAlternatePath(s[i].Data)
		if err != nil || path != want || family != (i == 1) {
			t.Fatalf("path %q %v %v", path, family, err)
		}
	}
	paths, err := dmr.ParseMutablePaths(s[2].Data)
	if err != nil || len(paths) != 2 || paths[0] != "" || paths[1] != "C:/Mutable" {
		t.Fatalf("paths %v %v", paths, err)
	}
	if err := dmr.ParseTrailer(s[3].Data); err != nil {
		t.Fatal(err)
	}
}

func TestDMRContainerBuiltinBounds(t *testing.T) {
	for _, expr := range []string{
		"dmr_container([])", "dmr_container([1])", "dmr_container([dmr_trailer()]*8193)",
		"dmr_container([dmr_trailer()],max_bytes=43)", "dmr_container([dmr_trailer()],max_bytes=-1)",
		"dmr_mutable_paths([])", "dmr_mutable_paths(['']*642)", "dmr_mutable_paths([1])", "dmr_trailer(1)",
	} {
		if _, err := starlark.Eval(&starlark.Thread{Name: "bad-container"}, "test.star", expr, Builtins()); err == nil {
			t.Fatalf("accepted %s", expr)
		}
	}
	if _, err := starlark.Eval(&starlark.Thread{Name: "exact-limit"}, "test.star", "dmr_container([dmr_trailer()],max_bytes=44)", Builtins()); err != nil {
		t.Fatal(err)
	}
}
