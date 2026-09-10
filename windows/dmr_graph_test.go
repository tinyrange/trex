package windows

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/dmr"
	"go.starlark.net/starlark"
	"testing"
)

func TestDMRGraphBuiltin(t *testing.T) {
	globals := Builtins()
	node := `{"name":"WinUI","publisher_id":"test","publisher":"CN=Test","full_name":"WinUI_1.0.0.0_x64__test","version":281474976710656,"architecture":9,"flags":17,"installation_path":"C:/Windows/SystemApps/WinUI","properties":{"minimum_version":123,"maximum_version_tested":456,"display_name":"ms-resource:DisplayName","logo":"logo.png"}}`
	v, err := starlark.Eval(&starlark.Thread{Name: "graph"}, "test.star", "dmr_graph(["+node+"])", globals)
	if err != nil {
		t.Fatal(err)
	}
	g, err := dmr.ParseGraph(v.(*starfile.Bytes).Data)
	if err != nil || len(g) != 1 {
		t.Fatalf("graph: %v", err)
	}
	if g[0].Identity.Flags != 17 || g[0].Properties.Value8 != 123 || g[0].Properties.Value16 != 456 || g[0].Properties.Strings[0] != "ms-resource:DisplayName" {
		t.Fatalf("node: %+v", g[0])
	}
	for _, expr := range []string{"dmr_graph([])", "dmr_graph([{}])", "dmr_graph([1])", "dmr_graph([" + node + "]*642)"} {
		if _, err := starlark.Eval(&starlark.Thread{Name: "bad-graph"}, "test.star", expr, globals); err == nil {
			t.Fatalf("accepted %s", expr)
		}
	}
}
