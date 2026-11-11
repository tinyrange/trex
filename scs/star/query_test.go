package script_test

import (
	"context"
	"strings"
	"testing"

	"github.com/tinyrange/trex/scs/repo"
	scsstar "github.com/tinyrange/trex/scs/star"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

func TestSourceControlQueryScript(t *testing.T) {
	globals, e := starlark.ExecFile(&starlark.Thread{}, "queries.star", `
r = scs.memory(max_bytes=8 * 1024 * 1024)
w = r.empty()
w.mkdir("src")
w.write_file("src/a", "old")
w.write_file("src/b", "old")
root = w.revision(author="agent", message="initial", task="task")
r.promote("main", expected="", next=root)
r.enable_indexed_refs()
changed = r.checkout_revision(root)
changed.write_file("src/a", "new")
next = changed.revision(parents=[root], message="edit")
page = changed.view().glob_page("src/**", limit=2)
history = r.path_history(next, "src/a", limit=1)
diff = w.diff(changed, prefix="src")
blame = r.blame(next, "src/a")
affected = w.affected_targets(changed, {"compile": ["src/**"], "docs": ["docs/**"]})
ancestor = r.is_ancestor(root, next)
bases = r.merge_bases(root, next)
r.promote("main", expected=root, next=next)
file = r.file()
r.close()
reopened = scs.memory(file)
metadata = reopened.revision(next)
read = reopened.checkout("main").read_file("src/a")
reopened.drop("main", expected=next)
reopened.clear_derived_indexes()
stats = reopened.operation_stats()
reopened.close()
`, starlark.StringDict{"scs": starlarkstruct.FromStringDict(starlark.String("scs"), scsstar.Builtins(nil, nil, nil))})
	if e != nil {
		t.Fatal(e)
	}
	if globals["read"] != starlark.String("new") || globals["ancestor"] != starlark.True {
		t.Fatal(globals)
	}
	if globals["blame"].(*starlark.List).Len() != 1 || globals["affected"].(*starlark.List).Len() != 1 {
		t.Fatal(globals)
	}
	diff := globals["diff"].(*starlark.List)
	if diff.Len() != 1 {
		t.Fatal(diff)
	}
	bases := globals["bases"].(*starlark.List)
	if bases.Len() != 1 || bases.Index(0) != globals["root"] {
		t.Fatal(bases)
	}
}
func TestNoPublishIncludesProvenance(t *testing.T) {
	r, e := repo.CreateOptimized(storage.NewMemoryStore(4 << 20))
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	e = scsstar.Run(context.Background(), r.Empty(), "denied.star", []byte(`workspace.revision(message="no")`), scsstar.Options{NoPublish: true})
	if e == nil || !strings.Contains(e.Error(), "controlled by the session host") {
		t.Fatal(e)
	}
}
