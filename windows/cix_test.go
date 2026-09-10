package windows

import (
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestContainerIndexTargetHashSelection(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	delta := `<Delta><Source type="RAW" name="payload"><Hash alg="SHA256" value="` + hash + `"/></Source></Delta>`
	xml := `<Container name="history" type="PSFX" version="2"><Files>` +
		`<File id="1" name="a" length="1"><Hash alg="SHA256" value="` + hash + `"/>` + delta + `</File>` +
		`<File id="2" name="b" length="1"><Hash alg="SHA256" value="` + hash + `"/>` + delta + `</File>` +
		`<File id="3" name="c" length="1"><Hash alg="SHA256" value="` + strings.Repeat("cd", 32) + `"/>` + delta + `</File>` +
		`</Files></Container>`
	for _, tc := range []struct {
		name   string
		kwargs []starlark.Tuple
		count  int
	}{
		{"no selectors", nil, 0},
		{"hash only", []starlark.Tuple{{starlark.String("target_hash"), starlark.String(strings.ToUpper(hash))}}, 2},
		{"narrow names", []starlark.Tuple{{starlark.String("target_hash"), starlark.String(hash)}, {starlark.String("names"), starlark.NewList([]starlark.Value{starlark.String("B"), starlark.String("c")})}}, 1},
		{"bounded", []starlark.Tuple{{starlark.String("target_hash"), starlark.String(hash)}, {starlark.String("limit"), starlark.MakeInt(1)}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := containerIndexBuiltin(nil, nil, starlark.Tuple{starlark.String(xml)}, tc.kwargs)
			if err != nil {
				t.Fatal(err)
			}
			files, err := got.(starlark.HasAttrs).Attr("files")
			if err != nil {
				t.Fatal(err)
			}
			if files.(*starlark.List).Len() != tc.count {
				t.Fatalf("files = %s, want %d", files, tc.count)
			}
		})
	}
	for _, hash := range []string{"00", strings.Repeat("xx", 32)} {
		if _, err := containerIndexBuiltin(nil, nil, starlark.Tuple{starlark.String(xml)}, []starlark.Tuple{{starlark.String("target_hash"), starlark.String(hash)}}); err == nil {
			t.Fatal("accepted malformed hash")
		}
	}
}
