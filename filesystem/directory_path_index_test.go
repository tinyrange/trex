package filesystem

import (
	"fmt"
	"go.starlark.net/starlark"
	"math/rand"
	"sort"
	"strings"
	"testing"
)

// Independent pre-index dictionary builder preserves the historical contract.
func (d *Directory) referencePathNames(lower, includeEmpty bool) (*starlark.Dict, error) {
	names := make(map[string]string, len(d.files)+len(d.dirs))
	names["/"] = "/"
	files := d.sortedFileNames()
	for _, name := range files {
		key := name
		if lower {
			key = strings.ToLower(key)
		}
		// names already contains every preceding file. Distinguish an actual
		// file from an implied parent using the existing namespace, instead
		// of constructing a second full-size collision table.
		if lower {
			if previous, found := names[key]; found && previous != name {
				if _, file := d.files[previous]; file {
					return nil, fmt.Errorf("path_names: ambiguous lowercase files %q and %q", previous, name)
				}
			}
		}
		names[key] = name
		for {
			end := strings.LastIndexByte(name, '/')
			if end <= 0 {
				break
			}
			name = name[:end]
			key = key[:strings.LastIndexByte(key, '/')]
			if _, found := names[key]; found {
				break
			}
			names[key] = name
		}
	}
	dirs := make([]string, 0, len(d.dirs))
	if includeEmpty {
		for name := range d.dirs {
			dirs = append(dirs, name)
		}
	}
	sort.Strings(dirs)
	for _, name := range dirs {
		key := name
		if lower {
			key = strings.ToLower(key)
		}
		if _, found := names[key]; !found {
			names[key] = name
		}
	}
	keys := make([]string, 0, len(names))
	for key := range names {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := starlark.NewDict(len(names))
	for _, key := range keys {
		if err := result.SetKey(starlark.String(key), starlark.String(names[key])); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func TestPathIndexReferenceAndEpochs(t *testing.T) {
	d := New()
	for _, name := range []string{"/A/child", "/a", "/Mixed/Deep/File", "/mixED/other", "/Ä/İ/File", "/AB/leaf", "/Parent/X/Deep", "/parent/x"} {
		d.PutFile(name, FileRecord{})
	}
	d.dirs["/EMPTY"] = struct{}{}
	d.dirs["/empty"] = struct{}{}
	for _, lower := range []bool{false, true} {
		for _, empty := range []bool{false, true} {
			p, err := d.pathIndex(lower, empty)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := d.referencePathNames(lower, empty)
			if err != nil {
				t.Fatal(err)
			}
			if p.keys != nil {
				t.Fatal("lookup eagerly sorted keys")
			}
			if p.Len() != ref.Len() {
				t.Fatal("length mismatch")
			}
			for _, item := range ref.Items() {
				got, found, err := p.Get(item[0])
				if err != nil || !found || got != item[1] {
					t.Fatalf("lookup %v: %v, %v", item[0], got, err)
				}
			}
			if p.keys != nil {
				t.Fatal("Get eagerly sorted keys")
			}
			if fmt.Sprint(p.Items()) != fmt.Sprint(ref.Items()) {
				t.Fatal("enumeration differs")
			}
			same, _ := d.pathIndex(lower, empty)
			if same != p {
				t.Fatal("snapshot not reused")
			}
			d.PutFile("/Mixed/Deep/File", FileRecord{Data: []byte("new"), Size: 3})
			same, _ = d.pathIndex(lower, empty)
			if same != p {
				t.Fatal("content update invalidated namespace")
			}
		}
	}
	old, _ := d.pathIndex(true, true)
	d.PutFile("/Fresh/name", FileRecord{})
	next, _ := d.pathIndex(true, true)
	if next == old {
		t.Fatal("namespace update reused stale snapshot")
	}
	if _, found, _ := old.Get(starlark.String("/fresh/name")); found {
		t.Fatal("old snapshot changed")
	}
	if _, found, _ := next.Get(starlark.String("/fresh/name")); !found {
		t.Fatal("new snapshot stale")
	}
	d.PutFile("/A", FileRecord{})
	if _, err := d.pathIndex(true, true); err == nil {
		t.Fatal("collision accepted")
	}
}
func TestPathIndexStarlark(t *testing.T) {
	d := New()
	d.PutFile("/Mixed/File", FileRecord{})
	_, err := starlark.ExecFile(&starlark.Thread{Name: "test"}, "index.star", `
def check():
    p = root.path_index(lower=True)
    assertions = [p["/mixed/file"] == "/Mixed/File", "/mixed" in p, len(p) == 3, p.get("missing") == None, p.get("missing", 7) == 7, dict(p) == root.path_names(lower=True), p.keys() == ["/", "/mixed", "/mixed/file"]]
    for ok in assertions:
        if not ok:
            fail("path index contract")
    a = p.keys()
    a.append("unrelated")
    if len(p.keys()) != 3:
        fail("enumeration aliases snapshot")
check()
`, starlark.StringDict{"root": d})
	if err != nil {
		t.Fatal(err)
	}
	_, err = starlark.ExecFile(&starlark.Thread{Name: "test"}, "immutable.star", `root.path_index()["new"] = "bad"`, starlark.StringDict{"root": d})
	if err == nil {
		t.Fatal("mutable index")
	}
}

func TestPathIndexRandomPrecedence(t *testing.T) {
	r := rand.New(rand.NewSource(901))
	parts := []string{"a", "A", "a-", "aa", "B", "b", "İ", "i", "Ä", "ä"}
	for sample := 0; sample < 300; sample++ {
		d := New()
		for n := 0; n < 70; n++ {
			name := ""
			for depth := r.Intn(5) + 1; depth > 0; depth-- {
				name += "/" + parts[r.Intn(len(parts))]
			}
			if r.Intn(3) == 0 {
				d.dirs[name] = struct{}{}
			} else {
				d.PutFile(name, FileRecord{})
			}
		}
		for _, lower := range []bool{false, true} {
			for _, empty := range []bool{false, true} {
				ref, re := d.referencePathNames(lower, empty)
				got, ge := d.pathIndex(lower, empty)
				if (re == nil) != (ge == nil) {
					t.Fatalf("sample %d errors %v / %v", sample, re, ge)
				}
				if re != nil {
					continue
				}
				if fmt.Sprint(ref.Items()) != fmt.Sprint(got.Items()) {
					t.Fatalf("sample %d lower=%v empty=%v\nreference=%v\nindex=%v", sample, lower, empty, ref.Items(), got.Items())
				}
			}
		}
	}
}
func BenchmarkPathIndex(b *testing.B) {
	d := New()
	for i := 0; i < 100000; i++ {
		d.PutFile(fmt.Sprintf("/Windows/WinSxS/Component%d/File%d.dll", i/20, i), FileRecord{})
	}
	b.Run("dictionary", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			d.referencePathNames(true, true)
		}
	})
	b.Run("index", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			d.buildPathIndex(true, true)
		}
	})
}
