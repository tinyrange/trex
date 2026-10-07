package native

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
)

func TestMirrorFileStarlarkValidationAndCacheRepair(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/bad" {
			_, _ = w.Write([]byte("bad payload"))
		} else {
			_, _ = w.Write([]byte("good payload"))
		}
	}))
	defer server.Close()
	thread := &starlark.Thread{Name: "mirror-validation"}
	resources := lifecycle.Install(thread)
	defer resources.Close()
	var seen []starlark.Value
	observe := starlark.NewBuiltin("observe", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		seen = append(seen, args[0])
		return starlark.None, nil
	})
	globals, err := starlark.ExecFile(thread, "validate.star", `
def validate(file):
    observe(file)
    if file.read() != "good payload":
        fail("invalid payload")
`, starlark.StringDict{"observe": observe})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	open := func(urls []string, validator starlark.Value) (*CachedFile, error) {
		values := make([]starlark.Value, len(urls))
		for i, url := range urls {
			values[i] = starlark.String(url)
		}
		value, err := mirrorFileBuiltin(thread, nil, starlark.Tuple{
			starlark.NewList(values), starlark.String(root), starlark.String("validation"),
		}, []starlark.Tuple{{starlark.String("validate"), validator}})
		if err != nil {
			return nil, err
		}
		return value.(*CachedFile), nil
	}
	file, err := open([]string{server.URL + "/bad", server.URL + "/good"}, globals["validate"])
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("validation did not select second mirror: %d", requests.Load())
	}
	borrowed := seen[0].(*validationFile)
	if _, err := borrowed.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("validation callback retained a live partial reader")
	}
	if _, err := open([]string{"http://127.0.0.1:1/offline"}, globals["validate"]); err != nil {
		t.Fatalf("new backend did not validate and reuse cache offline: %v", err)
	}
	if err := os.WriteFile(file.Name(), []byte("evil payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := open([]string{server.URL + "/good"}, globals["validate"]); err != nil {
		t.Fatalf("damaged object was not repaired: %v", err)
	}
	if requests.Load() != 3 {
		t.Fatalf("requests: %d, want 3", requests.Load())
	}
	if err := resources.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := file.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("cached file outlived runtime resources")
	}
}

func TestMirrorFileValidationRejectionIsNotPublished(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("payload"))
	}))
	defer server.Close()
	for _, value := range []string{"False", "True", "123", "'accepted'"} {
		t.Run(value, func(t *testing.T) {
			thread := &starlark.Thread{Name: "mirror-validation-return"}
			globals, err := starlark.ExecFile(thread, "validate.star", "def validate(file):\n    return "+value+"\n", nil)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			_, err = mirrorFileBuiltin(thread, nil, starlark.Tuple{
				starlark.NewList([]starlark.Value{starlark.String(server.URL)}),
				starlark.String(root), starlark.String("rejected"),
			}, []starlark.Tuple{{starlark.String("validate"), globals["validate"]}})
			if err == nil || !strings.Contains(err.Error(), "must return None") {
				t.Fatalf("ambiguous validator result accepted: %v", err)
			}
			objectID := mirrorObjectID(MirrorRequest{CacheKey: "rejected"}, nil)
			if _, err := os.Stat(filepath.Join(root, "objects", objectID[:2], objectID)); !os.IsNotExist(err) {
				t.Fatalf("rejected content published: %v", err)
			}
		})
	}
}
