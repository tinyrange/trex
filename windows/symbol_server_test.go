package windows

import (
	"go.starlark.net/starlark"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSymbolServerMissingIsExplicit(t *testing.T) {
	status := http.StatusNotFound
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer server.Close()
	args := starlark.Tuple{starlark.String(server.URL), starlark.String("image.pdb"), starlark.String("ABC1")}
	if _, err := windowsSymbolServerBuiltin(nil, nil, args, nil); err == nil {
		t.Fatal("default silently accepts 404")
	}
	kwargs := []starlark.Tuple{{starlark.String("missing_ok"), starlark.True}}
	value, err := windowsSymbolServerBuiltin(nil, nil, args, kwargs)
	if err != nil || value != starlark.None {
		t.Fatalf("missing result: %v %v", value, err)
	}
	status = http.StatusInternalServerError
	if _, err := windowsSymbolServerBuiltin(nil, nil, args, kwargs); err == nil {
		t.Fatal("server failure treated as missing symbols")
	}
}
