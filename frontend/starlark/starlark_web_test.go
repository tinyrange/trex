package starlarkfrontend

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	filesystemnative "github.com/tinyrange/trex/filesystem/native"
	starfile "github.com/tinyrange/trex/storage/star"
	webstar "github.com/tinyrange/trex/web/star"
	"go.starlark.net/starlark"
)

func testStarlarkWebApplication(t *testing.T, source string) *webstar.Application {
	t.Helper()
	thread, environment, err := newStarlarkRuntime("web_test.star")
	if err != nil {
		t.Fatal(err)
	}
	resources, err := resourcesForThread(thread)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resources.Close() })
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, "web_test.star", source, environment)
	if err != nil {
		t.Fatal(err)
	}
	handler, ok := globals["handle"].(starlark.Callable)
	if !ok {
		t.Fatal("test script has no handle function")
	}
	return webstar.NewApplication(thread, handler)
}

func TestStarlarkWebApplicationReceivesRequest(t *testing.T) {
	application := testStarlarkWebApplication(t, `
def handle(request):
    return web.response(
        request.method + " " + request.path + " " + request.query.get("q", "") + " " + request.cookies.get("disk", ""),
        status = 201,
        headers = {"Content-Type": "text/plain", "X-Application": "starlark"},
    )
`)
	request := httptest.NewRequest(http.MethodGet, "/items/New%20Name?q=search", nil)
	request.AddCookie(&http.Cookie{Name: "disk", Value: "disc-1"})
	recorder := httptest.NewRecorder()
	application.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("X-Application"); got != "starlark" {
		t.Fatalf("X-Application = %q", got)
	}
	if got := recorder.Body.String(); got != "GET /items/New Name search disc-1" {
		t.Fatalf("body = %q", got)
	}
}

func TestHostFilesystemAndZIPResponse(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "Folder"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "Folder", "Example.txt"), []byte("archive data"), 0644); err != nil {
		t.Fatal(err)
	}
	value, err := filesystemnative.HostBuiltin(nil, nil, starlark.Tuple{starlark.String(root)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	filesystem := value.(starlark.Mapping)
	fileValue, found, err := filesystem.Get(starlark.String("/folder/example.TXT"))
	if err != nil || !found {
		t.Fatalf("case-insensitive lookup = %v, %v", found, err)
	}
	data, err := starfile.ReadAll(fileValue.(starfile.File))
	if err != nil || string(data) != "archive data" {
		t.Fatalf("file data = %q, %v", data, err)
	}

	recorder := httptest.NewRecorder()
	if err := webstar.WriteZIP(recorder, filesystem, "/Folder"); err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(recorder.Body.Bytes()), int64(recorder.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.File) != 1 || archive.File[0].Name != "Example.txt" {
		t.Fatalf("ZIP entries = %#v", archive.File)
	}
	reader, err := archive.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	zipped, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(zipped) != "archive data" {
		t.Fatalf("ZIP data = %q, %v", zipped, err)
	}
}

func TestStarlarkRegexpCapturesOffsets(t *testing.T) {
	value, err := regexpCompileBuiltin(nil, nil, starlark.Tuple{starlark.String(`(?i)<b>(.*?)</b>`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := value.(*starlarkRegexp).findAllBuiltin(nil, nil, starlark.Tuple{starlark.String("x<B>Name</B>y")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	list := result.(*starlark.List)
	if list.Len() != 1 {
		t.Fatalf("matches = %d", list.Len())
	}
	match := list.Index(0).(starlark.HasAttrs)
	groups, _ := match.Attr("groups")
	if got, _ := starlark.AsString(groups.(*starlark.List).Index(0)); got != "Name" {
		t.Fatalf("capture = %q", got)
	}
}
