package archiveweb

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebListenAddressRequiresRemoteOptIn(t *testing.T) {
	got, err := webListenAddress(":8080", false)
	if err != nil || got != "127.0.0.1:8080" {
		t.Fatalf("default address = %q, %v", got, err)
	}
	if _, err := webListenAddress("192.0.2.1:8080", false); err == nil {
		t.Fatal("non-loopback address was accepted without remote opt-in")
	}
	got, err = webListenAddress("192.0.2.1:8080", true)
	if err != nil || got != "192.0.2.1:8080" {
		t.Fatalf("explicit remote address = %q, %v", got, err)
	}
}

func TestHostScanOmitsSymlinksAndUsesPinnedRoot(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "visible.bin"), []byte("visible"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("visible.bin", filepath.Join(directory, "alias.bin")); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	server := &webServer{rootFS: root, nodes: make(map[string]*webNode)}
	node := server.scanHostDir(".", "root", "/root")
	if len(node.Children) != 1 || node.Children[0].Name != "visible.bin" {
		t.Fatalf("children = %#v", node.Children)
	}
	if len(node.mountErrors) != 1 || !strings.Contains(node.mountErrors[0], "symbolic link omitted") {
		t.Fatalf("scan errors = %#v", node.mountErrors)
	}
	data := make([]byte, len("visible"))
	if _, err := node.Children[0].file.ReadAt(data, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(data) != "visible" {
		t.Fatalf("file data = %q", data)
	}
}

func TestMountRequiresRequestToken(t *testing.T) {
	server := &webServer{csrfToken: "expected"}
	request := httptest.NewRequest(http.MethodPost, "/api/mount?id=1&format=zip", nil)
	response := httptest.NewRecorder()
	server.handleMount(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestRemoteBrowserRequiresAccessToken(t *testing.T) {
	server := &webServer{remote: true, csrfToken: "expected"}
	handler := server.authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/?token=expected", nil))
	if login.Code != http.StatusSeeOther || len(login.Result().Cookies()) != 1 {
		t.Fatalf("login status = %d, cookies = %#v", login.Code, login.Result().Cookies())
	}

	authorizedRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	authorizedRequest.AddCookie(login.Result().Cookies()[0])
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusNoContent {
		t.Fatalf("authorized status = %d", authorized.Code)
	}
}

func TestArchiveEntryNodeCountIncludesImplicitDirectories(t *testing.T) {
	entries := []webArchiveEntry{
		{Name: "a/b/one.bin"},
		{Name: "a/c/two.bin"},
		{Name: "a/c", Dir: true},
	}
	if got, want := webArchiveEntryNodeCount(entries), 5; got != want {
		t.Fatalf("node count = %d, want %d", got, want)
	}
}
