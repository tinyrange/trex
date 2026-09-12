package starlarkfrontend

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAutoRecursiveHTTP(t *testing.T) {
	var packed bytes.Buffer
	z := zip.NewWriter(&packed)
	w, _ := z.Create("test.txt")
	w.Write([]byte("nested payload"))
	z.Close()
	var stream bytes.Buffer
	g := gzip.NewWriter(&stream)
	tw := tar.NewWriter(g)
	tw.WriteHeader(&tar.Header{Name: "etc/blah.zip", Size: int64(packed.Len()), Mode: 0644})
	tw.Write(packed.Bytes())
	tw.Close()
	g.Close()
	app := testStarlarkWebApplication(t, fmt.Sprintf(`
source = directory()
source.write("blah.tar.gz", b%q)
root = auto(source)
def handle(request):
    return web.browse(root, request)
`, stream.Bytes()))
	for _, test := range []struct {
		target, method, rang string
		status               int
		want                 string
	}{
		{"/blah.tar.gz/etc/blah.zip/test.txt?json=1", "GET", "", 200, "test.txt"},
		{"/blah.tar.gz/etc/blah.zip/test.txt?raw=1", "GET", "bytes=7-13", 206, "payload"},
		{"/blah.tar.gz/etc/blah.zip/test.txt?raw=1", "HEAD", "", 200, ""},
		{"/blah.tar.gz/etc/missing?json=1", "GET", "", 404, "error"},
		{"/blah.tar.gz/etc/../test?json=1", "GET", "", 400, "error"},
		{"/?json=1&limit=0", "GET", "", 400, "error"},
		{"/?json=1", "POST", "", 405, "error"},
	} {
		req := httptest.NewRequest(test.method, test.target, nil)
		if test.rang != "" {
			req.Header.Set("Range", test.rang)
		}
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		if rec.Code != test.status || !bytes.Contains(rec.Body.Bytes(), []byte(test.want)) {
			t.Fatalf("%s: %d %s", test.target, rec.Code, rec.Body.String())
		}
		if test.rang != "" && rec.Header().Get("Content-Range") != "bytes 7-13/14" {
			t.Fatal(rec.Header())
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/?json=1&limit=1", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	var data struct {
		Children []struct{ Name string }
		Total    int
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil || data.Total != 1 || len(data.Children) != 1 {
		t.Fatalf("listing %s %v", rec.Body, err)
	}
}

func TestAutoByteViewAndDisk(t *testing.T) {
	app := testStarlarkWebApplication(t, `
d = directory()
d.mkdir("empty")
d.write("hello.txt", "hello disk")
volume = filesystem.fat16(d, size=16 << 20)
root = auto(binary.view(volume), name="disk.img")
def handle(request):
    if root.metadata["format"] != "fat":
        fail("FAT not detected")
    if root["hello.txt"].file.bytes() != b"hello disk":
        fail("file view differs")
    return web.browse(root, request)
`)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest("GET", "/hello.txt?json=1", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
}

func TestAutoPartitionedDisk(t *testing.T) {
	app := testStarlarkWebApplication(t, `
d = directory()
d.write("hello.txt", "partition payload")
disk = filesystem.mbr(20 << 20).partition(filesystem.fat16(d, size=16 << 20), type=6, start_lba=63)
root = auto(disk)
def handle(request):
    return web.browse(root, request)
`)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest("GET", "/partition1/hello.txt?raw=1", nil))
	if rec.Code != 200 || rec.Body.String() != "partition payload" {
		t.Fatal(rec.Code, rec.Body.String())
	}
}
