package archiveweb

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func autoTestServer(data []byte, name string) (*webServer, *webNode) {
	s := &webServer{csrfToken: "test", nodes: make(map[string]*webNode), mounts: make(map[string]*webNode)}
	s.root = s.addNode(&webNode{Name: "Mountpoints", Path: "/", Kind: "dir"})
	source := s.addNode(&webNode{Name: name, Path: "/" + name, Kind: "file", file: adapter.File(bytes.NewReader(data))})
	s.root.Children = append(s.root.Children, source)
	return s, source
}

func requestAutoMount(s *webServer, id, format string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/mount?id="+id+"&format="+format, nil)
	r.Header.Set("X-Trex-CSRF", "test")
	w := httptest.NewRecorder()
	s.handleMount(w, r)
	return w
}

func TestAutoMountTarAndNestedZip(t *testing.T) {
	var inner bytes.Buffer
	zw := zip.NewWriter(&inner)
	f, err := zw.Create("payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("nested payload")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	var outer bytes.Buffer
	tw := tar.NewWriter(&outer)
	if err := tw.WriteHeader(&tar.Header{Name: "folder/nested.zip", Mode: 0600, Size: int64(inner.Len())}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(inner.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	s, source := autoTestServer(outer.Bytes(), "contents.bin")
	response := requestAutoMount(s, source.ID, "auto")
	if response.Code != http.StatusOK {
		t.Fatalf("mount: %d %s", response.Code, response.Body)
	}
	var result webTreeNode
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.MountedAs != "tar" || len(result.Children) != 1 || !result.Children[0].Lazy || len(result.Children[0].Children) != 0 {
		t.Fatalf("expected a detected tar with lazy folder: %+v", result)
	}
	folder := s.nodes[result.Children[0].ID]
	w := httptest.NewRecorder()
	s.handleChildren(w, httptest.NewRequest(http.MethodGet, "/api/children?id="+folder.ID, nil))
	if w.Code != http.StatusOK || len(folder.Children) != 1 || folder.Lazy {
		t.Fatalf("expand: %d %s", w.Code, w.Body)
	}
	nested := folder.Children[0]
	if nested.Name != "nested.zip" || nested.Path != "/contents.bin (tar)/folder/nested.zip" || nested.file == nil {
		t.Fatalf("nested file: %+v", nested)
	}
	response = requestAutoMount(s, nested.ID, "auto")
	if response.Code != http.StatusOK {
		t.Fatalf("nested mount: %d %s", response.Code, response.Body)
	}
	mount := s.mounts[nested.ID]
	if mount.MountedAs != "zip" || len(mount.Children) != 1 {
		t.Fatalf("nested mount: %+v", mount)
	}
	payload, err := io.ReadAll(io.NewSectionReader(mount.Children[0].file, 0, mount.Children[0].file.Size()))
	if err != nil || string(payload) != "nested payload" {
		t.Fatalf("payload: %q, %v", payload, err)
	}
	// Named and automatic requests reuse the same detected view.
	response = requestAutoMount(s, source.ID, "tar")
	if response.Code != http.StatusOK || len(s.mounts) != 2 {
		t.Fatalf("repeat mount: %d count=%d", response.Code, len(s.mounts))
	}
	response = requestAutoMount(s, source.ID, "zip")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("mismatched format: %d", response.Code)
	}
}

func TestWebAutoEntriesPreservesOccurrenceViewsAndLazyExpansion(t *testing.T) {
	// Record archives expose repeated paths as numbered occurrence views.
	calls := 0
	duplicate := auto.ViewFunc(func() ([]auto.Entry, error) {
		calls++
		return []auto.Entry{{Name: "1", Kind: "file", Reader: bytes.NewReader([]byte("first"))}, {Name: "2", Kind: "file", Reader: bytes.NewReader([]byte("second"))}}, nil
	})
	root := auto.FromView(auto.ViewFunc(func() ([]auto.Entry, error) {
		return []auto.Entry{{Name: "same", Kind: "directory", View: duplicate}}, nil
	}), "records", auto.Options{})
	entries, err := webAutoEntries(root, 0)
	if err != nil || len(entries) != 1 || calls != 0 {
		t.Fatalf("initial entries: %+v, calls=%d, %v", entries, calls, err)
	}
	s, _ := autoTestServer(nil, "source")
	s.addArchiveEntries(s.root, entries)
	var dir *webNode
	for _, node := range s.root.Children {
		if node.Name == "same" {
			dir = node
		}
	}
	if dir == nil {
		t.Fatal("missing occurrence directory")
	}
	if err := s.loadWebNodeChildren(dir); err != nil {
		t.Fatal(err)
	}
	if len(dir.Children) != 2 || calls != 1 {
		t.Fatalf("occurrences: %+v calls=%d", dir.Children, calls)
	}
	for i, want := range []string{"first", "second"} {
		data, _, err := readPreviewBytes(dir.Children[i].file)
		if err != nil || string(data) != want {
			t.Fatalf("occurrence %d: %q %v", i, data, err)
		}
	}
	if err := s.loadWebNodeChildren(dir); err != nil || calls != 1 {
		t.Fatalf("cached expansion: calls=%d %v", calls, err)
	}
	if _, err := webAutoEntries(root, 32); !errors.Is(err, auto.ErrLimit) {
		t.Fatalf("depth limit: %v", err)
	}
}

func TestAutoMountRejectsMalformedWithoutAddingNodes(t *testing.T) {
	s, source := autoTestServer([]byte("PK\x03\x04truncated zip"), "bad.zip")
	response := requestAutoMount(s, source.ID, "auto")
	if response.Code != http.StatusBadRequest || len(s.nodes) != 2 || len(s.mounts) != 0 {
		t.Fatalf("malformed mount: status=%d nodes=%d mounts=%d", response.Code, len(s.nodes), len(s.mounts))
	}
}

func TestAutoMountPreservesFileViewContext(t *testing.T) {
	for _, readable := range []bool{false, true} {
		name := "view only"
		var raw storage.Reader
		if readable {
			name, raw = "file and view", bytes.NewReader([]byte("plain data fork"))
		}
		t.Run(name, func(t *testing.T) {
			calls := 0
			forks := auto.ViewFunc(func() ([]auto.Entry, error) {
				calls++
				return []auto.Entry{{Name: "data", Kind: "file", Reader: bytes.NewReader([]byte("data"))}, {Name: "resource", Kind: "file", Reader: bytes.NewReader([]byte("resource"))}}, nil
			})
			root := auto.FromView(auto.ViewFunc(func() ([]auto.Entry, error) {
				return []auto.Entry{{Name: "forked", Kind: "file", Reader: raw, View: forks}}, nil
			}), "files", auto.Options{})
			entries, err := webAutoEntries(root, 0)
			if err != nil || calls != 0 {
				t.Fatalf("listing eagerly expanded file view: calls=%d, %v", calls, err)
			}
			s, _ := autoTestServer(nil, "source")
			s.addArchiveEntries(s.root, entries)
			var file *webNode
			for _, node := range s.root.Children {
				if node.Name == "forked" {
					file = node
				}
			}
			if file == nil {
				t.Fatal("file view missing")
			}
			if info := cloneWebTree(file); info.Readable != readable || !info.Browsable {
				t.Fatalf("readability or browsability does not match the original view: %+v", info)
			}
			response := requestAutoMount(s, file.ID, "auto")
			if response.Code != http.StatusOK {
				t.Fatalf("contextual mount: %d %s", response.Code, response.Body)
			}
			mount := s.mounts[file.ID]
			if len(mount.Children) != 2 || calls != 1 {
				t.Fatalf("file view: children=%d calls=%d", len(mount.Children), calls)
			}
			for _, child := range mount.Children {
				data, _, err := readPreviewBytes(child.file)
				if err != nil || string(data) != child.Name {
					t.Fatalf("fork %s: %q %v", child.Name, data, err)
				}
			}
			if readable {
				data, _, err := readPreviewBytes(file.file)
				if err != nil || string(data) != "plain data fork" {
					t.Fatalf("raw bytes lost: %q %v", data, err)
				}
			}
		})
	}
}

type previewStream struct {
	data       []byte
	readCalls  int
	maxRequest int
	readLimit  int64
}

func (*previewStream) Size() int64              { panic("preview must not scan an unknown stream for its length") }
func (*previewStream) KnownSize() (int64, bool) { return 0, false }
func (r *previewStream) ReadAt(p []byte, off int64) (int, error) {
	r.readCalls++
	r.maxRequest = max(r.maxRequest, len(p))
	limit := r.readLimit
	if limit == 0 {
		limit = webPreviewLimit + 1
	}
	if off < 0 || off+int64(len(p)) > limit {
		panic("preview exceeded its bounded prefix")
	}
	return bytes.NewReader(r.data).ReadAt(p, off)
}

func TestStructuredPreviewUnknownStreamAndKnownLimit(t *testing.T) {
	for _, mode := range []string{"inf", "hive"} {
		t.Run(mode, func(t *testing.T) {
			r := &previewStream{data: []byte("[Version]\nSignature=\"$Windows NT$\"\n"), readLimit: webStructuredPreviewLimit + 1}
			s, source := autoTestServer(nil, "stream")
			source.file = adapter.File(r)
			response := httptest.NewRecorder()
			s.handlePreview(response, httptest.NewRequest(http.MethodGet, "/api/preview?id="+source.ID+"&mode="+mode, nil))
			want := http.StatusOK
			if mode == "hive" {
				want = http.StatusBadRequest // Complete bounded input reaches the hive parser.
			}
			if response.Code != want || r.readCalls == 0 {
				t.Fatalf("preview: status=%d reads=%d %s", response.Code, r.readCalls, response.Body)
			}
			// A known oversize input is rejected before reading or parsing.
			r.readCalls = 0
			source.file = adapter.File(io.NewSectionReader(r, 0, webStructuredPreviewLimit+1))
			response = httptest.NewRecorder()
			s.handlePreview(response, httptest.NewRequest(http.MethodGet, "/api/preview?id="+source.ID+"&mode="+mode, nil))
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "structured preview exceeds") || r.readCalls != 0 {
				t.Fatalf("oversize preview: status=%d reads=%d %s", response.Code, r.readCalls, response.Body)
			}
		})
	}
}

type endlessPreviewStream struct{ lastEnd int64 }

func (*endlessPreviewStream) Size() int64              { panic("unknown structured preview requested its size") }
func (*endlessPreviewStream) KnownSize() (int64, bool) { return 0, false }
func (r *endlessPreviewStream) ReadAt(p []byte, off int64) (int, error) {
	if off != r.lastEnd || off+int64(len(p)) > webStructuredPreviewLimit+1 {
		panic("structured preview exceeded its bounded prefix")
	}
	r.lastEnd = off + int64(len(p))
	clear(p)
	return len(p), nil
}

func TestStructuredPreviewRejectsUnknownOversizeStream(t *testing.T) {
	r := &endlessPreviewStream{}
	file, err := structuredPreviewFile(adapter.File(r))
	if file != nil || err == nil || !strings.Contains(err.Error(), "structured preview exceeds") || r.lastEnd != webStructuredPreviewLimit+1 {
		t.Fatalf("oversize stream: file=%v err=%v bytes=%d", file, err, r.lastEnd)
	}
}

func TestPreviewUnknownStreamIsBounded(t *testing.T) {
	for _, length := range []int{0, 3, webPreviewLimit - 1, webPreviewLimit, webPreviewLimit + 1, 2 * webPreviewLimit} {
		r := &previewStream{data: bytes.Repeat([]byte("x"), length)}
		data, truncated, err := readPreviewBytes(adapter.File(r))
		if err != nil || !bytes.Equal(data, r.data[:min(length, webPreviewLimit)]) || truncated != (length > webPreviewLimit) {
			t.Fatalf("length %d: bytes=%d truncated=%v err=%v", length, len(data), truncated, err)
		}
		if r.readCalls != 1 || r.maxRequest > webPreviewLimit+1 {
			t.Fatalf("length %d: calls=%d maximum=%d", length, r.readCalls, r.maxRequest)
		}
	}
	for _, mode := range []string{"hex", "text", "utf16"} {
		t.Run(mode, func(t *testing.T) {
			data := bytes.Repeat([]byte{'A', 0}, webPreviewLimit)
			r := &previewStream{data: data}
			s, source := autoTestServer(nil, "stream")
			source.file = adapter.File(r)
			response := httptest.NewRecorder()
			s.handlePreview(response, httptest.NewRequest(http.MethodGet, "/api/preview?id="+source.ID+"&mode="+mode, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("preview: %d %s", response.Code, response.Body)
			}
			var result struct {
				Size      int64
				Truncated bool
				Content   string
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			want := string(data[:webPreviewLimit])
			if mode == "hex" {
				want = hex.Dump(data[:webPreviewLimit])
			} else if mode == "utf16" {
				want = strings.Repeat("A", webPreviewLimit/2)
			}
			if result.Size != -1 || !result.Truncated || result.Content != want || r.readCalls != 1 {
				t.Fatalf("preview metadata size=%d truncated=%v content bytes=%d calls=%d", result.Size, result.Truncated, len(result.Content), r.readCalls)
			}
		})
	}
}

func TestWebAutoEntriesPreserveNonReadableKinds(t *testing.T) {
	root := auto.FromView(auto.ViewFunc(func() ([]auto.Entry, error) {
		return []auto.Entry{
			{Name: "link", Kind: "symlink", Attributes: map[string]any{"link": "target"}},
			{Name: "device", Kind: "block-device"},
			{Name: "metadata", Kind: "file"},
		}, nil
	}), "special entries", auto.Options{})
	entries, err := webAutoEntries(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := autoTestServer(nil, "source")
	s.addArchiveEntries(s.root, entries)
	wants := map[string]string{"link": "symlink", "device": "block-device", "metadata": "file"}
	for _, node := range s.root.Children {
		kind, ok := wants[node.Name]
		if !ok {
			continue
		}
		info := cloneWebTree(node)
		if info.Kind != kind || info.Readable || info.Browsable || node.autoNode == nil {
			t.Fatalf("special entry lost its metadata or exposes an unusable action: %+v", info)
		}
		if node.Name == "link" && node.autoNode.Summary().Attributes["link"] != "target" {
			t.Fatal("symbolic link context was lost")
		}
		delete(wants, node.Name)
	}
	if len(wants) != 0 {
		t.Fatalf("missing entries: %v", wants)
	}
}
