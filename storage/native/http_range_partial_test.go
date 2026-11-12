package native

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestHTTPRangeContinuesTruncatedResponseWithinAttemptBudget(t *testing.T) {
	payload := []byte("abcdefgh")
	var starts []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var start, end int
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		starts = append(starts, start)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload)))
		w.Header().Set("Content-Length", fmt.Sprint(end-start+1))
		w.WriteHeader(http.StatusPartialContent)
		limit := 4
		if len(starts) > 1 {
			limit = 2
		}
		n := min(end-start+1, limit)
		w.Write(payload[start : start+n])
	}))
	defer server.Close()
	file, err := NewHTTPRangeFile("partial", []string{server.URL}, 8, 8, 8, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(file, 0, 8))
	if err != nil || string(got) != string(payload) {
		t.Fatalf("continuation = %q, %v; starts=%v", got, err, starts)
	}
	if !reflect.DeepEqual(starts, []int{0, 4, 6}) {
		t.Fatalf("discarded validated prefix or exceeded budget: %v", starts)
	}
	if _, err := file.ReadAt(make([]byte, 8), 0); err != nil {
		t.Fatal(err)
	}
	if len(starts) != httpRangeAttempts {
		t.Fatal("completed chunk was not cached")
	}
}

func TestHTTPRangeNeverCachesIncompleteChunk(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var start, end int
		fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/8", start, end))
		w.Header().Set("Content-Length", fmt.Sprint(end-start+1))
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte{'x'})
	}))
	defer server.Close()
	file, err := NewHTTPRangeFile("incomplete", []string{server.URL}, 8, 8, 8, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for read := 0; read < 2; read++ {
		if n, err := file.ReadAt(make([]byte, 8), 0); err == nil || n != 0 {
			t.Fatalf("partial chunk published: %d, %v", n, err)
		}
		if calls != (read+1)*httpRangeAttempts {
			t.Fatalf("unbounded or cached failed read: %d", calls)
		}
	}
}

func TestHTTPRangeContinuationRejectsChangedRangeMetadata(t *testing.T) {
	for _, mode := range []string{"start", "total", "status"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var start, end int
				fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end)
				declaredStart, total, status := start, 8, http.StatusPartialContent
				if calls > 1 {
					switch mode {
					case "start":
						declaredStart = 0
					case "total":
						total = 9
					case "status":
						status = http.StatusOK
					}
				}
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", declaredStart, end, total))
				w.Header().Set("Content-Length", fmt.Sprint(end-start+1))
				w.WriteHeader(status)
				if calls == 1 {
					w.Write([]byte("abcd"))
				} else {
					w.Write([]byte("efgh"))
				}
			}))
			defer server.Close()
			file, err := NewHTTPRangeFile("changed", []string{server.URL}, 8, 8, 8, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if n, err := file.ReadAt(make([]byte, 8), 0); err == nil || n != 0 {
				t.Fatalf("accepted changed continuation: n=%d,err=%v", n, err)
			}
			if calls != httpRangeAttempts {
				t.Fatalf("wrong request bound: %d", calls)
			}
		})
	}
}
