package star

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestRequestLogging(t *testing.T) {
	for _, fail := range []bool{false, true} {
		var output bytes.Buffer
		app := NewApplication(&starlark.Thread{}, starlark.NewBuiltin("handle", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			if fail {
				return nil, errors.New("test failure")
			}
			return starlark.String("hello"), nil
		}))
		app.RequestLogger = slog.New(slog.NewJSONHandler(&output, nil))
		recorder := httptest.NewRecorder()
		app.ServeHTTP(recorder, httptest.NewRequest("GET", "/a%20b?json=1&token=secret", nil))
		lines := strings.Split(strings.TrimSpace(output.String()), "\n")
		if len(lines) != 2 {
			t.Fatal(output.String())
		}
		var start, end map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &start); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(lines[1]), &end); err != nil {
			t.Fatal(err)
		}
		want := 200
		if fail {
			want = 500
		}
		if start["msg"] != "http.request.start" || end["msg"] != "http.request.end" || start["request_id"] != end["request_id"] || end["status"] != float64(want) || end["bytes"] != float64(recorder.Body.Len()) || end["path"] != "/a b" || end["json"] != "1" {
			t.Fatal(output.String())
		}
		if strings.Contains(output.String(), "secret") {
			t.Fatal("logged credentials")
		}
		for _, key := range []string{"duration_ms", "queue_ms", "handler_ms", "stream_ms"} {
			v, ok := end[key].(float64)
			if !ok || v < 0 || v > end["duration_ms"].(float64) {
				t.Fatalf("invalid timing %s: %v", key, end)
			}
		}
	}
}

func TestRequestWriterStatusAndErrors(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &requestWriter{ResponseWriter: rec}
	w.WriteHeader(http.StatusPartialContent)
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("abc"))
	if w.status != 206 || w.bytes != 3 || rec.Code != 206 || w.Unwrap() != rec {
		t.Fatal(w)
	}
}
