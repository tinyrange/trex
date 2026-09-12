package starlarkfrontend

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http/httptest"
	"testing"
)

func TestLegacyAutoHTTP(t *testing.T) {
	// A native standalone tape directory containing another tape directory.
	tape := func(name string, payload []byte) []byte {
		b := make([]byte, 512+len(payload))
		be := binary.BigEndian
		be.PutUint32(b, 0xaced1234)
		copy(b[32:48], name)
		be.PutUint32(b[48:], 1)
		be.PutUint32(b[52:], uint32(len(payload)))
		var sum uint32
		for off := 0; off < 512; off += 4 {
			sum += be.Uint32(b[off:])
		}
		be.PutUint32(b[4:], -sum)
		copy(b[512:], payload)
		return b
	}
	source := tape("inner", tape("hello", []byte("native payload")))
	app := testStarlarkWebApplication(t, fmt.Sprintf(`
root = auto(b%q)
def handle(request):
    return web.browse(root, request)
`, source))
	for _, test := range []struct {
		path, want string
		status     int
	}{
		{"/?json=1", "irix_tape", 200},
		{"/inner?json=1", "hello", 200},
		{"/inner/hello?raw=1", "native payload", 200},
		{"/inner/missing?json=1", "error", 404},
	} {
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, httptest.NewRequest("GET", test.path, nil))
		if rec.Code != test.status || !bytes.Contains(rec.Body.Bytes(), []byte(test.want)) {
			t.Fatal(test.path, rec.Code, rec.Body.String())
		}
	}
	source[4] ^= 1
	bad := testStarlarkWebApplication(t, fmt.Sprintf(`
root = auto(b%q)
def handle(request):
    return web.browse(root, request)
`, source))
	rec := httptest.NewRecorder()
	bad.ServeHTTP(rec, httptest.NewRequest("GET", "/?json=1", nil))
	if rec.Code != 422 || !bytes.Contains(rec.Body.Bytes(), []byte("checksum")) {
		t.Fatal(rec.Code, rec.Body.String())
	}
}
