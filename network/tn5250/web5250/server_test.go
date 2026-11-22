package web5250

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tinyrange/trex/network/tn5250"
)

// signOn applies a display with a user field and a nondisplay password
// field (the shape of an IBM i sign-on).
func signOn(t *testing.T) *tn5250.Terminal {
	t.Helper()
	body := []byte{4, 0x40, 4, 0x11, 0, 0, 0x11, 8, 46, 0x1d, 0x40, 0, 0x26, 0, 10}
	body = append(body, bytes.Repeat([]byte{0x40}, 10)...)
	body = append(body, 0x11, 9, 46, 0x1d, 0x40, 0, 0x27, 0, 33)
	body = append(body, bytes.Repeat([]byte{0x40}, 33)...)
	record := append([]byte{0, 0, 0x12, 0xa0, 0, 0, 4, 0, 0, 3}, body...)
	binary.BigEndian.PutUint16(record, uint16(len(record)))
	term := tn5250.New()
	if err := term.Apply(record); err != nil {
		t.Fatal(err)
	}
	return term
}

func TestServerPublishesScreensAndQueuesInput(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	s.Notes = "Sign on as QSECOFR"
	ts := httptest.NewServer(s)
	defer ts.Close()
	term := signOn(t)
	get := func(path string, token string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := get("/api/screen", "wrong"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("bad token: %d", r.StatusCode)
	}
	if r := get("/", ""); r.StatusCode != http.StatusOK || pageMentions(r, "QSECOFR") || !strings.Contains(r.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("page: %d %q", r.StatusCode, r.Header.Get("Content-Security-Policy"))
	}
	// A waiting viewer wakes on the first publish.
	done := make(chan screenJSON)
	go func() {
		r := get("/api/screen?after=0", s.Token)
		var got screenJSON
		_ = json.NewDecoder(r.Body).Decode(&got)
		done <- got
	}()
	time.Sleep(50 * time.Millisecond)
	s.Publish(term.Screen(), "running")
	got := <-done
	if got.Notes != "Sign on as QSECOFR" {
		t.Fatalf("notes %q", got.Notes)
	}
	if got.Version != 1 || got.Status != "running" || len(got.Fields) != 2 || !got.Fields[1].Hidden || got.Records != 1 || len(got.Attrs) != 2*1920 {
		t.Fatalf("screen %+v", got)
	}
	if out := s.snapshot(); out.Fields == nil {
		t.Fatal("fields must encode as a list")
	}
	empty, _ := json.Marshal((&Server{screen: tn5250.New().Screen()}).snapshot())
	if !strings.Contains(string(empty), `"fields":[]`) {
		t.Fatalf("a screen without input fields encodes %s", empty)
	}
	s.Publish(term.Screen(), "running") // unchanged: no new version
	if s.version != 1 {
		t.Fatalf("unchanged screen advanced the version to %d", s.version)
	}
	post := func(body, origin string) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/input", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+s.Token)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r.StatusCode
	}
	input := `{"records":1,"fields":{"0":"QSECOFR","1":"PW"},"row":8,"col":47,"key":"ENTER"}`
	if code := post(input, ""); code != http.StatusForbidden {
		t.Fatalf("missing origin: %d", code)
	}
	if code := post(input, "http://elsewhere.example"); code != http.StatusForbidden {
		t.Fatalf("cross-site origin: %d", code)
	}
	if code := post(`{"records":1,"key":"SHUTDOWN"}`, ts.URL); code != http.StatusBadRequest {
		t.Fatalf("unknown key: %d", code)
	}
	if code := post(input, ts.URL); code != http.StatusAccepted {
		t.Fatalf("input: %d", code)
	}
	if !s.Wait(time.Second) {
		t.Fatal("queued input did not end the wait")
	}
	pending := s.Pending()
	if s.Wait(10 * time.Millisecond) {
		t.Fatal("wait reported input after Pending drained it")
	}
	if len(pending) != 1 || pending[0].Fields[0] != "QSECOFR" || len(s.Pending()) != 0 {
		t.Fatalf("pending %+v", pending)
	}
	out, err := Apply(term, pending[0])
	if err != nil {
		t.Fatal(err)
	}
	// Cursor 8/47, Enter, then both modified fields.
	if !bytes.Equal(out[10:13], []byte{8, 47, 0xf1}) || !bytes.Contains(out, []byte{0x11, 8, 47, 0xd8, 0xe2}) || !bytes.Contains(out, []byte{0x11, 9, 47, 0xd7, 0xe6}) {
		t.Fatalf("input record %x", out)
	}
	if !strings.Contains(term.Screen().Rows[7], "QSECOFR") || strings.Contains(term.Screen().Rows[8], "PW") {
		t.Fatal("applied fields not shown as the terminal shows them")
	}
}

func TestApplyDiscardsStaleInputAndMapsKeys(t *testing.T) {
	term := signOn(t)
	if out, err := Apply(term, Input{Records: 0, Fields: map[int]string{0: "LATE"}, Key: "ENTER"}); out != nil || err != nil || term.Fields[0].Modified {
		t.Fatalf("stale input applied: %x %v", out, err)
	}
	if out, _ := Apply(term, Input{Records: 1, Key: "SYSREQ"}); !bytes.Equal(out, term.SystemRequest()) {
		t.Fatalf("system request %x", out)
	}
	if out, _ := Apply(term, Input{Records: 1, Key: "PF24"}); out[12] != 0xbc {
		t.Fatalf("PF24 aid %x", out[12])
	}
	if out, _ := Apply(term, Input{Records: 1, Key: "ROLLUP"}); out[12] != 0xf5 {
		t.Fatalf("roll up aid %x", out[12])
	}
	if _, err := Apply(term, Input{Records: 1, Fields: map[int]string{0: strings.Repeat("X", 11)}, Key: "ENTER"}); err == nil {
		t.Fatal("oversized field accepted")
	}
	if _, err := Apply(term, Input{Records: 1, Key: "NOPE"}); err == nil {
		t.Fatal("unknown key accepted")
	}
}

// pageMentions reports whether the static page contains text (notes must
// only travel through the authenticated API).
func pageMentions(r *http.Response, text string) bool {
	b, _ := io.ReadAll(r.Body)
	return strings.Contains(string(b), text)
}
