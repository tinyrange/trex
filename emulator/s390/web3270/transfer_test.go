package web3270

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinyrange/trex/emulator/s390"
)

func ddmField(req uint16, body []byte) []byte {
	sf := append([]byte{0, 0, 0xd0, byte(req >> 8), byte(req)}, body...)
	sf[0], sf[1] = byte(len(sf)>>8), byte(len(sf))
	return sf
}

func openField(name string) []byte {
	body := make([]byte, 30)
	copy(body[23:], name+"       ")
	return ddmField(0x0012, body)
}

func insertField(data string) []byte {
	return ddmField(0x4704, append([]byte{0xc0, 0x80, 0x61, byte((len(data) + 5) >> 8), byte(len(data) + 5)}, data...))
}

func TestTransferAPI(t *testing.T) {
	m := s390.NewMachine(s390.Config{Memory: 1 << 20, CPUs: 1, MIPS: 50})
	con := s390.NewConsole3270(24, 80)
	m.CSS.AttachConsole(0x0701, con)
	live := s390.NewLive(m, con)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go live.Run(ctx)
	srv0, _ := New(live, []s390.WebTerminal{{Name: "0701", Device: 0x0701, Display: con}})
	srv := httptest.NewServer(srv0)
	defer srv.Close()
	call := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+srv0.Token)
		req.Header.Set("Origin", srv.URL)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	// host performs a WRITE STRUCTURED FIELD and reads the reply.
	host := func(sf []byte) []byte {
		var out []byte
		live.Do(func(*s390.Machine) {
			con.Exec(0x11, sf, false)
			out, _, _ = con.Exec(0x06, nil, false)
		})
		return out
	}
	restore := func() { live.Do(func(*s390.Machine) { con.Exec(0x01, []byte{0xc2}, false); con.SetCursor(0, 0) }) }

	// Upload: the command is typed at the cursor and LF becomes CR LF.
	code, body := call("POST", "/api/transfer?terminal=0701&direction=put&dataset=MY.TEXT&mode=text", "one\ntwo\n")
	if code != 200 || !strings.Contains(body, "IND$FILE PUT MY.TEXT ASCII CRLF") {
		t.Fatalf("start upload: %d %s", code, body)
	}
	var screen string
	live.Do(func(*s390.Machine) { screen = con.Screen().Text })
	if !strings.HasPrefix(screen, "IND$FILE PUT MY.TEXT ASCII CRLF") {
		t.Fatalf("command not typed: %q", screen[:40])
	}
	if code, _ := call("POST", "/api/transfer?terminal=0701&direction=put&dataset=X&mode=text", "x"); code != http.StatusConflict {
		t.Fatalf("second transfer while the first runs: %d", code)
	}
	host(openField("FT:DATA"))
	if r := host(ddmField(0x4611, nil)); string(r[17:]) != "one\r\ntwo\r\n" {
		t.Fatalf("uploaded %q", r[17:])
	}
	host(ddmField(0x4611, nil))
	host(ddmField(0x4112, nil))
	host(openField("FT:MSG"))
	host(insertField("TRANS03 File transfer complete$"))
	_, body = call("GET", "/api/transfer?terminal=0701", "")
	var st map[string]any
	json.Unmarshal([]byte(body), &st)
	if st["done"] != true || st["failed"] != false || st["message"] != "TRANS03 File transfer complete" {
		t.Fatalf("status %s", body)
	}

	// Download: CR LF and the ^Z are removed from text.
	restore()
	if code, body := call("POST", "/api/transfer?terminal=0701&direction=get&dataset=MY.TEXT&mode=text", ""); code != 200 {
		t.Fatalf("start download: %d %s", code, body)
	}
	if code, _ := call("GET", "/api/transfer/data?terminal=0701", ""); code != http.StatusConflict {
		t.Fatalf("data before completion: %d", code)
	}
	host(openField("FT:DATA"))
	host(insertField("one\r\ntwo\r\n\x1a"))
	host(ddmField(0x4112, nil))
	host(openField("FT:MSG"))
	host(insertField("TRANS03 File transfer complete$"))
	if code, data := call("GET", "/api/transfer/data?terminal=0701", ""); code != 200 || data != "one\ntwo\n" {
		t.Fatalf("download %d %q", code, data)
	}
	if code, _ := call("POST", "/api/transfer?terminal=0701&direction=put&dataset=BAD;NAME&mode=text", ""); code != http.StatusBadRequest {
		t.Fatalf("bad data set name accepted: %d", code)
	}
}
