package web3270

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tinyrange/trex/emulator/s390"
)

// File transfers from the browser: the server sets up the display's DFT
// transfer and types the IND$FILE command where the cursor is, as a user
// of a terminal emulator's transfer dialog would.

const maxUpload = 64 << 20

type transferInfo struct {
	x         *s390.Transfer
	direction string
	dataset   string
	text      bool
	submit    bool
	submitted string // the SUBMIT outcome: "", "typed", or why not
}

// toCRLF ends every line with CR LF, as IND$FILE's CRLF option expects.
func toCRLF(b []byte) []byte {
	out := make([]byte, 0, len(b)+len(b)/32)
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			out = append(out, '\r')
		}
		out = append(out, c)
	}
	return out
}

// fromCRLF removes the carriage returns and end-of-file ^Z of a text
// download.
func fromCRLF(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c != '\r' && c != 0x1a {
			out = append(out, c)
		}
	}
	return out
}

type transfers struct {
	mu sync.Mutex
	by map[string]*transferInfo
}

var datasetName = regexp.MustCompile(`^[A-Za-z0-9@#$.'()+-/]{1,64}$`)
var transferOptions = regexp.MustCompile(`^[A-Za-z0-9(), ]{0,120}$`)

func (s *Server) transfer(w http.ResponseWriter, r *http.Request, sub string) {
	if !s.authorized(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
		http.Error(w, "invalid session token", http.StatusForbidden)
		return
	}
	var term *s390.WebTerminal
	for i := range s.terms {
		if strings.EqualFold(s.terms[i].Name, r.URL.Query().Get("terminal")) && s.terms[i].Display != nil {
			term = &s.terms[i]
		}
	}
	if term == nil {
		http.Error(w, "unknown 3270 terminal", http.StatusNotFound)
		return
	}
	s.xfer.mu.Lock()
	if s.xfer.by == nil {
		s.xfer.by = map[string]*transferInfo{}
	}
	info := s.xfer.by[term.Name]
	s.xfer.mu.Unlock()
	switch {
	case sub == "" && r.Method == http.MethodPost:
		if !s.validOrigin(r) {
			http.Error(w, "origin mismatch", http.StatusForbidden)
			return
		}
		s.startTransfer(w, r, term)
	case sub == "" && r.Method == http.MethodGet:
		status := map[string]any{"active": false}
		if info != nil {
			s.live.Do(func(*s390.Machine) {
				x := info.x
				status = map[string]any{"active": !x.Done, "direction": info.direction, "dataset": info.dataset,
					"records": x.Records, "bytes": x.Download.Len(), "uploaded": len(x.Upload), "done": x.Done,
					"failed": x.Failed, "message": x.Message, "submit": info.submit, "submitted": info.submitted}
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	case sub == "/data" && r.Method == http.MethodGet:
		if info == nil || info.direction != "get" {
			http.Error(w, "no download", http.StatusNotFound)
			return
		}
		var data []byte
		var done bool
		s.live.Do(func(*s390.Machine) { data, done = append([]byte(nil), info.x.Download.Bytes()...), info.x.Done })
		if info.text {
			data = fromCRLF(data)
		}
		if !done {
			http.Error(w, "the download is not complete", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)
	default:
		http.Error(w, "unsupported transfer request", http.StatusMethodNotAllowed)
	}
}

func (s *Server) startTransfer(w http.ResponseWriter, r *http.Request, term *s390.WebTerminal) {
	q := r.URL.Query()
	direction, dataset, mode, options := q.Get("direction"), strings.TrimSpace(q.Get("dataset")), q.Get("mode"), strings.TrimSpace(q.Get("options"))
	fail := func(code int, format string, args ...any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf(format, args...)})
	}
	if direction != "put" && direction != "get" {
		fail(http.StatusBadRequest, "direction must be put (upload) or get (download)")
		return
	}
	if !datasetName.MatchString(dataset) {
		fail(http.StatusBadRequest, "data set name %q is not valid", dataset)
		return
	}
	if !transferOptions.MatchString(options) {
		fail(http.StatusBadRequest, "options may hold only letters, digits, parentheses, commas and spaces")
		return
	}
	var upload []byte
	if direction == "put" {
		var err error
		upload, err = io.ReadAll(io.LimitReader(r.Body, maxUpload+1))
		if err != nil {
			fail(http.StatusBadRequest, "reading the upload: %v", err)
			return
		}
		if len(upload) > maxUpload {
			fail(http.StatusRequestEntityTooLarge, "uploads are limited to %d MB", maxUpload>>20)
			return
		}
	}
	cmd := "IND$FILE " + strings.ToUpper(direction) + " " + dataset
	text := mode != "binary"
	if text {
		cmd += " ASCII CRLF"
		upload = toCRLF(upload)
	}
	submit := q.Get("submit") == "1" && direction == "put"
	if submit && options == "" {
		options = "RECFM(F) LRECL(80) BLKSIZE(80)" // card-image JCL
	}
	if options != "" {
		cmd += " " + strings.ToUpper(options)
	}
	x := &s390.Transfer{Upload: upload}
	var err error
	s.live.Do(func(*s390.Machine) {
		t := term.Display
		switch {
		case t.Remote():
			err = fmt.Errorf("a tn3270 client is attached to %s: use its file transfer", term.Name)
		case t.Locked():
			err = fmt.Errorf("%s is busy: wait for the keyboard to be restored", term.Name)
		case t.TransferState() != nil && !t.TransferState().Done:
			err = fmt.Errorf("a transfer is already in progress on %s", term.Name)
		default:
			t.Key("ERASEEOF")
			if err = t.Type(cmd); err != nil {
				err = fmt.Errorf("put the cursor on a TSO command line (READY) first")
				return
			}
			t.SetTransfer(x)
			err = t.Key("ENTER")
		}
	})
	if err != nil {
		fail(http.StatusConflict, "%s", err)
		return
	}
	info := &transferInfo{x: x, direction: direction, dataset: dataset, text: text, submit: submit}
	s.xfer.mu.Lock()
	s.xfer.by[term.Name] = info
	s.xfer.mu.Unlock()
	if submit {
		go s.submitAfter(term, info)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"command": cmd})
}

// submitAfter types SUBMIT for an uploaded job once the transfer has
// completed and TSO has restored the keyboard.
func (s *Server) submitAfter(term *s390.WebTerminal, info *transferInfo) {
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		var done bool
		s.live.Do(func(*s390.Machine) {
			t, x := term.Display, info.x
			if !x.Done {
				return
			}
			done = true
			if x.Failed {
				info.submitted = "not submitted: the upload failed"
				return
			}
			if t.Locked() {
				done = false
				return
			}
			t.Key("ERASEEOF")
			if err := t.Type("SUBMIT " + info.dataset); err != nil {
				info.submitted = "not submitted: the cursor is not on a command line"
				return
			}
			t.Key("ENTER")
			info.submitted = "typed"
		})
		if done {
			return
		}
	}
	s.live.Do(func(*s390.Machine) { info.submitted = "not submitted: the transfer did not finish" })
}
