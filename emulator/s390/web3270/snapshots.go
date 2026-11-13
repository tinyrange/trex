package web3270

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// SnapshotInfo describes one named snapshot of the machine.
type SnapshotInfo struct {
	Name  string    `json:"name"`
	Bytes int64     `json:"bytes"`
	Saved time.Time `json:"saved"`
}

// Snapshots keeps named machine snapshots. The native frontend implements
// it over files; Restore loads a snapshot into the running machine.
type Snapshots interface {
	List() ([]SnapshotInfo, error)
	Save(name string) error
	Restore(name string) error
	Delete(name string) error
}

// SnapshotName is the form of a snapshot name.
var SnapshotName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,47}$`)

func (s *Server) snapshots(w http.ResponseWriter, r *http.Request, sub string) {
	if !s.authorized(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
		http.Error(w, "invalid session token", http.StatusForbidden)
		return
	}
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	if s.Snaps == nil {
		reply(http.StatusNotFound, map[string]string{"error": "this machine has no state file, so it keeps no snapshots"})
		return
	}
	if r.Method == http.MethodGet && sub == "" {
		list, err := s.Snaps.List()
		if err != nil {
			reply(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if list == nil {
			list = []SnapshotInfo{}
		}
		reply(http.StatusOK, map[string]any{"snapshots": list})
		return
	}
	if r.Method != http.MethodPost {
		reply(http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	if !s.validOrigin(r) {
		reply(http.StatusForbidden, map[string]string{"error": "origin mismatch"})
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if !SnapshotName.MatchString(name) {
		reply(http.StatusBadRequest, map[string]string{"error": "a snapshot name is 1-48 letters, digits, spaces, dots, dashes or underscores"})
		return
	}
	if !s.saving.CompareAndSwap(false, true) {
		reply(http.StatusConflict, map[string]string{"error": "a save or restore is already in progress"})
		return
	}
	defer s.saving.Store(false)
	began := time.Now()
	var err error
	switch sub {
	case "/save":
		err = s.Snaps.Save(name)
	case "/restore":
		err = s.Snaps.Restore(name)
	case "/delete":
		err = s.Snaps.Delete(name)
	default:
		reply(http.StatusNotFound, map[string]string{"error": "unknown snapshot action"})
		return
	}
	if err != nil {
		reply(http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	reply(http.StatusOK, map[string]any{"name": name, "seconds": time.Since(began).Seconds()})
}
