package star

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"go.starlark.net/starlark"
)

// ActivityPath is served natively, without waiting for the script's execution
// mutex. A handler may legitimately run for minutes (constructing media and
// booting a guest); a browser uses this endpoint to show which request owns
// the script and the script's own print() progress meanwhile. It reveals only
// what the script printed to the server console, behind the same session
// authentication as every other non-public route.
const ActivityPath = "/_trex/activity"

const (
	activityLines   = 400
	activityMaxWait = 25 * time.Second
)

type activityLine struct {
	N    uint64 `json:"n"`
	At   int64  `json:"at"` // Unix milliseconds
	Text string `json:"text"`
}

type activityLog struct {
	mu      sync.Mutex
	changed chan struct{} // closed and replaced on every observable change
	lines   []activityLine
	next    uint64
	route   string // the request path currently holding the script, if any
	since   time.Time
}

func newActivityLog() *activityLog { return &activityLog{changed: make(chan struct{}), next: 1} }

func (l *activityLog) notifyLocked() {
	close(l.changed)
	l.changed = make(chan struct{})
}

func (l *activityLog) print(text string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, activityLine{N: l.next, At: time.Now().UnixMilli(), Text: text})
	l.next++
	if len(l.lines) > activityLines {
		l.lines = append([]activityLine(nil), l.lines[len(l.lines)-activityLines:]...)
	}
	l.notifyLocked()
}

func (l *activityLog) enter(route string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.route, l.since = route, time.Now()
	l.notifyLocked()
}

func (l *activityLog) leave() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.route, l.since = "", time.Time{}
	l.notifyLocked()
}

type activitySnapshot struct {
	Busy      bool           `json:"busy"`
	Route     string         `json:"route,omitempty"`
	BusyMs    int64          `json:"busyMs,omitempty"`
	Next      uint64         `json:"next"`
	Truncated bool           `json:"truncated"`
	Lines     []activityLine `json:"lines"`
}

func (l *activityLog) snapshotLocked(after uint64) activitySnapshot {
	s := activitySnapshot{Busy: l.route != "", Route: l.route, Next: l.next, Lines: []activityLine{}}
	if s.Busy {
		s.BusyMs = time.Since(l.since).Milliseconds()
	}
	for _, line := range l.lines {
		if line.N > after {
			s.Lines = append(s.Lines, line)
		}
	}
	s.Truncated = len(l.lines) > 0 && l.lines[0].N > after+1
	return s
}

// ServeHTTP answers GET ?after=N[&wait=SECONDS]. With wait, it long-polls
// until a line after N is printed, the busy route changes, or the wait ends.
// Clients pass the returned next-1 as the following after.
func (l *activityLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Use GET", http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query()
	after, _ := strconv.ParseUint(query.Get("after"), 10, 64)
	seconds, _ := strconv.ParseFloat(query.Get("wait"), 64)
	wait := min(time.Duration(seconds*float64(time.Second)), activityMaxWait)
	busy := query.Get("busy") // the client's last observed route; a change ends the wait
	l.mu.Lock()
	snapshot := l.snapshotLocked(after)
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		for waiting := true; waiting && len(snapshot.Lines) == 0 && snapshot.Route == busy; {
			changed := l.changed
			l.mu.Unlock()
			select {
			case <-changed:
			case <-timer.C:
				waiting = false
			case <-r.Context().Done():
				waiting = false
			}
			l.mu.Lock()
			snapshot = l.snapshotLocked(after)
		}
	}
	l.mu.Unlock()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(snapshot)
}

// captureActivity records the thread's print() output while still writing it
// to the previous destination (the server console by default).
func captureActivity(thread *starlark.Thread, log *activityLog) {
	previous := thread.Print
	thread.Print = func(t *starlark.Thread, message string) {
		log.print(message)
		if previous != nil {
			previous(t, message)
			return
		}
		fmt.Fprintln(os.Stderr, message)
	}
}
