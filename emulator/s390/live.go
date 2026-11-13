package s390

import (
	"context"
	"io"
	"sync"
	"time"
)

// Live runs a machine continuously for interactive frontends. The machine is
// executed in short slices; between slices other goroutines inspect or change
// it through Do. Virtual time is paced to the wall clock: a machine that runs
// ahead of real time sleeps, and an idle machine's TOD clock follows real
// time, so operating-system timeouts behave as on a real console.
type Live struct {
	mu      sync.Mutex
	m       *Machine
	watched []Versioned
	// Slice is the instruction budget of one execution slice.
	Slice uint64

	wake chan struct{}

	notifyMu sync.Mutex
	changed  chan struct{}
	status   string

	rebase bool // the TOD clock jumped (a restore): re-anchor pacing
}

// Restore loads a checkpoint into the running machine (Machine.Restore)
// between slices.
func (l *Live) Restore(r io.Reader) error {
	var err error
	l.Do(func(m *Machine) {
		if err = m.Restore(r, false); err == nil {
			l.rebase = true
		}
	})
	if err == nil {
		l.notify()
	}
	return err
}

// Versioned is a console whose Version changes with its content.
type Versioned interface{ Version() uint64 }

// NewLive prepares m to run continuously; the consoles are watched for
// changes.
func NewLive(m *Machine, consoles ...Versioned) *Live {
	return &Live{m: m, watched: consoles, Slice: 200000, wake: make(chan struct{}, 1),
		changed: make(chan struct{}), status: "running"}
}

// Do runs f with exclusive access to the machine between slices. If f
// changed a watched console, observers are notified and the machine is woken
// so that attention is processed promptly.
func (l *Live) Do(f func(*Machine)) {
	changed := func() bool {
		l.mu.Lock()
		defer l.mu.Unlock() // a panicking f must not wedge the machine
		before := l.version()
		f(l.m)
		return l.version() != before
	}()
	if changed {
		select {
		case l.wake <- struct{}{}:
		default:
		}
		l.notify()
	}
}

// Save writes a checkpoint of the machine (Machine.Save). The state is
// captured between slices; encoding and compression happen while the
// machine continues to run.
func (l *Live) Save(w io.Writer) error {
	var s *machineSnap
	var err error
	l.mu.Lock()
	s, err = l.m.capture()
	l.mu.Unlock()
	if err != nil {
		return err
	}
	return writeSnapshot(w, s)
}

// Changed returns a channel that is closed at the next screen or status
// change.
func (l *Live) Changed() <-chan struct{} {
	l.notifyMu.Lock()
	defer l.notifyMu.Unlock()
	return l.changed
}

// Status describes the machine: "running", or the stop reason once it has
// stopped, check-stopped or entered a disabled wait.
func (l *Live) Status() string {
	l.notifyMu.Lock()
	defer l.notifyMu.Unlock()
	return l.status
}

func (l *Live) notify() {
	l.notifyMu.Lock()
	close(l.changed)
	l.changed = make(chan struct{})
	l.notifyMu.Unlock()
}

func (l *Live) setStatus(s string) bool {
	l.notifyMu.Lock()
	defer l.notifyMu.Unlock()
	if l.status == s {
		return false
	}
	l.status = s
	return true
}

func (l *Live) version() uint64 {
	var v uint64
	for _, c := range l.watched {
		v += c.Version()
	}
	return v
}

// Run executes the machine until ctx is done.
func (l *Live) Run(ctx context.Context) error {
	const lead = 20 * time.Millisecond // permitted virtual lead over real time
	l.mu.Lock()
	wall0, tod0 := time.Now(), l.m.tod
	seen := l.version()
	l.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.mu.Lock()
		if l.rebase {
			l.rebase = false
			wall0, tod0 = time.Now(), l.m.tod
		}
		r := l.m.Run(l.Slice)
		virtual := time.Duration((l.m.tod-tod0)/todMicro) * time.Microsecond
		v := l.version()
		l.mu.Unlock()
		status := "running"
		switch r.Kind {
		case "stopped", "check-stop", "disabled-wait":
			status = r.Kind
			if r.Detail != "" {
				status += " " + r.Detail
			}
		}
		statusChanged := l.setStatus(status)
		if v != seen || statusChanged {
			seen = v
			l.notify()
		}
		var wait time.Duration
		switch {
		case status != "running":
			wait = time.Second
		case r.Kind == "idle":
			// Waiting for I/O or the operator with no timer armed.
			wait = 10 * time.Millisecond
		default:
			ahead := virtual - time.Since(wall0)
			if ahead < -time.Second {
				// The machine is slower than real time; accept the lag
				// rather than racing to catch up later.
				wall0 = time.Now().Add(-virtual)
			}
			if ahead > lead {
				wait = min(ahead, 100*time.Millisecond)
			}
		}
		if wait == 0 {
			continue
		}
		timer := time.NewTimer(wait)
		began := time.Now()
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-l.wake:
		case <-timer.C:
		}
		timer.Stop()
		if r.Kind == "idle" {
			// Real time passed while nothing was armed.
			l.mu.Lock()
			l.m.tod += uint64(time.Since(began)/time.Microsecond) * todMicro
			l.mu.Unlock()
		}
	}
}
