package star

import (
	"net/http"
	"time"

	"go.starlark.net/starlark"
)

const requestPhasesKey = "trex.web.request.phases"

func requestPhase(thread *starlark.Thread, name string) func() {
	if thread == nil {
		return func() {}
	}
	phases, ok := thread.Local(requestPhasesKey).(map[string]float64)
	if !ok {
		return func() {}
	}
	start := time.Now()
	return func() { phases[name] += milliseconds(time.Since(start)) }
}

func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// Unwrap keeps ResponseController operations available on the native writer.
type requestWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
	err    error
}

func (w *requestWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *requestWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	if status >= 200 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *requestWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	if err != nil {
		w.err = err
	}
	return n, err
}
