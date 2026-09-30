package shell

import (
	"bytes"
	"fmt"
	"sync"
)

// Limit at the write boundary, not after unbounded shell output accumulation.
type makeCapture struct {
	mu      sync.Mutex
	buffer  *bytes.Buffer
	maximum int
}

func (w *makeCapture) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(p) > w.maximum-w.buffer.Len() {
		return 0, fmt.Errorf("make: shell output budget exceeded")
	}
	return w.buffer.Write(p)
}
