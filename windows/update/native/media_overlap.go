package native

import (
	"fmt"
	"sync"

	"go.starlark.net/starlark"
)

// runMediaPreparation runs at most one native preparation beside a caller-thread
// callback. The worker never touches the interpreter; its result and diagnostics
// are published only after joining, including when the callback fails.
func runMediaPreparation(thread *starlark.Thread, callback starlark.Callable, prepare func(func(string)) (starlark.Value, error)) (starlark.Value, error) {
	emit := func(message string) {
		if thread.Print != nil {
			thread.Print(thread, message)
		} else {
			fmt.Println(message)
		}
	}
	if callback == nil {
		return prepare(emit)
	}
	var mu sync.Mutex
	var messages []string
	dropped := false
	finished := false
	observe := func(message string) {
		mu.Lock()
		defer mu.Unlock()
		// Lazy readers can retain this observer; after this operation completes
		// it must neither retain unbounded diagnostics nor touch its old thread.
		if finished {
			return
		}
		if len(messages) < 1024 {
			messages = append(messages, message)
		} else {
			dropped = true
		}
	}
	var result starlark.Value
	var workerErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		result, workerErr = prepare(observe)
	}()
	// Also join during panic unwinding. Resources cannot close under a worker.
	defer func() { <-done }()
	_, callbackErr := starlark.Call(thread, callback, nil, nil)
	<-done
	mu.Lock()
	finished = true
	logs := messages
	messages = nil
	omitted := dropped
	mu.Unlock()
	for _, message := range logs {
		emit(message)
	}
	if omitted {
		emit("update_media: additional preparation diagnostics omitted")
	}
	if callbackErr != nil {
		return nil, callbackErr
	}
	if workerErr != nil {
		return nil, workerErr
	}
	return result, nil
}
