package star

import (
	"fmt"
	"sync"

	"go.starlark.net/starlark"
)

// ScriptedApplication keeps page and routing policy in a script. Native
// frontends optionally attach VM consoles and enforce session authentication.
type ScriptedApplication struct {
	Handler     starlark.Callable
	Consoles    starlark.Value
	PublicPaths []string
	Origin      string
}

func (*ScriptedApplication) String() string       { return "<web.application>" }
func (*ScriptedApplication) Type() string         { return "web.application" }
func (*ScriptedApplication) Freeze()              {}
func (*ScriptedApplication) Truth() starlark.Bool { return true }
func (*ScriptedApplication) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable web.application")
}

// NewApplicationWithMutex shares execution serialization with VM factories.
// The response is streamed after releasing the mutex, just as for ordinary apps.
func NewApplicationWithMutex(thread *starlark.Thread, handler starlark.Callable, mu *sync.Mutex) *Application {
	if mu == nil {
		mu = &sync.Mutex{}
	}
	return &Application{thread: thread, handler: handler, mu: mu}
}
func applicationBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var handler starlark.Callable
	var consoles starlark.Value = starlark.None
	var public starlark.Value = starlark.None
	var origin string
	if err := starlark.UnpackArgs("web.application", args, kwargs, "handler", &handler, "consoles?", &consoles, "public?", &public, "origin?", &origin); err != nil {
		return nil, err
	}
	app := &ScriptedApplication{Handler: handler, Consoles: consoles, Origin: origin}
	if public != starlark.None {
		iterable, ok := public.(starlark.Iterable)
		if !ok {
			return nil, fmt.Errorf("web.application public must be a sequence of paths")
		}
		it := iterable.Iterate()
		defer it.Done()
		var value starlark.Value
		for it.Next(&value) {
			path, ok := starlark.AsString(value)
			if !ok {
				return nil, fmt.Errorf("web.application public paths must be strings")
			}
			app.PublicPaths = append(app.PublicPaths, path)
		}
	}
	return app, nil
}
