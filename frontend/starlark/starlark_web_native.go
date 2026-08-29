package starlarkfrontend

import (
	"fmt"
	"net/http"
	"os"

	webstar "github.com/tinyrange/trex/web/star"
	"go.starlark.net/starlark"
)

// serveStarlarkWeb is the native listener adapter. The request/response
// framework itself lives in web/star and is independent of process setup.
func serveStarlarkWeb(addr, script string, arguments []string) error {
	thread, environment, err := newStarlarkRuntime(script)
	if err != nil {
		return err
	}
	installStarlarkConsole(thread, newStreamStarlarkConsole(os.Stdin, os.Stdout, os.Stderr))
	resources, err := resourcesForThread(thread)
	if err != nil {
		return err
	}
	defer resources.Close()
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, script, nil, environment)
	if err != nil {
		return err
	}
	mainValue, ok := globals["main"]
	if !ok {
		return fmt.Errorf("%s has no main function", script)
	}
	mainCallable, ok := mainValue.(starlark.Callable)
	if !ok {
		return fmt.Errorf("%s main is not callable", script)
	}
	values := make([]starlark.Value, len(arguments))
	for index, argument := range arguments {
		values[index] = starlark.String(argument)
	}
	result, err := starlark.Call(thread, mainCallable, starlark.Tuple{starlark.Tuple(values)}, nil)
	if err != nil {
		return err
	}
	handler, ok := result.(starlark.Callable)
	if !ok {
		return fmt.Errorf("%s main returned %s, want a request handler", script, result.Type())
	}
	fmt.Fprintf(os.Stderr, "Serving Starlark application %s at %s\n", script, webDisplayURL(addr))
	return http.ListenAndServe(addr, webstar.NewApplication(thread, handler))
}
