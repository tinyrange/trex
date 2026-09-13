package starlarkfrontend

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/vncweb"
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
	if workspace, ok := result.(interface{ VMMWorkspace() vmm.Workspace }); ok {
		app, err := vncweb.NewWorkspace(workspace.VMMWorkspace())
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Open VM workspace in your browser: %s/#%s\n", strings.TrimRight(webDisplayURL(addr), "/"), app.Token)
		return http.ListenAndServe(addr, app)
	}
	if vm, ok := result.(interface {
		VMMDisplay() (vmm.DisplaySource, error)
	}); ok {
		display, err := vm.VMMDisplay()
		if err != nil {
			return err
		}
		app, err := vncweb.New(display)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Open VM in your browser: %s/#%s\n", strings.TrimRight(webDisplayURL(addr), "/"), app.Token)
		return http.ListenAndServe(addr, app)
	}
	handler, ok := result.(starlark.Callable)
	if !ok {
		return fmt.Errorf("%s main returned %s, want a request handler", script, result.Type())
	}
	fmt.Fprintf(os.Stderr, "Serving Starlark application %s at %s\n", script, webDisplayURL(addr))
	app := webstar.NewApplication(thread, handler)
	app.RequestLogger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	return http.ListenAndServe(addr, app)
}
