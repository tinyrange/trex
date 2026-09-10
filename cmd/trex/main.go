// Command trex executes trex Starlark programs and web services.
package main

import (
	"os"
	"runtime"

	starlarkfrontend "github.com/tinyrange/trex/frontend/starlark"
)

// The native display backend requires Cocoa events on the initial OS thread.
func init() { runtime.LockOSThread() }

func main() {
	os.Exit(starlarkfrontend.RunCLI(os.Args, os.Stdin, os.Stdout, os.Stderr))
}
