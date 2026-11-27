// Command trex executes trex Starlark programs and web services.
package main

import (
	"fmt"
	"os"
	"runtime"

	labfrontend "github.com/tinyrange/trex/frontend/lab"
	starlarkfrontend "github.com/tinyrange/trex/frontend/starlark"
)

// The native display backend requires Cocoa events on the initial OS thread.
func init() { runtime.LockOSThread() }

func main() {
	if len(os.Args) > 1 && os.Args[1] == "lab" {
		if err := labfrontend.Run(os.Args[2:], labfrontend.Extension{}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	os.Exit(starlarkfrontend.RunCLI(os.Args, os.Stdin, os.Stdout, os.Stderr))
}
