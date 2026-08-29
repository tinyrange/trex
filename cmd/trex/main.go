// Command trex executes trex Starlark programs and web services.
package main

import (
	"os"

	starlarkfrontend "github.com/tinyrange/trex/frontend/starlark"
)

func main() {
	os.Exit(starlarkfrontend.RunCLI(os.Args, os.Stdin, os.Stdout, os.Stderr))
}
