package starlarkfrontend

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/pprof"

	archiveweb "github.com/tinyrange/trex/frontend/archiveweb"
	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

// RunCLI executes the trex command with caller-provided arguments and
// streams. args follows the os.Args convention: its first element is the
// command name. RunCLI returns the process exit code and never exits the
// calling process.
func RunCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// usage: trex [flags] <script> [args...]
	name := "trex"
	if len(args) > 0 {
		name = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	webAddr := fs.String("web", "", "serve a web archive browser on this address")
	webPublic := fs.Bool("web-public", false, "allow the archive browser to bind a non-loopback address")
	serveAddr := fs.String("serve", "", "serve a Starlark web application on this address")
	stdlibDocs := fs.Bool("stdlib-docs", false, "write embedded Starlark API documentation to stdout")
	replMode := fs.Bool("repl", false, "start an interactive Starlark session without a script")
	cpuProfile := fs.String("cpuprofile", "", "write a Go CPU profile to this path")
	memProfile := fs.String("memprofile", "", "write a Go allocation profile to this path")
	starlarkProfile := fs.String("starlarkprofile", "", "write a Starlark execution profile to this path")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage:\n  %s [flags] <script.star> [script arguments...]\n  %s [flags] - [script arguments...]\n  %s -repl\n  %s -serve <addr> <script.star> [script arguments...]\n  %s -web <addr> <directory>\n  %s -stdlib-docs\n\nUse - as the script to read a complete program from stdin.\nFlags before the script belong to trex; arguments after it belong to the script.\nIn the REPL, use help() for APIs and EOF (Ctrl-D) to exit.\n\nOptions:\n", name, name, name, name, name, name)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	modes := 0
	for _, enabled := range []bool{*replMode, *stdlibDocs, *webAddr != "", *serveAddr != ""} {
		if enabled {
			modes++
		}
	}
	if modes > 1 || (*replMode && fs.NArg() != 0) {
		fmt.Fprintln(stderr, "Select one mode; -repl does not accept a script or arguments")
		return 1
	}
	if *cpuProfile != "" {
		profile, err := os.Create(*cpuProfile)
		if err != nil {
			fmt.Fprintf(stderr, "Error creating CPU profile: %v\n", err)
			return 1
		}
		if err := pprof.StartCPUProfile(profile); err != nil {
			_ = profile.Close()
			fmt.Fprintf(stderr, "Error starting CPU profile: %v\n", err)
			return 1
		}
		defer func() {
			pprof.StopCPUProfile()
			if err := profile.Close(); err != nil {
				fmt.Fprintf(stderr, "Error closing CPU profile: %v\n", err)
			}
		}()
	}
	if *memProfile != "" {
		defer func() {
			profile, err := os.Create(*memProfile)
			if err == nil {
				err = pprof.Lookup("allocs").WriteTo(profile, 0)
				if closeErr := profile.Close(); err == nil {
					err = closeErr
				}
			}
			if err != nil {
				fmt.Fprintf(stderr, "Error writing allocation profile: %v\n", err)
			}
		}()
	}
	if *starlarkProfile != "" {
		profile, err := os.Create(*starlarkProfile)
		if err != nil {
			fmt.Fprintf(stderr, "Error creating Starlark profile: %v\n", err)
			return 1
		}
		if err := starlark.StartProfile(profile); err != nil {
			_ = profile.Close()
			fmt.Fprintf(stderr, "Error starting Starlark profile: %v\n", err)
			return 1
		}
		defer func() {
			err := starlark.StopProfile()
			if closeErr := profile.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				fmt.Fprintf(stderr, "Error closing Starlark profile: %v\n", err)
			}
		}()
	}
	if *webAddr != "" {
		if fs.NArg() != 1 {
			fmt.Fprintf(stderr, "Usage: %s -web <addr> <directory>\n", name)
			return 1
		}
		if err := archiveweb.ServeWithOptions(*webAddr, fs.Arg(0), archiveweb.ServeOptions{AllowRemote: *webPublic}); err != nil {
			fmt.Fprintf(stderr, "Error serving web interface: %v\n", err)
			return 1
		}
		return 0
	}
	if *serveAddr != "" {
		if fs.NArg() < 1 {
			fmt.Fprintf(stderr, "Usage: %s -serve <addr> <script> [args...]\n", name)
			return 1
		}
		if err := serveStarlarkWeb(*serveAddr, fs.Arg(0), fs.Args()[1:]); err != nil {
			fmt.Fprintf(stderr, "Error serving Starlark web application: %v\n", err)
			return 1
		}
		return 0
	}
	if *stdlibDocs {
		if fs.NArg() != 0 {
			fmt.Fprintln(stderr, "-stdlib-docs does not accept a script")
			return 1
		}
		documentation, err := standardLibraryDocumentation()
		if err != nil {
			fmt.Fprintf(stderr, "Error generating standard library documentation: %v\n", err)
			return 1
		}
		if _, err := stdout.Write(documentation); err != nil {
			fmt.Fprintf(stderr, "Error writing standard library documentation: %v\n", err)
			return 1
		}
		return 0
	}

	if fs.NArg() < 1 && !*replMode {
		fs.Usage()
		return 1
	}

	script := fs.Arg(0)
	var scriptArgs []string
	if *replMode {
		script = "-"
	} else {
		scriptArgs = fs.Args()[1:]
	}

	thread, environment, err := newStarlarkRuntime(script)
	if err != nil {
		fmt.Fprintf(stderr, "Error initializing Starlark runtime: %v\n", err)
		return 1
	}
	installStarlarkConsole(thread, newStreamStarlarkConsole(stdin, stdout, stderr))
	printOutput := stderr // Preserve script print diagnostics separately from binary stdout.
	if *replMode {
		printOutput = stdout
	}
	thread.Print = func(_ *starlark.Thread, msg string) { fmt.Fprintln(printOutput, msg) }
	resources, err := resourcesForThread(thread)
	if err != nil {
		fmt.Fprintf(stderr, "Error initializing runtime resources: %v\n", err)
		return 1
	}
	defer func() {
		if err := resources.Close(); err != nil {
			fmt.Fprintf(stderr, "Error cleaning up runtime resources: %v\n", err)
		}
	}()
	var source any
	if *replMode {
		source = "def main(args):\n    repl()\n"
	} else if script == "-" {
		data, err := io.ReadAll(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "Error reading stdin: %v\n", err)
			return 1
		}
		source = data
	} else {
		source = nil
	}
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, script, source, environment)
	if err != nil {
		writeStarlarkError(stderr, "Error executing script", err)
		return 1
	}

	mainFunc, ok := globals["main"]
	if !ok {
		fmt.Fprintln(stderr, "No 'main' function found in script")
		return 1
	}

	starlarkArgs := make([]starlark.Value, len(scriptArgs))
	for i, arg := range scriptArgs {
		starlarkArgs[i] = starlark.String(arg)
	}

	if _, err := starlark.Call(thread, mainFunc, starlark.Tuple{starlark.Tuple(starlarkArgs)}, nil); err != nil {
		writeStarlarkError(stderr, "Error calling 'main'", err)
		return 1
	}
	return 0
}

func printStarlarkError(context string, err error) {
	writeStarlarkError(os.Stderr, context, err)
}

func writeStarlarkError(writer io.Writer, context string, err error) {
	if evalErr, ok := err.(*starlark.EvalError); ok {
		fmt.Fprintf(writer, "%s:\n%s\n", context, evalErr.Backtrace())
		return
	}
	fmt.Fprintf(writer, "%s: %v\n", context, err)
}

func starlarkFileOptions() *syntax.FileOptions {
	return &syntax.FileOptions{
		Set:             true,
		While:           true,
		TopLevelControl: true,
		GlobalReassign:  true,
		Recursion:       true,
	}
}
