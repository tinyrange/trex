// Command trex-browser browses host directories and nested archives natively.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/tinyrange/trex/frontend/archivegui"
)

func init() { runtime.LockOSThread() }

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: trex-browser [directory-or-archive]\nBrowse folders and nested archives without extracting. Defaults to the current directory.")
	}
	flag.Parse()
	if flag.NArg() > 1 {
		flag.Usage()
		os.Exit(2)
	}
	name := "."
	if flag.NArg() == 1 {
		name = flag.Arg(0)
	}
	if err := run(name); err != nil {
		fmt.Fprintln(os.Stderr, "trex-browser:", err)
		os.Exit(1)
	}
}

func run(name string) error {
	abs, err := filepath.Abs(name)
	if err != nil {
		return err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return err
	}
	initial := "/"
	if !info.IsDir() {
		initial = filepath.Base(abs)
		abs = filepath.Dir(abs)
	}
	source, root, err := archivegui.OpenDirectory(abs)
	if err != nil {
		return err
	}
	defer source.Close()
	return archivegui.Run(root, abs, initial)
}
