package buildenv

import (
	"fmt"
	"strings"

	"github.com/tinyrange/trex/emulator/shell"
)

// uname describes this environment's explicit execution target, never the host.
// Release/version identify the emulator rather than claiming a kernel release.
// In particular Linux here does not imply glibc, GNU utilities or a full kernel.
func uname(in shell.Invocation) (int, error) {
	selected := make(map[byte]bool)
	ended := false
	for _, arg := range in.Args[1:] {
		if ended {
			return unameError(in, arg)
		}
		if arg == "--" {
			ended = true
			continue
		}
		if len(arg) < 2 || arg[0] != '-' || arg[1] == '-' {
			return unameError(in, arg)
		}
		for i := 1; i < len(arg); i++ {
			c := arg[i]
			if c == 'a' {
				for _, k := range []byte("snrvmo") {
					selected[k] = true
				}
				continue
			}
			if !strings.ContainsRune("snrvmpio", rune(c)) {
				return unameError(in, arg)
			}
			selected[c] = true
		}
	}
	if len(selected) == 0 {
		selected['s'] = true
	}
	var fields []string
	for _, field := range []struct {
		key   byte
		value string
	}{
		{'s', "Linux"}, {'n', "trex"}, {'r', "0.0.0-trex"}, {'v', "trex static Linux/amd64 interpreter"},
		{'m', "x86_64"}, {'p', "unknown"}, {'i', "unknown"}, {'o', "Linux"},
	} {
		if selected[field.key] {
			fields = append(fields, field.value)
		}
	}
	_, err := fmt.Fprintln(in.Stdout, strings.Join(fields, " "))
	return 0, err
}
func unameError(in shell.Invocation, arg string) (int, error) {
	_, err := fmt.Fprintf(in.Stderr, "uname: unsupported option or operand %q\n", arg)
	return 1, err
}
